use super::*;
use chunkstore::Store;

fn count(s: &Scheduler, sql: &str) -> i64 {
    s.db.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

/// Verify finds a corrupt chunk: it goes on the bad list, the snapshot is flagged
/// damaged with a critical alert, and a `chunk_repair` is queued (offsite target
/// configured). The fake nexus-offsite puts the good copy back; the store step
/// reports the snapshot healthy again, the flag and the alert go.
#[test]
fn verify_flags_damage_and_repair_heals_it() {
    let mut e = env(2);
    e.cfg.verify_parts = 1;
    let p = e.d.path().to_owned();
    let store = Store::open(p.join("store/t1"), Keyring::new("t1", &[(1, [7; 32])]), test_opts()).unwrap();
    let mut img = vec![0u8; 2 * 65536];
    img[70000] = 1;
    let idx = store.store_image(&img[..], 65536).unwrap();
    let id = *idx.chunk_ids()[1];
    store.commit_snapshot("vm-100", 1000, &[("drive-scsi0", idx)]).unwrap();
    let h = chunkstore::crypto::hex(&id);
    let chunk = p.join("store/t1/chunks").join(&h[..4]).join(&h);
    fs::copy(&chunk, p.join("good")).unwrap();
    let mut b = fs::read(&chunk).unwrap();
    b[40] ^= 0xff;
    fs::write(&chunk, b).unwrap();
    script(
        &p.join("offsite"),
        &format!(
            "echo \"$@\" >> {calls}\ncase \"$2\" in repair) cp {good} {chunk}; echo 'repair {{\"repaired\":1}}';; esac",
            calls = p.join("offsite-calls").display(),
            good = p.join("good").display(),
            chunk = chunk.display()
        ),
    );
    e.cfg.offsite_bin = p.join("offsite");
    let mut s = sched(&e);
    let o = json!({"remote": {"type": "sftp", "host": "box.example", "port": 23, "user": "u1",
                              "host_key": "ssh-ed25519 AAA", "key_file": "/etc/nexus/ssh/offsite"}});
    s.db.conn()
        .execute_batch(&format!(
            "UPDATE tenants SET offsite = '{o}' WHERE name = 't1';
             INSERT INTO snapshots (tenant, source, time, local, offsite) VALUES ('t1', 'vm-100', 1000, 1, 1);"
        ))
        .unwrap();

    let v = manual(&s, "verify", "t1", json!({}));
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    assert_eq!(state(&s, v), "failed");
    assert_eq!(count(&s, "SELECT damaged FROM snapshots WHERE source='vm-100'"), 1);
    let msg: String =
        s.db.conn()
            .query_row(
                "SELECT message FROM alerts WHERE key='snapshot_damaged:t1' AND resolved_at IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
    assert!(msg.contains("vm-100/1000"), "{msg}");
    assert_eq!(count(&s, "SELECT COUNT(*) FROM audit WHERE action='snapshot.damaged'"), 1);
    assert!(!store.has_chunk(&id), "the corrupt copy was moved aside");
    let snap = store.load_manifest("vm-100", 1000).unwrap();
    assert!(store.is_damaged(&snap).unwrap(), "no incremental on top of it");
    let repair: i64 = s
        .db
        .conn()
        .query_row("SELECT id FROM jobs WHERE kind='chunk_repair' AND tenant='t1'", [], |r| r.get(0))
        .unwrap();

    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    assert_eq!(state(&s, repair), "ok");
    assert!(fs::read_to_string(p.join("offsite-calls")).unwrap().contains(" repair\n"));
    assert_eq!(
        count(&s, "SELECT COUNT(*) FROM snapshots WHERE damaged IS NOT NULL"),
        0
    );
    assert_eq!(
        count(&s, "SELECT COUNT(*) FROM alerts WHERE key='snapshot_damaged:t1' AND resolved_at IS NULL"),
        0
    );
    assert_eq!(count(&s, "SELECT COUNT(*) FROM audit WHERE action='snapshot.repaired'"), 1);
    assert!(!store.is_damaged(&snap).unwrap());
    assert!(store.bad_chunks().unwrap().is_empty());

    // a tenant without offsite target or replication source has nothing to repair from
    let none = manual(&s, "chunk_repair", "t2", json!({}));
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    assert_eq!(state(&s, none), "failed");
}
