use super::*;
use chunkstore::Keyring;
use std::os::unix::fs::OpenOptionsExt;

fn script(path: &Path, body: &str) {
    use std::io::Write;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(path)
        .unwrap();
    f.write_all(format!("#!/bin/sh\n{body}\n").as_bytes()).unwrap();
}

fn test_opts() -> Options {
    Options {
        min_lock_secs: 0,
        gc_grace_secs: 0,
        ..Default::default()
    }
}

struct Env {
    d: tempfile::TempDir,
    db: Arc<Catalog>,
    cfg: Config,
}

fn env(max_parallel: usize) -> Env {
    let d = tempfile::tempdir().unwrap();
    let p = d.path();
    script(
        &p.join("pve"),
        &format!("echo \"$@\" >> {0}/calls; sleep 0.3; echo done", p.display()),
    );
    let cfg = Config {
        catalog: p.join("cat/catalog.db"),
        store_base: p.join("store"),
        offsite_state_base: p.join("offsite"),
        escrow_base: p.join("escrow"),
        downloads: p.join("downloads"),
        runtime_dir: p.join("run"),
        state_dir: p.join("state"),
        pve_bin: p.join("pve"),
        offsite_bin: p.join("pve"),
        alerts_config: p.join("alerts.json"),
        max_parallel,
        ..Default::default()
    };
    let db = Arc::new(Catalog::open_memory().unwrap());
    let src = json!({"api": {"host": "pve", "ca_pem": "CA", "token_id": "t@pve!x", "token_secret": "s3cret"},
                     "storage": "nx", "fleecing_storage": "local",
                     "nodes": {"n1": {"host": "10.0.0.1", "key_pem": "KEY", "known_hosts_text": "10.0.0.1 ssh-ed25519 AAA"}}});
    db.conn()
        .execute_batch(&format!(
            "INSERT INTO tenants (name) VALUES ('t1'), ('t2');
             INSERT INTO sources (id, tenant, kind, name, config) VALUES
               (1,'t1','pve','a','{src}'), (2,'t1','pve','b','{src}'), (3,'t2','pve','c','{src}');
             INSERT INTO policies (id, name, schedule, gfs, offsite) VALUES (1,'p','daily 22:00','{{\"daily\":3}}',0);
             INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES
               (1,'t1',1,1,'g1','[100]'), (2,'t1',2,1,'g2','[200]'), (3,'t1',1,1,'g3','[101]'), (4,'t2',3,1,'g4','[300]');"
        ))
        .unwrap();
    Env { d, db, cfg }
}

fn sched(e: &Env) -> Scheduler {
    let keys: KeySource = Arc::new(|t: &str| Ok(Keyring::new(t, &[(1, [7; 32])])));
    Scheduler::new(e.cfg.clone(), e.db.clone(), keys, test_opts).unwrap()
}

fn manual(s: &Scheduler, kind: &str, tenant: &str, p: Value) -> i64 {
    let c = s.db.conn();
    c.execute(
        "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES (?1,?2,?3,'queued','alice',0)",
        params![kind, tenant, p.to_string()],
    )
    .unwrap();
    c.last_insert_rowid()
}

fn state(s: &Scheduler, id: i64) -> String {
    s.db.conn()
        .query_row("SELECT state FROM jobs WHERE id=?1", [id], |r| r.get(0))
        .unwrap()
}

#[test]
fn fifo_with_per_source_exclusivity() {
    let e = env(4);
    let mut s = sched(&e);
    let a = manual(&s, "backup", "t1", json!({"group_id": 1})); // source 1
    let b = manual(&s, "backup", "t1", json!({"group_id": 3})); // source 1 again: waits
    let c = manual(&s, "backup", "t1", json!({"group_id": 2})); // source 2: may pass b
    s.start_jobs().unwrap();
    assert_eq!(s.running(), vec![(a, "source:1".into()), (c, "source:2".into())]);
    assert_eq!(state(&s, b), "queued");
    s.start_jobs().unwrap(); // nothing new while busy
    assert_eq!(s.running().len(), 2);
    s.wait_idle(Duration::from_secs(20)).unwrap();
    assert_eq!((state(&s, a).as_str(), state(&s, c).as_str()), ("ok", "ok"));
    // follow-up retentions (sources 1 and 2) were queued after b: b goes first on source 1
    s.start_jobs().unwrap();
    let r = s.running();
    assert_eq!(r[0], (b, "source:1".into()));
    assert_eq!(r[1].1, "source:2", "retention of group 2 runs beside it");
    assert_eq!(r.len(), 2);
    s.wait_idle(Duration::from_secs(20)).unwrap();
    let calls = fs::read_to_string(e.d.path().join("calls")).unwrap();
    assert_eq!(calls.matches("backup-all").count(), 3);
    assert_eq!(fs::read_dir(&e.cfg.runtime_dir).unwrap().count(), 0, "job dirs removed");
}

#[test]
fn bounded_parallelism_and_cancel() {
    let e = env(1);
    let mut s = sched(&e);
    let a = manual(&s, "backup", "t1", json!({"group_id": 1}));
    let b = manual(&s, "backup", "t1", json!({"group_id": 2}));
    let c = manual(&s, "backup", "t2", json!({"group_id": 4}));
    s.start_jobs().unwrap();
    assert_eq!(s.running().len(), 1);
    assert_eq!(s.running()[0].0, a);
    // web-api cancels b while it is queued
    s.db.conn()
        .execute("UPDATE jobs SET state='cancelled' WHERE id=?1", [b])
        .unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    s.start_jobs().unwrap();
    assert_eq!(s.running()[0].0, c);
    s.wait_idle(Duration::from_secs(20)).unwrap();
    assert_eq!(state(&s, b), "cancelled");
}

#[test]
fn tenant_isolation_and_bad_params() {
    let e = env(4);
    let mut s = sched(&e);
    let ids = [
        manual(&s, "backup", "t2", json!({"group_id": 1})), // group of t1
        manual(
            &s,
            "restore",
            "t2",
            json!({"source": "vm-100", "time": 1, "node": "n1", "target": 100, "storage": "x", "source_id": 1}),
        ),
        manual(&s, "files_list", "t1", json!({"source": "vm-100;rm", "time": 1})),
        manual(
            &s,
            "restore",
            "t1",
            json!({"source": "ct-100", "time": 1, "node": "n1", "target": 100, "storage": "x"}),
        ),
        manual(
            &s,
            "files_get",
            "t1",
            json!({"source": "vm-100", "time": 1, "paths": ["--evil"]}),
        ),
        manual(&s, "frobnicate", "t1", json!({})),
    ];
    s.start_jobs().unwrap();
    for id in ids {
        assert_eq!(state(&s, id), "failed", "job {id}");
    }
    assert!(s.running().is_empty());
    let n: i64 =
        s.db.conn()
            .query_row("SELECT COUNT(*) FROM alerts WHERE kind='job_failed'", [], |r| r.get(0))
            .unwrap();
    assert_eq!(n, ids.len() as i64);
}

#[test]
fn crash_recovery() {
    let e = env(4);
    fs::create_dir_all(e.cfg.runtime_dir.join("job-7")).unwrap();
    fs::write(e.cfg.runtime_dir.join("job-7/token"), "secret").unwrap();
    e.db.conn()
        .execute(
            "INSERT INTO jobs (id, kind, tenant, params, state, requested_by, created, started, log)
             VALUES (7,'backup','t1','{\"group_id\":1}','running','scheduler',1,2,'half done')",
            [],
        )
        .unwrap();
    let s = sched(&e);
    let (st, log, fin): (String, String, Option<i64>) =
        s.db.conn()
            .query_row("SELECT state, log, finished FROM jobs WHERE id=7", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
    assert_eq!(st, "failed");
    assert!(log.starts_with("half done") && log.contains("interrupted"), "{log}");
    assert!(fin.is_some());
    assert!(!e.cfg.runtime_dir.join("job-7").exists(), "stale secrets removed");
    let a: String =
        s.db.conn()
            .query_row("SELECT action FROM audit ORDER BY seq DESC LIMIT 1", [], |r| r.get(0))
            .unwrap();
    assert_eq!(a, "job.failed");
    // key creation + sealing the 3 legacy source configs + the failed job
    assert_eq!(s.db.verify_audit().unwrap(), 5);
}

#[test]
fn scheduled_backups_once_per_period() {
    let e = env(4);
    let mut s = sched(&e);
    let day = 20_000 * 86400;
    let count = |s: &Scheduler| -> i64 {
        s.db.conn()
            .query_row("SELECT COUNT(*) FROM jobs WHERE kind='backup'", [], |r| r.get(0))
            .unwrap()
    };
    s.now = day + 12 * 3600;
    s.queue_scheduled(s.now).unwrap();
    assert_eq!(count(&s), 0, "first sight: wait for the next slot");
    s.now = day + 22 * 3600 + 5;
    s.queue_scheduled(s.now).unwrap();
    assert_eq!(count(&s), 4, "one per group");
    s.now += 60;
    s.queue_scheduled(s.now).unwrap();
    assert_eq!(count(&s), 4, "queued jobs are not duplicated");
    s.db.conn().execute("UPDATE jobs SET state='ok'", []).unwrap();
    s.queue_scheduled(s.now).unwrap();
    assert_eq!(count(&s), 4, "not again in the same period");
    // down for three days, back at 09:00
    s.now = day + 4 * 86400 + 9 * 3600;
    s.queue_scheduled(s.now).unwrap();
    assert_eq!(count(&s), 8, "one catch-up run per group, not three");
    s.db.conn().execute("UPDATE jobs SET state='ok'", []).unwrap();
    s.now += 3600;
    s.queue_scheduled(s.now).unwrap();
    assert_eq!(count(&s), 8);
    s.now = day + 4 * 86400 + 22 * 3600;
    s.queue_scheduled(s.now).unwrap();
    assert_eq!(count(&s), 12, "regular slot after the catch-up");
}

#[test]
fn generated_config_keeps_secrets_in_files() {
    let e = env(4);
    let s = sched(&e);
    let job = Job {
        id: 9,
        kind: "backup".into(),
        tenant: "t1".into(),
        params: json!({"group_id": 1}),
    };
    let p = s.plan(&job).unwrap();
    let names: Vec<&str> = p.files.iter().map(|f| f.0.as_str()).collect();
    assert_eq!(
        names,
        ["ca.pem", "token", "node-n1.key", "node-n1.known_hosts", "pve.json"]
    );
    let cfg: Value = serde_json::from_slice(&p.files[4].1).unwrap();
    assert_eq!(cfg["vmids"], json!([100]));
    assert_eq!(cfg["api"]["port"], 8006);
    assert_eq!(cfg["api"]["token_secret_file"], json!(p.dir.join("token")));
    assert_eq!(cfg["store"], json!(e.cfg.store_base.join("t1")));
    assert_eq!(cfg["nodes"]["n1"]["key"], json!(p.dir.join("node-n1.key")));
    assert!(!String::from_utf8_lossy(&p.files[4].1).contains("s3cret"));
}

/// Review H-2: legacy plaintext secrets are sealed at startup (audited), the
/// job config gets the plaintext only in its 0600 files, and a sealed blob
/// neither follows a copy to another source nor an endpoint change.
#[test]
fn sealed_secrets_migrated_opened_and_bound() {
    let e = env(4);
    e.db.conn()
        .execute(
            "UPDATE tenants SET offsite = ?1 WHERE name = 't1'",
            [
                json!({"remote": {"type": "sftp", "host": "box", "user": "u", "host_key": "hk", "key_pem": "BOXKEY"}})
                    .to_string(),
            ],
        )
        .unwrap();
    let s = sched(&e);
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let key = e.cfg.state_dir.join("secrets.key");
    assert_eq!(mode(&key), 0o600);
    let pubf = e.cfg.catalog.parent().unwrap().join("secrets.pub");
    assert_eq!(mode(&pubf), 0o640);

    let rows: Vec<String> = {
        let c = s.db.conn();
        let mut st = c
            .prepare("SELECT config FROM sources UNION ALL SELECT offsite FROM tenants")
            .unwrap();
        let r = st.query_map([], |r| r.get(0)).unwrap();
        r.collect::<std::result::Result<_, _>>().unwrap()
    };
    for r in &rows {
        assert!(
            !r.contains("s3cret") && !r.contains("KEY\"") && !r.contains("BOXKEY"),
            "{r}"
        );
    }
    assert_eq!(rows.iter().filter(|r| r.contains("sealed:v1:")).count(), 4);
    let migrated: Vec<(String, String)> = {
        let c = s.db.conn();
        let mut st = c
            .prepare("SELECT target, details FROM audit WHERE action = 'secret.migrate' ORDER BY seq")
            .unwrap();
        let r = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        r.collect::<std::result::Result<_, _>>().unwrap()
    };
    let targets: Vec<&str> = migrated.iter().map(|m| m.0.as_str()).collect();
    assert_eq!(targets, ["source/1", "source/2", "source/3", "tenant/t1"]);
    assert!(migrated[0].1.contains("/api/token_secret") && migrated[0].1.contains("/nodes/n1/key_pem"));
    assert!(!migrated.iter().any(|m| m.1.contains("s3cret")));

    // job config: plaintext only inside the private job dir
    let job = |id, tenant: &str, g: i64| Job {
        id,
        kind: "backup".into(),
        tenant: tenant.into(),
        params: json!({"group_id": g}),
    };
    let p = s.plan(&job(9, "t1", 1)).unwrap();
    run::write_private(&p.dir, &p.files).unwrap();
    assert_eq!(fs::read(p.dir.join("token")).unwrap(), b"s3cret");
    assert_eq!(fs::read(p.dir.join("node-n1.key")).unwrap(), b"KEY\n");
    for f in ["token", "node-n1.key", "pve.json"] {
        assert_eq!(mode(&p.dir.join(f)), 0o600, "{f}");
    }
    assert!(!fs::read_to_string(p.dir.join("pve.json"))
        .unwrap()
        .contains("sealed:v1:"));
    let o = s.offsite_config("t1", &p.dir).unwrap().unwrap();
    assert_eq!(o.iter().find(|f| f.0 == "offsite.key").unwrap().1, b"BOXKEY\n");

    // a value sealed with the published key (what the web-api does) opens
    let pk = catalog::secret::SealKey::load(&pubf).unwrap();
    let mut cfg: Value = serde_json::from_str(&rows[1]).unwrap();
    cfg["api"]["token_secret"] = json!("n3w");
    pk.seal_all(&catalog::secret::source_owner(2), &mut cfg).unwrap();
    s.db.conn()
        .execute("UPDATE sources SET config = ?1 WHERE id = 2", [cfg.to_string()])
        .unwrap();
    let p = s.plan(&job(10, "t1", 2)).unwrap();
    assert_eq!(p.files.iter().find(|f| f.0 == "token").unwrap().1, b"n3w");

    // the sealed config of source 1 copied to source 3 (tenant t2) does not open
    s.db.conn()
        .execute(
            "UPDATE sources SET config = (SELECT config FROM sources WHERE id = 1) WHERE id = 3",
            [],
        )
        .unwrap();
    let err = format!("{:#}", s.plan(&job(11, "t2", 4)).err().unwrap());
    assert!(err.contains("another location"), "{err}");
    // nor does source 2's after its endpoint was changed in the catalog
    s.db.conn()
        .execute(
            "UPDATE sources SET config = json_set(config, '$.api.host', 'attacker.example') WHERE id = 2",
            [],
        )
        .unwrap();
    let err = format!("{:#}", s.plan(&job(12, "t1", 2)).err().unwrap());
    assert!(err.contains("another location"), "{err}");

    // restart: same key, nothing left to migrate
    drop(s);
    let s = sched(&e);
    let n: i64 =
        s.db.conn()
            .query_row("SELECT COUNT(*) FROM audit WHERE action LIKE 'secret.%'", [], |r| {
                r.get(0)
            })
            .unwrap();
    assert_eq!(n, 5, "key_create + 4 migrations, none added by the restart");
    assert!(s.plan(&job(13, "t1", 1)).is_ok());
}

/// TrueNAS: backup of a group's datasets via nexus-truenas (secrets opened into
/// 0600 job files, pinned host key as known_hosts), retention over the group's
/// datasets + their children, file jobs on `nas-` snapshots without secrets.
#[test]
fn truenas_jobs() {
    let e = env(4);
    let src = json!({"host": "nas", "port": 443, "connect_addr": "10.0.0.9:8443", "ca_pem": "CERT", "user": "nexusbackup",
                     "token_secret": "1-apikey",
                     "ssh": {"host": "10.0.0.9", "port": 2222, "user": "nexusbackup", "host_key": "ssh-ed25519 AAAHK",
                             "key_pem": "SSHKEY", "public_key": "ssh-ed25519 AAAPK"},
                     "datasets": ["tank/data", "tank/smb"], "recursive": true});
    e.db.conn()
        .execute_batch(&format!(
            "INSERT INTO sources (id, tenant, kind, name, config) VALUES (5,'t1','truenas','nas','{src}');
             INSERT INTO policies (id, name, schedule, gfs, offsite) VALUES (2,'q','daily 22:00','{{\"daily\":9}}',0);
             INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES (5,'t1',5,2,'nas','[\"tank/data\"]');"
        ))
        .unwrap();
    let s = sched(&e);
    let raw: String =
        s.db.conn()
            .query_row("SELECT config FROM sources WHERE id = 5", [], |r| r.get(0))
            .unwrap();
    assert!(!raw.contains("1-apikey") && !raw.contains("SSHKEY"), "{raw}");
    let job = |id, kind: &str, p: Value| Job {
        id,
        kind: kind.into(),
        tenant: "t1".into(),
        params: p,
    };
    let p = s.plan(&job(20, "backup", json!({"group_id": 5}))).unwrap();
    assert_eq!(p.key, "source:5");
    let names: Vec<&str> = p.files.iter().map(|f| f.0.as_str()).collect();
    assert_eq!(names, ["ca.pem", "api-key", "ssh.key", "known_hosts", "truenas.json"]);
    let file = |n: &str| p.files.iter().find(|f| f.0 == n).unwrap().1.clone();
    assert_eq!(file("api-key"), b"1-apikey");
    assert_eq!(file("ssh.key"), b"SSHKEY\n");
    assert_eq!(file("known_hosts"), b"[10.0.0.9]:2222 ssh-ed25519 AAAHK\n");
    let cfg: Value = serde_json::from_slice(&file("truenas.json")).unwrap();
    assert_eq!(cfg["datasets"], json!(["tank/data"]));
    assert_eq!(cfg["source_id"], 5);
    assert_eq!(cfg["api"]["connect_addr"], "10.0.0.9:8443");
    assert_eq!(cfg["ssh"]["key_file"], json!(p.dir.join("ssh.key")));
    assert_eq!(
        (cfg["recursive"].clone(), cfg["zfs_sudo"].clone()),
        (json!(true), json!(true))
    );
    assert!(!String::from_utf8_lossy(&file("truenas.json")).contains("apikey"));
    match &p.steps[..] {
        [Step::Cli { bin, args, .. }] => {
            assert_eq!(bin, &e.cfg.truenas_bin);
            assert_eq!(args[1], "backup");
        }
        st => panic!("{st:?}"),
    }
    let p = s
        .plan(&job(21, "retention", json!({"group_id": 5, "chain": true})))
        .unwrap();
    match &p.steps[..] {
        [Step::Retention { sources, prefixes, gfs }] => {
            assert_eq!(sources, &["nas-5-tank.data"]);
            assert_eq!(prefixes, &["nas-5-tank.data."]);
            assert_eq!(gfs.daily, 9);
        }
        st => panic!("{st:?}"),
    }
    let p = s
        .plan(&job(22, "retention", json!({"source": "nas-5-tank.data.projects"})))
        .unwrap();
    assert!(
        matches!(&p.steps[..], [Step::Retention { sources, gfs, .. }] if sources == &["nas-5-tank.data.projects"] && gfs.daily == 9)
    );
    let p = s
        .plan(&job(
            23,
            "files_list",
            json!({"source": "nas-5-tank.data", "time": 77, "path": "/docs"}),
        ))
        .unwrap();
    assert_eq!(p.files.len(), 1);
    assert!(!String::from_utf8_lossy(&p.files[0].1).contains("apikey"));
    match &p.steps[..] {
        [Step::Cli { bin, args, capture, .. }] => {
            assert!(*capture && bin == &e.cfg.truenas_bin);
            assert_eq!(&args[1..], ["files", "nas-5-tank.data", "77", "ls", "/docs"]);
        }
        st => panic!("{st:?}"),
    }
    for bad in ["nas-5-tank..x", "nas-x-tank"] {
        assert!(s
            .plan(&job(24, "files_list", json!({"source": bad, "time": 1, "path": "/"})))
            .is_err());
    }
    // the firewall allow-list contains the API and SSH endpoints
    assert_eq!(
        firewall::truenas_targets(&src),
        vec![("10.0.0.9".to_owned(), 8443), ("10.0.0.9".to_owned(), 2222)]
    );
    // retention with prefixes applies to the children found in the store
    let store_dir = e.cfg.store_base.join("t1");
    let st = chunkstore::Store::open(&store_dir, Keyring::new("t1", &[(1, [7; 32])]), test_opts()).unwrap();
    for (src, t) in [
        ("nas-5-tank.data", 1),
        ("nas-5-tank.data", 2),
        ("nas-5-tank.data.projects", 1),
        ("nas-5-tank.data.projects", 2),
        ("nas-5-tank.database", 1),
    ] {
        st.commit_snapshot(src, t, &[("tree", chunkstore::Index::Tree { entries: vec![] })])
            .unwrap();
    }
    let gfs = Gfs {
        daily: 1,
        weekly: 0,
        monthly: 0,
        yearly: 0,
    };
    let plan = Plan {
        key: "k".into(),
        tenant: "t1".into(),
        store: store_dir,
        dir: e.d.path().join("run/r"),
        files: vec![],
        steps: vec![Step::Retention {
            sources: vec!["nas-5-tank.data".into()],
            prefixes: vec!["nas-5-tank.data.".into()],
            gfs,
        }],
        download: None,
    };
    let keys: KeySource = Arc::new(|t: &str| Ok(Keyring::new(t, &[(1, [7; 32])])));
    let ctx = Ctx {
        keys,
        store_options: test_opts,
        log_max: 1 << 20,
    };
    let f = run::execute(1, &plan, &ctx);
    assert_eq!(f.outcome, Outcome::Ok, "{}", f.log);
    assert!(
        f.log.contains("retention nas-5-tank.data.projects:") && !f.log.contains("tank.database"),
        "{}",
        f.log
    );
    let left: Vec<(String, u64)> = st
        .list_snapshots()
        .unwrap()
        .into_iter()
        .map(|m| (m.source, m.time))
        .collect();
    assert_eq!(left.len(), 3, "{left:?}");
}
