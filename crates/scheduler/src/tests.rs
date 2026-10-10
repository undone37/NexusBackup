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

    // S3 remote (sealed like the web-api does): secret key and CA as files
    let pk = catalog::secret::SealKey::load(&pubf).unwrap();
    let mut s3 = json!({"remote": {"type": "s3", "endpoint": "https://minio.lan:9000", "region": "us-east-1",
                                    "bucket": "nexus", "path_style": true, "access_key": "appliance",
                                    "secret_key": "S3KEY", "ca_pem": "-----BEGIN CERTIFICATE-----\nX\n", "lock": true},
                        "uploaders": 2});
    pk.seal_all(&catalog::secret::tenant_owner("t1"), &mut s3).unwrap();
    s.db.conn()
        .execute("UPDATE tenants SET offsite = ?1 WHERE name = 't1'", [s3.to_string()])
        .unwrap();
    let o = s.offsite_config("t1", &p.dir).unwrap().unwrap();
    let file = |n: &str| o.iter().find(|f| f.0 == n).unwrap().1.clone();
    assert_eq!(file("offsite-s3.secret"), b"S3KEY");
    assert!(file("offsite-ca.pem").starts_with(b"-----BEGIN CERTIFICATE-----"));
    let cfg: Value = serde_json::from_slice(&file("offsite.json")).unwrap();
    let r = &cfg["remote"];
    assert!(r.get("secret_key").is_none() && r.get("ca_pem").is_none(), "{r}");
    assert_eq!(r["secret_key_file"], json!(p.dir.join("offsite-s3.secret")));
    assert_eq!(r["ca_file"], json!(p.dir.join("offsite-ca.pem")));
    assert_eq!((r["lock"].clone(), cfg["uploaders"].clone()), (json!(true), json!(2)));
    // the sealed key does not follow another bucket
    s.db.conn()
        .execute(
            "UPDATE tenants SET offsite = json_set(offsite, '$.remote.bucket', 'evil') WHERE name = 't1'",
            [],
        )
        .unwrap();
    assert!(s.offsite_config("t1", &p.dir).is_err());

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

/// NFS/SMB shares: backup of a share group via nexus-nas (SMB password opened
/// into a 0600 job file, never in nas.json), retention of `share-<id>`, file
/// jobs without secrets, firewall endpoints, result with consistency.
#[test]
fn share_jobs() {
    let e = env(4);
    let smb = json!({"host": "fs1", "port": 10445, "share": "Data", "user": "backup", "password": "pw,1",
                     "version": "3.1.1", "seal": true, "snapshot_dir": "~snapshot", "excludes": ["*.tmp"], "threads": 8});
    let nfs = json!({"host": "10.0.0.7", "export": "/srv/share", "version": "3", "mount_port": 12048});
    e.db.conn()
        .execute_batch(&format!(
            "INSERT INTO sources (id, tenant, kind, name, config) VALUES (6,'t1','smb','fs1','{smb}'), (7,'t1','nfs','nfs1','{nfs}');
             INSERT INTO policies (id, name, schedule, gfs, offsite) VALUES (2,'q','daily 22:00','{{\"daily\":9}}',0);
             INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES (6,'t1',6,2,'fs1','[]'), (7,'t1',7,1,'nfs1','[]');"
        ))
        .unwrap();
    let s = sched(&e);
    let raw: String =
        s.db.conn()
            .query_row("SELECT config FROM sources WHERE id = 6", [], |r| r.get(0))
            .unwrap();
    assert!(!raw.contains("pw,1") && raw.contains("sealed:v1:"), "{raw}");
    let job = |id, kind: &str, p: Value| Job {
        id,
        kind: kind.into(),
        tenant: "t1".into(),
        params: p,
    };
    let p = s.plan(&job(30, "backup", json!({"group_id": 6}))).unwrap();
    assert_eq!(p.key, "source:6");
    let names: Vec<&str> = p.files.iter().map(|f| f.0.as_str()).collect();
    assert_eq!(names, ["smb-password", "nas.json"]);
    assert_eq!(p.files[0].1, b"pw,1");
    let cfg: Value = serde_json::from_slice(&p.files[1].1).unwrap();
    assert!(!String::from_utf8_lossy(&p.files[1].1).contains("pw,1"));
    assert_eq!(cfg["share"]["password_file"], json!(p.dir.join("smb-password")));
    assert_eq!(
        (
            &cfg["share"]["kind"],
            &cfg["share"]["share"],
            &cfg["share"]["seal"],
            &cfg["share"]["sign"]
        ),
        (&json!("smb"), &json!("Data"), &json!(true), &json!(true))
    );
    assert_eq!(
        (&cfg["snapshot_dir"], &cfg["threads"], &cfg["source_id"]),
        (&json!("~snapshot"), &json!(8), &json!(6))
    );
    assert_eq!(cfg["mount_socket"], json!(nas::MOUNT_SOCKET));
    match &p.steps[..] {
        [Step::Cli { bin, args, .. }] => {
            assert_eq!(bin, &e.cfg.nas_bin);
            assert_eq!(args[1], "backup");
        }
        st => panic!("{st:?}"),
    }
    let p = s.plan(&job(31, "backup", json!({"group_id": 7}))).unwrap();
    assert_eq!(p.files.len(), 1, "NFS: no secret files");
    let p = s
        .plan(&job(32, "retention", json!({"group_id": 6, "chain": true})))
        .unwrap();
    assert!(
        matches!(&p.steps[..], [Step::Retention { sources, gfs, .. }] if sources == &["share-6"] && gfs.daily == 9)
    );
    let p = s.plan(&job(33, "retention", json!({"source": "share-6"}))).unwrap();
    assert!(
        matches!(&p.steps[..], [Step::Retention { sources, gfs, .. }] if sources == &["share-6"] && gfs.daily == 9)
    );
    let p = s
        .plan(&job(
            34,
            "files_get",
            json!({"source": "share-6", "time": 5, "paths": ["/a"], "format": "zip", "download_token": "ab".repeat(32)}),
        ))
        .unwrap();
    assert_eq!(p.files.len(), 1);
    assert!(!String::from_utf8_lossy(&p.files[0].1).contains("pw"));
    match &p.steps[..] {
        [Step::Cli { bin, args, capture, .. }] => {
            assert!(*capture && bin == &e.cfg.nas_bin);
            assert_eq!(&args[1..5], ["files", "share-6", "5", "get"]);
        }
        st => panic!("{st:?}"),
    }
    assert!(s
        .plan(&job(
            35,
            "files_list",
            json!({"source": "share-06", "time": 1, "path": "/"})
        ))
        .is_err());
    // firewall: SMB port; NFSv3 adds mountd (no portmapper)
    assert_eq!(firewall::share_targets("smb", &smb), vec![("fs1".to_owned(), 10445)]);
    assert_eq!(
        firewall::share_targets("nfs", &nfs),
        vec![("10.0.0.7".to_owned(), 2049), ("10.0.0.7".to_owned(), 12048)]
    );
    assert_eq!(
        firewall::share_targets("nfs", &json!({"host": "n", "export": "/x"})),
        vec![("n".to_owned(), 2049)]
    );
    // result: transferred bytes and consistency from nexus-nas output
    let mut log = String::from(
        "committed share-6/100 in 1.0s: 5 entries, 2 files read (10 bytes), 0 unchanged files reused (0 bytes), 2 new chunks (10 bytes), 10 bytes transferred, 0 inconsistent, 0 errors, 5 entries/s, live share (no NAS snapshot)\n\
         inconsistent share-6/100: consistent=false (no NAS snapshot; 0 files changed while read; 0 entries unreadable)\n",
    );
    let r = s
        .result(&job(36, "backup", json!({"group_id": 6})), None, &mut log)
        .unwrap();
    assert_eq!(
        (&r["source"], &r["transferred_bytes"], &r["consistent"]),
        (&json!("share-6"), &json!(10), &json!(false))
    );
}

/// Secondary side of docs/replication.md: enrollment and sync jobs spawn
/// nexus-replica with a generated config, results land in the catalog, key
/// mismatches raise their own alert, replicated tenants take no backups and
/// get no local DEK.
#[test]
fn replication_jobs() {
    let mut e = env(4);
    let dir = e.d.path().to_owned();
    script(
        &dir.join("replica"),
        &format!(
            r#"cp "$1" {0}/replica-$2.json; cat "$(dirname "$1")/token" > {0}/token-seen 2>/dev/null
case "$2" in
enroll) echo 'enrolled {{"cert_sha256":"{1}","tenants":["r1","r2"],"keyd_pub":"{2}"}}' ;;
sync) if grep -q '"tenant": "r2"' "$1"; then echo 'key-mismatch {{"tenant":"r2","version":2}}'; exit 1; fi
      echo 'replicated {{"imported":["vm-100/5"],"bytes_fetched":10,"remote":1,"key_versions":[1]}}' ;;
esac"#,
            dir.display(),
            "c".repeat(64),
            "d".repeat(64)
        ),
    );
    e.cfg.replica_bin = dir.join("replica");
    let mut s = sched(&e);
    let url = "10.0.2.2:28443";
    let (peer, pin) = ("0123456789abcdef", "a".repeat(64));
    s.db.conn()
        .execute_batch(
            "INSERT INTO tenants (name) VALUES ('r1'), ('r2');
             INSERT INTO replication_sources (id, name, url, peer_id, cert_pin, tenants, schedule, gfs, state, created)
             VALUES (1, 'prim', '10.0.2.2:28443', '0123456789abcdef', 'PIN', '[\"r1\",\"r2\"]', 'hourly 00', '{\"daily\":7}', 'enrolling', 0);",
        )
        .unwrap();
    s.db.conn()
        .execute("UPDATE replication_sources SET cert_pin = ?1", [&pin])
        .unwrap();
    let sealed = s
        .secrets
        .public()
        .seal(
            &catalog::secret::replication_source_token_location(1, url, peer, &pin),
            "digest-of-token",
        )
        .unwrap();
    s.db.conn()
        .execute("UPDATE replication_sources SET token_hash = ?1", [&sealed])
        .unwrap();
    // replicated tenants: no keyd ensure, no backups, nothing before data arrived
    assert!(s.replicated_tenants().unwrap().contains_key("r1"));
    s.ensure_tenant_keys().unwrap();
    assert!(!s.keyed.contains("r1") && s.keyed.contains("t1"));
    let job = |kind: &str, t: &str, p: Value| Job {
        id: 0,
        kind: kind.into(),
        tenant: t.into(),
        params: p,
    };
    let err = s.plan(&job("backup", "r1", json!({"vmid": 100}))).unwrap_err();
    assert!(format!("{err:#}").contains("no local backups"), "{err:#}");
    let err = s.plan(&job("gc", "r1", json!({}))).unwrap_err();
    assert!(format!("{err:#}").contains("no replicated data yet"), "{err:#}");
    assert!(
        s.plan(&job("replica_sync", "r1", json!({"replication_source_id": 1})))
            .is_err(),
        "not enrolled"
    );
    assert!(s
        .replication_targets()
        .unwrap()
        .contains(&("10.0.2.2".to_string(), 28443)));

    // enrollment: token digest in the private job dir, result recorded, token consumed
    let en = manual(&s, "replica_enroll", "r1", json!({"replication_source_id": 1}));
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    assert_eq!(state(&s, en), "ok");
    assert_eq!(fs::read_to_string(dir.join("token-seen")).unwrap(), "digest-of-token");
    let cfg: Value = serde_json::from_slice(&fs::read(dir.join("replica-enroll.json")).unwrap()).unwrap();
    assert_eq!(cfg["url"], url);
    assert_eq!(cfg["cert_pin"].as_str(), Some(pin.as_str()));
    assert_eq!(cfg["cred_dir"], json!(e.cfg.replica_cred_dir(1)));
    let (st, fp, tok): (String, String, Option<String>) =
        s.db.conn()
            .query_row(
                "SELECT state, cert_sha256, token_hash FROM replication_sources",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
    assert_eq!((st.as_str(), fp, tok), ("enrolled", "c".repeat(64), None));
    let again = manual(&s, "replica_enroll", "r1", json!({"replication_source_id": 1}));
    s.start_jobs().unwrap();
    assert_eq!(state(&s, again), "failed", "the code is single use");

    // schedule: one sync per tenant per period
    let hour = 20_000 * 86400 + 10 * 3600;
    s.now = hour + 600;
    s.queue_replication(s.now).unwrap();
    let n = |s: &Scheduler| -> i64 {
        s.db.conn()
            .query_row("SELECT COUNT(*) FROM jobs WHERE kind='replica_sync'", [], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(n(&s), 0, "first sight");
    s.now = hour + 3600 + 5;
    s.queue_replication(s.now).unwrap();
    s.queue_replication(s.now).unwrap();
    assert_eq!(n(&s), 2, "one per tenant, not duplicated");
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    let cfg: Value = serde_json::from_slice(&fs::read(dir.join("replica-sync.json")).unwrap()).unwrap();
    assert_eq!(cfg["gfs"], json!({"daily": 7}));
    let status: Value = serde_json::from_str(
        &s.db
            .conn()
            .query_row("SELECT status FROM replication_sources", [], |r| r.get::<_, String>(0))
            .unwrap(),
    )
    .unwrap();
    assert!(status["r1"]["last_ok"].is_i64(), "{status}");
    assert_eq!(status["r1"]["imported"], 1);
    assert!(status["r2"]["last_error"].is_string(), "{status}");
    let kinds: Vec<String> = {
        let c = s.db.conn();
        let mut q = c.prepare("SELECT kind FROM alerts ORDER BY id").unwrap();
        let v = q.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
        v
    };
    assert!(kinds.contains(&"replication_keys".to_string()), "{kinds:?}");
    // the r2 sync failure is reported as replication_keys, not as a generic failure
    // (job_failed only for the re-used enrollment code above)
    assert_eq!(kinds.iter().filter(|k| *k == "job_failed").count(), 1, "{kinds:?}");
    // lag: r1 synced just now, r2 never (the source was created at 0)
    s.check_replication_lag(catalog::now()).unwrap();
    let lag = |s: &Scheduler| -> Vec<String> {
        let c = s.db.conn();
        let mut q = c
            .prepare("SELECT message FROM alerts WHERE kind='replication_lag' ORDER BY id")
            .unwrap();
        let v = q.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
        v
    };
    let l = lag(&s);
    assert_eq!(l.len(), 1, "{l:?}");
    assert!(l[0].contains("tenant r2"), "{l:?}");
    s.check_replication_lag(catalog::now() + 49 * 3600).unwrap();
    assert_eq!(lag(&s).len(), 2);
}

/// User decision 2026-10-10: a missing snapshot warns once per source (even after
/// the alert was acknowledged), files changed while read warn again after an ack.
#[test]
fn inconsistent_alerts_once_per_source() {
    let e = env(1);
    let s = sched(&e);
    let count = |s: &Scheduler| -> i64 {
        s.db.conn()
            .query_row(
                "SELECT COUNT(*) FROM alerts WHERE kind='backup_inconsistent'",
                [],
                |r| r.get(0),
            )
            .unwrap()
    };
    let ack = |s: &Scheduler| {
        s.db.conn().execute("UPDATE alerts SET acked_by='op'", []).unwrap();
    };
    let nosnap = "inconsistent share-6/100: consistent=false (no NAS snapshot; 0 files changed while read; 0 entries unreadable)\n";
    let changed = "inconsistent share-6/101: consistent=false (no NAS snapshot; 4 files changed while read; 0 entries unreadable)\n";
    s.inconsistent_alerts(1, "acme", nosnap).unwrap();
    s.inconsistent_alerts(2, "acme", nosnap).unwrap();
    assert_eq!(count(&s), 1, "missing snapshot: once");
    ack(&s);
    s.inconsistent_alerts(3, "acme", nosnap).unwrap();
    assert_eq!(count(&s), 1, "still once after the ack");
    s.inconsistent_alerts(4, "acme", "inconsistent share-7/1: consistent=false (no NAS snapshot; 0 files changed while read; 0 entries unreadable)\n").unwrap();
    assert_eq!(count(&s), 2, "other source: its own first warning");
    s.inconsistent_alerts(5, "acme", changed).unwrap();
    s.inconsistent_alerts(6, "acme", changed).unwrap();
    assert_eq!(count(&s), 3, "changed files: warned, deduplicated while unacknowledged");
    ack(&s);
    s.inconsistent_alerts(7, "acme", changed).unwrap();
    assert_eq!(count(&s), 4, "changed files warn again after an ack");
}
