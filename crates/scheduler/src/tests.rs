use super::*;
use catalog::secret::source_owner;
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
        inventory_secs: 0, // inventory_jobs turns it on
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
        cancels: Default::default(),
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
    assert_eq!(count(&s), 3, "changed files: warned, deduplicated while open");
    let max_count = |s: &Scheduler| -> i64 {
        s.db.conn()
            .query_row(
                "SELECT MAX(count) FROM alerts WHERE kind='backup_inconsistent'",
                [],
                |r| r.get(0),
            )
            .unwrap()
    };
    assert_eq!(max_count(&s), 2, "the repeat counted on the open alert");
    // user decision 2026-10-10: changed files warn again after an ack (13f: the
    // seen alert is closed and a new one raised)
    ack(&s);
    s.inconsistent_alerts(7, "acme", changed).unwrap();
    assert_eq!(count(&s), 4, "changed files warn again after the ack");
    s.inconsistent_alerts(8, "acme", changed).unwrap();
    assert_eq!(count(&s), 4, "counted while the new one is unacknowledged");
}

/// 13f lifecycle: a repeat counts on the open alert, a higher severity and the
/// reminder interval deliver it again, the success path resolves it (audited),
/// the next failure opens a new one; resolved alerts are pruned per severity.
#[test]
fn alert_lifecycle() {
    let e = env(1);
    let mut s = sched(&e);
    let due = |s: &mut Scheduler| -> Vec<i64> {
        let before: Vec<i64> = {
            let c = s.db.conn();
            let mut st = c
                .prepare("SELECT id FROM alerts WHERE notified_ts IS NULL ORDER BY id")
                .unwrap();
            st.query_map([], |r| r.get(0)).unwrap().map(|x| x.unwrap()).collect()
        };
        s.deliver_alerts().unwrap();
        before
    };
    let row = |s: &Scheduler, key: &str| -> (i64, i64, String, Option<i64>, i64) {
        s.db.conn()
            .query_row(
                "SELECT id, count, severity, resolved_at, auto FROM alerts WHERE key = ?1 ORDER BY id DESC LIMIT 1",
                [key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap()
    };
    s.raise(
        "warning",
        "offsite_lag",
        "offsite_lag:acme",
        "lags by 49 h",
        Some("acme"),
    )
    .unwrap();
    assert_eq!(due(&mut s).len(), 1);
    s.raise(
        "warning",
        "offsite_lag",
        "offsite_lag:acme",
        "lags by 50 h",
        Some("acme"),
    )
    .unwrap();
    let (id, n, sev, resolved, _) = row(&s, "offsite_lag:acme");
    assert_eq!((n, sev.as_str(), resolved), (2, "warning", None));
    assert!(due(&mut s).is_empty(), "a repeat is not delivered again");
    // escalation: delivered again, same row
    s.raise(
        "critical",
        "offsite_lag",
        "offsite_lag:acme",
        "lags by 99 h",
        Some("acme"),
    )
    .unwrap();
    assert_eq!(due(&mut s), [id]);
    assert_eq!(row(&s, "offsite_lag:acme").2, "critical");
    // reminder after 24 h while unacknowledged, not once acknowledged
    s.db.conn()
        .execute("UPDATE alerts SET notified_ts = notified_ts - 25 * 3600", [])
        .unwrap();
    s.deliver_alerts().unwrap();
    let t: i64 =
        s.db.conn()
            .query_row("SELECT notified_ts FROM alerts WHERE id = ?1", [id], |r| r.get(0))
            .unwrap();
    assert!(t > catalog::now() - 60, "reminded");
    s.db.conn()
        .execute(
            "UPDATE alerts SET notified_ts = notified_ts - 25 * 3600, acked_by = 'op'",
            [],
        )
        .unwrap();
    s.deliver_alerts().unwrap();
    let t2: i64 =
        s.db.conn()
            .query_row("SELECT notified_ts FROM alerts WHERE id = ?1", [id], |r| r.get(0))
            .unwrap();
    assert!(t2 < catalog::now() - 3600, "acknowledged: no reminder");
    // resolve: closed automatically and audited; the next failure is a new alert
    s.resolve("offsite_lag:acme").unwrap();
    let (_, _, _, resolved, auto) = row(&s, "offsite_lag:acme");
    assert!(resolved.is_some() && auto == 1);
    let audits: i64 =
        s.db.conn()
            .query_row("SELECT COUNT(*) FROM audit WHERE action = 'alert.resolve'", [], |r| {
                r.get(0)
            })
            .unwrap();
    assert_eq!(audits, 1);
    s.resolve("offsite_lag:acme").unwrap();
    s.raise("warning", "offsite_lag", "offsite_lag:acme", "lags again", Some("acme"))
        .unwrap();
    let (id2, n, _, resolved, _) = row(&s, "offsite_lag:acme");
    assert!(id2 > id && n == 1 && resolved.is_none());
    // pruning: resolved info alerts after 14 days, warnings after 180 (setting overrides)
    s.raise("info", "x", "x:1", "old info", None).unwrap();
    s.raise("warning", "y", "y:1", "old warning", None).unwrap();
    let old = catalog::now() - 20 * 86400;
    s.db.conn()
        .execute(
            "UPDATE alerts SET resolved_at = ?1 WHERE key IN ('x:1', 'y:1', 'offsite_lag:acme')",
            [old],
        )
        .unwrap();
    s.prune_alerts(catalog::now()).unwrap();
    let keys = |s: &Scheduler| -> Vec<String> {
        let c = s.db.conn();
        let mut st = c.prepare("SELECT key FROM alerts ORDER BY id").unwrap();
        st.query_map([], |r| r.get(0)).unwrap().map(|x| x.unwrap()).collect()
    };
    assert_eq!(keys(&s), ["offsite_lag:acme", "offsite_lag:acme", "y:1"]);
    catalog::set_setting(&s.db.conn(), "alert_retention_days", r#"{"warning": 10}"#).unwrap();
    s.prune_alerts(catalog::now()).unwrap();
    assert_eq!(
        keys(&s),
        ["offsite_lag:acme"],
        "the escalated (critical) one is kept 180 days"
    );
}

/// A failed job raises `job_failed:<tenant>/<kind>/<target>` with the tenant;
/// a repeat counts, the next successful run of the same job resolves it.
#[test]
fn job_failure_resolved_by_success() {
    let e = env(1);
    let mut s = sched(&e);
    let job = Job {
        id: 1,
        kind: "backup".into(),
        tenant: "acme".into(),
        params: json!({"group_id": 1}),
    };
    let key = lifecycle::job_failed_key(&job);
    assert_eq!(key, "job_failed:acme/backup/group/1");
    let other = Job {
        params: json!({"source_id": 3, "source": "vm-100"}),
        kind: "restore".into(),
        ..job.clone()
    };
    assert_eq!(
        lifecycle::job_failed_key(&other),
        "job_failed:acme/restore/source/3/vm-100"
    );
    let by_vmid = Job {
        params: json!({"vmid": 101}),
        ..job.clone()
    };
    assert_eq!(lifecycle::job_failed_key(&by_vmid), "job_failed:acme/backup/vmid/101");
    for _ in 0..2 {
        let id = manual(&s, "backup", "acme", json!({"group_id": 1}));
        let j = s.job(id).unwrap();
        s.fail_unstartable(&j, "no route to host").unwrap();
    }
    let (count, tenant, open): (i64, String, bool) =
        s.db.conn()
            .query_row(
                "SELECT count, tenant, resolved_at IS NULL FROM alerts WHERE key = ?1",
                [&key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
    assert_eq!((count, tenant.as_str(), open), (2, "acme", true));
    s.resolve_after_ok(&job).unwrap();
    let open: i64 =
        s.db.conn()
            .query_row("SELECT COUNT(*) FROM alerts WHERE resolved_at IS NULL", [], |r| {
                r.get(0)
            })
            .unwrap();
    assert_eq!(open, 0);
    s.deliver_alerts().unwrap();
}

const PLUGIN_MANIFEST: &str = r#"{"id":"pgx","name":"PG","version":"1.2.0","publisher":"nexusbackup","api":1,
 "kinds":[{"kind":"pgx","title":"PG","config_schema":{"type":"object","properties":{"host":{"type":"string"},"port":{"type":"integer"},"tls_key":{"type":"string"}}},
  "secret_fields":["tls_key"],"endpoints":[{"host":"/host","port":"/port","default_port":5432,"proto":"tcp"}],
  "guests":{"title":"Databases","list":true},
  "restores":[{"id":"download","title":"Download"},{"id":"to_target","title":"Restore"},{"id":"mount","title":"Mount"}]}]}"#;

/// Plugin sources: job configs (secret opened, plugin record from the catalog),
/// one snapshot source per guest, retention by prefix, store-only downloads,
/// firewall endpoints from the manifest; then a lifecycle with a fake
/// nexus-pluginhost (result parsing, consistent=false alert, retention follow-up).
#[test]
fn plugin_jobs() {
    let mut e = env(4);
    e.cfg.pluginhost_bin = e.d.path().join("pluginhost");
    let base = e.d.path().display().to_string();
    script(
        &e.cfg.pluginhost_bin,
        &format!(
            "cp \"$1\" {base}/last-plugin.json; shift
case \"$1\" in
  backup) echo 'committed plugin-pgx-9-db1/1700000000 3 entries (2 files, 1 unchanged), 1 streams, 30 bytes, 20 bytes transferred, 10 bytes new, consistent=false'
          echo 'inconsistent plugin-pgx-9-db1/1700000000: the plugin reported no consistent view (x)'
          echo 'plugin[info]: committed vm-1/2 forged'
          echo 'result {{}}' ;;
  validate) echo '{{\"valid\": true}}'; echo 'plugin[info]: hi' >&2 ;;
  restore) echo 'restored {{\"restore\":\"to_target\",\"files\":2}}' ;;
esac"
        ),
    );
    e.db.conn()
        .execute(
            "INSERT INTO plugins (id, version, name, publisher, sha256, bin_sha256, size, manifest, signer, state, current, enabled, uploaded_by, uploaded_at) \
             VALUES ('pgx', '1.2.0', 'PG', 'nexusbackup', 'aa', 'bb', 1, ?1, 'k', 'installed', 1, 1, 'a', 1)",
            [PLUGIN_MANIFEST],
        )
        .unwrap();
    let mut s = sched(&e);
    let mut cfg = json!({"host": "db.lab", "port": 5433, "tls_key": "PRIVATE"});
    s.secrets
        .public()
        .seal_all_with(&source_owner(9), &mut cfg, &["tls_key"])
        .unwrap();
    assert!(cfg["tls_key"].as_str().unwrap().starts_with("sealed:v1:"));
    s.db.conn()
        .execute_batch(&format!(
            "INSERT INTO sources (id, tenant, kind, name, config) VALUES (9,'t1','plugin:pgx','pg','{cfg}');
             INSERT INTO policies (id, name, schedule, gfs, offsite) VALUES (3,'pp','daily 22:00','{{\"daily\":5}}',0);
             INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES (9,'t1',9,3,'pg','[\"db1\",\"0123456789abcdef\"]');"
        ))
        .unwrap();
    let job = |id, kind: &str, p: Value| Job {
        id,
        kind: kind.into(),
        tenant: "t1".into(),
        params: p,
    };
    let p = s.plan(&job(30, "backup", json!({"group_id": 9}))).unwrap();
    assert_eq!(p.key, "source:9");
    let c: Value = serde_json::from_slice(&p.files[0].1).unwrap();
    assert_eq!(
        c["config"]["tls_key"], "PRIVATE",
        "secret opened into the 0600 job file"
    );
    assert_eq!(
        c["guests"],
        json!(["db1", "0123456789abcdef"]),
        "plugin guests are not agents"
    );
    assert_eq!(c["plugin"]["bin_sha256"], "bb");
    assert_eq!(c["plugin"]["dir"], json!(e.cfg.plugins_dir.join("pgx/1.2.0")));
    assert_eq!(c["kind"], "pgx");
    let g = s.groups().unwrap().into_iter().find(|g| g.id == 9).unwrap();
    assert!(g.agents.is_empty());
    assert_eq!(group_sources(&g), ["plugin-pgx-9-db1", "plugin-pgx-9-0123456789abcdef"]);
    let p = s
        .plan(&job(
            31,
            "retention",
            json!({"chain": true, "source_id": 9, "plugin": true}),
        ))
        .unwrap();
    assert!(
        matches!(&p.steps[..], [Step::Retention { sources, prefixes, gfs }] if sources == &["plugin-pgx-9"] && prefixes == &["plugin-pgx-9-"] && gfs.daily == 5)
    );
    let p = s
        .plan(&job(
            32,
            "files_get",
            json!({"source": "plugin-pgx-9-db1", "time": 5, "paths": ["/"], "format": "tar", "download_token": "a".repeat(64)}),
        ))
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&p.files[0].1).contains("PRIVATE"),
        "downloads get no secrets"
    );
    assert!(s
        .plan(&job(
            33,
            "files_list",
            json!({"source": "plugin-other-9", "time": 5, "path": "/"})
        ))
        .is_err());
    assert!(
        s.plan(&job(
            34,
            "plugin_restore",
            json!({"source": "plugin-pgx-9-db1", "time": 5})
        ))
        .is_err(),
        "restore id required"
    );
    let p = s
        .plan(&job(
            35,
            "plugin_mount",
            json!({"source": "plugin-pgx-9-db1", "time": 5, "minutes": 9999}),
        ))
        .unwrap();
    let c: Value = serde_json::from_slice(&p.files[0].1).unwrap();
    assert_eq!(c["mount"]["minutes"], 1440);
    assert_eq!(s.plugin_targets().unwrap(), [("db.lab".to_owned(), 5433)]);

    let b = manual(&s, "plugin_backup", "t1", json!({"source_id": 9}));
    let v = manual(&s, "plugin_validate", "t1", json!({"source_id": 9}));
    let r = manual(
        &s,
        "plugin_restore",
        "t1",
        json!({"source": "plugin-pgx-9-db1", "time": 1, "restore": "to_target", "params": {}}),
    );
    // jobs of one source run one after the other
    for _ in 0..3 {
        s.start_jobs().unwrap();
        s.wait_idle(Duration::from_secs(20)).unwrap();
    }
    for id in [b, v, r] {
        assert_eq!(state(&s, id), "ok", "job {id}");
    }
    let res = |id: i64| -> Value {
        let r: String =
            s.db.conn()
                .query_row("SELECT result FROM jobs WHERE id=?1", [id], |r| r.get(0))
                .unwrap();
        serde_json::from_str(&r).unwrap()
    };
    let lg: String =
        s.db.conn()
            .query_row("SELECT log FROM jobs WHERE id=?1", [b], |r| r.get(0))
            .unwrap();
    assert_eq!(res(b)["snapshots"][0]["source"], "plugin-pgx-9-db1", "{lg}");
    assert_eq!(res(b)["consistent"], false);
    assert_eq!(res(b)["transferred_bytes"], 20);
    assert_eq!(
        res(b)["snapshots"].as_array().unwrap().len(),
        1,
        "forged plugin line not parsed"
    );
    assert_eq!(res(v), json!({"valid": true}));
    assert_eq!(res(r)["files"], 2);
    let alerts: i64 = s
        .db
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM alerts WHERE kind='backup_inconsistent' AND message LIKE 'plugin-pgx-9-db1: not consistent%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(alerts, 1);
    let follow: i64 =
        s.db.conn()
            .query_row(
                "SELECT COUNT(*) FROM jobs WHERE kind='retention' AND json_extract(params,'$.source_id')=9",
                [],
                |r| r.get(0),
            )
            .unwrap();
    assert_eq!(follow, 1, "retention follow-up queued");
    // a disabled plugin's jobs fail before starting
    s.db.conn().execute("UPDATE plugins SET enabled = 0", []).unwrap();
    assert!(format!(
        "{:#}",
        s.plan(&job(40, "plugin_validate", json!({"source_id": 9})))
            .unwrap_err()
    )
    .contains("disabled"));
}

fn result_of(s: &Scheduler, id: i64) -> Value {
    let r: Option<String> =
        s.db.conn()
            .query_row("SELECT result FROM jobs WHERE id=?1", [id], |r| r.get(0))
            .unwrap();
    r.map(|r| serde_json::from_str(&r).unwrap()).unwrap_or(Value::Null)
}

/// Phase 12 §3: the alert test sends through the channels of the catalog
/// setting (the sealed SMTP password stays with the scheduler) and reports per channel.
#[test]
fn alert_test_uses_catalog_setting() {
    use std::io::{Read, Write};
    let e = env(4);
    let mut s = sched(&e);
    let none = manual(&s, "alert_test", "-", json!({}));
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    assert_eq!(state(&s, none), "ok");
    assert_eq!(result_of(&s, none), json!({}), "nothing configured, nothing tested");
    // a webhook receiver on loopback that answers 204 and records the body
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let got = std::thread::spawn(move || {
        let (mut c, _) = l.accept().unwrap();
        let mut buf = vec![0u8; 8192];
        let mut req = Vec::new();
        while !String::from_utf8_lossy(&req).contains("\"kind\":\"test\"") {
            let n = c.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            req.extend_from_slice(&buf[..n]);
        }
        c.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
        String::from_utf8_lossy(&req).into_owned()
    });
    // SMTP to a closed port: an error per channel, not a failed job
    let dead = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut v = json!({"webhook_url": format!("http://127.0.0.1:{port}/hook"), "min_severity": "warning",
                       "smtp": {"host": "127.0.0.1", "port": dead, "starttls": false, "from": "a@b.example",
                                "to": ["ops@b.example"], "user": "nexus", "password": "pw"}});
    s.secrets.public().seal_all(alerts::SETTING_OWNER, &mut v).unwrap();
    catalog::set_setting(&s.db.conn(), "alerts", &v.to_string()).unwrap();
    let id = manual(&s, "alert_test", "-", json!({}));
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(60)).unwrap();
    assert_eq!(state(&s, id), "ok");
    // the pre-13f setting is read as one rule `default`
    let r = result_of(&s, id);
    assert_eq!(r["default/webhook"], "ok", "{r}");
    assert!(r["default/email"].as_str().unwrap().starts_with("error: "), "{r}");
    let body = got.join().unwrap();
    assert!(
        body.contains("\"severity\":\"info\"") && body.contains("\"hint\":"),
        "{body}"
    );
    // the allow-list follows the setting, not alerts.json
    let targets = firewall::alert_targets(&s.alerts_config().unwrap());
    assert_eq!(targets, vec![("127.0.0.1".into(), port), ("127.0.0.1".into(), dead)]);
}

/// 13f rules: only matching rules deliver; a webhook template renders with
/// JSON escaping and the sealed header is sent; every rule webhook is an egress target.
#[test]
fn rule_webhook_template_delivery() {
    use std::io::{Read, Write};
    let e = env(1);
    let mut s = sched(&e);
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let got = std::thread::spawn(move || {
        let (mut c, _) = l.accept().unwrap();
        let mut buf = vec![0u8; 8192];
        let mut req = Vec::new();
        while !String::from_utf8_lossy(&req).ends_with('}') {
            let n = c.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            req.extend_from_slice(&buf[..n]);
        }
        c.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
        String::from_utf8_lossy(&req).into_owned()
    });
    let url = format!("http://127.0.0.1:{port}/hook");
    let sealed = s
        .secrets
        .public()
        .seal(
            &catalog::alerting::header_location("acme-chat", "X-Token", &url),
            "t0ken",
        )
        .unwrap();
    let rules = json!([
        {"name": "globex-only", "min_severity": "info", "tenants": ["globex"],
         "channels": {"webhook": {"url": "https://hooks.example:8443/x"}}},
        {"name": "acme-chat", "min_severity": "warning", "tenants": ["acme"], "kinds": ["job_failed"],
         "channels": {"webhook": {"url": url, "headers": {"X-Token": sealed},
            "template": "{\"text\": \"[{{severity}}] {{message}} ({{count}}x) {{alert_url}}\"}"}}}
    ]);
    catalog::set_setting(&s.db.conn(), "alert_rules", &rules.to_string()).unwrap();
    s.raise("info", "job_failed", "k:1", "below the rule's severity", Some("acme"))
        .unwrap();
    s.raise(
        "critical",
        "job_failed",
        "k:2",
        "backup \"nightly\" failed:\nno route",
        Some("acme"),
    )
    .unwrap();
    s.deliver_alerts().unwrap();
    let req = got.join().unwrap();
    assert!(req.to_ascii_lowercase().contains("x-token: t0ken"), "{req}");
    let body = &req[req.find("\r\n\r\n").unwrap() + 4..];
    let v: Value = serde_json::from_str(body).unwrap();
    let text = v["text"].as_str().unwrap();
    assert!(
        text.starts_with("[critical] backup \"nightly\" failed:\nno route (1x) https://"),
        "{text}"
    );
    assert!(text.ends_with("/#/alerts?id=2"), "{text}");
    let targets = firewall::alert_targets(&s.alerts_config().unwrap());
    assert_eq!(
        targets,
        vec![("hooks.example".into(), 8443), ("127.0.0.1".into(), port)]
    );
}

/// Phase 12 §4: keys generated at start and published; an approved rotation
/// becomes a job that adds `<name>.next`; retire swaps it in.
#[test]
fn ssh_keys_rotate_and_retire() {
    let mut e = env(4);
    let dir = e.d.path().join("ssh");
    fs::create_dir(&dir).unwrap();
    e.cfg.ssh_dir = dir.clone();
    // keys in use: a PVE node key and an SFTP offsite key, both hand-placed
    for name in ["pve", "offsite"] {
        let (pem, _) = sshkeys::generate("lab");
        fs::write(dir.join(name), pem.as_bytes()).unwrap();
    }
    let node = json!({"nodes": {"n1": {"host": "10.0.0.1", "key": dir.join("pve")}}});
    e.db.conn()
        .execute("UPDATE sources SET config = ?1 WHERE id = 1", [node.to_string()])
        .unwrap();
    let offsite = json!({"remote": {"type": "sftp", "host": "box", "key_file": dir.join("offsite")}});
    e.db.conn()
        .execute(
            "UPDATE tenants SET offsite = ?1 WHERE name = 't1'",
            [offsite.to_string()],
        )
        .unwrap();
    fs::write(dir.join("unused"), "x").unwrap();
    let mut s = sched(&e);
    // listed by name (offsite, pve); reversed here: [pve, offsite]
    let published = |s: &Scheduler| -> Value {
        let mut v: Vec<Value> =
            serde_json::from_str(&catalog::setting(&s.db.conn(), "ssh_keys").unwrap().unwrap()).unwrap();
        v.reverse();
        json!(v)
    };
    let keys = published(&s);
    assert_eq!(keys.as_array().unwrap().len(), 2, "only keys in use: {keys}");
    assert_eq!(
        (keys[0]["name"].as_str(), keys[1]["name"].as_str()),
        (Some("pve"), Some("offsite"))
    );
    assert_eq!(keys[1]["purpose"], sshkeys::PURPOSE_OFFSITE);
    assert!(keys[0]["public_key"].as_str().unwrap().starts_with("ssh-ed25519 "));
    let fp = keys[0]["fingerprint"].clone();
    // approved by someone else: executed even with approvals on
    s.db.conn()
        .execute(
            "INSERT INTO quorum (action, params, requested_by, created, decided_by, decided_at, state) \
             VALUES ('ssh_key.rotate', '{\"name\":\"pve\"}', 'alice', 1, 'sam', 2, 'approved')",
            [],
        )
        .unwrap();
    // decided by its requester (approvals were off) while approvals are on: not executed
    s.db.conn()
        .execute(
            "INSERT INTO quorum (action, params, requested_by, created, decided_by, decided_at, state) \
             VALUES ('ssh_key.rotate', '{\"name\":\"offsite\"}', 'alice', 1, 'alice', 2, 'approved')",
            [],
        )
        .unwrap();
    s.tick(catalog::now()).unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    let keys = published(&s);
    assert_eq!(keys[0]["previous"]["fingerprint"], fp, "old key still in use");
    let next = keys[0]["fingerprint"].clone();
    assert_ne!(next, fp);
    assert!(
        keys[1]["previous"].is_null(),
        "self-approved rotation waits while approvals are on"
    );
    let q: String =
        s.db.conn()
            .query_row("SELECT state FROM quorum WHERE id = 1", [], |r| r.get(0))
            .unwrap();
    assert_eq!(q, "executed");
    s.tick(catalog::now()).unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    let n: i64 =
        s.db.conn()
            .query_row("SELECT COUNT(*) FROM jobs WHERE kind = 'ssh_key_rotate'", [], |r| {
                r.get(0)
            })
            .unwrap();
    assert_eq!(n, 1, "one job per approval");
    let id = manual(&s, "ssh_key_retire", "-", json!({"name": "pve"}));
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    assert_eq!(state(&s, id), "ok");
    assert_eq!(result_of(&s, id)["new"], next);
    let keys = published(&s);
    assert_eq!(keys[0]["fingerprint"], next);
    assert!(keys[0]["previous"].is_null());
    // nothing to retire: the job fails
    let id = manual(&s, "ssh_key_retire", "-", json!({"name": "pve"}));
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    assert_eq!(state(&s, id), "failed");
}

/// Phase 12 §1: one capacity sample per tenant and day, plus the file system figures.
#[test]
fn capacity_samples_daily() {
    let e = env(4);
    let s = sched(&e);
    let t1 = e.cfg.store_base.join("t1");
    fs::create_dir_all(t1.join("chunks")).unwrap();
    fs::write(t1.join("chunks/a"), vec![0u8; 1000]).unwrap();
    fs::write(t1.join("keycheck"), b"x").unwrap();
    s.db.conn()
        .execute(
            "INSERT INTO snapshots (tenant, source, time, size, local, offsite) VALUES ('t1', 'vm-100', 5, 4000, 1, 0)",
            [],
        )
        .unwrap();
    let now = 1_791_750_000;
    s.sample_capacity(now).unwrap();
    let one = |sql: &str| -> i64 { s.db.conn().query_row(sql, [], |r| r.get(0)).unwrap() };
    let row: (String, i64, i64) =
        s.db.conn()
            .query_row(
                "SELECT day, used, logical FROM capacity_samples WHERE tenant = 't1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
    assert_eq!(row, ("2026-10-11".into(), 1001, 4000));
    // once per day: a second refresh the same day keeps the sample
    fs::write(t1.join("chunks/b"), vec![0u8; 5000]).unwrap();
    s.sample_capacity(now + 3600).unwrap();
    assert_eq!(one("SELECT used FROM capacity_samples WHERE tenant = 't1'"), 1001);
    s.sample_capacity(now + 86400).unwrap();
    assert_eq!(one("SELECT COUNT(*) FROM capacity_samples WHERE tenant = 't1'"), 2);
    let fsv: Value = serde_json::from_str(&catalog::setting(&s.db.conn(), "capacity").unwrap().unwrap()).unwrap();
    assert!(fsv["total"].as_u64().unwrap() > 0 && fsv["free"].as_u64().is_some());
    assert_eq!(
        one("SELECT COUNT(*) FROM capacity_samples WHERE tenant = 't2'"),
        0,
        "no store, no sample"
    );
}

/// Phase 13a: the gc job prunes sources no group covers (setting `orphan_gfs`),
/// alerts once per orphan and audits what it deleted; approved `snapshot.delete`
/// requests become `snapshot_delete` jobs (refused while locked).
#[test]
fn orphan_sweep_and_snapshot_delete() {
    let e = env(4);
    let mut s = sched(&e);
    let st = chunkstore::Store::open(
        e.cfg.store_base.join("t1"),
        Keyring::new("t1", &[(1, [7; 32])]),
        test_opts(),
    )
    .unwrap();
    let day = 86400;
    for src in ["vm-100", "vm-999", "ct-201"] {
        for t in [day, 2 * day, 3 * day] {
            st.commit_snapshot(src, t, &[("tree", chunkstore::Index::Tree { entries: vec![] })])
                .unwrap();
        }
    }
    catalog::set_setting(
        &s.db.conn(),
        orphans::ORPHAN_GFS,
        r#"{"daily":1,"weekly":0,"monthly":0,"yearly":0}"#,
    )
    .unwrap();
    let left = |src: &str| -> Vec<u64> {
        st.list_snapshots()
            .unwrap()
            .into_iter()
            .filter(|m| m.source == src)
            .map(|m| m.time)
            .collect()
    };
    let one = |s: &Scheduler, sql: &str| -> i64 { s.db.conn().query_row(sql, [], |r| r.get(0)).unwrap() };
    for _ in 0..2 {
        let id = manual(&s, "gc", "t1", json!({}));
        s.start_jobs().unwrap();
        s.wait_idle(Duration::from_secs(20)).unwrap();
        assert_eq!(state(&s, id), "ok");
    }
    assert_eq!(left("vm-100").len(), 3, "group-covered source untouched");
    assert_eq!(left("vm-999"), vec![3 * day]);
    assert_eq!(left("ct-201"), vec![3 * day]);
    assert_eq!(
        one(&s, "SELECT COUNT(*) FROM alerts WHERE kind = 'orphaned'"),
        2,
        "once per source"
    );
    let msg: String =
        s.db.conn()
            .query_row(
                "SELECT message FROM alerts WHERE kind = 'orphaned' ORDER BY id LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
    assert!(msg.starts_with("t1/ct-201 is in no protection group"), "{msg}");
    assert_eq!(
        one(&s, "SELECT COUNT(*) FROM audit WHERE action = 'retention.orphans'"),
        1,
        "audited only when something was deleted"
    );
    // replicated tenants keep the replication source's retention
    s.db.conn()
        .execute(
            "INSERT INTO replication_sources (id, name, url, peer_id, cert_pin, tenants, schedule, state, created) \
             VALUES (1, 'p', '10.0.2.2:28443', '0123456789abcdef', 'PIN', '[\"t1\"]', 'hourly 00', 'enrolled', 0)",
            [],
        )
        .unwrap();
    assert!(s.orphan_step("t1").unwrap().is_none());
    s.db.conn().execute("DELETE FROM replication_sources", []).unwrap();

    // approved deletes: one unlocked, one locked; a self-decided one waits while approvals are on
    st.extend_lock("vm-100", 2 * day, u64::MAX / 2).unwrap();
    for (t, by) in [(day, "sam"), (2 * day, "sam"), (3 * day, "alice")] {
        let p = json!({"tenant": "t1", "source": "vm-100", "time": t});
        s.db.conn()
            .execute(
                "INSERT INTO quorum (action, params, requested_by, created, decided_by, decided_at, state) \
                 VALUES ('snapshot.delete', ?1, 'alice', 1, ?2, 2, 'approved')",
                params![p.to_string(), by],
            )
            .unwrap();
    }
    catalog::set_setting(&s.db.conn(), "approvals_enabled", "true").unwrap();
    s.queue_snapshot_deletes().unwrap();
    s.queue_snapshot_deletes().unwrap();
    assert_eq!(
        one(&s, "SELECT COUNT(*) FROM jobs WHERE kind = 'snapshot_delete'"),
        2,
        "one job per approval"
    );
    for _ in 0..2 {
        // one per tenant at a time
        s.start_jobs().unwrap();
        s.wait_idle(Duration::from_secs(20)).unwrap();
    }
    assert_eq!(left("vm-100"), vec![2 * day, 3 * day]);
    assert_eq!(
        one(
            &s,
            "SELECT COUNT(*) FROM jobs WHERE kind = 'snapshot_delete' AND state = 'failed'"
        ),
        1
    );
    assert_eq!(one(&s, "SELECT COUNT(*) FROM quorum WHERE state = 'executed'"), 2);
    assert_eq!(
        one(&s, "SELECT COUNT(*) FROM audit WHERE action = 'snapshot.delete'"),
        1
    );
}

fn alerts_of(s: &Scheduler, kind: &str) -> Vec<(String, String)> {
    let c = s.db.conn();
    let mut q = c
        .prepare("SELECT severity, message FROM alerts WHERE kind = ?1 ORDER BY id")
        .unwrap();
    let rows = q.query_map([kind], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    rows.map(Result::unwrap).collect()
}

fn stats_line(source: &str, time: i64, plain: u64, stored: u64) -> String {
    format!(
        "nexus-stats {}\n",
        json!({"source": source, "time": time, "read": plain, "logical": 100 * plain,
               "new_chunks": 1, "new_plain": plain, "new_stored": stored})
    )
}

/// Phase 13d/e: a backup job's `nexus-stats` lines land in `backup_stats`
/// (idempotent), and a run far above the source's median raises one critical
/// `anomaly` alert naming the last snapshot before it.
#[test]
fn backup_stats_and_anomaly_alert() {
    let e = env(1);
    let mut s = sched(&e);
    fs::remove_file(e.d.path().join("pve")).unwrap();
    script(
        &e.d.path().join("pve"),
        &format!(
            "echo 'committed vm-100/1000'; echo '{}'",
            stats_line("vm-100", 1000, 5 << 20, 2 << 20).trim()
        ),
    );
    let id = manual(&s, "backup", "t1", json!({"group_id": 1}));
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    assert_eq!(state(&s, id), "ok");
    let row = |t: i64| -> (i64, i64, i64) {
        s.db.conn()
            .query_row(
                "SELECT logical, new_plain, new_stored FROM backup_stats WHERE tenant='t1' AND source='vm-100' AND time=?1",
                [t],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap()
    };
    assert_eq!(row(1000), (500 << 20, 5 << 20, 2 << 20));
    // a repeat of the same snapshot updates in place
    s.record_stats("t1", &stats_line("vm-100", 1000, 6 << 20, 3 << 20))
        .unwrap();
    assert_eq!(row(1000).1, 6 << 20);

    // history: 5 runs of ~1 GiB, snapshot 1004 kept
    const G: u64 = 1 << 30;
    for t in 1001..=1004 {
        s.record_stats("t1", &stats_line("vm-100", t, G, G / 2)).unwrap();
    }
    s.db.conn()
        .execute(
            "INSERT INTO snapshots (tenant, source, time, size, local, offsite) VALUES ('t1', 'vm-100', 1004, 1, 1, 0)",
            [],
        )
        .unwrap();
    assert!(alerts_of(&s, "anomaly").is_empty(), "not enough history yet");
    // 5 points now (6 MiB, 1 GiB × 4): median 1 GiB, limit 3 GiB
    s.record_stats("t1", &stats_line("vm-100", 1005, 3 * G, 3 * G / 2))
        .unwrap();
    assert!(alerts_of(&s, "anomaly").is_empty(), "at the limit");
    s.record_stats("t1", &stats_line("vm-100", 1006, 10 * G, 5 * G))
        .unwrap();
    let a = alerts_of(&s, "anomaly");
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].0, "critical");
    assert!(
        a[0].1
            .starts_with("change-rate anomaly on t1/vm-100: snapshot 1006: 10.0 GiB new data")
            && a[0].1.ends_with("last snapshot before: vm-100/1004"),
        "{}",
        a[0].1
    );
    // disabled by the setting
    catalog::set_setting(&s.db.conn(), "anomaly", r#"{"enabled": false}"#).unwrap();
    s.db.conn().execute("UPDATE alerts SET acked_by='op'", []).unwrap();
    s.record_stats("t1", &stats_line("vm-100", 1007, 50 * G, 25 * G))
        .unwrap();
    assert_eq!(alerts_of(&s, "anomaly").len(), 1);
}

/// Phase 13d: soft quota alerts from the latest capacity sample: warning at
/// 80 %, critical at 100 %; tenants without a quota never alert.
#[test]
fn quota_alerts() {
    let e = env(1);
    let s = sched(&e);
    let c = || s.db.conn();
    c().execute_batch(
        "UPDATE tenants SET quota_bytes = 1000 WHERE name = 't1';
         INSERT INTO capacity_samples (day, tenant, used, logical) VALUES
           ('2026-10-01', 't1', 100, 1), ('2026-10-02', 't1', 850, 1), ('2026-10-02', 't2', 999999, 1);",
    )
    .unwrap();
    s.check_quotas().unwrap();
    s.check_quotas().unwrap();
    let a = alerts_of(&s, "quota");
    assert_eq!(a.len(), 1, "deduplicated: {a:?}");
    assert_eq!(a[0].0, "warning");
    assert!(
        a[0].1.starts_with("tenant t1 uses over 80 % of its storage quota"),
        "{}",
        a[0].1
    );
    c().execute(
        "INSERT INTO capacity_samples (day, tenant, used, logical) VALUES ('2026-10-03', 't1', 1200, 1)",
        [],
    )
    .unwrap();
    s.check_quotas().unwrap();
    // 13f: the same key escalates the open alert instead of adding one
    let a = alerts_of(&s, "quota");
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].0, "critical");
    assert!(a[0].1.contains("120 %"), "{}", a[0].1);
    // back under 80 %: resolved by the scheduler
    c().execute(
        "INSERT INTO capacity_samples (day, tenant, used, logical) VALUES ('2026-10-04', 't1', 100, 1)",
        [],
    )
    .unwrap();
    s.check_quotas().unwrap();
    let open: i64 = c()
        .query_row(
            "SELECT COUNT(*) FROM alerts WHERE kind='quota' AND resolved_at IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(open, 0);
}

/// Phase 13c: inventory jobs per source (periodic, not doubled), `all` / `tags`
/// groups resolved from the inventory for plans and retention (exclude wins),
/// newly protected guests audited, gone guests dropped, failures one warning.
#[test]
fn inventory_jobs_and_auto_protect() {
    let mut e = env(4);
    let p = e.d.path().to_owned();
    script(
        &p.join("pve-inv"),
        &format!(
            "echo \"$@\" >> {0}/inv-calls\ncase \"$2\" in inventory) cat {0}/inv.json || exit 1 ;; *) echo done ;; esac",
            p.display()
        ),
    );
    e.cfg.pve_bin = p.join("pve-inv");
    e.cfg.inventory_secs = 3600;
    let inv = |ids: &[(u32, &str)]| {
        let g: Vec<Value> = ids
            .iter()
            .map(|(v, t)| json!({"id": v.to_string(), "title": format!("vm{v}"), "kind": "qemu", "tags": [t]}))
            .collect();
        fs::write(p.join("inv.json"), json!({ "guests": g }).to_string()).unwrap();
    };
    inv(&[(100, "pool:prod"), (101, "pool:prod"), (102, "tag:web")]);
    e.db.conn()
        .execute_batch(
            r#"UPDATE groups SET mode='all', guests='[]', exclude='["101"]' WHERE id=1;
               UPDATE groups SET mode='tags', guests='[]', selector='["pool:prod"]' WHERE id=3;"#,
        )
        .unwrap();
    let mut s = sched(&e);
    let jobs = |s: &Scheduler| -> i64 {
        s.db.conn()
            .query_row("SELECT COUNT(*) FROM jobs WHERE kind='inventory'", [], |r| r.get(0))
            .unwrap()
    };
    let t0 = 1_000_000;
    s.now = t0;
    s.queue_inventory(t0).unwrap();
    s.queue_inventory(t0).unwrap();
    assert_eq!(jobs(&s), 3, "one per pve source, not doubled");
    // before the first listing an auto group protects nothing
    let g1 = |s: &Scheduler| s.groups().unwrap().into_iter().find(|g| g.id == 1).unwrap();
    assert!(g1(&s).guests.is_empty() && g1(&s).auto);
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    let n: i64 =
        s.db.conn()
            .query_row(
                "SELECT COUNT(*) FROM inventory WHERE source_id=1 AND gone IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
    assert_eq!(n, 3);
    assert_eq!(g1(&s).guests, vec![100, 102], "all minus exclude");
    let g3 = s.groups().unwrap().into_iter().find(|g| g.id == 3).unwrap();
    assert_eq!(g3.guests, vec![100, 101], "tags");
    assert_eq!(group_sources(&g3), ["vm-100", "ct-100", "vm-101", "ct-101"]);
    let audited: i64 = s
        .db
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM audit WHERE action='group.auto_protect' AND target='group/1' AND details LIKE '%102%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(audited, 1);
    // the backup plan backs up the resolved set
    let job = Job {
        id: 99,
        kind: "backup".into(),
        tenant: "t1".into(),
        params: json!({"group_id": 1}),
    };
    let plan = s.plan(&job).unwrap();
    let cfg: Value = serde_json::from_slice(&plan.files.iter().find(|f| f.0 == "pve.json").unwrap().1).unwrap();
    assert_eq!(cfg["vmids"], json!([100, 102]));
    // within the interval nothing is queued; afterwards the next round
    s.queue_inventory(t0 + 60).unwrap();
    assert_eq!(jobs(&s), 3);
    // 102 disappears: no longer selected, row kept as gone
    inv(&[(100, "pool:prod"), (101, "pool:prod")]);
    s.now = t0 + 3601;
    s.queue_inventory(t0 + 3601).unwrap();
    assert_eq!(jobs(&s), 6);
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    assert_eq!(g1(&s).guests, vec![100]);
    let gone: Option<i64> =
        s.db.conn()
            .query_row(
                "SELECT gone FROM inventory WHERE source_id=1 AND guest='102'",
                [],
                |r| r.get(0),
            )
            .unwrap();
    assert!(gone.is_some());
    // an unreachable source: a warning, once while open
    fs::remove_file(p.join("inv.json")).unwrap();
    for i in 0..2 {
        let id = manual(&s, "inventory", "t1", json!({"source_id": 1}));
        s.start_jobs().unwrap();
        s.wait_idle(Duration::from_secs(20)).unwrap();
        assert_eq!(state(&s, id), "failed", "run {i}");
    }
    let (n, sev): (i64, String) =
        s.db.conn()
            .query_row(
                "SELECT COUNT(*), MAX(severity) FROM alerts WHERE kind='inventory_refresh'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
    assert_eq!((n, sev.as_str()), (1, "warning"));
    // the failed listing kept the last inventory
    assert_eq!(g1(&s).guests, vec![100]);
    // inventory of another tenant's source is refused
    let id = manual(&s, "inventory", "t2", json!({"source_id": 1}));
    s.start_jobs().unwrap();
    assert_eq!(state(&s, id), "failed");
}
/// Phase 14d certificate / secret / token expiry alerts.
mod expiry;
/// Phase 14e scheduled reports.
mod report_mail;
/// Phase 13b run control (pause, blackout, retries, SLA, cancel).
mod runctl;
