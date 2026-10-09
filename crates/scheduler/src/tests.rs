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
    assert_eq!(s.db.verify_audit().unwrap(), 1);
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
