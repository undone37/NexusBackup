//! Scheduler loop against a temp catalog, a real chunk store and fake
//! `nexus-pve` / `nexus-offsite` shell scripts; alerts go to a local webhook.

use catalog::Catalog;
use chunkstore::{Keyring, Options, Store};
use scheduler::run::KeySource;
use scheduler::schedule::Schedule;
use scheduler::{Config, Scheduler};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::Duration;

const DAY: i64 = 86400;
const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn keys(t: &str) -> Keyring {
    Keyring::new(t, &[(1, [42; 32])])
}

fn opts() -> Options {
    Options {
        min_lock_secs: 0,
        gc_grace_secs: 0,
        ..Default::default()
    }
}

fn script(path: &Path, body: &str) {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(path)
        .unwrap();
    f.write_all(format!("#!/bin/sh\n{body}\n").as_bytes()).unwrap();
}

/// Minimal HTTP server: every POST body goes into the channel.
fn webhook() -> (String, Receiver<Value>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/hook", l.local_addr().unwrap());
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let mut s = s.unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut len = 0;
            loop {
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            let mut body = vec![0; len];
            r.read_exact(&mut body).unwrap();
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
            let _ = tx.send(serde_json::from_slice(&body).unwrap());
        }
    });
    (url, rx)
}

/// Deterministic pseudo-random image, distinct per seed.
fn image(seed: u64) -> Vec<u8> {
    let mut x = 0x9e37_79b9_7f4a_7c15u64 ^ seed.wrapping_mul(0x2545_f491_4f6c_dd1d);
    (0..256 * 1024)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn q<T: catalog::rusqlite::types::FromSql>(db: &Catalog, sql: &str) -> T {
    db.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

#[test]
fn job_lifecycle_followups_alerts() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path();
    let (url, hook) = webhook();
    fs::write(
        p.join("alerts.json"),
        json!({"webhook": {"url": url, "headers": {"X-Test": "1"}}}).to_string(),
    )
    .unwrap();

    // fake CLIs: record calls, the generated config and its mode
    script(
        &p.join("nexus-pve"),
        &format!(
            r#"D={d}
cfg="$1"; shift
echo "$@" >> $D/pve-calls
stat -c %a "$cfg" > $D/pve-mode; cp "$cfg" $D/pve-last.json
case "$1" in
  backup-all) if [ -e $D/fail-backup ]; then echo "backup of guest 100 failed: boom" >&2; exit 1; fi
              echo "committed vm-100/1";;
  files|ct-files) if [ "$4" = get ]; then echo payload > "$5"; echo "1 entries written to $5"
                  else echo '[{{"name":"etc","kind":"dir"}}]'; fi;;
  *) echo "unknown command" >&2; exit 2;;
esac"#,
            d = p.display()
        ),
    );
    script(
        &p.join("nexus-offsite"),
        &format!(
            r#"D={d}
cfg="$1"; shift
echo "$@" >> $D/offsite-calls; cp "$cfg" $D/offsite-last.json
case "$1" in
  list) cat $D/offsite-list 2>/dev/null;;
  check) if [ -e $D/fail-check ]; then echo "offsite inventory anomaly: 1 expected files missing" >&2; exit 1; fi;;
  *) echo "offsite $1 ok";;
esac"#,
            d = p.display()
        ),
    );

    let cfg = Config {
        catalog: p.join("catalog/catalog.db"),
        store_base: p.join("store"),
        offsite_state_base: p.join("offsite"),
        escrow_base: p.join("escrow"),
        downloads: p.join("downloads"),
        runtime_dir: p.join("run"),
        state_dir: p.join("state"),
        pve_bin: p.join("nexus-pve"),
        offsite_bin: p.join("nexus-offsite"),
        alerts_config: p.join("alerts.json"),
        maintenance: "daily 03:00".into(),
        alert_retry_secs: [0, 0],
        capacity_threshold: 2.0, // never in tests
        ..Default::default()
    };
    fs::create_dir_all(p.join("catalog")).unwrap();
    let db = Arc::new(Catalog::open(&cfg.catalog).unwrap());

    // fake "now": the next 22:00 slot (UTC) after the real clock
    let backup = Schedule::parse("daily 22:00").unwrap();
    let slot = backup.last_slot(catalog::now()) + DAY;

    // local store with 5 daily snapshots of vm-100 (distinct data)
    let store = Store::open(p.join("store/acme"), keys("acme"), opts()).unwrap();
    let times: Vec<u64> = (1..=5).map(|k| (slot - k * DAY) as u64).collect();
    for (i, t) in times.iter().enumerate() {
        let idx = store.store_image(&image(i as u64)[..], 64 * 1024).unwrap();
        store.commit_snapshot("vm-100", *t, &[("drive-scsi0", idx)]).unwrap();
    }
    drop(store);
    // a reopened compliance clock resumes from its persisted value (up to a minute
    // old); move it past the commit locks (min_lock_secs = 0) so retention may delete
    fs::write(p.join("store/acme/clock"), format!("{}\n", catalog::now() + 120)).unwrap();

    let src = json!({"host": "pve1", "port": 8006, "ca_pem": "-----BEGIN CERTIFICATE-----", "token_id": "nexus@pve!b",
                     "token_secret": "TOPSECRET", "storage": "nexus", "fleecing_storage": "local-lvm",
                     "nodes": [{"name": "pve1", "host": "10.0.0.5", "key": "/etc/nexus/ssh/id", "known_hosts": "/etc/nexus/ssh/kh"}]});
    let offsite = json!({"remote": {"type": "sftp", "host": "box", "user": "u1", "host_key": "ssh-ed25519 AAAA",
                                    "key_pem": "-----BEGIN OPENSSH PRIVATE KEY-----"}, "uploaders": 2});
    db.conn()
        .execute_batch(&format!(
            "INSERT INTO tenants (name, offsite) VALUES ('acme', '{offsite}');
             INSERT INTO sources (id, tenant, kind, name, config) VALUES (1, 'acme', 'pve', 'cluster', '{src}');
             INSERT INTO policies (id, name, schedule, gfs, offsite) VALUES
               (1, 'gold', 'daily 22:00', '{{\"daily\":2,\"weekly\":0,\"monthly\":0,\"yearly\":0}}', 1);
             INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES (1, 'acme', 1, 1, 'web', '[100]');"
        ))
        .unwrap();
    // offsite holds the newest snapshot only
    fs::write(p.join("offsite-list"), format!("vm-100/{}\n", times[0])).unwrap();

    let k: KeySource = Arc::new(|t: &str| Ok(keys(t)));
    let mut s = Scheduler::new(cfg.clone(), db.clone(), k, opts).unwrap();
    let wait = Duration::from_secs(30);
    let run = |s: &mut Scheduler, now: i64| {
        // tick until nothing is queued or running
        for _ in 0..10 {
            s.tick(now).unwrap();
            s.wait_idle(wait).unwrap();
            if q::<i64>(&db, "SELECT COUNT(*) FROM jobs WHERE state='queued'") == 0 {
                return;
            }
        }
        panic!("jobs still queued");
    };

    // 1. first tick before the slot: nothing scheduled yet, snapshots refreshed
    run(&mut s, slot - 60);
    assert_eq!(q::<i64>(&db, "SELECT COUNT(*) FROM jobs"), 0);
    assert_eq!(q::<i64>(&db, "SELECT COUNT(*) FROM snapshots WHERE local=1"), 5);
    assert_eq!(q::<i64>(&db, "SELECT COUNT(*) FROM snapshots WHERE offsite=1"), 1);
    // offsite lag: 4 local-only snapshots, oldest 5 days old
    assert_eq!(q::<i64>(&db, "SELECT COUNT(*) FROM alerts WHERE kind='offsite_lag'"), 1);

    // 2. the slot: backup -> retention -> offsite, all ok
    run(&mut s, slot + 5);
    let jobs: Vec<(String, String, String)> = {
        let c = db.conn();
        let mut st = c
            .prepare("SELECT kind, state, requested_by FROM jobs ORDER BY id")
            .unwrap();
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
        rows.map(Result::unwrap).collect()
    };
    let kinds: Vec<(&str, &str)> = jobs.iter().map(|j| (j.0.as_str(), j.1.as_str())).collect();
    assert_eq!(kinds, [("backup", "ok"), ("retention", "ok"), ("offsite", "ok")]);
    assert!(jobs.iter().all(|j| j.2 == "scheduler"));
    let bp: String = q(&db, "SELECT params FROM jobs WHERE kind='backup'");
    assert_eq!(
        bp, r#"{"group_id":1}"#,
        "web-api's last-backup metric needs {{group_id}}"
    );
    let log: String = q(&db, "SELECT log FROM jobs WHERE kind='backup'");
    assert!(
        log.contains("backup-all") && log.contains("committed vm-100/1"),
        "{log}"
    );
    let br: Value = serde_json::from_str(&q::<String>(&db, "SELECT result FROM jobs WHERE kind='backup'")).unwrap();
    assert_eq!(
        br,
        json!({"snapshots": [{"source": "vm-100", "time": 1}], "source": "vm-100", "time": 1})
    );
    let log: String = q(&db, "SELECT log FROM jobs WHERE kind='retention'");
    assert!(log.contains("retention vm-100: kept 2, deleted 3"), "{log}");
    let log: String = q(&db, "SELECT log FROM jobs WHERE kind='offsite'");
    assert!(
        log.contains("upload") && log.contains("check") && log.contains("retention"),
        "{log}"
    );
    // generated configs: 0600, secrets in files, paths per tenant
    assert_eq!(fs::read_to_string(p.join("pve-mode")).unwrap().trim(), "600");
    let pc: Value = serde_json::from_str(&fs::read_to_string(p.join("pve-last.json")).unwrap()).unwrap();
    assert_eq!(pc["vmids"], json!([100]));
    assert_eq!(pc["tenant"], "acme");
    assert_eq!(pc["nodes"]["pve1"]["key"], "/etc/nexus/ssh/id");
    assert!(!pc.to_string().contains("TOPSECRET"));
    let oc: Value = serde_json::from_str(&fs::read_to_string(p.join("offsite-last.json")).unwrap()).unwrap();
    assert_eq!(oc["gfs"]["daily"], 2);
    assert_eq!(oc["uploaders"], 2);
    assert_eq!(oc["escrow_dir"], json!(p.join("escrow/acme")));
    assert!(oc["remote"]["key_file"].as_str().unwrap().ends_with("offsite.key"));
    assert!(oc["remote"]["key_pem"].is_null());
    assert_eq!(
        fs::read_dir(p.join("run")).unwrap().count(),
        0,
        "job dirs (secrets) removed"
    );
    // snapshots refreshed after retention: 2 local left, lock extended
    assert_eq!(q::<i64>(&db, "SELECT COUNT(*) FROM snapshots WHERE local=1"), 2);
    assert!(q::<i64>(&db, "SELECT MIN(lock_until) FROM snapshots WHERE local=1") > slot);

    // 3. no second run in the same period
    run(&mut s, slot + 3600);
    assert_eq!(q::<i64>(&db, "SELECT COUNT(*) FROM jobs WHERE kind='backup'"), 1);

    // 4. maintenance at 03:00: gc needs quorum (3 of 5 snapshots' chunks unreferenced), verify ok
    let maint = slot + 5 * 3600;
    run(&mut s, maint);
    assert_eq!(q::<String>(&db, "SELECT state FROM jobs WHERE kind='gc'"), "failed");
    assert_eq!(q::<String>(&db, "SELECT state FROM jobs WHERE kind='verify'"), "ok");
    assert!(q::<i64>(&db, "SELECT MIN(verified) FROM snapshots WHERE local=1") > 0);
    let (qid, qstate, qparams): (i64, String, String) = db
        .conn()
        .query_row(
            "SELECT id, state, params FROM quorum WHERE action='gc_large'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(qstate, "pending");
    assert!(qparams.contains("\"tenant\":\"acme\""));
    assert_eq!(q::<i64>(&db, "SELECT COUNT(*) FROM alerts WHERE kind='gc_quorum'"), 1);
    assert_eq!(q::<i64>(&db, "SELECT COUNT(*) FROM alerts WHERE kind='job_failed'"), 0);
    // a security officer approves; the scheduler runs gc with the approval flag
    db.conn()
        .execute(
            "UPDATE quorum SET state='approved', decided_by='so', decided_at=1 WHERE id=?1",
            [qid],
        )
        .unwrap();
    run(&mut s, maint + 60);
    let (st, log, gp): (String, String, String) = db
        .conn()
        .query_row(
            "SELECT state, log, params FROM jobs WHERE kind='gc' ORDER BY id DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(st, "ok", "{log}");
    assert!(
        log.contains("quorum approved") && log.contains("offsite gc ok"),
        "{log}"
    );
    assert!(gp.contains(&format!("\"quorum_id\":{qid}")));
    assert_eq!(q::<String>(&db, "SELECT state FROM quorum"), "executed");
    assert_eq!(
        q::<i64>(&db, "SELECT COUNT(*) FROM jobs WHERE kind='gc'"),
        2,
        "executed once"
    );

    // 5. file restore: download with unguessable token, expiring after 24 h
    db.conn()
        .execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES ('files_get','acme',?1,'queued','bob',1)",
            [json!({"source": "vm-100", "time": times[0], "paths": ["/etc/hosts"], "format": "zip", "download_token": TOKEN}).to_string()],
        )
        .unwrap();
    db.conn()
        .execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES ('files_list','acme',?1,'queued','bob',1)",
            [json!({"source": "vm-100", "time": times[0], "path": "/"}).to_string()],
        )
        .unwrap();
    run(&mut s, maint + 120);
    let gp: Value = serde_json::from_str(&q::<String>(
        &db,
        "SELECT result FROM jobs WHERE kind='files_get' AND state='ok'",
    ))
    .unwrap();
    let token = gp["download_token"].as_str().unwrap();
    assert_eq!(token, TOKEN, "the web-api's token names the file");
    let file = p.join("downloads").join(format!("{token}.zip"));
    assert_eq!(fs::read_to_string(&file).unwrap(), "payload\n");
    assert_eq!(fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o640);
    assert_eq!(gp["size"], 8);
    assert_eq!(gp["format"], "zip");
    assert_eq!(gp["entries"], 1);
    let lp: Value = serde_json::from_str(&q::<String>(&db, "SELECT result FROM jobs WHERE kind='files_list'")).unwrap();
    assert_eq!(lp["entries"][0]["name"], "etc");
    let calls = fs::read_to_string(p.join("pve-calls")).unwrap();
    assert!(
        calls.contains(&format!("files 100 {} get {}", times[0], file.display())),
        "{calls}"
    );
    // expiry
    fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - Duration::from_secs(25 * 3600))
        .unwrap();
    s.tick(maint + 180).unwrap();
    assert!(!file.exists());

    // 6. next day: backup fails -> no follow-ups, alert; offsite check failure -> inventory alert
    fs::write(p.join("fail-backup"), "").unwrap();
    run(&mut s, slot + DAY + 10);
    assert_eq!(
        q::<String>(
            &db,
            "SELECT state FROM jobs WHERE kind='backup' ORDER BY id DESC LIMIT 1"
        ),
        "failed"
    );
    assert_eq!(q::<i64>(&db, "SELECT COUNT(*) FROM jobs WHERE kind='retention'"), 1);
    let msg: String = q(&db, "SELECT message FROM alerts WHERE kind='job_failed'");
    assert!(msg.contains("boom"), "{msg}");
    fs::write(p.join("fail-check"), "").unwrap();
    db.conn()
        .execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES ('offsite','acme','{}','queued','bob',1)",
            [],
        )
        .unwrap();
    run(&mut s, slot + DAY + 20);
    assert_eq!(q::<i64>(&db, "SELECT COUNT(*) FROM alerts WHERE kind='inventory'"), 1);
    let off = fs::read_to_string(p.join("offsite-calls")).unwrap();
    assert!(
        off.trim_end().ends_with("check"),
        "retention not run after a failed check:\n{off}"
    );

    // every alert reached the webhook (alerts raised by the last job go out with the next tick)
    s.tick(slot + DAY + 30).unwrap();
    let mut got: Vec<String> = Vec::new();
    while got.len() < 4 {
        let a = hook.recv_timeout(Duration::from_secs(20)).expect("webhook delivery");
        assert!(a["id"].as_i64().is_some() && a["message"].is_string());
        got.push(a["kind"].as_str().unwrap().to_owned());
    }
    got.sort();
    assert_eq!(got, ["gc_quorum", "inventory", "job_failed", "offsite_lag"]);

    // every job state change audited by the scheduler; chain intact
    let n = db.verify_audit().unwrap();
    let jobs: i64 = q(&db, "SELECT COUNT(*) FROM jobs");
    let ours: i64 = q(&db, "SELECT COUNT(*) FROM jobs WHERE requested_by='scheduler'");
    let audited: i64 = q(
        &db,
        "SELECT COUNT(*) FROM audit WHERE actor='scheduler' AND action LIKE 'job.%'",
    );
    assert_eq!(audited, ours + 2 * jobs, "queue (own jobs) + start + finish");
    assert!(n > audited);
}
