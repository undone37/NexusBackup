//! Phase 28: scheduled threat scans, the IOC hash hunt, file hashes in backup
//! configs, the tenant lockdown's job refusals and the new-device mail address.

use super::*;
use chunkstore::{Index, Store, TreeEntry, TreeKind};

const DAY: i64 = 86400;
/// 2023-11-14 22:13:20 UTC: the next `daily 02:00` slot is the following night
const T0: i64 = 1_700_000_000;

fn scanner(e: &Env, report: Value) {
    let d = e.d.path();
    fs::remove_file(&e.cfg.pve_bin).unwrap();
    script(
        &e.cfg.pve_bin,
        &format!(
            "echo \"$@\" >> {0}/calls\nif [ \"$2\" = scan ]; then cat {0}/scan.json || exit 1; else echo done; fi",
            d.display()
        ),
    );
    fs::write(d.join("scan.json"), report.to_string()).unwrap();
}

fn report(matches: u64, complete: bool) -> Value {
    let m: Vec<Value> = (0..matches)
        .map(|i| json!({"rule": "r.yar:Eicar", "path": format!("/vda1/f{i}.exe")}))
        .collect();
    json!({"files": 10, "skipped": 0, "errors": 0, "matches": m, "matches_total": matches, "complete": complete,
           "seconds": 3})
}

fn run_all(s: &mut Scheduler) {
    for _ in 0..4 {
        s.start_jobs().unwrap();
        s.wait_idle(Duration::from_secs(20)).unwrap();
    }
}

fn scans(s: &Scheduler) -> Vec<(i64, Value)> {
    let c = s.db.conn();
    let mut q = c
        .prepare("SELECT id, params FROM jobs WHERE kind='snapshot_scan' ORDER BY id")
        .unwrap();
    q.query_map([], |r| {
        Ok((r.get(0)?, serde_json::from_str(&r.get::<_, String>(1)?).unwrap()))
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

/// The scan part of a tick at `now` (jobs get `created = now`).
fn tick_scans(s: &mut Scheduler, now: i64) {
    s.now = now;
    s.queue_threat_scans(now).unwrap();
}

fn scan_state(s: &Scheduler, source: &str, time: i64) -> Option<String> {
    s.db.conn()
        .query_row(
            "SELECT scan_state FROM snapshots WHERE tenant='t1' AND source=?1 AND time=?2",
            params![source, time],
            |r| r.get(0),
        )
        .unwrap()
}

/// A group with a scan schedule gets one scheduled scan of the newest snapshot
/// of each source when the slot is due; the verdict lands in `scan_state`, a hit
/// raises `scan_hit`; a scanned snapshot is not scanned again; no rules, no scans.
#[test]
fn scheduled_scans_of_the_newest_snapshot() {
    let e = env(2);
    let mut s = sched(&e);
    s.db.conn()
        .execute_batch(
            "UPDATE groups SET scan_schedule = 'daily 02:00', scan_budget_min = 30 WHERE id = 1;
             INSERT INTO snapshots (tenant, source, time, size, local, offsite, lock_until) VALUES
               ('t1','vm-100',4,1,1,0,0), ('t1','vm-100',5,1,1,0,0), ('t1','vm-101',5,1,1,0,0),
               ('t2','vm-300',5,1,1,0,0);",
        )
        .unwrap();
    // without YARA rules nothing is queued
    tick_scans(&mut s, T0);
    tick_scans(&mut s, T0 + DAY);
    assert!(scans(&s).is_empty());
    s.db.conn()
        .execute(
            "INSERT INTO yara_rules VALUES ('r.yar', 'rule Eicar { condition: true }', 'abcdef0123456789', 'sam', 1)",
            [],
        )
        .unwrap();
    // first sight: no run; the next slot: vm-100/5 only (group 1, newest)
    tick_scans(&mut s, T0 + DAY);
    assert!(scans(&s).is_empty());
    tick_scans(&mut s, T0 + 2 * DAY);
    let q = scans(&s);
    assert_eq!(q.len(), 1, "{q:?}");
    assert_eq!(
        q[0].1,
        json!({"source": "vm-100", "time": 5, "group_id": 1, "scheduled": true, "budget": 1800})
    );
    // not twice while it waits
    tick_scans(&mut s, T0 + 3 * DAY);
    assert_eq!(scans(&s).len(), 1);
    scanner(&e, report(1, true));
    run_all(&mut s);
    assert_eq!(state(&s, q[0].0), "ok");
    assert_eq!(scan_state(&s, "vm-100", 5).as_deref(), Some("hit"));
    let (kind, msg): (String, String) =
        s.db.conn()
            .query_row(
                "SELECT kind, message FROM alerts WHERE kind IN ('scan_hit','malware')",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
    assert_eq!(kind, "scan_hit");
    assert!(msg.starts_with("Scheduled YARA scan of t1/vm-100 snapshot 5"), "{msg}");
    // scanned: the next slot queues nothing; a new snapshot is scanned
    tick_scans(&mut s, T0 + 4 * DAY);
    assert_eq!(scans(&s).len(), 1);
    s.db.conn()
        .execute(
            "INSERT INTO snapshots (tenant, source, time, size, local, offsite, lock_until) VALUES ('t1','vm-100',6,1,1,0,0)",
            [],
        )
        .unwrap();
    tick_scans(&mut s, T0 + 5 * DAY);
    assert_eq!(scans(&s).len(), 2);
    scanner(&e, report(0, true));
    run_all(&mut s);
    assert_eq!(scan_state(&s, "vm-100", 6).as_deref(), Some("clean"));
    assert_eq!(scan_state(&s, "vm-100", 4), None, "unscanned");
    // "latest clean" prefers the scanned-clean snapshot
    assert_eq!(
        s.last_clean("t1", "vm-100", 7).unwrap(),
        "last scanned-clean snapshot before: vm-100/6"
    );
    assert_eq!(
        s.last_clean("t1", "vm-100", 5).unwrap(),
        "last snapshot before: vm-100/4"
    );
    // restore priority: nothing is queued
    s.db.conn()
        .execute(
            "INSERT INTO snapshots (tenant, source, time, size, local, offsite, lock_until) VALUES ('t1','vm-100',8,1,1,0,0)",
            [],
        )
        .unwrap();
    s.db.conn()
        .execute("UPDATE groups SET scan_schedule = 'nonsense' WHERE id = 1", [])
        .unwrap();
    tick_scans(&mut s, T0 + 6 * DAY);
    assert_eq!(scans(&s).len(), 2, "invalid schedule: an alert, no scan");
    let n: i64 =
        s.db.conn()
            .query_row(
                "SELECT COUNT(*) FROM alerts WHERE kind='config' AND message LIKE '%threat scan schedule%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
    assert_eq!(n, 1);
}

fn file(path: &str, st: &chunkstore::FileStats, size: u64) -> TreeEntry {
    TreeEntry {
        path: path.as_bytes().to_vec(),
        kind: TreeKind::File,
        mode: 0o644,
        uid: 0,
        gid: 0,
        size,
        mtime_ns: 0,
        ctime_ns: 0,
        inode: 0,
        rdev: 0,
        link_target: None,
        xattrs: Vec::new(),
        chunks: st.chunks.clone(),
        inconsistent: false,
    }
}

fn store(e: &Env, tenant: &str) -> Store {
    Store::open(
        e.cfg.store_base.join(tenant),
        Keyring::new(tenant, &[(1, [7; 32])]),
        test_opts(),
    )
    .unwrap()
}

fn sha_hex(d: &[u8]) -> String {
    <sha2::Sha256 as sha2::Digest>::digest(d)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The hunt reads the hashes in the tenant's name indexes, reports one row per
/// file version with the snapshots that hold it, flags them and raises
/// `hash_hunt_hit`; snapshots without hashes are counted, other tenants unseen.
#[test]
fn hash_hunt_finds_flags_and_alerts() {
    let e = env(4);
    let t1 = store(&e, "t1");
    t1.enable_file_hashes();
    let evil = t1.store_file_stats(&b"evil payload"[..]).unwrap();
    let good = t1.store_file_stats(&b"good"[..]).unwrap();
    let tree = |v: Vec<TreeEntry>| [("tree", Index::Tree { entries: v })];
    t1.commit_snapshot(
        "host-a1",
        10,
        &tree(vec![file("tmp/x.exe", &evil, 12), file("ok.txt", &good, 4)]),
    )
    .unwrap();
    t1.commit_snapshot("host-a1", 20, &tree(vec![file("tmp/x.exe", &evil, 12)]))
        .unwrap();
    // a snapshot from before hashing
    store(&e, "t1")
        .commit_snapshot("share-2", 15, &tree(vec![file("evil-but-unhashed", &evil, 12)]))
        .unwrap();
    let t2 = store(&e, "t2");
    t2.enable_file_hashes();
    let ev2 = t2.store_file_stats(&b"evil payload"[..]).unwrap();
    t2.commit_snapshot("host-b1", 10, &tree(vec![file("x.exe", &ev2, 12)]))
        .unwrap();
    let mut s = sched(&e);
    // no lists: refused
    let id = manual(&s, "hash_hunt", "t1", json!({}));
    run_all(&mut s);
    assert_eq!(state(&s, id), "failed");
    s.db.conn()
        .execute(
            "INSERT INTO hash_lists (name, hashes, count, sha256, uploaded_by, uploaded_at) VALUES
               ('feed-a', ?1, 2, 'x', 'sam', 1), ('feed-b', ?2, 1, 'y', 'sam', 1)",
            params![
                format!("{}\n{}\n", sha_hex(b"evil payload"), "0".repeat(64)),
                format!("{}\n", sha_hex(b"evil payload"))
            ],
        )
        .unwrap();
    let id = manual(&s, "hash_hunt", "t1", json!({}));
    s.start_jobs().unwrap();
    assert_eq!(s.running(), vec![(id, format!("hunt:{id}"))], "read-only, own key");
    run_all(&mut s);
    assert_eq!(state(&s, id), "ok");
    let r: Value = serde_json::from_str(
        &s.db
            .conn()
            .query_row("SELECT result FROM jobs WHERE id=?1", [id], |r| r.get::<_, String>(0))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(r["scanned"], 3);
    assert_eq!(r["unhashed"], 1);
    assert_eq!(r["hashes"], 2);
    assert_eq!(
        r["matches"],
        json!([{"source": "host-a1", "path": "tmp/x.exe", "size": 12, "sha256": sha_hex(b"evil payload"),
                "lists": ["feed-a", "feed-b"], "times": [20, 10]}])
    );
    let c = s.db.conn();
    let flags: Vec<(i64, String)> = c
        .prepare("SELECT time, anomaly FROM snapshots WHERE tenant='t1' AND anomaly IS NOT NULL ORDER BY time")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(flags.len(), 2);
    assert!(flags[0].1.contains("IOC hash: 1 file(s)") && flags[0].1.contains("tmp/x.exe"));
    let (sev, msg, tenant): (String, String, String) = c
        .query_row(
            "SELECT severity, message, tenant FROM alerts WHERE kind='hash_hunt_hit'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!((sev.as_str(), tenant.as_str()), ("critical", "t1"));
    assert!(msg.contains("1 file versions on a hash list in 2 snapshots"), "{msg}");
    drop(c);
    // only the named list, one source, a time range
    let id = manual(
        &s,
        "hash_hunt",
        "t1",
        json!({"lists": ["feed-b"], "source": "host-a1", "from": 15}),
    );
    run_all(&mut s);
    let r: Value = serde_json::from_str(
        &s.db
            .conn()
            .query_row("SELECT result FROM jobs WHERE id=?1", [id], |r| r.get::<_, String>(0))
            .unwrap(),
    )
    .unwrap();
    assert_eq!((r["scanned"].clone(), r["hashes"].clone()), (json!(1), json!(1)));
    assert_eq!(r["matches"][0]["times"], json!([20]));
    assert_eq!(r["matches"][0]["lists"], json!(["feed-b"]));
}

/// The group option reaches the connector config (agents: `backup.file_hashes`),
/// for the group's own backups and an agent's manual one.
#[test]
fn file_hashes_in_the_backup_config() {
    const A: &str = "0123456789abcdef";
    let e = env(2);
    let s = sched(&e);
    s.db.conn()
        .execute_batch(&format!(
            "INSERT INTO agents (id, tenant, name, host, port, cert_sha256) VALUES ('{A}','t1','srv','10.0.0.9',7444,'ab');
             INSERT INTO sources (id, tenant, kind, name, config) VALUES
               (10,'t1','linux','l','{{\"agent_id\":\"{A}\",\"paths\":[\"/home\"]}}');
             INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES (10,'t1',10,1,'servers','[\"{A}\"]');"
        ))
        .unwrap();
    let cfg = |p: Value| -> Value {
        let id = manual(&s, "backup", "t1", p);
        let plan = s.plan(&s.job(id).unwrap()).unwrap();
        let (_, body) = plan.files.iter().find(|(n, _)| n.starts_with("agent-")).unwrap();
        serde_json::from_slice(body).unwrap()
    };
    assert_eq!(cfg(json!({"group_id": 10}))["backup"]["file_hashes"], Value::Null);
    s.db.conn()
        .execute("UPDATE groups SET file_hashes = 1 WHERE id = 10", [])
        .unwrap();
    assert_eq!(cfg(json!({"group_id": 10}))["backup"]["file_hashes"], true);
    assert_eq!(cfg(json!({"agent_id": A}))["backup"]["file_hashes"], true);
}

/// A locked-down tenant gets no backups, deletes or overwriting restores; reads
/// and other tenants go on.
#[test]
fn lockdown_refuses_changing_jobs() {
    let e = env(4);
    let mut s = sched(&e);
    s.db.conn()
        .execute(
            "INSERT INTO tenant_lockdowns (tenant, active, state) VALUES ('t1', 1, '{}')",
            [],
        )
        .unwrap();
    let b1 = manual(&s, "backup", "t1", json!({"group_id": 1}));
    let del = manual(&s, "snapshot_delete", "t1", json!({"source": "vm-100", "time": 5}));
    let rf = manual(
        &s,
        "restore_files",
        "t1",
        json!({"source": "host-0123456789abcdef", "time": 5, "paths": ["/x"], "target": "/",
               "overwrite": "always", "confirm": "x", "agent_id": "0123456789abcdef"}),
    );
    let b2 = manual(&s, "backup", "t2", json!({"group_id": 4}));
    run_all(&mut s);
    for id in [b1, del, rf] {
        assert_eq!(state(&s, id), "failed", "job {id}");
        let log: String =
            s.db.conn()
                .query_row("SELECT log FROM jobs WHERE id=?1", [id], |r| r.get(0))
                .unwrap();
        assert!(log.contains("tenant t1 is locked down"), "{log}");
    }
    assert_eq!(state(&s, b2), "ok");
    // lifted: backups run again
    s.db.conn()
        .execute("UPDATE tenant_lockdowns SET active = 0", [])
        .unwrap();
    let b3 = manual(&s, "backup", "t1", json!({"group_id": 1}));
    run_all(&mut s);
    assert_eq!(state(&s, b3), "ok");
}

/// The first delivery of a new-device sign-in also goes to the account's address.
#[test]
fn new_device_alert_has_the_account_address() {
    let e = env(1);
    let s = sched(&e);
    let c = s.db.conn();
    c.execute_batch(
        "INSERT INTO users (id, name, password_hash, totp_secret, role, created, email) VALUES
           (7, 'ann', 'x', 'y', 'admin', 1, 'ann@example.com'), (8, 'bob', 'x', 'y', 'operator', 1, NULL);
         INSERT INTO alerts (id, ts, severity, kind, key, message) VALUES
           (1, 1, 'warning', 'login_new_device', 'login_new_device:7:abc', 'm'),
           (2, 1, 'info', 'login_new_device', 'login_new_device:8:abc', 'm'),
           (3, 1, 'info', 'login_new_device', 'login_new_device:x:abc', 'm');",
    )
    .unwrap();
    assert_eq!(
        lifecycle::device_alert_email(&c, 1).unwrap().as_deref(),
        Some("ann@example.com")
    );
    assert_eq!(lifecycle::device_alert_email(&c, 2).unwrap(), None);
    assert_eq!(lifecycle::device_alert_email(&c, 3).unwrap(), None);
}
