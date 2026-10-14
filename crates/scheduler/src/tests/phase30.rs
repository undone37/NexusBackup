//! Phase 30 (NetBackup Tier 2): backup-duration and dedup-rate anomalies with
//! the per-source sensitivity.

use super::*;

const G: u64 = 1 << 30;

fn line(source: &str, time: i64, read: u64, plain: u64, secs: Option<u64>) -> String {
    let mut v = json!({"source": source, "time": time, "read": read, "logical": 100 * read,
                       "new_chunks": 1, "new_plain": plain, "new_stored": plain / 2});
    if let Some(s) = secs {
        v["secs"] = json!(s);
    }
    format!("nexus-stats {v}\n")
}

fn flag(s: &Scheduler, source: &str, time: i64) -> Option<String> {
    s.db.conn()
        .query_row(
            "SELECT anomaly FROM snapshots WHERE tenant='t1' AND source=?1 AND time=?2",
            params![source, time],
            |r| r.get(0),
        )
        .optional()
        .unwrap()
        .flatten()
}

/// The duration is stored; a backup far slower than usual raises a warning
/// `anomaly` and flags the snapshot; a dedup-rate jump on another source is
/// critical; the sensitivity changes what counts.
#[test]
fn duration_and_dedup_rate_anomalies() {
    let e = env(1);
    let s = sched(&e);
    // 5 runs of a VM: 2 GiB read, 0.1 GiB new, 10 minutes each
    for t in 1..=5 {
        s.record_stats("t1", &line("vm-100", t, 2 * G, G / 10, Some(600)))
            .unwrap();
    }
    let secs: Option<i64> =
        s.db.conn()
            .query_row(
                "SELECT secs FROM backup_stats WHERE source='vm-100' AND time=5",
                [],
                |r| r.get(0),
            )
            .unwrap();
    assert_eq!(secs, Some(600));
    // 25 minutes: under the medium limit (max(30 min, 25 min))
    s.record_stats("t1", &line("vm-100", 6, 2 * G, G / 10, Some(1500)))
        .unwrap();
    assert!(alerts_of(&s, "anomaly").is_empty());
    // 50 minutes: duration finding, a warning
    s.record_stats("t1", &line("vm-100", 7, 2 * G, G / 10, Some(3000)))
        .unwrap();
    let a = alerts_of(&s, "anomaly");
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].0, "warning");
    assert!(
        a[0].1
            .starts_with("backup-duration anomaly on t1/vm-100: snapshot 7: the backup took 50 min 00 s"),
        "{}",
        a[0].1
    );
    assert!(flag(&s, "vm-100", 7).unwrap().starts_with("the backup took 50 min"));

    // a file server: 4 GiB of changed files read, usually 5 % new
    for t in 1..=5 {
        s.record_stats("t1", &line("host-a1", t, 4 * G, G / 5, None)).unwrap();
    }
    // 0.9 GiB new of 1.5 GiB read: 60 %, below the 1 GiB volume floor
    s.record_stats("t1", &line("host-a1", 6, 3 * G / 2, 9 * G / 10, None))
        .unwrap();
    assert_eq!(
        alerts_of(&s, "anomaly").len(),
        1,
        "60 % stays under the medium floor (75 %)"
    );
    // high sensitivity: the floor is 50 %
    catalog::anomaly::set(
        &s.db.conn(),
        "t1",
        "host-a1",
        catalog::anomaly::Sensitivity::High,
        "ann",
    )
    .unwrap();
    s.record_stats("t1", &line("host-a1", 7, 3 * G / 2, 9 * G / 10, None))
        .unwrap();
    let a = alerts_of(&s, "anomaly");
    assert_eq!(a.len(), 2);
    assert_eq!(a[1].0, "critical");
    assert!(
        a[1].1.starts_with(
            "dedup-rate anomaly on t1/host-a1 (sensitivity high): snapshot 7: 60 % of the 1.5 GiB read did not deduplicate"
        ),
        "{}",
        a[1].1
    );
    assert!(flag(&s, "host-a1", 7).is_some());
    // low sensitivity on the VM: the 50 minutes would no longer count (limit 40 min -> max(40, 40))
    catalog::anomaly::set(&s.db.conn(), "t1", "vm-100", catalog::anomaly::Sensitivity::Low, "ann").unwrap();
    s.db.conn().execute("UPDATE alerts SET resolved_at = 1", []).unwrap();
    s.record_stats("t1", &line("vm-100", 8, 2 * G, G / 10, Some(2300)))
        .unwrap();
    assert_eq!(alerts_of(&s, "anomaly").len(), 2, "38 minutes are under the low limit");
}

/// Role elevation: the housekeeping resolves the info alert of an elevation
/// that ended by itself and keeps the one of a running elevation.
#[test]
fn ended_elevations_resolve_their_alert() {
    let e = env(1);
    let s = sched(&e);
    let c = || s.db.conn();
    c().execute_batch(
        "INSERT INTO users (id, name, password_hash, totp_secret, role, created, eligible_role)
           VALUES (50, 'bob', 'x', 'y', 'operator', 1, 'admin');
         INSERT INTO sessions (id, id_hash, user_id, csrf, created, last_seen) VALUES (1, 'a', 50, 'c', 1, 1),
           (2, 'b', 50, 'c', 1, 1);",
    )
    .unwrap();
    catalog::elevation::start(&c(), 1, 50, "admin", 15, "patch")
        .unwrap()
        .unwrap();
    catalog::elevation::start(&c(), 2, 50, "admin", 15, "patch")
        .unwrap()
        .unwrap();
    c().execute("UPDATE sessions SET elevated_until = 10 WHERE id = 2", [])
        .unwrap();
    s.check_accounts(catalog::now()).unwrap();
    let open: Vec<String> = c()
        .prepare("SELECT key FROM alerts WHERE kind = 'role_elevation' AND resolved_at IS NULL")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(open, vec!["role_elevation:50:1".to_owned()]);
}
