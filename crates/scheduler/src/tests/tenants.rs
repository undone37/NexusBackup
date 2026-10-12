use super::*;

fn count(s: &Scheduler, sql: &str) -> i64 {
    s.db.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

/// A deactivated tenant: no scheduled backups or replication syncs, queued
/// backups fail unstarted, its alerts are suppressed except one info
/// `tenant_disabled`, resolved on reactivation; retention-type jobs still plan.
#[test]
fn deactivated_tenant_is_skipped_and_silent() {
    let e = env(4);
    let mut s = sched(&e);
    s.db.conn()
        .execute_batch(
            "UPDATE tenants SET disabled = 1, disabled_at = 1, disabled_by = 'alice', disabled_reason = 'x' WHERE name = 't2';
             INSERT INTO replication_sources (id, name, url, peer_id, cert_pin, tenants, schedule, gfs, state, created)
             VALUES (1, 'prim', '10.0.2.2:28443', '0123456789abcdef', 'PIN', '[\"t1\",\"t2\"]', 'hourly 00', '{}', 'enrolled', 0);",
        )
        .unwrap();
    let day = 20_000 * 86400;
    s.now = day + 12 * 3600;
    s.queue_scheduled(s.now).unwrap();
    s.queue_replication(s.now).unwrap();
    s.now = day + 22 * 3600 + 5;
    s.queue_scheduled(s.now).unwrap();
    s.queue_replication(s.now).unwrap();
    assert_eq!(
        count(&s, "SELECT COUNT(*) FROM jobs WHERE kind='backup' AND tenant='t1'"),
        3
    );
    assert_eq!(count(&s, "SELECT COUNT(*) FROM jobs WHERE tenant='t2'"), 0);
    assert_eq!(
        count(
            &s,
            "SELECT COUNT(*) FROM jobs WHERE kind='replica_sync' AND tenant='t1'"
        ),
        1
    );
    s.db.conn().execute("DELETE FROM jobs", []).unwrap();

    // a backup queued before the deactivation fails unstarted, without an alert
    let id = manual(&s, "backup", "t2", json!({"group_id": 4}));
    s.start_jobs().unwrap();
    assert_eq!(state(&s, id), "failed");
    assert_eq!(count(&s, "SELECT COUNT(*) FROM alerts WHERE tenant='t2'"), 0);
    let job = Job {
        id: 0,
        kind: "gc".into(),
        tenant: "t2".into(),
        params: json!({}),
    };
    // GC / retention keep running (t2 is also in the replication source: no data yet)
    let gc = s.plan(&job).map(drop).unwrap_err();
    assert!(!format!("{gc:#}").contains("deactivated"), "{gc:#}");
    let backup = Job {
        kind: "backup".into(),
        ..job
    };
    assert!(format!("{:#}", s.plan(&backup).map(drop).unwrap_err()).contains("deactivated"));
    s.raise("warning", "offsite_lag", "offsite_lag:t2", "lags", Some("t2"))
        .unwrap();
    assert_eq!(count(&s, "SELECT COUNT(*) FROM alerts WHERE tenant='t2'"), 0);

    s.check_disabled_tenants().unwrap();
    s.check_disabled_tenants().unwrap();
    assert_eq!(
        count(
            &s,
            "SELECT COUNT(*) FROM alerts WHERE tenant='t2' AND kind='tenant_disabled' AND severity='info' AND resolved_at IS NULL"
        ),
        1
    );
    // reactivated: the notice resolves, scheduling resumes
    s.db.conn()
        .execute("UPDATE tenants SET disabled = 0 WHERE name = 't2'", [])
        .unwrap();
    s.check_disabled_tenants().unwrap();
    assert_eq!(
        count(
            &s,
            "SELECT COUNT(*) FROM alerts WHERE kind='tenant_disabled' AND resolved_at IS NULL"
        ),
        0
    );
    s.now += 86400;
    s.queue_scheduled(s.now).unwrap();
    assert_eq!(
        count(&s, "SELECT COUNT(*) FROM jobs WHERE kind='backup' AND tenant='t2'"),
        1
    );
}
