use super::*;
use catalog::priority::{self, Priority};

fn open_alert(s: &Scheduler) -> Option<String> {
    s.db.conn()
        .query_row(
            "SELECT message FROM alerts WHERE kind='restore_priority' AND resolved_at IS NULL",
            [],
            |r| r.get(0),
        )
        .optional()
        .unwrap()
}

/// While restore priority is on, scheduler-queued backups and the held kinds
/// wait, manual backups run; it expires on its own (audited) and the held
/// jobs start afterwards.
#[test]
fn restore_priority_holds_and_expires() {
    let e = env(4);
    let mut s = sched(&e);
    let now = catalog::now();
    priority::store(
        &s.db.conn(),
        &Priority {
            until: now + 3600,
            since: now,
            by: "alice".into(),
            reason: "DR".into(),
        },
    )
    .unwrap();
    let sched_backup = s.insert_job("backup", "t1", &json!({"group_id": 1})).unwrap();
    let gc = s.insert_job("gc", "t2", &json!({})).unwrap();
    let manual_backup = manual(&s, "backup", "t1", json!({"group_id": 2}));
    s.check_restore_priority(now).unwrap();
    assert!(open_alert(&s).unwrap().contains("restore priority is on (by alice: DR)"));
    s.start_jobs().unwrap();
    assert_eq!(s.running(), vec![(manual_backup, "source:2".into())]);
    assert_eq!(state(&s, sched_backup), "queued");
    assert_eq!(state(&s, gc), "queued");
    // nothing new is queued meanwhile
    s.queue_maintenance(now + 86400 * 2).unwrap();
    let n: i64 =
        s.db.conn()
            .query_row("SELECT COUNT(*) FROM jobs WHERE kind IN ('verify','file_index')", [], |r| r.get(0))
            .unwrap();
    assert_eq!(n, 0);
    s.wait_idle(Duration::from_secs(20)).unwrap();

    // expiry: cleared, audited, warning resolved, held jobs start
    s.check_restore_priority(now + 3600).unwrap();
    assert!(priority::load(&s.db.conn()).unwrap().is_none());
    assert!(open_alert(&s).is_none());
    let audited: i64 =
        s.db.conn()
            .query_row(
                "SELECT COUNT(*) FROM audit WHERE action='restore_priority.expire' AND actor='scheduler'",
                [],
                |r| r.get(0),
            )
            .unwrap();
    assert_eq!(audited, 1);
    s.start_jobs().unwrap();
    assert!(s.running().iter().any(|(id, _)| *id == sched_backup), "{:?}", s.running());
    s.wait_idle(Duration::from_secs(20)).unwrap();
}
