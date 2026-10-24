use super::*;

fn alert(s: &Scheduler) -> Option<(String, String, i64)> {
    s.db.conn()
        .query_row(
            "SELECT severity, message, count FROM alerts WHERE key = 'clock_skew' AND resolved_at IS NULL",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .unwrap()
}

/// A store whose compliance clock lags system time by an hour when the scheduler
/// starts (the appliance was off): info `clock_skew`, counted once (not per
/// tick), the status setting for nexus-diag; the clock is kept open and shared
/// with the jobs' stores.
#[test]
fn lagging_compliance_clock_raises_clock_skew() {
    let e = env(1);
    let mut s = sched(&e);
    s.check_clock().unwrap();
    assert!(alert(&s).is_none(), "no stores yet");

    let dir = e.cfg.store_base.join("t1");
    drop(chunkstore::Store::open(&dir, Keyring::new("t1", &[(1, [7; 32])]), test_opts()).unwrap());
    fs::write(dir.join("clock"), format!("{}\n", catalog::now() - 3600)).unwrap();
    s.check_clock().unwrap();
    s.check_clock().unwrap();
    let (sev, msg, count) = alert(&s).expect("clock_skew raised");
    assert_eq!((sev.as_str(), count), ("info", 1));
    assert!(
        msg.contains("tenant t1 is 1 h 0 min behind system time since the last restart"),
        "{msg}"
    );
    let st: Value = serde_json::from_str(
        &catalog::setting(&s.db.conn(), crate::clock::STATUS_SETTING)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(st["tenant"], "t1");
    assert!((3599..=3602).contains(&st["skew_secs"].as_i64().unwrap()), "{st}");
    assert_eq!(st["jump_secs"], 0);

    // a job's store in this process uses the same running clock
    let st = chunkstore::Store::open(&dir, Keyring::new("t1", &[(1, [7; 32])]), test_opts()).unwrap();
    assert!(catalog::now() - st.compliance_now().unwrap() as i64 >= 3599);
}

/// Within a minute: no alert, and an open one resolves.
#[test]
fn small_skew_resolves() {
    let e = env(1);
    let mut s = sched(&e);
    s.raise("warning", "clock_skew", "clock_skew", "old", None).unwrap();
    let dir = e.cfg.store_base.join("t2");
    drop(chunkstore::Store::open(&dir, Keyring::new("t2", &[(1, [7; 32])]), test_opts()).unwrap());
    fs::write(dir.join("clock"), format!("{}\n", catalog::now() - 30)).unwrap();
    s.check_clock().unwrap();
    assert!(alert(&s).is_none());
}

/// System time behind the compliance clock (moved back): critical.
#[test]
fn compliance_clock_ahead_is_critical() {
    let e = env(1);
    let mut s = sched(&e);
    let dir = e.cfg.store_base.join("t2");
    drop(chunkstore::Store::open(&dir, Keyring::new("t2", &[(1, [7; 32])]), test_opts()).unwrap());
    fs::write(dir.join("clock"), format!("{}\n", catalog::now() + 1800)).unwrap();
    s.check_clock().unwrap();
    let (sev, msg, _) = alert(&s).unwrap();
    assert_eq!(sev, "critical");
    assert!(msg.contains("ahead of system time"), "{msg}");
}

/// #48 lab: a jump undone while the clock still lags from a restart: the critical alert resolves and
/// an info one (the lag) is raised, not the critical one kept with the lag's text.
#[test]
fn an_undone_jump_leaves_the_lag_at_its_own_level() {
    let e = env(1);
    let mut s = sched(&e);
    s.raise("critical", "clock_skew", "clock_skew", "system time jumped", None)
        .unwrap();
    let dir = e.cfg.store_base.join("t1");
    drop(chunkstore::Store::open(&dir, Keyring::new("t1", &[(1, [7; 32])]), test_opts()).unwrap());
    fs::write(dir.join("clock"), format!("{}\n", catalog::now() - 3600)).unwrap();
    s.check_clock().unwrap();
    let (sev, msg, _) = alert(&s).unwrap();
    assert_eq!(sev, "info", "{msg}");
    assert!(msg.contains("since the last restart"), "{msg}");
    let resolved: i64 = s
        .db
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM alerts WHERE key = 'clock_skew' AND severity = 'critical' AND resolved_at IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(resolved, 1);
}
