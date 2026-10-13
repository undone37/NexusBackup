use super::*;

/// Replaces the fake connector.
fn connector(e: &Env, body: &str) {
    let p = e.d.path().join("pve");
    fs::remove_file(&p).unwrap();
    script(&p, body);
}

fn exec(s: &Scheduler, sql: &str) {
    s.db.conn().execute_batch(sql).unwrap();
}

fn count(s: &Scheduler, sql: &str) -> i64 {
    s.db.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn backups(s: &Scheduler) -> Vec<(i64, i64)> {
    s.db.conn()
        .prepare("SELECT id, json_extract(params,'$.group_id') FROM jobs WHERE kind='backup' ORDER BY id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn paused_maintenance_and_blackout_skip_scheduled_runs() {
    let e = env(4);
    let mut s = sched(&e);
    let day = 20_000 * 86400; // a Friday
                              // group 1 paused indefinitely, group 2 paused until tomorrow, source 3 (group 4) in maintenance
    exec(
        &s,
        &format!(
            "UPDATE groups SET paused_until = -1 WHERE id = 1;
             UPDATE groups SET paused_until = {} WHERE id = 2;
             UPDATE sources SET maintenance_until = -1 WHERE id = 3;",
            day + 86400 + 12 * 3600
        ),
    );
    s.now = day + 12 * 3600;
    s.queue_scheduled(s.now).unwrap();
    s.now = day + 22 * 3600 + 5;
    s.queue_scheduled(s.now).unwrap();
    assert_eq!(backups(&s).iter().map(|b| b.1).collect::<Vec<_>>(), vec![3]);
    // the next day: group 2's pause ended, the missed slot runs once
    exec(&s, "UPDATE jobs SET state='ok'");
    s.now = day + 86400 + 13 * 3600;
    s.queue_scheduled(s.now).unwrap();
    assert_eq!(backups(&s).iter().map(|b| b.1).collect::<Vec<_>>(), vec![3, 2]);
    // pause > 7 days / indefinite: one `paused` warning each
    s.check_paused(s.now).unwrap();
    s.check_paused(s.now).unwrap();
    assert_eq!(count(&s, "SELECT COUNT(*) FROM alerts WHERE kind='paused'"), 2);
    // resumed: the warning resolves itself
    exec(&s, "UPDATE groups SET paused_until = NULL WHERE id = 1");
    s.check_paused(s.now).unwrap();
    assert_eq!(
        count(
            &s,
            "SELECT COUNT(*) FROM alerts WHERE kind='paused' AND resolved_at IS NULL"
        ),
        1,
        "source 3 still in maintenance"
    );
    assert_eq!(
        count(
            &s,
            "SELECT COUNT(*) FROM alerts WHERE key='paused:group:1:-1' AND auto=1"
        ),
        1
    );

    // a blackout window over the slot (Berlin time) holds the run until it ends
    exec(
        &s,
        "UPDATE groups SET paused_until = NULL; UPDATE sources SET maintenance_until = NULL;
         UPDATE jobs SET state='ok';
         UPDATE groups SET timezone = 'Europe/Berlin';
         UPDATE policies SET schedule = 'daily 22:00', blackout = '[{\"days\":[],\"from\":\"21:00\",\"to\":\"23:30\"}]';",
    );
    let before = backups(&s).len();
    // 2024-10-05 22:00 CEST = 20:00 UTC: inside the window
    s.now = day + 86400 + 20 * 3600 + 5;
    s.queue_scheduled(s.now).unwrap();
    assert_eq!(backups(&s).len(), before, "blackout");
    s.now = day + 86400 + 21 * 3600 + 31 * 60; // 23:31 CEST
    s.queue_scheduled(s.now).unwrap();
    assert_eq!(backups(&s).len(), before + 4, "after the window");
}

#[test]
fn retries_failed_guests_then_alerts() {
    let e = env(4);
    // vm 100 commits, 101 fails; the config names the guests of each attempt
    connector(
        &e,
        &format!(
            "tr -d ' \\n' < \"$1\" | grep -o '\"vmids\":\\[[0-9,]*\\]' >> {0}/calls; echo 'committed vm-100/5'; echo 'backup of guest 101 failed' >&2; exit 1",
            e.d.path().display()
        ),
    );
    let mut s = sched(&e);
    exec(
        &s,
        "UPDATE groups SET guests = '[100,101]' WHERE id = 1;
         UPDATE policies SET retry = '{\"count\":2,\"delay_min\":5}';",
    );
    let a = manual(&s, "backup", "t1", json!({"group_id": 1}));
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    assert_eq!(state(&s, a), "failed");
    assert_eq!(result_of(&s, a), json!({"failed_guests": [101]}));
    let (b, p, nb, att, of): (i64, String, i64, i64, i64) =
        s.db.conn()
            .query_row(
                "SELECT id, params, not_before, attempt, retry_of FROM jobs WHERE id > ?1 AND kind='backup'",
                [a],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&p).unwrap(),
        json!({"group_id": 1, "guests": [101]})
    );
    assert!(nb > catalog::now() + 200 && (att, of) == (2, a), "{nb} {att} {of}");
    assert_eq!(
        count(&s, "SELECT COUNT(*) FROM alerts WHERE kind='job_failed'"),
        0,
        "not yet"
    );
    let log: String =
        s.db.conn()
            .query_row("SELECT log FROM jobs WHERE id=?1", [a], |r| r.get(0))
            .unwrap();
    assert!(
        log.contains(&format!("attempt 1 of 3 failed; retry as job {b}")),
        "{log}"
    );
    // waits for not_before
    s.start_jobs().unwrap();
    assert!(s.running().is_empty());
    exec(&s, "UPDATE jobs SET not_before = 0");
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    exec(&s, "UPDATE jobs SET not_before = 0");
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    let chain: Vec<(i64, i64, String)> =
        s.db.conn()
            .prepare("SELECT attempt, COALESCE(retry_of, 0), state FROM jobs WHERE kind='backup' ORDER BY id")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
    assert_eq!(
        chain,
        vec![
            (1, 0, "failed".into()),
            (2, a, "failed".into()),
            (3, a, "failed".into())
        ]
    );
    let msg: String =
        s.db.conn()
            .query_row("SELECT message FROM alerts WHERE kind='job_failed'", [], |r| r.get(0))
            .unwrap();
    assert!(msg.contains("failed after 3 attempts"), "{msg}");
    let calls = fs::read_to_string(e.d.path().join("calls")).unwrap();
    assert_eq!(calls, "\"vmids\":[100,101]\n\"vmids\":[101]\n\"vmids\":[101]\n");
    // a later successful run of the group resolves the job_failed alert (13f lifecycle)
    connector(&e, "echo 'committed vm-100/9'; echo 'committed vm-101/9'");
    let ok = manual(&s, "backup", "t1", json!({"group_id": 1}));
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    assert_eq!(state(&s, ok), "ok");
    assert_eq!(
        count(
            &s,
            "SELECT COUNT(*) FROM alerts WHERE kind='job_failed' AND resolved_at IS NULL"
        ),
        0
    );
}

#[test]
fn retry_that_succeeds_leaves_no_alert() {
    let e = env(4);
    // the first attempt fails, the retry succeeds
    connector(
        &e,
        &format!(
            "if [ -e {0}/failed ]; then echo 'committed vm-100/5'; exit 0; fi; touch {0}/failed; exit 1",
            e.d.path().display()
        ),
    );
    let mut s = sched(&e);
    let a = manual(&s, "backup", "t1", json!({"group_id": 1}));
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    assert_eq!(state(&s, a), "failed");
    exec(&s, "UPDATE jobs SET not_before = 0");
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    assert_eq!(
        count(
            &s,
            "SELECT COUNT(*) FROM jobs WHERE kind='backup' AND attempt=2 AND state='ok'"
        ),
        1
    );
    assert_eq!(count(&s, "SELECT COUNT(*) FROM alerts WHERE kind='job_failed'"), 0);
}

#[test]
fn sla_missed_once_per_job() {
    let e = env(4);
    let s = sched(&e);
    let now = catalog::now();
    exec(
        &s,
        &format!(
            "UPDATE policies SET sla_minutes = 30;
             INSERT INTO jobs (id, kind, tenant, params, state, requested_by, created, started)
               VALUES (50, 'backup', 't1', '{{\"group_id\":1}}', 'running', 'scheduler', 1, {0}),
                      (51, 'backup', 't1', '{{\"group_id\":2}}', 'running', 'scheduler', 1, {1});",
            now - 3600,
            now - 600
        ),
    );
    s.check_sla(now).unwrap();
    s.check_sla(now + 60).unwrap();
    let msgs: Vec<String> =
        s.db.conn()
            .prepare("SELECT message FROM alerts WHERE kind='sla_missed'")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
    assert_eq!(msgs.len(), 1, "{msgs:?}");
    assert!(msgs[0].starts_with("backup job 50 of group g1 (t1) still running after 60 min (SLA 30 min)"));
}

#[test]
fn cancel_running_job_term_then_kill_and_stop_task() {
    let e = env(4);
    let calls = e.d.path().join("calls");
    // ignores SIGTERM (so does its sleep): needs the SIGKILL; reports a PVE task first
    connector(
        &e,
        &format!(
            "if [ \"$2\" = task-stop ]; then echo \"$2 $3\" >> {0}; exit 0; fi
             echo 'upid: UPID:n1:0001:02:03:vzdump:100:root@pam:' >&2
             trap '' TERM; sleep 60",
            calls.display()
        ),
    );
    let mut cfg = e.cfg.clone();
    cfg.cancel_grace_secs = 1;
    let keys: KeySource = Arc::new(|t: &str| Ok(Keyring::new(t, &[(1, [7; 32])])));
    let mut s = Scheduler::new(cfg, e.db.clone(), keys, test_opts).unwrap();
    let a = manual(&s, "backup", "t1", json!({"group_id": 1}));
    s.start_jobs().unwrap();
    std::thread::sleep(Duration::from_millis(300));
    exec(&s, &format!("UPDATE jobs SET cancel_by = 'alice' WHERE id = {a}"));
    let t = Instant::now();
    while !s.running().is_empty() {
        assert!(t.elapsed() < Duration::from_secs(15), "still running");
        s.process_cancels().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        s.collect();
    }
    assert!(t.elapsed() >= Duration::from_secs(1), "SIGKILL after the grace period");
    assert_eq!(state(&s, a), "cancelled");
    assert_eq!(
        fs::read_to_string(&calls).unwrap(),
        "task-stop UPID:n1:0001:02:03:vzdump:100:root@pam:\n"
    );
    assert_eq!(count(&s, "SELECT COUNT(*) FROM alerts"), 0, "no job_failed");
    assert_eq!(
        count(&s, "SELECT COUNT(*) FROM jobs WHERE kind='retention'"),
        0,
        "no follow-up"
    );
    assert_eq!(fs::read_dir(&e.cfg.runtime_dir).unwrap().count(), 0, "job dir removed");
}

#[test]
fn blackout_abort_cancels_older_runs_only() {
    let e = env(4);
    connector(&e, "sleep 60");
    let mut s = sched(&e);
    let now = catalog::now();
    // a window over "now" in UTC with abort, started 1 h ago
    let h = |t: i64| format!("{:02}:{:02}", t.rem_euclid(86400) / 3600, t.rem_euclid(3600) / 60);
    exec(
        &s,
        &format!(
            "UPDATE policies SET blackout = '[{{\"from\":\"{}\",\"to\":\"{}\",\"abort\":true}}]'",
            h(now - 3600),
            h(now + 3600)
        ),
    );
    let a = manual(&s, "backup", "t1", json!({"group_id": 1}));
    let b = manual(&s, "backup", "t1", json!({"group_id": 2}));
    s.start_jobs().unwrap();
    // a started before the window (as if), b inside it (a manual run: allowed)
    exec(&s, &format!("UPDATE jobs SET started = {} WHERE id = {a}", now - 7200));
    s.blackout_aborts(now).unwrap();
    s.process_cancels().unwrap();
    let t = Instant::now();
    while state(&s, a) == "running" {
        assert!(t.elapsed() < Duration::from_secs(15));
        std::thread::sleep(Duration::from_millis(100));
        s.collect();
    }
    assert_eq!(state(&s, a), "cancelled");
    assert_eq!(state(&s, b), "running");
    let by: String =
        s.db.conn()
            .query_row("SELECT cancel_by FROM jobs WHERE id=?1", [a], |r| r.get(0))
            .unwrap();
    assert_eq!(by, "blackout");
    exec(&s, &format!("UPDATE jobs SET cancel_by = 'test' WHERE id = {b}"));
    s.process_cancels().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
}

#[test]
fn pve_backup_off_disks_are_a_warning() {
    // a VM whose disk has PVE backup=0: committed, but the job result carries a warning
    // (the dashboard shows it), never a plain "ok" with the system disk missing
    let e = env(4);
    connector(
        &e,
        "echo 'committed vm-100/9'; echo 'warnings vm-100/9: 1 disk(s) not in the snapshot, Proxmox VE option backup=0: scsi0'",
    );
    let mut s = sched(&e);
    let id = manual(&s, "backup", "t1", json!({"group_id": 1}));
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    assert_eq!(state(&s, id), "ok");
    let r: String =
        s.db.conn()
            .query_row("SELECT result FROM jobs WHERE id=?1", [id], |r| r.get(0))
            .unwrap();
    let r: Value = serde_json::from_str(&r).unwrap();
    assert_eq!(
        (&r["warnings"], &r["snapshots"][0]["warnings"]),
        (&json!(1), &json!(1)),
        "{r}"
    );
}

#[test]
fn fresh_snapshot_rows_are_local_at_once() {
    // rows created from a backup's own lines (identity, consistency) name a snapshot that was
    // just committed to the local store: local = 1 before any store scan
    let e = env(4);
    connector(
        &e,
        "echo 'committed vm-100/9'; echo 'identity vm-100/9 {\"changed\":false,\"previous\":null,\"vmgenid\":\"x\"}'; echo 'consistency vm-100/9: application (guest-agent fs-freeze/fs-thaw)'",
    );
    let mut s = sched(&e);
    let id = manual(&s, "backup", "t1", json!({"group_id": 1}));
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    assert_eq!(state(&s, id), "ok");
    assert_eq!(
        count(
            &s,
            "SELECT COUNT(*) FROM snapshots WHERE source = 'vm-100' AND time = 9 AND local = 1"
        ),
        1
    );
}
