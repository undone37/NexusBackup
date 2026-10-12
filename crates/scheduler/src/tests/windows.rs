use super::*;

const D: i64 = 20_000 * 86400; // 2024-10-04 00:00 UTC (a Friday)

fn exec(s: &Scheduler, sql: &str) {
    s.db.conn().execute_batch(sql).unwrap();
}

fn count(s: &Scheduler, sql: &str) -> i64 {
    s.db.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

/// An enrolled replication source (id 1, tenant r1, primary 10.0.2.2:28443)
/// whose fake nexus-replica copies its config and then syncs for a while.
fn replica_env() -> (Env, Scheduler) {
    let mut e = env(4);
    let dir = e.d.path().to_owned();
    script(
        &dir.join("replica"),
        &format!(r#"cp "$1" {0}/replica-$2.json; sleep 30"#, dir.display()),
    );
    e.cfg.replica_bin = dir.join("replica");
    e.cfg.cancel_grace_secs = 1;
    let s = sched(&e);
    exec(
        &s,
        "INSERT INTO tenants (name) VALUES ('r1');
         INSERT INTO replication_sources (id, name, url, peer_id, cert_pin, tenants, schedule, gfs, state, created,
           windows, sync_window, timezone)
         VALUES (1, 'prim', '10.0.2.2:28443', 'p', 'pin', '[\"r1\"]', 'hourly 00', '{}', 'enrolled', 0,
           '[{\"from\":\"22:00\",\"to\":\"23:00\",\"action\":\"limit\",\"rate_bytes\":1000}]',
           '[{\"from\":\"22:00\",\"to\":\"06:00\"}]', 'UTC');",
    );
    (e, s)
}

fn syncs(s: &Scheduler) -> i64 {
    count(s, "SELECT COUNT(*) FROM jobs WHERE kind='replica_sync'")
}

fn wait_done(s: &mut Scheduler, id: i64) {
    let t = Instant::now();
    while state(s, id) == "running" {
        assert!(t.elapsed() < Duration::from_secs(15), "still running");
        s.process_cancels().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        s.collect();
    }
}

/// Phase 17a: the firewall target and the syncs only inside the sync window;
/// at its end the running sync is cancelled (no error recorded, the next one
/// resumes) and queued ones are dropped.
#[test]
fn sync_window_gates_firewall_syncs_and_cancels() {
    let (e, mut s) = replica_env();
    let target = ("10.0.2.2".to_string(), 28443);
    // inside (23:00): reachable, a due sync is queued and runs with the windows
    s.now = D + 23 * 3600;
    assert_eq!(s.replication_targets().unwrap(), vec![target.clone()]);
    s.queue_replication(s.now).unwrap(); // first sight
    s.now = D + 24 * 3600 + 5; // 00:00:05, still inside
    s.queue_replication(s.now).unwrap();
    assert_eq!(syncs(&s), 1);
    s.replication_windows(s.now).unwrap();
    s.start_jobs().unwrap();
    let id = count(&s, "SELECT id FROM jobs WHERE kind='replica_sync'");
    let t = Instant::now();
    while !e.d.path().join("replica-sync.json").exists() {
        assert!(t.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(50));
    }
    let cfg: Value = serde_json::from_slice(&fs::read(e.d.path().join("replica-sync.json")).unwrap()).unwrap();
    assert_eq!(cfg["windows"][0]["rate_bytes"], 1000);
    assert_eq!(cfg["timezone"], "UTC");
    // a manual sync queued meanwhile
    let queued = manual(
        &s,
        "replica_sync",
        "r1",
        json!({"replication_source_id": 1, "tenant": "r1"}),
    );

    // the window closes (06:00): no target, no new syncs, running cancelled, queued dropped
    s.now = D + 30 * 3600;
    assert!(s.replication_targets().unwrap().is_empty());
    s.replication_windows(s.now).unwrap();
    assert_eq!(state(&s, queued), "cancelled");
    wait_done(&mut s, id);
    assert_eq!(state(&s, id), "cancelled");
    let by: String =
        s.db.conn()
            .query_row("SELECT cancel_by FROM jobs WHERE id=?1", [id], |r| r.get(0))
            .unwrap();
    assert_eq!(by, "sync_window");
    let status: String =
        s.db.conn()
            .query_row("SELECT status FROM replication_sources", [], |r| r.get(0))
            .unwrap();
    assert_eq!(status, "{}", "a cancelled sync is no error");
    assert_eq!(count(&s, "SELECT COUNT(*) FROM alerts"), 0, "no job_failed");
    s.now = D + 31 * 3600 + 5;
    s.queue_replication(s.now).unwrap();
    assert_eq!(syncs(&s), 2, "nothing queued outside the window");
    let job = Job {
        id: 0,
        kind: "replica_sync".into(),
        tenant: "r1".into(),
        params: json!({"replication_source_id": 1}),
    };
    let err = s.plan(&job).unwrap_err();
    assert!(format!("{err:#}").contains("outside its sync window"), "{err:#}");
    // back inside (22:00): the next due sync is queued again
    s.now = D + 46 * 3600 + 5;
    s.queue_replication(s.now).unwrap();
    assert_eq!(syncs(&s), 3);
    assert_eq!(s.replication_targets().unwrap(), vec![target]);
}

/// Phase 17b: a closed source has no firewall target, no syncs and an open
/// `vault_closed` alert (no lag warning); reopened, everything is back.
#[test]
fn closed_vault() {
    let (_e, mut s) = replica_env();
    exec(
        &s,
        "UPDATE replication_sources SET sync_window = '[]', closed_until = -1, closed_by = 'sofia'",
    );
    s.now = D + 12 * 3600;
    assert!(s.replication_targets().unwrap().is_empty());
    let queued = manual(
        &s,
        "replica_sync",
        "r1",
        json!({"replication_source_id": 1, "tenant": "r1"}),
    );
    s.replication_windows(s.now).unwrap();
    assert_eq!(state(&s, queued), "cancelled");
    let job = Job {
        id: 0,
        kind: "replica_sync".into(),
        tenant: "r1".into(),
        params: json!({"replication_source_id": 1}),
    };
    assert!(format!("{:#}", s.plan(&job).unwrap_err()).contains("vault closed"));
    s.queue_replication(s.now).unwrap();
    s.now += 3600;
    s.queue_replication(s.now).unwrap();
    assert_eq!(syncs(&s), 1, "only the cancelled manual one");
    let open = |s: &Scheduler| {
        count(
            s,
            "SELECT COUNT(*) FROM alerts WHERE kind='vault_closed' AND severity='info' AND resolved_at IS NULL \
             AND key='vault_closed:1' AND message LIKE '%by sofia%'",
        )
    };
    assert_eq!(open(&s), 1);
    s.replication_windows(s.now).unwrap();
    assert_eq!(open(&s), 1, "one alert while closed");
    s.check_replication_lag(catalog::now() + 49 * 3600).unwrap();
    assert_eq!(count(&s, "SELECT COUNT(*) FROM alerts WHERE kind='replication_lag'"), 0);
    // closed until a time: open again afterwards
    exec(
        &s,
        &format!("UPDATE replication_sources SET closed_until = {}", s.now + 60),
    );
    assert!(s.replication_targets().unwrap().is_empty());
    s.now += 120;
    assert_eq!(s.replication_targets().unwrap().len(), 1);
    s.replication_windows(s.now).unwrap();
    assert_eq!(open(&s), 0, "resolved when reopened");
    s.queue_replication(s.now).unwrap();
    s.now += 3600;
    s.queue_replication(s.now).unwrap();
    assert_eq!(syncs(&s), 2);
    // 17f: a source whose only tenant is deactivated is not reachable either
    exec(&s, "UPDATE tenants SET disabled = 1 WHERE name = 'r1'");
    assert!(s.replication_targets().unwrap().is_empty());
}

/// Phase 17a: an offsite upload that would start inside a pause window of its
/// tenant waits for the end of the pause; the windows reach nexus-offsite.
#[test]
fn offsite_pause_window_postpones_the_upload() {
    let e = env(4);
    let mut s = sched(&e);
    let offsite = json!({"remote": {"type": "local", "path": e.d.path().join("box")}, "bwlimit": 5000,
        "timezone": "Europe/Berlin",
        "windows": [{"from": "08:00", "to": "18:00", "action": "pause"},
                    {"from": "18:00", "to": "20:00", "action": "limit", "rate_bytes": 100}]});
    s.db.conn()
        .execute(
            "UPDATE tenants SET offsite = ?1 WHERE name = 't1'",
            [offsite.to_string()],
        )
        .unwrap();
    // 10:00 Berlin (CEST) = 08:00 UTC: paused until 18:00 Berlin = 16:00 UTC
    s.now = D + 8 * 3600;
    let id = manual(&s, "offsite", "t1", json!({}));
    s.start_jobs().unwrap();
    assert_eq!(state(&s, id), "queued");
    let nb: i64 =
        s.db.conn()
            .query_row("SELECT not_before FROM jobs WHERE id=?1", [id], |r| r.get(0))
            .unwrap();
    assert_eq!(nb, D + 16 * 3600);
    // outside the pause: planned, the windows go into offsite.json
    s.now = D + 17 * 3600;
    let job = s.job(id).unwrap();
    assert!(!s.hold_offsite(&job).unwrap());
    let plan = s.plan(&job).unwrap();
    let cfg: Value = plan
        .files
        .iter()
        .find(|(n, _)| n == "offsite.json")
        .map(|(_, b)| serde_json::from_slice(b).unwrap())
        .unwrap();
    assert_eq!(cfg["windows"], offsite["windows"]);
    assert_eq!(cfg["timezone"], "Europe/Berlin");
    assert_eq!(cfg["bwlimit"], 5000);
}
