use super::*;

fn open(s: &Scheduler) -> Vec<(String, String, String)> {
    let c = s.db.conn();
    let mut q = c
        .prepare("SELECT key, severity, message FROM alerts WHERE kind = 'disk' AND resolved_at IS NULL ORDER BY key")
        .unwrap();
    let rows = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
    rows.map(Result::unwrap).collect()
}

fn count(s: &Scheduler, key: &str) -> i64 {
    s.db.conn()
        .query_row(
            "SELECT count FROM alerts WHERE key = ?1 AND resolved_at IS NULL",
            [key],
            |r| r.get(0),
        )
        .unwrap()
}

fn write(e: &Env, name: &str, v: &Value) {
    fs::write(e.cfg.disks_dir.join(name), v.to_string()).unwrap();
}

fn smart(pending: i64, health: &str) -> Value {
    json!({"available": true, "health": health, "temperature": 36, "pending": pending, "reallocated": 0, "offline_uncorrectable": 0})
}

fn status(now: i64, sde: Value, array_state: &str, progress: Option<f64>) -> Value {
    let degraded = array_state != "clean";
    json!({
        "scanned": now,
        "disks": [
            {"name": "sde", "serial": "WD-03", "model": "WDC", "type": "hdd", "smart": sde},
            {"name": "vdb", "serial": "VIRT-1", "model": null, "type": "hdd", "smart": {"available": false}},
        ],
        "arrays": [{"name": "md126", "uuid": "3f0c:1", "level": "raid6", "md_name": "nexus-data",
                    "state": array_state, "degraded": degraded, "raid_devices": 4, "active_devices": if degraded { 3 } else { 4 },
                    "action": progress.map(|_| "recover"), "progress": progress, "finish_minutes": null,
                    "members": if degraded { json!([{"serial": "WD-04", "dev": "sdf", "state": "faulty"}]) } else { json!([]) }}]
    })
}

/// Phase 16a: `disk` alerts from the nexus-disks status: raised, escalated when bad sectors
/// grow, progress updated without counting repeats, resolved when healthy; a stale status
/// warns; finished helper operations are audited once.
#[test]
fn disk_alerts_and_ops_audit() {
    let mut e = env(1);
    e.cfg.disks_dir = e.d.path().join("disks");
    fs::create_dir(&e.cfg.disks_dir).unwrap();
    let s = sched(&e);
    let now = catalog::now();
    // no status: nothing
    s.check_disks(now).unwrap();
    assert!(open(&s).is_empty());

    write(&e, "status.json", &status(now, smart(8, "passed"), "degraded", None));
    s.check_disks(now).unwrap();
    s.check_disks(now).unwrap();
    let a = open(&s);
    assert_eq!(a.len(), 2, "{a:?}");
    assert_eq!((a[0].0.as_str(), a[0].1.as_str()), ("disk:WD-03", "warning"));
    assert_eq!(
        a[0].2,
        "Disk WDC WD-03 (sde): 8 pending, 0 reallocated, 0 offline-uncorrectable sectors"
    );
    assert_eq!((a[1].0.as_str(), a[1].1.as_str()), ("disk:md:3f0c:1", "critical"));
    assert!(
        a[1].2.contains("degraded: 3 of 4 devices active, failed: WD-04"),
        "{}",
        a[1].2
    );
    assert_eq!(count(&s, "disk:WD-03"), 1, "a repeat is not counted");

    // the replacement disk rebuilds: info with the progress; more pending sectors: critical
    write(
        &e,
        "status.json",
        &status(now, smart(12, "passed"), "recovering", Some(10.0)),
    );
    s.check_disks(now).unwrap();
    let a = open(&s);
    assert_eq!(a.len(), 3, "{a:?}");
    assert_eq!(a[0].1, "critical");
    assert!(a[0].2.ends_with("(growing: was 8)"), "{}", a[0].2);
    assert_eq!(
        (a[2].0.as_str(), a[2].1.as_str(), a[2].2.as_str()),
        (
            "disk:md:3f0c:1:sync",
            "info",
            "Array md126 (raid6, nexus-data): rebuilding 10.0 %"
        )
    );
    write(
        &e,
        "status.json",
        &status(now, smart(12, "passed"), "recovering", Some(55.5)),
    );
    s.check_disks(now).unwrap();
    let a = open(&s);
    assert_eq!(a[0].1, "critical", "stays critical while open");
    assert!(a[2].2.ends_with("rebuilding 55.5 %"));
    assert_eq!(count(&s, "disk:md:3f0c:1:sync"), 1);

    // rebuilt, sectors fixed (disk replaced): everything resolves, audited
    write(&e, "status.json", &status(now, smart(0, "passed"), "clean", None));
    s.check_disks(now).unwrap();
    assert!(open(&s).is_empty(), "{:?}", open(&s));
    let resolved: i64 =
        s.db.conn()
            .query_row("SELECT COUNT(*) FROM audit WHERE action = 'alert.resolve'", [], |r| {
                r.get(0)
            })
            .unwrap();
    assert_eq!(resolved, 3);

    // a failing disk is critical at once; a stale status warns
    write(
        &e,
        "status.json",
        &status(now - 3600, smart(0, "failed"), "clean", None),
    );
    s.check_disks(now).unwrap();
    let a = open(&s);
    assert_eq!(
        a.iter().map(|x| (x.0.as_str(), x.1.as_str())).collect::<Vec<_>>(),
        vec![("disk:WD-03", "critical"), ("disk:monitor", "warning")]
    );

    // operations: audited once each, running ones not yet
    let ops = json!([
        {"id": "a1", "op": "replace", "by": "alice", "quorum_id": 7, "state": "done", "detail": "rebuild started", "error": null, "params": {"disk": "WD-06"}},
        {"id": "a2", "op": "grow", "by": "alice", "quorum_id": 8, "state": "running", "detail": null, "error": null, "params": {}},
        {"id": "a3", "op": "create_array", "by": "alice", "quorum_id": 9, "state": "refused", "detail": null, "error": "the store is not empty", "params": {}},
    ]);
    write(&e, "ops.json", &ops);
    s.check_disks(now).unwrap();
    s.check_disks(now).unwrap();
    let rows: Vec<(String, String, String)> = {
        let c = s.db.conn();
        let mut q = c
            .prepare("SELECT actor, target, details FROM audit WHERE action = 'hardware.op' ORDER BY seq")
            .unwrap();
        let r = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
        r.map(Result::unwrap).collect()
    };
    assert_eq!(rows.len(), 2);
    assert_eq!(
        (rows[0].0.as_str(), rows[0].1.as_str()),
        ("nexus-disks", "hardware/replace")
    );
    let d: Value = serde_json::from_str(&rows[1].2).unwrap();
    assert_eq!(
        (d["state"].clone(), d["requested_by"].clone(), d["quorum_id"].clone()),
        (json!("refused"), json!("alice"), json!(9))
    );
}
