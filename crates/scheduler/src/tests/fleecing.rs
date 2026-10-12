use super::*;

fn open(s: &Scheduler) -> Vec<(String, String, String)> {
    let c = s.db.conn();
    let mut q = c
        .prepare("SELECT key, severity, message FROM alerts WHERE kind = 'fleecing_space' AND resolved_at IS NULL")
        .unwrap();
    let rows = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
    rows.map(Result::unwrap).collect()
}

fn line(node: &str, state: &str, free_gib: u64, pct: f64) -> String {
    format!(
        "fleecing-space {}",
        json!({"node": node, "storage": "local-lvm", "state": state, "free": free_gib << 30,
               "total": 100u64 << 30, "free_pct": pct, "meta_free_pct": null})
    )
}

/// The guard's lines in a backup job's output: a skipped guest (low) and a
/// cancelled one (critical) raise critical alerts per node/storage; a later
/// check with room resolves that node's alert only.
#[test]
fn fleecing_space_alerts_follow_the_connector() {
    let e = env(1);
    let s = sched(&e);
    let job = Job {
        id: 7,
        kind: "backup".into(),
        tenant: "t1".into(),
        params: json!({"group_id": 1}),
    };
    let log = [
        line("pve1", "ok", 50, 50.0),
        "backup of guest 100 failed: fleecing storage local-lvm on node pve2 has …: guest skipped".into(),
        line("pve2", "low", 9, 9.0),
        line("pve1", "critical", 3, 3.0), // later reading of pve1 wins
    ]
    .join("\n");
    s.fleecing_bookkeeping(&job, &log).unwrap();
    let a = open(&s);
    assert_eq!(a.len(), 2, "{a:?}");
    assert_eq!(a[0].0, "fleecing_space:t1/pve1/local-lvm");
    assert_eq!(a[0].1, "critical");
    assert!(
        a[0].2.contains("has 3.0 GiB (3.0 %) free, below the critical level") && a[0].2.contains("backup job 7"),
        "{}",
        a[0].2
    );
    assert!(
        a[1].2.contains("below the guard: guests on this node are skipped"),
        "{}",
        a[1].2
    );
    let tenant: Option<String> =
        s.db.conn()
            .query_row("SELECT tenant FROM alerts WHERE key = ?1", [&a[0].0], |r| r.get(0))
            .unwrap();
    assert_eq!(tenant.as_deref(), Some("t1"));

    s.fleecing_bookkeeping(&job, &line("pve1", "ok", 40, 40.0)).unwrap();
    let a = open(&s);
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].0, "fleecing_space:t1/pve2/local-lvm", "pve2 is still low");
}

/// End to end: nexus-pve's output of a failed backup job reaches the bookkeeping.
#[test]
fn backup_job_output_raises_fleecing_space() {
    let e = env(1);
    let p = e.d.path();
    fs::remove_file(p.join("pve")).unwrap();
    script(
        &p.join("pve"),
        &format!(
            "echo '{}'; echo 'backup of guest 100 failed: guest skipped' >&2; exit 1",
            line("n1", "low", 5, 5.0)
        ),
    );
    let mut s = sched(&e);
    let id = manual(&s, "backup", "t1", json!({"group_id": 1}));
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    assert_eq!(state(&s, id), "failed");
    let a = open(&s);
    assert_eq!(a.len(), 1, "{a:?}");
    assert_eq!(a[0].0, "fleecing_space:t1/n1/local-lvm");
}
