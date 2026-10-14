//! Phase 29 (NetBackup Tier 1): full read due per source and its bookkeeping,
//! frozen deletions and restores, restores of flagged snapshots, scan back.

use super::*;

fn run_all(s: &mut Scheduler) {
    for _ in 0..8 {
        s.start_jobs().unwrap();
        s.wait_idle(Duration::from_secs(20)).unwrap();
    }
}

fn log_of(s: &Scheduler, id: i64) -> String {
    s.db.conn()
        .query_row("SELECT log FROM jobs WHERE id=?1", [id], |r| r.get(0))
        .unwrap()
}

/// The fake nexus-pve keeps a copy of its config and prints `out`.
fn pve_printing(e: &Env, out: &str) {
    let d = e.d.path();
    fs::remove_file(&e.cfg.pve_bin).unwrap();
    script(
        &e.cfg.pve_bin,
        &format!(
            "echo \"$@\" >> {0}/calls\ncp \"$1\" {0}/cfg-copy.json\ncat <<'EOF'\n{out}\nEOF",
            d.display()
        ),
    );
}

fn copied_cfg(e: &Env) -> Value {
    serde_json::from_slice(&fs::read(e.d.path().join("cfg-copy.json")).unwrap()).unwrap()
}

/// A due source with a snapshot is read in full; the connector's line lands
/// in `full_reads`, the log and (drift) the `change_tracking` alert.
#[test]
fn full_read_due_patch_and_bookkeeping() {
    let e = env(2);
    let mut s = sched(&e);
    s.db.conn()
        .execute_batch(
            "INSERT INTO snapshots (tenant, source, time, size, local, offsite, lock_until) VALUES
               ('t1','vm-100',4,1,1,0,0);
             UPDATE groups SET full_read_days = 30 WHERE id = 1;",
        )
        .unwrap();
    pve_printing(&e, "committed vm-100/9");
    // first sight: a row, due somewhere within the interval (not read in full yet unless the stagger is 0)
    let a = manual(&s, "backup", "t1", json!({"group_id": 1}));
    run_all(&mut s);
    assert_eq!(state(&s, a), "ok");
    let due: i64 =
        s.db.conn()
            .query_row("SELECT next_due FROM full_reads WHERE source = 'vm-100'", [], |r| {
                r.get(0)
            })
            .unwrap();
    assert!(due <= catalog::now() + 30 * 86_400);
    // due now
    s.db.conn().execute("UPDATE full_reads SET next_due = 1", []).unwrap();
    pve_printing(
        &e,
        r#"committed vm-100/10
full-read vm-100/10 {"tracker":"dirty-bitmap","baseline":9,"compared":256,"changed":12,"unreported":2,"unreported_bytes":8388608,"examples":["drive-scsi0@0","drive-scsi0@4194304"]}"#,
    );
    let b = manual(&s, "backup", "t1", json!({"group_id": 1}));
    run_all(&mut s);
    assert_eq!(state(&s, b), "ok");
    assert_eq!(copied_cfg(&e)["full_read"], json!([100]));
    let (result, unreported, next, clean): (String, i64, i64, Option<i64>) =
        s.db.conn()
            .query_row(
                "SELECT result, unreported, next_due, last_clean_at FROM full_reads WHERE source = 'vm-100'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
    assert_eq!((result.as_str(), unreported, clean), ("drift", 2, None));
    assert!(next > catalog::now() + 29 * 86_400);
    assert!(log_of(&s, b).contains("[scheduler] full read of vm-100/10: 2 changes (8388608 bytes)"));
    let (sev, msg): (String, String) =
        s.db.conn()
            .query_row(
                "SELECT severity, message FROM alerts WHERE kind = 'change_tracking'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
    assert_eq!(sev, "critical");
    assert!(msg.contains("drive-scsi0@0"), "{msg}");
    // not due any more: no full read; off: none either
    pve_printing(&e, "committed vm-100/11");
    let c = manual(&s, "backup", "t1", json!({"group_id": 1}));
    run_all(&mut s);
    assert_eq!(state(&s, c), "ok");
    assert!(copied_cfg(&e)["full_read"].is_null());
    s.db.conn()
        .execute_batch("UPDATE full_reads SET next_due = 1; UPDATE groups SET full_read_days = 0 WHERE id = 1;")
        .unwrap();
    let d = manual(&s, "backup", "t1", json!({"group_id": 1}));
    run_all(&mut s);
    assert_eq!(state(&s, d), "ok");
    assert!(copied_cfg(&e)["full_read"].is_null(), "off");
    // a clean full read records the verified time
    s.db.conn()
        .execute("UPDATE groups SET full_read_days = NULL WHERE id = 1", [])
        .unwrap();
    pve_printing(
        &e,
        r#"committed vm-100/12
full-read vm-100/12 {"tracker":"dirty-bitmap","baseline":11,"compared":256,"changed":3,"unreported":0,"unreported_bytes":0,"examples":[]}"#,
    );
    let f = manual(&s, "backup", "t1", json!({"group_id": 1}));
    run_all(&mut s);
    assert_eq!(state(&s, f), "ok");
    let (result, clean, next): (String, Option<i64>, i64) =
        s.db.conn()
            .query_row(
                "SELECT result, last_clean_at, next_due FROM full_reads WHERE source = 'vm-100'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
    assert_eq!(result, "clean");
    assert!(clean.is_some());
    assert!(next > catalog::now() + 89 * 86_400, "PVE default: 90 days");
}

/// Frozen deletions: retention steps leave the plan (with a log line), a
/// snapshot delete is refused. Frozen restores: production restores fail.
#[test]
fn freezes_trim_deletions_and_refuse_restores() {
    let e = env(2);
    let mut s = sched(&e);
    catalog::set_setting(
        &s.db.conn(),
        "incident",
        r#"{"active": true, "freeze": {"config": false, "deletions": true, "restores": true}}"#,
    )
    .unwrap();
    let r = manual(&s, "retention", "t1", json!({"group_id": 1}));
    let p = s.plan(&s.job(r).unwrap()).unwrap();
    assert!(
        !p.steps.iter().any(|x| matches!(x, Step::Retention { .. })),
        "{:?}",
        p.steps
    );
    assert!(matches!(&p.steps[0], Step::Note(l) if l.contains("deletions frozen")));
    let del = manual(&s, "snapshot_delete", "t1", json!({"source": "vm-100", "time": 4}));
    assert!(format!("{:#}", s.plan(&s.job(del).unwrap()).unwrap_err()).contains("deletions frozen"));
    let rs = manual(
        &s,
        "restore",
        "t1",
        json!({"source": "vm-100", "time": 4, "node": "n1", "target": 900, "storage": "local"}),
    );
    assert!(format!("{:#}", s.plan(&s.job(rs).unwrap()).unwrap_err()).contains("restores to production are frozen"));
    run_all(&mut s);
    assert_eq!(state(&s, r), "ok");
    assert!(log_of(&s, r).contains("[scheduler] deletions frozen (incident mode): retention skipped"));
    assert_eq!(state(&s, rs), "failed");
    // the tenant's lockdown freezes only its own tenant
    catalog::set_setting(&s.db.conn(), "incident", r#"{"active": false}"#).unwrap();
    s.db.conn()
        .execute(
            "INSERT INTO tenant_lockdowns (tenant, active, state) VALUES ('t2', 1, ?1)",
            [r#"{"active": true, "freeze": {"deletions": true, "restores": false}}"#],
        )
        .unwrap();
    let r1 = manual(&s, "retention", "t1", json!({"group_id": 1}));
    assert!(s
        .plan(&s.job(r1).unwrap())
        .unwrap()
        .steps
        .iter()
        .any(|x| matches!(x, Step::Retention { .. })));
    let r2 = manual(&s, "retention", "t2", json!({"group_id": 4}));
    assert!(!s
        .plan(&s.job(r2).unwrap())
        .unwrap()
        .steps
        .iter()
        .any(|x| matches!(x, Step::Retention { .. })));
}

/// A production restore of a flagged snapshot runs only with an approved
/// `restore.infected` request, which the scheduler turns into the job.
#[test]
fn flagged_snapshot_restore_needs_the_approval() {
    let e = env(2);
    let mut s = sched(&e);
    s.db.conn()
        .execute_batch(
            "INSERT INTO snapshots (tenant, source, time, size, local, offsite, lock_until, scan_state, anomaly) VALUES
               ('t1','vm-100',4,1,1,0,0,'hit','YARA: 1 matches (Eicar)');",
        )
        .unwrap();
    let p = json!({"source": "vm-100", "time": 4, "node": "n1", "target": 900, "storage": "local"});
    let plain = manual(&s, "restore", "t1", p.clone());
    let mut iso = p.clone();
    iso["link_down"] = json!(true);
    let isolated = manual(&s, "restore", "t1", iso);
    run_all(&mut s);
    assert_eq!(state(&s, plain), "failed");
    assert!(log_of(&s, plain).contains("needs the approval restore.infected"));
    assert_eq!(state(&s, isolated), "ok");
    // approved request: queued by the scheduler with the quorum id, then runs
    let q = {
        let c = s.db.conn();
        c.execute(
            "INSERT INTO quorum (action, params, requested_by, created, decided_by, decided_at, state)
             VALUES ('restore.infected', ?1, 'otto', 1, 'sam', 2, 'approved')",
            [json!({"tenant": "t1", "kind": "restore", "params": p, "reason": "x"}).to_string()],
        )
        .unwrap();
        c.last_insert_rowid()
    };
    s.queue_restore_replaces().unwrap();
    s.queue_restore_replaces().unwrap();
    let ids: Vec<i64> =
        s.db.conn()
            .prepare("SELECT id FROM jobs WHERE json_extract(params, '$.quorum_id') = ?1")
            .unwrap()
            .query_map([q], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
    assert_eq!(ids.len(), 1, "queued once");
    run_all(&mut s);
    assert_eq!(state(&s, ids[0]), "ok", "{}", log_of(&s, ids[0]));
    let qs: String =
        s.db.conn()
            .query_row("SELECT state FROM quorum WHERE id = ?1", [q], |r| r.get(0))
            .unwrap();
    assert_eq!(qs, "executed");
}

/// Scan back: one stop-on-match scan per snapshot, newest first, until a clean
/// one; that becomes the clean point; the hits are flagged without alerts.
#[test]
fn scan_back_to_the_last_clean_snapshot() {
    let e = env(2);
    let mut s = sched(&e);
    let d = e.d.path();
    fs::remove_file(&e.cfg.pve_bin).unwrap();
    script(
        &e.cfg.pve_bin,
        &format!("echo \"$@\" >> {0}/calls\ncat {0}/scan-$4.json", d.display()),
    );
    let hit = json!({"files": 3, "skipped": 0, "errors": 0, "matches": [{"rule": "r.yar:Ransom", "path": "/x"}],
                     "matches_total": 1, "complete": false, "stopped": true, "seconds": 1});
    let clean = json!({"files": 9, "skipped": 0, "errors": 0, "matches": [], "matches_total": 0, "complete": true,
                       "stopped": false, "seconds": 2});
    for (t, r) in [(5, &hit), (4, &hit), (3, &clean)] {
        fs::write(d.join(format!("scan-{t}.json")), r.to_string()).unwrap();
    }
    s.db.conn()
        .execute_batch(
            "INSERT INTO yara_rules VALUES ('r.yar', 'rule Ransom { condition: true }', 'abcdef', 'sam', 1);
             INSERT INTO snapshots (tenant, source, time, size, local, offsite, lock_until) VALUES
               ('t1','vm-100',2,1,1,0,0), ('t1','vm-100',3,1,1,0,0), ('t1','vm-100',4,1,1,0,0),
               ('t1','vm-100',5,1,1,0,0), ('t1','vm-101',4,1,1,0,0);
             UPDATE snapshots SET clean_point = 7 WHERE source = 'vm-100' AND time = 2;",
        )
        .unwrap();
    let id = manual(
        &s,
        "scan_back",
        "t1",
        json!({"source": "vm-100", "from": 5, "budget": 600}),
    );
    run_all(&mut s);
    assert_eq!(state(&s, id), "ok", "{}", log_of(&s, id));
    let result: Value = serde_json::from_str(
        &s.db
            .conn()
            .query_row("SELECT result FROM jobs WHERE id = ?1", [id], |r| r.get::<_, String>(0))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(result["recommended"], 3);
    assert_eq!(
        result["scanned"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| (x["time"].as_i64().unwrap(), x["matches_total"].as_u64().unwrap()))
            .collect::<Vec<_>>(),
        [(5, 1), (4, 1), (3, 0)]
    );
    let calls = fs::read_to_string(d.join("calls")).unwrap();
    assert_eq!(calls.matches("--stop-on-match").count(), 3, "{calls}");
    assert!(calls.contains(" 600 --stop-on-match"));
    let points: Vec<(i64, Option<i64>, Option<String>, bool)> = s
        .db
        .conn()
        .prepare("SELECT time, clean_point, scan_state, anomaly IS NOT NULL FROM snapshots WHERE source = 'vm-100' ORDER BY time")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(points[0].1, None, "the older clean point is replaced");
    assert!(points[1].1.is_some());
    assert_eq!(points[1].2.as_deref(), Some("clean"));
    assert_eq!((points[2].2.as_deref(), points[2].3), (Some("hit"), true));
    assert_eq!((points[3].2.as_deref(), points[3].3), (Some("hit"), true));
    let alerts: i64 =
        s.db.conn()
            .query_row(
                "SELECT COUNT(*) FROM alerts WHERE kind IN ('malware', 'scan_hit')",
                [],
                |r| r.get(0),
            )
            .unwrap();
    assert_eq!(alerts, 0, "hits of a scan back are expected");
    let rows: i64 =
        s.db.conn()
            .query_row("SELECT COUNT(*) FROM snapshot_scans WHERE source = 'vm-100'", [], |r| {
                r.get(0)
            })
            .unwrap();
    assert_eq!(rows, 3);

    // no clean snapshot within max: ends without a recommendation, truncated
    for t in [4, 3] {
        fs::write(d.join(format!("scan-{t}.json")), hit.to_string()).unwrap();
    }
    let id = manual(&s, "scan_back", "t1", json!({"source": "vm-100", "from": 4, "max": 2}));
    run_all(&mut s);
    assert_eq!(state(&s, id), "ok");
    let r: Value = serde_json::from_str(
        &s.db
            .conn()
            .query_row("SELECT result FROM jobs WHERE id = ?1", [id], |r| r.get::<_, String>(0))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        (r["recommended"].clone(), r["truncated"].clone()),
        (Value::Null, json!(true))
    );
    // a failed scan fails the scan back
    fs::remove_file(d.join("scan-4.json")).unwrap();
    let id = manual(&s, "scan_back", "t1", json!({"source": "vm-101", "from": 4}));
    run_all(&mut s);
    assert_eq!(state(&s, id), "failed");
}
