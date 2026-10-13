use super::*;

/// The fake `nexus-pve`: `scan` prints `<dir>/scan.json`, everything else is logged to `calls`.
fn scanner(e: &Env, report: Option<Value>) {
    let d = e.d.path();
    fs::remove_file(&e.cfg.pve_bin).unwrap();
    script(
        &e.cfg.pve_bin,
        &format!(
            "echo \"$@\" >> {0}/calls\nif [ \"$2\" = scan ]; then cat {0}/scan.json || exit 1; else echo done; fi",
            d.display()
        ),
    );
    if let Some(r) = report {
        fs::write(d.join("scan.json"), r.to_string()).unwrap();
    }
}

fn rules(s: &Scheduler) {
    s.db.conn()
        .execute(
            "INSERT INTO yara_rules VALUES ('r.yar', 'rule Eicar { condition: true }', 'abcdef0123456789', 'sam', 1)",
            [],
        )
        .unwrap();
}

fn report(matches: u64, complete: bool) -> Value {
    let m: Vec<Value> = (0..matches)
        .map(|i| json!({"rule": "r.yar:Eicar", "path": format!("/vda1/f{i}.exe")}))
        .collect();
    json!({"files": 10, "skipped": 1, "errors": 0, "matches": m, "matches_total": matches, "complete": complete,
           "seconds": 3})
}

fn run_all(s: &mut Scheduler) {
    for _ in 0..4 {
        s.start_jobs().unwrap();
        s.wait_idle(Duration::from_secs(20)).unwrap();
    }
}

fn restore(s: &Scheduler, on_hit: &str) -> i64 {
    manual(
        s,
        "restore",
        "t1",
        json!({"source": "vm-100", "time": 5, "node": "n1", "target": 900, "storage": "x", "scan_first": on_hit}),
    )
}

fn log(s: &Scheduler, id: i64) -> String {
    s.db.conn()
        .query_row("SELECT log FROM jobs WHERE id=?1", [id], |r| r.get(0))
        .unwrap()
}

/// A scan with matches: result row, anomaly flag, critical `malware` alert, audit.
#[test]
fn scan_records_flags_and_alerts() {
    let e = env(2);
    let mut s = sched(&e);
    scanner(&e, Some(report(2, true)));
    // no rules: the job fails before the VM starts
    let id = manual(&s, "snapshot_scan", "t1", json!({"source": "vm-100", "time": 5}));
    s.start_jobs().unwrap();
    assert_eq!(state(&s, id), "failed");
    assert!(log(&s, id).contains("no YARA rules"));
    rules(&s);
    let id = manual(
        &s,
        "snapshot_scan",
        "t1",
        json!({"source": "vm-100", "time": 5, "budget": 600}),
    );
    run_all(&mut s);
    assert_eq!(state(&s, id), "ok");
    let calls = fs::read_to_string(e.d.path().join("calls")).unwrap();
    let line = calls.lines().find(|l| l.contains(" scan ")).unwrap();
    assert!(
        line.ends_with("scan vm-100 5 ") || line.contains("scan vm-100 5 "),
        "{line}"
    );
    assert!(line.ends_with("rules.json 600"), "{line}");
    let c = s.db.conn();
    let (total, rules, matches): (i64, String, String) = c
        .query_row(
            "SELECT matches_total, rules, matches FROM snapshot_scans WHERE job_id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!((total, rules.as_str()), (2, "r.yar@abcdef012345"));
    assert!(matches.contains("/vda1/f1.exe"));
    let flag: String = c
        .query_row(
            "SELECT anomaly FROM snapshots WHERE tenant='t1' AND source='vm-100' AND time=5",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(flag, "YARA: 2 matches (r.yar:Eicar)");
    let (sev, msg): (String, String) = c
        .query_row("SELECT severity, message FROM alerts WHERE kind='malware'", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(sev, "critical");
    assert!(msg.contains("r.yar:Eicar in /vda1/f0.exe"), "{msg}");
    let n: i64 = c
        .query_row("SELECT COUNT(*) FROM audit WHERE action='snapshot.scan'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(n, 1);
}

/// Scan first: a restore waits for its scan; clean → runs; hit → refused or
/// run with the NICs down; a failed scan refuses (fail-closed).
#[test]
fn scan_first_restores() {
    let e = env(2);
    let mut s = sched(&e);
    rules(&s);
    // clean
    scanner(&e, Some(report(0, true)));
    let r = restore(&s, "refuse");
    s.start_jobs().unwrap();
    assert_eq!(state(&s, r), "queued", "held for the scan");
    let scan: i64 =
        s.db.conn()
            .query_row(
                "SELECT json_extract(params, '$.scan_job') FROM jobs WHERE id=?1",
                [r],
                |x| x.get(0),
            )
            .unwrap();
    run_all(&mut s);
    assert_eq!((state(&s, scan).as_str(), state(&s, r).as_str()), ("ok", "ok"));
    assert!(log(&s, r).contains("scan first: clean"));
    let calls = fs::read_to_string(e.d.path().join("calls")).unwrap();
    let restore_line = calls.lines().find(|l| l.contains(" restore 100 5 n1 900")).unwrap();
    assert!(!restore_line.contains("--link-down"));

    // a hit, refuse
    scanner(&e, Some(report(1, true)));
    let r = restore(&s, "refuse");
    run_all(&mut s);
    assert_eq!(state(&s, r), "failed");
    assert!(log(&s, r).contains("1 YARA matches in the snapshot"), "{}", log(&s, r));
    assert!(log(&s, r).contains("restore refused"));

    // a hit, link down
    let r = restore(&s, "link_down");
    run_all(&mut s);
    assert_eq!(state(&s, r), "ok");
    assert!(log(&s, r).contains("restoring with the network disconnected"));
    let calls = fs::read_to_string(e.d.path().join("calls")).unwrap();
    assert!(calls
        .lines()
        .any(|l| l.contains(" restore 100 5 n1 900") && l.contains("--link-down")));

    // an incomplete scan is no clean verdict; link_down on a file restore cannot apply: refused
    scanner(&e, Some(report(0, false)));
    let r = manual(
        &s,
        "files_get",
        "t1",
        json!({"source": "vm-100", "time": 5, "paths": ["/vda1/x"], "format": "tar", "download_token": "ab",
               "scan_first": "link_down"}),
    );
    run_all(&mut s);
    assert_eq!(state(&s, r), "failed");
    assert!(log(&s, r).contains("did not finish within its time budget"));

    // the scan fails: refused
    fs::remove_file(e.d.path().join("scan.json")).unwrap();
    let r = restore(&s, "link_down");
    run_all(&mut s);
    assert_eq!(state(&s, r), "failed");
    assert!(log(&s, r).contains("failed; restore refused"));
    let n: i64 =
        s.db.conn()
            .query_row("SELECT COUNT(*) FROM audit WHERE action='restore.refused'", [], |r| {
                r.get(0)
            })
            .unwrap();
    assert_eq!(n, 3);

    // a job with scan_first but no verdict is never planned
    let j = Job {
        id: 99,
        kind: "restore".into(),
        tenant: "t1".into(),
        params: json!({"source": "vm-100", "time": 5, "node": "n1", "target": 900, "storage": "x",
                       "scan_first": "refuse", "scan_job": 1}),
    };
    assert!(s.plan(&j).is_err());
}
