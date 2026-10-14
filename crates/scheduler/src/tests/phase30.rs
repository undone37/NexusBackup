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

/// Instant rollback: an approved `restore.replace` with `rollback` runs
/// `nexus-pve restore … --replace --rollback`; its `rolled-back` line is the job
/// result.
#[test]
fn rollback_restore_flags_and_result() {
    let e = env(1);
    let mut s = sched(&e);
    let d = e.d.path();
    fs::remove_file(&e.cfg.pve_bin).unwrap();
    script(
        &e.cfg.pve_bin,
        &format!(
            "echo \"$@\" >> {0}/calls\necho 'committed vm-100/9'\n\
             echo 'rolled-back {{\"vmid\":100,\"snapshot\":4,\"pre_snapshot\":9,\"disks\":[{{\"device\":\"drive-scsi0\",\"chunks\":8,\"changed\":2,\"bytes_written\":8388608}}]}}'",
            d.display()
        ),
    );
    s.db.conn()
        .execute_batch(
            "INSERT INTO snapshots (tenant, source, time, size, local, offsite, lock_until) VALUES ('t1','vm-100',4,1,1,0,0);",
        )
        .unwrap();
    let p = json!({"source": "vm-100", "time": 4, "node": "n1", "target": 900, "storage": "local", "rollback": true});
    let q = {
        let c = s.db.conn();
        c.execute(
            "INSERT INTO quorum (action, params, requested_by, created, decided_by, decided_at, state)
             VALUES ('restore.replace', ?1, 'otto', 1, 'sam', 2, 'approved')",
            [json!({"tenant": "t1", "kind": "restore", "params": p}).to_string()],
        )
        .unwrap();
        c.last_insert_rowid()
    };
    s.queue_restore_replaces().unwrap();
    for _ in 0..4 {
        s.start_jobs().unwrap();
        s.wait_idle(Duration::from_secs(20)).unwrap();
    }
    let (id, st, result): (i64, String, Option<String>) =
        s.db.conn()
            .query_row(
                "SELECT id, state, result FROM jobs WHERE json_extract(params, '$.quorum_id') = ?1",
                [q],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
    assert_eq!(st, "ok", "job {id}");
    let calls = fs::read_to_string(d.join("calls")).unwrap();
    assert!(
        calls
            .lines()
            .any(|l| l.ends_with("restore 100 4 n1 900 local --replace --rollback")),
        "{calls}"
    );
    let r: Value = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(
        (r["rolled_back"].clone(), r["pre_snapshot"].clone()),
        (json!(true), json!(9))
    );
    // a container restore never rolls back in place
    let mut ct = p.clone();
    ct["source"] = json!("ct-100");
    let job = Job {
        id: 0,
        kind: "restore_ct".into(),
        tenant: "t1".into(),
        params: {
            let mut x = ct;
            x["replace"] = json!(true);
            x["quorum_id"] = json!(1);
            x
        },
    };
    let flags = crate::restore::restore_flags(&job).unwrap();
    assert!(flags.contains(&"--replace".to_owned()) && !flags.contains(&"--rollback".to_owned()));
}

/// Second offsite target: its own job config (`offsite2.json`, own state dir,
/// own retention never below the policies'), one chained offsite job per
/// target, copy status per target from each target's listing, `offsite_lag`
/// per target, egress to both.
#[test]
fn second_offsite_target() {
    let mut e = env(2);
    fs::create_dir_all(e.d.path().join("nft")).unwrap();
    e.cfg.firewall_settle_secs = 0;
    e.cfg.nft_allowed = e.d.path().join("nft/allowed.json");
    e.cfg.net_dir = e.d.path().join("net");
    fs::create_dir(&e.cfg.net_dir).unwrap();
    let d = e.d.path().to_owned();
    fs::remove_file(&e.cfg.offsite_bin).unwrap();
    // the fake nexus-offsite: target 1 holds vm-100/4, target 2 vm-100/5
    script(
        &e.cfg.offsite_bin,
        &format!(
            "echo \"$@\" >> {0}/calls\ncase \"$1\" in *offsite2.json) [ \"$2\" = list ] && echo vm-100/5 ;; \
             *) [ \"$2\" = list ] && echo vm-100/4 ;; esac\nexit 0",
            d.display()
        ),
    );
    let offsite = json!({
        "remote": {"type": "sftp", "host": "192.0.2.41", "port": 23, "user": "u1", "host_key": "k", "key_file": "/k"},
        "second": {"remote": {"type": "sftp", "host": "192.0.2.42", "port": 2323, "user": "u2", "host_key": "k",
                              "key_file": "/k"},
                   "gfs": {"daily": 1, "monthly": 84, "yearly": 7}, "uploaders": 2}});
    e.db.conn()
        .execute_batch(&format!(
            "UPDATE policies SET offsite = 1, gfs = '{{\"daily\":3,\"monthly\":2}}';
             UPDATE tenants SET offsite = '{offsite}' WHERE name = 't1';"
        ))
        .unwrap();
    let mut s = sched(&e);

    // job config of target 2: own file names, state dir and retention (max with the policies')
    let job = Job {
        id: 1,
        kind: "offsite".into(),
        tenant: "t1".into(),
        params: json!({"target": 2}),
    };
    let p = s.plan(&job).unwrap();
    let cfg: Value = serde_json::from_slice(&p.files.iter().find(|f| f.0 == "offsite2.json").unwrap().1).unwrap();
    assert_eq!(cfg["remote"]["host"], "192.0.2.42");
    assert_eq!(cfg["uploaders"], 2);
    assert_eq!(
        cfg["gfs"],
        json!({"daily": 3, "weekly": 4, "monthly": 84, "yearly": 7}),
        "never shorter than local, longer where the target asks"
    );
    assert_eq!(cfg["state"], json!(e.cfg.offsite_state_base.join(".second").join("t1")));
    assert!(cfg.get("second").is_none());
    let args: Vec<String> = p
        .steps
        .iter()
        .filter_map(|st| match st {
            Step::Cli { args, .. } => Some(args.join(" ")),
            _ => None,
        })
        .collect();
    assert!(args.iter().all(|a| a.contains("offsite2.json")), "{args:?}");
    // target 1 keeps the policies' retention and its own state dir
    let p1 = s
        .plan(&Job {
            id: 2,
            kind: "offsite".into(),
            tenant: "t1".into(),
            params: json!({}),
        })
        .unwrap();
    let cfg1: Value = serde_json::from_slice(&p1.files.iter().find(|f| f.0 == "offsite.json").unwrap().1).unwrap();
    assert_eq!(cfg1["gfs"], json!({"daily": 3, "weekly": 4, "monthly": 2, "yearly": 2}));
    assert_eq!(cfg1["state"], json!(e.cfg.offsite_state_base.join("t1")));
    // gc and verify cover both targets
    for kind in ["gc", "verify"] {
        let p = s
            .plan(&Job {
                id: 3,
                kind: kind.into(),
                tenant: "t1".into(),
                params: json!({}),
            })
            .unwrap();
        let n = p
            .steps
            .iter()
            .filter(|st| matches!(st, Step::Cli { args, .. } if args[0].ends_with("offsite.json") || args[0].ends_with("offsite2.json")))
            .count();
        assert_eq!(n, 2, "{kind}");
    }

    // a backup chains (after its retention) one offsite job per target
    let b = manual(&s, "backup", "t1", json!({"group_id": 1}));
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    assert_eq!(state(&s, b), "ok");
    s.db.conn()
        .execute("UPDATE jobs SET state = 'held' WHERE kind = 'offsite'", [])
        .unwrap();
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    let targets: Vec<Option<i64>> =
        s.db.conn()
            .prepare("SELECT json_extract(params, '$.target') FROM jobs WHERE kind = 'offsite' ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
    assert_eq!(targets, vec![None, Some(2)]);

    // copy status per target from each listing
    chunkstore::Store::open(
        e.cfg.store_base.join("t1"),
        Keyring::new("t1", &[(1, [7; 32])]),
        test_opts(),
    )
    .unwrap();
    s.db.conn().execute("DELETE FROM jobs", []).unwrap();
    s.refresh(catalog::now(), true).unwrap();
    let rows: Vec<(i64, i64, i64)> =
        s.db.conn()
            .prepare("SELECT time, offsite, offsite2 FROM snapshots WHERE tenant = 't1' ORDER BY time")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
    assert_eq!(rows, vec![(4, 1, 0), (5, 0, 1)]);

    // lag per target: a local snapshot on target 1 only
    let old = catalog::now() - 10 * 86_400;
    s.db.conn()
        .execute(
            "INSERT INTO snapshots (tenant, source, time, size, local, offsite, offsite2) VALUES ('t1','vm-100',?1,1,1,1,0)",
            [old],
        )
        .unwrap();
    s.check_offsite_lag(catalog::now()).unwrap();
    let keys: Vec<String> =
        s.db.conn()
            .prepare("SELECT key FROM alerts WHERE kind = 'offsite_lag' AND resolved_at IS NULL")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
    assert_eq!(keys, vec!["offsite_lag:t1:2".to_owned()]);

    // egress to both boxes
    s.sync_firewall().unwrap();
    let a = nftsync::Allowed::load(&s.cfg.nft_allowed).unwrap();
    let ports: Vec<u16> = a.roles["offsite"].endpoints.iter().map(|x| x.port).collect();
    assert!(ports.contains(&23) && ports.contains(&2323), "{ports:?}");
}
