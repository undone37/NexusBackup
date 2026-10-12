use super::*;

const DAY: u64 = 86400;

fn count(s: &Scheduler, sql: &str) -> i64 {
    s.db.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn run(s: &mut Scheduler, kind: &str, p: Value) -> String {
    let id = manual(s, kind, "t1", p);
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    state(s, id)
}

/// Active holds survive the group retention, the orphan sweep and an approved
/// delete, and go to nexus-offsite; advisory and released holds do not count;
/// released, the next retention prunes the snapshot.
#[test]
fn legal_holds_block_retention_orphans_and_delete() {
    let e = env(4);
    let mut s = sched(&e);
    let st = chunkstore::Store::open(
        e.cfg.store_base.join("t1"),
        Keyring::new("t1", &[(1, [7; 32])]),
        test_opts(),
    )
    .unwrap();
    for src in ["vm-100", "vm-999"] {
        for t in 1..=5 {
            st.commit_snapshot(src, t * DAY, &[("tree", chunkstore::Index::Tree { entries: vec![] })])
                .unwrap();
        }
    }
    let left = |src: &str| -> Vec<u64> {
        st.list_snapshots()
            .unwrap()
            .into_iter()
            .filter(|m| m.source == src)
            .map(|m| m.time / DAY)
            .collect()
    };
    catalog::set_setting(
        &s.db.conn(),
        orphans::ORPHAN_GFS,
        r#"{"daily":1,"weekly":0,"monthly":0,"yearly":0}"#,
    )
    .unwrap();
    s.db.conn()
        .execute_batch(&format!(
            "INSERT INTO legal_holds (tenant, source, time, state, reason, held_by, held_at, origin) VALUES
               ('t1', 'vm-100', {d1}, 'active', 'case', 'sam', 1, NULL),
               ('t1', 'vm-100', {d2}, 'released', 'old case', 'sam', 1, NULL),
               ('t1', 'vm-999', {d1}, 'active', 'case', 'sam', 1, NULL),
               ('t1', 'vm-999', {d2}, 'advisory', 'case', 'pat', 1, 'prim'),
               ('t2', 'vm-300', {d1}, 'active', 'other tenant', 'sam', 1, NULL);",
            d1 = DAY,
            d2 = 2 * DAY
        ))
        .unwrap();
    // group g1 keeps 3 daily
    assert_eq!(run(&mut s, "retention", json!({"group_id": 1})), "ok");
    assert_eq!(left("vm-100"), vec![1, 3, 4, 5]);
    // orphan sweep (daily 1): the held one stays, the advisory one does not
    assert_eq!(run(&mut s, "gc", json!({})), "ok");
    assert_eq!(left("vm-999"), vec![1, 5]);
    // an approved delete of a held snapshot fails
    assert_eq!(
        run(&mut s, "snapshot_delete", json!({"source": "vm-100", "time": DAY})),
        "failed"
    );
    assert_eq!(left("vm-100"), vec![1, 3, 4, 5]);
    // offsite retention gets the tenant's held snapshots
    s.db.conn()
        .execute(
            r#"UPDATE tenants SET offsite = '{"remote":{"type":"local","path":"/srv/box"}}' WHERE name = 't1'"#,
            [],
        )
        .unwrap();
    let files = s.offsite_config("t1", Path::new("/run/x")).unwrap().unwrap();
    let cfg: Value = serde_json::from_slice(&files.iter().find(|(n, _)| n == "offsite.json").unwrap().1).unwrap();
    assert_eq!(cfg["held"], json!([["vm-100", DAY], ["vm-999", DAY]]));
    // released: pruned by the next run
    s.db.conn()
        .execute("UPDATE legal_holds SET state = 'released' WHERE source = 'vm-100'", [])
        .unwrap();
    assert_eq!(run(&mut s, "retention", json!({"group_id": 1})), "ok");
    assert_eq!(left("vm-100"), vec![3, 4, 5]);
}

/// The primary's holds become advisory rows with one warning each (only for
/// snapshots this secondary has), are not enforced, and are withdrawn (alert
/// resolved) when the primary stops reporting them; applied ones stay.
#[test]
fn replication_hold_advisories() {
    let e = env(4);
    let s = sched(&e);
    s.db.conn()
        .execute_batch(
            "INSERT INTO snapshots (tenant, source, time, local, offsite, origin) VALUES
               ('t1', 'vm-100', 10, 1, 0, 'prim'), ('t1', 'vm-100', 20, 1, 0, 'prim');",
        )
        .unwrap();
    let h = |time: u64| replication::HoldInfo {
        source: "vm-100".into(),
        time,
        reason: "case 7".into(),
        held_by: "pat".into(),
        held_at: 5,
    };
    let all = [h(10), h(20), h(30), h(40)];
    for _ in 0..2 {
        s.hold_advisories("t1", "prim", &all, &["vm-100/30".into()]).unwrap();
    }
    assert_eq!(
        count(
            &s,
            "SELECT COUNT(*) FROM legal_holds WHERE state = 'advisory' AND origin = 'prim'"
        ),
        3,
        "40 is not on this appliance"
    );
    assert!(
        catalog::holds::held(&s.db.conn(), "t1").unwrap().is_empty(),
        "not enforced"
    );
    assert_eq!(
        count(
            &s,
            "SELECT COUNT(*) FROM alerts WHERE kind = 'legal_hold_advisory' AND count = 1"
        ),
        3
    );
    let msg: String =
        s.db.conn()
            .query_row(
                "SELECT message FROM alerts WHERE key = 'legal_hold_advisory:t1/vm-100/10'",
                [],
                |r| r.get(0),
            )
            .unwrap();
    assert!(msg.contains("case 7") && msg.contains("pat"), "{msg}");
    // the officer applies 10 (web-api); the primary releases everything
    s.db.conn()
        .execute(
            "UPDATE legal_holds SET state = 'active', held_by = 'sam' WHERE time = 10",
            [],
        )
        .unwrap();
    s.hold_advisories("t1", "prim", &[], &[]).unwrap();
    assert_eq!(
        count(&s, "SELECT COUNT(*) FROM legal_holds WHERE state = 'withdrawn'"),
        2
    );
    assert_eq!(
        count(
            &s,
            "SELECT COUNT(*) FROM legal_holds WHERE state = 'active' AND time = 10"
        ),
        1,
        "an applied hold is this appliance's own"
    );
    assert_eq!(
        count(
            &s,
            "SELECT COUNT(*) FROM alerts WHERE kind = 'legal_hold_advisory' AND resolved_at IS NULL"
        ),
        1,
        "withdrawn ones resolved (the applied one is resolved by the web-api)"
    );
    assert_eq!(
        count(
            &s,
            "SELECT COUNT(*) FROM audit WHERE action = 'snapshot.hold_withdrawn'"
        ),
        2
    );
}
