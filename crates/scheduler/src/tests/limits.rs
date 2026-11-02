use super::*;

/// The PVE source's caps and read limit end up in pve.json; the group's
/// parallel guests stay (nexus-pve applies `max_parallel` on top).
#[test]
fn pve_limits_in_the_job_config() {
    let e = env(1);
    let s = sched(&e);
    {
        let c = s.db.conn();
        let cfg: String = c
            .query_row("SELECT config FROM sources WHERE id=1", [], |r| r.get(0))
            .unwrap();
        let mut v: Value = serde_json::from_str(&cfg).unwrap();
        v["max_parallel"] = json!(2);
        v["storage_caps"] = json!({"ceph": 1});
        v["read_limit"] = json!({"bwlimit": 50_000_000, "timezone": "UTC"});
        c.execute("UPDATE sources SET config=?1 WHERE id=1", [v.to_string()])
            .unwrap();
        c.execute("UPDATE groups SET parallel_guests=4 WHERE id=1", []).unwrap();
    }
    let id = manual(&s, "backup", "t1", json!({"group_id": 1}));
    let plan = s.plan(&s.job(id).unwrap()).unwrap();
    let (_, body) = plan.files.iter().find(|(n, _)| n == "pve.json").unwrap();
    let cfg: Value = serde_json::from_slice(body).unwrap();
    assert_eq!(cfg["parallel"], 4);
    assert_eq!(cfg["max_parallel"], 2);
    assert_eq!(cfg["storage_caps"], json!({"ceph": 1}));
    assert_eq!(cfg["read_limit"]["bwlimit"], 50_000_000);
}

/// VM identity lines: kept in snapshots.meta (merged with what is there), a
/// changed identity raises `vmid_reused`; TrueNAS snapshot names become the
/// next run's references.
#[test]
fn identity_and_zfs_references() {
    let e = env(1);
    let s = sched(&e);
    s.db.conn()
        .execute(
            "INSERT INTO snapshots (tenant, source, time, local, offsite, meta) VALUES ('t1','vm-100',10,1,0,'{\"keep\":1}')",
            [],
        )
        .unwrap();
    let job = Job {
        id: 9,
        kind: "backup".into(),
        tenant: "t1".into(),
        params: json!({"group_id": 1}),
    };
    let log = "identity vm-100/10 {\"vmgenid\":\"g2\",\"smbios_uuid\":\"u2\",\"changed\":true,\"previous\":{\"vmgenid\":\"g1\",\"smbios_uuid\":\"u1\"}}\n\
               identity vm-101/11 {\"vmgenid\":\"x\",\"smbios_uuid\":\"y\",\"changed\":false,\"previous\":null}\n\
               result {\"snapshots\":[{\"source\":\"nas-5-tank.data\",\"time\":20,\"meta\":{\"zfs_snapshot\":\"auto-a\"}}]}\n";
    s.backup_meta_bookkeeping(&job, log).unwrap();
    let meta = |src: &str| -> Value {
        let m: String =
            s.db.conn()
                .query_row(
                    "SELECT meta FROM snapshots WHERE tenant='t1' AND source=?1",
                    [src],
                    |r| r.get(0),
                )
                .unwrap();
        serde_json::from_str(&m).unwrap()
    };
    assert_eq!(meta("vm-100")["keep"], 1, "merged");
    assert_eq!(meta("vm-100")["identity"]["vmgenid"], "g2");
    assert_eq!(meta("vm-101")["identity"]["changed"], false);
    let alerts: Vec<(String, String)> = {
        let c = s.db.conn();
        let mut q = c
            .prepare("SELECT key, message FROM alerts WHERE kind='vmid_reused'")
            .unwrap();
        let rows = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        rows.map(Result::unwrap).collect()
    };
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_eq!(alerts[0].0, "vmid_reused:t1/vm-100");
    assert!(alerts[0].1.contains("g1 → g2"), "{}", alerts[0].1);

    // a newer snapshot without a recorded snapshot name does not hide the older one
    s.db.conn()
        .execute(
            "INSERT INTO snapshots (tenant, source, time, local, offsite) VALUES ('t1','nas-5-tank.data',30,1,0)",
            [],
        )
        .unwrap();
    let mut cfg = json!({});
    s.truenas_limits(
        "t1",
        5,
        &json!({"existing_snapshots": "auto-", "read_limit": {"bwlimit": 1}}),
        &mut cfg,
    )
    .unwrap();
    assert_eq!(cfg["existing_snapshots"], "auto-");
    assert_eq!(cfg["read_limit"]["bwlimit"], 1);
    assert_eq!(
        cfg["references"],
        json!({"nas-5-tank.data": {"time": 20, "snapshot": "auto-a"}})
    );
    let mut plain = json!({});
    s.truenas_limits("t1", 5, &json!({}), &mut plain).unwrap();
    assert_eq!(plain, json!({}), "create mode: no references");
}

/// Instant disk recovery: only to a VM a group of the tenant protects on the
/// snapshot's source; the CLI gets the slot and the move target.
#[test]
fn instant_disk_plan() {
    let e = env(1);
    let s = sched(&e);
    let p = json!({"source": "vm-100", "time": 1700000000, "device": "drive-scsi1", "node": "n1",
                   "target": 101, "key": "scsi5", "move_to": "local-lvm"});
    let id = manual(&s, "instant_disk", "t1", p.clone());
    let plan = s.plan(&s.job(id).unwrap()).unwrap();
    assert_eq!(plan.key, "guest:t1/vm-100");
    let Step::Cli { args, .. } = &plan.steps[0] else {
        panic!()
    };
    assert_eq!(
        args[1..].to_vec(),
        [
            "instant-disk",
            "100",
            "1700000000",
            "drive-scsi1",
            "n1",
            "101",
            "--key",
            "scsi5",
            "--move-to",
            "local-lvm"
        ]
    );
    // VM 300 belongs to tenant t2; 999 to nobody
    for target in [300, 999] {
        let mut q = p.clone();
        q["target"] = json!(target);
        let id = manual(&s, "instant_disk", "t1", q);
        let err = s.plan(&s.job(id).unwrap()).unwrap_err().to_string();
        assert!(err.contains("not protected by a group of tenant t1"), "{err}");
    }
    let mut bad = p.clone();
    bad["device"] = json!("config");
    let id = manual(&s, "instant_disk", "t1", bad);
    assert!(s.plan(&s.job(id).unwrap()).is_err());
}

/// #137: a plugin's snapshot meta carrying the source system's own change-rate finding (NexusStor) flags that
/// snapshot and raises `anomaly`, naming the newest clean snapshot from no later than the system's last good
/// state; control characters from the source system do not reach the message.
#[test]
fn source_system_anomaly_from_plugin_meta() {
    let e = env(1);
    let s = sched(&e);
    let src = "plugin-nexusstor-3-acme";
    for t in [100, 200] {
        s.db.conn()
            .execute(
                "INSERT INTO snapshots (tenant, source, time, local, offsite) VALUES ('t1', ?1, ?2, 1, 0)",
                catalog::rusqlite::params![src, t],
            )
            .unwrap();
    }
    let job = Job {
        id: 11,
        kind: "backup".into(),
        tenant: "t1".into(),
        params: json!({"group_id": 1}),
    };
    // NexusStor: last good at 150, the jump found at 250; NexusBackup's snapshot 200 may hold it already
    let result = json!({"snapshots": [{"source": src, "time": 300, "meta": {"vstor": "acme", "anomaly": {
        "system": "NexusStor nas1", "snapshot": "auto-daily-\u{1b}[31m1", "at": 250,
        "last_good": "auto-daily-0", "last_good_created": 150}}}]});
    s.meta_bookkeeping(&job, Some(&result)).unwrap();
    let flag: Option<String> =
        s.db.conn()
            .query_row(
                "SELECT anomaly FROM snapshots WHERE tenant='t1' AND source=?1 AND time=300",
                [src],
                |r| r.get(0),
            )
            .unwrap();
    assert!(flag.unwrap().contains("NexusStor nas1 reported a change-rate anomaly"));
    let (sev, msg): (String, String) =
        s.db.conn()
            .query_row(
                "SELECT severity, message FROM alerts WHERE kind='anomaly' AND key=?1",
                [format!("anomaly:t1/{src}")],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
    assert_eq!(sev, "critical");
    assert!(
        msg.contains(&format!("{src}/100")),
        "the snapshot before the last good state: {msg}"
    );
    assert!(!msg.contains(&format!("{src}/200")), "{msg}");
    assert!(!msg.contains('\u{1b}'), "{msg}");
}

/// #43: a database plugin's `chain_break` raises log_chain (critical); the next snapshot with a recoverable range
/// and no break resolves it.
#[test]
fn log_chain_break_from_plugin_meta() {
    let e = env(1);
    let s = sched(&e);
    let src = "plugin-postgresql-4";
    let job = Job {
        id: 12,
        kind: "backup".into(),
        tenant: "t1".into(),
        params: json!({"group_id": 1}),
    };
    let open = |s: &Scheduler| -> Vec<(String, String)> {
        let c = s.db.conn();
        let mut q = c
            .prepare("SELECT severity, message FROM alerts WHERE kind='log_chain' AND resolved_at IS NULL")
            .unwrap();
        let rows = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        rows.map(Result::unwrap).collect()
    };
    let snap = |t: i64, meta: Value| json!({"snapshots": [{"source": src, "time": t, "meta": meta}]});
    s.meta_bookkeeping(&job, Some(&snap(100, json!({"recoverable": {"from_time": 90}, "chain_break": "WAL streaming refused (requested WAL segment has already been removed)\u{1b}[31m"}))))
        .unwrap();
    let a = open(&s);
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].0, "critical");
    assert!(
        a[0].1.contains("already been removed") && a[0].1.contains("snapshot 100") && !a[0].1.contains('\u{1b}'),
        "{}",
        a[0].1
    );
    // a logical dump snapshot (no recoverable range) leaves it alone, the next cluster snapshot resolves it
    s.meta_bookkeeping(&job, Some(&snap(150, json!({"databases": 3}))))
        .unwrap();
    assert_eq!(open(&s).len(), 1);
    s.meta_bookkeeping(&job, Some(&snap(200, json!({"recoverable": {"from_time": 100}}))))
        .unwrap();
    assert!(open(&s).is_empty());
}
