use super::*;

/// The PVE source's caps and read limit end up in pve.json; the group's
/// parallel guests stay (nexus-pve applies `max_parallel` on top).
#[test]
fn pve_limits_in_the_job_config() {
    let e = env(1);
    let s = sched(&e);
    {
        let c = s.db.conn();
        let cfg: String = c.query_row("SELECT config FROM sources WHERE id=1", [], |r| r.get(0)).unwrap();
        let mut v: Value = serde_json::from_str(&cfg).unwrap();
        v["max_parallel"] = json!(2);
        v["storage_caps"] = json!({"ceph": 1});
        v["read_limit"] = json!({"bwlimit": 50_000_000, "timezone": "UTC"});
        c.execute("UPDATE sources SET config=?1 WHERE id=1", [v.to_string()]).unwrap();
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
        let m: String = s
            .db
            .conn()
            .query_row("SELECT meta FROM snapshots WHERE tenant='t1' AND source=?1", [src], |r| r.get(0))
            .unwrap();
        serde_json::from_str(&m).unwrap()
    };
    assert_eq!(meta("vm-100")["keep"], 1, "merged");
    assert_eq!(meta("vm-100")["identity"]["vmgenid"], "g2");
    assert_eq!(meta("vm-101")["identity"]["changed"], false);
    let alerts: Vec<(String, String)> = {
        let c = s.db.conn();
        let mut q = c.prepare("SELECT key, message FROM alerts WHERE kind='vmid_reused'").unwrap();
        let rows = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        rows.map(Result::unwrap).collect()
    };
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_eq!(alerts[0].0, "vmid_reused:t1/vm-100");
    assert!(alerts[0].1.contains("g1 → g2"), "{}", alerts[0].1);

    // a newer snapshot without a recorded snapshot name does not hide the older one
    s.db.conn()
        .execute("INSERT INTO snapshots (tenant, source, time, local, offsite) VALUES ('t1','nas-5-tank.data',30,1,0)", [])
        .unwrap();
    let mut cfg = json!({});
    s.truenas_limits("t1", 5, &json!({"existing_snapshots": "auto-", "read_limit": {"bwlimit": 1}}), &mut cfg)
        .unwrap();
    assert_eq!(cfg["existing_snapshots"], "auto-");
    assert_eq!(cfg["read_limit"]["bwlimit"], 1);
    assert_eq!(cfg["references"], json!({"nas-5-tank.data": {"time": 20, "snapshot": "auto-a"}}));
    let mut plain = json!({});
    s.truenas_limits("t1", 5, &json!({}), &mut plain).unwrap();
    assert_eq!(plain, json!({}), "create mode: no references");
}
