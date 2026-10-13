//! Phase 22a: interface-bound egress from the nexus-net status, and the audit of its operations.
use super::*;

/// Sources (data) leave through the data interface, offsite through the interface of the chosen
/// role; a role without an interface and every other destination through any.
#[test]
fn role_destinations_bound_to_their_interface() {
    let mut e = env(1);
    fs::create_dir_all(e.d.path().join("nft")).unwrap();
    e.cfg.nft_allowed = e.d.path().join("nft/allowed.json");
    e.cfg.net_dir = e.d.path().join("net");
    fs::create_dir(&e.cfg.net_dir).unwrap();
    e.db.conn()
        .execute(
            "UPDATE tenants SET offsite = ?1 WHERE name = 't1'",
            [json!({"remote": {"type": "sftp", "host": "192.0.2.40"}}).to_string()],
        )
        .unwrap();
    let s = sched(&e);
    let load = |s: &Scheduler| {
        s.sync_firewall().unwrap();
        nftsync::Allowed::load(&s.cfg.nft_allowed).unwrap()
    };
    // no nexus-net status: every role through any interface
    let a = load(&s);
    assert_eq!(a.roles["data"].iface, None);
    assert_eq!(a.roles["data"].endpoints[0].addr.to_string(), "10.0.0.1");
    assert_eq!(a.roles["offsite"].endpoints[0].port, 23);
    assert!(!a.roles.contains_key("replication"), "no destinations: left out");

    let status = json!({"config": {"interfaces": [
        {"name": "bond0", "kind": "bond", "ports": ["ens4", "ens5"], "mode": "802.3ad", "role": null},
        {"name": "bond0.20", "kind": "vlan", "parent": "bond0", "vlan_id": 20, "role": "data", "addresses": ["10.0.0.5/24"]},
        {"name": "ens6", "kind": "ethernet", "role": "replication", "dhcp": true}
    ], "offsite_role": "replication"}});
    fs::write(e.cfg.net_dir.join("status.json"), status.to_string()).unwrap();
    let a = load(&s);
    assert_eq!(a.roles["data"].iface.as_deref(), Some("bond0.20"));
    assert_eq!(a.roles["offsite"].iface.as_deref(), Some("ens6"));
    assert!(
        !a.endpoints.iter().any(|x| x.addr.to_string() == "10.0.0.1"),
        "not unbound as well"
    );
    // offsite through the management interface, which this configuration does not have: any
    let mut st = status.clone();
    st["config"]["offsite_role"] = json!("management");
    fs::write(e.cfg.net_dir.join("status.json"), st.to_string()).unwrap();
    assert_eq!(load(&s).roles["offsite"].iface, None);
}

#[test]
fn network_ops_audited_once() {
    let mut e = env(1);
    e.cfg.net_dir = e.d.path().join("net");
    fs::create_dir(&e.cfg.net_dir).unwrap();
    let s = sched(&e);
    s.audit_net_ops().unwrap();
    let ops = json!([
        {"id": "a", "op": "apply", "by": "alice", "quorum_id": 3, "state": "rolled_back",
         "detail": "not confirmed within 120 s", "params": {}},
        {"id": "b", "op": "apply", "by": "alice", "quorum_id": null, "state": "confirming", "params": {}},
        {"id": "c", "op": "mtu_check", "by": "otto", "quorum_id": null, "state": "done", "params": {}}
    ]);
    fs::write(e.cfg.net_dir.join("ops.json"), ops.to_string()).unwrap();
    s.audit_net_ops().unwrap();
    s.audit_net_ops().unwrap();
    let rows: Vec<(String, String, String)> = {
        let c = s.db.conn();
        let mut q = c
            .prepare("SELECT actor, target, details FROM audit WHERE action = 'network.op' ORDER BY seq")
            .unwrap();
        q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!((rows[0].0.as_str(), rows[0].1.as_str()), ("nexus-net", "network/apply"));
    assert!(rows[0].2.contains("rolled_back"));
    assert_eq!(rows[1].1, "network/mtu_check");
}
