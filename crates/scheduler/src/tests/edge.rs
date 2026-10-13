//! Phase 26: edge proxies (edge.rs) — agent routes and the `SetEdge` push in the
//! poll, the control link (health, log, wake → immediate poll), enrollment
//! bookkeeping and the firewall.

use super::*;

const A: &str = "0123456789abcdef";
const FP: &str = "abababababababababababababababababababababababababababababababab";

/// Agent A (t1) assigned to the enrolled edge `e1`; the fake nexus-agentctl copies
/// its config per command and prints `<cmd>-out`.
fn setup() -> (Env, Scheduler) {
    let mut e = env(2);
    let d = e.d.path().to_path_buf();
    script(
        &d.join("agentctl"),
        &format!(
            "cp \"$1\" {0}/$2-cfg.json; cat {0}/$2-out 2>/dev/null; true",
            d.display()
        ),
    );
    e.cfg.agentctl_bin = d.join("agentctl");
    let s = sched(&e);
    s.db.conn()
        .execute_batch(&format!(
            "INSERT INTO edges (id, name, host, port, public_host, public_port, cert_sha256, created, created_by) VALUES
               ('e1', 'dmz', '10.0.0.5', 7445, 'edge.example.com', 443, '{FP}', 1, 'alice');
             INSERT INTO agents (id, tenant, name, host, port, cert_sha256, edge_id) VALUES
               ('{A}','t1','laptop1','10.0.0.9',7444,'cd','e1');"
        ))
        .unwrap();
    (e, s)
}

fn read_json(e: &Env, name: &str) -> Value {
    serde_json::from_slice(&fs::read(e.d.path().join(name)).unwrap()).unwrap()
}

#[test]
fn poll_routes_via_the_edge_and_pushes_it_once() {
    let (e, mut s) = setup();
    let line = json!({"agent_id": A, "ok": true, "poll": true, "info": {"version": "0.2.0", "via": "edge"},
                      "edge_set": "edge.example.com:443", "delivered": [], "requests": []});
    fs::write(e.d.path().join("poll-out"), format!("poll {line}\n")).unwrap();
    s.start_agent_poll(1_000_000).unwrap();
    s.collect_agent_poll(Some(Duration::from_secs(10))).unwrap();
    let cfg = read_json(&e, "poll-cfg.json");
    let t = &cfg["poll"]["agents"][0];
    assert_eq!(t["edge"], json!({"host": "10.0.0.5", "port": 7445, "cert_sha256": FP}));
    assert_eq!(
        t["set_edge"],
        json!({"addr": "edge.example.com:443", "cert_sha256": FP})
    );
    let (via, pushed): (String, String) =
        s.db.conn()
            .query_row("SELECT via, edge_pushed FROM agents", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
    assert_eq!((via.as_str(), pushed), ("edge", format!("edge.example.com:443 {FP}")));
    // confirmed: not pushed again; unassigned: an empty SetEdge removes it
    assert_eq!(
        s.agent_edge_push(A, Some(&format!("edge.example.com:443 {FP}")))
            .unwrap(),
        None
    );
    s.db.conn().execute("UPDATE agents SET edge_id = NULL", []).unwrap();
    let (set, key) = s.agent_edge_push(A, Some("x")).unwrap().unwrap();
    assert_eq!((set["addr"].as_str(), key.as_str()), (Some(""), ""));
    assert_eq!(s.agent_edge_route(A).unwrap(), None);
    // the agentctl config of a job carries the route
    s.db.conn().execute("UPDATE agents SET edge_id = 'e1'", []).unwrap();
    let a = s.agent("t1", A).unwrap();
    let job = Job {
        id: 1,
        kind: "backup".into(),
        tenant: "t1".into(),
        params: json!({}),
    };
    assert_eq!(
        s.agentctl_base("t1", &job, Some(&a), json!({}))["agent"]["edge"]["port"],
        7445
    );
    // the firewall allows the control port
    assert_eq!(s.edge_targets().unwrap(), vec![("10.0.0.5".to_string(), 7445)]);
}

#[test]
fn link_records_health_and_a_wake_polls_at_once() {
    let (e, mut s) = setup();
    fs::write(
        e.d.path().join("edge-link-out"),
        format!(
            "edge-health {}\nedge-log {}\nedge-wake {}\nedge-wake {}\n",
            json!({"version": "0.1.0", "agents_online": [A], "configured": true}),
            json!({"line": "2026-10-13T10:00:00Z agent online"}),
            json!({"agent_id": A}),
            json!({"agent_id": "fedcba9876543210"}),
        ),
    )
    .unwrap();
    let now = 1_000_000;
    s.poll.next.insert(A.into(), now + 600);
    assert!(!s.edge_links(now).unwrap(), "link started, nothing read yet");
    let mut woke = false;
    for _ in 0..100 {
        woke |= s.edge_links(now).unwrap();
        if woke {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(woke, "the wake of an agent of this edge");
    assert!(!s.poll.next.contains_key(A), "agent due for a poll now");
    let cfg = read_json(&e, "edge-link-cfg.json");
    assert_eq!(cfg["edge"]["cert_sha256"], FP);
    assert_eq!(cfg["edge"]["link"]["agents"], json!([{"id": A, "pins": ["cd"]}]));
    let (seen, version, log): (i64, String, String) =
        s.db.conn()
            .query_row("SELECT last_seen, version, log FROM edges", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
    assert_eq!((seen, version.as_str()), (now, "0.1.0"));
    assert!(log.contains("agent online"));
    // the link ended (fake): restarted only after the pause
    std::thread::sleep(Duration::from_millis(200));
    s.edge_links(now).unwrap();
    assert!(!s.edges_running("e1"));
    // a deleted edge loses its link
    s.db.conn().execute("DELETE FROM edges", []).unwrap();
    s.edge_links(now + 60).unwrap();
    assert!(!s.edges_running("e1"));
}

#[test]
fn enrollment_pins_the_edge_and_drops_the_token() {
    let (_e, s) = setup();
    s.db.conn()
        .execute(
            "INSERT INTO edges (id, name, host, public_host, token_hash, token_expires, created, created_by) \
             VALUES ('e2', 'branch', '10.1.0.5', 'b.example.com', 'sealed', 9, 1, 'alice')",
            [],
        )
        .unwrap();
    let job = Job {
        id: 2,
        kind: "edge_enroll".into(),
        tenant: "-".into(),
        params: json!({"edge_id": "e2"}),
    };
    let log = format!(
        "edge-enrolled {}\nedge-enrolled {}\n",
        json!({"edge_id": "e1", "cert_sha256": "00".repeat(32), "version": "0.1.0"}),
        json!({"edge_id": "e2", "cert_sha256": "EF".repeat(32), "version": "0.1.0"}),
    );
    s.edge_bookkeeping(&job, &log).unwrap();
    let row: (String, Option<String>, Option<i64>) =
        s.db.conn()
            .query_row(
                "SELECT cert_sha256, token_hash, enrolled_at FROM edges WHERE id='e2'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
    assert_eq!(row.0, "ef".repeat(32));
    assert_eq!(row.1, None);
    assert!(row.2.is_some());
    let other: String =
        s.db.conn()
            .query_row("SELECT cert_sha256 FROM edges WHERE id='e1'", [], |r| r.get(0))
            .unwrap();
    assert_eq!(other, FP, "a line for another edge is ignored");
}
