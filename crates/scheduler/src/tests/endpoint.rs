//! Phase 24a: agent poll (reachability, backoff, summaries, requests), laptop
//! policies and missed runs (endpoint.rs).

use super::*;

const A: &str = "0123456789abcdef";

/// Agent A enrolled in t1 (linux source 10, group 10, daily 22:00); the fake
/// nexus-agentctl copies its poll config to `poll-cfg.json` and prints `poll-out`.
fn setup() -> (Env, Scheduler) {
    let mut e = env(2);
    let d = e.d.path().to_path_buf();
    script(
        &d.join("agentctl"),
        &format!("cp \"$1\" {0}/poll-cfg.json; cat {0}/poll-out 2>/dev/null", d.display()),
    );
    e.cfg.agentctl_bin = d.join("agentctl");
    let s = sched(&e);
    s.db.conn()
        .execute_batch(&format!(
            "INSERT INTO agents (id, tenant, name, host, port, cert_sha256, ui_policy, ui_policy_version) VALUES
               ('{A}','t1','laptop1','10.0.0.9',7444,'ab','{{\"header\":\"ACME\",\"hide_tray\":true}}',3);
             INSERT INTO sources (id, tenant, kind, name, config) VALUES
               (10,'t1','linux','l','{{\"agent_id\":\"{A}\",\"paths\":[\"/home\"]}}');
             INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES (10,'t1',10,1,'laptops','[\"{A}\"]');"
        ))
        .unwrap();
    (e, s)
}

fn poll_out(e: &Env, lines: &[Value]) {
    let text: String = lines.iter().map(|v| format!("poll {v}\n")).collect();
    fs::write(e.d.path().join("poll-out"), text).unwrap();
}

/// Runs one poll round at `now`; returns the config handed to nexus-agentctl (None = nobody due).
fn round(e: &Env, s: &mut Scheduler, now: i64) -> Option<Value> {
    let cfg = e.d.path().join("poll-cfg.json");
    let _ = fs::remove_file(&cfg);
    s.start_agent_poll(now).unwrap();
    s.collect_agent_poll(Some(Duration::from_secs(10))).unwrap();
    fs::read(&cfg).ok().map(|b| serde_json::from_slice(&b).unwrap())
}

fn ok_line(requests: Value, power: Value) -> Value {
    json!({"agent_id": A, "ok": true, "poll": true, "info": {"version": "0.2.0", "os": "Debian 13"},
           "delivered": [7], "requests": requests, "power": power, "policy_version": 3, "busy": false})
}

fn agent_col<T: catalog::rusqlite::types::FromSql>(s: &Scheduler, col: &str) -> T {
    s.db.conn()
        .query_row(&format!("SELECT {col} FROM agents WHERE id='{A}'"), [], |r| r.get(0))
        .unwrap()
}

fn audits(s: &Scheduler, action: &str) -> Vec<(String, Value)> {
    let c = s.db.conn();
    let mut st = c
        .prepare("SELECT actor, details FROM audit WHERE action=?1 ORDER BY seq")
        .unwrap();
    st.query_map([action], |r| {
        Ok((r.get(0)?, serde_json::from_str(&r.get::<_, String>(1)?).unwrap()))
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

#[test]
fn poll_records_state_delivers_summaries_and_queues_requests() {
    let (e, mut s) = setup();
    s.db.conn()
        .execute(
            "INSERT INTO agent_sessions (agent_id, job_id, tenant, summary, created) VALUES (?1, 7, 't1', '{\"job\":7}', 1)",
            [A],
        )
        .unwrap();
    poll_out(
        &e,
        &[ok_line(
            json!([{"id": "aa11", "queued_at": 5}]),
            json!({"on_battery": true, "battery_percent": 55, "metered": false, "network_name": "Office"}),
        )],
    );
    let now = 1_000_000;
    let cfg = round(&e, &mut s, now).expect("first round polls the agent");
    let t = &cfg["poll"]["agents"][0];
    assert_eq!(t["id"], A);
    assert_eq!(t["pins"], json!(["ab"]));
    assert_eq!(t["summaries"], json!([{"job": 7}]));
    assert_eq!(t["status"]["ui_policy"]["header"], "ACME");
    assert_eq!(t["status"]["ui_policy"]["hide_tray"], true);
    assert_eq!(t["status"]["policy_version"], 3);
    assert!(t["status"]["next_run"].as_i64().is_some_and(|n| n > now), "daily 22:00");
    // state recorded
    assert_eq!(agent_col::<i64>(&s, "reachable"), 1);
    assert_eq!(
        agent_col::<i64>(&s, "last_seen"),
        catalog::now().min(agent_col::<i64>(&s, "last_seen"))
    );
    assert_eq!(agent_col::<String>(&s, "version"), "0.2.0");
    let power: Value = serde_json::from_str(&agent_col::<String>(&s, "power")).unwrap();
    assert_eq!(
        (power["battery_percent"].as_u64(), power["network_name"].as_str()),
        (Some(55), Some("Office"))
    );
    assert_eq!(agent_col::<i64>(&s, "ui_policy_seen"), 3);
    let delivered: Option<i64> =
        s.db.conn()
            .query_row("SELECT delivered FROM agent_sessions WHERE job_id=7", [], |r| r.get(0))
            .unwrap();
    assert!(delivered.is_some());
    // the request: one backup of the agent in its group, by actor agent:<id>
    let (params, by): (String, String) =
        s.db.conn()
            .query_row("SELECT params, requested_by FROM jobs WHERE kind='backup'", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
    let params: Value = serde_json::from_str(&params).unwrap();
    assert_eq!(params, json!({"group_id": 10, "guests": [A], "request_id": "aa11"}));
    assert_eq!(by, format!("agent:{A}"));
    let a = audits(&s, "agent.request_backup");
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].0, format!("agent:{A}"));

    // not due again before the interval
    assert!(round(&e, &mut s, now + 60).is_none());
    // next round acknowledges; the same request again is not queued twice
    let cfg = round(&e, &mut s, now + 121).unwrap();
    assert_eq!(cfg["poll"]["agents"][0]["ack"], json!(["aa11"]));
    let n: i64 =
        s.db.conn()
            .query_row("SELECT COUNT(*) FROM jobs", [], |r| r.get(0))
            .unwrap();
    assert_eq!(n, 1);
    // a new request within 10 minutes: acknowledged, refused (rate limit)
    poll_out(&e, &[ok_line(json!([{"id": "bb22", "queued_at": 6}]), json!({}))]);
    round(&e, &mut s, now + 250).unwrap();
    let n: i64 =
        s.db.conn()
            .query_row("SELECT COUNT(*) FROM jobs", [], |r| r.get(0))
            .unwrap();
    assert_eq!(n, 1);
    assert_eq!(audits(&s, "agent.request_backup")[1].1["refused"], "rate limited");

    // unreachable: backoff 240 s, 480 s ...
    poll_out(&e, &[json!({"agent_id": A, "ok": false, "error": "connect: refused"})]);
    let t0 = now + 400;
    round(&e, &mut s, t0).unwrap();
    assert_eq!(
        (agent_col::<i64>(&s, "reachable"), agent_col::<i64>(&s, "poll_failures")),
        (0, 1)
    );
    assert!(
        round(&e, &mut s, t0 + 200).is_none(),
        "backoff after one failure is 240 s"
    );
    assert!(round(&e, &mut s, t0 + 241).is_some());
    assert_eq!(agent_col::<i64>(&s, "poll_failures"), 2);
    assert!(round(&e, &mut s, t0 + 241 + 479).is_none(), "then 480 s");

    // a deactivated tenant's agents are not polled
    s.db.conn()
        .execute("UPDATE tenants SET disabled = 1 WHERE name = 't1'", [])
        .unwrap();
    assert!(round(&e, &mut s, t0 + 100_000).is_none());
}

#[test]
fn laptop_policy_skips_and_runs_missed_backups() {
    let (e, mut s) = setup();
    let now = catalog::now();
    s.db.conn()
        .execute(
            "UPDATE agents SET laptop='{\"min_battery\":20,\"run_missed\":true}', reachable=1, last_poll=?1, \
             power='{\"on_battery\":true,\"battery_percent\":10}' WHERE id=?2",
            params![now, A],
        )
        .unwrap();
    let g = s.groups().unwrap().into_iter().find(|g| g.id == 10).unwrap();
    s.queue_group_backup(&g, now).unwrap();
    let (state, log): (String, String) =
        s.db.conn()
            .query_row("SELECT state, log FROM jobs", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
    assert_eq!(state, "cancelled", "recorded, no alert");
    assert!(log.contains("on battery (10 % < 20 %)"), "{log}");
    assert_eq!(agent_col::<i64>(&s, "missed_at"), now);
    assert_eq!(audits(&s, "agent.backup_skipped").len(), 1);
    // stale power state: runs
    s.db.conn()
        .execute("UPDATE agents SET last_poll=?1 WHERE id=?2", params![now - 3600, A])
        .unwrap();
    s.queue_group_backup(&g, now).unwrap();
    let n: i64 =
        s.db.conn()
            .query_row("SELECT COUNT(*) FROM jobs WHERE state='queued'", [], |r| r.get(0))
            .unwrap();
    assert_eq!(n, 1);
    s.db.conn().execute("DELETE FROM jobs", []).unwrap();

    // back on mains: the poll queues the missed run and clears the mark
    poll_out(
        &e,
        &[ok_line(json!([]), json!({"on_battery": false, "battery_percent": 80}))],
    );
    round(&e, &mut s, now).unwrap();
    let params: String =
        s.db.conn()
            .query_row("SELECT params FROM jobs", [], |r| r.get(0))
            .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&params).unwrap(),
        json!({"group_id": 10, "guests": [A], "missed": true})
    );
    assert_eq!(agent_col::<Option<i64>>(&s, "missed_at"), None);

    // a mark older than the retry window is dropped instead
    s.db.conn().execute("DELETE FROM jobs", []).unwrap();
    s.db.conn()
        .execute(
            "UPDATE agents SET missed_at=?1 WHERE id=?2",
            params![now - 25 * 3600, A],
        )
        .unwrap();
    round(&e, &mut s, now + 10_000).unwrap();
    let n: i64 =
        s.db.conn()
            .query_row("SELECT COUNT(*) FROM jobs", [], |r| r.get(0))
            .unwrap();
    assert_eq!(n, 0);
    assert_eq!(audits(&s, "agent.missed_run_expired").len(), 1);
}

#[test]
fn summaries_stored_per_agent_and_capped() {
    let (_e, mut s) = setup();
    for id in 1..=105 {
        let job = Job {
            id,
            kind: "backup".into(),
            tenant: "t1".into(),
            params: json!({"group_id": 10}),
        };
        s.db.conn()
            .execute(
                "INSERT INTO jobs (id, kind, tenant, params, state, requested_by, created, started, finished) \
                 VALUES (?1,'backup','t1','{}','ok','scheduler',1,10,20)",
                [id],
            )
            .unwrap();
        let log = format!("agent-info {{\"agent_id\":\"{A}\"}}\ncommitted host-{A}/{id} in 1s\n");
        s.endpoint_bookkeeping(&job, "ok", &log).unwrap();
    }
    let (n, min): (i64, i64) =
        s.db.conn()
            .query_row(
                "SELECT COUNT(*), MIN(job_id) FROM agent_sessions WHERE agent_id=?1",
                [A],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
    assert_eq!((n, min), (100, 6));
    let sum: String =
        s.db.conn()
            .query_row("SELECT summary FROM agent_sessions WHERE job_id=105", [], |r| r.get(0))
            .unwrap();
    let sum: Value = serde_json::from_str(&sum).unwrap();
    assert_eq!(
        (sum["result"].as_str(), sum["snapshot_time"].as_i64()),
        (Some("Success"), Some(105))
    );
    assert_eq!((sum["started"].as_i64(), sum["ended"].as_i64()), (Some(10), Some(20)));
    // a failed scheduled run of a run_missed laptop is marked missed
    s.db.conn()
        .execute("UPDATE agents SET laptop='{\"run_missed\":true}' WHERE id=?1", [A])
        .unwrap();
    s.db.conn()
        .execute(
            "INSERT INTO jobs (id, kind, tenant, params, state, requested_by, created, started, finished) \
             VALUES (200,'backup','t1','{}','failed','scheduler',1,10,30)",
            [],
        )
        .unwrap();
    let job = Job {
        id: 200,
        kind: "backup".into(),
        tenant: "t1".into(),
        params: json!({"group_id": 10}),
    };
    s.endpoint_bookkeeping(&job, "failed", &format!("Error: connect {A}: timed out\n"))
        .unwrap();
    assert_eq!(agent_col::<i64>(&s, "missed_at"), 30);
}
