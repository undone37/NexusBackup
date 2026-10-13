use super::*;

const DAY: i64 = 86400;

fn count(s: &Scheduler, sql: &str) -> i64 {
    s.db.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

/// nexus-pve stand-in: keeps the spec, prints `out`, exits with `code`.
fn lab_env() -> Env {
    let mut e = env(4);
    let p = e.d.path().to_owned();
    script(
        &p.join("lab"),
        &format!(
            "echo \"$@\" >> {0}/calls; [ -f \"$3\" ] && cp \"$3\" {0}/spec-$(basename $(dirname \"$3\")).json; \
             cat {0}/lab.out; exit $(cat {0}/lab.code)",
            p.display()
        ),
    );
    e.cfg.pve_bin = p.join("lab");
    e
}

fn answer(e: &Env, lines: &[Value], code: i32) {
    let out: String = lines.iter().map(|l| format!("restore-test {l}\n")).collect();
    fs::write(e.d.path().join("lab.out"), out).unwrap();
    fs::write(e.d.path().join("lab.code"), code.to_string()).unwrap();
}

fn spec(e: &Env, job: i64) -> Value {
    serde_json::from_slice(&fs::read(e.d.path().join(format!("spec-job-{job}.json"))).unwrap()).unwrap()
}

fn run_all(s: &mut Scheduler) {
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
}

fn result(source: &str, time: i64, state: &str) -> Value {
    json!({"source": source, "time": time, "wave": 1, "target": 990_001, "name": format!("nxtest-{source}"),
           "state": state, "started": 10, "finished": 20, "boot_secs": 7, "destroyed": true,
           "checks": [{"name": "guest_agent", "ok": state == "passed", "detail": "no answer within 600 s"}]})
}

/// A manual restore test: spec for nexus-pve, one result row per guest, the
/// `restore_test` warning on failure (no generic job_failed), resolved by a pass.
#[test]
fn restore_test_results_and_alerts() {
    let e = lab_env();
    let mut s = sched(&e);
    e.db.conn()
        .execute(
            "INSERT INTO snapshots (tenant, source, time, local, offsite) VALUES ('t1', 'vm-100', 1000, 1, 0)",
            [],
        )
        .unwrap();
    answer(&e, &[result("vm-100", 1000, "failed")], 1);
    let p = json!({"source": "vm-100", "time": 1000, "node": "n1", "storage": "local-lvm", "bridge": "nxlab",
                   "checks": {"ports": [22], "boot_timeout": 300}});
    let id = manual(&s, "restore_test", "t1", p.clone());
    run_all(&mut s);
    assert_eq!(state(&s, id), "failed");
    let sp = spec(&e, id);
    assert_eq!(
        (sp["mode"].as_str(), sp["node"].as_str(), sp["bridge"].as_str()),
        (Some("test"), Some("n1"), Some("nxlab"))
    );
    assert_eq!(sp["guests"][0]["checks"]["ports"], json!([22]));
    assert_eq!(sp["guests"][0]["time"], 1000);
    assert!(sp["vmid_base"].as_u64().unwrap() >= 990_000);
    assert_eq!(
        count(
            &s,
            "SELECT COUNT(*) FROM restore_tests WHERE state = 'failed' AND source = 'vm-100' AND time = 1000"
        ),
        1
    );
    assert_eq!(
        count(
            &s,
            "SELECT COUNT(*) FROM alerts WHERE kind = 'restore_test' AND key = 'restore_test:t1/vm-100' \
             AND resolved_at IS NULL AND severity = 'warning' AND message LIKE '%guest_agent: no answer%'"
        ),
        1
    );
    assert_eq!(count(&s, "SELECT COUNT(*) FROM alerts WHERE kind = 'job_failed'"), 0);

    answer(&e, &[result("vm-100", 1000, "passed")], 0);
    let id = manual(&s, "restore_test", "t1", p);
    run_all(&mut s);
    assert_eq!(state(&s, id), "ok");
    assert_eq!(
        count(
            &s,
            "SELECT COUNT(*) FROM alerts WHERE key = 'restore_test:t1/vm-100' AND resolved_at IS NULL"
        ),
        0
    );
    // a job that never got to boot anything still fails the guest's test
    fs::write(e.d.path().join("lab.out"), "").unwrap();
    fs::write(e.d.path().join("lab.code"), "2").unwrap();
    let id = manual(
        &s,
        "restore_test",
        "t1",
        json!({"source": "vm-100", "time": 1000, "node": "n1", "storage": "x"}),
    );
    run_all(&mut s);
    assert_eq!(state(&s, id), "failed");
    assert_eq!(
        count(
            &s,
            "SELECT COUNT(*) FROM alerts WHERE key = 'restore_test:t1/vm-100' AND resolved_at IS NULL"
        ),
        1
    );
    // bad parameters never reach nexus-pve
    let bad = manual(
        &s,
        "restore_test",
        "t1",
        json!({"source": "vm-100", "time": 1000, "node": "n1;x", "storage": "x"}),
    );
    s.start_jobs().unwrap();
    assert_eq!(state(&s, bad), "failed");
}

/// Group schedules: the newest local snapshot of each guest every N days,
/// containers without agent checks, one test at a time per group.
#[test]
fn scheduled_group_tests() {
    let e = lab_env();
    let mut s = sched(&e);
    answer(&e, &[], 0);
    e.db.conn()
        .execute_batch(
            "UPDATE groups SET guests = '[100, 101]' WHERE id = 1;
             INSERT INTO snapshots (tenant, source, time, local, offsite) VALUES
               ('t1', 'vm-100', 1000, 1, 0), ('t1', 'vm-100', 2000, 1, 0), ('t1', 'vm-100', 3000, 0, 1),
               ('t1', 'ct-101', 1500, 1, 0);
             INSERT INTO restore_test_schedules (group_id, every_days, node, storage, bridge, checks)
               VALUES (1, 7, 'n1', 'local-lvm', NULL, '{\"ports\": [443], \"boot_timeout\": 900}');",
        )
        .unwrap();
    let now = 10 * DAY;
    s.queue_restore_tests(now).unwrap();
    let jobs: Vec<Value> = {
        let c = s.db.conn();
        let mut st = c
            .prepare("SELECT params FROM jobs WHERE kind = 'restore_test' ORDER BY id")
            .unwrap();
        st.query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|p| serde_json::from_str(&p.unwrap()).unwrap())
            .collect()
    };
    assert_eq!(jobs.len(), 2);
    assert_eq!(
        (jobs[0]["source"].as_str(), jobs[0]["time"].as_i64()),
        (Some("vm-100"), Some(2000))
    );
    assert_eq!(jobs[0]["checks"]["ports"], json!([443]));
    assert_eq!(
        (jobs[1]["source"].as_str(), jobs[1]["group_id"].as_i64()),
        (Some("ct-101"), Some(1))
    );
    assert_eq!(
        jobs[1]["checks"],
        json!({"boot_timeout": 900}),
        "no agent checks for containers"
    );
    // both wait for the group key: one at a time
    s.start_jobs().unwrap();
    assert_eq!(s.running().len(), 1);
    assert_eq!(s.running()[0].1, "restore_test:group/1");
    s.wait_idle(Duration::from_secs(20)).unwrap();
    run_all(&mut s);
    s.queue_restore_tests(now + 6 * DAY).unwrap();
    assert_eq!(count(&s, "SELECT COUNT(*) FROM jobs WHERE kind = 'restore_test'"), 2);
    s.queue_restore_tests(now + 7 * DAY).unwrap();
    assert_eq!(count(&s, "SELECT COUNT(*) FROM jobs WHERE kind = 'restore_test'"), 4);
}

fn plan_row(s: &Scheduler) -> i64 {
    let c = s.db.conn();
    c.execute(
        "INSERT INTO recovery_plans (tenant, name, source_id, node, storage, test_bridge, network_map, steps, rpo_hours, created, created_by)
         VALUES ('t1', 'erp', 1, 'n1', 'local-lvm', 'nxlab', '{\"vmbr0\": \"vmbr9\"}', ?1, 24, 1, 'alice')",
        [json!([{"source": "vm-100", "wave": 1, "delay": 0, "checks": {"ports": [5432]}},
                {"source": "ct-101", "wave": 2, "delay": 30, "target": 301}])
        .to_string()],
    )
    .unwrap();
    c.last_insert_rowid()
}

fn plan_json(s: &Scheduler, id: i64) -> Value {
    json!({"id": id, "tenant": "t1", "name": "erp", "source_id": 1, "node": "n1", "storage": "local-lvm",
           "test_bridge": "nxlab", "network_map": {"vmbr0": "vmbr9"}, "rpo_hours": 24,
           "steps": serde_json::from_str::<Value>(&s.db.conn().query_row("SELECT steps FROM recovery_plans WHERE id = ?1", [id], |r| r.get::<_, String>(0)).unwrap()).unwrap()})
}

/// Test run: newest snapshots, isolated bridge, results into the run and
/// restore_tests; execution only from an approved request (not self-approved),
/// network map and targets, a failure raises a critical alert.
#[test]
fn recovery_test_run_and_execute() {
    let e = lab_env();
    let mut s = sched(&e);
    let pid = plan_row(&s);
    e.db.conn()
        .execute_batch(
            "INSERT INTO snapshots (tenant, source, time, local, offsite) VALUES
               ('t1', 'vm-100', 1000, 1, 0), ('t1', 'vm-100', 2000, 1, 0), ('t1', 'ct-101', 1500, 1, 0);",
        )
        .unwrap();
    let run = {
        let pj = plan_json(&s, pid).to_string();
        let c = s.db.conn();
        c.execute(
            "INSERT INTO recovery_runs (plan_id, tenant, mode, requested_by, plan, started) VALUES (?1, 't1', 'test', 'alice', ?2, 1)",
            params![pid, pj],
        )
        .unwrap();
        c.last_insert_rowid()
    };
    answer(
        &e,
        &[result("vm-100", 2000, "passed"), result("ct-101", 1500, "passed")],
        0,
    );
    let id = manual(&s, "recovery_test", "t1", json!({"run_id": run, "plan_id": pid}));
    run_all(&mut s);
    assert_eq!(state(&s, id), "ok");
    let sp = spec(&e, id);
    assert_eq!(sp["bridge"], "nxlab");
    assert!(sp.get("network_map").is_none());
    assert_eq!(sp["guests"][0]["time"], 2000);
    assert_eq!(
        (sp["guests"][1]["wave"].as_u64(), sp["guests"][1]["delay"].as_u64()),
        (Some(2), Some(30))
    );
    assert!(sp["guests"][1].get("target").is_none(), "test runs use test VMIDs");
    let (st, n, job): (String, i64, i64) =
        s.db.conn()
            .query_row(
                "SELECT state, json_array_length(results), job_id FROM recovery_runs WHERE id = ?1",
                [run],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
    assert_eq!((st.as_str(), n, job), ("passed", 2, id));
    assert_eq!(
        count(&s, &format!("SELECT COUNT(*) FROM restore_tests WHERE run_id = {run}")),
        2
    );
    assert_eq!(
        count(&s, "SELECT COUNT(*) FROM audit WHERE action = 'recovery_plan.test_run'"),
        1
    );

    // execution: a self-approved request (approvals on) is not executed
    let req = |s: &Scheduler, by: &str, decided: &str| {
        let p = json!({"tenant": "t1", "plan_id": pid, "plan": plan_json(s, pid)}).to_string();
        let c = s.db.conn();
        c.execute(
            "INSERT INTO quorum (action, params, requested_by, created, decided_by, decided_at, state)
             VALUES ('recovery_plan.execute', ?1, ?2, 1, ?3, 2, 'approved')",
            params![p, by, decided],
        )
        .unwrap();
        c.last_insert_rowid()
    };
    req(&s, "alice", "alice");
    s.queue_recovery_executes().unwrap();
    assert_eq!(
        count(&s, "SELECT COUNT(*) FROM jobs WHERE kind = 'recovery_execute'"),
        0
    );
    let q = req(&s, "alice", "bob");
    s.queue_recovery_executes().unwrap();
    s.queue_recovery_executes().unwrap();
    assert_eq!(
        count(&s, "SELECT COUNT(*) FROM jobs WHERE kind = 'recovery_execute'"),
        1
    );
    let mut failed = result("vm-100", 2000, "failed");
    failed["destroyed"] = Value::Null;
    answer(&e, &[failed, result("ct-101", 1500, "skipped")], 1);
    run_all(&mut s);
    let (xid, xparams): (i64, String) =
        s.db.conn()
            .query_row("SELECT id, params FROM jobs WHERE kind = 'recovery_execute'", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
    assert_eq!(state(&s, xid), "failed");
    let xp: Value = serde_json::from_str(&xparams).unwrap();
    assert_eq!(xp["quorum_id"], q);
    let sp = spec(&e, xid);
    assert_eq!(sp["mode"], "execute");
    assert_eq!(sp["network_map"], json!({"vmbr0": "vmbr9"}));
    assert_eq!(sp["guests"][1]["target"], 301);
    assert!(sp.get("bridge").is_none());
    assert_eq!(
        count(
            &s,
            &format!(
                "SELECT COUNT(*) FROM recovery_runs WHERE mode = 'execute' AND state = 'failed' AND quorum_id = {q}"
            )
        ),
        1
    );
    assert_eq!(
        count(
            &s,
            &format!("SELECT COUNT(*) FROM quorum WHERE id = {q} AND state = 'executed'")
        ),
        1
    );
    assert_eq!(
        count(
            &s,
            &format!(
                "SELECT COUNT(*) FROM alerts WHERE kind = 'recovery_plan' AND key = 'recovery_run:{pid}' AND severity = 'critical'"
            )
        ),
        1
    );
    // executions raise no restore_test alerts (nothing is destroyed or isolated)
    assert_eq!(count(&s, "SELECT COUNT(*) FROM alerts WHERE kind = 'restore_test'"), 0);
}

/// Readiness: snapshots within the RPO, the lab check (node, storage space,
/// bridges) and blocking alerts; stored on the plan, alert while not ready.
#[test]
fn readiness_checks() {
    let e = lab_env();
    let mut s = sched(&e);
    let pid = plan_row(&s);
    let now = catalog::now();
    e.db.conn()
        .execute(
            "INSERT INTO snapshots (tenant, source, time, size, local, offsite) VALUES
               ('t1', 'vm-100', ?1, ?2, 1, 0), ('t1', 'ct-101', ?1, ?2, 1, 0)",
            params![now - 3600, 1i64 << 30],
        )
        .unwrap();
    let lab = |avail: i64, missing: &[&str]| {
        fs::write(
            e.d.path().join("lab.out"),
            json!({"node": "n1", "online": true, "storage": {"id": "local-lvm", "active": true, "avail": avail},
                   "ir_storage": {"id": "nx", "active": true, "avail": 1}, "missing_bridges": missing})
            .to_string(),
        )
        .unwrap();
        fs::write(e.d.path().join("lab.code"), "0").unwrap();
    };
    lab(10 << 30, &[]);
    // first sight: no run (the web-api checks a new plan at once); then daily
    s.queue_readiness(now).unwrap();
    assert_eq!(
        count(&s, "SELECT COUNT(*) FROM jobs WHERE kind = 'recovery_readiness'"),
        0
    );
    s.queue_readiness(now + DAY).unwrap();
    s.queue_readiness(now + DAY).unwrap();
    assert_eq!(
        count(&s, "SELECT COUNT(*) FROM jobs WHERE kind = 'recovery_readiness'"),
        1
    );
    run_all(&mut s);
    let ready = |s: &Scheduler| -> Value {
        serde_json::from_str(
            &s.db
                .conn()
                .query_row("SELECT readiness FROM recovery_plans WHERE id = ?1", [pid], |r| {
                    r.get::<_, String>(0)
                })
                .unwrap(),
        )
        .unwrap()
    };
    let r = ready(&s);
    assert_eq!(r["ok"], true, "{r}");
    let names: Vec<&str> = r["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "snapshot vm-100",
            "snapshot ct-101",
            "node n1",
            "target storage local-lvm",
            "instant recovery storage nx",
            "bridges",
            "alerts"
        ]
    );
    assert!(fs::read_to_string(e.d.path().join("calls"))
        .unwrap()
        .contains(" lab-check "));

    // too little space, a missing bridge, a failed restore test: not ready
    lab(1 << 30, &["nxlab"]);
    s.raise(
        "warning",
        "restore_test",
        "restore_test:t1/ct-101",
        "failed",
        Some("t1"),
    )
    .unwrap();
    let id = manual(&s, "recovery_readiness", "t1", json!({"plan_id": pid}));
    run_all(&mut s);
    assert_eq!(state(&s, id), "ok");
    let r = ready(&s);
    assert_eq!(r["ok"], false);
    let bad: Vec<&str> = r["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["ok"] == false)
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(bad, ["target storage local-lvm", "bridges", "alerts"]);
    assert_eq!(
        count(
            &s,
            &format!("SELECT COUNT(*) FROM alerts WHERE key = 'recovery_ready:{pid}' AND resolved_at IS NULL")
        ),
        1
    );
    // an old snapshot breaks the RPO; an unreachable cluster fails the target check
    e.db.conn()
        .execute(
            "UPDATE snapshots SET time = time - 2 * 86400 WHERE source = 'vm-100'",
            [],
        )
        .unwrap();
    fs::write(e.d.path().join("lab.code"), "1").unwrap();
    let id = manual(&s, "recovery_readiness", "t1", json!({"plan_id": pid}));
    run_all(&mut s);
    assert_eq!(state(&s, id), "failed");
    let r = ready(&s);
    let bad: Vec<&str> = r["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["ok"] == false)
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(bad, ["snapshot vm-100", "target", "alerts"]);
    assert_eq!(count(&s, "SELECT COUNT(*) FROM alerts WHERE kind = 'job_failed'"), 0);
}
