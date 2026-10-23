//! Phase 25: restore tests (jobs, results, group schedules) and recovery plans
//! (readiness, test runs, approved execution, runs, DR report).

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use catalog::rusqlite::params;
use catalog::secret::TotpKey;
use catalog::Catalog;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use tower::ServiceExt;
use web_api::AppState;

const PW: &str = "correct horse battery";

fn pw_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| catalog::auth::hash_password(PW).unwrap())
}

struct T {
    app: Router,
    st: Arc<AppState>,
    secrets: HashMap<String, String>,
    _dir: tempfile::TempDir,
}

struct S {
    cookie: String,
    csrf: String,
}

struct R {
    status: StatusCode,
    body: Value,
    cookie: Option<String>,
}

impl T {
    fn new() -> T {
        let dir = tempfile::tempdir().unwrap();
        let cat = Catalog::open(&dir.path().join("catalog.db")).unwrap();
        let downloads = dir.path().join("downloads");
        std::fs::create_dir(&downloads).unwrap();
        let st = AppState::with_keys(cat, None, downloads, TotpKey::generate(), None);
        let mut secrets = HashMap::new();
        for (n, role, tenant) in [
            ("alice", "admin", None),
            ("sam", "security_officer", None),
            ("otto", "operator", None),
            ("tina", "tenant_user", Some("acme")),
            ("vic", "viewer", None),
            ("dana", "tenant_admin", Some("acme")),
        ] {
            let secret = catalog::auth::new_totp_secret();
            let enc = st.totp.encrypt(n, &secret).unwrap();
            if let Some(t) = tenant {
                st.cat
                    .conn()
                    .execute("INSERT OR IGNORE INTO tenants (name) VALUES (?1)", [t])
                    .unwrap();
            }
            st.cat
                .conn()
                .execute(
                    "INSERT INTO users (name, password_hash, totp_secret, role, tenant, created) VALUES (?1,?2,?3,?4,?5,0)",
                    params![n, pw_hash(), enc, role, tenant],
                )
                .unwrap();
            secrets.insert(n.to_owned(), secret);
        }
        st.cat
            .conn()
            .execute_batch(
                r#"INSERT INTO tenants (name) VALUES ('globex');
                   INSERT INTO sources (id, tenant, kind, name, config) VALUES (1, 'acme', 'pve', 'pve-a', '{}'),
                     (2, 'globex', 'pve', 'pve-g', '{}'), (3, 'acme', 'nfs', 'share-a', '{}');
                   INSERT INTO policies (id, name, schedule, gfs, offsite) VALUES (1, 'daily', 'daily 22:00', '{"daily":7,"weekly":0,"monthly":0,"yearly":0}', 0);
                   INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES
                     (1, 'acme', 1, 1, 'g1', '[100,101,102]'), (2, 'globex', 2, 1, 'g2', '[200]'),
                     (3, 'acme', 3, 1, 'g3', '[]');"#,
            )
            .unwrap();
        T {
            app: web_api::router(st.clone()),
            st,
            secrets,
            _dir: dir,
        }
    }

    async fn call(&self, method: Method, path: &str, s: Option<&S>, body: Option<Value>) -> R {
        let mut b = Request::builder()
            .method(method.clone())
            .uri(path)
            .header(header::HOST, "nexus.test");
        if let Some(s) = s {
            b = b.header(header::COOKIE, format!("nx_session={}", s.cookie));
            if method != Method::GET {
                b = b.header("x-csrf-token", &s.csrf);
            }
        }
        let req = match body {
            Some(v) => b
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(v.to_string()))
                .unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let cookie = res
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|c| c.strip_prefix("nx_session=")?.split(';').next().map(str::to_owned));
        let raw = res.into_body().collect().await.unwrap().to_bytes().to_vec();
        R {
            status,
            body: serde_json::from_slice(&raw).unwrap_or(Value::Null),
            cookie,
        }
    }

    async fn get(&self, path: &str, s: &S) -> R {
        self.call(Method::GET, path, Some(s), None).await
    }
    async fn post(&self, path: &str, s: &S, body: Value) -> R {
        self.call(Method::POST, path, Some(s), Some(body)).await
    }
    async fn put(&self, path: &str, s: &S, body: Value) -> R {
        self.call(Method::PUT, path, Some(s), Some(body)).await
    }

    async fn login(&self, name: &str) -> S {
        let code = catalog::auth::totp_now(&self.secrets[name]).unwrap();
        let r = self
            .call(
                Method::POST,
                "/api/v1/auth/login",
                None,
                Some(json!({"name": name, "password": PW, "totp": code})),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{name}: {:?}", r.body);
        S {
            cookie: r.cookie.unwrap(),
            csrf: r.body["csrf"].as_str().unwrap().to_owned(),
        }
    }

    fn one<V: catalog::rusqlite::types::FromSql>(&self, sql: &str) -> V {
        self.st.cat.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }
}

impl T {
    async fn delete(&self, path: &str, s: &S) -> R {
        self.call(Method::DELETE, path, Some(s), None).await
    }
}

fn seed(t: &T) {
    t.st.cat
        .conn()
        .execute_batch(
            r#"INSERT INTO snapshots (tenant, source, time, local, offsite) VALUES
                 ('acme', 'vm-100', 1000, 1, 0), ('acme', 'ct-101', 1000, 1, 0), ('acme', 'vm-102', 900, 0, 1),
                 ('globex', 'vm-200', 1000, 1, 0);
               INSERT INTO restore_tests (tenant, source, time, job_id, state, started, finished, details) VALUES
                 ('acme', 'vm-100', 1000, 1, 'failed', 10, 20, '{"target": 990001, "checks": [{"name": "guest_agent", "ok": false, "detail": "x"}]}'),
                 ('acme', 'vm-100', 1000, 2, 'passed', 30, 40, '{"target": 990002, "boot_secs": 30, "checks": []}'),
                 ('globex', 'vm-200', 1000, 3, 'failed', 30, 40, '{}');"#,
        )
        .unwrap();
}

/// Manual restore tests are jobs (runners, not tenant users), validated:
/// a local snapshot, names, checks (none through the agent for containers).
#[tokio::test]
async fn restore_test_jobs() {
    let t = T::new();
    seed(&t);
    let (otto, tina, vic, dana) = (
        t.login("otto").await,
        t.login("tina").await,
        t.login("vic").await,
        t.login("dana").await,
    );
    let job = |params: Value| json!({"kind": "restore_test", "tenant": "acme", "params": params});
    let good = json!({"source": "vm-100", "time": 1000, "node": "pve1", "storage": "local-lvm", "bridge": "nxlab",
                      "checks": {"ports": [22, 443], "command": ["systemctl", "is-active", "nginx"], "boot_timeout": 300}});
    for s in [&tina, &vic] {
        assert_eq!(
            t.post("/api/v1/jobs", s, job(good.clone())).await.status,
            StatusCode::FORBIDDEN
        );
    }
    for s in [&otto, &dana] {
        let r = t.post("/api/v1/jobs", s, job(good.clone())).await;
        assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    }
    let p: String = t.one("SELECT params FROM jobs WHERE kind = 'restore_test' ORDER BY id DESC LIMIT 1");
    let p: Value = serde_json::from_str(&p).unwrap();
    assert_eq!(p["checks"]["ports"], json!([22, 443]));
    assert_eq!(p["bridge"], "nxlab");
    for (bad, code) in [
        (
            json!({"source": "ct-101", "time": 1000, "node": "pve1", "storage": "s", "checks": {"ports": [22]}}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"source": "vm-100", "time": 1000, "node": "pve1", "storage": "s", "checks": {"boot_timeout": 5}}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"source": "vm-100", "time": 1000, "node": "pve1", "storage": "s", "checks": {"agent": false, "ports": [22]}}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"source": "vm-100", "time": 1000, "node": "pve 1", "storage": "s"}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"source": "host-ab", "time": 1000, "node": "pve1", "storage": "s"}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"source": "vm-102", "time": 900, "node": "pve1", "storage": "s"}),
            StatusCode::NOT_FOUND,
        ),
        (
            json!({"source": "vm-100", "time": 1000, "node": "pve1", "storage": "s", "source_id": 2}),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        assert_eq!(
            t.post("/api/v1/jobs", &otto, job(bad.clone())).await.status,
            code,
            "{bad}"
        );
    }
    let r = t
        .post(
            "/api/v1/jobs",
            &otto,
            job(json!({"source": "ct-101", "time": 1000, "node": "pve1", "storage": "s"})),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "containers: init check only");
    // results: tenant-scoped, newest first
    let r = t.get("/api/v1/restore-tests", &tina).await;
    let rows = r.body.as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        (rows[0]["state"].as_str(), rows[0]["boot_secs"].as_i64()),
        (Some("passed"), Some(30))
    );
    let r = t.get("/api/v1/restore-tests?tenant=globex", &otto).await;
    assert_eq!(r.body.as_array().unwrap().len(), 1);
    // the dashboard KPI: the newest result per guest within the window (these are from 1970)
    let r = t.get("/api/v1/dashboard?days=30", &otto).await;
    assert_eq!(r.body["restore_tests"]["tested"], 0, "{}", r.body["restore_tests"]);
    let now = catalog::now();
    t.st.cat
        .conn()
        .execute("UPDATE restore_tests SET finished = ?1 + id", [now - 100])
        .unwrap();
    let r = t.get("/api/v1/dashboard?days=7", &tina).await;
    let k = &r.body["restore_tests"];
    assert_eq!(
        (k["tested"].as_i64(), k["passed"].as_i64(), k["failed"].as_i64()),
        (Some(1), Some(1), Some(0)),
        "{k}"
    );
}

/// Group schedules: PVE groups of the own tenant, admins and tenant admins.
#[tokio::test]
async fn restore_test_schedules() {
    let t = T::new();
    let (alice, otto, dana, tina) = (
        t.login("alice").await,
        t.login("otto").await,
        t.login("dana").await,
        t.login("tina").await,
    );
    let body = json!({"every_days": 7, "node": "pve1", "storage": "local-lvm", "checks": {"ports": [22]}});
    let url = "/api/v1/restore-tests/schedules/1";
    assert_eq!(t.put(url, &otto, body.clone()).await.status, StatusCode::FORBIDDEN);
    assert_eq!(
        t.put("/api/v1/restore-tests/schedules/2", &dana, body.clone())
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.put("/api/v1/restore-tests/schedules/3", &alice, body.clone())
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        t.put("/api/v1/restore-tests/schedules/9", &alice, body.clone())
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    let mut bad = body.clone();
    bad["every_days"] = json!(0);
    assert_eq!(t.put(url, &dana, bad).await.status, StatusCode::BAD_REQUEST);
    let r = t.put(url, &dana, body.clone()).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let mut b2 = body.clone();
    b2["every_days"] = json!(14);
    assert_eq!(t.put(url, &alice, b2).await.status, StatusCode::OK);
    t.put("/api/v1/restore-tests/schedules/2", &alice, body.clone()).await;
    let r = t.get("/api/v1/restore-tests/schedules", &tina).await;
    let rows = r.body.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0]["every_days"].as_i64(), rows[0]["group"].as_str()),
        (Some(14), Some("g1"))
    );
    assert_eq!(
        t.get("/api/v1/restore-tests/schedules", &otto)
            .await
            .body
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(t.delete(url, &dana).await.status, StatusCode::NO_CONTENT);
    assert_eq!(t.delete(url, &dana).await.status, StatusCode::NOT_FOUND);
    let n: i64 = t.one("SELECT COUNT(*) FROM audit WHERE action LIKE 'restore_test.%schedule'");
    assert_eq!(n, 4);

    // Phase 44: a plugin group gets a schedule when its plugin declares the restore `verify`;
    // node, storage and checks do not apply (the plugin's restore test)
    let manifest = |restores: Value| json!({"kinds": [{"kind": "pgx", "restores": restores}]}).to_string();
    t.st.cat
        .conn()
        .execute_batch(&format!(
            "INSERT INTO sources (id, tenant, kind, name, config) VALUES (4, 'acme', 'plugin:pgx', 'pg', '{{}}');
             INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES (4, 'acme', 4, 1, 'g4', '[\"db\"]');
             INSERT INTO plugins (id, version, name, publisher, sha256, bin_sha256, size, manifest, signer, state, current, enabled, uploaded_by, uploaded_at)
               VALUES ('pgx', '1.0.0', 'PG', 'p', 'a', 'b', 1, '{}', 'k', 'installed', 1, 1, 'a', 1);",
            manifest(json!([{"id": "to_target"}]))
        ))
        .unwrap();
    let url = "/api/v1/restore-tests/schedules/4";
    let r = t.put(url, &alice, json!({"every_days": 7})).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    assert!(
        r.body["error"].as_str().unwrap().contains("no restore test"),
        "{:?}",
        r.body
    );
    t.st.cat
        .conn()
        .execute(
            "UPDATE plugins SET manifest = ?1",
            [manifest(json!([{"id": "to_target"}, {"id": "verify"}]))],
        )
        .unwrap();
    let r = t
        .put(
            url,
            &alice,
            json!({"every_days": 7, "node": "ignored", "checks": {"ports": [22]}}),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let (node, checks): (String, String) =
        t.st.cat
            .conn()
            .query_row(
                "SELECT node, checks FROM restore_test_schedules WHERE group_id = 4",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
    assert_eq!((node.as_str(), checks.as_str()), ("", "{}"));
}

fn plan(name: &str) -> Value {
    json!({"name": name, "source_id": 1, "node": "pve1", "storage": "local-lvm", "test_bridge": "nxlab",
           "network_map": {"vmbr0": "vmbr10"}, "rpo_hours": 24,
           "steps": [{"source": "vm-100", "wave": 1, "checks": {"ports": [5432]}},
                     {"source": "ct-101", "wave": 2, "delay": 60, "target": 301}]})
}

/// Plans: create (readiness queued at once), validation, test run, execution
/// through the approval gate with a typed confirmation, runs and DR report.
#[tokio::test]
async fn recovery_plans() {
    let t = T::new();
    seed(&t);
    let (alice, otto, dana, tina) = (
        t.login("alice").await,
        t.login("otto").await,
        t.login("dana").await,
        t.login("tina").await,
    );
    assert_eq!(
        t.post("/api/v1/recovery-plans", &otto, plan("erp")).await.status,
        StatusCode::FORBIDDEN
    );
    let r = t.post("/api/v1/recovery-plans", &dana, plan("erp")).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["tenant"], "acme");
    let id = r.body["id"].as_i64().unwrap();
    let n: i64 = t.one("SELECT COUNT(*) FROM jobs WHERE kind = 'recovery_readiness'");
    assert_eq!(n, 1);
    assert_eq!(
        t.post("/api/v1/recovery-plans", &dana, plan("erp")).await.status,
        StatusCode::CONFLICT
    );
    for (k, v) in [
        ("steps", json!([])),
        ("steps", json!([{"source": "vm-100"}, {"source": "ct-100"}])),
        ("steps", json!([{"source": "ct-101", "checks": {"command": ["true"]}}])),
        ("steps", json!([{"source": "vm-100", "wave": 0}])),
        ("source_id", json!(2)),
        ("source_id", json!(3)),
        ("rpo_hours", json!(0)),
        ("network_map", json!({"vmbr0": "a b"})),
    ] {
        let mut p = plan("x");
        p["tenant"] = json!("acme");
        p[k] = v.clone();
        assert_eq!(
            t.post("/api/v1/recovery-plans", &alice, p).await.status,
            StatusCode::BAD_REQUEST,
            "{k}: {v}"
        );
    }
    let mut p = plan("erp2");
    p["tenant"] = json!("globex");
    assert_eq!(
        t.post("/api/v1/recovery-plans", &dana, p).await.status,
        StatusCode::FORBIDDEN
    );
    let mut upd = plan("erp");
    upd["rpo_hours"] = json!(12);
    let r = t.put(&format!("/api/v1/recovery-plans/{id}"), &dana, upd).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let r = t.get("/api/v1/recovery-plans", &tina).await;
    assert_eq!(r.body[0]["rpo_hours"], 12);
    assert_eq!(r.body[0]["steps"][1]["target"], 301);

    // test run
    let url = |x: &str| format!("/api/v1/recovery-plans/{id}/{x}");
    assert_eq!(
        t.post(&url("test"), &tina, json!({})).await.status,
        StatusCode::FORBIDDEN
    );
    let r = t.post(&url("test"), &otto, json!({})).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let run = r.body["run_id"].as_i64().unwrap();
    let job: i64 = t.one(&format!("SELECT job_id FROM recovery_runs WHERE id = {run}"));
    assert_eq!(job, r.body["job_id"].as_i64().unwrap());
    let jp: String = t.one(&format!(
        "SELECT params FROM jobs WHERE id = {job} AND kind = 'recovery_test'"
    ));
    assert!(jp.contains(&format!("\"run_id\":{run}")));
    assert_eq!(
        t.post(&url("test"), &otto, json!({})).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        t.post(&url("readiness"), &otto, json!({})).await.status,
        StatusCode::ACCEPTED
    );

    // execution: typed name, approval
    assert_eq!(
        t.post(&url("execute"), &otto, json!({"confirm": "ERP"})).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        t.post(&url("execute"), &tina, json!({"confirm": "erp"})).await.status,
        StatusCode::FORBIDDEN
    );
    let r = t.post(&url("execute"), &otto, json!({"confirm": "erp"})).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    let qp: String = t.one(&format!(
        "SELECT params FROM quorum WHERE id = {q} AND action = 'recovery_plan.execute' AND state = 'pending'"
    ));
    let qp: Value = serde_json::from_str(&qp).unwrap();
    assert_eq!(
        (qp["tenant"].as_str(), qp["plan"]["rpo_hours"].as_i64()),
        (Some("acme"), Some(12))
    );
    assert!(qp["plan"].get("readiness").is_none());

    // runs and the DR report
    t.st.cat
        .conn()
        .execute(
            "UPDATE recovery_runs SET state = 'passed', finished = started + 60, results = ?2 WHERE id = ?1",
            params![
                run,
                json!([{"source": "vm-100", "time": 1000, "wave": 1, "state": "passed", "checks": []}]).to_string()
            ],
        )
        .unwrap();
    let r = t.get(&url("runs"), &tina).await;
    assert_eq!(
        (r.body[0]["state"].as_str(), r.body[0]["mode"].as_str()),
        (Some("passed"), Some("test"))
    );
    let report = format!("/api/v1/recovery-runs/{run}/report");
    assert_eq!(t.get(&report, &tina).await.status, StatusCode::OK);
    t.st.cat
        .conn()
        .execute("UPDATE recovery_runs SET tenant = 'globex' WHERE id = ?1", [run])
        .unwrap();
    assert_eq!(t.get(&report, &tina).await.status, StatusCode::NOT_FOUND);
    assert_eq!(t.get(&report, &alice).await.status, StatusCode::OK);

    // delete: the runs stay
    let del = format!("/api/v1/recovery-plans/{id}");
    assert_eq!(t.delete(&del, &otto).await.status, StatusCode::FORBIDDEN);
    assert_eq!(t.delete(&del, &dana).await.status, StatusCode::NO_CONTENT);
    let n: i64 = t.one("SELECT COUNT(*) FROM recovery_runs");
    assert_eq!(n, 1);
    let n: i64 = t.one("SELECT COUNT(*) FROM audit WHERE action LIKE 'recovery_plan.%'");
    assert_eq!(n, 5, "create, update, test, readiness, delete");
}
