//! Phase 29 (NetBackup Tier 1): full-read interval and list, restores of flagged
//! snapshots (approval restore.infected), scan back requests, incident and lockdown
//! freezes, privileged-activity risk signals with step-up.

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
    ids: HashMap<String, i64>,
    _dir: tempfile::TempDir,
}

struct S {
    cookie: String,
    csrf: String,
}

struct R {
    status: StatusCode,
    body: Value,
}

impl T {
    fn new() -> T {
        let dir = tempfile::tempdir().unwrap();
        let cat = Catalog::open(&dir.path().join("catalog.db")).unwrap();
        let downloads = dir.path().join("downloads");
        std::fs::create_dir(&downloads).unwrap();
        let st = AppState::with_keys(cat, None, downloads, TotpKey::generate(), None);
        st.cat
            .conn()
            .execute_batch(
                r#"INSERT INTO tenants (name) VALUES ('acme'), ('globex');
                   INSERT INTO sources (id, tenant, kind, name, config) VALUES (1, 'acme', 'pve', 'pve-a', '{}'),
                     (2, 'globex', 'pve', 'pve-g', '{}');
                   INSERT INTO policies (id, name, schedule, gfs, offsite) VALUES
                     (1, 'daily', 'daily 22:00', '{"daily":7,"weekly":0,"monthly":0,"yearly":0}', 0);
                   INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES
                     (1, 'acme', 1, 1, 'a1', '[100]'), (2, 'acme', 1, 1, 'a2', '[101]'), (3, 'globex', 2, 1, 'g1', '[200]');
                   INSERT INTO snapshots (tenant, source, time, size, local, offsite) VALUES
                     ('acme', 'vm-100', 1000, 5, 1, 0), ('acme', 'vm-100', 2000, 5, 1, 0),
                     ('acme', 'vm-101', 1500, 5, 1, 0), ('globex', 'vm-200', 1500, 5, 1, 0);"#,
            )
            .unwrap();
        let mut t = T {
            app: web_api::router(st.clone()),
            st,
            secrets: HashMap::new(),
            ids: HashMap::new(),
            _dir: dir,
        };
        for (n, role, tenant) in [
            ("alice", "admin", None),
            ("sam", "security_officer", None),
            ("otto", "operator", None),
            ("tina", "tenant_user", Some("acme")),
        ] {
            let secret = catalog::auth::new_totp_secret();
            let enc = t.st.totp.encrypt(n, &secret).unwrap();
            let c = t.st.cat.conn();
            c.execute(
                "INSERT INTO users (name, password_hash, totp_secret, role, tenant, created) VALUES (?1,?2,?3,?4,?5,0)",
                params![n, pw_hash(), enc, role, tenant],
            )
            .unwrap();
            t.ids.insert(n.into(), c.last_insert_rowid());
            t.secrets.insert(n.into(), secret);
        }
        t
    }

    async fn call(&self, method: Method, path: &str, s: Option<&S>, body: Option<Value>) -> R {
        let mut b = Request::builder().method(method.clone()).uri(path);
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
        let raw = res.into_body().collect().await.unwrap().to_bytes().to_vec();
        R {
            status,
            body: serde_json::from_slice(&raw).unwrap_or(Value::Null),
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

    fn code(&self, name: &str) -> String {
        self.exec(&format!("UPDATE users SET totp_last_step = 0 WHERE name = '{name}'"));
        catalog::auth::totp_now(&self.secrets[name]).unwrap()
    }

    async fn login(&self, name: &str) -> S {
        let body = json!({"name": name, "password": PW, "totp": self.code(name)});
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let res = self.app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{name}");
        let cookie = res
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|c| c.strip_prefix("nx_session=")?.split(';').next().map(str::to_owned))
            .unwrap();
        let raw = res.into_body().collect().await.unwrap().to_bytes().to_vec();
        let body: Value = serde_json::from_slice(&raw).unwrap();
        S {
            cookie,
            csrf: body["csrf"].as_str().unwrap().to_owned(),
        }
    }

    fn reauth(&self, name: &str, extra: Value) -> Value {
        let mut v = json!({"current_password": PW, "current_totp": self.code(name)});
        v.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        v
    }

    fn exec(&self, sql: &str) {
        self.st.cat.conn().execute_batch(sql).unwrap();
    }

    fn one<V: catalog::rusqlite::types::FromSql>(&self, sql: &str) -> V {
        self.st.cat.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }
}

impl T {
    async fn delete(&self, path: &str, s: &S) -> R {
        self.call(Method::DELETE, path, Some(s), None).await
    }
    fn add_tenant_admin(&mut self) {
        let secret = catalog::auth::new_totp_secret();
        let enc = self.st.totp.encrypt("dana", &secret).unwrap();
        let c = self.st.cat.conn();
        c.execute(
            "INSERT INTO users (name, password_hash, totp_secret, role, tenant, created) VALUES ('dana',?1,?2,'tenant_admin','acme',0)",
            params![pw_hash(), enc],
        )
        .unwrap();
        self.ids.insert("dana".into(), c.last_insert_rowid());
        self.secrets.insert("dana".into(), secret);
    }
}

fn restore(source: &str, time: i64, link_down: bool) -> Value {
    json!({"kind": "restore", "tenant": if source == "vm-200" { "globex" } else { "acme" },
           "params": {"source": source, "time": time, "node": "pve1", "target": 900, "storage": "local-lvm",
                      "link_down": link_down}})
}

/// Full-read interval per group, the per-source list and the dashboard summary.
#[tokio::test]
async fn full_read_setting_list_and_dashboard() {
    let mut t = T::new();
    t.add_tenant_admin();
    let (alice, otto, tina, dana) = (
        t.login("alice").await,
        t.login("otto").await,
        t.login("tina").await,
        t.login("dana").await,
    );
    let r = t.put("/api/v1/groups/1/full-read", &alice, json!({"days": 14})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        (
            r.body["full_read_days"].clone(),
            r.body["full_read_default"].clone(),
            r.body["effective_days"].clone()
        ),
        (json!(14), json!(90), json!(14))
    );
    assert_eq!(
        t.put("/api/v1/groups/1/full-read", &alice, json!({"days": 400}))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    for s in [&otto, &tina] {
        assert_eq!(
            t.put("/api/v1/groups/1/full-read", s, json!({"days": 0})).await.status,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        t.put("/api/v1/groups/3/full-read", &dana, json!({"days": 0}))
            .await
            .status,
        StatusCode::NOT_FOUND,
        "another tenant's group"
    );
    let r = t.put("/api/v1/groups/2/full-read", &dana, json!({"days": null})).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body["effective_days"], 90);
    let groups = t.get("/api/v1/groups", &alice).await.body;
    let g1 = groups.as_array().unwrap().iter().find(|g| g["id"] == 1).unwrap();
    assert_eq!(
        (g1["full_read_days"].clone(), g1["full_read_default"].clone()),
        (json!(14), json!(90))
    );
    let audited: i64 = t.one("SELECT COUNT(*) FROM audit WHERE action = 'group.full_read'");
    assert_eq!(audited, 2);

    t.exec(
        r#"INSERT INTO full_reads (tenant, source, next_due, last_at, last_snapshot, last_job, result, changed,
             unreported, unreported_bytes, details, last_clean_at) VALUES
           ('acme', 'vm-100', 99999999999, 2000, 2000, 7, 'drift', 12, 2, 8388608,
            '{"tracker":"dirty-bitmap","examples":["drive-scsi0@0"]}', 1000),
           ('acme', 'vm-101', 99999999999, 1500, 1500, 6, 'clean', 3, 0, 0, '{"tracker":"dirty-bitmap"}', 1500),
           ('acme', 'host-a1', 5, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL),
           ('globex', 'vm-200', 99999999999, 1500, 1500, 5, 'clean', 0, 0, 0, NULL, 1500);"#,
    );
    let all = t.get("/api/v1/full-reads", &alice).await.body;
    assert_eq!(all.as_array().unwrap().len(), 4);
    let mine = t.get("/api/v1/full-reads", &tina).await.body;
    assert_eq!(mine.as_array().unwrap().len(), 3, "tenant-scoped");
    assert_eq!(
        t.get("/api/v1/full-reads?tenant=globex", &tina).await.status,
        StatusCode::FORBIDDEN
    );
    let one = t.get("/api/v1/full-reads?tenant=acme&source=vm-100", &otto).await.body;
    assert_eq!(one[0]["result"], "drift");
    assert_eq!(one[0]["details"]["tracker"], "dirty-bitmap");
    let d = t.get("/api/v1/dashboard", &tina).await.body;
    assert_eq!(
        d["full_reads"],
        json!({"sources": 3, "verified": 1, "drift": 1, "never": 1, "oldest_verified": 1000})
    );
}

/// A production restore of a flagged snapshot is an approval request
/// `restore.infected`; isolated restores and clean snapshots are not.
#[tokio::test]
async fn flagged_snapshot_restores_need_approval() {
    let t = T::new();
    let (alice, otto, tina) = (t.login("alice").await, t.login("otto").await, t.login("tina").await);
    t.exec(
        "UPDATE snapshots SET scan_state = 'hit', anomaly = 'YARA: 3 matches (ransom_note)', anomaly_at = 2100
         WHERE source = 'vm-100' AND time = 2000",
    );
    let snaps = t.get("/api/v1/snapshots?tenant=acme&source=vm-100", &alice).await.body;
    assert_eq!(
        snaps
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["flagged"].clone())
            .collect::<Vec<_>>(),
        [json!(true), json!(false)]
    );
    // isolated: a plain job
    let r = t.post("/api/v1/jobs", &otto, restore("vm-100", 2000, true)).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    assert!(r.body["id"].is_i64());
    // clean snapshot to production: a plain job
    let r = t.post("/api/v1/jobs", &tina, restore("vm-100", 1000, false)).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    assert!(r.body["id"].is_i64());
    // flagged to production: approval
    let r = t.post("/api/v1/jobs", &tina, restore("vm-100", 2000, false)).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    assert_eq!(r.body["infected"], true);
    let q = r.body["quorum_id"].as_i64().unwrap();
    let (action, params): (String, String) =
        t.st.cat
            .conn()
            .query_row("SELECT action, params FROM quorum WHERE id = ?1", [q], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
    assert_eq!(action, "restore.infected");
    let p: Value = serde_json::from_str(&params).unwrap();
    assert_eq!(
        (p["kind"].clone(), p["params"]["time"].clone()),
        (json!("restore"), json!(2000))
    );
    assert!(p["reason"].as_str().unwrap().contains("ransom_note"));
    let jobs: i64 = t.one("SELECT COUNT(*) FROM jobs WHERE json_extract(params, '$.time') = 2000 AND json_extract(params, '$.link_down') = 0");
    assert_eq!(jobs, 0, "no job before the approval");
    // the approver executes nothing in the web-api: the scheduler queues the job
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &alice, json!({})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["state"], "approved");
    // several guests at once: a flagged one only with the network disconnected
    let many = |link_down: bool| {
        json!({"tenant": "acme", "items": [{"source": "vm-101", "time": 1500}, {"source": "vm-100", "time": 2000}],
               "node": "pve1", "storage": "local-lvm", "target_base": 950, "link_down": link_down})
    };
    let r = t.post("/api/v1/restores", &otto, many(false)).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
    assert_eq!(
        t.post("/api/v1/restores", &otto, many(true)).await.status,
        StatusCode::ACCEPTED
    );
    // approvals disabled: administrators only
    t.exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('approvals_enabled', 'false')");
    let r = t.post("/api/v1/jobs", &otto, restore("vm-100", 2000, false)).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{:?}", r.body);
    let r = t.post("/api/v1/jobs", &alice, restore("vm-100", 2000, false)).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        (r.body["state"].clone(), r.body["infected"].clone()),
        (json!("approved"), json!(true))
    );
    // a security officer cleared the flag: a plain job again
    t.exec("UPDATE snapshots SET anomaly_cleared_at = 3000, anomaly_cleared_by = 'sam' WHERE time = 2000");
    let r = t.post("/api/v1/jobs", &otto, restore("vm-100", 2000, false)).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    assert!(r.body["id"].is_i64());
}

/// Scan back: rules needed, one at a time per source, the snapshot's clean point.
#[tokio::test]
async fn scan_back_requests() {
    let t = T::new();
    let (alice, otto, tina) = (t.login("alice").await, t.login("otto").await, t.login("tina").await);
    let path = "/api/v1/snapshots/acme/vm-100/2000/scan-back";
    assert_eq!(
        t.post(path, &otto, json!({})).await.status,
        StatusCode::CONFLICT,
        "no rules"
    );
    t.exec("INSERT INTO yara_rules VALUES ('r.yar', 'rule x { condition: true }', 'ab', 'alice', 1)");
    assert_eq!(t.post(path, &tina, json!({})).await.status, StatusCode::FORBIDDEN);
    assert_eq!(
        t.post(path, &otto, json!({"max": 0})).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        t.post("/api/v1/snapshots/acme/vm-100/9/scan-back", &otto, json!({}))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    let r = t.post(path, &otto, json!({"budget_min": 30, "max": 5})).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let id = r.body["id"].as_i64().unwrap();
    let (kind, params): (String, String) =
        t.st.cat
            .conn()
            .query_row("SELECT kind, params FROM jobs WHERE id = ?1", [id], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
    assert_eq!(kind, "scan_back");
    assert_eq!(
        serde_json::from_str::<Value>(&params).unwrap(),
        json!({"source": "vm-100", "from": 2000, "budget": 1800, "max": 5})
    );
    assert_eq!(
        t.post(path, &alice, json!({})).await.status,
        StatusCode::CONFLICT,
        "already queued"
    );
    t.exec("UPDATE snapshots SET clean_point = 4000 WHERE source = 'vm-100' AND time = 1000");
    let snaps = t.get("/api/v1/snapshots?tenant=acme&source=vm-100", &tina).await.body;
    assert_eq!(snaps[1]["clean_point"], 4000);
    assert!(snaps[0]["clean_point"].is_null());
}

/// Incident mode with freezes: configuration, deletions and restores to
/// production refused; what an incident needs still works; lifting the
/// freezes is a second person's approval; tenant lockdown freezes likewise.
#[tokio::test]
async fn incident_and_lockdown_freezes() {
    let t = T::new();
    let sam = t.login("sam").await;
    let body = json!({"reason": "ransomware on the file server", "groups": [],
                      "freeze": {"config": true, "deletions": true, "restores": true}});
    let r = t.post("/api/v1/incident", &sam, t.reauth("sam", body)).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(
        r.body["freeze"],
        json!({"config": true, "deletions": true, "restores": true})
    );
    let (alice, otto) = (t.login("alice").await, t.login("otto").await);
    let me = t.get("/api/v1/auth/me", &alice).await.body;
    assert_eq!(
        me["freeze"],
        json!({"config": true, "deletions": true, "restores": true, "tenants": []})
    );
    assert_eq!(me["incident"]["freeze"]["config"], true);
    // configuration: refused for every role
    for (m, p, b) in [
        (Method::PUT, "/api/v1/groups/1/full-read", json!({"days": 3})),
        (Method::POST, "/api/v1/policies", json!({"name": "x"})),
        (Method::PUT, "/api/v1/settings/mgmt-allow", json!({"cidrs": []})),
    ] {
        let r = t.call(m, p, Some(&alice), Some(b)).await;
        assert_eq!(r.status, StatusCode::CONFLICT, "{p}");
        assert!(r.body["error"].as_str().unwrap().contains("frozen"), "{p}");
    }
    // what an incident needs
    assert!(t
        .post("/api/v1/groups/1/pause", &alice, json!({}))
        .await
        .status
        .is_success());
    let r = t
        .put(
            &format!("/api/v1/users/{}", t.ids["otto"]),
            &alice,
            json!({"disabled": true}),
        )
        .await;
    assert_ne!(r.status, StatusCode::CONFLICT, "disabling an account: {:?}", r.body);
    let r = t
        .put(
            &format!("/api/v1/users/{}", t.ids["tina"]),
            &alice,
            json!({"role": "viewer"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "other account changes");
    // deletions (the config freeze answers first; also without it, see the lockdown below)
    assert_eq!(
        t.delete("/api/v1/snapshots/acme/vm-100/1000", &alice).await.status,
        StatusCode::CONFLICT
    );
    // restores: isolated yes, production no
    let r = t.post("/api/v1/jobs", &alice, restore("vm-100", 1000, false)).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
    assert!(r.body["error"]
        .as_str()
        .unwrap()
        .contains("restores to production are frozen"));
    assert_eq!(
        t.post("/api/v1/jobs", &alice, restore("vm-100", 1000, true))
            .await
            .status,
        StatusCode::ACCEPTED
    );
    let _ = otto;
    // lifting: a request, never approved by the requester
    let r = t.post("/api/v1/incident/freeze/lift", &sam, json!({})).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    assert_eq!(
        t.post("/api/v1/incident/freeze/lift", &alice, json!({})).await.status,
        StatusCode::CONFLICT,
        "already requested"
    );
    let st = t.get("/api/v1/incident", &alice).await.body;
    assert_eq!(st["freeze_lift_quorum"], q);
    assert_eq!(
        t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({}))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &alice, json!({})).await;
    assert_eq!(r.body["state"], "executed", "{:?}", r.body);
    assert_eq!(
        t.put("/api/v1/groups/1/full-read", &alice, json!({"days": 3}))
            .await
            .status,
        StatusCode::OK
    );
    let me = t.get("/api/v1/auth/me", &alice).await.body;
    assert!(me["freeze"].is_null());
    assert_eq!(me["incident"]["since"], st["since"], "incident mode stays");
    assert_eq!(
        t.post("/api/v1/incident/freeze/lift", &sam, json!({})).await.status,
        StatusCode::CONFLICT,
        "nothing frozen"
    );

    // tenant lockdown freezes
    let body = json!({"reason": "acme", "hold": null, "freeze": {"deletions": true, "restores": true}});
    let r = t
        .post("/api/v1/tenants/acme/lockdown", &sam, t.reauth("sam", body))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["freeze"]["restores"], true);
    let r = t.post("/api/v1/jobs", &alice, restore("vm-100", 1000, false)).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    let r = t.post("/api/v1/jobs", &alice, restore("vm-200", 1500, false)).await;
    assert_eq!(
        r.status,
        StatusCode::ACCEPTED,
        "other tenants are not frozen: {:?}",
        r.body
    );
    let me = t.get("/api/v1/auth/me", &alice).await.body;
    assert_eq!(
        me["freeze"]["tenants"],
        json!([{"tenant": "acme", "deletions": true, "restores": true}])
    );
    let l = t.get("/api/v1/lockdowns", &alice).await.body;
    assert_eq!(l[0]["freeze"]["deletions"], true);
    let r = t
        .post("/api/v1/tenants/acme/lockdown/freeze/lift", &alice, json!({}))
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let q = r.body["quorum_id"].as_i64().unwrap();
    assert_eq!(
        t.get("/api/v1/tenants/acme/lockdown", &sam).await.body["freeze_lift_quorum"],
        q
    );
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.body["state"], "executed", "{:?}", r.body);
    assert!(!catalog::incident::tenant(&t.st.cat.conn(), "acme").unwrap().any());
    assert!(
        catalog::tenants::locked_down(&t.st.cat.conn(), "acme").unwrap(),
        "the lockdown stays"
    );
}

/// Risk signals: bulk deletes and an unusual sign-in hour mark the account;
/// marked sessions step up before their next change; officers list and clear.
#[tokio::test]
async fn risk_signals_and_step_up() {
    let t = T::new();
    let (alice, sam) = (t.login("alice").await, t.login("sam").await);
    t.exec(
        "INSERT INTO snapshots (tenant, source, time, size, local, offsite) VALUES
           ('acme', 'vm-101', 11, 5, 1, 0), ('acme', 'vm-101', 12, 5, 1, 0), ('acme', 'vm-101', 13, 5, 1, 0),
           ('acme', 'vm-101', 14, 5, 1, 0), ('acme', 'vm-101', 15, 5, 1, 0), ('acme', 'vm-101', 16, 5, 1, 0),
           ('acme', 'vm-101', 17, 5, 1, 0), ('acme', 'vm-101', 18, 5, 1, 0), ('acme', 'vm-101', 19, 5, 1, 0),
           ('acme', 'vm-101', 20, 5, 1, 0);",
    );
    for time in 11..=19 {
        let r = t.delete(&format!("/api/v1/snapshots/acme/vm-101/{time}"), &alice).await;
        assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    }
    assert_eq!(
        t.put("/api/v1/groups/1/full-read", &alice, json!({"days": 5}))
            .await
            .status,
        StatusCode::OK,
        "nine deletes: no mark"
    );
    let r = t.delete("/api/v1/snapshots/acme/vm-101/20", &alice).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "the tenth is still requested");
    let (sev, msg): (String, String) =
        t.st.cat
            .conn()
            .query_row(
                "SELECT severity, message FROM alerts WHERE kind = 'user_risk'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
    assert_eq!(sev, "critical");
    assert!(msg.contains("10 delete requests"), "{msg}");
    let r = t.put("/api/v1/groups/1/full-read", &alice, json!({"days": 6})).await;
    assert_eq!(r.status, StatusCode::PRECONDITION_REQUIRED, "{:?}", r.body);
    assert!(r.body["error"].as_str().unwrap().starts_with("step-up required"));
    assert_eq!(
        t.get("/api/v1/groups", &alice).await.status,
        StatusCode::OK,
        "reading stays"
    );
    let me = t.get("/api/v1/auth/me", &alice).await.body;
    assert_eq!(me["step_up"]["done"], false);
    let r = t
        .post(
            "/api/v1/auth/step-up",
            &alice,
            json!({"current_password": "wrong", "current_totp": t.code("alice")}),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = t
        .post("/api/v1/auth/step-up", &alice, t.reauth("alice", json!({})))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        t.put("/api/v1/groups/1/full-read", &alice, json!({"days": 6}))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(t.get("/api/v1/auth/me", &alice).await.body["step_up"]["done"], true);
    // a new session of the marked account steps up again
    let alice2 = t.login("alice").await;
    assert_eq!(
        t.put("/api/v1/groups/1/full-read", &alice2, json!({"days": 7}))
            .await
            .status,
        StatusCode::PRECONDITION_REQUIRED
    );
    let list = t.get("/api/v1/risk", &sam).await.body;
    assert_eq!(list[0]["user"], "alice");
    assert_eq!(
        t.get("/api/v1/risk", &t.login("otto").await).await.status,
        StatusCode::FORBIDDEN
    );
    let alice_id = t.ids["alice"];
    let r = t
        .post(&format!("/api/v1/users/{alice_id}/risk/clear"), &sam, json!({}))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        t.put("/api/v1/groups/1/full-read", &alice2, json!({"days": 7}))
            .await
            .status,
        StatusCode::OK
    );
    assert!(t.get("/api/v1/auth/me", &alice2).await.body["step_up"].is_null());

    // an hour the account never signs in at, after enough history
    let hour = (catalog::now().rem_euclid(86_400)) / 3600;
    let far = (hour + 12) % 24;
    t.exec(&format!(
        "DELETE FROM login_hours WHERE user_id = {sid};
         INSERT INTO login_hours (user_id, hour, count, last_seen) VALUES ({sid}, {far}, 20, {now});",
        sid = t.ids["sam"],
        now = catalog::now()
    ));
    let sam2 = t.login("sam").await;
    let n: i64 = t.one("SELECT COUNT(*) FROM alerts WHERE kind = 'user_risk' AND severity = 'warning'");
    assert_eq!(n, 1);
    let clear_own = format!("/api/v1/users/{}/risk/clear", t.ids["sam"]);
    let r = t.post(&clear_own, &sam2, json!({})).await;
    assert_eq!(r.status, StatusCode::PRECONDITION_REQUIRED, "marked: step up first");
    let r = t.post("/api/v1/auth/step-up", &sam2, t.reauth("sam", json!({}))).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = t.post(&clear_own, &sam2, json!({})).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "not one's own mark");
}
