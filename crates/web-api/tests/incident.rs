//! Phase 21b: incident mode (enter at once, leave by approval), the session cap
//! per account and the DEK rotation reminder setting.

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

#[tokio::test]
async fn incident_mode_enters_at_once_and_leaves_by_approval() {
    let t = T::new();
    let (alice, sam, otto, tina) = (
        t.login("alice").await,
        t.login("sam").await,
        t.login("otto").await,
        t.login("tina").await,
    );
    let sam2 = t.login("sam").await;
    t.exec(&format!(
        "INSERT INTO api_tokens (user_id, name, prefix, hash, scope, expires, created)
         VALUES ({}, 'ci', 'abcd1234', 'x', 'read', {}, 1)",
        t.ids["otto"],
        catalog::now() + 3600
    ));
    // group 2 was paused before (until a time): restored when leaving
    let later = catalog::now() + 86400;
    t.exec(&format!("UPDATE groups SET paused_until = {later} WHERE id = 2"));
    let body = json!({"reason": "ransomware on fileserver", "hold": {"tenants": ["acme"], "sources": ["vm-100"], "from": 0, "to": 1500},
                      "groups": [1, 2]});

    for s in [&alice, &otto, &tina] {
        let r = t.post("/api/v1/incident", s, t.reauth("alice", body.clone())).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "security officers only");
    }
    assert_eq!(
        t.post("/api/v1/incident", &sam, body.clone()).await.status,
        StatusCode::BAD_REQUEST,
        "re-authentication"
    );
    let mut bad = body.clone();
    bad["groups"] = json!([99]);
    assert_eq!(
        t.post("/api/v1/incident", &sam, t.reauth("sam", bad)).await.status,
        StatusCode::BAD_REQUEST
    );
    let mut bad = body.clone();
    bad["hold"]["tenants"] = json!(["nobody"]);
    assert_eq!(
        t.post("/api/v1/incident", &sam, t.reauth("sam", bad)).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        t.one::<i64>("SELECT COUNT(*) FROM legal_holds"),
        0,
        "nothing applied on errors"
    );

    let r = t.post("/api/v1/incident", &sam, t.reauth("sam", body.clone())).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["held"], json!(["acme/vm-100/1000"]));
    assert_eq!(
        r.body["paused"],
        json!([{"id": 1, "prev": null}, {"id": 2, "prev": later}])
    );
    assert_eq!(
        (r.body["sessions_ended"].clone(), r.body["tokens_revoked"].clone()),
        (json!(4), json!(1))
    );
    assert_eq!(t.one::<String>("SELECT state FROM legal_holds"), "active");
    assert_eq!(t.one::<i64>("SELECT COUNT(*) FROM groups WHERE paused_until = -1"), 2);
    assert_eq!(
        t.one::<Option<i64>>("SELECT paused_until FROM groups WHERE id = 3"),
        None
    );
    assert_eq!(t.one::<i64>("SELECT COUNT(*) FROM api_tokens"), 0);
    for s in [&alice, &otto, &tina, &sam2] {
        assert_eq!(
            t.get("/api/v1/auth/me", s).await.status,
            StatusCode::UNAUTHORIZED,
            "other sessions ended"
        );
    }
    let me = t.get("/api/v1/auth/me", &sam).await;
    assert_eq!(me.status, StatusCode::OK, "the officer's own session stays");
    assert_eq!(me.body["incident"]["by"], "sam");
    assert_eq!(
        t.one::<String>("SELECT severity || ' ' || kind FROM alerts WHERE resolved_at IS NULL"),
        "critical incident"
    );
    assert_eq!(
        t.one::<i64>("SELECT COUNT(*) FROM audit WHERE action = 'incident.enter'"),
        1
    );
    assert_eq!(
        t.post("/api/v1/incident", &sam, t.reauth("sam", body.clone()))
            .await
            .status,
        StatusCode::CONFLICT
    );

    // banners and state; tenant accounts see none
    let (alice, otto, tina) = (t.login("alice").await, t.login("otto").await, t.login("tina").await);
    assert_eq!(
        t.get("/api/v1/dashboard", &otto).await.body["incident"]["reason"],
        "ransomware on fileserver"
    );
    assert_eq!(t.get("/api/v1/auth/me", &tina).await.body["incident"], Value::Null);
    assert_eq!(t.get("/api/v1/incident", &tina).await.status, StatusCode::FORBIDDEN);
    assert_eq!(t.get("/api/v1/incident", &otto).await.body["active"], true);
    // no group resumes while it is active
    let r = t.post("/api/v1/groups/1/resume", &otto, json!({})).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);

    // leaving: a request, approved by another approver even with approvals disabled
    t.exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('approvals_enabled', 'false')");
    assert_eq!(
        t.post("/api/v1/incident/leave", &otto, json!({})).await.status,
        StatusCode::FORBIDDEN
    );
    let r = t.post("/api/v1/incident/leave", &sam, json!({})).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    assert_eq!(
        t.post("/api/v1/incident/leave", &alice, json!({})).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(t.get("/api/v1/incident", &alice).await.body["leave_quorum"], json!(q));
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "not by the requester");
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &alice, json!({})).await;
    assert_eq!(r.body["state"], "executed", "{:?}", r.body);
    let v = t.get("/api/v1/incident", &alice).await.body;
    assert_eq!(
        (
            v["active"].clone(),
            v["ended_by"].clone(),
            v["approved_by"].clone(),
            v["resumed"].clone()
        ),
        (json!(false), json!("sam"), json!("alice"), json!(2))
    );
    assert_eq!(
        t.one::<Option<i64>>("SELECT paused_until FROM groups WHERE id = 1"),
        None
    );
    assert_eq!(
        t.one::<Option<i64>>("SELECT paused_until FROM groups WHERE id = 2"),
        Some(later)
    );
    assert_eq!(t.one::<i64>("SELECT COUNT(*) FROM alerts WHERE resolved_at IS NULL"), 0);
    assert_eq!(t.one::<String>("SELECT state FROM legal_holds"), "active", "holds stay");
    assert_eq!(t.get("/api/v1/auth/me", &alice).await.body["incident"], Value::Null);
    assert_eq!(
        t.post("/api/v1/groups/1/resume", &otto, json!({})).await.status,
        StatusCode::OK
    );
    assert_eq!(
        t.post("/api/v1/incident/leave", &sam, json!({})).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        t.one::<i64>("SELECT COUNT(*) FROM audit WHERE action = 'incident.leave'"),
        1
    );
}

/// Everything held / paused when the request names no tenants and no groups.
#[tokio::test]
async fn incident_defaults_hold_all_tenants_and_pause_all_groups() {
    let t = T::new();
    let sam = t.login("sam").await;
    let body = json!({"reason": "x", "hold": {"from": 1500, "to": 1500}});
    let r = t.post("/api/v1/incident", &sam, t.reauth("sam", body)).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["held"], json!(["acme/vm-101/1500", "globex/vm-200/1500"]));
    assert_eq!(t.one::<i64>("SELECT COUNT(*) FROM groups WHERE paused_until = -1"), 3);
}

#[tokio::test]
async fn session_cap_drops_the_oldest_and_settings_are_admin_only() {
    let t = T::new();
    let alice = t.login("alice").await;
    let sam = t.login("sam").await;
    let sec = t.get("/api/v1/settings/security", &sam).await.body;
    assert_eq!(
        (sec["max_sessions"].clone(), sec["dek_rotation_days"].clone()),
        (json!(5), json!(365))
    );
    for (body, path) in [
        (json!({"max": 2}), "/api/v1/settings/max-sessions"),
        (json!({"days": 90}), "/api/v1/settings/dek-rotation"),
    ] {
        assert_eq!(t.put(path, &sam, body.clone()).await.status, StatusCode::FORBIDDEN);
        assert_eq!(t.put(path, &alice, body).await.status, StatusCode::OK);
    }
    for (body, path) in [
        (json!({"max": 0}), "/api/v1/settings/max-sessions"),
        (json!({"max": 51}), "/api/v1/settings/max-sessions"),
        (json!({"days": 29}), "/api/v1/settings/dek-rotation"),
    ] {
        assert_eq!(t.put(path, &alice, body).await.status, StatusCode::BAD_REQUEST);
    }
    assert_eq!(
        t.get("/api/v1/settings/security", &alice).await.body["dek_rotation_days"],
        90
    );
    // a third login of alice ends her oldest session
    t.exec("UPDATE sessions SET created = created - 100");
    let a2 = t.login("alice").await;
    assert_eq!(t.get("/api/v1/auth/me", &alice).await.status, StatusCode::OK);
    let _a3 = t.login("alice").await;
    assert_eq!(
        t.get("/api/v1/auth/me", &alice).await.status,
        StatusCode::UNAUTHORIZED,
        "oldest ended"
    );
    assert_eq!(t.get("/api/v1/auth/me", &a2).await.status, StatusCode::OK);
    assert_eq!(
        t.get("/api/v1/auth/me", &sam).await.status,
        StatusCode::OK,
        "per account"
    );
    assert_eq!(
        t.one::<i64>("SELECT COUNT(*) FROM audit WHERE action = 'session.limit'"),
        1
    );
    for a in ["security.max_sessions", "security.dek_rotation"] {
        assert_eq!(
            t.one::<i64>(&format!("SELECT COUNT(*) FROM audit WHERE action = '{a}'")),
            1,
            "{a}"
        );
    }
}
