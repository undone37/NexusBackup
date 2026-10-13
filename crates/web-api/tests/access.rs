//! Phase 14d access controls: viewer role, download privilege, account expiry,
//! session list / revoke, configurable timeouts, login banner, management
//! allow-list, dormant-account setting and the approver-count warning; API
//! tokens follow the account state.

impl T {
    /// An API token for `name` written straight into the catalog (bypasses the
    /// create checks, e.g. an operator scope for a viewer).
    fn token(&self, name: &str, scope: &str) -> String {
        let (prefix, secret) = (format!("{:08x}", self.ids[name]), "s".repeat(40));
        self.exec(&format!(
            "INSERT INTO api_tokens (user_id, name, prefix, hash, scope, expires, created)
             VALUES ({}, 't', '{prefix}', '{}', '{scope}', {}, 1)",
            self.ids[name],
            web_api::sha256_hex(secret.as_bytes()),
            catalog::now() + 3600
        ));
        format!("nxt_{prefix}_{secret}")
    }

    async fn bearer(&self, method: Method, path: &str, tok: &str, body: Option<Value>) -> StatusCode {
        let b = Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {tok}"));
        let req = match body {
            Some(v) => b
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(v.to_string()))
                .unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        self.app.clone().oneshot(req).await.unwrap().status()
    }
}

/// API tokens follow the account checks: expired or disabled (also dormant-disabled)
/// owners make them invalid, a viewer's token stays read-only whatever its scope.
#[tokio::test]
async fn api_tokens_follow_account_state() {
    let t = T::new();
    let job =
        json!({"kind": "files_list", "tenant": "acme", "params": {"source": "vm-100", "time": 1000, "path": "/"}});
    let vic = t.token("vic", "operator");
    assert_eq!(
        t.bearer(Method::GET, "/api/v1/snapshots", &vic, None).await,
        StatusCode::OK
    );
    assert_eq!(
        t.bearer(Method::POST, "/api/v1/jobs", &vic, Some(job.clone())).await,
        StatusCode::FORBIDDEN,
        "viewer token stays read-only"
    );
    let s = t.login("vic").await;
    let r = t
        .post(
            "/api/v1/auth/tokens",
            &s,
            json!({"name": "x", "scope": "operator", "days": 1, "current_password": PW, "current_totp": t.code("vic")}),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    let otto = t.token("otto", "operator");
    assert_eq!(
        t.bearer(Method::POST, "/api/v1/jobs", &otto, Some(job)).await,
        StatusCode::ACCEPTED
    );
    let id = t.ids["otto"];
    t.exec(&format!("UPDATE users SET expires = 1 WHERE id = {id}"));
    assert_eq!(
        t.bearer(Method::GET, "/api/v1/snapshots", &otto, None).await,
        StatusCode::UNAUTHORIZED,
        "expired owner"
    );
    t.exec(&format!(
        "UPDATE users SET expires = NULL, disabled = 1 WHERE id = {id}"
    ));
    assert_eq!(
        t.bearer(Method::GET, "/api/v1/snapshots", &otto, None).await,
        StatusCode::UNAUTHORIZED,
        "disabled (or dormant-disabled) owner"
    );
}

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use catalog::rusqlite::params;
use catalog::secret::TotpKey;
use catalog::Catalog;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
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

#[derive(Clone)]
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
        st.cat
            .conn()
            .execute_batch(
                r#"INSERT INTO tenants (name) VALUES ('acme'), ('globex');
                   INSERT INTO sources (id, tenant, kind, name, config) VALUES (1, 'acme', 'pve', 'pve-a', '{}'),
                     (2, 'globex', 'pve', 'pve-g', '{}');
                   INSERT INTO snapshots (tenant, source, time, size, local, offsite) VALUES
                     ('acme', 'vm-100', 1000, 5, 1, 0), ('globex', 'vm-200', 1000, 5, 1, 0);
                   INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES
                     ('backup', 'acme', '{}', 'ok', 'x', 1), ('backup', 'globex', '{}', 'ok', 'x', 1);"#,
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
            ("vic", "viewer", None),
            ("vera", "viewer", Some("acme")),
        ] {
            t.add_user(n, role, tenant);
        }
        t
    }

    fn add_user(&mut self, name: &str, role: &str, tenant: Option<&str>) {
        let secret = catalog::auth::new_totp_secret();
        let enc = self.st.totp.encrypt(name, &secret).unwrap();
        let c = self.st.cat.conn();
        c.execute(
            "INSERT INTO users (name, password_hash, totp_secret, role, tenant, created) VALUES (?1,?2,?3,?4,?5,0)",
            params![name, pw_hash(), enc, role, tenant],
        )
        .unwrap();
        self.ids.insert(name.into(), c.last_insert_rowid());
        self.secrets.insert(name.into(), secret);
    }

    async fn send(&self, method: Method, path: &str, s: Option<&S>, body: Option<Value>, ip: &str, ua: &str) -> R {
        let mut b = Request::builder()
            .method(method.clone())
            .uri(path)
            .header(header::USER_AGENT, ua);
        if let Some(s) = s {
            b = b.header(header::COOKIE, format!("nx_session={}", s.cookie));
            if method != Method::GET {
                b = b.header("x-csrf-token", &s.csrf);
            }
        }
        let mut req = match body {
            Some(v) => b
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(v.to_string()))
                .unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(ip.parse().unwrap(), 50000)));
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

    async fn call(&self, method: Method, path: &str, s: Option<&S>, body: Option<Value>) -> R {
        self.send(method, path, s, body, "192.0.2.10", "test-agent").await
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
    async fn delete(&self, path: &str, s: &S) -> R {
        self.call(Method::DELETE, path, Some(s), None).await
    }

    fn code(&self, name: &str) -> String {
        self.exec(&format!("UPDATE users SET totp_last_step = 0 WHERE name = '{name}'"));
        catalog::auth::totp_now(&self.secrets[name]).unwrap()
    }

    async fn try_login_from(&self, name: &str, ip: &str, ua: &str) -> R {
        let body = json!({"name": name, "password": PW, "totp": self.code(name)});
        self.send(Method::POST, "/api/v1/auth/login", None, Some(body), ip, ua)
            .await
    }

    async fn login_from(&self, name: &str, ip: &str, ua: &str) -> S {
        let r = self.try_login_from(name, ip, ua).await;
        assert_eq!(r.status, StatusCode::OK, "{name}: {:?}", r.body);
        S {
            cookie: r.cookie.unwrap(),
            csrf: r.body["csrf"].as_str().unwrap().to_owned(),
        }
    }

    async fn login(&self, name: &str) -> S {
        self.login_from(name, "192.0.2.10", "test-agent").await
    }

    fn reauth(&self, name: &str) -> Value {
        json!({"current_password": PW, "current_totp": self.code(name)})
    }

    fn exec(&self, sql: &str) {
        self.st.cat.conn().execute_batch(sql).unwrap();
    }

    fn one<V: catalog::rusqlite::types::FromSql>(&self, sql: &str) -> V {
        self.st.cat.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }

    async fn approve(&self, r: &R, by: &S) -> R {
        assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
        let q = r.body["quorum_id"].as_i64().unwrap();
        self.post(&format!("/api/v1/quorum/{q}/approve"), by, json!({})).await
    }
}

fn files_get() -> Value {
    json!({"kind": "files_get", "tenant": "acme",
           "params": {"source": "vm-100", "time": 1000, "paths": ["/etc/hosts"], "format": "zip"}})
}

#[tokio::test]
async fn viewer_reads_within_its_scope_and_writes_nothing() {
    let t = T::new();
    let (vic, vera) = (t.login("vic").await, t.login("vera").await);
    for path in ["/api/v1/snapshots", "/api/v1/jobs", "/api/v1/sources"] {
        let all = t.get(path, &vic).await;
        assert_eq!(all.status, StatusCode::OK, "{path}");
        assert_eq!(all.body.as_array().unwrap().len(), 2, "{path}: appliance-wide viewer");
        let own = t.get(path, &vera).await;
        let rows = own.body.as_array().unwrap();
        assert_eq!(rows.len(), 1, "{path}: tenant viewer");
        assert_eq!(rows[0]["tenant"], "acme");
    }
    for (path, s) in [
        ("/api/v1/alerts", &vic),
        ("/api/v1/storage", &vera),
        ("/api/v1/dashboard", &vera),
    ] {
        assert_eq!(t.get(path, s).await.status, StatusCode::OK, "{path}");
    }
    // no job kinds at all, not even listing files
    for kind in ["files_list", "files_get", "backup", "restore"] {
        let r = t
            .post(
                "/api/v1/jobs",
                &vic,
                json!({"kind": kind, "tenant": "acme", "params": {}}),
            )
            .await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{kind}");
    }
    for path in [
        "/api/v1/quorum",
        "/api/v1/audit",
        "/api/v1/settings/approvals",
        "/api/v1/replication/peers",
    ] {
        assert_eq!(t.get(path, &vic).await.status, StatusCode::FORBIDDEN, "{path}");
    }
    let me = t.get("/api/v1/auth/me", &vera).await.body;
    assert_eq!(
        (
            me["user"]["role"].clone(),
            me["user"]["tenant"].clone(),
            me["user"]["can_download"].clone()
        ),
        (json!("viewer"), json!("acme"), json!(false))
    );
    // admins create viewers with or without a tenant; tenant_user and tenant_admin need one
    let alice = t.login("alice").await;
    for (body, ok) in [
        (json!({"name": "v1", "role": "viewer"}), true),
        (json!({"name": "v2", "role": "viewer", "tenant": "globex"}), true),
        (json!({"name": "t1", "role": "tenant_user"}), false),
        (json!({"name": "ta", "role": "tenant_admin", "tenant": "acme"}), true),
        (json!({"name": "ta2", "role": "tenant_admin"}), false),
    ] {
        let r = t.post("/api/v1/users", &alice, body.clone()).await;
        assert_eq!(r.status.is_success(), ok, "{body}: {:?}", r.body);
    }
}

#[tokio::test]
async fn download_privilege_by_role_and_per_user() {
    let t = T::new();
    let alice = t.login("alice").await;
    let users = t.get("/api/v1/users", &alice).await.body;
    let dl = |name: &str| users.as_array().unwrap().iter().find(|u| u["name"] == name).unwrap()["can_download"].clone();
    assert_eq!(
        [dl("alice"), dl("sam"), dl("otto"), dl("tina"), dl("vic")],
        [json!(true), json!(false), json!(true), json!(true), json!(false)]
    );
    let otto = t.login("otto").await;
    assert_eq!(
        t.post("/api/v1/jobs", &otto, files_get()).await.status,
        StatusCode::ACCEPTED
    );
    let id = t.ids["otto"];
    let r = t
        .put(&format!("/api/v1/users/{id}"), &alice, json!({"can_download": false}))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["user"]["can_download"], false);
    // the update ended otto's sessions
    let otto = t.login("otto").await;
    assert_eq!(
        t.post("/api/v1/jobs", &otto, files_get()).await.status,
        StatusCode::FORBIDDEN
    );
    let r = t.get(&format!("/api/v1/downloads/{}", "ab".repeat(32)), &otto).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // listing files is no download
    let r = t
        .post(
            "/api/v1/jobs",
            &otto,
            json!({"kind": "files_list", "tenant": "acme", "params": {"source": "vm-100", "time": 1000, "path": "/"}}),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    // explicit at creation
    let r = t
        .post(
            "/api/v1/users",
            &alice,
            json!({"name": "op2", "role": "operator", "can_download": false}),
        )
        .await;
    assert_eq!(r.body["user"]["can_download"], false, "{:?}", r.body);
    let audit: i64 = t.one("SELECT COUNT(*) FROM audit WHERE action = 'user.update' AND details LIKE '%can_download%'");
    assert_eq!(audit, 1);
}

#[tokio::test]
async fn expired_accounts_cannot_log_in_and_lose_their_sessions() {
    let t = T::new();
    let alice = t.login("alice").await;
    let otto = t.login("otto").await;
    let id = t.ids["otto"];
    let soon = catalog::now() + 3600;
    let r = t
        .put(&format!("/api/v1/users/{id}"), &alice, json!({"expires": soon}))
        .await;
    assert_eq!(r.body["user"]["expires"], soon, "{:?}", r.body);
    assert_eq!(
        t.get("/api/v1/auth/me", &otto).await.status,
        StatusCode::UNAUTHORIZED,
        "updates end sessions"
    );
    let otto = t.login("otto").await;
    t.exec(&format!(
        "UPDATE users SET expires = {} WHERE id = {id}",
        catalog::now() - 1
    ));
    let r = t.get("/api/v1/auth/me", &otto).await;
    assert_eq!(
        (r.status, r.body["error"].clone()),
        (StatusCode::UNAUTHORIZED, json!("account expired"))
    );
    assert_eq!(
        t.one::<i64>(&format!("SELECT COUNT(*) FROM sessions WHERE user_id = {id}")),
        0
    );
    assert_eq!(
        t.try_login_from("otto", "192.0.2.10", "x").await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        t.one::<String>("SELECT json_extract(details, '$.reason') FROM audit WHERE action = 'auth.login_failed' ORDER BY seq DESC LIMIT 1"),
        "expired"
    );
    // cleared again: logs in
    let r = t
        .put(&format!("/api/v1/users/{id}"), &alice, json!({"expires": null}))
        .await;
    assert_eq!(r.body["user"]["expires"], Value::Null);
    t.login("otto").await;
    // the last admin without an expiry date keeps it that way
    let me = t.ids["alice"];
    let r = t
        .put(&format!("/api/v1/users/{me}"), &alice, json!({"expires": soon}))
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
    let r = t
        .put(&format!("/api/v1/users/{id}"), &alice, json!({"expires": "tomorrow"}))
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sessions_are_listed_and_revoked() {
    let t = T::new();
    let a1 = t.login_from("alice", "192.0.2.10", "Firefox/130").await;
    let a2 = t.login_from("alice", "2001:db8::7", "curl/8").await;
    let otto = t.login("otto").await;
    let r = t.get("/api/v1/auth/sessions", &a1).await;
    let list = r.body.as_array().unwrap();
    assert_eq!(list.len(), 2, "own sessions only: {list:?}");
    let current: Vec<&Value> = list.iter().filter(|s| s["current"] == true).collect();
    assert_eq!(
        (current.len(), current[0]["user_agent"].clone()),
        (1, json!("Firefox/130"))
    );
    let other = list.iter().find(|s| s["current"] == false).unwrap();
    assert_eq!(other["ip"], "2001:db8::7");
    assert!(other.get("id_hash").is_none() && other["id"].is_i64());
    // another user's session is not "own"
    let otto_sid: i64 = t.one(&format!("SELECT id FROM sessions WHERE user_id = {}", t.ids["otto"]));
    assert_eq!(
        t.delete(&format!("/api/v1/auth/sessions/{otto_sid}"), &a1).await.status,
        StatusCode::NOT_FOUND
    );
    let r = t.delete(&format!("/api/v1/auth/sessions/{}", other["id"]), &a1).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(t.get("/api/v1/auth/me", &a2).await.status, StatusCode::UNAUTHORIZED);
    // admin: all sessions, one user's, and revoking them
    let all = t.get("/api/v1/sessions", &a1).await.body;
    assert_eq!(all.as_array().unwrap().len(), 2);
    let r = t.get(&format!("/api/v1/sessions?user={}", t.ids["otto"]), &a1).await;
    assert_eq!(r.body[0]["user"], "otto");
    let r = t
        .post(
            &format!("/api/v1/users/{}/sessions/revoke", t.ids["otto"]),
            &a1,
            json!({}),
        )
        .await;
    assert_eq!(r.body["revoked"], 1);
    assert_eq!(t.get("/api/v1/auth/me", &otto).await.status, StatusCode::UNAUTHORIZED);
    // appliance-wide: re-authentication, keeps the caller's own session
    let (_s1, _s2) = (t.login("sam").await, t.login("tina").await);
    let r = t.post("/api/v1/sessions/revoke-all", &a1, json!({})).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = t
        .post(
            "/api/v1/sessions/revoke-all",
            &a1,
            json!({"current_password": "wrong", "current_totp": "000000"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = t.post("/api/v1/sessions/revoke-all", &a1, t.reauth("alice")).await;
    assert_eq!((r.status, r.body["revoked"].clone()), (StatusCode::OK, json!(2)));
    assert_eq!(t.get("/api/v1/auth/me", &a1).await.status, StatusCode::OK);
    for a in ["session.revoke", "session.revoke_user", "session.revoke_all"] {
        assert_eq!(
            t.one::<i64>(&format!("SELECT COUNT(*) FROM audit WHERE action = '{a}'")),
            1,
            "{a}"
        );
    }
    assert!(t.one::<i64>("SELECT last_login FROM users WHERE name = 'alice'") > 0);
}

#[tokio::test]
async fn session_timeouts_tighten_directly_and_loosen_with_approval() {
    let t = T::new();
    let (alice, sam) = (t.login("alice").await, t.login("sam").await);
    for bad in [
        json!({"idle_min": 4, "absolute_h": 12}),
        json!({"idle_min": 30, "absolute_h": 25}),
    ] {
        assert_eq!(
            t.put("/api/v1/settings/session", &alice, bad).await.status,
            StatusCode::BAD_REQUEST
        );
    }
    let r = t
        .put(
            "/api/v1/settings/session",
            &alice,
            json!({"idle_min": 10, "absolute_h": 8}),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "tightening applies at once: {:?}", r.body);
    // idle limit enforced on existing sessions
    let otto = t.login("otto").await;
    t.exec(&format!(
        "UPDATE sessions SET last_seen = {} WHERE user_id = {}",
        catalog::now() - 11 * 60,
        t.ids["otto"]
    ));
    assert_eq!(t.get("/api/v1/auth/me", &otto).await.status, StatusCode::UNAUTHORIZED);
    let r = t
        .put(
            "/api/v1/settings/session",
            &alice,
            json!({"idle_min": 60, "absolute_h": 8}),
        )
        .await;
    let sec = t.get("/api/v1/settings/security", &sam).await.body;
    assert_eq!(sec["session"], json!({"idle_min": 10, "absolute_h": 8}));
    assert!(sec["pending"]["session"].is_i64());
    let r = t.approve(&r, &sam).await;
    assert_eq!(r.body["state"], "executed", "{:?}", r.body);
    let sec = t.get("/api/v1/settings/security", &alice).await.body;
    assert_eq!(sec["session"], json!({"idle_min": 60, "absolute_h": 8}));
    // the cookie lifetime follows the absolute limit
    let r = t.try_login_from("tina", "192.0.2.10", "x").await;
    assert_eq!(r.status, StatusCode::OK);
}

#[tokio::test]
async fn login_banner_is_public_and_validated() {
    let t = T::new();
    let alice = t.login("alice").await;
    let r = t.call(Method::GET, "/api/v1/auth/banner", None, None).await;
    assert_eq!((r.status, r.body["banner"].clone()), (StatusCode::OK, json!("")));
    let text = "Authorised use only.\nActivity is logged.";
    assert_eq!(
        t.put("/api/v1/settings/banner", &alice, json!({"banner": text}))
            .await
            .status,
        StatusCode::OK
    );
    let r = t.call(Method::GET, "/api/v1/auth/banner", None, None).await;
    assert_eq!(r.body["banner"], text);
    for bad in ["x".repeat(2001), "bell\u{7}".into()] {
        let r = t.put("/api/v1/settings/banner", &alice, json!({"banner": bad})).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
    }
    let otto = t.login("otto").await;
    assert_eq!(
        t.put("/api/v1/settings/banner", &otto, json!({"banner": "x"}))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.one::<i64>("SELECT COUNT(*) FROM audit WHERE action = 'security.login_banner'"),
        1
    );
}

#[tokio::test]
async fn management_allow_list_needs_approval_and_protects_the_requester() {
    let t = T::new();
    let (alice, sam) = (t.login("alice").await, t.login("sam").await);
    let url = "/api/v1/settings/mgmt-allow";
    let r = t.put(url, &alice, json!({"mgmt_allow": ["10.0.0.0/33"]})).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // the requester (192.0.2.10) would lock themselves out
    let r = t.put(url, &alice, json!({"mgmt_allow": ["10.0.0.0/8"]})).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
    let r = t
        .put(
            url,
            &alice,
            json!({"mgmt_allow": ["10.0.0.0/8"], "force": true, "confirm": "10.0.0.1"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    let r = t
        .put(
            url,
            &alice,
            json!({"mgmt_allow": ["192.0.2.77/24", "2001:db8::/32", "192.0.2.0/24"]}),
        )
        .await;
    let sec = t.get("/api/v1/settings/security", &alice).await.body;
    assert_eq!(
        (sec["mgmt_allow"].clone(), sec["client_allowed"].clone()),
        (json!([]), json!(true))
    );
    let r = t.approve(&r, &sam).await;
    assert_eq!(r.body["state"], "executed", "{:?}", r.body);
    let sec = t.get("/api/v1/settings/security", &alice).await.body;
    assert_eq!(sec["mgmt_allow"], json!(["192.0.2.0/24", "2001:db8::/32"]));
    assert_eq!(
        (sec["client_ip"].clone(), sec["client_allowed"].clone()),
        (json!("192.0.2.10"), json!(true))
    );
    // opening it again also needs approval; a stale request is refused
    let open = t.put(url, &alice, json!({"mgmt_allow": []})).await;
    let forced = t
        .put(
            url,
            &alice,
            json!({"mgmt_allow": ["10.0.0.0/8"], "force": true, "confirm": "192.0.2.10"}),
        )
        .await;
    assert_eq!(t.approve(&forced, &sam).await.body["state"], "executed");
    assert_eq!(t.approve(&open, &sam).await.status, StatusCode::CONFLICT);
    let otto = t.login("otto").await;
    assert_eq!(
        t.put(url, &otto, json!({"mgmt_allow": []})).await.status,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn dormant_setting_and_approver_warning() {
    let mut t = T::new();
    let alice = t.login("alice").await;
    for (days, ok) in [(10, false), (90, true), (0, true), (4000, false)] {
        let r = t.put("/api/v1/settings/dormant", &alice, json!({"days": days})).await;
        assert_eq!(r.status.is_success(), ok, "{days}");
    }
    // approvals on (fresh catalog), two possible approvers (alice, sam): warning
    let v = t.get("/api/v1/settings/approvals", &alice).await.body;
    assert_eq!(
        (v["possible_approvers"].clone(), v["few_approvers"].clone()),
        (json!(2), json!(true))
    );
    t.add_user("sue", "security_officer", None);
    let v = t.get("/api/v1/settings/approvals", &alice).await.body;
    assert_eq!(v["few_approvers"], false);
    // an expired approver does not count
    t.exec(&format!("UPDATE users SET expires = 1 WHERE id = {}", t.ids["sue"]));
    let v = t.get("/api/v1/settings/approvals", &alice).await.body;
    assert_eq!(
        (v["possible_approvers"].clone(), v["few_approvers"].clone()),
        (json!(2), json!(true))
    );
}

/// Phase 16c: inbound firewall per service. Every change needs approval; the
/// web service is guarded against locking the requester out; the 14d list
/// migrates into `web`; the effective state comes from nexus-nft-sync's status.
#[tokio::test]
async fn inbound_firewall_rules() {
    let t = T::new();
    let (alice, sam, otto) = (t.login("alice").await, t.login("sam").await, t.login("otto").await);
    let status = t._dir.path().join("status.json");
    t.st.nft_status.set(status.clone()).unwrap();
    // the 14d allow-list is web's list
    t.exec(r#"INSERT INTO settings (key, value) VALUES ('mgmt_allow', '["192.0.2.0/24"]')"#);
    let fw = t.get("/api/v1/firewall", &alice).await;
    assert_eq!(fw.status, StatusCode::OK, "{:?}", fw.body);
    let ids: Vec<&str> = fw.body["services"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["web", "icmp", "ssh"]);
    let web = &fw.body["services"][0];
    assert_eq!(
        (web["allow"].clone(), web["enabled"].clone()),
        (json!(["192.0.2.0/24"]), json!(true))
    );
    assert_eq!(fw.body["services"][2]["available"], false);
    assert_eq!(
        (fw.body["status_stale"].clone(), fw.body["outbound"].clone()),
        (json!(true), Value::Null)
    );
    assert_eq!(fw.body["client_allowed"], true);
    // effective state + blocked attempts from the status file
    let now = catalog::now();
    let st = json!({"ts": now, "sets": {"in_web_v4": ["192.0.2.0/24"], "in_web_v6": [], "in_icmp_v4": [],
        "in_icmp_v6": [], "allowed_out_v4": ["10.0.2.2 . tcp . 8006"], "allowed_out_v6": [],
        "dns_servers_v4": ["10.0.2.3"]},
        "drops": [{"src": "198.51.100.9", "proto": "tcp", "port": 22, "last_seen": now, "packets": 4}]});
    std::fs::write(&status, st.to_string()).unwrap();
    let fw = t.get("/api/v1/firewall", &sam).await.body;
    assert_eq!(
        fw["services"][0]["effective"],
        json!({"v4": ["192.0.2.0/24"], "v6": []})
    );
    assert_eq!(fw["services"][2]["effective"], Value::Null);
    assert_eq!(fw["outbound"]["endpoints"], json!(["10.0.2.2 . tcp . 8006"]));
    assert_eq!(fw["outbound"]["dns"], json!(["10.0.2.3"]));
    assert_eq!(fw["drops"][0]["port"], 22);
    assert_eq!(fw["status_stale"], false);
    // validation
    let url = |s: &str| format!("/api/v1/firewall/inbound/{s}");
    let lockout = json!({"allow": ["10.0.0.0/8"], "force": true, "confirm": "10.0.0.1"});
    for (svc, body, code) in [
        ("ssh", json!({"allow": []}), StatusCode::CONFLICT),
        ("telnet", json!({"allow": []}), StatusCode::NOT_FOUND),
        ("web", json!({"allow": [], "enabled": false}), StatusCode::BAD_REQUEST),
        ("icmp", json!({"allow": ["10.0.0.0/33"]}), StatusCode::BAD_REQUEST),
        ("web", json!({"allow": ["10.0.0.0/8"]}), StatusCode::CONFLICT),
        ("web", lockout, StatusCode::CONFLICT),
    ] {
        let r = t.put(&url(svc), &alice, body.clone()).await;
        assert_eq!(r.status, code, "{svc} {body}: {:?}", r.body);
    }
    let r = t.put(&url("icmp"), &alice, json!({"allow": [], "x": 1})).await;
    assert!(r.status.is_client_error(), "unknown field");
    let many: Vec<String> = (0..65).map(|n| format!("10.0.{n}.0/24")).collect();
    assert_eq!(
        t.put(&url("icmp"), &alice, json!({"allow": many})).await.status,
        StatusCode::BAD_REQUEST
    );
    // RBAC: admins change, security officers read, operators neither
    for s in [&sam, &otto] {
        let r = t.put(&url("icmp"), s, json!({"allow": []})).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN);
    }
    assert_eq!(t.get("/api/v1/firewall", &otto).await.status, StatusCode::FORBIDDEN);
    // ping: no lock-out guard; duplicates collapse; approval
    let body = json!({"allow": ["198.51.100.7/24", "198.51.100.0/24"], "enabled": true});
    let r = t.put(&url("icmp"), &alice, body).await;
    let q = r.body["quorum_id"].clone();
    let fw = t.get("/api/v1/firewall", &alice).await.body;
    assert_eq!(fw["services"][1]["pending"], q);
    assert_eq!(t.approve(&r, &sam).await.body["state"], "executed");
    let fw = t.get("/api/v1/firewall", &alice).await.body;
    let icmp = &fw["services"][1];
    assert_eq!(
        (icmp["allow"].clone(), icmp["enabled"].clone()),
        (json!(["198.51.100.0/24"]), json!(true))
    );
    // web: the requester's address keeps it; typed override; a stale request is refused
    let keep = t
        .put(&url("web"), &alice, json!({"allow": ["192.0.2.10", "10.0.0.0/8"]}))
        .await;
    let forced_body = json!({"allow": ["10.0.0.0/8"], "force": true, "confirm": "192.0.2.10"});
    let forced = t.put(&url("web"), &alice, forced_body.clone()).await;
    assert_eq!(t.approve(&forced, &sam).await.body["state"], "executed");
    assert_eq!(t.approve(&keep, &sam).await.status, StatusCode::CONFLICT);
    let fw = t.get("/api/v1/firewall", &alice).await.body;
    assert_eq!(
        (fw["services"][0]["allow"].clone(), fw["client_allowed"].clone()),
        (json!(["10.0.0.0/8"]), json!(false))
    );
    // the 14d setting mirrors web; the change is in the audit chain
    assert_eq!(
        t.one::<String>("SELECT value FROM settings WHERE key = 'mgmt_allow'"),
        r#"["10.0.0.0/8"]"#
    );
    assert!(
        t.one::<i64>(
            "SELECT COUNT(*) FROM audit WHERE action = 'quorum.request' AND details LIKE '%firewall.inbound%'"
        ) >= 3
    );
    // unchanged: nothing to approve
    let r = t.put(&url("web"), &alice, forced_body).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
}
