//! In-process integration tests: the axum Router is driven with
//! `tower::ServiceExt::oneshot` (no TLS, no sockets).

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use axum::Router;
use catalog::rusqlite::params;
use catalog::secret::{source_owner, tenant_owner, SchedulerKey, TotpKey};
use catalog::Catalog;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use tower::ServiceExt;
use web_api::{AppState, CSP};

const PW: &str = "correct horse battery";
const METRICS_TOKEN: &str = "metrics-secret-token";

fn pw_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| catalog::auth::hash_password(PW).unwrap())
}

struct T {
    app: Router,
    st: Arc<AppState>,
    secrets: HashMap<String, String>,
    ids: HashMap<String, i64>,
    /// the scheduler's private key (opens what the web-api sealed)
    sk: SchedulerKey,
    secrets_pub: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

#[derive(Clone)]
struct S {
    cookie: String,
    csrf: String,
}

#[derive(Debug)]
struct R {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
    raw: Vec<u8>,
}

impl T {
    fn new() -> T {
        let dir = tempfile::tempdir().unwrap();
        let cat = Catalog::open(&dir.path().join("catalog.db")).unwrap();
        for t in ["acme", "globex"] {
            cat.conn()
                .execute("INSERT INTO tenants (name) VALUES (?1)", [t])
                .unwrap();
        }
        let downloads = dir.path().join("downloads");
        std::fs::create_dir(&downloads).unwrap();
        let sk = SchedulerKey::generate();
        let secrets_pub = dir.path().join("secrets.pub");
        sk.write_public(&secrets_pub, None).unwrap();
        let st = AppState::with_keys(
            cat,
            Some(METRICS_TOKEN.into()),
            downloads,
            TotpKey::generate(),
            Some(secrets_pub.clone()),
        );
        let mut t = T {
            app: web_api::router(st.clone()),
            st,
            secrets: HashMap::new(),
            ids: HashMap::new(),
            sk,
            secrets_pub,
            _dir: dir,
        };
        for (n, role, tenant) in [
            ("alice", "admin", None),
            ("sam", "security_officer", None),
            ("sue", "security_officer", None),
            ("otto", "operator", None),
            ("tina", "tenant_user", Some("acme")),
            ("tom", "tenant_user", Some("globex")),
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

    async fn send(&self, req: Request<Body>) -> R {
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let raw = res.into_body().collect().await.unwrap().to_bytes().to_vec();
        let body = serde_json::from_slice(&raw).unwrap_or(Value::Null);
        R {
            status,
            headers,
            body,
            raw,
        }
    }

    fn req(method: Method, path: &str, s: Option<&S>, body: Option<&Value>) -> Request<Body> {
        let mut b = Request::builder().method(method.clone()).uri(path);
        if let Some(s) = s {
            b = b.header(header::COOKIE, format!("nx_session={}", s.cookie));
            if method != Method::GET {
                b = b.header("x-csrf-token", &s.csrf);
            }
        }
        match body {
            Some(v) => b
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(v.to_string()))
                .unwrap(),
            None => b.body(Body::empty()).unwrap(),
        }
    }

    async fn call(&self, method: Method, path: &str, s: Option<&S>, body: Option<Value>) -> R {
        self.send(Self::req(method, path, s, body.as_ref())).await
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

    async fn try_login(&self, name: &str, totp: &str, ip: Option<&str>) -> R {
        let mut req = Self::req(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(&json!({"name": name, "password": PW, "totp": totp})),
        );
        if let Some(ip) = ip {
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::new(ip.parse().unwrap(), 50000)));
        }
        self.send(req).await
    }

    /// Current code; forgets the last accepted step first so tests can log in
    /// repeatedly within one 30 s window (simulates the clock moving on).
    fn code(&self, name: &str) -> String {
        self.st
            .cat
            .conn()
            .execute("UPDATE users SET totp_last_step = 0 WHERE name = ?1", [name])
            .unwrap();
        catalog::auth::totp_now(&self.secrets[name]).unwrap()
    }

    /// `body` plus the re-authentication fields of `name` (fresh code).
    fn reauth(&self, name: &str, mut body: Value) -> Value {
        body["current_password"] = json!(PW);
        body["current_totp"] = json!(self.code(name));
        body
    }

    async fn login(&self, name: &str) -> S {
        let r = self.try_login(name, &self.code(name), None).await;
        assert_eq!(r.status, StatusCode::OK, "{name}: {:?}", r.body);
        let sc = r.headers[header::SET_COOKIE].to_str().unwrap().to_owned();
        let cookie = sc
            .strip_prefix("nx_session=")
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        S {
            cookie,
            csrf: r.body["csrf"].as_str().unwrap().to_owned(),
        }
    }

    /// Unauthenticated POST (activation), optionally from a given client IP.
    async fn anon_post(&self, path: &str, body: Value, ip: Option<&str>) -> R {
        let mut req = Self::req(Method::POST, path, None, Some(&body));
        if let Some(ip) = ip {
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::new(ip.parse().unwrap(), 50000)));
        }
        self.send(req).await
    }

    /// Self-enrollment as the person would do it: code → own authenticator →
    /// own password (`PW`). Afterwards `login(name)` works.
    async fn activate(&mut self, name: &str, code: &str, ip: Option<&str>) {
        let r = self
            .anon_post("/api/v1/auth/activate/begin", json!({"name": name, "code": code}), ip)
            .await;
        assert_eq!(r.status, StatusCode::OK, "begin {name}: {:?}", r.body);
        let secret = r.body["totp_secret"].as_str().unwrap().to_owned();
        assert!(r.body["totp_uri"]
            .as_str()
            .unwrap()
            .starts_with(&format!("otpauth://totp/NexusBackup:{name}?")));
        let r = self
            .anon_post(
                "/api/v1/auth/activate/complete",
                json!({"name": name, "code": code, "password": PW,
                       "totp": catalog::auth::totp_now(&secret).unwrap()}),
                ip,
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "complete {name}: {:?}", r.body);
        self.secrets.insert(name.into(), secret);
        if let Ok(id) = self
            .st
            .cat
            .conn()
            .query_row("SELECT id FROM users WHERE name = ?1", [name], |r| r.get(0))
        {
            self.ids.insert(name.into(), id);
        }
    }

    fn set_approvals(&self, on: bool) {
        catalog::set_setting(
            &self.st.cat.conn(),
            "approvals_enabled",
            if on { "true" } else { "false" },
        )
        .unwrap();
    }

    fn audit_actions(&self) -> Vec<String> {
        let c = self.st.cat.conn();
        let mut s = c.prepare("SELECT action FROM audit ORDER BY seq").unwrap();
        s.query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn scalar<V: catalog::rusqlite::types::FromSql>(&self, sql: &str) -> V {
        self.st.cat.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }

    /// Every test ends with an intact audit chain.
    fn finish(self) {
        let n = self.st.cat.verify_audit().expect("audit chain verifies");
        assert!(n > 0);
    }
}

fn wrong_code(c: &str) -> String {
    format!("{:06}", (c.parse::<u32>().unwrap() + 500_000) % 1_000_000)
}

fn src_cfg(secret: Option<&str>) -> Value {
    let mut v = json!({
        "host": "pve1.lab.local", "port": 8006,
        "ca_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        "token_id": "nexus@pve!backup",
        "nodes": {"pve1": {"host": "10.0.0.1", "port": 22, "key": "/etc/nexus/ssh/id", "known_hosts": "/etc/nexus/ssh/kh"}},
        "storage": "local-lvm"
    });
    if let Some(s) = secret {
        v["token_secret"] = json!(s);
    }
    v
}

fn policy(daily: u32, offsite: bool) -> Value {
    json!({"name": "std", "schedule": "daily 01:30",
           "gfs": {"daily": daily, "weekly": 4, "monthly": 12, "yearly": 1}, "offsite": offsite})
}

/// tenant acme + globex each with one source, a policy, a group, a snapshot and a job.
async fn seed(t: &T, admin: &S) -> HashMap<&'static str, i64> {
    let mut ids = HashMap::new();
    let p = t.post("/api/v1/policies", admin, policy(7, true)).await;
    assert_eq!(p.status, StatusCode::CREATED, "{:?}", p.body);
    ids.insert("policy", p.body["id"].as_i64().unwrap());
    for (tenant, key_s, key_g) in [("acme", "src_acme", "grp_acme"), ("globex", "src_globex", "grp_globex")] {
        let s = t
            .post(
                "/api/v1/sources",
                admin,
                json!({"tenant": tenant, "kind": "pve", "name": "pve", "config": src_cfg(Some("s3cr3t-token"))}),
            )
            .await;
        assert_eq!(s.status, StatusCode::CREATED, "{:?}", s.body);
        let sid = s.body["id"].as_i64().unwrap();
        ids.insert(key_s, sid);
        let g = t
            .post(
                "/api/v1/groups",
                admin,
                json!({"tenant": tenant, "source_id": sid, "policy_id": ids["policy"], "name": "prod", "guests": [101, 100, 101]}),
            )
            .await;
        assert_eq!(g.status, StatusCode::CREATED, "{:?}", g.body);
        assert_eq!(g.body["guests"], json!([100, 101]));
        ids.insert(key_g, g.body["id"].as_i64().unwrap());
        t.st.cat
            .conn()
            .execute(
                "INSERT INTO snapshots (tenant, source, time, size, local, offsite) VALUES (?1, 'vm-100', 1000, 5, 1, 0)",
                [tenant],
            )
            .unwrap();
    }
    for (tenant, key) in [("acme", "job_acme"), ("globex", "job_globex")] {
        let j = t
            .post(
                "/api/v1/jobs",
                admin,
                json!({"kind": "backup", "tenant": tenant, "params": {"vmid": 100}}),
            )
            .await;
        assert_eq!(j.status, StatusCode::ACCEPTED, "{:?}", j.body);
        ids.insert(key, j.body["id"].as_i64().unwrap());
    }
    ids
}

// ---------------------------------------------------------------- auth

#[tokio::test]
async fn login_with_totp_me_and_logout() {
    let t = T::new();
    let r = t.try_login("alice", &t.code("alice"), None).await;
    assert_eq!(r.status, StatusCode::OK);
    let sc = r.headers[header::SET_COOKIE].to_str().unwrap();
    for flag in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/"] {
        assert!(sc.contains(flag), "{sc}");
    }
    assert_eq!(r.body["user"]["name"], "alice");
    assert_eq!(r.body["user"]["role"], "admin");
    assert!(r.body["user"].get("password_hash").is_none() && r.body["user"].get("totp_secret").is_none());

    let s = t.login("alice").await;
    // the DB only holds the hash of the cookie
    let stored: i64 =
        t.st.cat
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM sessions WHERE id_hash = ?1",
                [web_api::sha256_hex(s.cookie.as_bytes())],
                |r| r.get(0),
            )
            .unwrap();
    assert_eq!(stored, 1);
    let n: i64 =
        t.st.cat
            .conn()
            .query_row("SELECT COUNT(*) FROM sessions WHERE id_hash = ?1", [&s.cookie], |r| {
                r.get(0)
            })
            .unwrap();
    assert_eq!(n, 0);

    let me = t.get("/api/v1/auth/me", &s).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.body["user"]["name"], "alice");
    assert_eq!(me.body["csrf"], json!(s.csrf));

    let out = t.post("/api/v1/auth/logout", &s, json!({})).await;
    assert_eq!(out.status, StatusCode::OK);
    assert_eq!(t.get("/api/v1/auth/me", &s).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        t.call(Method::GET, "/api/v1/auth/me", None, None).await.status,
        StatusCode::UNAUTHORIZED
    );
    let a = t.audit_actions();
    assert!(a.contains(&"auth.login".into()) && a.contains(&"auth.logout".into()));
    t.finish();
}

#[tokio::test]
async fn wrong_totp_wrong_password_unknown_user() {
    let t = T::new();
    let r = t.try_login("alice", &wrong_code(&t.code("alice")), None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.headers.get(header::SET_COOKIE).is_none());
    let r = t
        .call(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({"name": "alice", "password": "wrong password!!", "totp": t.code("alice")})),
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = t.try_login("nobody", "123456", None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(t.audit_actions(), vec!["auth.login_failed"; 3]);
    let reasons: Vec<String> = {
        let c = t.st.cat.conn();
        let mut s = c
            .prepare("SELECT json_extract(details, '$.reason') FROM audit ORDER BY seq")
            .unwrap();
        s.query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert_eq!(reasons, ["totp", "password", "unknown user"]);
    t.finish();
}

#[tokio::test]
async fn lockout_per_user_and_per_ip() {
    let t = T::new();
    // per user: 5 failures from different IPs lock the account
    for i in 0..5 {
        let r = t
            .try_login("otto", &wrong_code(&t.code("otto")), Some(&format!("10.0.0.{}", i + 1)))
            .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    let r = t.try_login("otto", &t.code("otto"), Some("10.9.9.9")).await;
    assert_eq!(
        r.status,
        StatusCode::TOO_MANY_REQUESTS,
        "correct credentials rejected while locked"
    );
    assert!(r.body["error"].is_string());
    // other users from those IPs are unaffected
    assert_eq!(
        t.try_login("alice", &t.code("alice"), Some("10.0.0.1")).await.status,
        StatusCode::OK
    );

    // per IP: 5 failures for different names from one address
    for n in ["a1", "a2", "a3", "a4", "a5"] {
        assert_eq!(
            t.try_login(n, "000000", Some("192.0.2.7")).await.status,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        t.try_login("alice", &t.code("alice"), Some("192.0.2.7")).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        t.try_login("alice", &t.code("alice"), Some("192.0.2.8")).await.status,
        StatusCode::OK
    );

    let lockouts: Vec<String> = {
        let c = t.st.cat.conn();
        let mut s = c
            .prepare("SELECT target FROM audit WHERE action = 'auth.lockout' ORDER BY seq")
            .unwrap();
        s.query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert_eq!(lockouts, ["user/otto", "ip/192.0.2.7"]);
    t.finish();
}

#[tokio::test]
async fn session_idle_and_absolute_expiry() {
    let t = T::new();
    let s = t.login("otto").await;
    let h = web_api::sha256_hex(s.cookie.as_bytes());
    let now = catalog::now();
    t.st.cat
        .conn()
        .execute(
            "UPDATE sessions SET last_seen = ?1 WHERE id_hash = ?2",
            params![now - 31 * 60, h],
        )
        .unwrap();
    assert_eq!(t.get("/api/v1/auth/me", &s).await.status, StatusCode::UNAUTHORIZED);

    let s = t.login("otto").await;
    let h = web_api::sha256_hex(s.cookie.as_bytes());
    t.st.cat
        .conn()
        .execute(
            "UPDATE sessions SET created = ?1 WHERE id_hash = ?2",
            params![now - 12 * 3600 - 1, h],
        )
        .unwrap();
    assert_eq!(t.get("/api/v1/auth/me", &s).await.status, StatusCode::UNAUTHORIZED);

    // disabling a user ends their session
    let s = t.login("otto").await;
    let admin = t.login("alice").await;
    let r = t
        .put(
            &format!("/api/v1/users/{}", t.ids["otto"]),
            &admin,
            json!({"disabled": true}),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(t.get("/api/v1/auth/me", &s).await.status, StatusCode::UNAUTHORIZED);
    t.finish();
}

#[tokio::test]
async fn csrf_required_on_non_get() {
    let t = T::new();
    let s = t.login("alice").await;
    let body = json!({"name": "initech"});
    let mut req = T::req(Method::POST, "/api/v1/tenants", None, Some(&body));
    req.headers_mut()
        .insert(header::COOKIE, format!("nx_session={}", s.cookie).parse().unwrap());
    let r = t.send(req).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert!(r.body["error"].as_str().unwrap().contains("CSRF"));

    let bad = S {
        csrf: "0".repeat(64),
        ..s.clone()
    };
    assert_eq!(
        t.post("/api/v1/tenants", &bad, body.clone()).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.delete("/api/v1/tenants/acme", &bad).await.status,
        StatusCode::FORBIDDEN
    );
    // logout is protected as well
    let mut req = T::req(Method::POST, "/api/v1/auth/logout", None, None);
    req.headers_mut()
        .insert(header::COOKIE, format!("nx_session={}", s.cookie).parse().unwrap());
    assert_eq!(t.send(req).await.status, StatusCode::FORBIDDEN);

    assert_eq!(t.post("/api/v1/tenants", &s, body).await.status, StatusCode::CREATED);
    t.finish();
}

// ---------------------------------------------------------------- RBAC

#[tokio::test]
async fn rbac_denials_per_role() {
    let t = T::new();
    let admin = t.login("alice").await;
    let ids = seed(&t, &admin).await;
    let op = t.login("otto").await;
    let so = t.login("sam").await;
    let tu = t.login("tina").await;
    let forbidden = StatusCode::FORBIDDEN;

    // operator: no config CRUD, no audit, no quorum decisions; runs jobs
    assert_eq!(
        t.post("/api/v1/tenants", &op, json!({"name": "x"})).await.status,
        forbidden
    );
    assert_eq!(t.post("/api/v1/policies", &op, policy(1, true)).await.status, forbidden);
    assert_eq!(
        t.put(
            &format!("/api/v1/groups/{}", ids["grp_acme"]),
            &op,
            json!({"source_id": ids["src_acme"], "policy_id": ids["policy"], "name": "p", "guests": []})
        )
        .await
        .status,
        forbidden
    );
    assert_eq!(t.get("/api/v1/audit", &op).await.status, forbidden);
    assert_eq!(t.get("/api/v1/audit/verify", &op).await.status, forbidden);
    assert_eq!(
        t.post("/api/v1/quorum/1/approve", &op, json!({})).await.status,
        forbidden
    );
    let j = t
        .post(
            "/api/v1/jobs",
            &op,
            json!({"kind": "backup", "tenant": "acme", "params": {"group_id": ids["grp_acme"]}}),
        )
        .await;
    assert_eq!(j.status, StatusCode::ACCEPTED, "{:?}", j.body);
    let cancel = format!("/api/v1/jobs/{}/cancel", j.body["id"]);
    assert_eq!(t.post(&cancel, &tu, json!({})).await.status, forbidden);
    assert_eq!(t.post(&cancel, &so, json!({})).await.status, forbidden);
    assert_eq!(t.post(&cancel, &op, json!({})).await.status, StatusCode::OK);
    assert_eq!(
        t.post(&cancel, &op, json!({})).await.status,
        StatusCode::CONFLICT,
        "queued only"
    );

    // security officer: reads + audit + quorum, but no jobs and no CRUD
    assert_eq!(
        t.post(
            "/api/v1/jobs",
            &so,
            json!({"kind": "backup", "tenant": "acme", "params": {"vmid": 100}})
        )
        .await
        .status,
        forbidden
    );
    assert_eq!(
        t.post(
            "/api/v1/sources",
            &so,
            json!({"tenant": "acme", "kind": "pve", "name": "x", "config": src_cfg(Some("x"))})
        )
        .await
        .status,
        forbidden
    );
    assert_eq!(
        t.post("/api/v1/users", &so, json!({"name": "x", "role": "operator"}))
            .await
            .status,
        forbidden
    );
    assert_eq!(t.get("/api/v1/audit", &so).await.status, StatusCode::OK);
    assert_eq!(t.get("/api/v1/audit/verify", &so).await.body["ok"], json!(true));
    assert_eq!(t.get("/api/v1/sources", &so).await.status, StatusCode::OK);

    // admins are approvers too (plan §2): an unknown request is 404, not 403;
    // operators cannot decide
    assert_eq!(
        t.post("/api/v1/quorum/999/approve", &admin, json!({})).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        t.post("/api/v1/quorum/999/reject", &admin, json!({})).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        t.post("/api/v1/quorum/999/approve", &op, json!({})).await.status,
        forbidden
    );
    assert_eq!(t.get("/api/v1/audit", &admin).await.status, StatusCode::OK);

    // tenant user: no backups, no CRUD, no audit, no quorum
    assert_eq!(
        t.post(
            "/api/v1/jobs",
            &tu,
            json!({"kind": "backup", "tenant": "acme", "params": {"vmid": 100}})
        )
        .await
        .status,
        forbidden
    );
    assert_eq!(
        t.post("/api/v1/jobs", &tu, json!({"kind": "gc", "tenant": "acme"}))
            .await
            .status,
        forbidden
    );
    assert_eq!(t.post("/api/v1/policies", &tu, policy(1, true)).await.status, forbidden);
    assert_eq!(t.get("/api/v1/audit", &tu).await.status, forbidden);
    assert_eq!(t.get("/api/v1/quorum", &tu).await.status, forbidden);
    assert_eq!(t.post("/api/v1/alerts/1/ack", &tu, json!({})).await.status, forbidden);

    // alerts: operator+ may acknowledge
    t.st.cat
        .conn()
        .execute(
            "INSERT INTO alerts (ts, severity, kind, message) VALUES (1, 'warning', 'capacity', 'store > 75 %')",
            [],
        )
        .unwrap();
    assert_eq!(t.get("/api/v1/alerts", &op).await.body.as_array().unwrap().len(), 1);
    assert_eq!(
        t.post("/api/v1/alerts/1/ack", &op, json!({})).await.status,
        StatusCode::OK
    );
    assert_eq!(
        t.post("/api/v1/alerts/1/ack", &so, json!({})).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(t.get("/api/v1/alerts?acked=false", &op).await.body, json!([]));
    t.finish();
}

#[tokio::test]
async fn tenant_user_isolation() {
    let t = T::new();
    let admin = t.login("alice").await;
    let ids = seed(&t, &admin).await;
    let tina = t.login("tina").await;
    t.st.cat
        .conn()
        .execute(
            "INSERT INTO alerts (ts, severity, kind, message) VALUES (1, 'error', 'job', 'globex backup failed')",
            [],
        )
        .unwrap();

    let only_acme = |v: &Value, key: &str| {
        let a = v.as_array().unwrap();
        assert!(!a.is_empty());
        assert!(a.iter().all(|x| x[key] == "acme"), "{v}");
    };
    only_acme(&t.get("/api/v1/sources", &tina).await.body, "tenant");
    only_acme(&t.get("/api/v1/groups", &tina).await.body, "tenant");
    only_acme(&t.get("/api/v1/jobs", &tina).await.body, "tenant");
    assert_eq!(t.get("/api/v1/jobs?tenant=globex", &tina).await.body, json!([]));
    only_acme(&t.get("/api/v1/snapshots", &tina).await.body, "tenant");
    assert_eq!(t.get("/api/v1/snapshots?tenant=globex", &tina).await.body, json!([]));
    only_acme(&t.get("/api/v1/users", &tina).await.body, "tenant");
    let uid = t.scalar::<String>("SELECT uid FROM tenants WHERE name = 'acme'");
    assert_eq!(
        t.get("/api/v1/tenants", &tina).await.body,
        json!([{"name": "acme", "offsite": {}, "quota_bytes": null, "disabled": false, "disabled_at": null,
                 "disabled_by": null, "disabled_reason": null, "uid": uid, "policies": [], "tiers": []}])
    );
    assert_eq!(t.get("/api/v1/alerts", &tina).await.body, json!([]));

    assert_eq!(
        t.get(&format!("/api/v1/jobs/{}", ids["job_globex"]), &tina)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        t.get(&format!("/api/v1/jobs/{}", ids["job_acme"]), &tina).await.status,
        StatusCode::OK
    );

    let restore = |tenant: &str| {
        json!({"kind": "restore", "tenant": tenant,
        "params": {"source": "vm-100", "time": 1000, "node": "pve1", "target": 900, "storage": "local-lvm"}})
    };
    assert_eq!(
        t.post("/api/v1/jobs", &tina, restore("globex")).await.status,
        StatusCode::FORBIDDEN
    );
    let r = t.post("/api/v1/jobs", &tina, restore("acme")).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    // unknown snapshot
    let mut bad = restore("acme");
    bad["params"]["time"] = json!(1001);
    assert_eq!(t.post("/api/v1/jobs", &tina, bad).await.status, StatusCode::NOT_FOUND);
    t.finish();
}

// ---------------------------------------------------------------- quorum

#[tokio::test]
async fn quorum_policy_weakening_and_approval() {
    let t = T::new();
    let admin = t.login("alice").await;
    let sam = t.login("sam").await;
    let sue = t.login("sue").await;
    let p = t.post("/api/v1/policies", &admin, policy(7, true)).await;
    let pid = p.body["id"].as_i64().unwrap();
    let url = format!("/api/v1/policies/{pid}");
    let daily = |t: &T| {
        t.scalar::<i64>(&format!(
            "SELECT json_extract(gfs, '$.daily') FROM policies WHERE id = {pid}"
        ))
    };

    // strengthening applies directly
    let r = t.put(&url, &admin, policy(14, true)).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(daily(&t), 14);
    // a neutral change (schedule) too
    let mut p2 = policy(14, true);
    p2["schedule"] = json!("hourly 15");
    assert_eq!(t.put(&url, &admin, p2).await.status, StatusCode::OK);

    // weakening is gated
    let r = t.put(&url, &admin, policy(3, true)).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let qid = r.body["quorum_id"].as_i64().unwrap();
    assert_eq!(daily(&t), 14, "not applied yet");
    assert_eq!(
        t.put(&url, &admin, policy(14, false)).await.status,
        StatusCode::ACCEPTED,
        "offsite off is weakening"
    );

    let list = t.get("/api/v1/quorum?state=pending", &sam).await.body;
    assert_eq!(list.as_array().unwrap().len(), 2);
    assert_eq!(list[1]["action"], "policy.update");
    assert_eq!(list[1]["requested_by"], "alice");

    let r = t.post(&format!("/api/v1/quorum/{qid}/approve"), &sam, json!({})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["state"], "executed");
    assert_eq!(daily(&t), 3);
    assert_eq!(
        t.post(&format!("/api/v1/quorum/{qid}/approve"), &sue, json!({}))
            .await
            .status,
        StatusCode::CONFLICT
    );

    // reject the offsite one
    let r = t
        .post(&format!("/api/v1/quorum/{}/reject", qid + 1), &sue, json!({}))
        .await;
    assert_eq!(r.body["state"], "rejected");
    assert_eq!(
        t.scalar::<i64>(&format!("SELECT offsite FROM policies WHERE id = {pid}")),
        1
    );

    // the requester cannot approve their own request
    let now = catalog::now();
    t.st.cat.conn().execute(
        "INSERT INTO quorum (action, params, requested_by, created, state) VALUES ('gc', '{\"delete_pct\":35}', 'sam', ?1, 'pending')",
        [now],
    ).unwrap();
    let own = t.scalar::<i64>("SELECT MAX(id) FROM quorum");
    let r = t.post(&format!("/api/v1/quorum/{own}/approve"), &sam, json!({})).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // scheduler actions are only marked approved
    let r = t.post(&format!("/api/v1/quorum/{own}/approve"), &sue, json!({})).await;
    assert_eq!(r.body["state"], "approved");
    assert_eq!(
        t.scalar::<String>(&format!("SELECT decided_by FROM quorum WHERE id = {own}")),
        "sue"
    );

    // expiry after 72 h
    t.st.cat.conn().execute(
        "INSERT INTO quorum (action, params, requested_by, created, state) VALUES ('policy.delete', ?1, 'alice', ?2, 'pending')",
        params![json!({"id": pid}).to_string(), now - 72 * 3600 - 1],
    ).unwrap();
    let old = t.scalar::<i64>("SELECT MAX(id) FROM quorum");
    let r = t.post(&format!("/api/v1/quorum/{old}/approve"), &sue, json!({})).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(
        t.scalar::<String>(&format!("SELECT state FROM quorum WHERE id = {old}")),
        "expired"
    );
    assert_eq!(
        t.scalar::<i64>("SELECT COUNT(*) FROM policies"),
        1,
        "expired delete not executed"
    );

    let a = t.audit_actions();
    for x in [
        "quorum.request",
        "quorum.approve",
        "quorum.reject",
        "quorum.expire",
        "policy.update",
    ] {
        assert!(a.contains(&x.to_string()), "{x}");
    }
    t.finish();
}

#[tokio::test]
async fn quorum_deletes_and_group_policy_swap() {
    let t = T::new();
    let admin = t.login("alice").await;
    let ids = seed(&t, &admin).await;
    let sam = t.login("sam").await;

    // a weaker policy for a group is a weakening; a stronger one is not
    let mut weak = policy(1, false);
    weak["name"] = json!("weak");
    let weak_id = t.post("/api/v1/policies", &admin, weak).await.body["id"]
        .as_i64()
        .unwrap();
    let mut strong = policy(30, true);
    strong["name"] = json!("strong");
    let strong_id = t.post("/api/v1/policies", &admin, strong).await.body["id"]
        .as_i64()
        .unwrap();
    let g = |pid: i64| json!({"source_id": ids["src_acme"], "policy_id": pid, "name": "prod", "guests": [100]});
    let gurl = format!("/api/v1/groups/{}", ids["grp_acme"]);
    assert_eq!(t.put(&gurl, &admin, g(weak_id)).await.status, StatusCode::ACCEPTED);
    assert_eq!(t.put(&gurl, &admin, g(strong_id)).await.status, StatusCode::OK);

    // deleting a referenced source is refused up front
    let surl = format!("/api/v1/sources/{}", ids["src_globex"]);
    assert_eq!(t.delete(&surl, &admin).await.status, StatusCode::CONFLICT);
    // group delete → quorum → approve → gone; then the source
    let r = t.delete(&format!("/api/v1/groups/{}", ids["grp_globex"]), &admin).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    assert_eq!(t.scalar::<i64>("SELECT COUNT(*) FROM groups"), 2);
    let q = r.body["quorum_id"].as_i64().unwrap();
    assert_eq!(
        t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({}))
            .await
            .body["state"],
        "executed"
    );
    assert_eq!(t.scalar::<i64>("SELECT COUNT(*) FROM groups"), 1);
    let r = t.delete(&surl, &admin).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let q = r.body["quorum_id"].as_i64().unwrap();
    assert_eq!(
        t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({}))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(t.scalar::<i64>("SELECT COUNT(*) FROM sources"), 1);

    // tenant with users can't be deleted; an empty one is gated
    assert_eq!(
        t.delete("/api/v1/tenants/acme", &admin).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        t.post("/api/v1/tenants", &admin, json!({"name": "initech"}))
            .await
            .status,
        StatusCode::CREATED
    );
    let r = t.delete("/api/v1/tenants/initech", &admin).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let q = r.body["quorum_id"].as_i64().unwrap();
    assert_eq!(
        t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({}))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        t.scalar::<i64>("SELECT COUNT(*) FROM tenants WHERE name = 'initech'"),
        0
    );
    // policy delete is gated too
    let r = t.delete(&format!("/api/v1/policies/{weak_id}"), &admin).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    t.finish();
}

#[tokio::test]
async fn privileged_user_grants_need_quorum() {
    let mut t = T::new();
    let admin = t.login("alice").await;
    let sam = t.login("sam").await;
    let sue = t.login("sue").await;

    // an operator: no password from the admin, no TOTP secret, a one-time code
    let r = t
        .post("/api/v1/users", &admin, json!({"name": "olga", "role": "operator"}))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert!(r.body.get("totp_uri").is_none());
    let a = &r.body["activation"];
    assert_eq!((a["part"].as_i64(), a["parts"].as_i64()), (Some(1), Some(1)));
    assert_eq!(a["path"], "/#/activate?name=olga");
    assert!(a["expires"].as_i64().unwrap() > catalog::now() + 71 * 3600);
    assert_eq!(r.body["user"]["pending_activation"], json!(true));
    let olga = r.body["user"]["id"].as_i64().unwrap();
    let olga_code = a["code"].as_str().unwrap().to_owned();
    assert_eq!(olga_code.len(), 26, "128 bit base32");
    let stored = t.scalar::<String>(&format!("SELECT activation_hash FROM users WHERE id = {olga}"));
    assert!(!stored.contains(&olga_code), "stored hashed");
    assert_eq!(
        t.post(
            "/api/v1/users",
            &admin,
            json!({"name": "pw", "password": PW, "role": "operator"})
        )
        .await
        .status,
        StatusCode::BAD_REQUEST,
        "the admin cannot set a password"
    );
    assert_eq!(
        t.post("/api/v1/users", &admin, json!({"name": "tu", "role": "tenant_user"}))
            .await
            .status,
        StatusCode::BAD_REQUEST,
        "tenant required"
    );
    // a pending account cannot log in, whatever the admin tries
    assert_eq!(
        t.try_login("olga", "000000", Some("10.1.1.2")).await.status,
        StatusCode::UNAUTHORIZED
    );
    t.activate("olga", &olga_code, Some("10.1.1.3")).await;
    t.login("olga").await;

    // a new admin: created disabled + quorum; the requester gets part 1 only
    let r = t
        .post("/api/v1/users", &admin, json!({"name": "ada", "role": "admin"}))
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    assert_eq!(r.body["user"]["disabled"], json!(true));
    assert_eq!(r.body["activation"]["parts"], 2);
    assert_eq!(r.body["activation"]["expires"], Value::Null);
    let part1 = r.body["activation"]["code"].as_str().unwrap().to_owned();
    let q = r.body["quorum_id"].as_i64().unwrap();
    let begin = |code: String| {
        let t = &t;
        async move {
            t.anon_post(
                "/api/v1/auth/activate/begin",
                json!({"name": "ada", "code": code}),
                Some("10.2.0.1"),
            )
            .await
            .status
        }
    };
    assert_eq!(begin(part1.clone()).await, StatusCode::UNAUTHORIZED, "not approved yet");
    // the requester cannot approve; the quorum list does not reveal the code digest
    assert_eq!(
        t.post(&format!("/api/v1/quorum/{q}/approve"), &admin, json!({}))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let list = String::from_utf8(t.get("/api/v1/quorum?state=pending", &sam).await.raw).unwrap();
    assert!(list.contains("<redacted>"), "{list}");
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let a = &r.body["activation"];
    assert_eq!((a["name"].as_str(), a["part"].as_i64()), (Some("ada"), Some(2)));
    let part2 = a["code"].as_str().unwrap().to_owned();
    // neither half alone activates: not the requesting admin, not the approver
    assert_eq!(begin(part1.clone()).await, StatusCode::UNAUTHORIZED);
    assert_eq!(begin(part2.clone()).await, StatusCode::UNAUTHORIZED);
    t.activate("ada", &format!("{part1} {part2}"), Some("10.2.0.2")).await;
    t.login("ada").await;

    // promoting an operator is gated, demoting/disabling a non-last admin is not
    let r = t
        .put(
            &format!("/api/v1/users/{olga}"),
            &admin,
            json!({"role": "security_officer"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    assert_eq!(
        t.scalar::<String>(&format!("SELECT role FROM users WHERE id = {olga}")),
        "operator"
    );
    let ada = t.ids["ada"];
    assert_eq!(
        t.put(&format!("/api/v1/users/{ada}"), &admin, json!({"disabled": true}))
            .await
            .status,
        StatusCode::OK
    );
    // re-enabling an admin is a grant
    assert_eq!(
        t.put(&format!("/api/v1/users/{ada}"), &admin, json!({"disabled": false}))
            .await
            .status,
        StatusCode::ACCEPTED
    );
    // alice is now the last enabled admin
    assert_eq!(
        t.put(
            &format!("/api/v1/users/{}", t.ids["alice"]),
            &admin,
            json!({"disabled": true})
        )
        .await
        .status,
        StatusCode::ACCEPTED
    );

    // another user's password / authenticator: only by a new activation code
    for body in [json!({"reset_totp": true}), json!({"password": "a brand new password"})] {
        let r = t
            .put(&format!("/api/v1/users/{olga}"), &admin, t.reauth("alice", body))
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    }
    // a security officer's new activation is gated and split; the old
    // credentials keep working until it is approved
    let r = t
        .put(
            &format!("/api/v1/users/{}", t.ids["sam"]),
            &admin,
            t.reauth("alice", json!({"new_activation": true})),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    assert_eq!(r.body["activation"]["parts"], 2);
    let sam1 = r.body["activation"]["code"].as_str().unwrap().to_owned();
    let q = r.body["quorum_id"].as_i64().unwrap();
    t.login("sam").await;
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sue, json!({})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let sam2 = r.body["activation"]["code"].as_str().unwrap().to_owned();
    assert_eq!(
        t.try_login("sam", &t.code("sam"), Some("10.1.1.4")).await.status,
        StatusCode::UNAUTHORIZED,
        "old credentials invalid after approval"
    );
    t.activate("sam", &format!("{sam1}{sam2}"), Some("10.1.1.5")).await;
    t.login("sam").await;

    // a plain operator's new activation is direct: old credentials stop at once
    let r = t
        .put(
            &format!("/api/v1/users/{olga}"),
            &admin,
            t.reauth("alice", json!({"new_activation": true})),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["activation"]["parts"], 1);
    assert_eq!(r.body["user"]["pending_activation"], json!(true));
    assert_eq!(
        t.try_login("olga", &t.code("olga"), Some("10.1.1.6")).await.status,
        StatusCode::UNAUTHORIZED
    );
    // ... and while it waits with a code the admin knows, it cannot be promoted
    let r = t
        .put(&format!("/api/v1/users/{olga}"), &admin, json!({"role": "admin"}))
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);

    let users = t.get("/api/v1/users", &admin).await;
    let raw = String::from_utf8(users.raw).unwrap();
    assert!(
        !raw.contains("password_hash")
            && !raw.contains("totp_secret")
            && !raw.contains("$argon2")
            && !raw.contains("activation_hash"),
        "{raw}"
    );
    t.finish();
}

// ---------------------------------------------------------------- secrets, validation

#[tokio::test]
async fn source_secrets_are_write_only() {
    let t = T::new();
    let admin = t.login("alice").await;
    let r = t
        .post(
            "/api/v1/sources",
            &admin,
            json!({"tenant": "acme", "kind": "pve", "name": "pve", "config": src_cfg(Some("s3cr3t-token"))}),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let id = r.body["id"].as_i64().unwrap();
    assert!(!String::from_utf8_lossy(&r.raw).contains("s3cr3t"));
    assert_eq!(r.body["config"]["token_secret_set"], json!(true));
    let all = t.get("/api/v1/sources", &admin).await;
    assert!(!String::from_utf8_lossy(&all.raw).contains("s3cr3t"));
    assert_eq!(all.body[0]["config"]["token_id"], "nexus@pve!backup");

    // update without a secret keeps the stored one; with one replaces it
    let r = t
        .put(
            &format!("/api/v1/sources/{id}"),
            &admin,
            json!({"name": "pve-main", "config": src_cfg(None)}),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert!(!String::from_utf8_lossy(&r.raw).contains("s3cr3t"));
    // stored sealed to the scheduler; only its private key opens it
    let stored = |t: &T| {
        let raw = t.scalar::<String>(&format!("SELECT config FROM sources WHERE id = {id}"));
        assert!(!raw.contains("s3cr3t") && !raw.contains("n3w-token"), "{raw}");
        let mut v: Value = serde_json::from_str(&raw).unwrap();
        assert!(v["token_secret"].as_str().unwrap().starts_with("sealed:v1:"));
        t.sk.open_all(&source_owner(id), &mut v).unwrap();
        v["token_secret"].as_str().unwrap().to_owned()
    };
    assert_eq!(stored(&t), "s3cr3t-token");
    t.put(
        &format!("/api/v1/sources/{id}"),
        &admin,
        json!({"name": "pve-main", "config": src_cfg(Some("n3w-token"))}),
    )
    .await;
    assert_eq!(stored(&t), "n3w-token");
    // Phase 18: the fleecing space guard is validated and returned
    let guarded = |g: Value| {
        let mut c = src_cfg(None);
        c["fleecing_storage"] = json!("local-lvm");
        c["fleecing_guard"] = g;
        json!({"name": "pve-main", "config": c})
    };
    let r = t
        .put(
            &format!("/api/v1/sources/{id}"),
            &admin,
            guarded(json!({"min_free_pct": 20, "min_free_gib": 50, "cancel_free_pct": 4})),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        r.body["config"]["fleecing_guard"],
        json!({"min_free_pct": 20.0, "min_free_gib": 50.0, "cancel_free_pct": 4.0})
    );
    for bad in [
        json!({"min_free_pct": 95}),
        json!({"min_free_pct": 5, "cancel_free_pct": 10}),
        json!({"cancel_free_pct": 20}),
        json!({"min_free_gib": -1}),
        json!({"interval_secs": 1}),
        json!({"bogus": 1}),
    ] {
        let r = t
            .put(&format!("/api/v1/sources/{id}"), &admin, guarded(bad.clone()))
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}: {:?}", r.body);
    }
    // creating without a secret is refused, so is an inline secret in opaque blobs
    assert_eq!(
        t.post(
            "/api/v1/sources",
            &admin,
            json!({"tenant": "acme", "kind": "pve", "name": "x", "config": src_cfg(None)})
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        t.put(
            "/api/v1/tenants/acme",
            &admin,
            json!({"offsite": {"type": "sftp", "password": "pw"}})
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
    // nor do secrets end up in the audit log or the audit API
    let audit = t.get("/api/v1/audit", &admin).await;
    assert!(!String::from_utf8_lossy(&audit.raw).contains("s3cr3t"));
    t.finish();
}

#[tokio::test]
async fn input_validation() {
    let t = T::new();
    let admin = t.login("alice").await;
    let bad = StatusCode::BAD_REQUEST;
    for sched in ["daily 25:00", "weekly 01:00", "hourly 7", ""] {
        let mut p = policy(7, true);
        p["schedule"] = json!(sched);
        assert_eq!(t.post("/api/v1/policies", &admin, p).await.status, bad, "{sched}");
    }
    let mut p = policy(1001, true);
    assert_eq!(t.post("/api/v1/policies", &admin, p.clone()).await.status, bad);
    p["gfs"]["daily"] = json!(-1);
    assert_eq!(t.post("/api/v1/policies", &admin, p.clone()).await.status, bad);
    p["gfs"]["daily"] = json!(1000);
    p["name"] = json!("../etc");
    assert_eq!(t.post("/api/v1/policies", &admin, p.clone()).await.status, bad);
    p["name"] = json!("ok");
    p["extra"] = json!(1);
    assert_eq!(
        t.post("/api/v1/policies", &admin, p.clone()).await.status,
        bad,
        "unknown fields"
    );
    p.as_object_mut().unwrap().remove("extra");
    assert_eq!(
        t.post("/api/v1/policies", &admin, p.clone()).await.status,
        StatusCode::CREATED
    );
    assert_eq!(
        t.post("/api/v1/policies", &admin, p).await.status,
        StatusCode::CONFLICT,
        "duplicate name"
    );
    assert_eq!(
        t.post("/api/v1/tenants", &admin, json!({"name": "a".repeat(65)}))
            .await
            .status,
        bad
    );
    assert_eq!(
        t.post("/api/v1/tenants", &admin, json!({"name": ".hidden"}))
            .await
            .status,
        bad
    );

    // wrong content type and malformed JSON
    let mut req = T::req(Method::POST, "/api/v1/tenants", Some(&admin), None);
    *req.body_mut() = Body::from("name=x");
    req.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/x-www-form-urlencoded".parse().unwrap(),
    );
    let r = t.send(req).await;
    assert_eq!(r.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(r.body["error"].is_string());
    let mut req = T::req(Method::POST, "/api/v1/tenants", Some(&admin), None);
    *req.body_mut() = Body::from("{");
    req.headers_mut()
        .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    assert_eq!(t.send(req).await.status, bad);

    // jobs: unknown kind, bad params, group of another tenant
    let ids = seed(&t, &admin).await;
    for (kind, params) in [
        ("frobnicate", json!({})),
        ("backup", json!({"vmid": 5})),
        ("backup", json!({"vmid": 100, "group_id": ids["grp_acme"]})),
        ("backup", json!({"group_id": ids["grp_globex"]})),
        (
            "files_get",
            json!({"source": "vm-100", "time": 1000, "paths": ["etc/passwd"], "format": "tar"}),
        ),
        (
            "files_get",
            json!({"source": "vm-100", "time": 1000, "paths": ["/etc"], "format": "rar"}),
        ),
        (
            "files_get",
            json!({"source": "vm-100", "time": 1000, "paths": ["/etc"], "format": "tar", "download_token": "0".repeat(64)}),
        ),
        (
            "restore_ct",
            json!({"source": "vm-100", "time": 1000, "node": "pve1", "target": 900, "storage": "x"}),
        ),
    ] {
        let r = t
            .post(
                "/api/v1/jobs",
                &admin,
                json!({"kind": kind, "tenant": "acme", "params": params}),
            )
            .await;
        assert_eq!(r.status, bad, "{kind} {params}: {:?}", r.body);
    }
    // group with a source of another tenant
    let r = t.post("/api/v1/groups", &admin, json!({"tenant": "acme", "source_id": ids["src_globex"], "policy_id": ids["policy"], "name": "x", "guests": []})).await;
    assert_eq!(r.status, bad);
    let r = t.post("/api/v1/groups", &admin, json!({"tenant": "acme", "source_id": ids["src_acme"], "policy_id": ids["policy"], "name": "x", "guests": [99]})).await;
    assert_eq!(r.status, bad);
    t.finish();
}

// ---------------------------------------------------------------- downloads, metrics, headers, SPA

#[tokio::test]
async fn downloads_only_for_the_requester() {
    let t = T::new();
    let admin = t.login("alice").await;
    seed(&t, &admin).await;
    let tina = t.login("tina").await;
    let r = t
        .post(
            "/api/v1/jobs",
            &tina,
            json!({"kind": "files_get", "tenant": "acme",
        "params": {"source": "vm-100", "time": 1000, "paths": ["/etc/hosts"], "format": "tar"}}),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let token = r.body["download_token"].as_str().unwrap().to_owned();
    let id = r.body["id"].as_i64().unwrap();
    let url = format!("/api/v1/downloads/{token}");
    assert_eq!(
        t.get(&url, &tina).await.status,
        StatusCode::NOT_FOUND,
        "not written yet"
    );
    std::fs::write(t.st.downloads.join(format!("{token}.tar")), b"tar bytes").unwrap();
    let r = t.get(&url, &tina).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.raw, b"tar bytes");
    assert_eq!(r.headers[header::CONTENT_TYPE], "application/x-tar");
    assert!(r.headers[header::CONTENT_DISPOSITION]
        .to_str()
        .unwrap()
        .starts_with("attachment"));
    assert_eq!(t.get(&url, &admin).await.status, StatusCode::NOT_FOUND);
    let tom = t.login("tom").await;
    assert_eq!(t.get(&url, &tom).await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        t.get("/api/v1/downloads/..%2Fcatalog.db", &tina).await.status,
        StatusCode::NOT_FOUND
    );
    assert!(t.audit_actions().contains(&"download.get".into()));
    // the scheduler's structured result is returned with the job
    let job = t.get(&format!("/api/v1/jobs/{id}"), &tina).await;
    assert_eq!(job.body["result"], Value::Null, "NULL until finished");
    t.st.cat
        .conn()
        .execute(
            "UPDATE jobs SET state = 'ok', result = ?1 WHERE id = ?2",
            params![
                json!({"download_token": token, "format": "tar", "entries": 1}).to_string(),
                id
            ],
        )
        .unwrap();
    let job = t.get(&format!("/api/v1/jobs/{id}"), &tina).await;
    assert_eq!(job.body["result"]["entries"], 1);
    assert_eq!(job.body["result"]["download_token"], json!(token));
    t.finish();
}

#[tokio::test]
async fn audit_paging_both_directions() {
    let t = T::new();
    let admin = t.login("alice").await;
    for i in 0..9 {
        t.st.cat.audit("x", "test", &format!("t/{i}"), &json!({})).unwrap();
    }
    let n: i64 = t.scalar("SELECT MAX(seq) FROM audit");
    let seqs = |r: &R| -> Vec<i64> {
        r.body
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["seq"].as_i64().unwrap())
            .collect()
    };
    // forward (default): oldest first after a cursor
    let r = t.get("/api/v1/audit?after=2&limit=3", &admin).await;
    assert_eq!(seqs(&r), [3, 4, 5]);
    // newest first, then page backwards with `before`
    let r = t.get("/api/v1/audit?order=desc&limit=4", &admin).await;
    assert_eq!(seqs(&r), [n, n - 1, n - 2, n - 3]);
    let r = t.get(&format!("/api/v1/audit?before={}&limit=4", n - 3), &admin).await;
    assert_eq!(seqs(&r), [n - 4, n - 5, n - 6, n - 7]);
    let r = t.get("/api/v1/audit?before=3", &admin).await;
    assert_eq!(seqs(&r), [2, 1]);
    assert_eq!(
        t.get("/api/v1/audit?before=3&order=asc", &admin).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        t.get("/api/v1/audit?order=up", &admin).await.status,
        StatusCode::BAD_REQUEST
    );
    t.finish();
}

#[tokio::test]
async fn metrics_with_bearer_token() {
    let t = T::new();
    let admin = t.login("alice").await;
    let ids = seed(&t, &admin).await;
    t.st.cat
        .conn()
        .execute(
            "UPDATE jobs SET state = 'ok', finished = 4242, params = ?1 WHERE id = ?2",
            params![json!({"group_id": ids["grp_acme"]}).to_string(), ids["job_acme"]],
        )
        .unwrap();
    t.try_login("alice", "000000", Some("10.0.0.1")).await;
    let r = t.call(Method::GET, "/metrics", None, None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let mut req = T::req(Method::GET, "/api/v1/metrics", None, None);
    req.headers_mut()
        .insert(header::AUTHORIZATION, "Bearer wrong".parse().unwrap());
    assert_eq!(t.send(req).await.status, StatusCode::UNAUTHORIZED);
    let mut req = T::req(Method::GET, "/metrics", None, None);
    req.headers_mut().insert(
        header::AUTHORIZATION,
        format!("Bearer {METRICS_TOKEN}").parse().unwrap(),
    );
    let r = t.send(req).await;
    assert_eq!(r.status, StatusCode::OK);
    let text = String::from_utf8(r.raw).unwrap();
    for line in [
        "nexus_jobs{state=\"queued\"} 1",
        "nexus_jobs{state=\"ok\"} 1",
        "nexus_snapshots{tenant=\"acme\",location=\"local\"} 1",
        "nexus_snapshots{tenant=\"acme\",location=\"offsite\"} 0",
        "nexus_last_successful_backup_timestamp_seconds{tenant=\"acme\",group=\"prod\"} 4242",
        "nexus_last_successful_backup_timestamp_seconds{tenant=\"globex\",group=\"prod\"} 0",
        "nexus_failed_logins_total 1",
    ] {
        assert!(text.contains(line), "{line}\n{text}");
    }
    assert!(text.contains("nexus_audit_entries "));
    t.finish();
}

fn assert_security_headers(r: &R) {
    assert_eq!(r.headers[header::CONTENT_SECURITY_POLICY], CSP);
    assert_eq!(r.headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(r.headers[header::REFERRER_POLICY], "no-referrer");
    assert_eq!(r.headers[header::STRICT_TRANSPORT_SECURITY], "max-age=31536000");
}

#[tokio::test]
async fn security_headers_and_spa_fallback() {
    let t = T::new();
    assert_eq!(
        CSP,
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    );
    let h = t.call(Method::GET, "/api/v1/health", None, None).await;
    assert_eq!(h.status, StatusCode::OK);
    assert_eq!(h.body, json!({"ok": true}));
    assert_security_headers(&h);
    assert_eq!(h.headers[header::CACHE_CONTROL], "no-store");

    let r = t.call(Method::GET, "/api/v1/nope", None, None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert!(r.body["error"].is_string());
    assert_security_headers(&r);
    let r = t.call(Method::GET, "/api/v1/sources", None, None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_security_headers(&r);
    let r = t.try_login("alice", "123", None).await;
    assert_security_headers(&r);

    for route in ["/", "/jobs/12", "/restore/acme/vm-100"] {
        let r = t.call(Method::GET, route, None, None).await;
        assert_eq!(r.status, StatusCode::OK, "{route}");
        assert!(r.headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/html"));
        assert!(String::from_utf8_lossy(&r.raw).to_lowercase().contains("<html"));
        assert_eq!(r.headers[header::CACHE_CONTROL], "no-cache");
        assert_security_headers(&r);
    }
    let r = t.call(Method::GET, "/assets/missing-abc123.js", None, None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert_security_headers(&r);
    assert_eq!(
        t.call(Method::POST, "/somewhere", None, None).await.status,
        StatusCode::METHOD_NOT_ALLOWED
    );
    // embedded hashed assets (only when web/dist existed at build time)
    for (path, bytes) in web_api::spa::ASSETS.iter().filter(|(p, _)| p.starts_with("assets/")) {
        let r = t.call(Method::GET, &format!("/{path}"), None, None).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(&r.raw[..], *bytes);
        assert_eq!(r.headers[header::CACHE_CONTROL], "public, max-age=31536000, immutable");
        assert_security_headers(&r);
    }
}

#[tokio::test]
async fn totp_code_cannot_be_replayed() {
    let t = T::new();
    let code = t.code("alice");
    assert_eq!(t.try_login("alice", &code, None).await.status, StatusCode::OK);
    // same code again (an observer replaying it) within its window
    let r = t.try_login("alice", &code, None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{:?}", r.body);
    assert!(t.audit_actions().iter().filter(|a| *a == "auth.login_failed").count() == 1);
    t.st.cat.verify_audit().unwrap();
}

// ---------------------------------------------------------------- security review (docs/security-review.md)

/// Every route × every role against the RBAC matrix of docs/control-plane.md:
/// allowed roles never get 401/403, the others always 403, anonymous callers
/// always 401. Every successful non-GET call appends to the audit log.
#[tokio::test]
async fn rbac_matrix_and_audit_completeness() {
    let mut t = T::new();
    let admin = t.login("alice").await;
    let ids = seed(&t, &admin).await;
    t.add_user("rbac-victim", "operator", None);
    t.add_user("vic", "viewer", None);
    t.add_user("vera", "viewer", Some("acme"));
    t.add_user("dana", "tenant_admin", Some("acme"));
    let victim = t.ids["rbac-victim"];
    let (agent, _) = add_agent(&t, &admin).await;
    t.st.cat
        .conn()
        .execute(
            "INSERT INTO snapshots (tenant, source, time, size, local, offsite) VALUES ('acme', ?1, 2000, 5, 1, 0)",
            [format!("host-{agent}")],
        )
        .unwrap();
    let sessions = [
        ('A', t.login("alice").await),
        ('S', t.login("sam").await),
        ('O', t.login("otto").await),
        ('T', t.login("tina").await),
        ('V', t.login("vic").await),
        ('W', t.login("vera").await),
        ('D', t.login("dana").await),
    ];
    t.st.cat
        .conn()
        .execute(
            "INSERT INTO alerts (ts, severity, kind, message) VALUES (1, 'warning', 'capacity', 'x')",
            [],
        )
        .unwrap();
    let alert = t.scalar::<i64>("SELECT MAX(id) FROM alerts");
    // a pending request for the approve/reject rows, made by another admin
    t.add_user("adam", "admin", None);
    let adam = t.login("adam").await;
    let r = t.delete(&format!("/api/v1/groups/{}", ids["grp_globex"]), &adam).await;
    let qid = r.body["quorum_id"].as_i64().unwrap();
    let (src, grp, pol, job) = (ids["src_acme"], ids["grp_acme"], ids["policy"], ids["job_acme"]);
    // V = appliance-wide viewer, W = viewer of tenant acme: read-only
    // D = tenant_admin of acme (Phase 19b; every other route: tenant_admin_routes_classified)
    let all = "ASOTVWD";

    let calls: Vec<(Method, String, Option<Value>, &str)> = vec![
        (Method::GET, "/api/v1/auth/me".into(), None, all),
        (Method::GET, "/api/v1/tenants".into(), None, all),
        (
            Method::POST,
            "/api/v1/tenants".into(),
            Some(json!({"name": "rbac-t"})),
            "A",
        ),
        (
            Method::PUT,
            "/api/v1/tenants/acme".into(),
            Some(json!({"offsite": {}})),
            "A",
        ),
        (Method::DELETE, "/api/v1/tenants/globex".into(), None, "A"),
        (Method::GET, "/api/v1/sources".into(), None, all),
        (
            Method::POST,
            "/api/v1/sources".into(),
            Some(json!({"tenant": "acme", "kind": "pve", "name": "rbac-s", "config": src_cfg(Some("x"))})),
            "AD",
        ),
        (
            Method::PUT,
            format!("/api/v1/sources/{src}"),
            Some(json!({"name": "pve", "config": src_cfg(None)})),
            "AD",
        ),
        (Method::DELETE, format!("/api/v1/sources/{src}"), None, "AD"),
        (Method::GET, "/api/v1/policies".into(), None, all),
        (
            Method::POST,
            "/api/v1/policies".into(),
            Some(
                json!({"name": "rbac-p", "schedule": "daily 02:00", "gfs": {"daily": 1, "weekly": 0, "monthly": 0, "yearly": 0}}),
            ),
            "A",
        ),
        (
            Method::PUT,
            format!("/api/v1/policies/{pol}"),
            Some(policy(8, true)),
            "A",
        ),
        (Method::DELETE, format!("/api/v1/policies/{pol}"), None, "A"),
        (Method::GET, "/api/v1/groups".into(), None, all),
        (
            Method::POST,
            "/api/v1/groups".into(),
            Some(json!({"tenant": "acme", "source_id": src, "policy_id": pol, "name": "rbac-g", "guests": [100]})),
            "AD",
        ),
        (
            Method::PUT,
            format!("/api/v1/groups/{grp}"),
            Some(json!({"source_id": src, "policy_id": pol, "name": "prod", "guests": [100, 101, 102]})),
            "AD",
        ),
        (Method::GET, "/api/v1/users".into(), None, all),
        (
            Method::POST,
            "/api/v1/users".into(),
            Some(json!({"name": "rbac-u", "role": "operator"})),
            "A",
        ),
        (Method::GET, "/api/v1/settings/approvals".into(), None, "ASO"),
        (Method::GET, "/api/v1/gc/pending".into(), None, "ASO"),
        (
            Method::POST,
            "/api/v1/gc/approve-large".into(),
            Some(json!({"tenant": "acme"})),
            "A",
        ),
        (
            Method::PUT,
            format!("/api/v1/users/{victim}"),
            Some(json!({"disabled": false})),
            "A",
        ),
        (Method::GET, "/api/v1/agents".into(), None, all),
        (
            Method::POST,
            "/api/v1/agents".into(),
            Some(json!({"tenant": "acme", "name": "rbac-a", "host": "h"})),
            "AD",
        ),
        (
            Method::POST,
            format!("/api/v1/agents/{agent}/token"),
            Some(json!({})),
            "AD",
        ),
        (
            Method::POST,
            format!("/api/v1/agents/{agent}/enroll"),
            Some(json!({})),
            "AD",
        ),
        (Method::DELETE, format!("/api/v1/agents/{agent}"), None, "AD"),
        (
            Method::POST,
            "/api/v1/agents/bulk".into(),
            Some(json!({"csv": "host,tenant\nrbac-bulk,acme"})),
            "AD",
        ),
        (Method::GET, "/api/v1/fleets".into(), None, "A"),
        (Method::GET, "/api/v1/fleet/candidates".into(), None, all),
        (
            Method::POST,
            "/api/v1/jobs".into(),
            Some(json!({"kind": "agent_update", "tenant": "acme", "params": {"agent_id": agent}})),
            "AD",
        ),
        (
            Method::POST,
            "/api/v1/jobs".into(),
            Some(
                json!({"kind": "restore_files", "tenant": "acme", "params": {"source": format!("host-{agent}"),
                        "time": 2000, "paths": ["/etc"], "target": "/srv", "overwrite": "never", "confirm": "web01"}}),
            ),
            "AOTD",
        ),
        (Method::GET, "/api/v1/snapshots".into(), None, all),
        (Method::GET, "/api/v1/jobs".into(), None, all),
        (Method::GET, format!("/api/v1/jobs/{job}"), None, all),
        (
            Method::POST,
            "/api/v1/jobs".into(),
            Some(json!({"kind": "backup", "tenant": "acme", "params": {"vmid": 100}})),
            "AOD",
        ),
        (
            Method::POST,
            "/api/v1/jobs".into(),
            Some(
                json!({"kind": "files_list", "tenant": "acme", "params": {"source": "vm-100", "time": 1000, "path": "/"}}),
            ),
            "AOTD",
        ),
        (
            Method::POST,
            format!("/api/v1/jobs/{job}/cancel"),
            Some(json!({})),
            "AOD",
        ),
        (
            Method::GET,
            format!("/api/v1/downloads/{}", "ab".repeat(32)),
            None,
            "AOTD",
        ),
        (Method::GET, "/api/v1/storage".into(), None, all),
        (Method::GET, "/api/v1/dashboard".into(), None, all),
        (Method::GET, "/api/v1/auth/sessions".into(), None, all),
        (Method::DELETE, "/api/v1/auth/sessions/999999".into(), None, all),
        (Method::GET, "/api/v1/sessions".into(), None, "A"),
        (Method::DELETE, "/api/v1/sessions/999999".into(), None, "A"),
        (
            Method::POST,
            format!("/api/v1/users/{victim}/sessions/revoke"),
            Some(json!({})),
            "A",
        ),
        (Method::GET, "/api/v1/settings/security".into(), None, "AS"),
        (
            Method::PUT,
            "/api/v1/settings/session".into(),
            Some(json!({"idle_min": 30, "absolute_h": 12})),
            "A",
        ),
        (
            Method::PUT,
            "/api/v1/settings/dormant".into(),
            Some(json!({"days": 0})),
            "A",
        ),
        (
            Method::PUT,
            "/api/v1/settings/banner".into(),
            Some(json!({"banner": "Authorised use only."})),
            "A",
        ),
        (
            Method::PUT,
            "/api/v1/settings/mgmt-allow".into(),
            Some(json!({"mgmt_allow": ["10.0.0.0/8"], "force": true, "confirm": "unknown"})),
            "A",
        ),
        (Method::GET, "/api/v1/firewall".into(), None, "AS"),
        (
            Method::PUT,
            "/api/v1/firewall/inbound/icmp".into(),
            Some(json!({"allow": ["10.0.0.0/8"], "enabled": true})),
            "A",
        ),
        (Method::GET, "/api/v1/quorum".into(), None, "ASOD"),
        (Method::GET, "/api/v1/audit".into(), None, "ASD"),
        (Method::GET, "/api/v1/audit/verify".into(), None, "AS"),
        (Method::GET, "/api/v1/alerts".into(), None, all),
        (
            Method::POST,
            format!("/api/v1/alerts/{alert}/ack"),
            Some(json!({})),
            "ASO",
        ),
        (
            Method::POST,
            format!("/api/v1/quorum/{qid}/reject"),
            Some(json!({})),
            "AS",
        ),
        (
            Method::POST,
            format!("/api/v1/quorum/{qid}/approve"),
            Some(json!({})),
            "AS",
        ),
        (Method::POST, "/api/v1/auth/logout".into(), Some(json!({})), all),
    ];

    for (method, path, body, allowed) in calls {
        // anonymous first, admin last: denied attempts never see the admin's changes
        let r = t.call(method.clone(), &path, None, body.clone()).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "anonymous {method} {path}");
        for (role, s) in sessions.iter().rev() {
            let before = t.scalar::<i64>("SELECT COUNT(*) FROM audit");
            let r = t.call(method.clone(), &path, Some(s), body.clone()).await;
            if allowed.contains(*role) {
                assert!(
                    r.status != StatusCode::FORBIDDEN && r.status != StatusCode::UNAUTHORIZED,
                    "{role} {method} {path}: {} {:?}",
                    r.status,
                    r.body
                );
            } else {
                assert_eq!(r.status, StatusCode::FORBIDDEN, "{role} {method} {path}: {:?}", r.body);
            }
            let after = t.scalar::<i64>("SELECT COUNT(*) FROM audit");
            if method != Method::GET && r.status.is_success() {
                assert!(
                    after > before,
                    "{role} {method} {path} succeeded without an audit entry"
                );
            }
        }
    }
    // health stays public
    assert_eq!(
        t.call(Method::GET, "/api/v1/health", None, None).await.status,
        StatusCode::OK
    );
    t.finish();
}

/// Approving a request whose object changed since it was made would apply a
/// change nobody reviewed (the approver saw the diff against `old`).
#[tokio::test]
async fn quorum_refuses_stale_requests() {
    let t = T::new();
    let admin = t.login("alice").await;
    let sam = t.login("sam").await;
    let pid = t.post("/api/v1/policies", &admin, policy(7, true)).await.body["id"]
        .as_i64()
        .unwrap();
    let url = format!("/api/v1/policies/{pid}");
    // request: daily 7 -> 6 (the approver sees only that)
    let mut weak = policy(6, true);
    weak["gfs"]["yearly"] = json!(1);
    let qid = t.put(&url, &admin, weak).await.body["quorum_id"].as_i64().unwrap();
    // meanwhile a direct (strengthening) change: yearly 1 -> 10
    let mut strong = policy(7, true);
    strong["gfs"]["yearly"] = json!(10);
    assert_eq!(t.put(&url, &admin, strong).await.status, StatusCode::OK);
    // approving would silently drop yearly back to 1
    let r = t.post(&format!("/api/v1/quorum/{qid}/approve"), &sam, json!({})).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
    assert_eq!(
        t.scalar::<i64>(&format!(
            "SELECT json_extract(gfs, '$.yearly') FROM policies WHERE id = {pid}"
        )),
        10
    );
    assert_eq!(
        t.scalar::<String>(&format!("SELECT state FROM quorum WHERE id = {qid}")),
        "pending"
    );
    assert_eq!(
        t.post(&format!("/api/v1/quorum/{qid}/reject"), &sam, json!({}))
            .await
            .status,
        StatusCode::OK
    );
    t.finish();
}

/// Changing or removing an existing offsite target stops or redirects the
/// offsite copy (a weakening outside the policy): quorum. A first setup is direct.
#[tokio::test]
async fn tenant_offsite_change_needs_quorum() {
    let t = T::new();
    let admin = t.login("alice").await;
    let sam = t.login("sam").await;
    let box1 = json!({"remote": "sftp", "host": "u1.your-storagebox.de", "key": "/etc/nexus/ssh/box"});
    let r = t.put("/api/v1/tenants/acme", &admin, json!({"offsite": box1})).await;
    assert_eq!(r.status, StatusCode::OK, "first setup applies directly");
    for new in [
        json!({}),
        json!({"remote": "sftp", "host": "evil.example", "key": "/etc/nexus/ssh/box"}),
    ] {
        let r = t.put("/api/v1/tenants/acme", &admin, json!({"offsite": new})).await;
        assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    }
    let offsite = |t: &T| t.scalar::<String>("SELECT offsite FROM tenants WHERE name = 'acme'");
    assert_eq!(serde_json::from_str::<Value>(&offsite(&t)).unwrap(), box1);
    let q = t.scalar::<i64>("SELECT MAX(id) FROM quorum");
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.body["state"], "executed", "{:?}", r.body);
    assert_eq!(
        serde_json::from_str::<Value>(&offsite(&t)).unwrap()["host"],
        "evil.example"
    );
    // the other pending request is stale now
    let r = t
        .post(&format!("/api/v1/quorum/{}/approve", q - 1), &sam, json!({}))
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    t.finish();
}

/// The write-only PVE token must not follow an endpoint change: otherwise an
/// admin could point the source at a host of their choice and receive it.
#[tokio::test]
async fn source_secret_does_not_follow_a_new_endpoint() {
    let t = T::new();
    let admin = t.login("alice").await;
    let ids = seed(&t, &admin).await;
    let url = format!("/api/v1/sources/{}", ids["src_acme"]);
    let mut moved = src_cfg(None);
    moved["host"] = json!("attacker.example");
    let r = t.put(&url, &admin, json!({"name": "pve", "config": moved})).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    let mut ca = src_cfg(None);
    ca["ca_pem"] = json!("-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n");
    assert_eq!(
        t.put(&url, &admin, json!({"name": "pve", "config": ca})).await.status,
        StatusCode::BAD_REQUEST
    );
    // same endpoint: keeping the secret is fine; new endpoint with a new secret too
    let mut nodes = src_cfg(None);
    nodes["storage"] = json!("other");
    assert_eq!(
        t.put(&url, &admin, json!({"name": "pve", "config": nodes}))
            .await
            .status,
        StatusCode::OK
    );
    moved["token_secret"] = json!("new-secret");
    assert_eq!(
        t.put(&url, &admin, json!({"name": "pve", "config": moved}))
            .await
            .status,
        StatusCode::OK
    );
    t.finish();
}

/// Inline SSH keys in opaque blobs were readable via GET /sources, GET /tenants
/// (tenant users included) and the audit log.
#[tokio::test]
async fn inline_private_keys_are_refused() {
    let t = T::new();
    let admin = t.login("alice").await;
    let mut cfg = src_cfg(Some("x"));
    cfg["nodes"]["pve1"]["key_pem"] = json!("KEY");
    let r = t
        .post(
            "/api/v1/sources",
            &admin,
            json!({"tenant": "acme", "kind": "pve", "name": "a", "config": cfg}),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n";
    let r = t
        .put(
            "/api/v1/tenants/acme",
            &admin,
            json!({"offsite": {"remote": {"identity": pem}}}),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    t.finish();
}

/// Config CRUD and quorum decisions are appliance-wide, so a tenant-scoped
/// admin would write across tenants and could lift its own scope.
#[tokio::test]
async fn privileged_accounts_are_never_tenant_scoped() {
    let mut t = T::new();
    let admin = t.login("alice").await;
    for role in ["admin", "security_officer"] {
        let r = t
            .post(
                "/api/v1/users",
                &admin,
                json!({"name": format!("scoped-{role}"), "role": role, "tenant": "acme"}),
            )
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{role}: {:?}", r.body);
    }
    // promoting a scoped operator keeps the scope -> refused; with the scope cleared -> quorum
    let r = t
        .post(
            "/api/v1/users",
            &admin,
            json!({"name": "scoped-op", "role": "operator", "tenant": "acme"}),
        )
        .await;
    let id = r.body["user"]["id"].as_i64().unwrap();
    t.activate("scoped-op", r.body["activation"]["code"].as_str().unwrap(), None)
        .await;
    let url = format!("/api/v1/users/{id}");
    assert_eq!(
        t.put(&url, &admin, json!({"role": "admin"})).await.status,
        StatusCode::BAD_REQUEST
    );
    let r = t.put(&url, &admin, json!({"role": "admin", "tenant": null})).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = t.get("/api/v1/quorum?state=pending", &admin).await.body;
    assert_eq!(q[0]["params"]["role"], "admin", "the approver sees the resulting role");
    t.finish();
}

// ---------------------------------------------------------------- H-2 / M-5

/// Review H-2: the catalog only ever holds the sealed token; GETs and the
/// audit log never show it; without the scheduler's public key secret writes
/// are refused with 503 instead of storing plaintext.
#[tokio::test]
async fn source_secrets_are_sealed_to_the_scheduler() {
    let t = T::new();
    let admin = t.login("alice").await;
    let ids = seed(&t, &admin).await;
    let rows: Vec<(i64, String)> = {
        let c = t.st.cat.conn();
        let mut q = c.prepare("SELECT id, config FROM sources").unwrap();
        let r = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        r.collect::<Result<_, _>>().unwrap()
    };
    assert_eq!(rows.len(), 2);
    for (id, raw) in &rows {
        assert!(!raw.contains("s3cr3t"), "{raw}");
        let mut v: Value = serde_json::from_str(raw).unwrap();
        assert!(v["token_secret"].as_str().unwrap().starts_with("sealed:v1:"));
        // bound to its source: the other source's id does not open it
        let other = rows.iter().find(|r| r.0 != *id).unwrap().0;
        assert!(t.sk.open_all(&source_owner(other), &mut v.clone()).is_err());
        t.sk.open_all(&source_owner(*id), &mut v).unwrap();
        assert_eq!(v["token_secret"], "s3cr3t-token");
    }
    for path in ["/api/v1/sources", "/api/v1/audit", "/api/v1/tenants"] {
        let raw = String::from_utf8(t.get(path, &admin).await.raw).unwrap();
        assert!(!raw.contains("s3cr3t") && !raw.contains("sealed:v1:"), "{path}: {raw}");
    }

    // no public key published (scheduler never started): 503, nothing written
    std::fs::remove_file(&t.secrets_pub).unwrap();
    let before = t.scalar::<String>("SELECT group_concat(config) FROM sources");
    let r = t
        .post(
            "/api/v1/sources",
            &admin,
            json!({"tenant": "acme", "kind": "pve", "name": "new", "config": src_cfg(Some("x-token"))}),
        )
        .await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE, "{:?}", r.body);
    assert!(r.body["error"].as_str().unwrap().contains("nexus-scheduler"));
    let url = format!("/api/v1/sources/{}", ids["src_acme"]);
    let r = t
        .put(&url, &admin, json!({"name": "pve", "config": src_cfg(Some("x-token"))}))
        .await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE, "{:?}", r.body);
    assert_eq!(t.scalar::<String>("SELECT group_concat(config) FROM sources"), before);
    assert_eq!(t.scalar::<i64>("SELECT COUNT(*) FROM sources"), 2);
    t.finish();
}

/// Review M-5: credential changes (own password / authenticator, another
/// user's new activation code) need the actor's current password and a fresh
/// TOTP code; failures are audited, count toward the login limiter, and a code
/// cannot be used twice.
#[tokio::test]
async fn credential_changes_need_reauthentication() {
    let mut t = T::new();
    t.add_user("olga", "operator", None);
    let admin = t.login("alice").await;
    let url = format!("/api/v1/users/{}", t.ids["olga"]);
    let olga_hash =
        |t: &T| t.scalar::<String>(&format!("SELECT password_hash FROM users WHERE id = {}", t.ids["olga"]));
    let before = olga_hash(&t);

    // missing
    for body in [
        json!({"new_activation": true}),
        json!({"new_activation": true, "current_password": PW}),
        json!({"new_activation": true, "current_totp": "123456"}),
    ] {
        let r = t.put(&url, &admin, body).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
        assert!(r.body["error"].as_str().unwrap().contains("current_password"));
    }
    // wrong password, wrong code
    let mut wrong_pw = t.reauth("alice", json!({"new_activation": true}));
    wrong_pw["current_password"] = json!("not the password");
    assert_eq!(t.put(&url, &admin, wrong_pw).await.status, StatusCode::FORBIDDEN);
    let code = t.code("alice");
    let wrong_totp = json!({"new_activation": true, "current_password": PW, "current_totp": wrong_code(&code)});
    assert_eq!(t.put(&url, &admin, wrong_totp).await.status, StatusCode::FORBIDDEN);
    assert_eq!(olga_hash(&t), before);
    let reasons: Vec<String> = {
        let c = t.st.cat.conn();
        let mut q = c
            .prepare("SELECT json_extract(details, '$.reason') FROM audit WHERE action = 'auth.reauth_failed' AND actor = 'alice' ORDER BY seq")
            .unwrap();
        let r = q.query_map([], |r| r.get(0)).unwrap();
        r.collect::<Result<_, _>>().unwrap()
    };
    assert_eq!(reasons, ["password", "totp"]);

    // correct: applied; the same code a second time is a replay
    let code = t.code("alice");
    let ok = json!({"new_activation": true, "current_password": PW, "current_totp": code});
    let r = t.put(&url, &admin, ok.clone()).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_ne!(olga_hash(&t), before);
    assert!(r.body["activation"]["code"].is_string());
    let r = t.put(&url, &admin, ok).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{:?}", r.body);
    assert_eq!(
        t.scalar::<String>("SELECT json_extract(details, '$.reason') FROM audit WHERE action = 'auth.reauth_failed' ORDER BY seq DESC LIMIT 1"),
        "totp replay"
    );
    // own TOTP reset: new seed stored encrypted, shown to the owner only
    let me = format!("/api/v1/users/{}", t.ids["alice"]);
    let r = t.put(&me, &admin, t.reauth("alice", json!({"reset_totp": true}))).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let seed = t.scalar::<String>(&format!("SELECT totp_secret FROM users WHERE id = {}", t.ids["alice"]));
    assert!(seed.starts_with("enc:v1:"));
    let uri = r.body["totp_uri"].as_str().unwrap();
    let plain = t.st.totp.decrypt("alice", &seed).unwrap().to_string();
    assert!(uri.contains(&format!("secret={plain}")));
    t.secrets.insert("alice".into(), plain);
    let admin = t.login("alice").await;
    // role changes alone need no re-authentication
    assert_eq!(
        t.put(&url, &admin, json!({"disabled": true})).await.status,
        StatusCode::OK
    );

    // own password: re-authenticated, then the own sessions end
    let r = t
        .put(
            &me,
            &admin,
            t.reauth("alice", json!({"password": "another new password"})),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(t.get("/api/v1/auth/me", &admin).await.status, StatusCode::UNAUTHORIZED);

    // failures count toward the login limiter (all test requests share one IP:
    // the 3 failures above + 2 = 5 → lockout)
    t.add_user("adam", "admin", None);
    let admin = t.login("adam").await;
    for _ in 0..2 {
        let mut b = t.reauth("adam", json!({"new_activation": true}));
        b["current_password"] = json!("not the password");
        assert_eq!(t.put(&url, &admin, b).await.status, StatusCode::FORBIDDEN);
    }
    assert!(t.audit_actions().iter().any(|a| a == "auth.lockout"));
    // locked: even correct credentials are refused, for re-auth and login alike
    let r = t
        .put(&url, &admin, t.reauth("adam", json!({"new_activation": true})))
        .await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{:?}", r.body);
    assert_eq!(
        t.try_login("adam", &t.code("adam"), None).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    t.finish();
}

/// TOTP seeds: encrypted with the web-api key (bound to the user name);
/// legacy plaintext seeds keep working and are encrypted by the startup
/// migration (audited), pending quorum params included.
#[tokio::test]
async fn totp_seeds_encrypted_and_legacy_migrated() {
    let mut t = T::new();
    // legacy rows written before the key existed
    let legacy = catalog::auth::new_totp_secret();
    {
        let c = t.st.cat.conn();
        c.execute(
            "INSERT INTO users (name, password_hash, totp_secret, role, created) VALUES ('leg', ?1, ?2, 'operator', 0)",
            params![pw_hash(), legacy],
        )
        .unwrap();
        c.execute(
            "INSERT INTO quorum (action, params, requested_by, created, state) VALUES ('user.update', ?1, 'alice', ?2, 'pending')",
            params![json!({"id": 1, "name": "sam", "totp_secret": legacy}).to_string(), catalog::now()],
        )
        .unwrap();
    }
    t.secrets.insert("leg".into(), legacy.clone());
    t.login("leg").await;

    assert_eq!(web_api::migrate_totp_seeds(&t.st).unwrap(), 2);
    assert_eq!(web_api::migrate_totp_seeds(&t.st).unwrap(), 0, "idempotent");
    assert_eq!(
        t.scalar::<i64>("SELECT COUNT(*) FROM users WHERE totp_secret NOT LIKE 'enc:v1:%'"),
        0
    );
    let q = t.scalar::<String>("SELECT params FROM quorum");
    assert!(!q.contains(&legacy) && q.contains("enc:v1:"));
    let targets: Vec<String> = {
        let c = t.st.cat.conn();
        let mut s = c
            .prepare("SELECT target FROM audit WHERE action = 'secret.migrate' ORDER BY seq")
            .unwrap();
        let r = s.query_map([], |r| r.get(0)).unwrap();
        r.collect::<Result<_, _>>().unwrap()
    };
    assert_eq!(targets, ["user/leg", "quorum/1"]);
    t.login("leg").await;

    // a seed copied to another user does not decrypt for them
    t.st.cat
        .conn()
        .execute(
            "UPDATE users SET totp_secret = (SELECT totp_secret FROM users WHERE name = 'leg') WHERE name = 'otto'",
            [],
        )
        .unwrap();
    t.secrets.insert("otto".into(), legacy);
    assert_eq!(
        t.try_login("otto", &t.code("otto"), Some("10.2.2.2")).await.status,
        StatusCode::UNAUTHORIZED
    );

    // the key file is created only while no seed depends on a lost key
    let d = tempfile::tempdir().unwrap();
    let key = d.path().join("webapi/totp.key");
    assert!(TotpKey::open_or_create(&key, &t.st.cat)
        .err()
        .unwrap()
        .to_string()
        .contains("restore the key file"));
    assert!(!key.exists());
    let empty = Catalog::open_memory().unwrap();
    let (_, created) = TotpKey::open_or_create(&key, &empty).unwrap();
    assert!(created);
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
    assert!(!TotpKey::open_or_create(&key, &t.st.cat).unwrap().1);
    t.finish();
}

// ---------------------------------------------------------------- agents

/// Creates agent `web01` in acme; returns (id, token).
async fn add_agent(t: &T, admin: &S) -> (String, String) {
    let r = t
        .post(
            "/api/v1/agents",
            admin,
            json!({"tenant": "acme", "name": "web01", "host": "web01.lan"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    (
        r.body["id"].as_str().unwrap().to_owned(),
        r.body["token"].as_str().unwrap().to_owned(),
    )
}

#[tokio::test]
async fn agents_tokens_enrollment_and_deletion() {
    let t = T::new();
    let admin = t.login("alice").await;
    let r = t
        .post(
            "/api/v1/agents",
            &admin,
            json!({"tenant": "acme", "name": "web01", "host": "web01.lan"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let id = r.body["id"].as_str().unwrap().to_owned();
    let token = r.body["token"].as_str().unwrap().to_owned();
    assert_eq!(id.len(), 16);
    assert_eq!(token.len(), 26);
    assert_eq!(r.body["port"], 7444);
    // the token is pasted on stdin, never part of the command (ps / shell history)
    assert_eq!(r.body["install_command"], "sudo nexus-agent init --token -");
    assert!(!r.body["install_command"].as_str().unwrap().contains(&token));
    assert!(r.body["enrolled_at"].is_null());

    // the token is shown once: neither the list nor the audit log nor the catalog has it
    for path in ["/api/v1/agents", "/api/v1/audit"] {
        let raw = String::from_utf8(t.get(path, &admin).await.raw).unwrap();
        assert!(
            !raw.contains(&token) && !raw.contains("token_hash") && !raw.contains("sealed:v1:"),
            "{path}"
        );
    }
    let stored = t.scalar::<String>("SELECT token_hash FROM agents");
    assert!(stored.starts_with("sealed:v1:"));
    // sealed to the scheduler, bound to the agent and its endpoint
    let digest =
        t.sk.open(&catalog::secret::agent_token_location(&id, "web01.lan", 7444), &stored)
            .unwrap();
    assert_eq!(*digest, agent_proto::token_digest(&token));
    assert!(t
        .sk
        .open(&catalog::secret::agent_token_location(&id, "evil.lan", 7444), &stored)
        .is_err());

    // validation and scoping
    for bad in [
        json!({"tenant": "acme", "name": "web01", "host": "x"}), // duplicate name
        json!({"tenant": "nope", "name": "a", "host": "x"}),
        json!({"tenant": "acme", "name": ".a", "host": "x"}),
        json!({"tenant": "acme", "name": "a", "host": "x;rm"}),
        json!({"tenant": "acme", "name": "a", "host": "x", "port": 0}),
        json!({"tenant": "acme", "name": "a", "host": "x", "token": "mine"}),
    ] {
        let r = t.post("/api/v1/agents", &admin, bad.clone()).await;
        assert!(
            r.status == StatusCode::BAD_REQUEST || r.status == StatusCode::CONFLICT,
            "{bad}: {:?}",
            r.body
        );
    }
    let tom = t.login("tom").await;
    assert_eq!(t.get("/api/v1/agents", &tom).await.body, json!([]));
    let tina = t.login("tina").await;
    assert_eq!(t.get("/api/v1/agents", &tina).await.body.as_array().unwrap().len(), 1);

    // enrollment job
    let r = t.post(&format!("/api/v1/agents/{id}/enroll"), &admin, json!({})).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let job = r.body["id"].as_i64().unwrap();
    let (kind, params): (String, String) =
        t.st.cat
            .conn()
            .query_row("SELECT kind, params FROM jobs WHERE id = ?1", [job], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
    assert_eq!(
        (kind.as_str(), params),
        ("agent_enroll", json!({"agent_id": id}).to_string())
    );
    // expired token: 409 until a new one is issued
    t.st.cat
        .conn()
        .execute("UPDATE agents SET token_expires = 1", [])
        .unwrap();
    let r = t.post(&format!("/api/v1/agents/{id}/enroll"), &admin, json!({})).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    let r = t.post(&format!("/api/v1/agents/{id}/token"), &admin, json!({})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let token2 = r.body["token"].as_str().unwrap();
    assert_ne!(token2, token);
    assert!(r.body["token_expires"].as_i64().unwrap() > catalog::now());
    let r = t.post(&format!("/api/v1/agents/{id}/enroll"), &admin, json!({})).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    assert_eq!(
        t.post("/api/v1/agents/0000000000000000/enroll", &admin, json!({}))
            .await
            .status,
        StatusCode::NOT_FOUND
    );

    // linux source + group (guest = the agent)
    let p = t.post("/api/v1/policies", &admin, policy(7, true)).await;
    let pol = p.body["id"].as_i64().unwrap();
    let cfg = json!({"agent_id": id, "paths": ["/etc", "/var/lib/postgresql"], "excludes": ["*.tmp"], "hooks": true});
    let s = t
        .post(
            "/api/v1/sources",
            &admin,
            json!({"tenant": "acme", "kind": "linux", "name": "web01", "config": cfg}),
        )
        .await;
    assert_eq!(s.status, StatusCode::CREATED, "{:?}", s.body);
    assert_eq!(s.body["config"]["paths"], json!(["/etc", "/var/lib/postgresql"]));
    let sid = s.body["id"].as_i64().unwrap();
    for bad in [
        json!({"agent_id": id, "paths": []}),
        json!({"agent_id": id, "paths": ["etc"]}),
        json!({"agent_id": id, "paths": ["/etc/../root"]}),
        json!({"agent_id": id, "paths": ["/etc"], "excludes": ["a\nb"]}),
        json!({"agent_id": "0000000000000000", "paths": ["/etc"]}),
        json!({"agent_id": id, "paths": ["/etc"], "token_secret": "x"}),
    ] {
        let r = t
            .post(
                "/api/v1/sources",
                &admin,
                json!({"tenant": "acme", "kind": "linux", "name": "bad", "config": bad}),
            )
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}: {:?}", r.body);
    }
    // an agent of another tenant cannot be used
    let r = t
        .post(
            "/api/v1/sources",
            &admin,
            json!({"tenant": "globex", "kind": "linux", "name": "x", "config": {"agent_id": id, "paths": ["/"]}}),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = t
        .put(
            &format!("/api/v1/sources/{sid}"),
            &admin,
            json!({"name": "web01", "config": {"agent_id": id, "paths": ["/"], "hooks": false}}),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let g = t
        .post(
            "/api/v1/groups",
            &admin,
            json!({"tenant": "acme", "source_id": sid, "policy_id": pol, "name": "hosts", "guests": []}),
        )
        .await;
    assert_eq!(g.status, StatusCode::CREATED, "{:?}", g.body);
    assert_eq!(g.body["guests"], json!([id]));
    for bad in [json!([100]), json!(["fedcba9876543210"])] {
        let r = t
            .post(
                "/api/v1/groups",
                &admin,
                json!({"tenant": "acme", "source_id": sid, "policy_id": pol, "name": "h2", "guests": bad}),
            )
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    }

    // deletion: refused while a source uses the agent, then quorum
    let r = t.delete(&format!("/api/v1/agents/{id}"), &admin).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    t.st.cat
        .conn()
        .execute_batch(&format!("DELETE FROM groups; DELETE FROM sources WHERE id = {sid};"))
        .unwrap();
    let r = t.delete(&format!("/api/v1/agents/{id}"), &admin).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let q = r.body["quorum_id"].as_i64().unwrap();
    assert_eq!(
        t.scalar::<i64>("SELECT COUNT(*) FROM agents"),
        1,
        "not deleted before approval"
    );
    let sam = t.login("sam").await;
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.body["state"], "executed", "{:?}", r.body);
    assert_eq!(t.scalar::<i64>("SELECT COUNT(*) FROM agents"), 0);
    let actions = t.audit_actions();
    for a in [
        "agent.create",
        "agent.token",
        "agent.delete",
        "quorum.approve",
        "source.create",
        "group.create",
    ] {
        assert!(actions.iter().any(|x| x == a), "{a} audited");
    }
    t.finish();
}

#[tokio::test]
async fn agent_jobs_rbac_and_confirmation() {
    let t = T::new();
    let admin = t.login("alice").await;
    let (id, _) = add_agent(&t, &admin).await;
    let src = format!("host-{id}");
    t.st.cat
        .conn()
        .execute(
            "INSERT INTO snapshots (tenant, source, time, size, local, offsite) VALUES ('acme', ?1, 2000, 5, 1, 0)",
            [&src],
        )
        .unwrap();
    let restore = |confirm: &str| {
        json!({"kind": "restore_files", "tenant": "acme", "params": {"source": src, "time": 2000,
               "paths": ["/etc"], "target": "/srv/restore", "overwrite": "never", "confirm": confirm}})
    };
    // the confirm token must be the target agent's name
    let r = t.post("/api/v1/jobs", &admin, restore("yes")).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.body["error"].as_str().unwrap().contains("web01"));
    for (who, want) in [
        ("alice", StatusCode::ACCEPTED),
        ("otto", StatusCode::ACCEPTED),
        ("tina", StatusCode::ACCEPTED),
        ("tom", StatusCode::FORBIDDEN),
        ("sam", StatusCode::FORBIDDEN),
    ] {
        let s = t.login(who).await;
        let r = t.post("/api/v1/jobs", &s, restore("web01")).await;
        assert_eq!(r.status, want, "{who}: {:?}", r.body);
    }
    let p: String = t.scalar("SELECT params FROM jobs WHERE kind = 'restore_files' ORDER BY id LIMIT 1");
    let p: Value = serde_json::from_str(&p).unwrap();
    assert_eq!(p["agent_id"], id, "target agent made explicit");
    for bad in [
        json!({"source": src, "time": 2000, "paths": ["/etc"], "target": "srv", "overwrite": "never", "confirm": "web01"}),
        json!({"source": src, "time": 2000, "paths": ["/etc"], "target": "/srv/../etc", "overwrite": "never", "confirm": "web01"}),
        json!({"source": src, "time": 2000, "paths": ["/etc"], "target": "/srv", "overwrite": "sometimes", "confirm": "web01"}),
        json!({"source": src, "time": 2000, "paths": [], "target": "/srv", "overwrite": "never", "confirm": "web01"}),
        json!({"source": "vm-100", "time": 2000, "paths": ["/"], "target": "/srv", "overwrite": "never", "confirm": "web01"}),
        json!({"source": src, "time": 2000, "paths": ["/"], "target": "/srv", "overwrite": "never", "confirm": "web01",
               "agent_id": "0000000000000000"}),
    ] {
        let r = t
            .post(
                "/api/v1/jobs",
                &admin,
                json!({"kind": "restore_files", "tenant": "acme", "params": bad}),
            )
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    }
    let r = t
        .post(
            "/api/v1/jobs",
            &admin,
            json!({"kind": "restore_files", "tenant": "acme", "params": {"source": src, "time": 1, "paths": ["/"],
                   "target": "/srv", "overwrite": "never", "confirm": "web01"}}),
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "no such snapshot");

    // Phase 15b: NAS share, TrueNAS, VM and CT snapshots onto an agent of the same tenant
    // (agent_id required); never onto an agent of another tenant, never for viewers
    t.st.cat
        .conn()
        .execute_batch(
            "INSERT INTO snapshots (tenant, source, time, size, local, offsite) VALUES
               ('acme','share-3',2000,5,1,0), ('acme','nas-3-tank.data',2000,5,1,0),
               ('acme','vm-100',2000,5,1,0), ('acme','ct-200',2000,5,1,0), ('globex','share-4',2000,5,1,0);
             INSERT INTO agents (id, tenant, name, host, port) VALUES ('fedcba9876543210','globex','gx01','gx.lan',7444);",
        )
        .unwrap();
    let to_host = |source: &str, agent: Option<&str>, confirm: &str| {
        let mut p = json!({"source": source, "time": 2000, "paths": ["/data"], "target": "/srv/r",
                           "overwrite": "if_older", "confirm": confirm});
        if let Some(a) = agent {
            p["agent_id"] = json!(a);
        }
        json!({"kind": "restore_files", "tenant": "acme", "params": p})
    };
    let tina = t.login("tina").await;
    for source in ["share-3", "nas-3-tank.data", "vm-100", "ct-200"] {
        let r = t.post("/api/v1/jobs", &tina, to_host(source, Some(&id), "web01")).await;
        assert_eq!(r.status, StatusCode::ACCEPTED, "{source}: {:?}", r.body);
        let r = t.post("/api/v1/jobs", &admin, to_host(source, None, "web01")).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{source} without agent_id");
        assert!(r.body["error"].as_str().unwrap().contains("agent_id"));
    }
    let r = t
        .post(
            "/api/v1/jobs",
            &admin,
            to_host("share-3", Some("fedcba9876543210"), "gx01"),
        )
        .await;
    assert_eq!(
        r.status,
        StatusCode::BAD_REQUEST,
        "agent of another tenant: {:?}",
        r.body
    );
    let mut x = to_host("share-4", Some(&id), "web01");
    x["tenant"] = json!("globex");
    let r = t.post("/api/v1/jobs", &admin, x).await;
    assert_eq!(
        r.status,
        StatusCode::BAD_REQUEST,
        "acme's agent for a globex snapshot: {:?}",
        r.body
    );
    let r = t
        .post("/api/v1/jobs", &admin, to_host("share-3", Some(&id), "gx01"))
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "confirm = target agent's name");
    let tom = t.login("tom").await;
    let r = t
        .post("/api/v1/jobs", &tom, to_host("share-3", Some(&id), "web01"))
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "tenant user of another tenant");
    // file downloads from host snapshots use the generic file jobs
    let tina = t.login("tina").await;
    let r = t
        .post(
            "/api/v1/jobs",
            &tina,
            json!({"kind": "files_get", "tenant": "acme", "params": {"source": src, "time": 2000,
                   "paths": ["/etc/hostname"], "format": "tar"}}),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    // agent_update / agent_enroll: admin only
    let upd = json!({"kind": "agent_update", "tenant": "acme", "params": {"agent_id": id}});
    for (who, want) in [
        ("otto", StatusCode::FORBIDDEN),
        ("tina", StatusCode::FORBIDDEN),
        ("alice", StatusCode::ACCEPTED),
    ] {
        let s = t.login(who).await;
        let r = t.post("/api/v1/jobs", &s, upd.clone()).await;
        assert_eq!(r.status, want, "{who}");
    }
    let r = t
        .post(
            "/api/v1/jobs",
            &admin,
            json!({"kind": "agent_update", "tenant": "globex", "params": {"agent_id": id}}),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "agent of another tenant");
    // manual backup of one agent
    let otto = t.login("otto").await;
    let r = t
        .post(
            "/api/v1/jobs",
            &otto,
            json!({"kind": "backup", "tenant": "acme", "params": {"agent_id": id}}),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let r = t
        .post(
            "/api/v1/jobs",
            &admin,
            json!({"kind": "backup", "tenant": "acme", "params": {"agent_id": id, "vmid": 100}}),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // agent endpoints: admin only
    assert_eq!(
        t.post(
            "/api/v1/agents",
            &otto,
            json!({"tenant": "acme", "name": "x", "host": "x"})
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    for path in [
        format!("/api/v1/agents/{id}/token"),
        format!("/api/v1/agents/{id}/enroll"),
    ] {
        assert_eq!(t.post(&path, &otto, json!({})).await.status, StatusCode::FORBIDDEN);
    }
    assert_eq!(
        t.delete(&format!("/api/v1/agents/{id}"), &otto).await.status,
        StatusCode::FORBIDDEN
    );
    // a tenant with an agent cannot be deleted
    assert_eq!(
        t.delete("/api/v1/tenants/acme", &admin).await.status,
        StatusCode::CONFLICT
    );
    t.finish();
}

fn truenas_cfg(api_key: Option<&str>, key_pem: Option<&str>) -> Value {
    let mut c = json!({
        "host": "nas.lab", "port": 443, "connect_addr": "192.0.2.20:443",
        "ca_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        "user": "nexusbackup",
        "ssh": {"host": "192.0.2.20", "port": 22, "user": "nexusbackup",
                "host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostKey",
                "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIApplianceKey nexus@appliance",
                "from": "192.0.2.10"},
        "datasets": ["tank/data", "tank/smb"], "recursive": true
    });
    if let Some(k) = api_key {
        c["token_secret"] = json!(k);
    }
    if let Some(k) = key_pem {
        c["ssh"]["key_pem"] = json!(k);
    }
    c
}

/// TrueNAS sources: API key + SSH private key write-only and sealed (bound to
/// their endpoints), authorized_keys line returned, group guests = datasets,
/// `nas-<id>-<dataset>` snapshots accepted by file jobs, validation.
#[tokio::test]
async fn truenas_sources() {
    let t = T::new();
    let admin = t.login("alice").await;
    let key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn\n-----END OPENSSH PRIVATE KEY-----\n";
    let src = |cfg: Value| json!({"tenant": "acme", "kind": "truenas", "name": "nas", "config": cfg});
    for cfg in [truenas_cfg(None, Some(key)), truenas_cfg(Some("1-abc"), None)] {
        let r = t.post("/api/v1/sources", &admin, src(cfg)).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    }
    let r = t
        .post(
            "/api/v1/sources",
            &admin,
            src(truenas_cfg(Some("1-s3cr3tapikey"), Some(key))),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let sid = r.body["id"].as_i64().unwrap();
    let c = &r.body["config"];
    assert_eq!(c["token_secret_set"], true);
    assert_eq!(c["ssh"]["key_pem_set"], true);
    let line = c["authorized_keys"].as_str().unwrap();
    assert!(line.starts_with("restrict,from=\"192.0.2.10\",command=\""), "{line}");
    assert!(line.ends_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIApplianceKey nexus@appliance"));
    assert!(line.contains("A=\\\"tank/data tank/smb\\\""), "{line}");
    let raw = String::from_utf8(t.get("/api/v1/sources", &admin).await.raw).unwrap();
    assert!(
        !raw.contains("s3cr3t") && !raw.contains("PRIVATE KEY") && !raw.contains("sealed:v1:"),
        "{raw}"
    );
    let stored = t.scalar::<String>(&format!("SELECT config FROM sources WHERE id = {sid}"));
    let mut v: Value = serde_json::from_str(&stored).unwrap();
    assert!(v["token_secret"].as_str().unwrap().starts_with("sealed:v1:"));
    assert!(v["ssh"]["key_pem"].as_str().unwrap().starts_with("sealed:v1:"));
    t.sk.open_all(&source_owner(sid), &mut v).unwrap();
    assert_eq!(v["token_secret"], "1-s3cr3tapikey");
    assert_eq!(v["ssh"]["key_pem"], key);

    // update without secrets: kept for the same endpoints, refused when they move
    let url = format!("/api/v1/sources/{sid}");
    let mut cfg = truenas_cfg(None, None);
    cfg["recursive"] = json!(false);
    let r = t.put(&url, &admin, json!({"name": "nas", "config": cfg})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["config"]["token_secret_set"], true);
    assert_eq!(r.body["config"]["ssh"]["key_pem_set"], true);
    let mut moved = truenas_cfg(None, None);
    moved["ssh"]["host"] = json!("203.0.113.9");
    let r = t.put(&url, &admin, json!({"name": "nas", "config": moved})).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.body["error"].as_str().unwrap().contains("ssh.key_pem"));
    let mut moved = truenas_cfg(None, None);
    moved["ca_pem"] = json!("-----BEGIN CERTIFICATE-----\nOTHER\n-----END CERTIFICATE-----\n");
    let r = t.put(&url, &admin, json!({"name": "nas", "config": moved})).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.body["error"].as_str().unwrap().contains("token_secret"));

    // validation
    for (field, val) in [
        ("datasets", json!([])),
        ("datasets", json!(["tank/a b"])),
        ("datasets", json!(["tank/a.b"])),
        ("datasets", json!(["tank/a", "tank/a/b"])),
        ("user", json!("Root!")),
        ("ssh.user", json!("x;id")),
        ("ssh.host_key", json!("not a key")),
        ("ssh.public_key", json!("ssh-ed25519 AAAA\"evil")),
        ("ssh.from", json!("1.2.3.4\",command=\"sh")),
        ("ssh.key_pem", json!("no key")),
        ("connect_addr", json!("nas:443")),
        ("ca_pem", json!("x")),
        ("token_secret", json!("with space")),
        ("unknown", json!(1)),
    ] {
        let mut c = truenas_cfg(Some("1-k"), Some(key));
        match field.split_once('.') {
            Some((a, b)) => c[a][b] = val,
            None => c[field] = val,
        }
        let r = t.post("/api/v1/sources", &admin, src(c)).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{field}: {:?}", r.body);
    }

    // groups: guests are datasets of the source (empty = all: mode `all`, resolved at
    // run time from the inventory instead of frozen at save time, Phase 13c)
    let pol = t.post("/api/v1/policies", &admin, policy(7, false)).await.body["id"]
        .as_i64()
        .unwrap();
    let group = |name: &str, guests: Value| json!({"tenant": "acme", "source_id": sid, "policy_id": pol, "name": name, "guests": guests});
    let g = t.post("/api/v1/groups", &admin, group("nas", json!([]))).await;
    assert_eq!(g.status, StatusCode::CREATED, "{:?}", g.body);
    assert_eq!(
        (g.body["guests"].clone(), g.body["mode"].clone()),
        (json!([]), json!("all"))
    );
    let g = t
        .post("/api/v1/groups", &admin, group("nas2", json!(["tank/smb"])))
        .await;
    assert_eq!(g.status, StatusCode::CREATED);
    let g = t
        .post("/api/v1/groups", &admin, group("nas3", json!(["tank/other"])))
        .await;
    assert_eq!(g.status, StatusCode::BAD_REQUEST);

    // file jobs accept nas-<id>-<dataset> snapshots; restore_files needs a target agent (Phase 15b)
    let snap = format!("nas-{sid}-tank.data");
    t.st.cat
        .conn()
        .execute(
            "INSERT INTO snapshots (tenant, source, time, size, local, offsite) VALUES ('acme', ?1, 1000, 1, 1, 0)",
            [&snap],
        )
        .unwrap();
    let files = |source: &str| json!({"kind": "files_list", "tenant": "acme", "params": {"source": source, "time": 1000, "path": "/"}});
    let r = t.post("/api/v1/jobs", &admin, files(&snap)).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    for bad in ["nas-x-tank", "nas-1-tank..a", "nas-1-"] {
        let r = t.post("/api/v1/jobs", &admin, files(bad)).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let r = t
        .post(
            "/api/v1/jobs",
            &admin,
            json!({"kind": "restore_files", "tenant": "acme", "params": {"source": snap, "time": 1000,
                   "paths": ["/a"], "target": "/r", "overwrite": "never", "confirm": "x"}}),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    t.finish();
}

/// NFS/SMB share sources (docs/nas-connector.md): admin only, SMB password /
/// keytab write-only and sealed (kept on update only for the same server and
/// user), validation of every field the mount helper sees, groups without
/// guests, `share-<id>` snapshots for file jobs.
#[tokio::test]
async fn share_sources() {
    let t = T::new();
    let admin = t.login("alice").await;
    let op = t.login("otto").await;
    let src =
        |kind: &str, cfg: Value| json!({"tenant": "acme", "kind": kind, "name": format!("{kind}1"), "config": cfg});
    let nfs = json!({"host": "nas.lab", "export": "/srv/share", "version": "4.2", "snapshot_dir": ".zfs/snapshot",
                     "snapshot_prefix": "auto-", "excludes": ["*.tmp"], "threads": 8});
    let smb = json!({"host": "fs1.lab", "share": "Data Files", "user": "backup", "domain": "LAB",
                     "password": "s3cr3t,pw=x", "version": "3.1.1", "seal": true});
    assert_eq!(
        t.post("/api/v1/sources", &op, src("nfs", nfs.clone())).await.status,
        StatusCode::FORBIDDEN
    );
    let r = t.post("/api/v1/sources", &admin, src("nfs", nfs.clone())).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let nfs_id = r.body["id"].as_i64().unwrap();
    assert_eq!(r.body["config"]["export"], "/srv/share");
    let r = t.post("/api/v1/sources", &admin, src("smb", smb.clone())).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let sid = r.body["id"].as_i64().unwrap();
    assert_eq!(r.body["config"]["password_set"], true);
    assert!(r.body["config"]["password"].is_null());
    let raw = String::from_utf8(t.get("/api/v1/sources", &admin).await.raw).unwrap();
    assert!(!raw.contains("s3cr3t") && !raw.contains("sealed:v1:"), "{raw}");
    let stored = t.scalar::<String>(&format!("SELECT config FROM sources WHERE id = {sid}"));
    let mut v: Value = serde_json::from_str(&stored).unwrap();
    assert!(v["password"].as_str().unwrap().starts_with("sealed:v1:"));
    t.sk.open_all(&source_owner(sid), &mut v).unwrap();
    assert_eq!(v["password"], "s3cr3t,pw=x");

    // SMB without a secret is refused; update keeps it for the same server and user only
    let mut nopw = smb.clone();
    nopw.as_object_mut().unwrap().remove("password");
    let r = t
        .post(
            "/api/v1/sources",
            &admin,
            json!({"tenant": "acme", "kind": "smb", "name": "x", "config": nopw}),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let url = format!("/api/v1/sources/{sid}");
    let mut upd = nopw.clone();
    upd["seal"] = json!(false);
    let r = t.put(&url, &admin, json!({"name": "smb1", "config": upd})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["config"]["password_set"], true);
    for (k, val) in [
        ("host", json!("evil.lab")),
        ("user", json!("other")),
        ("port", json!(4455)),
    ] {
        let mut m = nopw.clone();
        m[k] = val;
        let r = t.put(&url, &admin, json!({"name": "smb1", "config": m})).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{k}");
        assert!(r.body["error"].as_str().unwrap().contains("password"), "{:?}", r.body);
    }

    // validation (what reaches the mount helper)
    for (kind, field, val) in [
        ("nfs", "export", json!("/srv/share,rw")),
        ("nfs", "export", json!("relative")),
        ("nfs", "export", json!("/srv/../etc")),
        ("nfs", "version", json!("2")),
        ("nfs", "host", json!("nas lab")),
        ("nfs", "host", json!("-o")),
        ("nfs", "share", json!("x")),
        ("nfs", "password", json!("x")),
        ("nfs", "snapshot_dir", json!("../x")),
        ("nfs", "snapshot_dir", json!("/abs")),
        ("nfs", "snapshot_order", json!("random")),
        ("nfs", "threads", json!(0)),
        ("nfs", "timeout_secs", json!(9999)),
        ("nfs", "unknown", json!(1)),
        ("smb", "share", json!("a/b")),
        ("smb", "share", json!("a,b")),
        ("smb", "user", json!("dom\\user")),
        ("smb", "version", json!("1.0")),
        ("smb", "sec", json!("ntlm")),
        ("smb", "domain", json!("a b")),
        ("smb", "export", json!("/x")),
        ("smb", "password", json!("")),
        ("smb", "keytab", json!("AAAA")),
    ] {
        let mut c = if kind == "nfs" { nfs.clone() } else { smb.clone() };
        c[field] = val;
        let r = t
            .post(
                "/api/v1/sources",
                &admin,
                json!({"tenant": "acme", "kind": kind, "name": "v", "config": c}),
            )
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{kind} {field}: {:?}", r.body);
    }
    let mut seal21 = smb.clone();
    seal21["version"] = json!("2.1");
    let r = t
        .post(
            "/api/v1/sources",
            &admin,
            json!({"tenant": "acme", "kind": "smb", "name": "v", "config": seal21}),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "seal needs SMB 3");
    // Kerberos is not offered in v1 (user decision 2026-10-10)
    let mut k = smb.clone();
    k.as_object_mut().unwrap().remove("password");
    k["sec"] = json!("krb5");
    k["keytab"] = json!("BQIAAAA=");
    k["principal"] = json!("backup@LAB.EXAMPLE");
    let r = t
        .post(
            "/api/v1/sources",
            &admin,
            json!({"tenant": "acme", "kind": "smb", "name": "k", "config": k}),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    assert!(r.body["error"].as_str().unwrap().contains("krb5"));

    // groups: no guests
    let pol = t.post("/api/v1/policies", &admin, policy(7, false)).await.body["id"]
        .as_i64()
        .unwrap();
    let group = |name: &str, s: i64, guests: Value| json!({"tenant": "acme", "source_id": s, "policy_id": pol, "name": name, "guests": guests});
    let g = t
        .post("/api/v1/groups", &admin, group("share", nfs_id, json!([])))
        .await;
    assert_eq!(g.status, StatusCode::CREATED, "{:?}", g.body);
    let g = t
        .post("/api/v1/groups", &admin, group("share2", sid, json!([100])))
        .await;
    assert_eq!(g.status, StatusCode::BAD_REQUEST);

    // file jobs on share-<id> snapshots; restore_files needs a target agent (Phase 15b)
    let snap = format!("share-{sid}");
    t.st.cat
        .conn()
        .execute(
            "INSERT INTO snapshots (tenant, source, time, size, local, offsite) VALUES ('acme', ?1, 1000, 1, 1, 0)",
            [&snap],
        )
        .unwrap();
    let files = |source: &str| json!({"kind": "files_list", "tenant": "acme", "params": {"source": source, "time": 1000, "path": "/"}});
    let r = t.post("/api/v1/jobs", &op, files(&snap)).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    for bad in ["share-x", "share-01", "share-"] {
        let r = t.post("/api/v1/jobs", &admin, files(bad)).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let r = t
        .post(
            "/api/v1/jobs",
            &admin,
            json!({"kind": "restore_files", "tenant": "acme", "params": {"source": snap, "time": 1000,
                   "paths": ["/a"], "target": "/r", "overwrite": "never", "confirm": "x"}}),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    t.finish();
}

fn s3_offsite(secret: Option<&str>) -> Value {
    let mut r = json!({"type": "s3", "endpoint": "https://fsn1.your-objectstorage.com", "region": "fsn1",
                       "bucket": "nexus-acme", "prefix": "appliance1", "access_key": "AKIA1",
                       "storage_class_packs": "STANDARD_IA", "lock": true});
    if let Some(s) = secret {
        r["secret_key"] = json!(s);
    }
    json!({"remote": r, "uploaders": 4})
}

/// S3 offsite: strict validation, the secret key is sealed to the scheduler
/// (bound to tenant + endpoint fields), never shown, kept on unchanged
/// endpoints only, and changes go through the quorum like any offsite change.
#[tokio::test]
async fn tenant_s3_offsite_secret_is_sealed_and_bound() {
    let t = T::new();
    let admin = t.login("alice").await;
    let sam = t.login("sam").await;
    let r = t
        .post(
            "/api/v1/tenants",
            &admin,
            json!({"name": "s3t", "offsite": s3_offsite(None)}),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "secret required on create");
    let r = t
        .post(
            "/api/v1/tenants",
            &admin,
            json!({"name": "s3t", "offsite": s3_offsite(Some("s3cr3t/KEY+x"))}),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["offsite"]["remote"]["secret_key_set"], true);
    let stored = || {
        serde_json::from_str::<Value>(&t.scalar::<String>("SELECT offsite FROM tenants WHERE name = 's3t'")).unwrap()
    };
    let mut v = stored();
    assert!(v["remote"]["secret_key"].as_str().unwrap().starts_with("sealed:v1:"));
    assert!(
        t.sk.open_all(&tenant_owner("acme"), &mut v.clone()).is_err(),
        "bound to the tenant"
    );
    t.sk.open_all(&tenant_owner("s3t"), &mut v).unwrap();
    assert_eq!(v["remote"]["secret_key"], "s3cr3t/KEY+x");
    for path in ["/api/v1/tenants", "/api/v1/audit"] {
        let raw = String::from_utf8(t.get(path, &admin).await.raw).unwrap();
        assert!(!raw.contains("s3cr3t") && !raw.contains("sealed:v1:"), "{path}: {raw}");
    }

    // unchanged config (as the UI sends it back, secret omitted): applies directly
    let mut same = s3_offsite(None);
    same["remote"]["secret_key_set"] = json!(true);
    let r = t.put("/api/v1/tenants/s3t", &admin, json!({"offsite": same})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(stored(), {
        let mut x = v.clone();
        x["remote"]["secret_key"] = stored()["remote"]["secret_key"].clone();
        x
    });
    // the secret does not follow a new endpoint / bucket / key id
    for (f, val) in [
        ("endpoint", json!("https://attacker.example")),
        ("bucket", json!("other-bucket")),
        ("access_key", json!("AKIA2")),
        ("region", json!("nbg1")),
    ] {
        let mut moved = s3_offsite(None);
        moved["remote"][f] = val;
        let r = t.put("/api/v1/tenants/s3t", &admin, json!({"offsite": moved})).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{f}: {:?}", r.body);
    }
    // a prefix change keeps the key but needs a quorum (redirects the copy)
    let mut moved = s3_offsite(None);
    moved["remote"]["prefix"] = json!("elsewhere");
    let r = t.put("/api/v1/tenants/s3t", &admin, json!({"offsite": moved})).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    for path in ["/api/v1/quorum", "/api/v1/audit"] {
        let raw = String::from_utf8(t.get(path, &sam).await.raw).unwrap();
        assert!(
            raw.contains("elsewhere") && !raw.contains("sealed:v1:"),
            "{path}: {raw}"
        );
    }
    let q = t.scalar::<i64>("SELECT MAX(id) FROM quorum");
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.body["state"], "executed", "{:?}", r.body);
    let mut v = stored();
    assert_eq!(v["remote"]["prefix"], "elsewhere");
    t.sk.open_all(&tenant_owner("s3t"), &mut v).unwrap();
    assert_eq!(v["remote"]["secret_key"], "s3cr3t/KEY+x");

    // validation
    for (f, val) in [
        ("endpoint", json!("http://s3.example.com")),
        ("endpoint", json!("https://s3.example.com/path")),
        ("endpoint", json!("https://user@s3.example.com")),
        ("region", json!("EU Central")),
        ("bucket", json!("Bad_Bucket")),
        ("bucket", json!("with.dots")),
        ("prefix", json!("../x")),
        ("prefix", json!("/abs")),
        ("access_key", json!("")),
        ("secret_key", json!("has space")),
        ("ca_pem", json!("-----BEGIN PRIVATE KEY-----")),
        ("storage_class_packs", json!("DEEP_ARCHIVE")),
        ("storage_class_meta", json!("lower")),
        ("bogus", json!(1)),
    ] {
        let mut bad = s3_offsite(Some("k"));
        bad["remote"][f] = val;
        let r = t
            .post("/api/v1/tenants", &admin, json!({"name": "bad", "offsite": bad}))
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{f}: {:?}", r.body);
    }
    let mut ok = s3_offsite(Some("k"));
    ok["remote"]["bucket"] = json!("with.dots");
    ok["remote"]["path_style"] = json!(true);
    ok["remote"]["endpoint"] = json!("https://[2001:db8::1]:9000");
    let r = t
        .post("/api/v1/tenants", &admin, json!({"name": "ok", "offsite": ok}))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    // other secrets in the blob are still refused
    let mut extra = s3_offsite(Some("k"));
    extra["password"] = json!("pw");
    let r = t
        .post("/api/v1/tenants", &admin, json!({"name": "extra", "offsite": extra}))
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    // no scheduler public key: 503, nothing stored
    std::fs::remove_file(&t.secrets_pub).unwrap();
    let r = t
        .post(
            "/api/v1/tenants",
            &admin,
            json!({"name": "late", "offsite": s3_offsite(Some("k"))}),
        )
        .await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    t.finish();
}

// ---------------------------------------------------------------- optional approvals, self-enrollment

async fn approvals_of(t: &T, s: &S) -> Value {
    t.get("/api/v1/settings/approvals", s).await.body
}

async fn create_op(t: &T, admin: &S, name: &str) -> String {
    let r = t
        .post("/api/v1/users", admin, json!({"name": name, "role": "operator"}))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    r.body["activation"]["code"].as_str().unwrap().to_owned()
}

async fn act_begin(t: &T, name: &str, code: &str, ip: &str) -> R {
    t.anon_post(
        "/api/v1/auth/activate/begin",
        json!({"name": name, "code": code}),
        Some(ip),
    )
    .await
}

async fn act_complete(t: &T, body: Value, ip: &str) -> R {
    t.anon_post("/api/v1/auth/activate/complete", body, Some(ip)).await
}

/// `true` if the answer is a direct execution with approvals disabled.
fn direct(r: &R) -> bool {
    r.status == StatusCode::OK && r.body["approvals"] == "disabled" && r.body["executed"] == json!(true)
}

/// Approvals disabled (plan §2): every quorum-gated action executes directly,
/// audited with `"approvals": "disabled"`; no quorum row is created. Retention
/// locks and write-only secrets are unaffected (not touched by the switch).
#[tokio::test]
async fn approvals_disabled_gated_actions_execute_directly() {
    let mut t = T::new();
    t.set_approvals(false);
    let admin = t.login("alice").await;
    let ids = seed(&t, &admin).await;

    // weakening a policy
    let purl = format!("/api/v1/policies/{}", ids["policy"]);
    let r = t.put(&purl, &admin, policy(1, false)).await;
    assert!(direct(&r), "{:?}", r.body);
    let gfs: String = t.scalar(&format!("SELECT gfs FROM policies WHERE id = {}", ids["policy"]));
    assert!(gfs.contains("\"daily\":1"), "{gfs}");
    // moving a group to a weaker policy
    let mut weak = policy(0, false);
    weak["name"] = json!("weaker");
    let weak_id = t.post("/api/v1/policies", &admin, weak).await.body["id"]
        .as_i64()
        .unwrap();
    let gurl = format!("/api/v1/groups/{}", ids["grp_acme"]);
    let r = t
        .put(
            &gurl,
            &admin,
            json!({"source_id": ids["src_acme"], "policy_id": weak_id, "name": "prod", "guests": [100]}),
        )
        .await;
    assert!(direct(&r), "{:?}", r.body);
    // deleting a group, a source, a policy, a tenant, an agent
    let r = t.delete(&format!("/api/v1/groups/{}", ids["grp_globex"]), &admin).await;
    assert!(direct(&r), "{:?}", r.body);
    let r = t
        .delete(&format!("/api/v1/sources/{}", ids["src_globex"]), &admin)
        .await;
    assert!(direct(&r), "{:?}", r.body);
    let mut spare = policy(3, true);
    spare["name"] = json!("spare");
    let spare = t.post("/api/v1/policies", &admin, spare).await.body["id"]
        .as_i64()
        .unwrap();
    let r = t.delete(&format!("/api/v1/policies/{spare}"), &admin).await;
    assert!(direct(&r), "{:?}", r.body);
    t.post("/api/v1/tenants", &admin, json!({"name": "initech"})).await;
    let r = t.delete("/api/v1/tenants/initech", &admin).await;
    assert!(direct(&r), "{:?}", r.body);
    let (agent, _) = add_agent(&t, &admin).await;
    let r = t.delete(&format!("/api/v1/agents/{agent}"), &admin).await;
    assert!(direct(&r), "{:?}", r.body);
    assert_eq!(t.scalar::<i64>("SELECT COUNT(*) FROM groups"), 1);
    assert_eq!(t.scalar::<i64>("SELECT COUNT(*) FROM sources"), 1);
    assert_eq!(
        t.scalar::<i64>("SELECT COUNT(*) FROM tenants WHERE name = 'initech'"),
        0
    );
    assert_eq!(t.scalar::<i64>("SELECT COUNT(*) FROM agents"), 0);

    // users: a new admin is enabled at once; the admin gets the whole code
    let r = t
        .post("/api/v1/users", &admin, json!({"name": "ada", "role": "admin"}))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["user"]["disabled"], json!(false));
    assert_eq!(r.body["activation"]["parts"], 1);
    let ada_code = r.body["activation"]["code"].as_str().unwrap().to_owned();
    t.activate("ada", &ada_code, Some("10.3.0.1")).await;
    let ada = t.ids["ada"];
    // promoting, disabling + re-enabling, a security officer's new activation
    let otto = t.ids["otto"];
    let r = t
        .put(
            &format!("/api/v1/users/{otto}"),
            &admin,
            json!({"role": "security_officer"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["user"]["role"], "security_officer");
    let r = t
        .put(&format!("/api/v1/users/{ada}"), &admin, json!({"disabled": true}))
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let r = t
        .put(&format!("/api/v1/users/{ada}"), &admin, json!({"disabled": false}))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let r = t
        .put(
            &format!("/api/v1/users/{}", t.ids["sam"]),
            &admin,
            t.reauth("alice", json!({"new_activation": true})),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["activation"]["parts"], 1);
    // the last enabled admin cannot be removed at all (nobody would administer)
    let r = t
        .put(&format!("/api/v1/users/{ada}"), &admin, json!({"disabled": true}))
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let r = t
        .put(
            &format!("/api/v1/users/{}", t.ids["alice"]),
            &admin,
            json!({"role": "operator"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);

    assert_eq!(t.scalar::<i64>("SELECT COUNT(*) FROM quorum"), 0, "no quorum rows");
    let audited: i64 = t.scalar("SELECT COUNT(*) FROM audit WHERE json_extract(details, '$.approvals') = 'disabled'");
    // policy, group move, group, source, policy, tenant, agent, admin create,
    // promotion, re-enable, SO activation
    assert_eq!(audited, 11);
    t.finish();
}

/// Enabling is immediate (any admin); disabling needs the requester plus one
/// other admin or security officer; admins approve like security officers.
#[tokio::test]
async fn approvals_switch_enable_direct_disable_four_eyes() {
    let mut t = T::new();
    t.add_user("adam", "admin", None);
    let admin = t.login("alice").await;
    let adam = t.login("adam").await;
    let op = t.login("otto").await;
    let v = approvals_of(&t, &op).await;
    assert_eq!(v["enabled"], json!(true), "existing catalogs keep approvals on");
    assert_eq!(v["possible_approvers"], 4);
    assert_eq!(v["recommend"], json!(false));
    assert_eq!(
        t.put("/api/v1/settings/approvals", &op, json!({"enabled": false}))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    // disabling: a request, not the change
    let r = t
        .put("/api/v1/settings/approvals", &admin, json!({"enabled": false}))
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    assert_eq!(approvals_of(&t, &admin).await["pending_disable"], json!(q));
    assert_eq!(
        t.put("/api/v1/settings/approvals", &adam, json!({"enabled": false}))
            .await
            .status,
        StatusCode::CONFLICT,
        "one pending request at a time"
    );
    assert_eq!(approvals_of(&t, &admin).await["enabled"], json!(true));
    assert_eq!(
        t.post(&format!("/api/v1/quorum/{q}/approve"), &admin, json!({}))
            .await
            .status,
        StatusCode::FORBIDDEN,
        "not by the requester"
    );
    assert_eq!(
        t.post(&format!("/api/v1/quorum/{q}/approve"), &op, json!({}))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    // another admin is an approver
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &adam, json!({})).await;
    assert_eq!((r.status, r.body["state"].as_str()), (StatusCode::OK, Some("executed")));
    let v = approvals_of(&t, &admin).await;
    assert_eq!(
        (v["enabled"].as_bool(), v["recommend"].as_bool()),
        (Some(false), Some(true))
    );
    // enabling: direct, audited
    let r = t.put("/api/v1/settings/approvals", &op, json!({"enabled": true})).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = t
        .put("/api/v1/settings/approvals", &adam, json!({"enabled": true}))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(approvals_of(&t, &admin).await["enabled"], json!(true));
    let a = t.audit_actions();
    assert!(a.contains(&"approvals.enable".to_string()) && a.contains(&"approvals.disable".to_string()));

    // with approvals on, nobody may become the only possible approver:
    // alice, adam, sam, sue → disable sue, adam (fine) → sam would leave alice alone
    for u in ["sue", "adam"] {
        let r = t
            .put(
                &format!("/api/v1/users/{}", t.ids[u]),
                &admin,
                json!({"disabled": true}),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{u}: {:?}", r.body);
    }
    // sam is the last security officer: quorum; approving it would leave alice alone
    let r = t
        .put(
            &format!("/api/v1/users/{}", t.ids["sam"]),
            &admin,
            json!({"disabled": true}),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    let sam = t.login("sam").await;
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
    assert_eq!(
        t.scalar::<i64>(&format!("SELECT disabled FROM users WHERE id = {}", t.ids["sam"])),
        0
    );
    // alice is the last enabled admin: demoting her is a quorum request, as before
    let r = t
        .put(
            &format!("/api/v1/users/{}", t.ids["alice"]),
            &admin,
            json!({"role": "operator"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "the last admin: quorum as before");
    t.add_user("ann", "admin", None);
    let r = t
        .put(
            &format!("/api/v1/users/{}", t.ids["ann"]),
            &admin,
            json!({"disabled": true}),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "three approvers left before: fine");
    t.add_user("bob", "security_officer", None);
    let r = t
        .put(
            &format!("/api/v1/users/{}", t.ids["bob"]),
            &admin,
            json!({"role": "operator"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let r = t
        .put(
            &format!("/api/v1/users/{}", t.ids["sam"]),
            &admin,
            json!({"role": "operator"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "last security officer: quorum");

    // enabling needs a second person: alone, approvals could never be disabled again
    t.set_approvals(false);
    let r = t
        .put(
            &format!("/api/v1/users/{}", t.ids["sam"]),
            &admin,
            json!({"disabled": true}),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let r = t
        .put("/api/v1/settings/approvals", &admin, json!({"enabled": true}))
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
    assert_eq!(
        approvals_of(&t, &admin).await["recommend"],
        json!(false),
        "only one approver"
    );
    t.finish();
}

/// The appliance as a single-admin setup leaves it: approvals off, no banner;
/// a second person is added directly, activates, and the banner appears.
#[tokio::test]
async fn single_admin_default_and_recommendation() {
    let mut t = T::new();
    t.set_approvals(false);
    {
        let c = t.st.cat.conn();
        c.execute("DELETE FROM users WHERE name != 'alice' AND name != 'otto'", [])
            .unwrap();
    }
    let admin = t.login("alice").await;
    let v = t.get("/api/v1/settings/approvals", &admin).await.body;
    assert_eq!(
        v,
        json!({"enabled": false, "possible_approvers": 1, "recommend": false, "few_approvers": false,
               "pending_disable": null})
    );
    let r = t
        .post(
            "/api/v1/users",
            &admin,
            json!({"name": "sofia", "role": "security_officer"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let code = r.body["activation"]["code"].as_str().unwrap().to_owned();
    assert_eq!(
        t.get("/api/v1/settings/approvals", &admin).await.body["recommend"],
        json!(false),
        "a pending account cannot approve yet"
    );
    t.activate("sofia", &code, Some("10.4.0.1")).await;
    let v = t.get("/api/v1/settings/approvals", &admin).await.body;
    assert_eq!(
        (v["possible_approvers"].as_i64(), v["recommend"].as_bool()),
        (Some(2), Some(true))
    );
    let r = t
        .put("/api/v1/settings/approvals", &admin, json!({"enabled": true}))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let sofia = t.login("sofia").await;
    let r = t
        .put("/api/v1/settings/approvals", &admin, json!({"enabled": false}))
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let q = r.body["quorum_id"].as_i64().unwrap();
    assert_eq!(
        t.post(&format!("/api/v1/quorum/{q}/approve"), &sofia, json!({}))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        t.get("/api/v1/settings/approvals", &admin).await.body["enabled"],
        json!(false)
    );
    t.finish();
}

/// Approvals disabled: a large GC waits for one admin's confirmation instead
/// of a quorum request (the scheduler writes `gc_confirm/<tenant>`).
#[tokio::test]
async fn large_gc_confirmation_without_approvals() {
    let t = T::new();
    let admin = t.login("alice").await;
    let op = t.login("otto").await;
    let pending = json!({"job": 7, "reason": "GC would delete 12 of 20 chunks", "created": 1});
    catalog::set_setting(&t.st.cat.conn(), "gc_confirm/acme", &pending.to_string()).unwrap();
    let r = t
        .post("/api/v1/gc/approve-large", &admin, json!({"tenant": "acme"}))
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "approvals on: quorum instead");
    t.set_approvals(false);
    let list = t.get("/api/v1/gc/pending", &op).await.body;
    assert_eq!(list[0]["tenant"], "acme");
    assert_eq!(list[0]["job"], 7);
    assert_eq!(
        t.post("/api/v1/gc/approve-large", &op, json!({"tenant": "acme"}))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let r = t
        .post("/api/v1/gc/approve-large", &admin, json!({"tenant": "acme"}))
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let job = r.body["job_id"].as_i64().unwrap();
    let p: Value =
        serde_json::from_str(&t.scalar::<String>(&format!("SELECT params FROM jobs WHERE id = {job}"))).unwrap();
    assert_eq!(p, json!({"approved": true, "confirmed_by": "alice"}));
    assert_eq!(t.get("/api/v1/gc/pending", &admin).await.body, json!([]));
    assert_eq!(
        t.post("/api/v1/gc/approve-large", &admin, json!({"tenant": "acme"}))
            .await
            .status,
        StatusCode::CONFLICT,
        "once"
    );
    assert!(t.audit_actions().contains(&"gc.approve_large".to_string()));
    // the job API cannot forge the flag
    let r = t
        .post(
            "/api/v1/jobs",
            &admin,
            json!({"kind": "gc", "tenant": "acme", "params": {"approved": true, "confirmed_by": "alice"}}),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    t.finish();
}

/// Activation: wrong code, expiry, rate limit, replay of the code and of the
/// TOTP step, weak password, and the code is useless afterwards.
#[tokio::test]
async fn activation_edge_cases() {
    let mut t = T::new();
    let admin = t.login("alice").await;
    // wrong code: 401, audited, no detail about why
    let code = create_op(&t, &admin, "olga").await;
    let r = act_begin(&t, "olga", "AAAAAAAAAAAAAAAAAAAAAAAAAA", "10.5.0.1").await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r2 = act_begin(&t, "nobody", &code, "10.5.0.1").await;
    assert_eq!(
        (r2.status, &r2.body),
        (StatusCode::UNAUTHORIZED, &r.body),
        "no user enumeration"
    );
    assert_eq!(
        t.scalar::<String>("SELECT json_extract(details, '$.reason') FROM audit WHERE action = 'auth.activate_failed' ORDER BY seq LIMIT 1"),
        "code"
    );
    // weak password, wrong TOTP: still pending
    let r = act_begin(&t, "olga", &code, "10.5.0.2").await;
    assert_eq!(r.status, StatusCode::OK);
    let secret = r.body["totp_secret"].as_str().unwrap().to_owned();
    let now = catalog::auth::totp_now(&secret).unwrap();
    let r = act_complete(
        &t,
        json!({"name": "olga", "code": code, "password": "short", "totp": now}),
        "10.5.0.2",
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    let r = act_complete(
        &t,
        json!({"name": "olga", "code": code, "password": PW, "totp": wrong_code(&now)}),
        "10.5.0.2",
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        t.scalar::<i64>("SELECT COUNT(*) FROM users WHERE name = 'olga' AND activation_hash IS NOT NULL"),
        1
    );
    // success; the TOTP step is consumed, the code is used up
    let r = act_complete(
        &t,
        json!({"name": "olga", "code": code, "password": PW, "totp": now}),
        "10.5.0.3",
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        t.try_login("olga", &now, Some("10.5.0.4")).await.status,
        StatusCode::UNAUTHORIZED,
        "TOTP replay after activation"
    );
    assert_eq!(
        act_begin(&t, "olga", &code, "10.5.0.5").await.status,
        StatusCode::UNAUTHORIZED
    );
    let r = act_complete(
        &t,
        json!({"name": "olga", "code": code, "password": PW, "totp": now}),
        "10.5.0.5",
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "code replay");
    t.secrets.insert("olga".into(), secret);
    t.login("olga").await;
    assert!(t.audit_actions().contains(&"user.activate".to_string()));

    // expiry
    let code = create_op(&t, &admin, "eve").await;
    t.st.cat
        .conn()
        .execute(
            "UPDATE users SET activation_expires = ?1 WHERE name = 'eve'",
            [catalog::now() - 1],
        )
        .unwrap();
    assert_eq!(
        act_begin(&t, "eve", &code, "10.5.1.1").await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        t.scalar::<String>("SELECT json_extract(details, '$.reason') FROM audit WHERE action = 'auth.activate_failed' ORDER BY seq DESC LIMIT 1"),
        "expired"
    );
    // a disabled pending account cannot be activated
    let code = create_op(&t, &admin, "dora").await;
    let dora = t.scalar::<i64>("SELECT id FROM users WHERE name = 'dora'");
    t.put(&format!("/api/v1/users/{dora}"), &admin, json!({"disabled": true}))
        .await;
    assert_eq!(
        act_begin(&t, "dora", &code, "10.5.1.2").await.status,
        StatusCode::UNAUTHORIZED
    );

    // rate limit: 5 failures for one user → locked, even with the right code
    let code = create_op(&t, &admin, "max").await;
    for i in 0..5 {
        let r = act_begin(&t, "max", "WRONGWRONGWRONGWRONGWRONG2", &format!("10.6.0.{i}")).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(
        act_begin(&t, "max", &code, "10.6.1.1").await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert!(t.audit_actions().contains(&"auth.lockout".to_string()));
    t.finish();
}

/// Phase 17a: offsite bandwidth windows. Tightening (a pause added, a lower
/// limit) applies directly; weakening (a pause removed, a higher limit) or any
/// other change together with it needs the quorum as before.
#[tokio::test]
async fn tenant_offsite_windows_tighten_direct_weaken_quorum() {
    let t = T::new();
    let admin = t.login("alice").await;
    let base = json!({"remote": "sftp", "host": "u1.your-storagebox.de", "key": "/etc/nexus/ssh/box"});
    let with = |extra: Value| {
        let mut v = base.clone();
        v.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        v
    };
    let put = |o: Value| t.put("/api/v1/tenants/acme", &admin, json!({"offsite": o}));
    assert_eq!(put(base.clone()).await.status, StatusCode::OK);
    let pause =
        json!([{"days": ["Mon", "Tue", "Wed", "Thu", "Fri"], "from": "08:00", "to": "18:00", "action": "pause"}]);
    for bad in [
        json!({"windows": [{"from": "08:00", "to": "18:00", "action": "limit"}]}),
        json!({"windows": [{"from": "08:00", "to": "18:00", "action": "nap"}]}),
        json!({"windows": pause, "timezone": "Nowhere/Land"}),
    ] {
        assert_eq!(put(with(bad.clone())).await.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let r = put(with(
        json!({"windows": pause, "timezone": "Europe/Berlin", "bwlimit": 10_000_000}),
    ))
    .await;
    assert_eq!(r.status, StatusCode::OK, "a pause and a limit added: {:?}", r.body);
    assert_eq!(r.body["offsite"]["windows"], pause);
    let r = put(with(
        json!({"windows": pause, "timezone": "Europe/Berlin", "bwlimit": 5_000_000}),
    ))
    .await;
    assert_eq!(r.status, StatusCode::OK, "lower limit");
    for weak in [
        json!({"timezone": "Europe/Berlin", "bwlimit": 5_000_000}),
        json!({"windows": pause, "timezone": "Europe/Berlin", "bwlimit": 6_000_000}),
        json!({"windows": pause, "timezone": "Asia/Tokyo", "bwlimit": 5_000_000}),
        json!({"windows": pause, "timezone": "Europe/Berlin", "bwlimit": 1, "host": "evil.example"}),
    ] {
        let r = put(with(weak.clone())).await;
        assert_eq!(r.status, StatusCode::ACCEPTED, "{weak}: {:?}", r.body);
    }
    t.finish();
}

// ---------------------------------------------------------------- tenant admins (Phase 19b)

/// Every `(METHOD, path)` the API router registers (lib.rs and the modules'
/// `routes()`), read from the source: a new route fails
/// [`tenant_admin_routes_classified`] until it is classified there.
fn registered_routes() -> std::collections::BTreeSet<(String, String)> {
    let lib = include_str!("../src/lib.rs");
    let api = &lib[lib.find("let api = Router::new()").unwrap()..lib.find("let peer = Router::new()").unwrap()];
    let mut out = std::collections::BTreeSet::new();
    for src in [
        api,
        include_str!("../src/access.rs"),
        include_str!("../src/firewall.rs"),
        include_str!("../src/holds.rs"),
        include_str!("../src/hardware.rs"),
        include_str!("../src/tenants.rs"),
        include_str!("../src/tenancy.rs"),
        include_str!("../src/vault.rs"),
    ] {
        for piece in src.split(".route(").skip(1) {
            let piece = piece.split(".merge(").next().unwrap().split("\n}").next().unwrap();
            let path = piece.split('"').nth(1).unwrap();
            for m in ["get", "post", "put", "delete"] {
                let call = format!("{m}(");
                let b = piece.as_bytes();
                if piece
                    .match_indices(&call)
                    .any(|(i, _)| i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_'))
                {
                    out.insert((m.to_uppercase(), path.to_owned()));
                }
            }
        }
    }
    out
}

/// Every route classified for `tenant_admin` (docs/control-plane.md "Tenant
/// admins"): `Y` reaches the handler (never 401/403), `N` is always 403, `-`
/// is public or session plumbing (not called here). Its own tenant only: the
/// rows use objects of acme (dana's tenant).
#[tokio::test]
async fn tenant_admin_routes_classified() {
    let mut t = T::new();
    let admin = t.login("alice").await;
    let ids = seed(&t, &admin).await;
    let (agent, _) = add_agent(&t, &admin).await;
    t.add_user("dana", "tenant_admin", Some("acme"));
    let dana = t.login("dana").await;
    let (src, grp, pol, job, tina) = (
        ids["src_acme"],
        ids["grp_acme"],
        ids["policy"],
        ids["job_acme"],
        t.ids["tina"],
    );
    let r = t
        .put("/api/v1/tenants/acme/policies", &admin, json!({"policy_ids": [pol]}))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let snap = "/api/v1/snapshots/acme/vm-100/1000";
    let none = || None::<Value>;
    let oidc_off = json!({"enabled": false, "issuer": "", "client_id": "", "scopes": [], "username_claim": "x",
                          "groups_claim": "x", "label": "x", "mappings": []});
    let e = || Some(json!({}));
    #[rustfmt::skip]
    let table: Vec<(&str, &str, String, Option<Value>, char)> = vec![
        ("GET", "/health", "/api/v1/health".into(), none(), '-'),
        ("GET", "/metrics", "/api/v1/metrics".into(), none(), '-'),
        ("POST", "/auth/login", "".into(), none(), '-'),
        ("POST", "/auth/logout", "".into(), none(), '-'),
        ("GET", "/auth/me", "/api/v1/auth/me".into(), none(), 'Y'),
        ("POST", "/auth/activate/begin", "".into(), none(), '-'),
        ("POST", "/auth/activate/complete", "".into(), none(), '-'),
        ("GET", "/auth/tokens", "/api/v1/auth/tokens".into(), none(), 'Y'),
        ("POST", "/auth/tokens", "/api/v1/auth/tokens".into(), Some(json!({"name": "x", "scope": "read", "days": 1})), 'Y'),
        ("DELETE", "/auth/tokens/{id}", "/api/v1/auth/tokens/999".into(), none(), 'Y'),
        ("GET", "/certificate", "/api/v1/certificate".into(), none(), 'N'),
        ("POST", "/certificate/csr", "/api/v1/certificate/csr".into(), Some(json!({"cn": "x", "sans": []})), 'N'),
        ("POST", "/certificate/install", "/api/v1/certificate/install".into(), Some(json!({"chain_pem": "x"})), 'N'),
        ("POST", "/certificate/revert", "/api/v1/certificate/revert".into(), e(), 'N'),
        ("GET", "/auth/oidc", "".into(), none(), '-'),
        ("GET", "/auth/oidc/start", "".into(), none(), '-'),
        ("GET", "/auth/oidc/callback", "".into(), none(), '-'),
        ("GET", "/dashboard", "/api/v1/dashboard".into(), none(), 'Y'),
        ("GET", "/storage", "/api/v1/storage".into(), none(), 'Y'),
        ("GET", "/reports/{file}", "/api/v1/reports/sla.csv".into(), none(), 'Y'),
        ("GET", "/settings/reports", "/api/v1/settings/reports".into(), none(), 'N'),
        ("PUT", "/settings/reports", "/api/v1/settings/reports".into(), Some(json!({"reports": []})), 'N'),
        ("POST", "/settings/reports/{name}/send", "/api/v1/settings/reports/x/send".into(), e(), 'N'),
        ("PUT", "/tenants/{name}/quota", "/api/v1/tenants/acme/quota".into(), Some(json!({"quota_bytes": 1})), 'N'),
        ("GET", "/tenants/{tenant}/recovery-key", "/api/v1/tenants/acme/recovery-key".into(), none(), 'N'),
        ("POST", "/tenants/{tenant}/recovery-key", "/api/v1/tenants/acme/recovery-key".into(), e(), 'N'),
        ("POST", "/tenants/{tenant}/recovery-key/{id}/show", "/api/v1/tenants/acme/recovery-key/1/show".into(), e(), 'N'),
        ("GET", "/settings/anomaly", "/api/v1/settings/anomaly".into(), none(), 'N'),
        ("PUT", "/settings/anomaly", "/api/v1/settings/anomaly".into(), Some(json!({"enabled": true, "factor": 3.0, "history": 14, "floor_bytes": 1u64 << 30})), 'N'),
        ("GET", "/settings/oidc", "/api/v1/settings/oidc".into(), none(), 'N'),
        ("PUT", "/settings/oidc", "/api/v1/settings/oidc".into(), Some(oidc_off.clone()), 'N'),
        ("POST", "/settings/oidc/test", "/api/v1/settings/oidc/test".into(), Some(oidc_off), 'N'),
        ("GET", "/settings/alerts", "/api/v1/settings/alerts".into(), none(), 'N'),
        ("PUT", "/settings/alerts", "/api/v1/settings/alerts".into(), e(), 'N'),
        ("POST", "/settings/alerts/test", "/api/v1/settings/alerts/test".into(), e(), 'N'),
        ("GET", "/ssh-keys", "/api/v1/ssh-keys".into(), none(), 'N'),
        ("POST", "/ssh-keys/{name}/rotate", "/api/v1/ssh-keys/x/rotate".into(), e(), 'N'),
        ("POST", "/ssh-keys/{name}/retire", "/api/v1/ssh-keys/x/retire".into(), e(), 'N'),
        ("GET", "/updates", "/api/v1/updates".into(), none(), 'N'),
        ("POST", "/updates/check", "/api/v1/updates/check".into(), e(), 'N'),
        ("POST", "/updates/apply", "/api/v1/updates/apply".into(), e(), 'N'),
        ("GET", "/updates/registry", "/api/v1/updates/registry".into(), none(), 'N'),
        ("PUT", "/updates/registry", "/api/v1/updates/registry".into(), Some(json!({"username": "bot", "token": "x"})), 'N'),
        ("DELETE", "/updates/registry", "/api/v1/updates/registry".into(), none(), 'N'),
        ("GET", "/diagnostics", "/api/v1/diagnostics".into(), none(), 'N'),
        ("POST", "/diagnostics/checks", "/api/v1/diagnostics/checks".into(), e(), 'N'),
        ("POST", "/diagnostics/bundle", "/api/v1/diagnostics/bundle".into(), e(), 'N'),
        ("GET", "/diagnostics/{id}", "/api/v1/diagnostics/x".into(), none(), 'N'),
        ("GET", "/diagnostics/{id}/download", "/api/v1/diagnostics/x/download".into(), none(), 'N'),
        ("GET", "/settings/config-backup", "/api/v1/settings/config-backup".into(), none(), 'N'),
        ("POST", "/settings/config-backup/run", "/api/v1/settings/config-backup/run".into(), e(), 'N'),
        ("GET", "/settings/config-backup/download", "/api/v1/settings/config-backup/download".into(), none(), 'N'),
        ("GET", "/settings/approvals", "/api/v1/settings/approvals".into(), none(), 'N'),
        ("PUT", "/settings/approvals", "/api/v1/settings/approvals".into(), Some(json!({"enabled": true})), 'N'),
        ("GET", "/gc/pending", "/api/v1/gc/pending".into(), none(), 'N'),
        ("POST", "/gc/approve-large", "/api/v1/gc/approve-large".into(), Some(json!({"tenant": "acme"})), 'N'),
        ("GET", "/tenants", "/api/v1/tenants".into(), none(), 'Y'),
        ("POST", "/tenants", "/api/v1/tenants".into(), Some(json!({"name": "ta-new"})), 'N'),
        ("POST", "/tenants/attach", "/api/v1/tenants/attach".into(), Some(json!({"name": "x", "offsite": {}})), 'N'),
        ("POST", "/tenants/attach/{id}/run", "/api/v1/tenants/attach/1/run".into(), Some(json!({"recovery_key": "x"})), 'N'),
        ("PUT", "/tenants/{name}", "/api/v1/tenants/acme".into(), Some(json!({"offsite": {}})), 'N'),
        ("DELETE", "/tenants/{name}", "/api/v1/tenants/acme".into(), none(), 'N'),
        ("GET", "/sources", "/api/v1/sources".into(), none(), 'Y'),
        ("POST", "/sources", "/api/v1/sources".into(), Some(json!({"tenant": "acme", "kind": "pve", "name": "ta-s", "config": src_cfg(Some("x"))})), 'Y'),
        ("PUT", "/sources/{id}", format!("/api/v1/sources/{src}"), Some(json!({"name": "pve", "config": src_cfg(None)})), 'Y'),
        ("DELETE", "/sources/{id}", "/api/v1/sources/999".into(), none(), 'Y'),
        ("GET", "/sources/{id}/inventory", format!("/api/v1/sources/{src}/inventory"), none(), 'Y'),
        ("GET", "/policies", "/api/v1/policies".into(), none(), 'Y'),
        ("POST", "/policies", "/api/v1/policies".into(), Some(json!({"name": "ta-p", "schedule": "daily 02:00", "gfs": {"daily": 1, "weekly": 0, "monthly": 0, "yearly": 0}})), 'N'),
        ("PUT", "/policies/{id}", format!("/api/v1/policies/{pol}"), Some(policy(8, true)), 'N'),
        ("DELETE", "/policies/{id}", format!("/api/v1/policies/{pol}"), none(), 'N'),
        ("GET", "/groups", "/api/v1/groups".into(), none(), 'Y'),
        ("POST", "/groups", "/api/v1/groups".into(), Some(json!({"tenant": "acme", "source_id": src, "policy_id": pol, "name": "ta-g", "guests": [100]})), 'Y'),
        ("PUT", "/groups/{id}", format!("/api/v1/groups/{grp}"), Some(json!({"source_id": src, "policy_id": pol, "name": "prod", "guests": [100, 101, 102]})), 'Y'),
        ("DELETE", "/groups/{id}", "/api/v1/groups/999".into(), none(), 'Y'),
        ("POST", "/groups/{id}/pause", format!("/api/v1/groups/{grp}/pause"), Some(json!({"hours": 1})), 'Y'),
        ("POST", "/groups/{id}/resume", format!("/api/v1/groups/{grp}/resume"), e(), 'Y'),
        ("PUT", "/groups/{id}/index-files", format!("/api/v1/groups/{grp}/index-files"), Some(json!({"enabled": true})), 'Y'),
        ("POST", "/search", "/api/v1/search".into(), Some(json!({"tenant": "acme", "query": "etc"})), 'Y'),
        ("POST", "/sources/{id}/maintenance", format!("/api/v1/sources/{src}/maintenance"), Some(json!({"hours": 1})), 'Y'),
        ("POST", "/sources/{id}/maintenance/end", format!("/api/v1/sources/{src}/maintenance/end"), e(), 'Y'),
        ("GET", "/users", "/api/v1/users".into(), none(), 'Y'),
        ("POST", "/users", "/api/v1/users".into(), Some(json!({"name": "ta-u", "role": "tenant_user"})), 'Y'),
        ("PUT", "/users/{id}", format!("/api/v1/users/{tina}"), Some(json!({"can_download": false})), 'Y'),
        ("GET", "/agents", "/api/v1/agents".into(), none(), 'Y'),
        ("POST", "/agents", "/api/v1/agents".into(), Some(json!({"tenant": "acme", "name": "ta-a", "host": "h"})), 'Y'),
        ("DELETE", "/agents/{id}", format!("/api/v1/agents/{agent}"), none(), 'Y'),
        ("POST", "/agents/{id}/token", format!("/api/v1/agents/{agent}/token"), e(), 'Y'),
        ("POST", "/agents/{id}/enroll", format!("/api/v1/agents/{agent}/enroll"), e(), 'Y'),
        ("PUT", "/agents/{id}/limits", format!("/api/v1/agents/{agent}/limits"), Some(json!({"bwlimit": 1 << 20, "nice": 10})), 'Y'),
        ("POST", "/agents/bulk", "/api/v1/agents/bulk".into(), Some(json!({"csv": "host,tenant\nta-bulk,acme"})), 'Y'),
        ("GET", "/fleets", "/api/v1/fleets".into(), none(), 'N'),
        ("POST", "/fleets", "/api/v1/fleets".into(), Some(json!({"name": "f", "tenant": "acme", "expires_days": 1})), 'N'),
        ("DELETE", "/fleets/{id}", "/api/v1/fleets/0011223344556677".into(), none(), 'N'),
        ("POST", "/fleets/{id}/scan", "/api/v1/fleets/0011223344556677/scan".into(), e(), 'N'),
        ("GET", "/fleet/candidates", "/api/v1/fleet/candidates".into(), none(), 'Y'),
        ("POST", "/fleet/candidates/{id}/accept", "/api/v1/fleet/candidates/999/accept".into(), e(), 'Y'),
        ("POST", "/fleet/candidates/{id}/reject", "/api/v1/fleet/candidates/999/reject".into(), e(), 'Y'),
        ("PUT", "/agents/{id}/ui-policy", format!("/api/v1/agents/{agent}/ui-policy"), Some(json!({"header": "x"})), 'N'),
        ("PUT", "/agents/{id}/laptop", format!("/api/v1/agents/{agent}/laptop"), Some(json!({"min_battery": 20})), 'Y'),
        ("GET", "/agents/{id}/sessions", format!("/api/v1/agents/{agent}/sessions"), none(), 'Y'),
        ("GET", "/snapshots", "/api/v1/snapshots".into(), none(), 'Y'),
        ("DELETE", "/snapshots/{tenant}/{source}/{time}", snap.into(), none(), 'N'),
        ("POST", "/snapshots/diff", "/api/v1/snapshots/diff".into(), Some(json!({"tenant": "acme", "source": "vm-100", "time": 1000})), 'Y'),
        ("POST", "/snapshots/{tenant}/{source}/{time}/anomaly/clear", format!("{snap}/anomaly/clear"), Some(json!({"note": "x"})), 'N'),
        ("GET", "/stats/trends", "/api/v1/stats/trends".into(), none(), 'Y'),
        ("GET", "/jobs", "/api/v1/jobs".into(), none(), 'Y'),
        ("POST", "/jobs", "/api/v1/jobs".into(), Some(json!({"kind": "backup", "tenant": "acme", "params": {"vmid": 100}})), 'Y'),
        ("POST", "/restores", "/api/v1/restores".into(), Some(json!({"tenant": "acme", "items": []})), 'Y'),
        ("GET", "/jobs/{id}", format!("/api/v1/jobs/{job}"), none(), 'Y'),
        ("POST", "/jobs/{id}/cancel", format!("/api/v1/jobs/{job}/cancel"), e(), 'Y'),
        ("GET", "/downloads/{token}", format!("/api/v1/downloads/{}", "ab".repeat(32)), none(), 'Y'),
        ("GET", "/quorum", "/api/v1/quorum".into(), none(), 'Y'),
        ("GET", "/console/unlock", "/api/v1/console/unlock".into(), none(), 'N'),
        ("POST", "/console/unlock", "/api/v1/console/unlock".into(), Some(json!({"hours": 1, "reason": "x"})), 'N'),
        ("DELETE", "/console/unlock/{id}", "/api/v1/console/unlock/1".into(), none(), 'N'),
        ("POST", "/console/unlock/{id}/code", "/api/v1/console/unlock/1/code".into(), e(), 'N'),
        ("POST", "/quorum/{id}/approve", "/api/v1/quorum/1/approve".into(), e(), 'N'),
        ("POST", "/quorum/{id}/reject", "/api/v1/quorum/1/reject".into(), e(), 'N'),
        ("GET", "/audit", "/api/v1/audit".into(), none(), 'Y'),
        ("GET", "/audit/verify", "/api/v1/audit/verify".into(), none(), 'N'),
        ("GET", "/audit.csv", "/api/v1/audit.csv".into(), none(), 'Y'),
        ("GET", "/audit/forwarding", "/api/v1/audit/forwarding".into(), none(), 'N'),
        ("GET", "/settings/forwarding", "/api/v1/settings/forwarding".into(), none(), 'N'),
        ("PUT", "/settings/forwarding", "/api/v1/settings/forwarding".into(), Some(json!({"syslog": null, "https": null})), 'N'),
        ("POST", "/settings/forwarding/test", "/api/v1/settings/forwarding/test".into(), e(), 'N'),
        ("GET", "/alerts", "/api/v1/alerts".into(), none(), 'Y'),
        ("POST", "/alerts/{id}/ack", "/api/v1/alerts/1/ack".into(), e(), 'N'),
        ("POST", "/alerts/{id}/resolve", "/api/v1/alerts/1/resolve".into(), e(), 'N'),
        ("GET", "/plugins", "/api/v1/plugins".into(), none(), 'Y'),
        ("POST", "/plugins", "/api/v1/plugins".into(), e(), 'N'),
        ("DELETE", "/plugins/{id}", "/api/v1/plugins/x".into(), none(), 'N'),
        ("POST", "/plugins/{id}/enable", "/api/v1/plugins/x/enable".into(), e(), 'N'),
        ("POST", "/plugins/{id}/disable", "/api/v1/plugins/x/disable".into(), e(), 'N'),
        ("POST", "/plugins/{id}/activate", "/api/v1/plugins/x/activate".into(), Some(json!({"version": "1.0.0"})), 'N'),
        ("GET", "/plugin-keys", "/api/v1/plugin-keys".into(), none(), 'N'),
        ("POST", "/plugin-keys", "/api/v1/plugin-keys".into(), Some(json!({"publisher": "x", "public_key": "x"})), 'N'),
        ("DELETE", "/plugin-keys/{fp}", "/api/v1/plugin-keys/x".into(), none(), 'N'),
        ("GET", "/replication/peers", "/api/v1/replication/peers".into(), none(), 'N'),
        ("POST", "/replication/peers", "/api/v1/replication/peers".into(), Some(json!({"name": "p", "tenants": ["acme"]})), 'N'),
        ("DELETE", "/replication/peers/{id}", "/api/v1/replication/peers/x".into(), none(), 'N'),
        ("POST", "/replication/peers/{id}/export-keys", "/api/v1/replication/peers/x/export-keys".into(), e(), 'N'),
        ("GET", "/replication/sources", "/api/v1/replication/sources".into(), none(), 'N'),
        ("POST", "/replication/sources", "/api/v1/replication/sources".into(), Some(json!({"name": "s", "url": "h", "code": "0123456789abcdef.ABCDEFGHIJKLMNOPQRSTUVWXYZ", "fingerprint": "ab".repeat(32), "tenants": ["dr1"], "schedule": "hourly 05"})), 'N'),
        ("PUT", "/replication/sources/{id}", "/api/v1/replication/sources/1".into(), e(), 'N'),
        ("DELETE", "/replication/sources/{id}", "/api/v1/replication/sources/1".into(), none(), 'N'),
        ("POST", "/replication/sources/{id}/enroll", "/api/v1/replication/sources/1/enroll".into(), e(), 'N'),
        ("POST", "/replication/sources/{id}/sync", "/api/v1/replication/sources/1/sync".into(), e(), 'N'),
        ("POST", "/replication/sources/{id}/close", "/api/v1/replication/sources/1/close".into(), e(), 'N'),
        ("POST", "/replication/sources/{id}/reopen", "/api/v1/replication/sources/1/reopen".into(), e(), 'N'),
        ("GET", "/auth/banner", "".into(), none(), '-'),
        ("GET", "/auth/sessions", "/api/v1/auth/sessions".into(), none(), 'Y'),
        ("DELETE", "/auth/sessions/{id}", "/api/v1/auth/sessions/999999".into(), none(), 'Y'),
        ("GET", "/sessions", "/api/v1/sessions".into(), none(), 'N'),
        ("DELETE", "/sessions/{id}", "/api/v1/sessions/999999".into(), none(), 'N'),
        ("POST", "/sessions/revoke-all", "/api/v1/sessions/revoke-all".into(), e(), 'N'),
        ("POST", "/users/{id}/sessions/revoke", format!("/api/v1/users/{tina}/sessions/revoke"), e(), 'N'),
        ("GET", "/settings/security", "/api/v1/settings/security".into(), none(), 'N'),
        ("PUT", "/settings/session", "/api/v1/settings/session".into(), Some(json!({"idle_min": 30, "absolute_h": 12})), 'N'),
        ("PUT", "/settings/dormant", "/api/v1/settings/dormant".into(), Some(json!({"days": 0})), 'N'),
        ("PUT", "/settings/banner", "/api/v1/settings/banner".into(), Some(json!({"banner": "x"})), 'N'),
        ("PUT", "/settings/mgmt-allow", "/api/v1/settings/mgmt-allow".into(), Some(json!({"mgmt_allow": ["10.0.0.0/8"]})), 'N'),
        ("GET", "/firewall", "/api/v1/firewall".into(), none(), 'N'),
        ("PUT", "/firewall/inbound/{service}", "/api/v1/firewall/inbound/icmp".into(), Some(json!({"allow": ["10.0.0.0/8"], "enabled": true})), 'N'),
        ("GET", "/holds", "/api/v1/holds".into(), none(), 'Y'),
        ("POST", "/holds", "/api/v1/holds".into(), Some(json!({"tenant": "acme", "source": "vm-100", "from": 0, "to": 100, "reason": "x"})), 'N'),
        ("POST", "/snapshots/{tenant}/{source}/{time}/hold", format!("{snap}/hold"), Some(json!({"reason": "x"})), 'N'),
        ("DELETE", "/snapshots/{tenant}/{source}/{time}/hold", format!("{snap}/hold"), none(), 'N'),
        ("GET", "/hardware", "/api/v1/hardware".into(), none(), 'N'),
        ("POST", "/hardware/scan", "/api/v1/hardware/scan".into(), e(), 'N'),
        ("POST", "/hardware/selftest", "/api/v1/hardware/selftest".into(), Some(json!({"disk": "sda", "type": "short"})), 'N'),
        ("POST", "/hardware/arrays", "/api/v1/hardware/arrays".into(), Some(json!({"role": "data", "level": "raid1", "disks": [], "confirm": "x"})), 'N'),
        ("POST", "/hardware/arrays/{name}/spare", "/api/v1/hardware/arrays/md0/spare".into(), Some(json!({"disk": "sdb", "confirm": "x"})), 'N'),
        ("POST", "/hardware/arrays/{name}/replace", "/api/v1/hardware/arrays/md0/replace".into(), Some(json!({"disk": "sdb", "confirm": "x"})), 'N'),
        ("POST", "/hardware/arrays/{name}/grow", "/api/v1/hardware/arrays/md0/grow".into(), Some(json!({"disk": "sdb", "confirm": "x"})), 'N'),
        ("POST", "/tenants/{name}/deactivate", "/api/v1/tenants/acme/deactivate".into(), Some(json!({"reason": "x"})), 'N'),
        ("POST", "/tenants/{name}/reactivate", "/api/v1/tenants/acme/reactivate".into(), e(), 'N'),
        ("GET", "/vault", "/api/v1/vault".into(), none(), 'Y'),
        ("PUT", "/vault", "/api/v1/vault".into(), Some(json!({"enabled": true})), 'N'),
        ("GET", "/tenants/tombstones", "/api/v1/tenants/tombstones".into(), none(), 'N'),
        ("PUT", "/tenants/{name}/policies", "/api/v1/tenants/acme/policies".into(), Some(json!({"policy_ids": [pol]})), 'N'),
        ("POST", "/tenants/{name}/impersonate", "/api/v1/tenants/acme/impersonate".into(), e(), 'N'),
        ("POST", "/auth/impersonation/end", "/api/v1/auth/impersonation/end".into(), e(), 'Y'),
        ("GET", "/policies/templates", "/api/v1/policies/templates".into(), none(), 'Y'),
        ("POST", "/policies/templates", "/api/v1/policies/templates".into(), Some(json!({"tier": "gold"})), 'N'),
    ];
    let classified: std::collections::BTreeSet<(String, String)> =
        table.iter().map(|(m, p, ..)| (m.to_string(), p.to_string())).collect();
    assert_eq!(classified.len(), table.len(), "duplicate rows");
    assert_eq!(
        classified,
        registered_routes(),
        "every route classified for tenant_admin"
    );
    let mut wrong = vec![];
    for (m, _, path, body, exp) in table {
        if exp == '-' {
            continue;
        }
        let method = Method::from_bytes(m.as_bytes()).unwrap();
        let r = t.call(method, &path, Some(&dana), body).await;
        let denied = r.status == StatusCode::FORBIDDEN || r.status == StatusCode::UNAUTHORIZED;
        if (exp == 'Y') == denied || (exp == 'N' && r.status != StatusCode::FORBIDDEN) {
            wrong.push(format!("{exp} {m} {path}: {} {}", r.status, r.body));
        }
    }
    assert!(wrong.is_empty(), "tenant_admin:\n{}", wrong.join("\n"));
    t.finish();
}

/// A tenant admin manages its own tenant only: groups with assigned policies,
/// accounts with tenant roles, the same approvals as an admin (decided by the
/// provider), no provider-side job kinds.
#[tokio::test]
async fn tenant_admin_scope_policies_users_and_approvals() {
    let mut t = T::new();
    let admin = t.login("alice").await;
    let ids = seed(&t, &admin).await;
    t.add_user("dana", "tenant_admin", Some("acme"));
    let dana = t.login("dana").await;
    let (src, pol) = (ids["src_acme"], ids["policy"]);
    let weak = t
        .post(
            "/api/v1/policies",
            &admin,
            json!({"name": "weak", "schedule": "daily 03:00",
               "gfs": {"daily": 1, "weekly": 0, "monthly": 0, "yearly": 0}, "offsite": false}),
        )
        .await
        .body["id"]
        .as_i64()
        .unwrap();
    let gold = t
        .post("/api/v1/policies/templates", &admin, json!({"tier": "gold"}))
        .await;
    assert_eq!(gold.status, StatusCode::CREATED, "{:?}", gold.body);
    assert_eq!(
        (gold.body["tier"].clone(), gold.body["name"].clone()),
        (json!("gold"), json!("Gold"))
    );
    assert_eq!(
        t.post("/api/v1/policies/templates", &admin, json!({"tier": "gold"}))
            .await
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        t.post("/api/v1/policies/templates", &admin, json!({"tier": "tin"}))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    let gold = gold.body["id"].as_i64().unwrap();
    // nothing assigned: the policy of acme's existing group shows, no other
    let names = |v: &Value| {
        v.as_array()
            .unwrap()
            .iter()
            .map(|p| p["id"].as_i64().unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(names(&t.get("/api/v1/policies", &dana).await.body), vec![pol]);
    let group = |name: &str, tenant: &str, policy: i64| json!({"tenant": tenant, "source_id": src, "policy_id": policy, "name": name, "guests": [100]});
    let r = t.post("/api/v1/groups", &dana, group("g1", "acme", gold)).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "unassigned policy: {:?}", r.body);
    let r = t
        .put(
            "/api/v1/tenants/acme/policies",
            &admin,
            json!({"policy_ids": [gold, weak, gold]}),
        )
        .await;
    assert_eq!(r.body["policy_ids"], json!([weak.min(gold), weak.max(gold)]));
    let tenants = t.get("/api/v1/tenants", &admin).await.body;
    let acme = tenants
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["name"] == "acme")
        .unwrap();
    assert_eq!(
        (acme["tiers"].clone(), acme["uid"].as_str().unwrap().len()),
        (json!(["gold"]), 32)
    );
    let r = t.post("/api/v1/groups", &dana, group("g1", "acme", gold)).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let g1 = r.body["id"].as_i64().unwrap();
    assert_eq!(
        t.post("/api/v1/groups", &dana, group("g2", "globex", gold))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let upd = |policy: i64| json!({"source_id": src, "policy_id": policy, "name": "g1", "guests": [100]});
    let r = t
        .put(&format!("/api/v1/groups/{}", ids["grp_globex"]), &dana, upd(gold))
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // the old (unassigned) policy of acme's group stays, but cannot be chosen again
    let r = t.put(&format!("/api/v1/groups/{g1}"), &dana, upd(pol)).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    // a weaker assigned policy: approval like for an admin; the provider decides
    let r = t.put(&format!("/api/v1/groups/{g1}"), &dana, upd(weak)).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q1 = r.body["quorum_id"].as_i64().unwrap();
    assert_eq!(
        t.post(&format!("/api/v1/quorum/{q1}/approve"), &dana, json!({}))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let r = t.delete(&format!("/api/v1/groups/{g1}"), &dana).await;
    assert_eq!(
        r.status,
        StatusCode::ACCEPTED,
        "group delete needs approval: {:?}",
        r.body
    );
    let q2 = r.body["quorum_id"].as_i64().unwrap();
    t.delete(&format!("/api/v1/groups/{}", ids["grp_globex"]), &admin).await;
    let mine = t.get("/api/v1/quorum", &dana).await.body;
    let qs: Vec<i64> = mine
        .as_array()
        .unwrap()
        .iter()
        .map(|q| q["id"].as_i64().unwrap())
        .collect();
    assert_eq!(qs, vec![q2, q1], "own requests only");
    // unassigned meanwhile: the approval is refused
    t.put("/api/v1/tenants/acme/policies", &admin, json!({"policy_ids": [gold]}))
        .await;
    let sam = t.login("sam").await;
    assert_eq!(
        t.post(&format!("/api/v1/quorum/{q1}/approve"), &sam, json!({}))
            .await
            .status,
        StatusCode::CONFLICT
    );
    let r = t.post(&format!("/api/v1/quorum/{q2}/approve"), &sam, json!({})).await;
    assert_eq!(r.body["state"], "executed", "{:?}", r.body);
    assert_eq!(
        t.delete(&format!("/api/v1/policies/{gold}"), &admin).await.status,
        StatusCode::CONFLICT,
        "still assigned"
    );

    // accounts: tenant roles in the own tenant only
    for (body, want) in [
        (json!({"name": "u1", "role": "tenant_user"}), StatusCode::CREATED),
        (
            json!({"name": "u2", "role": "viewer", "tenant": "acme"}),
            StatusCode::CREATED,
        ),
        (json!({"name": "u3", "role": "tenant_admin"}), StatusCode::CREATED),
        (json!({"name": "u4", "role": "admin"}), StatusCode::FORBIDDEN),
        (json!({"name": "u5", "role": "operator"}), StatusCode::FORBIDDEN),
        (json!({"name": "u6", "role": "security_officer"}), StatusCode::FORBIDDEN),
        (
            json!({"name": "u7", "role": "tenant_user", "tenant": "globex"}),
            StatusCode::FORBIDDEN,
        ),
    ] {
        let r = t.post("/api/v1/users", &dana, body.clone()).await;
        assert_eq!(r.status, want, "{body}: {:?}", r.body);
        if want == StatusCode::CREATED {
            assert_eq!(r.body["user"]["tenant"], "acme");
        }
    }
    let (tina, tom, otto) = (t.ids["tina"], t.ids["tom"], t.ids["otto"]);
    for (id, body, want) in [
        (tina, json!({"disabled": true}), StatusCode::OK),
        (tina, json!({"role": "admin"}), StatusCode::FORBIDDEN),
        (tina, json!({"role": "operator", "tenant": null}), StatusCode::FORBIDDEN),
        (tina, json!({"tenant": "globex"}), StatusCode::FORBIDDEN),
        (tina, json!({"role": "tenant_admin"}), StatusCode::OK),
        (tom, json!({"disabled": true}), StatusCode::FORBIDDEN),
        (otto, json!({"disabled": true}), StatusCode::FORBIDDEN),
    ] {
        let r = t.put(&format!("/api/v1/users/{id}"), &dana, body.clone()).await;
        assert_eq!(r.status, want, "{id} {body}: {:?}", r.body);
    }
    let users = t.get("/api/v1/users", &dana).await.body;
    assert!(users.as_array().unwrap().iter().all(|u| u["tenant"] == "acme"));

    // jobs: backups and restores yes, the provider's maintenance no
    let job = |kind: &str, params: Value| json!({"kind": kind, "tenant": "acme", "params": params});
    let r = t.post("/api/v1/jobs", &dana, job("backup", json!({"vmid": 100}))).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    for kind in ["retention", "gc", "offsite", "verify"] {
        assert_eq!(
            t.post("/api/v1/jobs", &dana, job(kind, json!({}))).await.status,
            StatusCode::FORBIDDEN,
            "{kind}"
        );
    }
    let r = t
        .post(
            "/api/v1/jobs",
            &dana,
            json!({"kind": "backup", "tenant": "globex", "params": {"vmid": 100}}),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(
        t.delete("/api/v1/snapshots/acme/vm-100/1000", &dana).await.status,
        StatusCode::FORBIDDEN
    );
    t.finish();
}

/// "View as tenant": read-only by default, elevated only after approval;
/// audited as the real admin plus `impersonating:<tenant>`, and those entries
/// are in the tenant admin's audit view (which shows nothing of other tenants).
#[tokio::test]
async fn impersonation_is_scoped_approved_and_visible_to_the_tenant() {
    let mut t = T::new();
    let admin = t.login("alice").await;
    seed(&t, &admin).await;
    t.add_user("dana", "tenant_admin", Some("acme"));
    let r = t.post("/api/v1/tenants/acme/impersonate", &admin, json!({})).await;
    assert_eq!(
        r.body["impersonating"],
        json!({"tenant": "acme", "role": "viewer"}),
        "{:?}",
        r.body
    );
    let me = t.get("/api/v1/auth/me", &admin).await.body;
    assert_eq!(
        (
            me["user"]["name"].clone(),
            me["user"]["role"].clone(),
            me["user"]["tenant"].clone()
        ),
        (json!("alice"), json!("viewer"), json!("acme"))
    );
    assert_eq!(me["impersonating"], json!({"tenant": "acme", "role": "viewer"}));
    let srcs = t.get("/api/v1/sources", &admin).await.body;
    assert!(srcs.as_array().unwrap().iter().all(|s| s["tenant"] == "acme"));
    let body = json!({"tenant": "acme", "kind": "pve", "name": "imp", "config": src_cfg(Some("x"))});
    assert_eq!(
        t.post("/api/v1/sources", &admin, body.clone()).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.get("/api/v1/settings/approvals", &admin).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.post("/api/v1/tenants/globex/impersonate", &admin, json!({}))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let r = t
        .post(
            "/api/v1/auth/tokens",
            &admin,
            t.reauth("alice", json!({"name": "x", "scope": "read", "days": 1})),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "no tokens while impersonating");
    assert_eq!(
        t.post("/api/v1/auth/impersonation/end", &admin, json!({})).await.status,
        StatusCode::OK
    );
    assert_eq!(
        t.get("/api/v1/auth/me", &admin).await.body["impersonating"],
        Value::Null
    );
    assert_eq!(
        t.post("/api/v1/auth/impersonation/end", &admin, json!({})).await.status,
        StatusCode::CONFLICT
    );

    // elevated: approval by someone else; then the session acts as acme's tenant admin
    let r = t
        .post("/api/v1/tenants/acme/impersonate", &admin, json!({"elevated": true}))
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    assert_eq!(
        t.get("/api/v1/auth/me", &admin).await.body["impersonating"],
        Value::Null
    );
    let sam = t.login("sam").await;
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.body["state"], "executed", "{:?}", r.body);
    let me = t.get("/api/v1/auth/me", &admin).await.body;
    assert_eq!(me["impersonating"], json!({"tenant": "acme", "role": "tenant_admin"}));
    assert_eq!(me["user"]["can_download"], false);
    let r = t.post("/api/v1/sources", &admin, body).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(t.get("/api/v1/quorum", &admin).await.status, StatusCode::OK);
    assert_eq!(
        t.post(&format!("/api/v1/quorum/{q}/approve"), &admin, json!({}))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let actor: String = t.scalar("SELECT actor FROM audit WHERE action = 'source.create' ORDER BY seq DESC LIMIT 1");
    assert_eq!(actor, "alice impersonating:acme");
    t.post("/api/v1/auth/impersonation/end", &admin, json!({})).await;
    // approvals off: directly
    t.set_approvals(false);
    let r = t
        .post("/api/v1/tenants/acme/impersonate", &admin, json!({"elevated": true}))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        t.get("/api/v1/auth/me", &admin).await.body["impersonating"]["role"],
        "tenant_admin"
    );
    t.post("/api/v1/auth/impersonation/end", &admin, json!({})).await;
    // demoted admins lose the view
    t.post("/api/v1/tenants/acme/impersonate", &admin, json!({})).await;
    t.st.cat
        .conn()
        .execute("UPDATE users SET role = 'operator' WHERE name = 'alice'", [])
        .unwrap();
    let me = t.get("/api/v1/auth/me", &admin).await.body;
    assert_eq!(
        (me["user"]["role"].clone(), me["impersonating"].clone()),
        (json!("operator"), Value::Null)
    );
    t.st.cat
        .conn()
        .execute("UPDATE users SET role = 'admin' WHERE name = 'alice'", [])
        .unwrap();

    // the tenant's admin reads the impersonation entries, nothing of globex
    let dana = t.login("dana").await;
    let log = t.get("/api/v1/audit?limit=1000", &dana).await.body;
    let log = log.as_array().unwrap();
    assert!(log
        .iter()
        .any(|e| e["actor"] == "alice impersonating:acme" && e["action"] == "source.create"));
    assert!(log
        .iter()
        .any(|e| e["action"] == "tenant.impersonate" && e["target"] == "tenant/acme"));
    assert!(log.iter().any(|e| e["action"] == "tenant.impersonate_end"));
    assert!(!log.iter().any(|e| e.to_string().contains("globex")), "{log:?}");
    let all: i64 = t.scalar("SELECT COUNT(*) FROM audit");
    assert!((log.len() as i64) < all);
    let r = t.get("/api/v1/audit?tenant=globex", &dana).await.body;
    assert_eq!(r.as_array().unwrap().len(), log.len(), "own tenant forced");
    let csv = t.get("/api/v1/audit.csv", &dana).await;
    assert!(!String::from_utf8_lossy(&csv.raw).contains("globex"));
    let g = t.get("/api/v1/audit?tenant=globex", &admin).await.body;
    assert!(
        !g.as_array().unwrap().is_empty() && g.as_array().unwrap().iter().all(|e| e.to_string().contains("globex"))
    );
    t.finish();
}

/// Deleted tenant names are never handed out again; uids are fixed.
#[tokio::test]
async fn tenant_names_are_tombstoned_and_uids_immutable() {
    let t = T::new();
    let admin = t.login("alice").await;
    t.set_approvals(false);
    assert_eq!(
        t.post("/api/v1/tenants", &admin, json!({"name": "temp"})).await.status,
        StatusCode::CREATED
    );
    let uid: String = t.scalar("SELECT uid FROM tenants WHERE name = 'temp'");
    let r = t.delete("/api/v1/tenants/temp", &admin).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let r = t.post("/api/v1/tenants", &admin, json!({"name": "temp"})).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
    let tomb = t.get("/api/v1/tenants/tombstones", &admin).await.body;
    assert_eq!(tomb[0]["name"], "temp");
    assert_eq!(tomb[0]["uid"], json!(uid));
    assert_eq!(tomb[0]["deleted_by"], "alice");
    assert!(t
        .st
        .cat
        .conn()
        .execute("UPDATE tenants SET uid = 'x' WHERE name = 'acme'", [])
        .is_err());
    t.finish();
}
