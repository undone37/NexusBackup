//! In-process integration tests: the axum Router is driven with
//! `tower::ServiceExt::oneshot` (no TLS, no sockets).

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use axum::Router;
use catalog::rusqlite::params;
use catalog::secret::{source_owner, SchedulerKey, TotpKey};
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
        t.post(
            "/api/v1/users",
            &so,
            json!({"name": "x", "password": PW, "role": "operator"})
        )
        .await
        .status,
        forbidden
    );
    assert_eq!(t.get("/api/v1/audit", &so).await.status, StatusCode::OK);
    assert_eq!(t.get("/api/v1/audit/verify", &so).await.body["ok"], json!(true));
    assert_eq!(t.get("/api/v1/sources", &so).await.status, StatusCode::OK);

    // admin cannot decide quorum requests
    assert_eq!(
        t.post("/api/v1/quorum/1/approve", &admin, json!({})).await.status,
        forbidden
    );
    assert_eq!(
        t.post("/api/v1/quorum/1/reject", &admin, json!({})).await.status,
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
    assert_eq!(
        t.get("/api/v1/tenants", &tina).await.body,
        json!([{"name": "acme", "offsite": {}}])
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

    let r = t
        .post(
            "/api/v1/users",
            &admin,
            json!({"name": "olga", "password": PW, "role": "operator"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert!(r.body["totp_uri"]
        .as_str()
        .unwrap()
        .starts_with("otpauth://totp/NexusBackup:olga?"));
    let olga = r.body["user"]["id"].as_i64().unwrap();
    assert_eq!(
        t.post(
            "/api/v1/users",
            &admin,
            json!({"name": "short", "password": "short", "role": "operator"})
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        t.post(
            "/api/v1/users",
            &admin,
            json!({"name": "tu", "password": PW, "role": "tenant_user"})
        )
        .await
        .status,
        StatusCode::BAD_REQUEST,
        "tenant required"
    );

    // new admin: created disabled + quorum
    let r = t
        .post(
            "/api/v1/users",
            &admin,
            json!({"name": "ada", "password": PW, "role": "admin"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    assert!(r.body["totp_uri"].is_string() && r.body["user"]["disabled"] == json!(true));
    let q = r.body["quorum_id"].as_i64().unwrap();
    let ada = r.body["user"]["id"].as_i64().unwrap();
    let secret: String =
        t.st.cat
            .conn()
            .query_row("SELECT totp_secret FROM users WHERE id = ?1", [ada], |r| r.get(0))
            .unwrap();
    assert!(secret.starts_with("enc:v1:"), "TOTP seed stored encrypted");
    let secret = t.st.totp.decrypt("ada", &secret).unwrap().to_string();
    t.secrets.insert("ada".into(), secret);
    assert_eq!(
        t.try_login("ada", &t.code("ada"), Some("10.1.1.1")).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({}))
            .await
            .status,
        StatusCode::OK
    );
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
    // resetting a security officer's credentials is gated; the quorum list hides the new secrets
    let r = t
        .put(
            &format!("/api/v1/users/{}", t.ids["sam"]),
            &admin,
            t.reauth("alice", json!({"reset_totp": true, "password": "a brand new password"})),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    assert!(r.body["totp_uri"].is_string());
    let list = t.get("/api/v1/quorum?state=pending", &sam).await;
    let raw = String::from_utf8(list.raw).unwrap();
    assert!(raw.contains("<redacted>") && !raw.contains("$argon2id$"));
    // a plain operator reset is direct
    let r = t
        .put(
            &format!("/api/v1/users/{olga}"),
            &admin,
            t.reauth("alice", json!({"reset_totp": true})),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body["totp_uri"].is_string());

    let users = t.get("/api/v1/users", &admin).await;
    let raw = String::from_utf8(users.raw).unwrap();
    assert!(!raw.contains("password_hash") && !raw.contains("totp_secret") && !raw.contains("$argon2"));
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
    ];
    t.st.cat
        .conn()
        .execute(
            "INSERT INTO alerts (ts, severity, kind, message) VALUES (1, 'warning', 'capacity', 'x')",
            [],
        )
        .unwrap();
    let alert = t.scalar::<i64>("SELECT MAX(id) FROM alerts");
    // a pending request for the approve/reject rows
    let r = t.delete(&format!("/api/v1/groups/{}", ids["grp_globex"]), &admin).await;
    let qid = r.body["quorum_id"].as_i64().unwrap();
    let (src, grp, pol, job) = (ids["src_acme"], ids["grp_acme"], ids["policy"], ids["job_acme"]);
    let all = "ASOT";

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
            "A",
        ),
        (
            Method::PUT,
            format!("/api/v1/sources/{src}"),
            Some(json!({"name": "pve", "config": src_cfg(None)})),
            "A",
        ),
        (Method::DELETE, format!("/api/v1/sources/{src}"), None, "A"),
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
            "A",
        ),
        (
            Method::PUT,
            format!("/api/v1/groups/{grp}"),
            Some(json!({"source_id": src, "policy_id": pol, "name": "prod", "guests": [100, 101, 102]})),
            "A",
        ),
        (Method::GET, "/api/v1/users".into(), None, all),
        (
            Method::POST,
            "/api/v1/users".into(),
            Some(json!({"name": "rbac-u", "password": PW, "role": "operator"})),
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
            "A",
        ),
        (
            Method::POST,
            format!("/api/v1/agents/{agent}/token"),
            Some(json!({})),
            "A",
        ),
        (
            Method::POST,
            format!("/api/v1/agents/{agent}/enroll"),
            Some(json!({})),
            "A",
        ),
        (Method::DELETE, format!("/api/v1/agents/{agent}"), None, "A"),
        (
            Method::POST,
            "/api/v1/jobs".into(),
            Some(json!({"kind": "agent_update", "tenant": "acme", "params": {"agent_id": agent}})),
            "A",
        ),
        (
            Method::POST,
            "/api/v1/jobs".into(),
            Some(
                json!({"kind": "restore_files", "tenant": "acme", "params": {"source": format!("host-{agent}"),
                        "time": 2000, "paths": ["/etc"], "target": "/srv", "overwrite": "never", "confirm": "web01"}}),
            ),
            "AOT",
        ),
        (Method::GET, "/api/v1/snapshots".into(), None, all),
        (Method::GET, "/api/v1/jobs".into(), None, all),
        (Method::GET, format!("/api/v1/jobs/{job}"), None, all),
        (
            Method::POST,
            "/api/v1/jobs".into(),
            Some(json!({"kind": "backup", "tenant": "acme", "params": {"vmid": 100}})),
            "AO",
        ),
        (
            Method::POST,
            "/api/v1/jobs".into(),
            Some(
                json!({"kind": "files_list", "tenant": "acme", "params": {"source": "vm-100", "time": 1000, "path": "/"}}),
            ),
            "AOT",
        ),
        (
            Method::POST,
            format!("/api/v1/jobs/{job}/cancel"),
            Some(json!({})),
            "AO",
        ),
        (Method::GET, format!("/api/v1/downloads/{}", "ab".repeat(32)), None, all),
        (Method::GET, "/api/v1/quorum".into(), None, "ASO"),
        (Method::GET, "/api/v1/audit".into(), None, "AS"),
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
            "S",
        ),
        (
            Method::POST,
            format!("/api/v1/quorum/{qid}/approve"),
            Some(json!({})),
            "S",
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
    let t = T::new();
    let admin = t.login("alice").await;
    for role in ["admin", "security_officer"] {
        let r = t
            .post(
                "/api/v1/users",
                &admin,
                json!({"name": format!("scoped-{role}"), "password": PW, "role": role, "tenant": "acme"}),
            )
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{role}: {:?}", r.body);
    }
    // promoting a scoped operator keeps the scope -> refused; with the scope cleared -> quorum
    let r = t
        .post(
            "/api/v1/users",
            &admin,
            json!({"name": "scoped-op", "password": PW, "role": "operator", "tenant": "acme"}),
        )
        .await;
    let id = r.body["user"]["id"].as_i64().unwrap();
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

/// Review M-5: password / TOTP changes need the actor's current password and
/// a fresh TOTP code; failures are audited, count toward the login limiter,
/// and a code cannot be used twice.
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
        json!({"password": "a brand new password"}),
        json!({"reset_totp": true, "current_password": PW}),
        json!({"reset_totp": true, "current_totp": "123456"}),
    ] {
        let r = t.put(&url, &admin, body).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
        assert!(r.body["error"].as_str().unwrap().contains("current_password"));
    }
    // wrong password, wrong code
    let mut wrong_pw = t.reauth("alice", json!({"password": "a brand new password"}));
    wrong_pw["current_password"] = json!("not the password");
    assert_eq!(t.put(&url, &admin, wrong_pw).await.status, StatusCode::FORBIDDEN);
    let code = t.code("alice");
    let wrong_totp =
        json!({"password": "a brand new password", "current_password": PW, "current_totp": wrong_code(&code)});
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
    let ok = json!({"password": "a brand new password", "current_password": PW, "current_totp": code});
    let r = t.put(&url, &admin, ok.clone()).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_ne!(olga_hash(&t), before);
    let r = t.put(&url, &admin, ok).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{:?}", r.body);
    assert_eq!(
        t.scalar::<String>("SELECT json_extract(details, '$.reason') FROM audit WHERE action = 'auth.reauth_failed' ORDER BY seq DESC LIMIT 1"),
        "totp replay"
    );
    // TOTP reset: new seed stored encrypted for olga
    let r = t
        .put(&url, &admin, t.reauth("alice", json!({"reset_totp": true})))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let seed = t.scalar::<String>(&format!("SELECT totp_secret FROM users WHERE id = {}", t.ids["olga"]));
    assert!(seed.starts_with("enc:v1:"));
    let uri = r.body["totp_uri"].as_str().unwrap();
    let plain = t.st.totp.decrypt("olga", &seed).unwrap();
    assert!(uri.contains(&format!("secret={}", plain.as_str())));
    // role changes alone need no re-authentication
    assert_eq!(
        t.put(&url, &admin, json!({"disabled": true})).await.status,
        StatusCode::OK
    );

    // own password: re-authenticated, then the own sessions end
    let me = format!("/api/v1/users/{}", t.ids["alice"]);
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
        let mut b = t.reauth("adam", json!({"reset_totp": true}));
        b["current_password"] = json!("not the password");
        assert_eq!(t.put(&url, &admin, b).await.status, StatusCode::FORBIDDEN);
    }
    assert!(t.audit_actions().iter().any(|a| a == "auth.lockout"));
    // locked: even correct credentials are refused, for re-auth and login alike
    let r = t.put(&url, &admin, t.reauth("adam", json!({"reset_totp": true}))).await;
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
    assert_eq!(
        r.body["install_command"],
        format!("/usr/local/sbin/nexus-agent init --token {token}")
    );
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
        .post("/api/v1/sources", &admin, src(truenas_cfg(Some("1-s3cr3tapikey"), Some(key))))
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

    // groups: guests are datasets of the source (empty = all)
    let pol = t.post("/api/v1/policies", &admin, policy(7, false)).await.body["id"]
        .as_i64()
        .unwrap();
    let group = |name: &str, guests: Value| {
        json!({"tenant": "acme", "source_id": sid, "policy_id": pol, "name": name, "guests": guests})
    };
    let g = t.post("/api/v1/groups", &admin, group("nas", json!([]))).await;
    assert_eq!(g.status, StatusCode::CREATED, "{:?}", g.body);
    assert_eq!(g.body["guests"], json!(["tank/data", "tank/smb"]));
    let g = t.post("/api/v1/groups", &admin, group("nas2", json!(["tank/smb"]))).await;
    assert_eq!(g.status, StatusCode::CREATED);
    let g = t.post("/api/v1/groups", &admin, group("nas3", json!(["tank/other"]))).await;
    assert_eq!(g.status, StatusCode::BAD_REQUEST);

    // file jobs accept nas-<id>-<dataset> snapshots; restore_files does not (download only)
    let snap = format!("nas-{sid}-tank.data");
    t.st.cat
        .conn()
        .execute(
            "INSERT INTO snapshots (tenant, source, time, size, local, offsite) VALUES ('acme', ?1, 1000, 1, 1, 0)",
            [&snap],
        )
        .unwrap();
    let files = |source: &str| {
        json!({"kind": "files_list", "tenant": "acme", "params": {"source": source, "time": 1000, "path": "/"}})
    };
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
