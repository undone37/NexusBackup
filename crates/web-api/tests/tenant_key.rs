//! Phase 17e tenant recovery key: `tenant.recovery_key` through the quorum,
//! shown once to the requester, only the public key kept, RBAC (tenant-scoped
//! admins for their own tenant), replacement, the key never in the audit log
//! or the catalog, and keyd sealing to the stored public key.

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
            ("bob", "admin", None),
            ("sam", "security_officer", None),
            ("otto", "operator", None),
            ("tina", "tenant_user", Some("acme")),
            ("gadmin", "admin", Some("globex")),
            ("tadmin", "admin", Some("acme")),
        ] {
            let secret = catalog::auth::new_totp_secret();
            let enc = st.totp.encrypt(n, &secret).unwrap();
            let c = st.cat.conn();
            if let Some(t) = tenant {
                c.execute("INSERT OR IGNORE INTO tenants (name) VALUES (?1)", [t])
                    .unwrap();
            }
            c.execute(
                "INSERT INTO users (name, password_hash, totp_secret, role, tenant, created) VALUES (?1,?2,?3,?4,?5,0)",
                params![n, pw_hash(), enc, role, tenant],
            )
            .unwrap();
            secrets.insert(n.to_owned(), secret);
        }
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

    fn approvals(&self, on: bool) {
        catalog::set_setting(
            &self.st.cat.conn(),
            "approvals_enabled",
            if on { "true" } else { "false" },
        )
        .unwrap();
    }

    fn count(&self, sql: &str) -> i64 {
        self.st.cat.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }
}

fn path(t: &str) -> String {
    format!("/api/v1/tenants/{t}/recovery-key")
}

impl T {
    /// No trace of the key anywhere in the catalog (audit, quorum, settings).
    fn assert_secret_absent(&self, key: &str) {
        let raw: String = key.chars().filter(|c| *c != '-').collect();
        let c = self.st.cat.conn();
        for sql in [
            "SELECT details FROM audit",
            "SELECT params FROM quorum",
            "SELECT value FROM settings",
            "SELECT message FROM alerts",
        ] {
            let mut q = c.prepare(sql).unwrap();
            for v in q.query_map([], |r| r.get::<_, String>(0)).unwrap() {
                let v = v.unwrap().to_lowercase();
                assert!(!v.contains(key) && !v.contains(&raw), "{sql}: key leaked");
            }
        }
    }
}

#[tokio::test]
async fn tenant_key_quorum_show_once_replace() {
    let t = T::new();
    t.approvals(true);
    let (alice, bob, sam, otto, tina, tadmin, gadmin) = (
        t.login("alice").await,
        t.login("bob").await,
        t.login("sam").await,
        t.login("otto").await,
        t.login("tina").await,
        t.login("tadmin").await,
        t.login("gadmin").await,
    );
    let p = path("acme");
    assert_eq!(
        t.post(&path("nope"), &alice, json!({})).await.status,
        StatusCode::NOT_FOUND
    );
    for s in [&sam, &otto, &tina, &gadmin] {
        assert_eq!(t.post(&p, s, json!({})).await.status, StatusCode::FORBIDDEN);
    }
    for s in [&otto, &tina, &gadmin] {
        assert_eq!(t.get(&p, s).await.status, StatusCode::FORBIDDEN);
    }
    let st = t.get(&p, &sam).await;
    assert_eq!(st.status, StatusCode::OK);
    assert_eq!(st.body["key"], Value::Null);

    // a tenant-scoped admin requests for its own tenant
    let r = t.post(&p, &tadmin, json!({})).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let id = r.body["quorum_id"].as_i64().unwrap();
    assert_eq!(
        t.post(&p, &alice, json!({})).await.status,
        StatusCode::CONFLICT,
        "one open request"
    );
    let show = format!("{p}/{id}/show");
    assert_eq!(
        t.post(&show, &tadmin, json!({})).await.status,
        StatusCode::CONFLICT,
        "pending"
    );
    assert_eq!(
        t.post(&format!("/api/v1/quorum/{id}/approve"), &tadmin, json!({}))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let a = t.post(&format!("/api/v1/quorum/{id}/approve"), &bob, json!({})).await;
    assert_eq!(a.status, StatusCode::OK, "{:?}", a.body);
    assert_eq!(a.body["state"], "approved");
    assert_eq!(
        t.post(&show, &bob, json!({})).await.status,
        StatusCode::FORBIDDEN,
        "requester only"
    );
    let k = t.post(&show, &tadmin, json!({})).await;
    assert_eq!(k.status, StatusCode::OK, "{:?}", k.body);
    let key = k.body["key"].as_str().unwrap().to_owned();
    assert_eq!(key.split(' ').count(), 24);
    assert_eq!(k.body["replaced"], Value::Null);
    assert_eq!(
        t.post(&show, &tadmin, json!({})).await.status,
        StatusCode::CONFLICT,
        "shown once"
    );

    // only the public key is kept; keyd seals to it and the key opens the escrow
    let stored = catalog::tenant_key::get(&t.st.cat.conn(), "acme").unwrap().unwrap();
    let public = keyd::tenant_key::public_of(&key).unwrap();
    assert_eq!(catalog::tenant_key::parse_public(&stored.public).unwrap(), public);
    assert_eq!(
        (stored.requested_by.as_str(), stored.approved_by.as_str()),
        ("tadmin", "bob")
    );
    let kd = tempfile::tempdir().unwrap();
    keyd::init(kd.path()).unwrap();
    keyd::create_tenant(kd.path(), "acme").unwrap();
    keyd::tenant_key::set(kd.path(), "acme", Some(&public)).unwrap();
    let files: Vec<_> = keyd::export_escrow(kd.path(), "acme")
        .unwrap()
        .into_iter()
        .filter_map(|(n, b)| Some((n.strip_prefix("tenants/acme/")?.to_owned(), b)))
        .collect();
    assert_eq!(keyd::tenant_key::open("acme", &key, &files).unwrap().len(), 1);

    let st = t.get(&p, &tadmin).await;
    assert_eq!(st.body["key"]["kid"], stored.kid);
    assert_eq!(st.body["requests"][0]["status"], "shown");
    assert!(!st.body.to_string().contains(&key));
    let audit = t.count(&format!(
        "SELECT COUNT(*) FROM audit WHERE action = 'tenant.recovery_key_shown' AND details LIKE '%{}%'",
        stored.kid
    ));
    assert_eq!(audit, 1);
    t.assert_secret_absent(&key);

    // replacing needs approval again; approvals disabled: approved at once, shown by the requester
    t.approvals(false);
    let r = t.post(&p, &alice, json!({})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["state"], "approved");
    let id2 = r.body["quorum_id"].as_i64().unwrap();
    let k2 = t.post(&format!("{p}/{id2}/show"), &alice, json!({})).await;
    assert_eq!(k2.status, StatusCode::OK);
    assert_eq!(k2.body["replaced"], stored.kid.as_str());
    let key2 = k2.body["key"].as_str().unwrap().to_owned();
    assert_ne!(key2, key);
    let stored2 = catalog::tenant_key::get(&t.st.cat.conn(), "acme").unwrap().unwrap();
    assert_eq!(
        catalog::tenant_key::parse_public(&stored2.public).unwrap(),
        keyd::tenant_key::public_of(&key2).unwrap()
    );
    t.assert_secret_absent(&key2);
    // other tenants are untouched
    assert!(catalog::tenant_key::get(&t.st.cat.conn(), "globex").unwrap().is_none());
}

#[tokio::test]
async fn rejected_and_expired_requests_show_nothing() {
    let t = T::new();
    t.approvals(true);
    let (alice, bob) = (t.login("alice").await, t.login("bob").await);
    let p = path("acme");
    let id = t.post(&p, &alice, json!({})).await.body["quorum_id"].as_i64().unwrap();
    t.post(&format!("/api/v1/quorum/{id}/reject"), &bob, json!({})).await;
    assert_eq!(
        t.post(&format!("{p}/{id}/show"), &alice, json!({})).await.status,
        StatusCode::CONFLICT
    );
    // approved more than 24 h ago: expired
    let id = t.post(&p, &alice, json!({})).await.body["quorum_id"].as_i64().unwrap();
    t.post(&format!("/api/v1/quorum/{id}/approve"), &bob, json!({})).await;
    t.st.cat
        .conn()
        .execute("UPDATE quorum SET decided_at = decided_at - 90000 WHERE id = ?1", [id])
        .unwrap();
    assert_eq!(
        t.post(&format!("{p}/{id}/show"), &alice, json!({})).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(t.get(&p, &alice).await.body["requests"][0]["status"], "expired");
    assert!(catalog::tenant_key::get(&t.st.cat.conn(), "acme").unwrap().is_none());
    // a new request is possible again
    assert_eq!(t.post(&p, &alice, json!({})).await.status, StatusCode::ACCEPTED);
}
