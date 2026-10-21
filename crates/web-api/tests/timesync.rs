//! Settings > Time: the status of nexus-time, validation (plain NTP only with the explicit opt-in),
//! approval and the request file, RBAC. The helper is simulated by writing its status.json.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use catalog::rusqlite::params;
use catalog::secret::TotpKey;
use catalog::Catalog;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
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
    time: PathBuf,
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

fn status(now: i64, servers: Value) -> Value {
    json!({"scanned": now, "servers": servers, "allow_ntp": false,
           "sources": [{"name": "ptbtime2.ptb.de", "state": "selected", "stratum": 1, "reach": 255,
                        "last_rx": 879, "offset": 0.0003, "error": 0.0068, "nts": true}],
           "tracking": {"reference": "C0356768", "stratum": 2, "offset": -0.00006, "leap": "Normal", "synced": true},
           "chrony_error": null, "last": null})
}

fn defaults() -> Value {
    json!([{"host": "time.cloudflare.com", "nts": true}, {"host": "ptbtime1.ptb.de", "nts": true}])
}

impl T {
    fn new() -> T {
        let dir = tempfile::tempdir().unwrap();
        let cat = Catalog::open(&dir.path().join("catalog.db")).unwrap();
        let downloads = dir.path().join("downloads");
        std::fs::create_dir(&downloads).unwrap();
        let st = AppState::with_keys(cat, None, downloads, TotpKey::generate(), None);
        let time = dir.path().join("time");
        std::fs::create_dir(&time).unwrap();
        st.time_dir.set(time.clone()).unwrap();
        st.cat
            .conn()
            .execute("INSERT INTO tenants (name) VALUES ('acme')", [])
            .unwrap();
        let mut secrets = HashMap::new();
        for (n, role, tenant) in [
            ("alice", "admin", None),
            ("ada", "admin", None),
            ("otto", "operator", None),
            ("vic", "viewer", None),
            ("vera", "viewer", Some("acme")),
        ] {
            let secret = catalog::auth::new_totp_secret();
            let enc = st.totp.encrypt(n, &secret).unwrap();
            st.cat
                .conn()
                .execute(
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
            time,
            _dir: dir,
        }
    }

    fn helper_status(&self, s: &Value) {
        std::fs::write(self.time.join("status.json"), s.to_string()).unwrap();
    }

    /// The request nexus-time would pick up (removed, as the helper does).
    fn take_request(&self) -> Option<Value> {
        let p = self.time.join("request.json");
        let v = serde_json::from_slice(&std::fs::read(&p).ok()?).unwrap();
        std::fs::remove_file(p).unwrap();
        Some(v)
    }

    async fn put_time(&self, s: &S, servers: Value, allow_ntp: bool) -> R {
        let body = json!({"servers": servers, "allow_ntp": allow_ntp});
        self.call(Method::PUT, "/api/v1/settings/time", Some(s), Some(body))
            .await
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
        let raw = res.into_body().collect().await.unwrap().to_bytes().to_vec();
        R {
            status,
            body: serde_json::from_slice(&raw).unwrap_or(Value::Null),
        }
    }

    fn audit_count(&self, action: &str) -> i64 {
        self.st
            .cat
            .conn()
            .query_row("SELECT COUNT(*) FROM audit WHERE action = ?1", [action], |r| r.get(0))
            .unwrap()
    }
}

async fn login(t: &T, name: &str) -> S {
    let code = catalog::auth::totp_now(&t.secrets[name]).unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/login")
        .header(header::HOST, "nexus.test")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"name": name, "password": PW, "totp": code}).to_string(),
        ))
        .unwrap();
    let res = t.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK, "{name}");
    let cookie = res
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| c.strip_prefix("nx_session=")?.split(';').next().map(str::to_owned))
        .unwrap();
    let raw = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&raw).unwrap();
    S {
        cookie,
        csrf: body["csrf"].as_str().unwrap().to_owned(),
    }
}

#[tokio::test]
async fn status_roles_and_validation() {
    let t = T::new();
    let (alice, otto, vic, vera) = (
        login(&t, "alice").await,
        login(&t, "otto").await,
        login(&t, "vic").await,
        login(&t, "vera").await,
    );
    let r = t.call(Method::GET, "/api/v1/settings/time", Some(&vic), None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body["available"], false);
    t.helper_status(&status(catalog::now(), defaults()));
    for s in [&alice, &otto, &vic] {
        let r = t.call(Method::GET, "/api/v1/settings/time", Some(s), None).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.body["servers"], defaults());
        assert_eq!(r.body["sources"][0]["state"], "selected");
        assert_eq!(r.body["tracking"]["synced"], true);
        assert_eq!(r.body["stale"], false);
    }
    // appliance-wide: never for tenant-scoped accounts
    let r = t.call(Method::GET, "/api/v1/settings/time", Some(&vera), None).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // only admins change it
    let one = json!([{"host": "nts.internal.example", "nts": true}]);
    assert_eq!(
        t.put_time(&otto, one.clone(), false).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.put_time(&vera, one.clone(), false).await.status,
        StatusCode::FORBIDDEN
    );
    // refused at once: bad host, duplicate, none, plain NTP without the opt-in
    for (servers, allow) in [
        (json!([{"host": "bad host", "nts": true}]), false),
        (
            json!([{"host": "a.example", "nts": true}, {"host": "A.example", "nts": true}]),
            false,
        ),
        (json!([]), false),
        (json!([{"host": "ntp.internal", "nts": false}]), false),
    ] {
        let r = t.put_time(&alice, servers.clone(), allow).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{servers}: {:?}", r.body);
    }
    let r = t
        .put_time(&alice, json!([{"host": "ntp.internal", "nts": false}]), false)
        .await;
    assert!(
        r.body["error"].as_str().unwrap_or_default().contains("allow_ntp"),
        "{:?}",
        r.body
    );
    // the configured list again: nothing to do
    let r = t.put_time(&alice, defaults(), false).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body["unchanged"], true);
    assert!(t.take_request().is_none());
}

#[tokio::test]
async fn change_needs_approval_then_request_file() {
    let t = T::new();
    let (alice, ada) = (login(&t, "alice").await, login(&t, "ada").await);
    t.helper_status(&status(catalog::now(), defaults()));
    let servers = json!([{"host": "nts.internal.example", "nts": true}, {"host": "10.0.0.5", "nts": false}]);
    let r = t.put_time(&alice, servers.clone(), true).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let qid = r.body["quorum_id"].as_i64().unwrap();
    assert!(t.take_request().is_none(), "nothing before the approval");
    let r = t.call(Method::GET, "/api/v1/settings/time", Some(&alice), None).await;
    assert_eq!(r.body["request_pending"], qid);
    let r = t
        .call(
            Method::POST,
            &format!("/api/v1/quorum/{qid}/approve"),
            Some(&ada),
            Some(json!({})),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["state"], "executed");
    let q = t.take_request().expect("request.json for nexus-time");
    assert_eq!((q["by"].as_str(), q["quorum_id"].as_i64()), (Some("alice"), Some(qid)));
    assert_eq!(q["servers"], servers);
    assert_eq!(q["allow_ntp"], true);
    assert_eq!(q["id"].as_str().map(str::len), Some(32));
    assert_eq!(t.audit_count("time.servers"), 1);
    // the approver saw which servers are unauthenticated
    let p: String =
        t.st.cat
            .conn()
            .query_row("SELECT params FROM quorum WHERE id = ?1", [qid], |r| r.get(0))
            .unwrap();
    assert!(p.contains("\"plain_ntp\":[\"10.0.0.5\"]"), "{p}");

    // approvals off: the request file at once
    catalog::set_setting(&t.st.cat.conn(), "approvals_enabled", "false").unwrap();
    let r = t
        .put_time(&alice, json!([{"host": "nts.internal.example", "nts": true}]), false)
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["executed"], true);
    assert_eq!(t.take_request().unwrap()["allow_ntp"], false);
    assert_eq!(t.audit_count("time.servers"), 2);
}
