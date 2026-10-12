//! Phase 14b diagnostics: self-check and support-bundle requests for nexus-diag
//! (request.json in the control dir), results and the bundle download. The helper
//! is simulated by writing its result files.

use axum::body::Body;
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use axum::Router;
use catalog::rusqlite::params;
use catalog::secret::TotpKey;
use catalog::Catalog;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};
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
    diag: PathBuf,
    _dir: tempfile::TempDir,
}

struct S {
    cookie: String,
    csrf: String,
}

struct R {
    status: StatusCode,
    headers: HeaderMap,
    raw: Vec<u8>,
    body: Value,
}

impl T {
    fn new() -> T {
        let dir = tempfile::tempdir().unwrap();
        let cat = Catalog::open(&dir.path().join("catalog.db")).unwrap();
        let downloads = dir.path().join("downloads");
        std::fs::create_dir(&downloads).unwrap();
        let st = AppState::with_keys(cat, None, downloads, TotpKey::generate(), None);
        let diag = dir.path().join("diag");
        std::fs::create_dir(&diag).unwrap();
        st.diag_dir.set(diag.clone()).unwrap();
        st.cat
            .conn()
            .execute("INSERT INTO tenants (name) VALUES ('acme')", [])
            .unwrap();
        let mut secrets = HashMap::new();
        for (n, role, tenant) in [
            ("alice", "admin", None),
            ("ada", "admin", None),
            ("sam", "security_officer", None),
            ("otto", "operator", None),
            ("tina", "tenant_user", Some("acme")),
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
            diag,
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
        let headers = res.headers().clone();
        let raw = res.into_body().collect().await.unwrap().to_bytes().to_vec();
        R {
            status,
            headers,
            body: serde_json::from_slice(&raw).unwrap_or(Value::Null),
            raw,
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
        let cookie = r
            .headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|c| c.strip_prefix("nx_session=")?.split(';').next().map(str::to_owned))
            .unwrap();
        S {
            cookie,
            csrf: r.body["csrf"].as_str().unwrap().to_owned(),
        }
    }

    fn request(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.diag.join("request.json")).unwrap()).unwrap()
    }

    /// What nexus-diag does with the pending request.
    fn helper_runs(&self, created: i64) -> String {
        let r = self.request();
        std::fs::remove_file(self.diag.join("request.json")).unwrap();
        let id = r["id"].as_str().unwrap().to_owned();
        let out = self.diag.join(&id);
        std::fs::create_dir(&out).unwrap();
        let checks = json!([{"id": "selinux", "title": "SELinux mode", "status": "pass", "severity": 1,
                             "detail": "enforcing", "manual": "15-troubleshooting-faq.md#check-selinux"}]);
        std::fs::write(out.join("checks.json"), checks.to_string()).unwrap();
        let mut files = json!({"checks.json": 10});
        if r["kind"] == "bundle" {
            std::fs::write(out.join("bundle.tar.gz"), b"\x1f\x8bfake-bundle").unwrap();
            files["bundle.tar.gz"] = json!(13);
        }
        let st = json!({"id": id, "kind": r["kind"], "by": r["by"], "since": r["since"], "until": r["until"],
                        "created": created, "finished": created + 5, "state": "done", "error": null, "files": files});
        std::fs::write(out.join("status.json"), st.to_string()).unwrap();
        id
    }

    fn audit_count(&self, action: &str) -> i64 {
        self.st
            .cat
            .conn()
            .query_row("SELECT COUNT(*) FROM audit WHERE action = ?1", [action], |r| r.get(0))
            .unwrap()
    }
}

fn age(p: &Path, secs: u64) {
    let f = std::fs::File::options().write(true).open(p).unwrap();
    f.set_modified(SystemTime::now() - Duration::from_secs(secs)).unwrap();
}

#[tokio::test]
async fn roles_requests_and_audit() {
    let t = T::new();
    let (alice, sam, otto, tina) = (
        t.login("alice").await,
        t.login("sam").await,
        t.login("otto").await,
        t.login("tina").await,
    );
    for s in [&otto, &tina] {
        assert_eq!(t.get("/api/v1/diagnostics", s).await.status, StatusCode::FORBIDDEN);
        assert_eq!(
            t.post("/api/v1/diagnostics/checks", s, json!({})).await.status,
            StatusCode::FORBIDDEN
        );
    }
    // security officers run checks, never bundles
    assert_eq!(
        t.post("/api/v1/diagnostics/bundle", &sam, json!({})).await.status,
        StatusCode::FORBIDDEN
    );
    let r = t.post("/api/v1/diagnostics/checks", &sam, json!({})).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let id = r.body["id"].as_str().unwrap().to_owned();
    assert_eq!(t.request(), json!({"id": id, "kind": "checks", "by": "sam"}));
    assert_eq!(t.audit_count("diag.checks"), 1);
    // queued, visible to every reader
    let r = t.get(&format!("/api/v1/diagnostics/{id}"), &alice).await;
    assert_eq!((r.status, r.body["state"].as_str()), (StatusCode::OK, Some("queued")));
    // one request at a time
    let r = t.post("/api/v1/diagnostics/bundle", &alice, json!({})).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
    // a request nobody picked up for 10 min is replaced
    age(&t.diag.join("request.json"), 700);
    let now = catalog::now();
    let r = t
        .post(
            "/api/v1/diagnostics/bundle",
            &alice,
            json!({"since": now - 7200, "until": now - 3600}),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let req = t.request();
    assert_eq!(
        (
            req["kind"].as_str(),
            req["by"].as_str(),
            req["since"].as_i64(),
            req["until"].as_i64()
        ),
        (Some("bundle"), Some("alice"), Some(now - 7200), Some(now - 3600))
    );
    let row: (String, String) =
        t.st.cat
            .conn()
            .query_row(
                "SELECT target, details FROM audit WHERE action = 'diag.bundle'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
    assert_eq!(row.0, format!("diag/{}", r.body["id"].as_str().unwrap()));
    assert_eq!(
        serde_json::from_str::<Value>(&row.1).unwrap(),
        json!({"since": now - 7200, "until": now - 3600})
    );
}

#[tokio::test]
async fn bundle_range_validation() {
    let t = T::new();
    let alice = t.login("alice").await;
    let now = catalog::now();
    for bad in [
        json!({"since": now, "until": now - 1}),
        json!({"since": now - 32 * 86400, "until": now}),
        json!({"until": now + 7200}),
        json!({"since": -5, "until": now}),
        json!({"bogus": 1}),
        json!({"since": "yesterday"}),
    ] {
        let r = t.post("/api/v1/diagnostics/bundle", &alice, bad.clone()).await;
        assert!(r.status.is_client_error(), "{bad}: {:?}", r.body);
    }
    assert!(!t.diag.join("request.json").exists());
    // default: the last 24 h
    let r = t.post("/api/v1/diagnostics/bundle", &alice, json!({})).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let req = t.request();
    let until = req["until"].as_i64().unwrap();
    assert!((until - now).abs() < 5);
    assert_eq!(req["since"].as_i64().unwrap(), until - 86400);
}

#[tokio::test]
async fn results_visibility_and_download() {
    let t = T::new();
    let (alice, ada, sam) = (t.login("alice").await, t.login("ada").await, t.login("sam").await);
    let now = catalog::now();
    assert_eq!(
        t.post("/api/v1/diagnostics/checks", &sam, json!({})).await.status,
        StatusCode::ACCEPTED
    );
    let checks = t.helper_runs(now - 100);
    assert_eq!(
        t.post("/api/v1/diagnostics/bundle", &alice, json!({})).await.status,
        StatusCode::ACCEPTED
    );
    let bundle = t.helper_runs(now - 50);

    // the checks result: everyone who reads diagnostics
    for s in [&alice, &ada, &sam] {
        let r = t.get(&format!("/api/v1/diagnostics/{checks}"), s).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.body["state"], "done");
        assert_eq!(r.body["checks"][0]["id"], "selinux");
        assert!(r.body["bundle"].is_null());
    }
    // the bundle: only alice's
    let r = t.get(&format!("/api/v1/diagnostics/{bundle}"), &alice).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(
        r.body["bundle"],
        json!({"bytes": 13, "url": format!("/api/v1/diagnostics/{bundle}/download")})
    );
    assert_eq!(r.body["expires"], json!(now - 50 + 86400));
    for s in [&ada, &sam] {
        assert_eq!(
            t.get(&format!("/api/v1/diagnostics/{bundle}"), s).await.status,
            StatusCode::NOT_FOUND
        );
    }
    let ids = |r: &R| -> Vec<String> {
        r.body["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(
        ids(&t.get("/api/v1/diagnostics", &alice).await),
        vec![bundle.clone(), checks.clone()]
    );
    assert_eq!(ids(&t.get("/api/v1/diagnostics", &ada).await), vec![checks.clone()]);

    // download: requester only, audited
    let url = format!("/api/v1/diagnostics/{bundle}/download");
    assert_eq!(t.get(&url, &ada).await.status, StatusCode::NOT_FOUND);
    assert_eq!(t.get(&url, &sam).await.status, StatusCode::FORBIDDEN);
    let r = t.get(&url, &alice).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.raw, b"\x1f\x8bfake-bundle");
    assert_eq!(r.headers[header::CONTENT_TYPE], "application/gzip");
    assert!(r.headers[header::CONTENT_DISPOSITION]
        .to_str()
        .unwrap()
        .contains(&format!("nexus-support-{bundle}.tar.gz")));
    let target: String =
        t.st.cat
            .conn()
            .query_row(
                "SELECT target FROM audit WHERE action = 'download.get' AND actor = 'alice'",
                [],
                |r| r.get(0),
            )
            .unwrap();
    assert_eq!(target, format!("diag/{bundle}"));
    // checks have nothing to download; bad ids are 404
    assert_eq!(
        t.get(&format!("/api/v1/diagnostics/{checks}/download"), &alice)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    for bad in ["x", "..", "0123456789ABCDEF0123456789ABCDEF"] {
        assert_eq!(
            t.get(&format!("/api/v1/diagnostics/{bad}"), &alice).await.status,
            StatusCode::NOT_FOUND
        );
    }

    // after 24 h the bundle is no longer served (nexus-diag deletes it at its next run)
    let p = t.diag.join(&bundle).join("status.json");
    let mut st: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
    st["created"] = json!(now - 90_000);
    std::fs::write(&p, st.to_string()).unwrap();
    assert!(t.get(&format!("/api/v1/diagnostics/{bundle}"), &alice).await.body["bundle"].is_null());
    assert_eq!(t.get(&url, &alice).await.status, StatusCode::NOT_FOUND);
}
