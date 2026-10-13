//! Settings → Backup of this appliance: status, Run now (admin, queues
//! `config_backup`), download of the latest sealed bundle (admin with the download
//! permission, audited, never through API tokens). The helper is simulated by
//! writing its files into the control dir.

use axum::body::Body;
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
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
    ctl: PathBuf,
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
        let ctl = dir.path().join("config-backup");
        std::fs::create_dir(&ctl).unwrap();
        st.config_backup_dir.set(ctl.clone()).unwrap();
        st.cat
            .conn()
            .execute_batch(
                "INSERT INTO tenants (name, offsite) VALUES ('acme', '{\"remote\":{\"type\":\"local\",\"path\":\"/x\"}}');
                 INSERT INTO tenants (name) VALUES ('beta');",
            )
            .unwrap();
        let mut secrets = HashMap::new();
        for (n, role, tenant, dl) in [
            ("alice", "admin", None, None),
            ("bob", "admin", None, Some(false)),
            ("sam", "security_officer", None, None),
            ("otto", "operator", None, None),
            ("vic", "viewer", None, None),
            ("tina", "tenant_user", Some("acme"), None),
        ] {
            let secret = catalog::auth::new_totp_secret();
            let enc = st.totp.encrypt(n, &secret).unwrap();
            st.cat
                .conn()
                .execute(
                    "INSERT INTO users (name, password_hash, totp_secret, role, tenant, created, can_download)
                     VALUES (?1,?2,?3,?4,?5,0,?6)",
                    params![n, pw_hash(), enc, role, tenant, dl],
                )
                .unwrap();
            secrets.insert(n.to_owned(), secret);
        }
        T {
            app: web_api::router(st.clone()),
            st,
            secrets,
            ctl,
            _dir: dir,
        }
    }

    async fn call(&self, method: Method, path: &str, s: &S) -> R {
        let mut b = Request::builder()
            .method(method.clone())
            .uri(path)
            .header(header::HOST, "nexus.test")
            .header(header::COOKIE, format!("nx_session={}", s.cookie));
        if method != Method::GET {
            b = b.header("x-csrf-token", &s.csrf);
        }
        let res = self.app.clone().oneshot(b.body(Body::empty()).unwrap()).await.unwrap();
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

    async fn login(&self, name: &str) -> S {
        let code = catalog::auth::totp_now(&self.secrets[name]).unwrap();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/auth/login")
            .header(header::HOST, "nexus.test")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({"name": name, "password": PW, "totp": code}).to_string(),
            ))
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
        let body: Value = serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
        S {
            cookie,
            csrf: body["csrf"].as_str().unwrap().to_owned(),
        }
    }

    fn audit(&self, action: &str) -> Vec<(String, String)> {
        self.st
            .cat
            .conn()
            .prepare("SELECT actor, target FROM audit WHERE action = ?1 ORDER BY seq")
            .unwrap()
            .query_map([action], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }
}

const BASE: &str = "/api/v1/settings/config-backup";

#[tokio::test]
async fn status_run_now_and_download() {
    let t = T::new();
    let (alice, bob, sam, otto, vic, tina) = (
        t.login("alice").await,
        t.login("bob").await,
        t.login("sam").await,
        t.login("otto").await,
        t.login("vic").await,
        t.login("tina").await,
    );
    for s in [&otto, &vic, &tina] {
        assert_eq!(t.call(Method::GET, BASE, s).await.status, StatusCode::FORBIDDEN);
    }
    let v = t.call(Method::GET, BASE, &sam).await;
    assert_eq!(v.status, StatusCode::OK);
    assert!(v.body["latest"].is_null() && v.body["last_success"].is_null());
    assert_eq!(
        v.body["targets"][0]["tenant"], "acme",
        "only tenants with an offsite target"
    );
    assert_eq!(v.body["targets"].as_array().unwrap().len(), 1);
    // no bundle yet
    assert_eq!(
        t.call(Method::GET, &format!("{BASE}/download"), &alice).await.status,
        StatusCode::NOT_FOUND
    );

    // Run now: admin only, once at a time, audited as a job
    for s in [&sam, &otto] {
        assert_eq!(
            t.call(Method::POST, &format!("{BASE}/run"), s).await.status,
            StatusCode::FORBIDDEN
        );
    }
    let r = t.call(Method::POST, &format!("{BASE}/run"), &alice).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let job = r.body["job_id"].as_i64().unwrap();
    assert_eq!(
        t.call(Method::POST, &format!("{BASE}/run"), &alice).await.status,
        StatusCode::CONFLICT
    );
    let (kind, tenant): (String, String) =
        t.st.cat
            .conn()
            .query_row("SELECT kind, tenant FROM jobs WHERE id = ?1", [job], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
    assert_eq!((kind.as_str(), tenant.as_str()), ("config_backup", "-"));
    assert!(t.audit("job.create").iter().any(|(a, _)| a == "alice"));

    // the scheduler finished it and the helper left the bundle
    t.st.cat
        .conn()
        .execute(
            "UPDATE jobs SET state = 'ok', finished = 1800000005, result = '{\"bytes\":9}' WHERE id = ?1",
            [job],
        )
        .unwrap();
    std::fs::write(t.ctl.join("latest.bundle"), b"NXCFGB1\0x").unwrap();
    std::fs::write(
        t.ctl.join("latest.json"),
        json!({"id": job, "state": "done", "appliance": "0a1b2c", "created": 1_800_000_000, "bytes": 9,
               "sha256": "ab", "files": ["a", "b"]})
        .to_string(),
    )
    .unwrap();
    let v = t.call(Method::GET, BASE, &alice).await.body;
    assert_eq!(v["last_success"], 1_800_000_005);
    assert_eq!(v["latest"]["files"], 2);
    assert_eq!(v["runs"][0]["id"], job);

    // download: admin with the download permission only, audited
    for s in [&sam, &bob, &otto, &tina] {
        assert_eq!(
            t.call(Method::GET, &format!("{BASE}/download"), s).await.status,
            StatusCode::FORBIDDEN
        );
    }
    let d = t.call(Method::GET, &format!("{BASE}/download"), &alice).await;
    assert_eq!(d.status, StatusCode::OK);
    assert_eq!(d.raw, b"NXCFGB1\0x");
    assert!(d.headers[header::CONTENT_DISPOSITION]
        .to_str()
        .unwrap()
        .contains("nexus-config-0a1b2c-1800000000.bundle"));
    assert_eq!(
        t.audit("download.get"),
        vec![("alice".to_owned(), "config_backup/0a1b2c".to_owned())]
    );

    // API tokens never reach these routes
    for (m, p) in [
        (Method::GET, BASE),
        (Method::GET, "/settings/config-backup/download"),
        (Method::POST, "/settings/config-backup/run"),
    ] {
        assert!(!web_api::tokens::allowed(true, &m, p) && !web_api::tokens::allowed(true, &m, &format!("/api/v1{p}")));
    }
}
