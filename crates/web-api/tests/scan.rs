//! Phase 21e: opt-in YARA scan of a snapshot (rule files, scan requests and
//! results) and the `scan_first` restore option.

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

fn seed(t: &T) {
    t.st.cat
        .conn()
        .execute_batch(
            r#"INSERT INTO snapshots (tenant, source, time, local, offsite) VALUES
                 ('acme', 'vm-100', 1, 1, 0), ('acme', 'share-3', 2, 1, 0), ('globex', 'vm-200', 5, 1, 0),
                 ('acme', 'vm-101', 3, 0, 1);
               INSERT INTO snapshot_scans (job_id, tenant, source, time, finished, rules, files, skipped, errors,
                   complete, matches_total, matches) VALUES
                 (40, 'acme', 'vm-100', 1, 9, 'r.yar@ab', 10, 0, 0, 1, 1, '[{"rule":"r.yar:Eicar","path":"/vda1/x"}]'),
                 (41, 'globex', 'vm-200', 5, 9, 'r.yar@ab', 3, 0, 0, 1, 0, '[]');"#,
        )
        .unwrap();
}

const RULE: &str = "rule Eicar { strings: $a = \"X5O!P%@AP\" condition: $a }";

/// Rule files: admins and security officers only, size caps, audited.
#[tokio::test]
async fn rules_managed_by_admins_and_security_officers() {
    let t = T::new();
    let (alice, sam, otto, tina) = (
        t.login("alice").await,
        t.login("sam").await,
        t.login("otto").await,
        t.login("tina").await,
    );
    for s in [&otto, &tina] {
        assert_eq!(t.get("/api/v1/scan/rules", s).await.status, StatusCode::FORBIDDEN);
        assert_eq!(
            t.put("/api/v1/scan/rules/a.yar", s, json!({"text": RULE})).await.status,
            StatusCode::FORBIDDEN
        );
    }
    let r = t.put("/api/v1/scan/rules/a.yar", &sam, json!({"text": RULE})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["sha256"].as_str().unwrap().len(), 64);
    for (name, text) in [
        ("a:b", RULE.to_owned()),
        (".x", RULE.to_owned()),
        ("b.yar", " ".into()),
        ("b.yar", "just text".into()),
        (
            "b.yar",
            format!("rule x {{ condition: true }} // {}", "x".repeat(256 << 10)),
        ),
    ] {
        let r = t
            .put(&format!("/api/v1/scan/rules/{name}"), &alice, json!({"text": text}))
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{name}: {:?}", r.body);
    }
    // 1 MiB together
    let big = format!("rule x {{ condition: true }} // {}", "x".repeat(250 << 10));
    for i in 0..4 {
        let r = t
            .put(&format!("/api/v1/scan/rules/big{i}.yar"), &alice, json!({"text": big}))
            .await;
        assert_eq!(r.status, StatusCode::OK, "{i}");
    }
    assert_eq!(
        t.put("/api/v1/scan/rules/big4.yar", &alice, json!({"text": big}))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    // replacing a file counts its new size only
    assert_eq!(
        t.put("/api/v1/scan/rules/big3.yar", &alice, json!({"text": big}))
            .await
            .status,
        StatusCode::OK
    );
    let r = t.get("/api/v1/scan/rules", &sam).await;
    let names: Vec<&str> = r
        .body
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["a.yar", "big0.yar", "big1.yar", "big2.yar", "big3.yar"]);
    assert_eq!(r.body[0]["uploaded_by"], "sam");
    assert!(r.body[0].get("text").is_none());
    let del = "/api/v1/scan/rules/big0.yar";
    for (s, want) in [
        (&otto, StatusCode::FORBIDDEN),
        (&alice, StatusCode::NO_CONTENT),
        (&alice, StatusCode::NOT_FOUND),
    ] {
        assert_eq!(t.call(Method::DELETE, del, Some(s), None).await.status, want);
    }
    let n: i64 = t.one("SELECT COUNT(*) FROM audit WHERE action IN ('scan.rules_put', 'scan.rules_delete')");
    assert_eq!(n, 7);
}

/// `POST …/scan` queues a `snapshot_scan` for a local snapshot of the user's
/// tenant once rules exist; results list per snapshot (tenant-scoped).
#[tokio::test]
async fn scan_requests_and_results() {
    let t = T::new();
    seed(&t);
    let (alice, sam, otto, tina, vic) = (
        t.login("alice").await,
        t.login("sam").await,
        t.login("otto").await,
        t.login("tina").await,
        t.login("vic").await,
    );
    let url = "/api/v1/snapshots/acme/vm-100/1/scan";
    assert_eq!(
        t.post(url, &otto, json!({})).await.status,
        StatusCode::CONFLICT,
        "no rules yet"
    );
    t.put("/api/v1/scan/rules/a.yar", &alice, json!({"text": RULE})).await;
    for s in [&tina, &vic] {
        assert_eq!(t.post(url, s, json!({})).await.status, StatusCode::FORBIDDEN);
    }
    let r = t.post(url, &sam, json!({"budget_min": 30})).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let id = r.body["id"].as_i64().unwrap();
    let p: String = t.one(&format!(
        "SELECT params FROM jobs WHERE id = {id} AND kind = 'snapshot_scan'"
    ));
    assert_eq!(
        serde_json::from_str::<Value>(&p).unwrap(),
        json!({"source": "vm-100", "time": 1, "budget": 1800})
    );
    assert_eq!(
        t.post(url, &otto, json!({"budget_min": 0})).await.status,
        StatusCode::BAD_REQUEST
    );
    for bad in [
        "/api/v1/snapshots/acme/vm-100/9/scan",
        "/api/v1/snapshots/acme/vm-101/3/scan",
    ] {
        assert_eq!(
            t.post(bad, &otto, json!({})).await.status,
            StatusCode::NOT_FOUND,
            "{bad}"
        );
    }
    let n: i64 = t.one("SELECT COUNT(*) FROM audit WHERE action = 'snapshot.scan_request'");
    assert_eq!(n, 1);

    let r = t.get("/api/v1/scans?tenant=acme&source=vm-100&time=1", &tina).await;
    assert_eq!(r.body[0]["matches"][0]["rule"], "r.yar:Eicar");
    assert_eq!(r.body[0]["complete"], true);
    let r = t.get("/api/v1/scans", &tina).await;
    assert_eq!(r.body.as_array().unwrap().len(), 1, "own tenant only");
    let r = t.get("/api/v1/scans", &vic).await;
    assert_eq!(r.body.as_array().unwrap().len(), 2);
    // the latest scan on the snapshot list
    let r = t.get("/api/v1/snapshots?tenant=acme&source=vm-100", &tina).await;
    assert_eq!(
        r.body[0]["scan"],
        json!({"job": 40, "finished": 9, "matches": 1, "complete": true})
    );
    let r = t.get("/api/v1/snapshots?tenant=acme&source=share-3", &tina).await;
    assert_eq!(r.body[0]["scan"], Value::Null);
}

/// `scan_first` on restores: refuse | link_down (guest restores only), needs rules;
/// kept in the job params for the scheduler.
#[tokio::test]
async fn scan_first_on_restores() {
    let t = T::new();
    seed(&t);
    let (alice, tina) = (t.login("alice").await, t.login("tina").await);
    let restore = |scan: Value| {
        json!({"kind": "restore", "tenant": "acme", "params": {"source": "vm-100", "time": 1, "node": "n1",
               "target": 900, "storage": "local", "scan_first": scan}})
    };
    let r = t.post("/api/v1/jobs", &alice, restore(json!("refuse"))).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "no rules: {:?}", r.body);
    t.put("/api/v1/scan/rules/a.yar", &alice, json!({"text": RULE})).await;
    for bad in [json!("maybe"), json!(true)] {
        assert_eq!(
            t.post("/api/v1/jobs", &alice, restore(bad)).await.status,
            StatusCode::BAD_REQUEST
        );
    }
    for (by, scan) in [(&alice, "link_down"), (&tina, "refuse")] {
        let r = t.post("/api/v1/jobs", by, restore(json!(scan))).await;
        assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
        let p: String = t.one(&format!("SELECT params FROM jobs WHERE id = {}", r.body["id"]));
        assert_eq!(serde_json::from_str::<Value>(&p).unwrap()["scan_first"], scan);
    }
    // downloads: refuse only
    let get = |scan: &str| {
        json!({"kind": "files_get", "tenant": "acme", "params": {"source": "vm-100", "time": 1,
               "paths": ["/vda1/etc"], "format": "zip", "scan_first": scan}})
    };
    assert_eq!(
        t.post("/api/v1/jobs", &alice, get("link_down")).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        t.post("/api/v1/jobs", &alice, get("refuse")).await.status,
        StatusCode::ACCEPTED
    );
    // not on other kinds
    let r = t
        .post(
            "/api/v1/jobs",
            &alice,
            json!({"kind": "verify", "tenant": "acme", "params": {"scan_first": "refuse"}}),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}
