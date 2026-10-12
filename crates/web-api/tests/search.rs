//! Phase 15g file search: `POST /search` queues a `file_search` job (RBAC,
//! tenant isolation, audit), the per-group VM/CT `index_files` flag.

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

#[tokio::test]
async fn search_queues_a_job_rbac_tenant_isolation_and_audit() {
    let t = T::new();
    let (alice, otto, tina, vic, sam) = (
        t.login("alice").await,
        t.login("otto").await,
        t.login("tina").await,
        t.login("vic").await,
        t.login("sam").await,
    );
    let q = |tenant: &str| json!({"tenant": tenant, "query": "*.docx", "source": "share-3", "from": 1, "to": 2});
    for s in [&alice, &otto, &tina] {
        let r = t.post("/api/v1/search", s, q("acme")).await;
        assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
        let id = r.body["id"].as_i64().unwrap();
        let job = t.get(&format!("/api/v1/jobs/{id}"), s).await;
        assert_eq!(job.body["kind"], "file_search");
        assert_eq!(job.body["tenant"], "acme");
        assert_eq!(job.body["params"]["query"], "*.docx");
        assert_eq!(job.body["params"]["limit"], 500);
        assert_eq!(job.body["params"]["case_sensitive"], false);
    }
    // viewers and security officers request no jobs; tenant users only their tenant
    for s in [&vic, &sam] {
        assert_eq!(
            t.post("/api/v1/search", s, q("acme")).await.status,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        t.post("/api/v1/search", &tina, q("globex")).await.status,
        StatusCode::FORBIDDEN
    );
    // a tenant user cannot read another tenant's search
    let r = t.post("/api/v1/search", &alice, q("globex")).await;
    let other = r.body["id"].as_i64().unwrap();
    assert_eq!(
        t.get(&format!("/api/v1/jobs/{other}"), &tina).await.status,
        StatusCode::NOT_FOUND
    );
    for bad in [
        json!({"tenant": "acme", "query": ""}),
        json!({"tenant": "acme", "query": "a".repeat(257)}),
        json!({"tenant": "acme", "query": "a\nb"}),
        json!({"tenant": "acme", "query": "a", "limit": 0}),
        json!({"tenant": "acme", "query": "a", "limit": 2001}),
        json!({"tenant": "acme", "query": "a", "source": "../etc"}),
        json!({"tenant": "acme", "query": "a", "from": 5, "to": 4}),
        json!({"tenant": "acme", "query": "a", "bogus": 1}),
        json!({"tenant": "nope", "query": "a"}),
    ] {
        let r = t.post("/api/v1/search", &alice, bad.clone()).await;
        assert!(r.status.is_client_error(), "{bad}: {:?}", r.body);
    }
    // the query is in the audit trail
    let n: i64 = t
        .one("SELECT COUNT(*) FROM audit WHERE action = 'file.search' AND json_extract(details, '$.query') = '*.docx'");
    assert_eq!(n, 4);
}

#[tokio::test]
async fn index_files_flag_pve_groups_admin_only() {
    let t = T::new();
    let (alice, otto, tina) = (t.login("alice").await, t.login("otto").await, t.login("tina").await);
    let r = t.get("/api/v1/groups", &alice).await;
    assert!(r.body.as_array().unwrap().iter().all(|g| g["index_files"] == false));
    for s in [&otto, &tina] {
        let r = t.put("/api/v1/groups/1/index-files", s, json!({"enabled": true})).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN);
    }
    let r = t
        .put("/api/v1/groups/1/index-files", &alice, json!({"enabled": true}))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body, json!({"id": 1, "index_files": true}));
    let r = t.get("/api/v1/groups", &alice).await;
    let g1 = r
        .body
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["id"] == 1)
        .unwrap()
        .clone();
    assert_eq!(g1["index_files"], true);
    // a share group's files are always indexed: no flag
    let r = t
        .put("/api/v1/groups/3/index-files", &alice, json!({"enabled": true}))
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        t.put("/api/v1/groups/99/index-files", &alice, json!({"enabled": true}))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    let n: i64 = t.one("SELECT COUNT(*) FROM audit WHERE action = 'group.index_files' AND target = 'group/1'");
    assert_eq!(n, 1);
}
