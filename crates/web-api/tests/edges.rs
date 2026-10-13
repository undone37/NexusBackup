//! Phase 26: edge proxies (admin only, token shown once and sealed, enrollment job,
//! delete clears the agents' routes) and the per-agent "reach via edge" setting.

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
        // agent tokens are sealed to the scheduler: publish a key
        let secrets_pub = dir.path().join("secrets.pub");
        catalog::secret::SchedulerKey::generate()
            .write_public(&secrets_pub, None)
            .unwrap();
        let st = AppState::with_keys(cat, None, downloads, TotpKey::generate(), Some(secrets_pub));
        let mut secrets = HashMap::new();
        for (n, role, tenant) in [
            ("alice", "admin", None),
            ("sam", "security_officer", None),
            ("otto", "operator", None),
            ("tina", "tenant_user", Some("acme")),
            ("tam", "tenant_admin", Some("acme")),
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

    fn exec(&self, sql: &str) {
        self.st.cat.conn().execute_batch(sql).unwrap();
    }

    fn one<V: catalog::rusqlite::types::FromSql>(&self, sql: &str) -> V {
        self.st.cat.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }
}

const AG: &str = "0123456789abcdef";

#[tokio::test]
async fn edges_admin_only_token_enroll_route_delete() {
    let t = T::new();
    t.exec(&format!(
        "INSERT INTO agents (id, tenant, name, host, port, cert_sha256, enrolled_at) VALUES
           ('{AG}', 'acme', 'laptop1', '10.0.0.9', 7444, '{fp}', 5);",
        fp = "ab".repeat(32)
    ));
    let (alice, otto, tam) = (t.login("alice").await, t.login("otto").await, t.login("tam").await);
    let req = json!({"name": "dmz", "host": "10.1.0.5", "public_host": "edge.example.com"});

    // admin only
    for s in [&otto, &tam] {
        assert_eq!(
            t.post("/api/v1/edges", s, req.clone()).await.status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(t.get("/api/v1/edges", s).await.status, StatusCode::FORBIDDEN);
    }
    let bad = t
        .post(
            "/api/v1/edges",
            &alice,
            json!({"name": "x", "host": "a b", "public_host": "e"}),
        )
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);

    let r = t.post("/api/v1/edges", &alice, req.clone()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let id = r.body["id"].as_str().unwrap().to_owned();
    let token = r.body["token"].as_str().unwrap().to_owned();
    assert_eq!(token.len(), 26);
    assert_eq!(
        (r.body["port"].as_i64(), r.body["public_port"].as_i64()),
        (Some(7445), Some(443))
    );
    assert_eq!(r.body["setup"], "nexus-edge init --token -");
    assert_eq!(r.body["online"], false);
    // only the sealed digest is stored
    let sealed: String = t.one(&format!("SELECT token_hash FROM edges WHERE id = '{id}'"));
    assert!(!sealed.contains(&token) && !sealed.contains(&agent_proto::token_digest(&token)));
    assert_eq!(
        t.post("/api/v1/edges", &alice, req.clone()).await.status,
        StatusCode::CONFLICT,
        "unique name"
    );

    // list: never the token
    let l = t.get("/api/v1/edges", &alice).await;
    assert_eq!(l.status, StatusCode::OK);
    assert_eq!(l.body.as_array().unwrap().len(), 1);
    assert!(l.body[0].get("token").is_none() && l.body[0].get("token_hash").is_none());

    // enrollment job (appliance job)
    let e = t.post(&format!("/api/v1/edges/{id}/enroll"), &alice, json!({})).await;
    assert_eq!(e.status, StatusCode::ACCEPTED, "{:?}", e.body);
    let job = e.body["id"].as_i64().unwrap();
    let (kind, tenant, params): (String, String, String) =
        t.st.cat
            .conn()
            .query_row("SELECT kind, tenant, params FROM jobs WHERE id = ?1", [job], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
    assert_eq!((kind.as_str(), tenant.as_str()), ("edge_enroll", "-"));
    assert_eq!(serde_json::from_str::<Value>(&params).unwrap(), json!({"edge_id": id}));
    t.exec(&format!("UPDATE edges SET token_expires = 1 WHERE id = '{id}'"));
    assert_eq!(
        t.post(&format!("/api/v1/edges/{id}/enroll"), &alice, json!({}))
            .await
            .status,
        StatusCode::CONFLICT
    );
    let n = t.post(&format!("/api/v1/edges/{id}/token"), &alice, json!({})).await;
    assert_eq!(n.status, StatusCode::OK);
    assert_ne!(n.body["token"], json!(token));
    assert!(n.body["expires"].as_i64().unwrap() > catalog::now());

    // the control link's report shows up
    t.exec(&format!(
        "UPDATE edges SET cert_sha256 = 'cd', enrolled_at = 7, last_seen = strftime('%s','now'), version = '0.2.0', \
         health = '{{\"agents_online\":[\"{AG}\"]}}', log = '[\"agent {AG} online\"]' WHERE id = '{id}'"
    ));
    let l = t.get("/api/v1/edges", &alice).await;
    assert_eq!(l.body[0]["online"], true);
    assert_eq!(l.body[0]["health"]["agents_online"][0], AG);
    assert_eq!(l.body[0]["log"].as_array().unwrap().len(), 1);

    // reach via edge: admin only, edge must exist
    let path = format!("/api/v1/agents/{AG}/edge");

    assert_eq!(
        t.call(Method::PUT, &path, Some(&tam), Some(json!({"edge_id": id})))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.call(Method::PUT, &path, Some(&alice), Some(json!({"edge_id": "nope"})))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    let a = t
        .call(Method::PUT, &path, Some(&alice), Some(json!({"edge_id": id})))
        .await;
    assert_eq!(a.status, StatusCode::OK, "{:?}", a.body);
    assert_eq!(a.body["edge_id"], json!(id));
    assert_eq!(t.get("/api/v1/edges", &alice).await.body[0]["agents"], 1);
    let ag = t.get("/api/v1/agents", &alice).await;
    assert_eq!(ag.body[0]["edge_id"], json!(id));
    assert!(ag.body[0].get("via").is_some());

    // delete clears the agents' routes; audited
    assert_eq!(
        t.call(Method::DELETE, &format!("/api/v1/edges/{id}"), Some(&otto), None)
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let d = t
        .call(Method::DELETE, &format!("/api/v1/edges/{id}"), Some(&alice), None)
        .await;
    assert_eq!(d.status, StatusCode::OK);
    assert_eq!(d.body["agents"], 1);
    let e: Option<String> = t.one(&format!("SELECT edge_id FROM agents WHERE id = '{AG}'"));
    assert_eq!(e, None);
    let audits: i64 = t.one(
        "SELECT COUNT(*) FROM audit WHERE action IN ('edge.create','edge.enroll','edge.token','agent.edge','edge.delete')",
    );
    assert_eq!(audits, 5);
}
