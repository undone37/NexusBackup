//! Phase 30 (NetBackup Tier 2): per-source anomaly sensitivity and the trend
//! fields, just-in-time role elevation, instant rollback requests, offsite
//! targets.

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
    ids: HashMap<String, i64>,
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
                   INSERT INTO policies (id, name, schedule, gfs, offsite) VALUES
                     (1, 'daily', 'daily 22:00', '{"daily":7,"weekly":0,"monthly":0,"yearly":0}', 0);
                   INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES
                     (1, 'acme', 1, 1, 'a1', '[100]'), (2, 'acme', 1, 1, 'a2', '[101]'), (3, 'globex', 2, 1, 'g1', '[200]');
                   INSERT INTO snapshots (tenant, source, time, size, local, offsite) VALUES
                     ('acme', 'vm-100', 1000, 5, 1, 0), ('acme', 'vm-100', 2000, 5, 1, 0),
                     ('acme', 'vm-101', 1500, 5, 1, 0), ('globex', 'vm-200', 1500, 5, 1, 0);"#,
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
        ] {
            let secret = catalog::auth::new_totp_secret();
            let enc = t.st.totp.encrypt(n, &secret).unwrap();
            let c = t.st.cat.conn();
            c.execute(
                "INSERT INTO users (name, password_hash, totp_secret, role, tenant, created) VALUES (?1,?2,?3,?4,?5,0)",
                params![n, pw_hash(), enc, role, tenant],
            )
            .unwrap();
            t.ids.insert(n.into(), c.last_insert_rowid());
            t.secrets.insert(n.into(), secret);
        }
        t
    }

    async fn call(&self, method: Method, path: &str, s: Option<&S>, body: Option<Value>) -> R {
        let mut b = Request::builder().method(method.clone()).uri(path);
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
    async fn get(&self, path: &str, s: &S) -> R {
        self.call(Method::GET, path, Some(s), None).await
    }
    async fn post(&self, path: &str, s: &S, body: Value) -> R {
        self.call(Method::POST, path, Some(s), Some(body)).await
    }
    async fn put(&self, path: &str, s: &S, body: Value) -> R {
        self.call(Method::PUT, path, Some(s), Some(body)).await
    }

    fn code(&self, name: &str) -> String {
        self.exec(&format!("UPDATE users SET totp_last_step = 0 WHERE name = '{name}'"));
        catalog::auth::totp_now(&self.secrets[name]).unwrap()
    }

    async fn login(&self, name: &str) -> S {
        let body = json!({"name": name, "password": PW, "totp": self.code(name)});
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
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
        let raw = res.into_body().collect().await.unwrap().to_bytes().to_vec();
        let body: Value = serde_json::from_slice(&raw).unwrap();
        S {
            cookie,
            csrf: body["csrf"].as_str().unwrap().to_owned(),
        }
    }

    fn exec(&self, sql: &str) {
        self.st.cat.conn().execute_batch(sql).unwrap();
    }

    fn one<V: catalog::rusqlite::types::FromSql>(&self, sql: &str) -> V {
        self.st.cat.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }
}

impl T {
    fn add_tenant_admin(&mut self) {
        let secret = catalog::auth::new_totp_secret();
        let enc = self.st.totp.encrypt("dana", &secret).unwrap();
        let c = self.st.cat.conn();
        c.execute(
            "INSERT INTO users (name, password_hash, totp_secret, role, tenant, created) VALUES ('dana',?1,?2,'tenant_admin','acme',0)",
            params![pw_hash(), enc],
        )
        .unwrap();
        self.ids.insert("dana".into(), c.last_insert_rowid());
        self.secrets.insert("dana".into(), secret);
    }
}

/// Per-source sensitivity: raising applies at once, lowering is an approval
/// (`anomaly.sensitivity`); the trends carry duration, bytes read and the level.
#[tokio::test]
async fn anomaly_sensitivity_and_trends() {
    let mut t = T::new();
    t.add_tenant_admin();
    let (alice, sam, otto, tina, dana) = (
        t.login("alice").await,
        t.login("sam").await,
        t.login("otto").await,
        t.login("tina").await,
        t.login("dana").await,
    );
    t.exec(
        "INSERT INTO backup_stats (tenant, source, time, read, logical, new_chunks, new_plain, new_stored, secs) VALUES
           ('acme', 'vm-100', 1000, 50, 500, 1, 10, 5, 120), ('acme', 'vm-100', 2000, 60, 500, 1, 12, 6, NULL);",
    );
    let r = t.get("/api/v1/stats/trends", &alice).await;
    assert_eq!(r.status, StatusCode::OK);
    let tr = &r.body[0];
    assert_eq!(
        (tr["source"].clone(), tr["sensitivity"].clone()),
        (json!("vm-100"), json!("medium"))
    );
    assert_eq!(
        (
            tr["runs"][0]["secs"].clone(),
            tr["runs"][0]["read"].clone(),
            tr["runs"][1]["secs"].clone()
        ),
        (json!(120), json!(50), Value::Null)
    );
    let set = |level: &str| json!({"tenant": "acme", "source": "vm-100", "level": level});
    // raising: at once, by admins, security officers and tenant admins of the tenant
    let r = t.put("/api/v1/stats/sensitivity", &sam, set("high")).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["old"], "medium");
    assert_eq!(
        t.one::<String>("SELECT level FROM anomaly_sensitivity WHERE source = 'vm-100'"),
        "high"
    );
    for s in [&otto, &tina] {
        assert_eq!(
            t.put("/api/v1/stats/sensitivity", s, set("high")).await.status,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        t.put(
            "/api/v1/stats/sensitivity",
            &dana,
            json!({"tenant": "globex", "source": "vm-200", "level": "high"})
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.put("/api/v1/stats/sensitivity", &alice, set("max")).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        t.put(
            "/api/v1/stats/sensitivity",
            &alice,
            json!({"tenant": "nope", "source": "vm-100", "level": "high"})
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    // lowering: an approval by a second person
    let r = t.put("/api/v1/stats/sensitivity", &dana, set("low")).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    assert_eq!(
        t.one::<String>("SELECT level FROM anomaly_sensitivity WHERE source = 'vm-100'"),
        "high",
        "unchanged until approved"
    );
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["state"], "executed");
    assert_eq!(
        t.one::<String>("SELECT level FROM anomaly_sensitivity WHERE source = 'vm-100'"),
        "low"
    );
    // back to medium is raising: no row (the default)
    let r = t.put("/api/v1/stats/sensitivity", &alice, set("medium")).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(t.one::<i64>("SELECT COUNT(*) FROM anomaly_sensitivity"), 0);
    // a request made against an older level is refused when approved
    let r = t.put("/api/v1/stats/sensitivity", &alice, set("low")).await;
    let q = r.body["quorum_id"].as_i64().unwrap();
    t.put("/api/v1/stats/sensitivity", &alice, set("high")).await;
    assert_eq!(
        t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({}))
            .await
            .status,
        StatusCode::CONFLICT
    );
    // with approvals off a lowering executes directly (audited as such)
    t.exec("UPDATE settings SET value = 'false' WHERE key = 'approvals_enabled'");
    let r = t.put("/api/v1/stats/sensitivity", &alice, set("low")).await;
    assert_eq!((r.status, r.body["executed"].clone()), (StatusCode::OK, json!(true)));
    assert_eq!(
        t.one::<i64>(
            "SELECT COUNT(*) FROM audit WHERE action = 'anomaly.sensitivity' AND details LIKE '%\"approvals\":\"disabled\"%'"
        ),
        1
    );
}
