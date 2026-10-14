//! Phase 33 (Commvault Tier 2): PSA channel of notification rules, tenant-side
//! approvers, synthetic restores, cases.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use catalog::rusqlite::params;
use catalog::secret::{SchedulerKey, TotpKey};
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
    sk: SchedulerKey,
    secrets: HashMap<String, String>,
    ids: HashMap<String, i64>,
    _dir: tempfile::TempDir,
}

struct S {
    cookie: String,
    csrf: String,
}

#[derive(Debug)]
struct R {
    status: StatusCode,
    body: Value,
    raw: Vec<u8>,
}

impl T {
    fn new() -> T {
        let dir = tempfile::tempdir().unwrap();
        let cat = Catalog::open(&dir.path().join("catalog.db")).unwrap();
        let downloads = dir.path().join("downloads");
        std::fs::create_dir(&downloads).unwrap();
        let sk = SchedulerKey::generate();
        let secrets_pub = dir.path().join("secrets.pub");
        sk.write_public(&secrets_pub, None).unwrap();
        let st = AppState::with_keys(cat, None, downloads, TotpKey::generate(), Some(secrets_pub));
        st.cat
            .conn()
            .execute_batch(
                r#"INSERT INTO tenants (name) VALUES ('acme'), ('globex');
                   INSERT INTO sources (id, tenant, kind, name, config) VALUES (1, 'acme', 'pve', 'pve-a', '{}'),
                     (2, 'globex', 'pve', 'pve-g', '{}');
                   INSERT INTO policies (id, name, schedule, gfs, offsite) VALUES
                     (1, 'daily', 'daily 22:00', '{"daily":7,"weekly":0,"monthly":0,"yearly":0}', 0);
                   INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES
                     (1, 'acme', 1, 1, 'a1', '[100]'), (2, 'globex', 2, 1, 'g1', '[200]');
                   INSERT INTO snapshots (tenant, source, time, size, local, offsite) VALUES
                     ('acme', 'vm-100', 1000, 5, 1, 0), ('acme', 'vm-100', 2000, 5, 1, 0),
                     ('globex', 'vm-200', 1500, 5, 1, 0);"#,
            )
            .unwrap();
        let mut t = T {
            app: web_api::router(st.clone()),
            st,
            sk,
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
            t.add_user(n, role, tenant, 0);
        }
        t
    }

    fn add_user(&mut self, n: &str, role: &str, tenant: Option<&str>, created: i64) {
        let secret = catalog::auth::new_totp_secret();
        let enc = self.st.totp.encrypt(n, &secret).unwrap();
        let c = self.st.cat.conn();
        c.execute(
            "INSERT INTO users (name, password_hash, totp_secret, role, tenant, created) VALUES (?1,?2,?3,?4,?5,?6)",
            params![n, pw_hash(), enc, role, tenant, created],
        )
        .unwrap();
        self.ids.insert(n.into(), c.last_insert_rowid());
        self.secrets.insert(n.into(), secret);
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
            raw,
        }
    }
    async fn get(&self, path: &str, s: &S) -> R {
        self.call(Method::GET, path, Some(s), None).await
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

fn halo(secret: Option<&str>) -> Value {
    json!({"vendor": "halopsa", "url": "https://acme.halopsa.example/api",
           "token_url": "https://acme.halopsa.example/auth/token", "client_id": "nexus",
           "secret": secret, "account": "12", "board": "3"})
}

fn rules(psa: Value) -> Value {
    json!({"smtp": null, "rules": [{"name": "acme-psa", "min_severity": "warning", "tenants": ["acme"],
            "channels": {"psa": psa}}]})
}

/// PSA channel: admins only, validated per vendor, the secret sealed to the
/// scheduler at the rule and both URLs, write-only (kept while the URLs stay,
/// required again when one changes); alerts list their tickets.
#[tokio::test]
async fn psa_channel_settings() {
    let t = T::new();
    let (alice, otto) = (t.login("alice").await, t.login("otto").await);
    let r = t
        .put("/api/v1/settings/alerts", &otto, rules(halo(Some("s3cret"))))
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = t
        .put("/api/v1/settings/alerts", &alice, rules(halo(Some("s3cret"))))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let shown = &r.body["rules"][0]["channels"]["psa"];
    assert_eq!(
        (shown["secret"].clone(), shown["secret_set"].clone()),
        (Value::Null, json!(true))
    );
    assert!(!r.raw.windows(6).any(|w| w == b"s3cret"), "never shown");
    // stored sealed, opened by the scheduler at the rule and both URLs
    let stored: Value =
        serde_json::from_str(&t.one::<String>("SELECT value FROM settings WHERE key = 'alert_rules'")).unwrap();
    let psa: catalog::alerting::Psa = serde_json::from_value(stored[0]["channels"]["psa"].clone()).unwrap();
    assert!(catalog::secret::is_sealed(&psa.secret));
    let loc = catalog::alerting::psa_location("acme-psa", &psa);
    assert_eq!(&*t.sk.open(&loc, &psa.secret).unwrap(), "s3cret");
    // null keeps it; a changed token URL needs it again
    let r = t.put("/api/v1/settings/alerts", &alice, rules(halo(None))).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let mut moved = halo(None);
    moved["token_url"] = json!("https://elsewhere.example/auth/token");
    let r = t.put("/api/v1/settings/alerts", &alice, rules(moved)).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(
        r.body["error"].as_str().unwrap().contains("secret: required"),
        "{:?}",
        r.body
    );
    // validation per vendor
    for (bad, why) in [
        (
            json!({"vendor": "servicenow", "url": "https://x.example", "secret": "s"}),
            "vendor",
        ),
        (
            json!({"vendor": "autotask", "url": "http://x.example/at", "secret": "s", "username": "u",
                "integration_code": "c", "account": "1"}),
            "url",
        ),
        (
            json!({"vendor": "autotask", "url": "https://u:p@x.example/at", "secret": "s", "username": "u",
                "integration_code": "c", "account": "1"}),
            "url",
        ),
        (
            json!({"vendor": "autotask", "url": "https://x.example/at", "secret": "s", "username": "u",
                "integration_code": "c", "account": "ACME"}),
            "account",
        ),
        (
            json!({"vendor": "connectwise", "url": "https://x.example/cw", "secret": "s", "username": "u",
                "client_id": "c", "account": "ACME"}),
            "company",
        ),
        (
            json!({"vendor": "halopsa", "url": "https://x.example/api", "secret": "s", "client_id": "c"}),
            "token_url",
        ),
    ] {
        let r = t.put("/api/v1/settings/alerts", &alice, rules(bad)).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{why}");
        assert!(r.body["error"].as_str().unwrap().contains(why), "{why}: {:?}", r.body);
    }
    let r = t
        .put(
            "/api/v1/settings/alerts",
            &alice,
            rules(
                json!({"vendor": "connectwise", "url": "https://na.myconnectwise.example/v4_6_release/apis/3.0",
                         "secret": "priv", "username": "pub", "client_id": "c", "company": "msp",
                         "account": "ACME", "board": "Alerts", "closed_status": "Closed (resolved)"}),
            ),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    // alerts list their tickets (the scheduler writes psa_tickets)
    t.exec(
        "INSERT INTO alerts (id, ts, last_ts, severity, kind, key, message, tenant) VALUES
           (1, 100, 100, 'critical', 'job_failed', 'job_failed:acme/x', 'm', 'acme');
         INSERT INTO psa_tickets (rule, key, vendor, ticket, alert_id, opened, noted_count, noted_at, noted_severity)
           VALUES ('acme-psa', 'job_failed:acme/x', 'connectwise', '4711', 1, 101, 1, 101, 'critical');",
    );
    let r = t.get("/api/v1/alerts", &alice).await;
    assert_eq!(
        r.body[0]["tickets"],
        json!([{"rule": "acme-psa", "vendor": "connectwise", "ticket": "4711", "closed": null}])
    );
}
