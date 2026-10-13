//! Phase 23a service-provider operations: monthly usage export, restore point
//! simulator, "back up now, keep until", the published OpenAPI document with
//! API tokens and the SIEM pull route (`/audit?since_seq=`). The tenant IdP is
//! tested with the fake IdP in phase12.rs.

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
const DAY: i64 = 86400;

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

enum Auth<'a> {
    Session(&'a S),
    Bearer(&'a str),
}

struct S {
    cookie: String,
    csrf: String,
}

struct R {
    status: StatusCode,
    body: Value,
    text: String,
    headers: axum::http::HeaderMap,
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
            .execute_batch("INSERT INTO tenants (name) VALUES ('acme'), ('globex');")
            .unwrap();
        let mut secrets = HashMap::new();
        for (n, role, tenant) in [
            ("alice", "admin", None),
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
        st.cat
            .conn()
            .execute_batch(
                r#"INSERT INTO sources (id, tenant, kind, name, config) VALUES (1, 'acme', 'pve', 'pve-a', '{}'),
                     (2, 'globex', 'pve', 'pve-g', '{}');
                   INSERT INTO policies (id, name, schedule, gfs, offsite) VALUES
                     (1, 'daily', 'daily 22:00', '{"daily":14,"weekly":4,"monthly":6,"yearly":2}', 0);
                   INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES
                     (1, 'acme', 1, 1, 'web', '[100]'), (2, 'globex', 2, 1, 'erp', '[200]');"#,
            )
            .unwrap();
        T {
            app: web_api::router(st.clone()),
            st,
            secrets,
            _dir: dir,
        }
    }

    async fn call(&self, method: Method, path: &str, a: Option<Auth<'_>>, body: Option<Value>) -> (R, Option<String>) {
        let mut b = Request::builder()
            .method(method.clone())
            .uri(path)
            .header(header::HOST, "nexus.test");
        match a {
            Some(Auth::Session(s)) => {
                b = b.header(header::COOKIE, format!("nx_session={}", s.cookie));
                if method != Method::GET {
                    b = b.header("x-csrf-token", &s.csrf);
                }
            }
            Some(Auth::Bearer(t)) => b = b.header(header::AUTHORIZATION, format!("Bearer {t}")),
            None => {}
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
        let cookie = headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|c| c.strip_prefix("nx_session=")?.split(';').next().map(str::to_owned));
        let raw = res.into_body().collect().await.unwrap().to_bytes().to_vec();
        let text = String::from_utf8(raw).unwrap();
        let r = R {
            status,
            body: serde_json::from_str(&text).unwrap_or(Value::Null),
            text,
            headers,
        };
        (r, cookie)
    }

    async fn get(&self, path: &str, s: &S) -> R {
        self.call(Method::GET, path, Some(Auth::Session(s)), None).await.0
    }
    async fn post(&self, path: &str, s: &S, body: Value) -> R {
        self.call(Method::POST, path, Some(Auth::Session(s)), Some(body))
            .await
            .0
    }
    async fn put(&self, path: &str, s: &S, body: Value) -> R {
        self.call(Method::PUT, path, Some(Auth::Session(s)), Some(body)).await.0
    }
    async fn bearer(&self, path: &str, tok: &str) -> R {
        self.call(Method::GET, path, Some(Auth::Bearer(tok)), None).await.0
    }

    async fn login(&self, name: &str) -> S {
        let code = catalog::auth::totp_now(&self.secrets[name]).unwrap();
        let (r, cookie) = self
            .call(
                Method::POST,
                "/api/v1/auth/login",
                None,
                Some(json!({"name": name, "password": PW, "totp": code})),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{name}: {:?}", r.body);
        S {
            cookie: cookie.unwrap(),
            csrf: r.body["csrf"].as_str().unwrap().to_owned(),
        }
    }

    /// A `read` API token of `user` (inserted directly; creation is tested in tokens.rs).
    fn token(&self, user: &str) -> String {
        let (prefix, secret) = ("0123abcd", "s".repeat(40));
        self.st
            .cat
            .conn()
            .execute(
                "INSERT INTO api_tokens (user_id, name, prefix, hash, scope, expires, created)
                 SELECT id, 'ci', ?2, ?3, 'read', ?4, 0 FROM users WHERE name = ?1",
                params![
                    user,
                    prefix,
                    web_api::sha256_hex(secret.as_bytes()),
                    catalog::now() + DAY
                ],
            )
            .unwrap();
        format!("nxt_{prefix}_{secret}")
    }

    fn one<V: catalog::rusqlite::types::FromSql>(&self, sql: &str) -> V {
        self.st.cat.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }

    fn exec(&self, sql: &str) {
        self.st.cat.conn().execute_batch(sql).unwrap();
    }
}

#[tokio::test]
async fn usage_export_scoped_csv_and_tokens() {
    let t = T::new();
    let now = catalog::now();
    let today = reports::day(now);
    let month = &today[..7];
    t.exec(&format!(
        "INSERT INTO capacity_samples (day, tenant, used, logical, offsite) VALUES ('{today}', 'acme', 500, 3000, 1000);
         INSERT INTO backup_stats (tenant, source, time, read, logical, new_chunks, new_plain, new_stored) VALUES
           ('acme', 'vm-100', {now}, 1, 3000, 1, 1, 1), ('globex', 'vm-200', {now}, 1, 10, 1, 1, 1);"
    ));
    let (alice, tina) = (t.login("alice").await, t.login("tina").await);
    let r = t.get("/api/v1/usage", &alice).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    assert_eq!(r.body["month"], month);
    assert_eq!(r.body["complete"], false);
    let acme = &r.body["tenants"][0];
    assert_eq!(
        (
            acme["tenant"].as_str(),
            acme["objects"].as_i64(),
            acme["stored_peak"].as_i64()
        ),
        (Some("acme"), Some(1), Some(500))
    );
    assert_eq!(acme["offsite_avg"], 1000);
    assert_eq!(r.body["tenants"].as_array().unwrap().len(), 2);
    // tenant users: their own tenant only
    let r = t.get("/api/v1/usage", &tina).await;
    assert_eq!(r.body["tenants"].as_array().unwrap().len(), 1);
    assert_eq!(
        t.get("/api/v1/usage?tenant=globex", &tina).await.status,
        StatusCode::FORBIDDEN
    );
    for bad in ["2026-13", "x", "2999-01"] {
        assert_eq!(
            t.get(&format!("/api/v1/usage?month={bad}"), &alice).await.status,
            StatusCode::BAD_REQUEST,
            "{bad}"
        );
    }
    // CSV, audited like the other reports; the same table as report type `usage`
    let r = t.get(&format!("/api/v1/usage?month={month}&format=csv"), &alice).await;
    assert_eq!(r.headers[header::CONTENT_TYPE], "text/csv; charset=utf-8");
    assert!(r
        .text
        .starts_with("period_start,period_end,tenant,tenant_uid,objects,backups,"));
    assert!(r.headers[header::CONTENT_DISPOSITION]
        .to_str()
        .unwrap()
        .contains(&format!("nexus-usage-{month}.csv")));
    assert_eq!(
        t.one::<i64>("SELECT COUNT(*) FROM audit WHERE action = 'report.export' AND target = 'report/usage'"),
        1
    );
    let r = t.get("/api/v1/reports/usage.csv", &tina).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.text.contains(",acme,") && !r.text.contains("globex"));
    // API tokens (nexusctl usage): JSON and CSV; the description with and without a token
    let tok = t.token("otto");
    assert_eq!(t.bearer("/api/v1/usage", &tok).await.status, StatusCode::OK);
    assert_eq!(t.bearer("/api/v1/usage?format=csv", &tok).await.status, StatusCode::OK);
    let r = t.bearer("/api/v1/openapi.json", &tok).await;
    assert_eq!(r.body["openapi"], "3.1.0");
    let r = t.call(Method::GET, "/api/openapi.json", None, None).await.0;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.headers[header::CONTENT_TYPE], "application/json");
    assert!(r.body["paths"]["/usage"]["get"].is_object());
    // still closed to tokens: the simulator and the keep-until setting
    assert_eq!(
        t.bearer("/api/v1/settings/keep-until", &tok).await.status,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn restore_point_simulator() {
    let t = T::new();
    let now = catalog::now();
    t.exec(&format!(
        "INSERT INTO backup_stats (tenant, source, time, read, logical, new_chunks, new_plain, new_stored) VALUES
           ('acme', 'vm-100', {a}, 1, 1000, 1, 1000, 500), ('acme', 'vm-100', {b}, 1, 1000, 1, 100, 50),
           ('acme', 'vm-999', {b}, 1, 7, 1, 7, 7);",
        a = now - 2 * DAY,
        b = now - DAY
    ));
    let alice = t.login("alice").await;
    let gfs = json!({"daily": 14, "weekly": 4, "monthly": 6, "yearly": 2});
    let r = t
        .post(
            "/api/v1/policies/simulate",
            &alice,
            json!({"schedule": "daily 22:00", "gfs": gfs, "policy_id": 1, "timezone": "Europe/Berlin"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    let f = &r.body["final"];
    assert_eq!((f["daily"].as_i64(), f["yearly"].as_i64()), (Some(14), Some(2)));
    assert_eq!(r.body["runs"], 400);
    assert!(r.body["series"].as_array().unwrap().len() > 10);
    // the policy's group covers vm-100 only: full 1000 / compression 2, one run adds 50
    let e = &r.body["estimate"];
    assert_eq!(
        (e["sources"].as_i64(), e["full"].as_i64(), e["delta"].as_i64()),
        (Some(1), Some(500), Some(50))
    );
    let n = f["points"].as_i64().unwrap();
    assert_eq!(e["stored"].as_i64(), Some(500 + (n - 1) * 50));
    // a new policy: every source of the tenant
    let r = t
        .post(
            "/api/v1/policies/simulate",
            &alice,
            json!({"schedule": "every 4h", "gfs": {"recent": 24, "daily": 7, "weekly": 0, "monthly": 0, "yearly": 0},
                   "tenant": "acme", "days": 30}),
        )
        .await;
    assert_eq!(r.body["estimate"]["sources"], 2);
    assert_eq!(r.body["final"]["recent"], 6);
    for bad in [
        json!({"schedule": "sometimes", "gfs": gfs}),
        json!({"schedule": "daily 22:00", "gfs": gfs, "days": 2000}),
        json!({"schedule": "daily 22:00", "gfs": {"daily": 5000, "weekly": 0, "monthly": 0, "yearly": 0}}),
    ] {
        let r = t.post("/api/v1/policies/simulate", &alice, bad.clone()).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let tina = t.login("tina").await;
    let r = t
        .post(
            "/api/v1/policies/simulate",
            &tina,
            json!({"schedule": "daily 22:00", "gfs": gfs}),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn keep_until_backups_and_limit() {
    let t = T::new();
    let now = catalog::now();
    let (alice, sam, otto) = (t.login("alice").await, t.login("sam").await, t.login("otto").await);
    let backup =
        |until: i64| json!({"kind": "backup", "tenant": "acme", "params": {"group_id": 1, "keep_until": until}});
    // within the limit (default 90 days): an ordinary job carrying keep_until
    let r = t.post("/api/v1/jobs", &otto, backup(now + 10 * DAY)).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{}", r.text);
    let id = r.body["id"].as_i64().unwrap();
    let p: String = t.one(&format!("SELECT params FROM jobs WHERE id = {id}"));
    assert_eq!(serde_json::from_str::<Value>(&p).unwrap()["keep_until"], now + 10 * DAY);
    for bad in [now - 1, now + 4000 * DAY] {
        assert_eq!(
            t.post("/api/v1/jobs", &otto, backup(bad)).await.status,
            StatusCode::BAD_REQUEST
        );
    }
    // beyond it: approval; approving queues the job for the requester
    let jobs = t.one::<i64>("SELECT COUNT(*) FROM jobs");
    let r = t.post("/api/v1/jobs", &otto, backup(now + 200 * DAY)).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let q = r.body["quorum_id"].as_i64().expect("approval request");
    assert_eq!(t.one::<i64>("SELECT COUNT(*) FROM jobs"), jobs);
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.body["state"], "executed", "{}", r.text);
    let job = r.body["job_id"].as_i64().unwrap();
    let (by, kind): (String, String) =
        t.st.cat
            .conn()
            .query_row("SELECT requested_by, kind FROM jobs WHERE id = ?1", [job], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
    assert_eq!((by.as_str(), kind.as_str()), ("otto", "backup"));
    // the limit: operators read it, lowering applies at once, raising needs approval
    let r = t.get("/api/v1/settings/keep-until", &otto).await;
    assert_eq!(r.body["max_days"], 90);
    assert_eq!(
        t.put("/api/v1/settings/keep-until", &otto, json!({"max_days": 30}))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let r = t
        .put("/api/v1/settings/keep-until", &alice, json!({"max_days": 30}))
        .await;
    assert_eq!((r.status, r.body["max_days"].as_i64()), (StatusCode::OK, Some(30)));
    let r = t
        .put("/api/v1/settings/keep-until", &alice, json!({"max_days": 365}))
        .await;
    let q = r.body["quorum_id"].as_i64().expect("raising needs approval");
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.body["state"], "executed", "{}", r.text);
    assert_eq!(t.get("/api/v1/settings/keep-until", &otto).await.body["max_days"], 365);
    assert_eq!(
        t.put("/api/v1/settings/keep-until", &alice, json!({"max_days": 0}))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    // approvals off: queued directly, audited
    t.exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('approvals_enabled', 'false')");
    let r = t.post("/api/v1/jobs", &otto, backup(now + 400 * DAY)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    assert!(r.body["job_id"].is_i64());
    assert_eq!(
        t.one::<i64>("SELECT COUNT(*) FROM audit WHERE action = 'backup.keep'"),
        2
    );
}

#[tokio::test]
async fn audit_pull_since_seq() {
    let t = T::new();
    let sam = t.login("sam").await;
    let tok = t.token("sam");
    let last: i64 = t.one("SELECT MAX(seq) FROM audit");
    t.st.cat.audit("test", "x.one", "x", &json!({})).unwrap();
    t.st.cat.audit("test", "x.two", "x", &json!({})).unwrap();
    let r = t.bearer(&format!("/api/v1/audit?since_seq={last}&limit=1"), &tok).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    let rows = r.body.as_array().unwrap();
    assert_eq!((rows.len(), rows[0]["seq"].as_i64()), (1, Some(last + 1)));
    let r = t.get(&format!("/api/v1/audit?since_seq={}", last + 1), &sam).await;
    assert_eq!(r.body[0]["action"], "x.two");
    assert_eq!(
        t.get("/api/v1/audit?since_seq=1&after=2", &sam).await.status,
        StatusCode::BAD_REQUEST
    );
}
