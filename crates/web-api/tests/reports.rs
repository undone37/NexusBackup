//! Phase 14e reports: CSV downloads (types, ranges, tenant scoping, RBAC,
//! audit) and the scheduled reports setting (validation, admin only, send now).

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
        let now = catalog::now();
        st.cat
            .conn()
            .execute_batch(&format!(
                r#"INSERT INTO sources (id, tenant, kind, name, config) VALUES (1, 'acme', 'pve', 'pve-a', '{{}}'),
                     (2, 'globex', 'pve', 'pve-g', '{{}}');
                   INSERT INTO policies (id, name, schedule, gfs, offsite) VALUES (1, 'daily', 'daily 22:00', '{{}}', 0);
                   INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES
                     (1, 'acme', 1, 1, 'web', '[100]'), (2, 'globex', 2, 1, 'erp', '[200]');
                   INSERT INTO snapshots (tenant, source, time, size, local, offsite) VALUES
                     ('acme', 'vm-100', {a}, 10, 1, 0), ('globex', 'vm-200', {a}, 10, 1, 0);
                   INSERT INTO jobs (kind, tenant, params, state, requested_by, created, finished, log) VALUES
                     ('backup', 'acme', '{{"group_id":1}}', 'failed', 'scheduler', {f}, {f}, 'error: acme broke'),
                     ('backup', 'globex', '{{"group_id":2}}', 'failed', 'scheduler', {f}, {f}, 'error: globex broke');"#,
                a = now - 3600,
                f = now - 2 * 86400,
            ))
            .unwrap();
        T {
            app: web_api::router(st.clone()),
            st,
            secrets,
            _dir: dir,
        }
    }

    async fn call(&self, method: Method, path: &str, s: Option<&S>, body: Option<Value>) -> (R, Option<String>) {
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
        self.call(Method::GET, path, Some(s), None).await.0
    }
    async fn post(&self, path: &str, s: &S, body: Value) -> R {
        self.call(Method::POST, path, Some(s), Some(body)).await.0
    }
    async fn put(&self, path: &str, s: &S, body: Value) -> R {
        self.call(Method::PUT, path, Some(s), Some(body)).await.0
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

    fn one<V: catalog::rusqlite::types::FromSql>(&self, sql: &str) -> V {
        self.st.cat.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }
}

#[tokio::test]
async fn csv_downloads_scoped_and_audited() {
    let t = T::new();
    let (alice, sam, otto, tina) = (
        t.login("alice").await,
        t.login("sam").await,
        t.login("otto").await,
        t.login("tina").await,
    );
    // every role may export; admin sees both tenants
    for s in [&alice, &sam, &otto, &tina] {
        for kind in ["protection", "failed", "sla", "storage"] {
            let r = t.get(&format!("/api/v1/reports/{kind}.csv"), s).await;
            assert_eq!(r.status, StatusCode::OK, "{kind}: {}", r.text);
            assert_eq!(r.headers[header::CONTENT_TYPE], "text/csv; charset=utf-8");
            assert!(r.text.ends_with("\r\n"));
        }
    }
    let r = t.get("/api/v1/reports/failed.csv", &alice).await;
    assert!(r
        .text
        .starts_with("job,tenant,kind,target,created,finished,attempt,error\r\n"));
    assert!(
        r.text.contains("acme broke") && r.text.contains("globex broke"),
        "{}",
        r.text
    );
    let disp = r.headers[header::CONTENT_DISPOSITION].to_str().unwrap();
    assert!(disp.starts_with("attachment; filename=\"nexus-failed-") && disp.ends_with(".csv\""));
    // tenant filter for appliance-wide users
    let r = t.get("/api/v1/reports/failed.csv?tenant=globex", &otto).await;
    assert!(!r.text.contains("acme broke") && r.text.contains("globex broke"));
    assert!(r.headers[header::CONTENT_DISPOSITION]
        .to_str()
        .unwrap()
        .contains("nexus-failed-globex-"));
    // tenant users: their tenant only, another tenant is refused
    let r = t.get("/api/v1/reports/failed.csv", &tina).await;
    assert!(r.text.contains("acme broke") && !r.text.contains("globex"));
    let r = t.get("/api/v1/reports/protection.csv", &tina).await;
    assert!(r.text.contains("pve-a guest 100") && !r.text.contains("globex"));
    assert_eq!(
        t.get("/api/v1/reports/failed.csv?tenant=acme", &tina).await.status,
        StatusCode::OK
    );
    assert_eq!(
        t.get("/api/v1/reports/failed.csv?tenant=globex", &tina).await.status,
        StatusCode::FORBIDDEN
    );
    // ranges: dates (to inclusive) or unix seconds; the failures were 2 days ago
    let today = reports::day(catalog::now());
    let r = t
        .get(&format!("/api/v1/reports/failed.csv?from={today}&to={today}"), &alice)
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.text.lines().count(), 1, "header only: {}", r.text);
    let from = catalog::now() - 3 * 86400;
    let r = t.get(&format!("/api/v1/reports/failed.csv?from={from}"), &alice).await;
    assert_eq!(r.text.lines().count(), 3);
    for bad in [
        "from=2026-13-01",
        "from=x",
        "from=2026-10-10&to=2026-10-01",
        "from=2020-01-01&to=2026-01-01",
    ] {
        let r = t.get(&format!("/api/v1/reports/failed.csv?{bad}"), &alice).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    assert_eq!(
        t.get("/api/v1/reports/bogus.csv", &alice).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        t.get("/api/v1/reports/failed", &alice).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        t.get("/api/v1/reports/failed.csv?evil=1", &alice).await.status,
        StatusCode::BAD_REQUEST
    );
    // not logged in
    let (r, _) = t.call(Method::GET, "/api/v1/reports/failed.csv", None, None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // audited with the scope
    let n: i64 = t.one("SELECT COUNT(*) FROM audit WHERE action = 'report.export'");
    assert!(n >= 20);
    let d: String =
        t.one("SELECT details FROM audit WHERE action = 'report.export' AND actor = 'tina' ORDER BY seq DESC LIMIT 1");
    let d: Value = serde_json::from_str(&d).unwrap();
    assert_eq!(
        (d["tenant"].as_str(), d["type"].as_str()),
        (Some("acme"), Some("failed"))
    );
}

#[tokio::test]
async fn scheduled_reports_setting() {
    let t = T::new();
    let (alice, sam, otto, tina) = (
        t.login("alice").await,
        t.login("sam").await,
        t.login("otto").await,
        t.login("tina").await,
    );
    let one = json!({"name": "weekly-ops", "types": ["protection", "failed"], "schedule": "Mon 07:00",
                     "timezone": "Europe/Berlin", "recipients": ["ops@example.com"]});
    // the SMTP server must exist first
    let r = t
        .put("/api/v1/settings/reports", &alice, json!({"reports": [one]}))
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.body["error"].as_str().unwrap().contains("SMTP"));
    catalog::set_setting(
        &t.st.cat.conn(),
        "alerts",
        &json!({"smtp": {"host": "mail.example.com", "port": 587, "starttls": true, "from": "nexus@example.com"}})
            .to_string(),
    )
    .unwrap();
    // admin only for changes; admin and security officer read
    for s in [&sam, &otto, &tina] {
        let r = t.put("/api/v1/settings/reports", s, json!({"reports": [one]})).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN);
    }
    for s in [&otto, &tina] {
        assert_eq!(t.get("/api/v1/settings/reports", s).await.status, StatusCode::FORBIDDEN);
    }
    // validation
    let bad = |patch: Value| {
        let mut v = one.clone();
        for (k, x) in patch.as_object().unwrap() {
            v[k] = x.clone();
        }
        json!({"reports": [v]})
    };
    for (patch, want) in [
        (json!({"schedule": "hourly 05"}), "weekdays"),
        (json!({"schedule": "Mon 7:00"}), "bad schedule"),
        (json!({"timezone": "Mars/Base"}), "time zone"),
        (json!({"types": []}), "types"),
        (json!({"recipients": ["not-a-mail"]}), "recipients"),
        (json!({"recipients": []}), "recipients"),
        (json!({"tenant": "nope"}), "unknown tenant"),
        (json!({"name": "a b"}), "name"),
    ] {
        let r = t.put("/api/v1/settings/reports", &alice, bad(patch.clone())).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{patch}");
        assert!(
            r.body["error"].as_str().unwrap().contains(want),
            "{patch}: {:?}",
            r.body
        );
    }
    let r = t
        .put("/api/v1/settings/reports", &alice, json!({"reports": [one, one]}))
        .await;
    assert!(r.body["error"].as_str().unwrap().contains("unique"));
    let r = t
        .put("/api/v1/settings/reports", &alice, bad(json!({"types": ["bogus"]})))
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // stored, audited, readable
    let monthly = json!({"name": "acme-monthly", "types": ["sla", "storage"], "schedule": "monthly 1 06:00",
                         "recipients": ["it@acme.example"], "tenant": "acme"});
    let r = t
        .put("/api/v1/settings/reports", &alice, json!({"reports": [one, monthly]}))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["smtp"], true);
    assert_eq!(r.body["reports"][1]["timezone"], "UTC");
    assert_eq!(r.body["reports"][0]["last"], Value::Null);
    let n: i64 = t.one("SELECT COUNT(*) FROM audit WHERE action = 'settings.reports'");
    assert_eq!(n, 1);
    let r = t.get("/api/v1/settings/reports", &sam).await;
    assert_eq!(r.body["reports"].as_array().unwrap().len(), 2);
    // send now: admin, queues report_send for one period up to now
    let r = t
        .post("/api/v1/settings/reports/weekly-ops/send", &otto, json!({}))
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(
        t.post("/api/v1/settings/reports/nope/send", &alice, json!({}))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    let r = t
        .post("/api/v1/settings/reports/weekly-ops/send", &alice, json!({}))
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let id = r.body["job_id"].as_i64().unwrap();
    let (kind, tenant, p): (String, String, String) =
        t.st.cat
            .conn()
            .query_row("SELECT kind, tenant, params FROM jobs WHERE id = ?1", [id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
    let p: Value = serde_json::from_str(&p).unwrap();
    assert_eq!(
        (kind.as_str(), tenant.as_str(), p["name"].as_str()),
        ("report_send", "-", Some("weekly-ops"))
    );
    assert_eq!(p["to"].as_i64().unwrap() - p["from"].as_i64().unwrap(), 7 * 86400);
    // once at a time
    let r = t
        .post("/api/v1/settings/reports/weekly-ops/send", &alice, json!({}))
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    let r = t.get("/api/v1/settings/reports", &alice).await;
    assert_eq!(r.body["reports"][0]["last"]["job_id"], id);
    assert_eq!(r.body["reports"][0]["last"]["state"], "queued");
    // tenant users never see appliance jobs
    let r = t.get("/api/v1/jobs", &tina).await;
    assert!(!r.text.contains("report_send"));
    // POST /jobs refuses the kind
    let r = t
        .post(
            "/api/v1/jobs",
            &alice,
            json!({"kind": "report_send", "tenant": "acme", "params": {}}),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // clearing is allowed without SMTP checks
    let r = t.put("/api/v1/settings/reports", &alice, json!({"reports": []})).await;
    assert_eq!(r.status, StatusCode::OK);
}
