//! Phase 12 API (docs/phase12-contract.md): dashboard KPIs, alert delivery,
//! appliance SSH keys, OS updates, break-glass banner, OIDC settings and the
//! OIDC login flow against a local fake IdP (authorization code + PKCE). The
//! real-IdP run is in tests/oidc_keycloak.rs.

use axum::body::Body;
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use catalog::rusqlite::params;
use catalog::secret::{SchedulerKey, TotpKey};
use catalog::Catalog;
use http_body_util::BodyExt;
use ring::signature::{self as sg, KeyPair};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
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
    sk: SchedulerKey,
    dir: tempfile::TempDir,
}

#[derive(Clone)]
struct S {
    cookie: String,
    csrf: String,
}

#[derive(Debug)]
struct R {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

impl R {
    fn location(&self) -> String {
        self.headers[header::LOCATION].to_str().unwrap().to_owned()
    }
    fn cookie(&self, name: &str) -> Option<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|c| {
                c.strip_prefix(&format!("{name}="))?
                    .split(';')
                    .next()
                    .map(str::to_owned)
            })
            .filter(|v| !v.is_empty())
    }
}

impl T {
    fn new() -> T {
        let dir = tempfile::tempdir().unwrap();
        let cat = Catalog::open(&dir.path().join("catalog.db")).unwrap();
        for t in ["acme", "globex"] {
            cat.conn()
                .execute("INSERT INTO tenants (name) VALUES (?1)", [t])
                .unwrap();
        }
        let downloads = dir.path().join("downloads");
        std::fs::create_dir(&downloads).unwrap();
        let sk = SchedulerKey::generate();
        let secrets_pub = dir.path().join("secrets.pub");
        sk.write_public(&secrets_pub, None).unwrap();
        let st = AppState::with_keys(cat, None, downloads, TotpKey::generate(), Some(secrets_pub));
        let upd = dir.path().join("update");
        std::fs::create_dir(&upd).unwrap();
        st.update_dir.set(upd).unwrap();
        let mut t = T {
            app: web_api::router(st.clone()),
            st,
            secrets: HashMap::new(),
            ids: HashMap::new(),
            sk,
            dir,
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
            drop(c);
            t.secrets.insert(n.into(), secret);
        }
        t
    }

    async fn send(&self, req: Request<Body>) -> R {
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let raw = res.into_body().collect().await.unwrap().to_bytes().to_vec();
        R {
            status,
            headers,
            body: serde_json::from_slice(&raw).unwrap_or(Value::Null),
        }
    }

    fn req(method: Method, path: &str, s: Option<&S>, body: Option<&Value>) -> Request<Body> {
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
        match body {
            Some(v) => b
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(v.to_string()))
                .unwrap(),
            None => b.body(Body::empty()).unwrap(),
        }
    }

    async fn get(&self, path: &str, s: &S) -> R {
        self.send(Self::req(Method::GET, path, Some(s), None)).await
    }
    async fn post(&self, path: &str, s: &S, body: Value) -> R {
        self.send(Self::req(Method::POST, path, Some(s), Some(&body))).await
    }
    async fn put(&self, path: &str, s: &S, body: Value) -> R {
        self.send(Self::req(Method::PUT, path, Some(s), Some(&body))).await
    }
    async fn anon(&self, path: &str, cookie: Option<&str>) -> R {
        let mut b = Request::builder().uri(path).header(header::HOST, "nexus.test");
        if let Some(c) = cookie {
            b = b.header(header::COOKIE, c);
        }
        self.send(b.body(Body::empty()).unwrap()).await
    }

    async fn login(&self, name: &str) -> S {
        self.st
            .cat
            .conn()
            .execute("UPDATE users SET totp_last_step = 0 WHERE name = ?1", [name])
            .unwrap();
        let code = catalog::auth::totp_now(&self.secrets[name]).unwrap();
        let r = self
            .send(Self::req(
                Method::POST,
                "/api/v1/auth/login",
                None,
                Some(&json!({"name": name, "password": PW, "totp": code})),
            ))
            .await;
        assert_eq!(r.status, StatusCode::OK, "{name}: {:?}", r.body);
        S {
            cookie: r.cookie("nx_session").unwrap(),
            csrf: r.body["csrf"].as_str().unwrap().to_owned(),
        }
    }

    fn approvals(&self, on: bool) {
        catalog::set_setting(
            &self.st.cat.conn(),
            "approvals_enabled",
            if on { "true" } else { "false" },
        )
        .unwrap();
    }

    fn audit_count(&self, action: &str) -> i64 {
        self.st
            .cat
            .conn()
            .query_row("SELECT COUNT(*) FROM audit WHERE action = ?1", [action], |r| r.get(0))
            .unwrap()
    }

    fn exec(&self, sql: &str) {
        self.st.cat.conn().execute_batch(sql).unwrap();
    }
}

// ---------------------------------------------------------------- dashboard

#[tokio::test]
async fn dashboard_kpis_scoping_and_cache() {
    let t = T::new();
    let now = catalog::now();
    let day = 86400;
    t.exec(&format!(
        r#"INSERT INTO sources (id, tenant, kind, name, config) VALUES (1, 'acme', 'pve', 'pve-a', '{{}}'), (2, 'globex', 'pve', 'pve-g', '{{}}');
           INSERT INTO policies (id, name, schedule, gfs, offsite) VALUES (1, 'daily', 'daily 22:00', '{{}}', 1), (2, 'hourly', 'hourly 05', '{{}}', 0);
           INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES
             (1, 'acme', 1, 1, 'g1', '[100, 101, 102]'), (2, 'globex', 2, 2, 'g2', '[200]');
           INSERT INTO snapshots (tenant, source, time, size, local, offsite, lock_until) VALUES
             ('acme', 'vm-100', {ok}, 10, 1, 1, {lock}),
             ('acme', 'ct-101', {old}, 10, 1, 0, 0),
             ('globex', 'vm-200', {ok}, 10, 1, 0, 0);
           INSERT INTO agents (id, tenant, name, host, port) VALUES ('0123456789abcdef', 'acme', 'web', 'h', 7444);
           INSERT INTO jobs (kind, tenant, params, state, requested_by, created, finished, result) VALUES
             ('backup', 'acme', '{{"group_id": 1}}', 'ok', 'scheduler', {now}, {now}, '{{}}'),
             ('backup', 'acme', '{{"group_id": 1}}', 'failed', 'scheduler', {now}, {now}, NULL),
             ('backup', 'acme', '{{"agent_id": "0123456789abcdef"}}', 'ok', 'scheduler', {now}, {now}, '{{"consistent": false}}'),
             ('backup', 'globex', '{{"group_id": 2}}', 'failed', 'scheduler', {now}, {now}, NULL),
             ('backup', 'acme', '{{"group_id": 1}}', 'failed', 'scheduler', {ancient}, {ancient}, NULL),
             ('verify', 'acme', '{{}}', 'ok', 'scheduler', {now}, {now}, NULL);
           INSERT INTO tenants (name, offsite) VALUES ('init', '{{"remote": {{"type": "sftp", "host": "box"}}}}');"#,
        ok = now - 3600,
        old = now - 3 * day,
        lock = now + day,
        ancient = now - 40 * day,
    ));
    t.exec(r#"UPDATE tenants SET offsite = '{"remote": {"type": "sftp", "host": "box"}}' WHERE name = 'acme';"#);
    // capacity: 10 growing days for acme, file system figures from the scheduler
    for i in 0..10i64 {
        let d = web_api::dashboard::day(now - (9 - i) * day);
        t.st.cat
            .conn()
            .execute(
                "INSERT INTO capacity_samples (day, tenant, used, logical) VALUES (?1, 'acme', ?2, ?3)",
                params![d, 1000 + 100 * i, 4000 + 400 * i],
            )
            .unwrap();
    }
    catalog::set_setting(
        &t.st.cat.conn(),
        "capacity",
        &json!({"total": 100_000, "used": 10_000, "free": 90_000, "at": now}).to_string(),
    )
    .unwrap();

    let alice = t.login("alice").await;
    let r = t.get("/api/v1/dashboard?days=7", &alice).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let b = &r.body;
    assert_eq!(b["days"], 7);
    let p = &b["protection"];
    // 4 guests in groups + 1 agent without a group
    assert_eq!(
        (
            p["protected"].as_i64(),
            p["unprotected"].as_i64(),
            p["objects"].as_i64()
        ),
        (Some(4), Some(1), Some(5))
    );
    assert_eq!(
        (p["sla_ok"].as_i64(), p["sla_breach"].as_i64(), p["never"].as_i64()),
        (Some(2), Some(1), Some(1))
    );
    let worst = p["worst"].as_array().unwrap();
    assert_eq!(worst[0]["sla"], "never");
    assert_eq!(worst[0]["source"], "vm-102");
    assert_eq!(worst[1]["sla"], "breach");
    assert_eq!(worst[1]["source"], "ct-101", "found under its CT name");
    assert_eq!(worst[1]["rpo_s"], 86400);
    assert_eq!(worst.iter().find(|w| w["source"] == "vm-200").unwrap()["rpo_s"], 3600);
    let j = &b["jobs"];
    assert_eq!(
        (
            j["total"].as_i64(),
            j["ok"].as_i64(),
            j["warning"].as_i64(),
            j["failed"].as_i64()
        ),
        (Some(4), Some(1), Some(1), Some(2))
    );
    assert_eq!(j["success_rate"], 0.5);
    assert_eq!(j["per_day"].as_array().unwrap().len(), 7);
    assert_eq!(j["failed_by_kind"], json!([{"kind": "pve", "failed": 2}]));
    let c = &b["capacity"];
    assert_eq!(
        (
            c["total"].as_i64(),
            c["free"].as_i64(),
            c["physical"].as_i64(),
            c["logical"].as_i64()
        ),
        (Some(100_000), Some(90_000), Some(1900), Some(7600))
    );
    assert_eq!(c["reduction"], 4.0);
    assert!(c["dedup"].is_null() && c["compression"].is_null());
    assert_eq!(c["per_day"].as_array().unwrap().len(), 7);
    assert_eq!(c["forecast_full_days"], 900, "90000 free / 100 per day");
    let o = &b["offsite"];
    assert_eq!(o["tenants"], 2);
    assert!(
        o["lag_max_s"].as_i64().unwrap() >= 3 * day - 5,
        "ct-101 not offsite for 3 days"
    );
    assert_eq!(o["lagging"], 1);
    assert!(o["lock_coverage"].as_f64().unwrap() > 0.3);
    assert!(o["last_verify"].is_i64());
    assert!(b["break_glass"].is_null());
    assert!(t.get("/api/v1/dashboard?days=9", &alice).await.status == StatusCode::BAD_REQUEST);
    let r30 = t.get("/api/v1/dashboard", &alice).await;
    assert_eq!(r30.body["days"], 30);
    assert_eq!(r30.body["jobs"]["total"], 4, "the failure 40 days ago is outside");
    assert_eq!(r30.body["jobs"]["per_day"].as_array().unwrap().len(), 30);

    // tenant user: own tenant, no appliance-wide figures
    let tina = t.login("tina").await;
    let r = t.get("/api/v1/dashboard?days=7", &tina).await;
    assert_eq!(r.status, StatusCode::OK);
    let b = &r.body;
    assert_eq!(b["protection"]["protected"], 3);
    assert!(b["protection"]["worst"]
        .as_array()
        .unwrap()
        .iter()
        .all(|w| w["tenant"] == "acme"));
    assert_eq!(b["jobs"]["total"], 3);
    assert!(b["capacity"]["total"].is_null() && b["capacity"]["forecast_full_days"].is_null());
    assert_eq!(b["capacity"]["used"], 1900);
    assert!(b["offsite"]["replication_lag_max_s"].is_null());

    // cached: a new failure shows only after the cache expired
    t.exec(&format!(
        "INSERT INTO jobs (kind, tenant, params, state, requested_by, created, finished) VALUES ('backup', 'acme', '{{}}', 'failed', 'x', {now}, {now});"
    ));
    let again = t.get("/api/v1/dashboard?days=7", &alice).await;
    assert_eq!(again.body["jobs"]["total"], 4);
    t.st.dashboard.lock().unwrap().clear();
    assert_eq!(t.get("/api/v1/dashboard?days=7", &alice).await.body["jobs"]["total"], 5);
}

// ---------------------------------------------------------------- alert delivery

#[tokio::test]
async fn alert_settings_sealed_and_write_only() {
    let t = T::new();
    let alice = t.login("alice").await;
    let sam = t.login("sam").await;
    let otto = t.login("otto").await;
    let r = t.get("/api/v1/settings/alerts", &sam).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body["min_severity"], "warning");
    assert_eq!(
        t.get("/api/v1/settings/alerts", &otto).await.status,
        StatusCode::FORBIDDEN
    );
    let body = json!({"webhook_url": "https://hooks.example.com/x", "min_severity": "critical",
        "smtp": {"host": "mail.example.com", "port": 587, "starttls": true, "from": "nexus@example.com",
                 "to": ["ops@example.com"], "user": "nexus", "password": "smtp-s3cret"}});
    assert_eq!(
        t.put("/api/v1/settings/alerts", &sam, body.clone()).await.status,
        StatusCode::FORBIDDEN
    );
    let r = t.put("/api/v1/settings/alerts", &alice, body.clone()).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["smtp"]["password_set"], true);
    assert!(r.body["smtp"].get("password").is_none());
    let raw = catalog::setting(&t.st.cat.conn(), "alerts").unwrap().unwrap();
    assert!(!raw.contains("smtp-s3cret"));
    let stored: Value = serde_json::from_str(&raw).unwrap();
    // sealed to the scheduler, bound to the SMTP endpoint
    let mut v = stored.clone();
    t.sk.open_all("settings/alerts", &mut v).unwrap();
    assert_eq!(v["smtp"]["password"], "smtp-s3cret");
    // keep the password while the endpoint stays; refuse to carry it to another host
    let mut keep = body.clone();
    keep["smtp"].as_object_mut().unwrap().remove("password");
    keep["smtp"]["password_set"] = json!(true);
    assert_eq!(
        t.put("/api/v1/settings/alerts", &alice, keep.clone()).await.status,
        StatusCode::OK
    );
    let again: Value = serde_json::from_str(&catalog::setting(&t.st.cat.conn(), "alerts").unwrap().unwrap()).unwrap();
    assert_eq!(again["smtp"]["password"], stored["smtp"]["password"]);
    let mut moved = keep.clone();
    moved["smtp"]["host"] = json!("evil.example.com");
    assert_eq!(
        t.put("/api/v1/settings/alerts", &alice, moved).await.status,
        StatusCode::BAD_REQUEST
    );
    for bad in [
        json!({"webhook_url": "ftp://x"}),
        json!({"webhook_url": "https://user:pw@hooks.example.com/"}),
        json!({"min_severity": "debug"}),
        json!({"smtp": {"host": "m", "from": "not-a-mail", "to": ["a@b.example"]}}),
        json!({"smtp": {"host": "m", "from": "a@b.example", "to": []}}),
        json!({"smtp": {"host": "m;rm", "from": "a@b.example", "to": ["a@b.example"]}}),
        json!({"bogus": 1}),
    ] {
        assert_eq!(
            t.put("/api/v1/settings/alerts", &alice, bad.clone()).await.status,
            StatusCode::BAD_REQUEST,
            "{bad}"
        );
    }
    assert_eq!(t.audit_count("settings.alerts"), 2);
    // nothing in the audit log or the API reveals the password
    let audit: String =
        t.st.cat
            .conn()
            .query_row("SELECT group_concat(details) FROM audit", [], |r| r.get(0))
            .unwrap();
    assert!(!audit.contains("smtp-s3cret") && !audit.contains("sealed:v1:"));
}

/// The test endpoint queues a scheduler job and returns its result.
#[tokio::test]
async fn alert_test_waits_for_the_scheduler() {
    let t = T::new();
    let alice = t.login("alice").await;
    let st = t.st.clone();
    // a stand-in scheduler: finishes the job with a result
    let fake = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let n = st
                .cat
                .conn()
                .execute(
                    "UPDATE jobs SET state = 'ok', result = '{\"webhook\": \"ok\"}' WHERE kind = 'alert_test' AND tenant = '-'",
                    [],
                )
                .unwrap();
            if n > 0 {
                break;
            }
        }
    });
    let r = t.post("/api/v1/settings/alerts/test", &alice, json!({})).await;
    fake.await.unwrap();
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        r.body,
        json!({"webhook": "ok"}),
        "flat: one member per configured channel"
    );
    let otto = t.login("otto").await;
    assert_eq!(
        t.post("/api/v1/settings/alerts/test", &otto, json!({})).await.status,
        StatusCode::FORBIDDEN
    );
    // a tenant user never sees appliance jobs
    let tina = t.login("tina").await;
    assert_eq!(t.get("/api/v1/jobs", &tina).await.body, json!([]));
}

// ---------------------------------------------------------------- SSH keys

#[tokio::test]
async fn ssh_keys_rotate_with_quorum_and_retire() {
    let t = T::new();
    let keys = json!([{"name": "pve", "purpose": "Proxmox VE nodes (forced command)", "public_key": "ssh-ed25519 AAAA nexus",
                       "fingerprint": "SHA256:old", "created": 1, "previous": null}]);
    catalog::set_setting(&t.st.cat.conn(), "ssh_keys", &keys.to_string()).unwrap();
    let alice = t.login("alice").await;
    let otto = t.login("otto").await;
    let tina = t.login("tina").await;
    let sam = t.login("sam").await;
    assert_eq!(t.get("/api/v1/ssh-keys", &otto).await.body, keys);
    assert_eq!(t.get("/api/v1/ssh-keys", &tina).await.status, StatusCode::FORBIDDEN);
    assert_eq!(
        t.post("/api/v1/ssh-keys/pve/rotate", &otto, json!({})).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.post("/api/v1/ssh-keys/nope/rotate", &alice, json!({})).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        t.post("/api/v1/ssh-keys/pve/retire", &alice, json!({})).await.status,
        StatusCode::CONFLICT
    );
    // approvals on: quorum, approved by someone else → approved for the scheduler
    let r = t.post("/api/v1/ssh-keys/pve/rotate", &alice, json!({})).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.body["state"], "approved", "the scheduler generates the key");
    // approvals off: an approved work item at once
    t.approvals(false);
    let r = t.post("/api/v1/ssh-keys/pve/rotate", &alice, json!({})).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(
        (r.body["approvals"].as_str(), r.body["state"].as_str()),
        (Some("disabled"), Some("approved"))
    );
    // the scheduler published the new key: retire queues the swap
    let mut k = keys.clone();
    k[0]["previous"] = k[0].clone();
    k[0]["public_key"] = json!("ssh-ed25519 BBBB nexus");
    k[0]["fingerprint"] = json!("SHA256:new");
    catalog::set_setting(&t.st.cat.conn(), "ssh_keys", &k.to_string()).unwrap();
    assert_eq!(
        t.post("/api/v1/ssh-keys/pve/rotate", &alice, json!({})).await.status,
        StatusCode::CONFLICT
    );
    let r = t.post("/api/v1/ssh-keys/pve/retire", &alice, json!({})).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let job = r.body["job_id"].as_i64().unwrap();
    let (kind, tenant, p): (String, String, String) =
        t.st.cat
            .conn()
            .query_row("SELECT kind, tenant, params FROM jobs WHERE id = ?1", [job], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
    assert_eq!(
        (kind.as_str(), tenant.as_str(), p.as_str()),
        ("ssh_key_retire", "-", r#"{"name":"pve"}"#)
    );
    assert_eq!(t.audit_count("ssh_key.retire"), 1);
}

// ---------------------------------------------------------------- updates

#[tokio::test]
async fn updates_status_check_and_apply() {
    let t = T::new();
    let dir = t.dir.path().join("update");
    let alice = t.login("alice").await;
    let otto = t.login("otto").await;
    let sam = t.login("sam").await;
    let tina = t.login("tina").await;
    let r = t.get("/api/v1/updates", &otto).await;
    assert_eq!(r.body["status"], "error", "{:?}", r.body);
    assert_eq!(t.get("/api/v1/updates", &tina).await.status, StatusCode::FORBIDDEN);
    std::fs::write(
        dir.join("status.json"),
        json!({"api": {"booted": {"version": "0.0.1-alpha", "digest": "sha256:a", "since": 1}, "staged": null,
                       "available": null, "channel": "stable", "window": "Sun 03:00 120", "last_check": 5,
                       "status": "idle", "error": null, "rollback": null}})
        .to_string(),
    )
    .unwrap();
    let r = t.get("/api/v1/updates", &sam).await;
    assert_eq!(
        (r.body["status"].as_str(), r.body["booted"]["version"].as_str()),
        (Some("idle"), Some("0.0.1-alpha"))
    );
    assert_eq!(
        t.post("/api/v1/updates/check", &otto, json!({})).await.status,
        StatusCode::FORBIDDEN
    );
    let r = t.post("/api/v1/updates/check", &alice, json!({})).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    assert_eq!(std::fs::read_to_string(dir.join("request")).unwrap(), "stage\n");
    assert_eq!(t.get("/api/v1/updates", &otto).await.body["status"], "checking");
    std::fs::remove_file(dir.join("request")).unwrap();
    // apply: quorum while approvals are on; the request is written on approval
    let r = t.post("/api/v1/updates/apply", &alice, json!({})).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    assert!(!dir.join("request").exists());
    let q = r.body["quorum_id"].as_i64().unwrap();
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.body["state"], "executed", "{:?}", r.body);
    assert_eq!(std::fs::read_to_string(dir.join("request")).unwrap(), "apply\n");
    std::fs::remove_file(dir.join("request")).unwrap();
    t.approvals(false);
    let r = t.post("/api/v1/updates/apply", &alice, json!({})).await;
    assert_eq!((r.status, r.body["executed"].as_bool()), (StatusCode::OK, Some(true)));
    assert_eq!(std::fs::read_to_string(dir.join("request")).unwrap(), "apply\n");
}

// ---------------------------------------------------------------- break-glass banner

#[tokio::test]
async fn break_glass_banner_until_acknowledged() {
    let t = T::new();
    t.exec("INSERT INTO alerts (id, ts, severity, kind, message) VALUES (7, 1, 'critical', 'break_glass', 'break-glass: admin account alice was reset');");
    catalog::set_setting(
        &t.st.cat.conn(),
        "break_glass",
        &json!({"at": 1, "user": "alice", "alert": 7, "forced_solo": false}).to_string(),
    )
    .unwrap();
    let otto = t.login("otto").await;
    let tina = t.login("tina").await;
    let sam = t.login("sam").await;
    let me = t.get("/api/v1/auth/me", &otto).await;
    assert_eq!(me.body["break_glass"]["user"], "alice");
    assert!(t.get("/api/v1/auth/me", &tina).await.body["break_glass"].is_null());
    assert_eq!(t.get("/api/v1/dashboard", &otto).await.body["break_glass"]["alert"], 7);
    // operators acknowledge other alerts, not this one
    assert_eq!(
        t.post("/api/v1/alerts/7/ack", &otto, json!({})).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.post("/api/v1/alerts/7/ack", &sam, json!({})).await.status,
        StatusCode::OK
    );
    assert!(t.get("/api/v1/auth/me", &otto).await.body["break_glass"].is_null());
    assert!(t.get("/api/v1/dashboard", &otto).await.body["break_glass"].is_null());
    assert!(catalog::setting(&t.st.cat.conn(), "break_glass").unwrap().is_none());
}

// ---------------------------------------------------------------- OIDC: fake IdP

struct IdpState {
    keys: Vec<(String, sg::EcdsaKeyPair)>,
    /// kids served in the JWKS
    published: Vec<String>,
    signing: String,
    /// claims of the next login (sub, preferred_username, groups, …)
    user: Value,
    /// code → (nonce, challenge, redirect_uri)
    codes: HashMap<String, (String, String, String)>,
    secret: String,
    token_requests: usize,
    /// tweak the ID token of the next login
    tamper: Option<fn(&mut Value)>,
}

#[derive(Clone)]
struct Idp {
    url: String,
    st: Arc<Mutex<IdpState>>,
}

fn ec_key() -> sg::EcdsaKeyPair {
    let rng = ring::rand::SystemRandom::new();
    let pk8 = sg::EcdsaKeyPair::generate_pkcs8(&sg::ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    sg::EcdsaKeyPair::from_pkcs8(&sg::ECDSA_P256_SHA256_FIXED_SIGNING, pk8.as_ref(), &rng).unwrap()
}

fn query(url: &str) -> HashMap<String, String> {
    reqwest::Url::parse(url)
        .unwrap()
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

async fn fake_idp() -> Idp {
    use axum::extract::{Query, State};
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
    let st = Arc::new(Mutex::new(IdpState {
        keys: vec![
            ("k1".into(), ec_key()),
            ("k2".into(), ec_key()),
            ("k3".into(), ec_key()),
        ],
        published: vec!["k1".into()],
        signing: "k1".into(),
        user: json!({}),
        codes: HashMap::new(),
        secret: "client-s3cret".into(),
        token_requests: 0,
        tamper: None,
    }));
    let idp = Idp {
        url: url.clone(),
        st: st.clone(),
    };
    type Shared = (String, Arc<Mutex<IdpState>>);
    let disc = |State((url, _)): State<Shared>| async move {
        axum::Json(json!({"issuer": url, "authorization_endpoint": format!("{url}/auth"),
            "token_endpoint": format!("{url}/token"), "jwks_uri": format!("{url}/jwks"),
            "id_token_signing_alg_values_supported": ["ES256"], "code_challenge_methods_supported": ["S256"]}))
    };
    let jwks = |State((_, st)): State<Shared>| async move {
        let s = st.lock().unwrap();
        let keys: Vec<Value> = s
            .keys
            .iter()
            .filter(|(k, _)| s.published.contains(k))
            .map(|(kid, k)| {
                let p = k.public_key().as_ref();
                json!({"kty": "EC", "crv": "P-256", "kid": kid, "use": "sig", "alg": "ES256",
                       "x": URL_SAFE_NO_PAD.encode(&p[1..33]), "y": URL_SAFE_NO_PAD.encode(&p[33..])})
            })
            .collect();
        axum::Json(json!({"keys": keys}))
    };
    // the user "logs in" at once: straight back with a code
    let auth = |State((_, st)): State<Shared>, Query(q): Query<HashMap<String, String>>| async move {
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["code_challenge_method"], "S256");
        assert!(q["scope"].split(' ').any(|s| s == "openid"));
        let code = format!("code-{}", rand::random::<u64>());
        st.lock().unwrap().codes.insert(
            code.clone(),
            (
                q["nonce"].clone(),
                q["code_challenge"].clone(),
                q["redirect_uri"].clone(),
            ),
        );
        let to = format!("{}?code={code}&state={}", q["redirect_uri"], q["state"]);
        (StatusCode::FOUND, [(header::LOCATION, to)]).into_response()
    };
    let token = |State((url, st)): State<Shared>, headers: HeaderMap, body: String| async move {
        let f = query(&format!("http://x/?{body}"));
        let mut s = st.lock().unwrap();
        s.token_requests += 1;
        let basic = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("nexusbackup:{}", s.secret))
        );
        if headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) != Some(basic.as_str()) {
            return (StatusCode::UNAUTHORIZED, axum::Json(json!({"error": "invalid_client"}))).into_response();
        }
        let Some((nonce, challenge, redirect)) = s.codes.remove(&f["code"]) else {
            return (StatusCode::BAD_REQUEST, axum::Json(json!({"error": "invalid_grant"}))).into_response();
        };
        let pkce = URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(f["code_verifier"].as_bytes()));
        if pkce != challenge || f["redirect_uri"] != redirect || f["grant_type"] != "authorization_code" {
            return (StatusCode::BAD_REQUEST, axum::Json(json!({"error": "invalid_grant"}))).into_response();
        }
        let now = catalog::now();
        let mut c = json!({"iss": url, "aud": "nexusbackup", "exp": now + 300, "iat": now, "nonce": nonce});
        for (k, v) in s.user.as_object().unwrap() {
            c[k] = v.clone();
        }
        if let Some(f) = s.tamper.take() {
            f(&mut c);
        }
        let kid = s.signing.clone();
        let h = URL_SAFE_NO_PAD.encode(json!({"alg": "ES256", "kid": kid}).to_string());
        let p = URL_SAFE_NO_PAD.encode(c.to_string());
        let msg = format!("{h}.{p}");
        let key = &s.keys.iter().find(|(k, _)| *k == kid).unwrap().1;
        let sig = key.sign(&ring::rand::SystemRandom::new(), msg.as_bytes()).unwrap();
        let id_token = format!("{msg}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()));
        axum::Json(json!({"access_token": "at", "token_type": "Bearer", "id_token": id_token})).into_response()
    };
    use sha2::Digest;
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(disc))
        .route("/jwks", get(jwks))
        .route("/auth", get(auth))
        .route("/token", post(token))
        .with_state((url, st));
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    idp
}

/// Forgets failed OIDC callbacks (per IP; the tests run from one address).
fn unlock(t: &T) {
    let mut l = t.st.limiter.lock().unwrap();
    l.clear("oidc-ip:unknown");
    l.clear("ip:unknown");
}

/// Browser walk: start → IdP → callback. Returns the callback answer.
async fn oidc_login(t: &T, idp: &Idp, next: &str) -> R {
    unlock(t);
    let r = t.anon(&format!("/api/v1/auth/oidc/start?next={next}"), None).await;
    assert_eq!(r.status, StatusCode::FOUND, "{:?}", r.body);
    let to_idp = r.location();
    assert!(to_idp.starts_with(&format!("{}/auth?", idp.url)), "{to_idp}");
    let binder = r.cookie("nx_oidc").unwrap();
    let sc = r.headers[header::SET_COOKIE].to_str().unwrap();
    assert!(
        sc.contains("HttpOnly") && sc.contains("SameSite=Lax") && sc.contains("Path=/api/v1/auth/oidc"),
        "{sc}"
    );
    let q = query(&to_idp);
    assert_eq!(q["redirect_uri"], "https://nexus.test/api/v1/auth/oidc/callback");
    let back = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .get(&to_idp)
        .send()
        .await
        .unwrap();
    let cb = back.headers()[header::LOCATION].to_str().unwrap().to_owned();
    let path = cb.strip_prefix("https://nexus.test").unwrap();
    t.anon(path, Some(&format!("nx_oidc={binder}"))).await
}

fn session_of(r: &R) -> S {
    S {
        cookie: r.cookie("nx_session").expect("session cookie"),
        csrf: String::new(),
    }
}

#[tokio::test]
async fn oidc_settings_quorum_and_login_flow() {
    let t = T::new();
    let idp = fake_idp().await;
    let alice = t.login("alice").await;
    let sam = t.login("sam").await;
    // nothing configured
    let r = t.anon("/api/v1/auth/oidc", None).await;
    assert_eq!(r.body, json!({"enabled": false, "label": "Sign in with SSO"}));
    assert_eq!(
        t.anon("/api/v1/auth/oidc/start", None).await.location(),
        "/#/login?oidc_error=disabled"
    );
    let g = t.get("/api/v1/settings/oidc", &sam).await;
    assert_eq!(g.status, StatusCode::OK);
    assert_eq!(g.body["redirect_uri"], "https://nexus.test/api/v1/auth/oidc/callback");
    assert_eq!(
        t.get("/api/v1/settings/oidc", &t.login("otto").await).await.status,
        StatusCode::FORBIDDEN
    );
    let settings = json!({"enabled": true, "issuer": idp.url, "client_id": "nexusbackup", "client_secret": "client-s3cret",
        "scopes": ["openid", "profile", "groups"], "username_claim": "preferred_username", "groups_claim": "groups",
        "label": "Sign in with Fake IdP",
        "mappings": [{"group": "nexus-admins", "role": "admin", "tenants": []},
                     {"group": "acme-users", "role": "tenant_user", "tenants": ["acme"]},
                     {"group": "ops", "role": "operator", "tenants": []}]});
    assert_eq!(
        t.put("/api/v1/settings/oidc", &sam, settings.clone()).await.status,
        StatusCode::FORBIDDEN
    );
    // quorum while approvals are on: it changes who can log in
    let r = t.put("/api/v1/settings/oidc", &alice, settings.clone()).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    let list = t.get("/api/v1/quorum", &sam).await;
    let row = list
        .body
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == q)
        .unwrap()
        .clone();
    assert_eq!(row["action"], "oidc.update");
    assert_eq!(row["params"]["settings"]["client_secret"], "<redacted>");
    assert!(!list.body.to_string().contains("client-s3cret"));
    assert!(
        t.anon("/api/v1/auth/oidc", None).await.body["enabled"] == false,
        "not before approval"
    );
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.body["state"], "executed", "{:?}", r.body);
    assert_eq!(t.audit_count("settings.oidc"), 1);
    let raw = catalog::setting(&t.st.cat.conn(), "oidc").unwrap().unwrap();
    assert!(!raw.contains("client-s3cret") && raw.contains("enc:v1:"));
    let g = t.get("/api/v1/settings/oidc", &alice).await;
    assert_eq!(
        (g.body["client_secret_set"].as_bool(), g.body.get("client_secret")),
        (Some(true), None)
    );
    assert_eq!(
        t.anon("/api/v1/auth/oidc", None).await.body,
        json!({"enabled": true, "label": "Sign in with Fake IdP"})
    );
    // test endpoint: discovery + JWKS, endpoints recorded for the firewall
    let r = t.post("/api/v1/settings/oidc/test", &alice, json!({})).await;
    assert_eq!(r.body, json!({"discovery": "ok", "jwks": "ok: 1 keys"}));
    let ep: Value =
        serde_json::from_str(&catalog::setting(&t.st.cat.conn(), "oidc_endpoints").unwrap().unwrap()).unwrap();
    assert_eq!(ep["jwks_uri"], format!("{}/jwks", idp.url));

    // first login: JIT account from the mapping, session like a local one
    idp.st.lock().unwrap().user =
        json!({"sub": "kc-1", "preferred_username": "kc.alice", "groups": ["/nexus-admins", "acme-users"]});
    let r = oidc_login(&t, &idp, "/%23/jobs").await;
    assert_eq!(r.status, StatusCode::FOUND);
    assert_eq!(r.location(), "/#/jobs");
    let s = session_of(&r);
    let me = t.get("/api/v1/auth/me", &s).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(
        (
            me.body["user"]["name"].as_str(),
            me.body["user"]["role"].as_str(),
            me.body["user"]["auth"].as_str()
        ),
        (Some("kc.alice"), Some("admin"), Some("oidc"))
    );
    assert_eq!(t.audit_count("user.oidc_created"), 1);
    assert_eq!(t.audit_count("auth.oidc_login"), 1);
    // OIDC accounts cannot log in locally (no password, no TOTP)
    let r = t
        .send(T::req(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(&json!({"name": "kc.alice", "password": "!oidc", "totp": "000000"})),
        ))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // second login with other groups: role refreshed, same account
    idp.st.lock().unwrap().user = json!({"sub": "kc-1", "preferred_username": "renamed", "groups": ["acme-users"]});
    let r = oidc_login(&t, &idp, "/").await;
    let s2 = session_of(&r);
    let me = t.get("/api/v1/auth/me", &s2).await;
    assert_eq!(
        (
            me.body["user"]["name"].as_str(),
            me.body["user"]["role"].as_str(),
            me.body["user"]["tenant"].as_str()
        ),
        (Some("kc.alice"), Some("tenant_user"), Some("acme"))
    );
    assert_eq!(t.audit_count("user.oidc_updated"), 1);
    // role/tenant/credentials of OIDC accounts are the IdP's
    let id: i64 =
        t.st.cat
            .conn()
            .query_row("SELECT id FROM users WHERE name = 'kc.alice'", [], |r| r.get(0))
            .unwrap();
    let r = t
        .put(&format!("/api/v1/users/{id}"), &alice, json!({"role": "operator"}))
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // no mapping matches any more: denied and disabled; stays disabled after regaining a group
    idp.st.lock().unwrap().user = json!({"sub": "kc-1", "preferred_username": "kc.alice", "groups": ["nobody"]});
    assert_eq!(oidc_login(&t, &idp, "/").await.location(), "/#/login?oidc_error=denied");
    assert_eq!(
        t.get("/api/v1/auth/me", &s2).await.status,
        StatusCode::UNAUTHORIZED,
        "sessions ended"
    );
    idp.st.lock().unwrap().user = json!({"sub": "kc-1", "preferred_username": "kc.alice", "groups": ["ops"]});
    assert_eq!(
        oidc_login(&t, &idp, "/").await.location(),
        "/#/login?oidc_error=account_disabled"
    );
    // only an admin re-enables it
    let r = t
        .put(&format!("/api/v1/users/{id}"), &alice, json!({"disabled": false}))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let r = oidc_login(&t, &idp, "/").await;
    assert!(r.cookie("nx_session").is_some(), "{}", r.location());
    let r = t
        .put(&format!("/api/v1/users/{id}"), &alice, json!({"disabled": true}))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        oidc_login(&t, &idp, "/").await.location(),
        "/#/login?oidc_error=account_disabled"
    );
    // a local account's name is never taken over
    idp.st.lock().unwrap().user = json!({"sub": "kc-2", "preferred_username": "alice", "groups": ["nexus-admins"]});
    assert_eq!(oidc_login(&t, &idp, "/").await.location(), "/#/login?oidc_error=denied");
    idp.st.lock().unwrap().user = json!({"sub": "kc-3", "preferred_username": "bad name", "groups": ["ops"]});
    assert_eq!(oidc_login(&t, &idp, "/").await.location(), "/#/login?oidc_error=denied");
    // Entra-style UPN as the name
    idp.st.lock().unwrap().user =
        json!({"sub": "kc-5", "preferred_username": "bob@contoso.example", "groups": ["ops"]});
    let r = oidc_login(&t, &idp, "/").await;
    let me = t.get("/api/v1/auth/me", &session_of(&r)).await;
    assert_eq!(me.body["user"]["name"], "bob@contoso.example");

    // key rotation at the IdP: unknown kid → JWKS fetched again
    {
        let mut s = idp.st.lock().unwrap();
        s.published = vec!["k1".into(), "k2".into()];
        s.signing = "k2".into();
        s.user = json!({"sub": "kc-4", "preferred_username": "kc.otto", "groups": ["ops"]});
    }
    let r = oidc_login(&t, &idp, "/").await;
    assert!(r.cookie("nx_session").is_some(), "{}", r.location());
    // a key the JWKS never published (and no second forced fetch within 10 s)
    idp.st.lock().unwrap().signing = "k3".into();
    assert_eq!(oidc_login(&t, &idp, "/").await.location(), "/#/login?oidc_error=token");
    idp.st.lock().unwrap().signing = "k1".into();
    // wrong audience / issuer / nonce from the IdP: refused
    for f in [
        (|c: &mut Value| c["aud"] = json!("someone-else")) as fn(&mut Value),
        |c: &mut Value| c["iss"] = json!("https://evil.example"),
        |c: &mut Value| c["nonce"] = json!("replayed"),
        |c: &mut Value| c["exp"] = json!(catalog::now() - 3600),
    ] {
        idp.st.lock().unwrap().tamper = Some(f);
        assert_eq!(oidc_login(&t, &idp, "/").await.location(), "/#/login?oidc_error=token");
    }
    assert!(t.audit_count("auth.oidc_denied") >= 9);
}

#[tokio::test]
async fn oidc_state_binding_replay_and_redirects() {
    let t = T::new();
    t.approvals(false);
    let idp = fake_idp().await;
    let alice = t.login("alice").await;
    let r = t
        .put(
            "/api/v1/settings/oidc",
            &alice,
            json!({"enabled": true, "issuer": idp.url, "client_id": "nexusbackup", "client_secret": "client-s3cret",
                   "label": "SSO", "mappings": [{"group": "ops", "role": "operator", "tenants": []}]}),
        )
        .await;
    assert_eq!(
        (r.status, r.body["executed"].as_bool()),
        (StatusCode::OK, Some(true)),
        "{:?}",
        r.body
    );
    assert_eq!(t.audit_count("settings.oidc"), 1);
    idp.st.lock().unwrap().user = json!({"sub": "s1", "preferred_username": "kc.op", "groups": ["ops"]});

    // open redirect attempts end on the SPA root
    for evil in ["//evil.example/x", "https://evil.example/", "/%5Cevil.example", "evil"] {
        let r = oidc_login(&t, &idp, evil).await;
        assert_eq!(r.location(), "/", "{evil}");
    }

    // replayed callback (same state twice): the second one is refused
    let r = t.anon("/api/v1/auth/oidc/start", None).await;
    let binder = r.cookie("nx_oidc").unwrap();
    let back = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .get(r.location())
        .send()
        .await
        .unwrap();
    let cb = back.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .strip_prefix("https://nexus.test")
        .unwrap()
        .to_owned();
    let first = t.anon(&cb, Some(&format!("nx_oidc={binder}"))).await;
    assert!(first.cookie("nx_session").is_some(), "{}", first.location());
    let again = t.anon(&cb, Some(&format!("nx_oidc={binder}"))).await;
    assert_eq!(again.location(), "/#/login?oidc_error=state");
    assert!(again.cookie("nx_session").is_none());

    // a callback without the browser binding (login CSRF / stolen code) is refused, and burns the state
    let r = t.anon("/api/v1/auth/oidc/start", None).await;
    let back = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .get(r.location())
        .send()
        .await
        .unwrap();
    let cb = back.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .strip_prefix("https://nexus.test")
        .unwrap()
        .to_owned();
    assert_eq!(t.anon(&cb, None).await.location(), "/#/login?oidc_error=state");
    assert_eq!(
        t.anon(&cb, Some("nx_oidc=forged")).await.location(),
        "/#/login?oidc_error=state"
    );
    let binder = r.cookie("nx_oidc").unwrap();
    assert_eq!(
        t.anon(&cb, Some(&format!("nx_oidc={binder}"))).await.location(),
        "/#/login?oidc_error=state"
    );
    unlock(&t);
    // unknown state, IdP error
    assert_eq!(
        t.anon("/api/v1/auth/oidc/callback?code=x&state=nope", None)
            .await
            .location(),
        "/#/login?oidc_error=state"
    );
    let r = t.anon("/api/v1/auth/oidc/start", None).await;
    let state = query(&r.location())["state"].clone();
    let binder = r.cookie("nx_oidc").unwrap();
    let r = t
        .anon(
            &format!("/api/v1/auth/oidc/callback?error=access_denied&state={state}"),
            Some(&format!("nx_oidc={binder}")),
        )
        .await;
    assert_eq!(r.location(), "/#/login?oidc_error=idp");
    // failures count toward the per-address lockout like failed logins
    for _ in 0..3 {
        t.anon("/api/v1/auth/oidc/callback?code=x&state=nope", None).await;
    }
    assert_eq!(
        t.anon("/api/v1/auth/oidc/callback?code=x&state=nope", None)
            .await
            .location(),
        "/#/login?oidc_error=denied"
    );
    unlock(&t);
    // the IdP only ever exchanged codes that came with the right PKCE verifier
    assert!(idp.st.lock().unwrap().token_requests >= 5);

    // client secret: kept when omitted, refused by the IdP when wrong
    let s: Value = serde_json::from_str(&catalog::setting(&t.st.cat.conn(), "oidc").unwrap().unwrap()).unwrap();
    let r = t
        .put(
            "/api/v1/settings/oidc",
            &alice,
            json!({"enabled": true, "issuer": idp.url, "client_id": "nexusbackup", "client_secret_set": true,
                   "label": "SSO", "mappings": [{"group": "ops", "role": "operator", "tenants": []}]}),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let kept: Value = serde_json::from_str(&catalog::setting(&t.st.cat.conn(), "oidc").unwrap().unwrap()).unwrap();
    assert_eq!(kept["client_secret"], s["client_secret"]);
    idp.st.lock().unwrap().secret = "rotated".into();
    assert_eq!(oidc_login(&t, &idp, "/").await.location(), "/#/login?oidc_error=token");
    // invalid settings are refused before any quorum
    for bad in [
        json!({"enabled": true, "issuer": "http://idp.example.com", "client_id": "c", "label": "x", "mappings": [{"group": "g", "role": "admin"}]}),
        json!({"enabled": true, "issuer": idp.url, "client_id": "c", "label": "x", "mappings": []}),
        json!({"enabled": false, "issuer": idp.url, "client_id": "c", "label": "x", "mappings": [{"group": "g", "role": "admin", "tenants": ["acme"]}]}),
        json!({"enabled": false, "issuer": "", "client_id": "", "label": "x", "unknown": 1}),
    ] {
        assert_eq!(
            t.put("/api/v1/settings/oidc", &alice, bad.clone()).await.status,
            StatusCode::BAD_REQUEST,
            "{bad}"
        );
    }
}

// ---------------------------------------------------------------- snapshot delete (Phase 13a)

#[tokio::test]
async fn snapshot_delete_refuses_locked_and_needs_approval() {
    let t = T::new();
    let now = catalog::now();
    t.exec(&format!(
        "INSERT INTO snapshots (tenant, source, time, size, local, offsite, lock_until, origin) VALUES
           ('acme', 'vm-100', 1, 10, 1, 0, 0, NULL),
           ('acme', 'vm-100', 2, 10, 1, 1, {}, NULL),
           ('acme', 'vm-100', 3, 10, 0, 1, 0, NULL),
           ('acme', 'vm-100', 4, 10, 1, 0, 0, 'prim'),
           ('globex', 'vm-700', 1, 10, 1, 0, 0, NULL);",
        now + 3600
    ));
    let alice = t.login("alice").await;
    let otto = t.login("otto").await;
    let tina = t.login("tina").await;
    let sam = t.login("sam").await;
    let del = |path: &str, s: &S| T::req(Method::DELETE, path, Some(s), None);
    for (who, path, want) in [
        (&otto, "/api/v1/snapshots/acme/vm-100/1", StatusCode::FORBIDDEN),
        (&tina, "/api/v1/snapshots/acme/vm-100/1", StatusCode::FORBIDDEN),
        (&alice, "/api/v1/snapshots/acme/vm-100/9", StatusCode::NOT_FOUND),
        (&alice, "/api/v1/snapshots/acme/vm-100/2", StatusCode::CONFLICT), // locked
        (&alice, "/api/v1/snapshots/acme/vm-100/3", StatusCode::CONFLICT), // offsite only
        (&alice, "/api/v1/snapshots/acme/vm-100/4", StatusCode::CONFLICT), // replicated
        (&alice, "/api/v1/snapshots/acme/..%2Fx/1", StatusCode::BAD_REQUEST),
    ] {
        let r = t.send(del(path, who)).await;
        assert_eq!(r.status, want, "{path}: {:?}", r.body);
    }
    assert_eq!(t.audit_count("quorum.request"), 0, "refused before any request");
    // approvals on: a request another approver approves for the scheduler
    let r = t.send(del("/api/v1/snapshots/acme/vm-100/1", &alice)).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.body["state"], "approved", "the scheduler deletes it");
    let p: String =
        t.st.cat
            .conn()
            .query_row("SELECT params FROM quorum WHERE id = ?1", [q], |r| r.get(0))
            .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&p).unwrap(),
        json!({"tenant": "acme", "source": "vm-100", "time": 1})
    );
    // approvals off: an approved work item at once
    t.approvals(false);
    let r = t.send(del("/api/v1/snapshots/globex/vm-700/1", &alice)).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        (r.body["approvals"].as_str(), r.body["state"].as_str()),
        (Some("disabled"), Some("approved"))
    );
    assert_eq!(t.audit_count("snapshot.delete"), 1);
}

// ------------------------------------------------- storage accounting (13d/e)

/// `GET /storage`: figures from `backup_stats` of kept snapshots, per tenant
/// and group (ungrouped bucket), growth from capacity samples, tenant scoping;
/// real dedup / compression on the dashboard; quotas; anomaly settings.
#[tokio::test]
async fn storage_accounting_quota_and_anomaly_settings() {
    let t = T::new();
    let now = catalog::now();
    let day = 86400;
    t.exec(
        r#"INSERT INTO sources (id, tenant, kind, name, config) VALUES (1, 'acme', 'pve', 'pve-a', '{}'), (2, 'globex', 'pve', 'pve-g', '{}');
           INSERT INTO policies (id, name, schedule, gfs, offsite) VALUES (1, 'daily', 'daily 22:00', '{}', 0);
           INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES
             (1, 'acme', 1, 1, 'web', '[100]'), (2, 'globex', 2, 1, 'g2', '[200]');
           INSERT INTO snapshots (tenant, source, time, size, local, offsite) VALUES
             ('acme', 'vm-100', 1, 1000, 1, 0), ('acme', 'vm-100', 2, 1000, 1, 0), ('acme', 'ct-555', 1, 400, 1, 0),
             ('globex', 'vm-200', 1, 900, 1, 0), ('acme', 'vm-100', 9, 1000, 1, 0);
           INSERT INTO backup_stats (tenant, source, time, read, logical, new_chunks, new_plain, new_stored) VALUES
             ('acme', 'vm-100', 1, 1000, 1000, 4, 500, 250),
             ('acme', 'vm-100', 2, 100, 1000, 1, 100, 50),
             ('acme', 'ct-555', 1, 400, 400, 2, 400, 400),
             ('acme', 'vm-100', 3, 100, 1000, 1, 100, 50),
             ('globex', 'vm-200', 1, 900, 900, 3, 300, 100);"#,
    );
    // vm-100/3 is gone (no snapshot row), vm-100/9 has no stats (older release)
    for (i, used) in [(95, 100), (31, 200), (8, 300), (0, 450)] {
        t.st.cat
            .conn()
            .execute(
                "INSERT INTO capacity_samples (day, tenant, used, logical) VALUES (?1, 'acme', ?2, 0)",
                params![web_api::dashboard::day(now - i * day), used],
            )
            .unwrap();
    }
    let alice = t.login("alice").await;
    let r = t.get("/api/v1/storage", &alice).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let tot = &r.body["totals"];
    assert_eq!(
        (&tot["logical"], &tot["data_in"], &tot["stored"], &tot["saved"]),
        (&json!(3300), &json!(1300), &json!(800), &json!(2500))
    );
    assert_eq!((&tot["snapshots"], &tot["snapshots_all"]), (&json!(4), &json!(5)));
    assert_eq!(tot["compression"], json!(1300.0 / 800.0));
    let acme = r.body["tenants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["tenant"] == "acme")
        .unwrap();
    assert_eq!(acme["dedup"], json!(2400.0 / 1000.0));
    assert_eq!(acme["used"], json!(450));
    // growth: vs. the newest sample at least 7 / 30 / 90 days old
    assert_eq!(acme["growth"], json!({"d7": 150, "d30": 250, "d90": 350}));
    let groups = r.body["groups"].as_array().unwrap();
    let web = groups.iter().find(|g| g["group"] == "web").unwrap();
    assert_eq!((&web["logical"], &web["sources"]), (&json!(2000), &json!(1)));
    let loose = groups
        .iter()
        .find(|g| g["tenant"] == "acme" && g["group_id"].is_null())
        .unwrap();
    assert_eq!(loose["stored"], json!(400), "ct-555 is in no group");
    // dashboard tile: real ratios
    let d = t.get("/api/v1/dashboard?days=7", &alice).await;
    assert_eq!(d.body["capacity"]["dedup"], json!(3300.0 / 1300.0));
    assert_eq!(d.body["capacity"]["compression"], json!(1300.0 / 800.0));
    // tenant users: their tenant only
    let tina = t.login("tina").await;
    let r = t.get("/api/v1/storage", &tina).await;
    assert_eq!(r.body["tenants"].as_array().unwrap().len(), 1);
    assert_eq!(r.body["totals"]["logical"], json!(2400));
    assert!(r.body["groups"]
        .as_array()
        .unwrap()
        .iter()
        .all(|g| g["tenant"] == "acme"));

    // quota: admin only, soft (no approval), audited, shown in the tenant list
    assert_eq!(
        t.put("/api/v1/tenants/acme/quota", &tina, json!({"quota_bytes": 1}))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.put("/api/v1/tenants/acme/quota", &alice, json!({"quota_bytes": 0}))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        t.put("/api/v1/tenants/nope/quota", &alice, json!({"quota_bytes": 5}))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    let r = t
        .put("/api/v1/tenants/acme/quota", &alice, json!({"quota_bytes": 500}))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(t.audit_count("tenant.quota"), 1);
    let l = t.get("/api/v1/tenants", &alice).await;
    assert_eq!(l.body[0]["quota_bytes"], json!(500));
    let r = t.get("/api/v1/storage", &alice).await;
    assert_eq!(r.body["tenants"][0]["quota_used"], json!(0.9));
    t.put("/api/v1/tenants/acme/quota", &alice, json!({"quota_bytes": null}))
        .await;
    assert_eq!(
        t.get("/api/v1/tenants", &alice).await.body[0]["quota_bytes"],
        Value::Null
    );

    // anomaly thresholds: defaults; stricter applies, weaker needs approval
    let r = t.get("/api/v1/settings/anomaly", &alice).await;
    assert_eq!(
        r.body,
        json!({"enabled": true, "factor": 3.0, "history": 14, "floor_bytes": 1u64 << 30})
    );
    let otto = t.login("otto").await;
    assert_eq!(
        t.get("/api/v1/settings/anomaly", &otto).await.status,
        StatusCode::FORBIDDEN
    );
    let strict = json!({"enabled": true, "factor": 2.0, "history": 14, "floor_bytes": 1u64 << 30});
    let r = t.put("/api/v1/settings/anomaly", &alice, strict.clone()).await;
    assert_eq!((r.status, &r.body), (StatusCode::OK, &strict));
    for bad in [
        json!({"enabled": true, "factor": 1.0, "history": 14, "floor_bytes": 1u64 << 30}),
        json!({"enabled": true, "factor": 3.0, "history": 2, "floor_bytes": 1u64 << 30}),
        json!({"enabled": true, "factor": 3.0, "history": 14, "floor_bytes": 1}),
    ] {
        assert_eq!(
            t.put("/api/v1/settings/anomaly", &alice, bad.clone()).await.status,
            StatusCode::BAD_REQUEST,
            "{bad}"
        );
    }
    let off = json!({"enabled": false, "factor": 2.0, "history": 14, "floor_bytes": 1u64 << 30});
    let r = t.put("/api/v1/settings/anomaly", &alice, off.clone()).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    assert_eq!(t.get("/api/v1/settings/anomaly", &alice).await.body, strict);
    let sam = t.login("sam").await;
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.body["state"], "executed", "{:?}", r.body);
    assert_eq!(t.get("/api/v1/settings/anomaly", &alice).await.body, off);
}
