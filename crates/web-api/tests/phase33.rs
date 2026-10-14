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
    async fn post(&self, path: &str, s: &S, body: Value) -> R {
        self.call(Method::POST, path, Some(s), Some(body)).await
    }
    async fn delete(&self, path: &str, s: &S) -> R {
        self.call(Method::DELETE, path, Some(s), None).await
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

// ---------------------------------------------------------------- tenant-side approvers

const DAY: i64 = 86400;

/// dana: tenant admin of acme, an approver for more than 24 hours.
fn with_tenant_admin() -> T {
    let mut t = T::new();
    t.add_user("dana", "tenant_admin", Some("acme"), 0);
    t
}

fn quorum_row(t: &T, id: i64) -> (String, Option<String>, Option<String>) {
    t.st.cat
        .conn()
        .query_row(
            "SELECT state, decided_by, approved_by FROM quorum WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap()
}

/// Opt-in by a tenant admin (or an admin), only with an approver; a snapshot
/// delete of that tenant then needs the provider's and the tenant's approval in
/// any order; other tenants are unaffected; the tenant sees the request.
#[tokio::test]
async fn tenant_approvers_gate_destructive_requests() {
    let mut t = with_tenant_admin();
    t.add_user("gary", "tenant_admin", Some("globex"), 0);
    let (alice, sam, dana, tina) = (
        t.login("alice").await,
        t.login("sam").await,
        t.login("dana").await,
        t.login("tina").await,
    );
    let r = t.get("/api/v1/tenants/acme/approvers", &dana).await;
    assert_eq!((r.status, r.body["enabled"].clone()), (StatusCode::OK, json!(false)));
    assert_eq!(r.body["approvers"][0]["name"], "dana");
    assert_eq!(r.body["approvers"][0]["eligible"], true);
    let on = json!({"enabled": true});
    assert_eq!(
        t.put("/api/v1/tenants/acme/approvers", &tina, on.clone()).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.put("/api/v1/tenants/globex/approvers", &dana, on.clone())
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let r = t.put("/api/v1/tenants/acme/approvers", &dana, on.clone()).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        (r.body["enabled"].clone(), r.body["enabled_by"].clone()),
        (json!(true), json!("dana"))
    );
    assert_eq!(
        t.put("/api/v1/tenants/acme/approvers", &alice, on.clone()).await.status,
        StatusCode::CONFLICT
    );
    // a snapshot delete of acme: provider first, then the tenant
    let r = t.delete("/api/v1/snapshots/acme/vm-100/1000", &alice).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    let r = t.get("/api/v1/quorum", &dana).await;
    let row = r
        .body
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == q)
        .expect("dana sees the request");
    assert_eq!(
        row["tenant_approvals"],
        json!([{"tenant": "acme", "decided_by": null, "decided_at": null, "decision": null}])
    );
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        (r.body["state"].clone(), r.body["waiting_for"].clone()),
        (json!("pending"), json!(["acme"]))
    );
    assert_eq!(quorum_row(&t, q), ("pending".into(), None, Some("sam".into())));
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &alice, json!({})).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "the requester");
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &dana, json!({})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["state"], "approved", "the scheduler deletes it now");
    assert_eq!(
        quorum_row(&t, q),
        ("approved".into(), Some("sam".into()), Some("sam".into()))
    );
    // tenant first, then the provider
    let r = t.delete("/api/v1/snapshots/acme/vm-100/2000", &alice).await;
    let q = r.body["quorum_id"].as_i64().unwrap();
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &dana, json!({})).await;
    assert_eq!(
        (r.body["state"].clone(), r.body["provider_approved"].clone()),
        (json!("pending"), json!(false))
    );
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &dana, json!({})).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "decided already");
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.body["state"], "approved", "{:?}", r.body);
    // another tenant's request: the tenant admin of acme neither sees nor decides it
    let r = t.delete("/api/v1/snapshots/globex/vm-200/1500", &alice).await;
    let q = r.body["quorum_id"].as_i64().unwrap();
    let r = t.get("/api/v1/quorum", &dana).await;
    assert!(!r.body.as_array().unwrap().iter().any(|x| x["id"] == q));
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &dana, json!({})).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.body["state"], "approved", "globex did not opt in");
    // weakening a policy used by acme's group waits for acme as well
    let r = t
        .put(
            "/api/v1/policies/1",
            &alice,
            json!({"name": "daily", "schedule": "daily 22:00", "gfs": {"daily": 3, "weekly": 0, "monthly": 0, "yearly": 0},
                   "offsite": false}),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.body["waiting_for"], json!(["acme"]));
}

/// A new approver waits 24 hours; a tenant approver's refusal is final; with
/// approvals disabled the tenant is still asked; switching the requirement off
/// needs the tenant as well (a tenant admin's own request is its consent).
#[tokio::test]
async fn tenant_approvers_wait_refusal_and_opt_out() {
    let mut t = with_tenant_admin();
    t.add_user("nina", "tenant_admin", Some("acme"), 0);
    let (alice, sam, dana, nina) = (
        t.login("alice").await,
        t.login("sam").await,
        t.login("dana").await,
        t.login("nina").await,
    );
    assert_eq!(
        t.put("/api/v1/tenants/acme/approvers", &alice, json!({"enabled": true}))
            .await
            .status,
        StatusCode::OK
    );
    // nina just became a tenant admin (trigger: role change)
    t.exec("UPDATE users SET role = 'tenant_user' WHERE name = 'nina'; UPDATE users SET role = 'tenant_admin' WHERE name = 'nina';");
    let r = t.get("/api/v1/tenants/acme/approvers", &alice).await;
    let nina_row = r.body["approvers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == "nina")
        .unwrap()
        .clone();
    assert_eq!(nina_row["eligible"], false);
    assert!(
        nina_row["eligible_from"].as_i64().unwrap()
            >= t.one::<i64>("SELECT CAST(strftime('%s','now') AS INTEGER)") + DAY - 5
    );
    let r = t
        .post(
            "/api/v1/tenants/acme/deactivate",
            &alice,
            json!({"reason": "contract ended"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &nina, json!({})).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{:?}", r.body);
    assert!(r.body["error"].as_str().unwrap().contains("24 hours"));
    assert_eq!(
        t.post(&format!("/api/v1/quorum/{q}/reject"), &nina, json!({}))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    // dana refuses: final, the provider cannot approve any more
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.body["state"], "pending");
    let r = t.post(&format!("/api/v1/quorum/{q}/reject"), &dana, json!({})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &alice, json!({})).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(t.one::<i64>("SELECT disabled FROM tenants WHERE name = 'acme'"), 0);
    assert_eq!(
        t.one::<String>("SELECT decision FROM quorum_tenants WHERE quorum_id = (SELECT MAX(id) FROM quorum)"),
        "rejected"
    );
    // approvals disabled: a legal hold release still waits for the tenant
    t.exec(
        "INSERT INTO legal_holds (id, tenant, source, time, state, reason, held_by, held_at)
           VALUES (1, 'acme', 'vm-100', 1000, 'active', 'case', 'sam', 1);",
    );
    catalog::set_setting(&t.st.cat.conn(), "approvals_enabled", "false").unwrap();
    let r = t.delete("/api/v1/snapshots/acme/vm-100/1000/hold", &sam).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    assert_eq!(quorum_row(&t, q), ("pending".into(), None, Some("sam".into())));
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &dana, json!({})).await;
    assert_eq!(r.body["state"], "executed", "{:?}", r.body);
    assert_eq!(
        t.one::<String>("SELECT state FROM legal_holds WHERE id = 1"),
        "released"
    );
    catalog::set_setting(&t.st.cat.conn(), "approvals_enabled", "true").unwrap();
    // switching it off: dana's own request is acme's consent, the provider approves
    let r = t
        .put("/api/v1/tenants/acme/approvers", &dana, json!({"enabled": false}))
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    assert_eq!(
        t.one::<String>(&format!("SELECT decision FROM quorum_tenants WHERE quorum_id = {q}")),
        "requested"
    );
    assert_eq!(
        t.put("/api/v1/tenants/acme/approvers", &alice, json!({"enabled": false}))
            .await
            .status,
        StatusCode::CONFLICT
    );
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.body["state"], "executed", "{:?}", r.body);
    let r = t.get("/api/v1/tenants/acme/approvers", &alice).await;
    assert_eq!(r.body["enabled"], false);
}

/// Opt-in needs an activated tenant admin; an admin impersonating the tenant's
/// admin ("view as tenant", approved) cannot decide for the tenant.
#[tokio::test]
async fn tenant_approvers_need_an_approver() {
    let mut t = with_tenant_admin();
    t.add_user("adam", "admin", None, 0);
    let (alice, adam, sam, dana) = (
        t.login("alice").await,
        t.login("adam").await,
        t.login("sam").await,
        t.login("dana").await,
    );
    let r = t
        .put("/api/v1/tenants/globex/approvers", &alice, json!({"enabled": true}))
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert!(r.body["error"].as_str().unwrap().contains("no activated tenant admin"));
    let r = t.get("/api/v1/tenants/nope/approvers", &alice).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert_eq!(
        t.put("/api/v1/tenants/acme/approvers", &dana, json!({"enabled": true}))
            .await
            .status,
        StatusCode::OK
    );
    let r = t.delete("/api/v1/snapshots/acme/vm-100/1000", &adam).await;
    let q = r.body["quorum_id"].as_i64().unwrap();
    let r = t
        .post("/api/v1/tenants/acme/impersonate", &alice, json!({"elevated": true}))
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let imp = r.body["quorum_id"].as_i64().unwrap();
    let r = t.post(&format!("/api/v1/quorum/{imp}/approve"), &sam, json!({})).await;
    assert_eq!(r.body["state"], "executed", "{:?}", r.body);
    assert_eq!(
        t.get("/api/v1/auth/me", &alice).await.body["user"]["role"],
        "tenant_admin"
    );
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &alice, json!({})).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{:?}", r.body);
    let r = t.post(&format!("/api/v1/quorum/{q}/reject"), &alice, json!({})).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(quorum_row(&t, q).0, "pending");
}
