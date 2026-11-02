//! Reboot and shutdown (top bar > Power, issue #179): RBAC, the approval of both actions, the request file for
//! nexus-power with the running jobs, the refusals (scheduled already, an update in progress, checked again at
//! the approval), cancel. The helper is simulated by writing its status.json.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
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
const PATH: &str = "/api/v1/system/power";

fn pw_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| catalog::auth::hash_password(PW).unwrap())
}

struct T {
    app: Router,
    st: Arc<AppState>,
    secrets: HashMap<String, String>,
    power: PathBuf,
    update: PathBuf,
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

fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .unwrap()
        .trim()
        .to_owned()
}

impl T {
    fn new() -> T {
        let dir = tempfile::tempdir().unwrap();
        let cat = Catalog::open(&dir.path().join("catalog.db")).unwrap();
        let downloads = dir.path().join("downloads");
        std::fs::create_dir(&downloads).unwrap();
        let st = AppState::with_keys(cat, None, downloads, TotpKey::generate(), None);
        let (power, update) = (dir.path().join("power"), dir.path().join("update"));
        std::fs::create_dir(&power).unwrap();
        std::fs::create_dir(&update).unwrap();
        st.power_dir.set(power.clone()).unwrap();
        st.update_dir.set(update.clone()).unwrap();
        st.cat
            .conn()
            .execute("INSERT INTO tenants (name) VALUES ('acme')", [])
            .unwrap();
        let mut secrets = HashMap::new();
        for (n, role, tenant) in [
            ("alice", "admin", None),
            ("ada", "admin", None),
            ("otto", "operator", None),
            ("sam", "security_officer", None),
            ("vic", "viewer", None),
            ("vera", "tenant_admin", Some("acme")),
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
        T {
            app: web_api::router(st.clone()),
            st,
            secrets,
            power,
            update,
            _dir: dir,
        }
    }

    /// The request nexus-power would pick up (removed, as the helper does).
    fn take_request(&self) -> Option<Value> {
        let p = self.power.join("request.json");
        let v = serde_json::from_slice(&std::fs::read(&p).ok()?).unwrap();
        std::fs::remove_file(p).unwrap();
        Some(v)
    }

    async fn post(&self, s: &S, body: Value) -> R {
        self.call(Method::POST, PATH, Some(s), Some(body)).await
    }

    async fn approve(&self, s: &S, id: i64) -> R {
        self.call(
            Method::POST,
            &format!("/api/v1/quorum/{id}/approve"),
            Some(s),
            Some(json!({})),
        )
        .await
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
        let raw = res.into_body().collect().await.unwrap().to_bytes().to_vec();
        R {
            status,
            body: serde_json::from_slice(&raw).unwrap_or(Value::Null),
        }
    }

    fn audit_count(&self, action: &str) -> i64 {
        self.st
            .cat
            .conn()
            .query_row("SELECT COUNT(*) FROM audit WHERE action = ?1", [action], |r| r.get(0))
            .unwrap()
    }
}

async fn login(t: &T, name: &str) -> S {
    let code = catalog::auth::totp_now(&t.secrets[name]).unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/login")
        .header(header::HOST, "nexus.test")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"name": name, "password": PW, "totp": code}).to_string(),
        ))
        .unwrap();
    let res = t.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK, "{name}");
    let cookie = res
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| c.strip_prefix("nx_session=")?.split(';').next().map(str::to_owned))
        .unwrap();
    let raw = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&raw).unwrap();
    S {
        cookie,
        csrf: body["csrf"].as_str().unwrap().to_owned(),
    }
}

#[tokio::test]
async fn status_and_roles() {
    let t = T::new();
    let (alice, otto, sam, vic, vera) = (
        login(&t, "alice").await,
        login(&t, "otto").await,
        login(&t, "sam").await,
        login(&t, "vic").await,
        login(&t, "vera").await,
    );
    for s in [&alice, &otto, &sam] {
        let r = t.call(Method::GET, PATH, Some(s), None).await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
        assert_eq!(r.body["pending"], Value::Null);
        assert_eq!(r.body["blockers"], json!([]));
        assert_eq!(r.body["approval_required"], true);
        assert_eq!(r.body["max_delay_s"], 300);
    }
    for s in [&vic, &vera] {
        assert_eq!(
            t.call(Method::GET, PATH, Some(s), None).await.status,
            StatusCode::FORBIDDEN
        );
    }
    // only appliance-wide admins request or cancel
    let body = json!({"action": "reboot", "reason": "kernel update"});
    for s in [&otto, &sam, &vic, &vera] {
        assert_eq!(t.post(s, body.clone()).await.status, StatusCode::FORBIDDEN);
        assert_eq!(
            t.call(Method::DELETE, PATH, Some(s), None).await.status,
            StatusCode::FORBIDDEN
        );
    }
    for bad in [
        json!({"action": "halt", "reason": "kernel update"}),
        json!({"action": "reboot", "reason": "x"}),
        json!({"action": "reboot", "reason": "kernel update", "delay_s": 301}),
        json!({"action": "reboot", "reason": "kernel update", "extra": 1}),
    ] {
        let r = t.post(&alice, bad.clone()).await;
        assert!(r.status.is_client_error(), "{bad}: {:?}", r.body);
    }
    assert!(t.take_request().is_none());
    assert_eq!(t.audit_count("quorum.request"), 0);
}

/// Security (#179): one admin account alone neither reboots nor shuts the appliance down while approvals
/// are on; the request for nexus-power exists only after a second person approved.
#[tokio::test]
async fn both_actions_need_approval_then_request_file() {
    let t = T::new();
    let (alice, ada) = (login(&t, "alice").await, login(&t, "ada").await);
    t.st.cat
        .conn()
        .execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES ('backup', 'acme', '{}', 'running', 'scheduler', 0)",
            [],
        )
        .unwrap();
    for action in ["reboot", "poweroff"] {
        let r = t
            .post(
                &alice,
                json!({"action": action, "reason": "  rack move  ", "delay_s": 60}),
            )
            .await;
        assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
        let qid = r.body["quorum_id"].as_i64().unwrap();
        assert!(t.take_request().is_none(), "nothing before the approval");
        let v = t.call(Method::GET, PATH, Some(&alice), None).await.body;
        assert_eq!(v["request_pending"]["id"], qid);
        assert_eq!(v["running_jobs"], 1);
        assert_eq!(v["running_by_kind"], json!([{"kind": "backup", "count": 1}]));
        // the approver sees what it interrupts
        let p: Value = serde_json::from_str(
            &t.st
                .cat
                .conn()
                .query_row("SELECT params FROM quorum WHERE id = ?1", [qid], |r| {
                    r.get::<_, String>(0)
                })
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            (p["running_jobs"].as_i64(), p["reason"].as_str()),
            (Some(1), Some("rack move"))
        );
        assert_eq!(
            t.approve(&alice, qid).await.status,
            StatusCode::FORBIDDEN,
            "own request"
        );
        let r = t.approve(&ada, qid).await;
        assert_eq!(
            (r.status, r.body["state"].as_str()),
            (StatusCode::OK, Some("executed")),
            "{:?}",
            r.body
        );
        let q = t.take_request().expect("request.json for nexus-power");
        assert_eq!(q["action"], action);
        assert_eq!((q["delay_s"].as_u64(), q["running_jobs"].as_i64()), (Some(60), Some(1)));
        assert_eq!(
            (q["requested_by"].as_str(), q["approved_by"].as_str()),
            (Some("alice"), Some("ada"))
        );
        assert_eq!(q["id"].as_str().map(str::len), Some(32));
    }
    assert_eq!(
        (t.audit_count("system.reboot"), t.audit_count("system.poweroff")),
        (1, 1)
    );

    // approvals off: the request file at once, still audited
    catalog::set_setting(&t.st.cat.conn(), "approvals_enabled", "false").unwrap();
    let r = t
        .post(&alice, json!({"action": "reboot", "reason": "hung service"}))
        .await;
    assert_eq!(
        (r.status, r.body["executed"].as_bool()),
        (StatusCode::OK, Some(true)),
        "{:?}",
        r.body
    );
    let q = t.take_request().unwrap();
    assert_eq!(
        (q["delay_s"].as_u64(), q["approved_by"].clone()),
        (Some(0), Value::Null)
    );
    assert_eq!(t.audit_count("system.reboot"), 2);
}

#[tokio::test]
async fn refused_while_an_update_runs_or_one_is_scheduled() {
    let t = T::new();
    let (alice, ada) = (login(&t, "alice").await, login(&t, "ada").await);
    let body = json!({"action": "reboot", "reason": "kernel update"});
    // an update request waits for nexus-update
    std::fs::write(t.update.join("request"), "stage\n").unwrap();
    let r = t.post(&alice, body.clone()).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
    assert!(r.body["error"].as_str().unwrap().contains("update"), "{:?}", r.body);
    let v = t.call(Method::GET, PATH, Some(&alice), None).await.body;
    assert_eq!(v["blockers"].as_array().map(Vec::len), Some(1));
    // forced: accepted
    let r = t
        .post(
            &alice,
            json!({"action": "reboot", "reason": "kernel update", "force": true}),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let forced = r.body["quorum_id"].as_i64().unwrap();
    std::fs::remove_file(t.update.join("request")).unwrap();
    // requested while idle, then an update starts: the approval is refused and the request stays pending
    let qid = t.post(&alice, body.clone()).await.body["quorum_id"].as_i64().unwrap();
    std::fs::write(t.update.join("request"), "apply\n").unwrap();
    let r = t.approve(&ada, qid).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
    assert!(t.take_request().is_none());
    // the forced one goes through
    let r = t.approve(&ada, forced).await;
    assert_eq!(r.body["state"], "executed", "{:?}", r.body);
    assert_eq!(t.take_request().unwrap()["force"], true);
    std::fs::remove_file(t.update.join("request")).unwrap();

    // nexus-power scheduled one in this boot: no second, cancel it
    let at = catalog::now() + 60;
    std::fs::write(
        t.power.join("status.json"),
        json!({"boot_id": boot_id(), "pending": {"id": "a".repeat(32), "action": "reboot", "at": at,
               "reason": "kernel update", "requested_by": "alice", "approved_by": "ada"},
               "last": {"result": "scheduled"}})
        .to_string(),
    )
    .unwrap();
    let v = t.call(Method::GET, PATH, Some(&alice), None).await.body;
    assert_eq!(v["pending"]["at"], at);
    assert_eq!(t.post(&alice, body.clone()).await.status, StatusCode::CONFLICT);
    assert_eq!(t.approve(&ada, qid).await.status, StatusCode::CONFLICT);
    let r = t.call(Method::DELETE, PATH, Some(&alice), None).await;
    assert_eq!(
        (r.status, r.body["action"].as_str()),
        (StatusCode::OK, Some("reboot")),
        "{:?}",
        r.body
    );
    assert_eq!(t.take_request().unwrap()["action"], "cancel");
    assert_eq!(t.audit_count("system.power_cancel"), 1);
    // after the reboot (another boot id) nothing is pending
    std::fs::write(
        t.power.join("status.json"),
        json!({"boot_id": "earlier-boot", "pending": {"action": "reboot", "at": at}}).to_string(),
    )
    .unwrap();
    let v = t.call(Method::GET, PATH, Some(&alice), None).await.body;
    assert_eq!(v["pending"], Value::Null);
    assert_eq!(
        t.call(Method::DELETE, PATH, Some(&alice), None).await.status,
        StatusCode::CONFLICT
    );
}
