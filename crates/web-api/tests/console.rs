//! Phase 14c emergency console root access: `console.unlock` requests through
//! the quorum, the one-time code (shown once, to the requester, only its hash
//! on disk), expiry, revocation, the status list and the banner while a
//! console root shell runs.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use catalog::console::Unlock;
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

fn pw_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| catalog::auth::hash_password(PW).unwrap())
}

struct T {
    app: Router,
    st: Arc<AppState>,
    secrets: HashMap<String, String>,
    unlock: PathBuf,
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
        let unlock = dir.path().join("console-unlock");
        std::fs::create_dir(&unlock).unwrap();
        st.console_dir.set(unlock.clone()).unwrap();
        let mut secrets = HashMap::new();
        for (n, role, tenant) in [
            ("alice", "admin", None),
            ("bob", "admin", None),
            ("sam", "security_officer", None),
            ("otto", "operator", None),
            ("tina", "tenant_user", Some("acme")),
            ("tadmin", "admin", Some("acme")),
        ] {
            let secret = catalog::auth::new_totp_secret();
            let enc = st.totp.encrypt(n, &secret).unwrap();
            let c = st.cat.conn();
            if let Some(t) = tenant {
                c.execute("INSERT OR IGNORE INTO tenants (name) VALUES (?1)", [t])
                    .unwrap();
            }
            c.execute(
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
            unlock,
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
    async fn delete(&self, path: &str, s: &S) -> R {
        self.call(Method::DELETE, path, Some(s), None).await
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

    fn approvals(&self, on: bool) {
        catalog::set_setting(
            &self.st.cat.conn(),
            "approvals_enabled",
            if on { "true" } else { "false" },
        )
        .unwrap();
    }

    fn count(&self, sql: &str) -> i64 {
        self.st.cat.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }

    async fn status_of(&self, s: &S, id: i64) -> String {
        let l = self.get("/api/v1/console/unlock", s).await;
        assert_eq!(l.status, StatusCode::OK);
        l.body.as_array().unwrap().iter().find(|x| x["id"] == id).unwrap()["status"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}

const REQ: &str = "/api/v1/console/unlock";

#[tokio::test]
async fn unlock_needs_a_second_person_and_shows_the_code_once() {
    let t = T::new();
    t.approvals(true);
    let (alice, bob, sam, otto, tadmin) = (
        t.login("alice").await,
        t.login("bob").await,
        t.login("sam").await,
        t.login("otto").await,
        t.login("tadmin").await,
    );
    let body = json!({"hours": 2, "reason": "storage driver debugging"});
    // admins only, appliance-wide only, 1..8 h, a reason
    assert_eq!(t.post(REQ, &otto, body.clone()).await.status, StatusCode::FORBIDDEN);
    assert_eq!(t.post(REQ, &sam, body.clone()).await.status, StatusCode::FORBIDDEN);
    assert_eq!(t.post(REQ, &tadmin, body.clone()).await.status, StatusCode::FORBIDDEN);
    for bad in [
        json!({"hours": 0, "reason": "x"}),
        json!({"hours": 9, "reason": "x"}),
        json!({"hours": 1, "reason": " "}),
    ] {
        assert_eq!(t.post(REQ, &alice, bad).await.status, StatusCode::BAD_REQUEST);
    }
    let r = t.post(REQ, &alice, body).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let id = r.body["quorum_id"].as_i64().unwrap();
    assert_eq!(t.status_of(&sam, id).await, "pending");
    assert_eq!(t.get(REQ, &otto).await.status, StatusCode::FORBIDDEN);
    // no code before the approval; the requester cannot approve
    let code = format!("{REQ}/{id}/code");
    assert_eq!(t.post(&code, &alice, json!({})).await.status, StatusCode::CONFLICT);
    assert_eq!(
        t.post(&format!("/api/v1/quorum/{id}/approve"), &alice, json!({}))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let a = t.post(&format!("/api/v1/quorum/{id}/approve"), &sam, json!({})).await;
    assert_eq!((a.status, a.body["state"].as_str()), (StatusCode::OK, Some("approved")));
    assert_eq!(t.status_of(&alice, id).await, "approved");
    // only the requester sees the code
    assert_eq!(t.post(&code, &bob, json!({})).await.status, StatusCode::FORBIDDEN);
    assert_eq!(t.post(&code, &sam, json!({})).await.status, StatusCode::FORBIDDEN);
    let c = t.post(&code, &alice, json!({})).await;
    assert_eq!(c.status, StatusCode::OK, "{:?}", c.body);
    let shown = c.body["code"].as_str().unwrap().to_owned();
    assert_eq!(c.body["hours"], 2);
    assert_eq!(
        t.post(&code, &alice, json!({})).await.status,
        StatusCode::CONFLICT,
        "once"
    );
    // on disk: the hash, never the code
    let raw = std::fs::read_to_string(t.unlock.join(format!("{id}.json"))).unwrap();
    assert!(!raw.contains(&shown) && !raw.contains(&catalog::console::normalize(&shown).unwrap()));
    let u: Unlock = serde_json::from_str(&raw).unwrap();
    assert_eq!(
        (u.hash.clone(), u.hours, u.requested_by.as_str(), u.approved_by.as_str()),
        (catalog::console::hash(&shown).unwrap(), 2, "alice", "sam")
    );
    assert!(u.expires > catalog::now() + 23 * 3600);
    assert_eq!(catalog::console::find(&t.unlock, &shown, catalog::now()).unwrap().1, u);
    assert_eq!(std::fs::read_dir(&t.unlock).unwrap().count(), 1, "no temp file left");
    assert_eq!(t.status_of(&sam, id).await, "issued");
    assert_eq!(
        t.count("SELECT COUNT(*) FROM alerts WHERE kind = 'console_unlock' AND severity = 'critical' AND message LIKE '%approved by sam%'"),
        1
    );
    assert_eq!(
        t.count("SELECT COUNT(*) FROM audit WHERE action = 'console.unlock_code'"),
        1
    );
    // the console alerts are closed by admins and security officers only
    let alert = t.count("SELECT id FROM alerts WHERE kind = 'console_unlock'");
    assert_eq!(
        t.post(&format!("/api/v1/alerts/{alert}/ack"), &otto, json!({}))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.post(&format!("/api/v1/alerts/{alert}/ack"), &sam, json!({}))
            .await
            .status,
        StatusCode::OK
    );
    // the gate's audit entry marks it used
    t.st.cat
        .audit(
            "console",
            "console.root_shell",
            &format!("console-unlock/{id}"),
            &json!({}),
        )
        .unwrap();
    assert_eq!(t.status_of(&sam, id).await, "used");
    assert_eq!(
        t.delete(&format!("{REQ}/{id}"), &sam).await.status,
        StatusCode::CONFLICT
    );
    assert!(t.st.cat.verify_audit().is_ok());
}

#[tokio::test]
async fn approvals_off_expiry_and_revocation() {
    let t = T::new();
    t.approvals(false);
    let (alice, sam, otto) = (t.login("alice").await, t.login("sam").await, t.login("otto").await);
    let r = t.post(REQ, &alice, json!({"hours": 8, "reason": "r1"})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        (r.body["approvals"].as_str(), r.body["state"].as_str()),
        (Some("disabled"), Some("approved"))
    );
    let id = r.body["quorum_id"].as_i64().unwrap();
    assert_eq!(t.count("SELECT COUNT(*) FROM audit WHERE action = 'console.unlock'"), 1);
    // revoke before the code was fetched (security officer)
    assert_eq!(
        t.delete(&format!("{REQ}/{id}"), &otto).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(t.delete(&format!("{REQ}/{id}"), &sam).await.status, StatusCode::OK);
    assert_eq!(t.status_of(&alice, id).await, "revoked");
    assert_eq!(
        t.post(&format!("{REQ}/{id}/code"), &alice, json!({})).await.status,
        StatusCode::CONFLICT
    );

    // issued, then revoked: the file goes
    let id = t.post(REQ, &alice, json!({"hours": 1, "reason": "r2"})).await.body["quorum_id"]
        .as_i64()
        .unwrap();
    let c = t.post(&format!("{REQ}/{id}/code"), &alice, json!({})).await;
    assert_eq!(c.status, StatusCode::OK);
    assert_eq!(
        t.count("SELECT COUNT(*) FROM alerts WHERE kind = 'console_unlock' AND message LIKE '%approvals disabled%'"),
        1
    );
    assert!(t.unlock.join(format!("{id}.json")).exists());
    assert_eq!(t.delete(&format!("{REQ}/{id}"), &alice).await.status, StatusCode::OK);
    assert!(!t.unlock.join(format!("{id}.json")).exists());
    assert_eq!(t.status_of(&alice, id).await, "revoked");

    // a code must be fetched (and used) within 24 h of the approval
    let id = t.post(REQ, &alice, json!({"hours": 1, "reason": "r3"})).await.body["quorum_id"]
        .as_i64()
        .unwrap();
    t.st.cat
        .conn()
        .execute("UPDATE quorum SET decided_at = decided_at - 86400 WHERE id = ?1", [id])
        .unwrap();
    assert_eq!(t.status_of(&alice, id).await, "expired");
    let e = t.post(&format!("{REQ}/{id}/code"), &alice, json!({})).await;
    assert_eq!(e.status, StatusCode::CONFLICT);
    assert!(e.body.to_string().contains("expired"), "{:?}", e.body);
}

#[tokio::test]
async fn banner_while_a_console_shell_runs() {
    let t = T::new();
    let (otto, tina) = (t.login("otto").await, t.login("tina").await);
    assert!(t.get("/api/v1/auth/me", &otto).await.body["console_shell"].is_null());
    catalog::set_setting(
        &t.st.cat.conn(),
        catalog::console::SHELL_SETTING,
        &json!({"at": 1, "until": 3601, "method": "recovery_key", "unlock": null, "alert": 4}).to_string(),
    )
    .unwrap();
    let me = t.get("/api/v1/auth/me", &otto).await;
    assert_eq!(me.body["console_shell"]["method"], "recovery_key");
    assert_eq!(
        t.get("/api/v1/dashboard", &otto).await.body["console_shell"]["until"],
        3601
    );
    assert!(t.get("/api/v1/auth/me", &tina).await.body["console_shell"].is_null());
    assert!(t.get("/api/v1/dashboard", &tina).await.body["console_shell"].is_null());
    assert_eq!(t.get(REQ, &tina).await.status, StatusCode::FORBIDDEN);
}
