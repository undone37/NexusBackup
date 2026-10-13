//! Phase 22a network interfaces: the status of nexus-net, validation, approval and the request
//! file, the confirmation of a management change, the path-MTU check request, RBAC. The helper
//! is simulated by writing its status.json / ops.json.

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

fn pw_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| catalog::auth::hash_password(PW).unwrap())
}

struct T {
    app: Router,
    st: Arc<AppState>,
    secrets: HashMap<String, String>,
    net: PathBuf,
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

fn empty_config() -> Value {
    json!({"interfaces": [], "offsite_role": "management"})
}

/// What nexus-net reports for a host with five NICs, the management network from the console on
/// ens3, nothing configured here yet.
fn status(now: i64, config: Value, pending: Value) -> Value {
    let nic = |n: &str| json!({"name": n, "kind": "nic", "mac": "52:54:00:00:00:01", "mtu": 1500, "state": "up",
                               "speed": 1000, "master": null, "addresses": []});
    json!({"version": 1, "scanned": now,
           "devices": [nic("ens3"), nic("ens4"), nic("ens5"), nic("ens6"), nic("ens7")],
           "config": config, "reset": null,
           "management": {"ifname": "ens3", "source": "console"},
           "pending": pending,
           "mtu": {"ts": now, "results": [{"role": "data", "addr": "10.0.20.7", "dev": "bond0.20", "expected_dev": "bond0.20",
                                           "mtu": 9000, "result": "mismatch", "path_mtu": 1500}]}})
}

fn data_config() -> Value {
    json!({"interfaces": [
        {"name": "bond0", "kind": "bond", "ports": ["ens4", "ens5"], "mode": "802.3ad", "mtu": 9000},
        {"name": "bond0.20", "kind": "vlan", "parent": "bond0", "vlan_id": 20, "role": "data", "mtu": 9000,
         "addresses": ["10.0.20.5/24"], "routes": [{"to": "10.30.0.0/16", "via": "10.0.20.1"}]}
    ]})
}

impl T {
    fn new() -> T {
        let dir = tempfile::tempdir().unwrap();
        let cat = Catalog::open(&dir.path().join("catalog.db")).unwrap();
        let downloads = dir.path().join("downloads");
        std::fs::create_dir(&downloads).unwrap();
        let st = AppState::with_keys(cat, None, downloads, TotpKey::generate(), None);
        let net = dir.path().join("net");
        std::fs::create_dir(&net).unwrap();
        st.net_dir.set(net.clone()).unwrap();
        st.cat
            .conn()
            .execute("INSERT INTO tenants (name) VALUES ('acme')", [])
            .unwrap();
        let mut secrets = HashMap::new();
        for (n, role, tenant) in [
            ("alice", "admin", None),
            ("ada", "admin", None),
            ("otto", "operator", None),
            ("vic", "viewer", None),
            ("vera", "viewer", Some("acme")),
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
            net,
            _dir: dir,
        }
    }

    fn helper_status(&self, s: &Value) {
        std::fs::write(self.net.join("status.json"), s.to_string()).unwrap();
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

    async fn put_net(&self, s: &S, c: Value) -> R {
        self.call(Method::PUT, "/api/v1/network", Some(s), Some(json!({"config": c})))
            .await
    }

    async fn confirm(&self, s: &S, id: &str, keep: bool) -> R {
        let body = json!({"id": id, "keep": keep});
        self.call(Method::POST, "/api/v1/network/confirm", Some(s), Some(body))
            .await
    }

    async fn mtu(&self, s: &S) -> R {
        self.call(Method::POST, "/api/v1/network/mtu-check", Some(s), Some(json!({})))
            .await
    }

    /// The request files nexus-net would pick up (and removes them, as the helper does).
    fn take_requests(&self) -> Vec<Value> {
        let mut v = Vec::new();
        for e in std::fs::read_dir(&self.net).unwrap().filter_map(Result::ok) {
            if e.file_name().to_string_lossy().starts_with("req-") {
                v.push(serde_json::from_slice(&std::fs::read(e.path()).unwrap()).unwrap());
                std::fs::remove_file(e.path()).unwrap();
            }
        }
        v
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
async fn status_roles_and_validation() {
    let t = T::new();
    let (alice, otto, vic, vera) = (
        login(&t, "alice").await,
        login(&t, "otto").await,
        login(&t, "vic").await,
        login(&t, "vera").await,
    );
    let r = t.call(Method::GET, "/api/v1/network", Some(&vic), None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body["available"], false);
    assert_eq!(r.body["config"], empty_config());
    assert_eq!(
        t.call(Method::GET, "/api/v1/network", Some(&vera), None)
            .await
            .status,
        StatusCode::FORBIDDEN,
        "tenant-scoped viewer"
    );
    // no status: nothing can be changed yet
    let r = t
        .call(Method::PUT, "/api/v1/network", Some(&alice), Some(json!({"config": data_config()})))
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);

    let now = catalog::now();
    t.helper_status(&status(now, empty_config(), Value::Null));
    let r = t.call(Method::GET, "/api/v1/network", Some(&otto), None).await;
    assert_eq!(r.body["available"], true);
    assert_eq!(r.body["devices"].as_array().unwrap().len(), 5);
    assert_eq!(r.body["management"]["ifname"], "ens3");
    assert_eq!(r.body["mtu"]["results"][0]["result"], "mismatch");
    assert_eq!(r.body["confirm_secs"], 120);

    // only admins change it; the server validates against the NICs the helper reported
    assert_eq!(t.put_net(&otto, data_config()).await.status, StatusCode::FORBIDDEN);
    for (cfg, want) in [
        (json!({"interfaces": [{"name": "ens9", "kind": "ethernet"}]}), "no network card"),
        (
            json!({"interfaces": [{"name": "bond0", "kind": "bond", "ports": ["ens3"], "mode": "802.3ad"}]}),
            "management network card",
        ),
        (
            json!({"interfaces": [{"name": "ens4", "kind": "ethernet", "addresses": ["10.0.0.5/24"], "gateway": "10.0.0.1"}]}),
            "only the management",
        ),
    ] {
        let r = t.put_net(&alice, cfg).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{want}");
        assert!(r.body["error"].as_str().unwrap_or_default().contains(want), "{:?}", r.body);
    }
    let r = t.put_net(&alice, json!({"interfaces": [{"name": "ens4", "kind": "ethernet", "bogus": 1}]})).await;
    assert!(r.status.is_client_error());
    // unchanged: nothing to approve
    let r = t.put_net(&alice, empty_config()).await;
    assert_eq!((r.status, r.body["unchanged"].clone()), (StatusCode::OK, json!(true)));
    assert!(t.take_requests().is_empty());
}

#[tokio::test]
async fn apply_needs_approval_then_request_file() {
    let t = T::new();
    let (alice, ada) = (login(&t, "alice").await, login(&t, "ada").await);
    let now = catalog::now();
    t.helper_status(&status(now, empty_config(), Value::Null));
    let r = t
        .call(Method::PUT, "/api/v1/network", Some(&alice), Some(json!({"config": data_config()})))
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let qid = r.body["quorum_id"].as_i64().unwrap();
    assert!(t.take_requests().is_empty(), "nothing before the approval");
    let r = t.call(Method::GET, "/api/v1/network", Some(&alice), None).await;
    assert_eq!(r.body["request_pending"], qid);
    let r = t
        .call(Method::POST, &format!("/api/v1/quorum/{qid}/approve"), Some(&ada), Some(json!({})))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["state"], "executed");
    let reqs = t.take_requests();
    assert_eq!(reqs.len(), 1);
    let q = &reqs[0];
    assert_eq!((q["op"].as_str(), q["by"].as_str(), q["quorum_id"].as_i64()), (Some("apply"), Some("alice"), Some(qid)));
    assert_eq!(q["old"], empty_config());
    assert_eq!(q["config"]["interfaces"][1]["vlan_id"], 20);
    assert_eq!(q["config"]["interfaces"][0]["gateway"], Value::Null, "every field serialized");
    assert_eq!(t.audit_count("network.apply"), 1);

    // approvals off: the request file at once; a management move is flagged for the approver
    catalog::set_setting(&t.st.cat.conn(), "approvals_enabled", "false").unwrap();
    let mgmt = json!({"interfaces": [{"name": "bond1", "kind": "bond", "ports": ["ens3", "ens7"], "mode": "active-backup",
                                      "role": "management", "addresses": ["192.0.2.10/24"], "gateway": "192.0.2.1"}]});
    let r = t
        .call(Method::PUT, "/api/v1/network", Some(&alice), Some(json!({"config": mgmt})))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["executed"], true);
    assert_eq!(t.take_requests().len(), 1);
    let p: String = t
        .st
        .cat
        .conn()
        .query_row(
            "SELECT details FROM audit WHERE action = 'network.apply' ORDER BY seq DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(p.contains("\"management_change\":true"), "{p}");
}

#[tokio::test]
async fn confirm_and_mtu_check() {
    let t = T::new();
    let (alice, otto, vic) = (login(&t, "alice").await, login(&t, "otto").await, login(&t, "vic").await);
    let now = catalog::now();
    let pid = "e".repeat(32);
    t.helper_status(&status(
        now,
        empty_config(),
        json!({"id": pid, "by": "alice", "deadline": now + 100}),
    ));
    let r = t.call(Method::GET, "/api/v1/network", Some(&vic), None).await;
    assert_eq!(r.body["pending"]["id"], pid.as_str());
    assert!(r.body["pending"]["remaining"].as_i64().unwrap() > 90);
    // no other change meanwhile
    let r = t
        .call(Method::PUT, "/api/v1/network", Some(&alice), Some(json!({"config": data_config()})))
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(t.confirm(&otto, &pid, true).await.status, StatusCode::FORBIDDEN);
    assert_eq!(t.confirm(&alice, "x", true).await.status, StatusCode::CONFLICT);
    let r = t.confirm(&alice, &pid, true).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let c: Value = serde_json::from_slice(&std::fs::read(t.net.join("confirm.json")).unwrap()).unwrap();
    assert_eq!(c, json!({"id": pid, "keep": true, "by": "alice"}));
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(t.net.join("confirm.json")).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o640);
    assert_eq!(t.audit_count("network.confirm"), 1);
    assert_eq!(t.confirm(&alice, &pid, false).await.status, StatusCode::ACCEPTED);
    assert_eq!(t.audit_count("network.revert"), 1);
    // past the deadline: gone
    t.helper_status(&status(now, empty_config(), json!({"id": pid, "by": "alice", "deadline": now - 1})));
    assert_eq!(t.confirm(&alice, &pid, true).await.status, StatusCode::CONFLICT);
    let r = t.call(Method::GET, "/api/v1/network", Some(&vic), None).await;
    assert_eq!(r.body["pending"], Value::Null);

    // path-MTU check: admins and operators
    assert_eq!(t.mtu(&vic).await.status, StatusCode::FORBIDDEN);
    assert_eq!(t.mtu(&otto).await.status, StatusCode::ACCEPTED);
    let r = t.call(Method::GET, "/api/v1/network", Some(&vic), None).await;
    assert_eq!(r.body["ops"][0]["state"], "queued");
    let reqs = t.take_requests();
    assert_eq!((reqs.len(), reqs[0]["op"].as_str()), (1, Some("mtu_check")));
    assert_eq!(t.audit_count("network.mtu_check"), 1);
}
