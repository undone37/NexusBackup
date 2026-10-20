//! Phase 19a: bare-metal recovery and P2V sessions (docs/bmr.md): recovery token
//! issue (sealed digest, public lookup, shown once), RBAC, the unauthenticated
//! check-in (validation, rate limit, unknown tokens), start → `bmr` job, cancel,
//! expiry, P2V → `p2v` job and the unattended start at check-in.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use catalog::rusqlite::params;
use catalog::secret::{rescue_p2v_token_location, rescue_token_location, SchedulerKey, TotpKey};
use catalog::Catalog;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use tower::ServiceExt;
use web_api::AppState;

const PW: &str = "correct horse battery";
const AGENT: &str = "0123456789abcdef";
const OTHER: &str = "1111111111111111";

fn pw_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| catalog::auth::hash_password(PW).unwrap())
}

struct T {
    app: Router,
    st: Arc<AppState>,
    secrets: HashMap<String, String>,
    sk: SchedulerKey,
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
        let sk = SchedulerKey::generate();
        let public = dir.path().join("secrets.pub");
        sk.write_public(&public, None).unwrap();
        let st = AppState::with_keys(cat, None, downloads, TotpKey::generate(), Some(public));
        let mut secrets = HashMap::new();
        st.cat
            .conn()
            .execute_batch(
                r#"INSERT INTO tenants (name) VALUES ('acme'), ('globex');
                   INSERT INTO sources (id, tenant, kind, name, config) VALUES (1, 'acme', 'pve', 'pve-a', '{}'),
                     (2, 'globex', 'pve', 'pve-g', '{}'), (3, 'acme', 'linux', 'web01', '{"agent_id":"0123456789abcdef"}');
                   INSERT INTO agents (id, tenant, name, host, port) VALUES ('0123456789abcdef', 'acme', 'web01', 'web01.lab', 7444),
                     ('1111111111111111', 'globex', 'db01', 'db01.lab', 7444);
                   INSERT INTO snapshots (tenant, source, time, local, offsite) VALUES ('acme', 'host-0123456789abcdef', 1000, 1, 0);"#,
            )
            .unwrap();
        for (n, role, tenant) in [
            ("alice", "admin", None),
            ("otto", "operator", None),
            ("vic", "viewer", None),
            ("tina", "tenant_user", Some("acme")),
            ("gina", "operator", Some("globex")),
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
            sk,
            _dir: dir,
        }
    }

    async fn call(&self, method: Method, path: &str, s: Option<&S>, body: Option<Value>) -> (R, Option<String>) {
        let mut b = Request::builder()
            .method(method.clone())
            .uri(path)
            .header(header::HOST, "nexus.test:8443");
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
        (
            R {
                status,
                body: serde_json::from_slice(&raw).unwrap_or(Value::Null),
            },
            cookie,
        )
    }

    async fn get(&self, path: &str, s: &S) -> R {
        self.call(Method::GET, path, Some(s), None).await.0
    }
    async fn post(&self, path: &str, s: &S, body: Value) -> R {
        self.call(Method::POST, path, Some(s), Some(body)).await.0
    }
    async fn checkin(&self, body: Value) -> R {
        self.call(Method::POST, "/api/v1/rescue/checkin", None, Some(body))
            .await
            .0
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

    fn audit(&self, action: &str) -> i64 {
        self.one(&format!("SELECT COUNT(*) FROM audit WHERE action = '{action}'"))
    }
}

fn checkin_body(token: &str) -> Value {
    json!({"lookup": agent_proto::rescue_lookup(token), "host": "192.0.2.50", "port": 7444,
           "disks": [{"path": "/dev/sda", "size": 21474836480u64}], "version": "0.2.0"})
}

#[tokio::test]
async fn recovery_token_checkin_start_cancel() {
    let t = T::new();
    let (alice, otto, vic, tina, gina) = (
        t.login("alice").await,
        t.login("otto").await,
        t.login("vic").await,
        t.login("tina").await,
        t.login("gina").await,
    );
    let url = format!("/api/v1/agents/{AGENT}/rescue");
    // RBAC: viewers and tenant users cannot issue; other tenants do not see the agent
    assert_eq!(t.post(&url, &vic, json!({})).await.status, StatusCode::FORBIDDEN);
    assert_eq!(t.post(&url, &tina, json!({})).await.status, StatusCode::FORBIDDEN);
    assert_eq!(t.post(&url, &gina, json!({})).await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        t.post("/api/v1/agents/ffffffffffffffff/rescue", &alice, json!({}))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    let r = t.post(&url, &otto, json!({"reboot": false})).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let token = r.body["token"].as_str().unwrap().to_owned();
    let id = r.body["id"].as_str().unwrap().to_owned();
    assert_eq!(token.len(), 26);
    assert_eq!(r.body["state"], "issued");
    assert_eq!(r.body["reboot"], false);
    assert_eq!(t.audit("rescue.create"), 1);
    // only the sealed digest and the lookup key are stored
    let sealed: String = t.one("SELECT token_hash FROM rescue_sessions");
    assert!(sealed.starts_with("sealed:v1:"));
    assert_eq!(
        t.sk.open(&rescue_token_location(&id, AGENT), &sealed).unwrap().as_str(),
        agent_proto::token_digest(&token)
    );
    let lookup: String = t.one("SELECT lookup FROM rescue_sessions");
    assert_eq!(lookup, agent_proto::rescue_lookup(&token));
    // GETs never show the token
    let list = t.get("/api/v1/rescue", &vic).await;
    assert_eq!(list.status, StatusCode::OK);
    assert_eq!(list.body.as_array().unwrap().len(), 1);
    assert!(!list.body.to_string().contains(&token));
    assert_eq!(list.body[0]["agent_name"], "web01");
    assert_eq!(t.get("/api/v1/rescue", &gina).await.body, json!([]), "tenant-scoped");
    assert_eq!(
        t.get(&format!("/api/v1/rescue/{id}"), &gina).await.status,
        StatusCode::NOT_FOUND
    );

    // start before the check-in: refused
    let start = format!("/api/v1/rescue/{id}/start");
    assert_eq!(
        t.post(&start, &alice, json!({"time": 1000})).await.status,
        StatusCode::CONFLICT
    );

    // check-in: validation, unknown token
    let mut bad = checkin_body(&token);
    bad["host"] = json!("bad host!");
    assert_eq!(t.checkin(bad).await.status, StatusCode::BAD_REQUEST);
    let mut bad = checkin_body(&token);
    bad["disks"] = json!([{"path": "/etc/passwd", "size": 1}]);
    assert_eq!(t.checkin(bad).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        t.checkin(checkin_body("WRONGTOKENWRONGTOKENWRONG1")).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(t.audit("rescue.checkin_rejected"), 1);
    let r = t.checkin(checkin_body(&token)).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["session"], id);
    let s = t.get(&format!("/api/v1/rescue/{id}"), &otto).await.body;
    assert_eq!(
        (s["state"].as_str(), s["host"].as_str(), s["port"].as_i64()),
        (Some("waiting"), Some("192.0.2.50"), Some(7444))
    );
    assert_eq!(s["disks"][0]["size"], 21474836480u64);
    assert!(s["job_id"].is_null(), "bare metal: the admin starts");

    // start: snapshot must exist; then a bmr job, session running
    assert_eq!(
        t.post(&start, &alice, json!({"time": 999})).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        t.post(&start, &vic, json!({"time": 1000})).await.status,
        StatusCode::FORBIDDEN
    );
    // Phase 39 S3: a flagged snapshot is refused (no approval route), restorable once cleared
    let flag = |on: bool| {
        let sql = if on {
            "UPDATE snapshots SET anomaly = 'YARA: 1 match', anomaly_cleared_at = NULL WHERE time = 1000"
        } else {
            "UPDATE snapshots SET anomaly_cleared_at = 3000, anomaly_cleared_by = 'sam' WHERE time = 1000"
        };
        t.st.cat.conn().execute_batch(sql).unwrap();
    };
    flag(true);
    let r = t.post(&start, &otto, json!({"time": 1000})).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
    assert!(
        r.body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("flagged as infected"),
        "{:?}",
        r.body
    );
    flag(false);
    let r = t.post(&start, &otto, json!({"time": 1000, "reboot": true})).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let job = r.body["id"].as_i64().unwrap();
    let (kind, params): (String, String) =
        t.st.cat
            .conn()
            .query_row("SELECT kind, params FROM jobs WHERE id = ?1", [job], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
    assert_eq!(kind, "bmr");
    let p: Value = serde_json::from_str(&params).unwrap();
    assert_eq!(p, json!({"session": id, "source_agent": AGENT, "time": 1000}));
    let s = t.get(&format!("/api/v1/rescue/{id}"), &otto).await.body;
    assert_eq!(
        (s["state"].as_str(), s["job_id"].as_i64(), s["reboot"].as_bool()),
        (Some("running"), Some(job), Some(true))
    );
    assert_eq!(t.audit("rescue.start"), 1);
    // running sessions cannot be cancelled, nor checked in again
    assert_eq!(
        t.post(&format!("/api/v1/rescue/{id}/cancel"), &alice, json!({}))
            .await
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(t.checkin(checkin_body(&token)).await.status, StatusCode::NOT_FOUND);

    // a new token cancels the agent's open sessions; cancel; expiry
    let r2 = t.post(&url, &alice, json!({})).await.body;
    let r3 = t.post(&url, &alice, json!({})).await.body;
    let state = |id: &Value| -> String {
        t.st.cat
            .conn()
            .query_row(
                "SELECT state FROM rescue_sessions WHERE id = ?1",
                [id.as_str().unwrap()],
                |r| r.get(0),
            )
            .unwrap()
    };
    assert_eq!(state(&r2["id"]), "cancelled");
    assert_eq!(state(&json!(id)), "running");
    let c = t
        .post(
            &format!("/api/v1/rescue/{}/cancel", r3["id"].as_str().unwrap()),
            &otto,
            json!({}),
        )
        .await;
    assert_eq!(c.status, StatusCode::OK);
    assert_eq!(c.body["state"], "cancelled");
    assert_eq!(c.body["token_valid"], false);
    let r4 = t.post(&url, &alice, json!({})).await.body;
    t.st.cat
        .conn()
        .execute(
            "UPDATE rescue_sessions SET token_expires = 1 WHERE id = ?1",
            [r4["id"].as_str().unwrap()],
        )
        .unwrap();
    assert_eq!(
        t.checkin(checkin_body(r4["token"].as_str().unwrap())).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(state(&r4["id"]), "expired");

    // vault mode refuses recoveries
    catalog::vault::store(
        &t.st.cat.conn(),
        &catalog::vault::Vault {
            enabled: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(t.post(&url, &alice, json!({})).await.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn checkin_rate_limit() {
    let t = T::new();
    for _ in 0..5 {
        assert_eq!(t.checkin(checkin_body("NOPE")).await.status, StatusCode::NOT_FOUND);
    }
    assert_eq!(
        t.checkin(checkin_body("NOPE")).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn p2v_creates_session_and_starts_at_checkin() {
    let t = T::new();
    let (alice, gina) = (t.login("alice").await, t.login("gina").await);
    let url = format!("/api/v1/agents/{AGENT}/p2v");
    let body = json!({"time": 1000, "source_id": 1, "node": "pve1", "storage": "local-lvm",
                      "iso": "local:iso/nexus-rescue-0.2.0.iso"});
    for (k, v) in [
        ("source_id", json!(2)),
        ("source_id", json!(3)),
        ("time", json!(5)),
        ("iso", json!("nexus-rescue.iso")),
        ("node", json!("pve1;rm")),
        ("memory", json!(64)),
        ("appliance_sha256", json!("xyz")),
    ] {
        let mut b = body.clone();
        b[k] = v.clone();
        let r = t.post(&url, &alice, b).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{k}={v}: {:?}", r.body);
    }
    assert_eq!(
        t.post(&format!("/api/v1/agents/{OTHER}/p2v"), &alice, body.clone())
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(t.post(&url, &gina, body.clone()).await.status, StatusCode::NOT_FOUND);
    // Phase 39 S3: a flagged snapshot is refused (no approval route), restorable once cleared
    let flag = |on: bool| {
        let sql = if on {
            "UPDATE snapshots SET anomaly = 'YARA: 1 match', anomaly_cleared_at = NULL WHERE time = 1000"
        } else {
            "UPDATE snapshots SET anomaly_cleared_at = 3000, anomaly_cleared_by = 'sam' WHERE time = 1000"
        };
        t.st.cat.conn().execute_batch(sql).unwrap();
    };
    flag(true);
    assert_eq!(t.post(&url, &alice, body.clone()).await.status, StatusCode::CONFLICT);
    flag(false);
    let r = t.post(&url, &alice, body.clone()).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    assert!(r.body["token"].is_null(), "the P2V token is never shown");
    let id = r.body["id"].as_str().unwrap().to_owned();
    let p2v_job = r.body["p2v_job"].as_i64().unwrap();
    let kind: String = t.one(&format!("SELECT kind FROM jobs WHERE id = {p2v_job}"));
    assert_eq!(kind, "p2v");
    assert_eq!(
        r.body["p2v"]["appliance"], "nexus.test:8443",
        "default: the request's Host"
    );
    assert_eq!(r.body["p2v"]["iso_storage"], "local");
    assert_eq!(r.body["p2v"]["bridge"], "vmbr0");
    assert!(r.body["p2v"]["token"].is_null());
    // the plaintext token is sealed for the scheduler only
    let p2v: String = t.one("SELECT p2v FROM rescue_sessions");
    let p2v: Value = serde_json::from_str(&p2v).unwrap();
    let token =
        t.sk.open(&rescue_p2v_token_location(&id, AGENT), p2v["token"].as_str().unwrap())
            .unwrap()
            .to_string();
    // the VM's check-in starts the recovery unattended
    let c = t.checkin(checkin_body(&token)).await;
    assert_eq!(c.status, StatusCode::OK, "{:?}", c.body);
    let s = t.get(&format!("/api/v1/rescue/{id}"), &alice).await.body;
    assert_eq!(s["state"], "running");
    let job = s["job_id"].as_i64().unwrap();
    let (kind, by): (String, String) =
        t.st.cat
            .conn()
            .query_row("SELECT kind, requested_by FROM jobs WHERE id = ?1", [job], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
    assert_eq!((kind.as_str(), by.as_str()), ("bmr", "rescue"));
    assert_eq!(t.audit("rescue.p2v"), 1);
}
