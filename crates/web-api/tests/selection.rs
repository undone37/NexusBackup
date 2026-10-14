//! Phase 15e/f: group exclude disks / restore mode / parallel guests, policy global
//! file filters, linux and share source filters, agent limits, "renew certificate
//! now" and re-enrollment of an enrolled agent (same id).

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
    cookie: Option<String>,
}

impl T {
    fn new() -> T {
        let dir = tempfile::tempdir().unwrap();
        let cat = Catalog::open(&dir.path().join("catalog.db")).unwrap();
        let downloads = dir.path().join("downloads");
        std::fs::create_dir(&downloads).unwrap();
        // agent tokens are sealed to the scheduler: publish a key
        let secrets_pub = dir.path().join("secrets.pub");
        catalog::secret::SchedulerKey::generate()
            .write_public(&secrets_pub, None)
            .unwrap();
        let st = AppState::with_keys(cat, None, downloads, TotpKey::generate(), Some(secrets_pub));
        let mut secrets = HashMap::new();
        for (n, role, tenant) in [
            ("alice", "admin", None),
            ("sam", "security_officer", None),
            ("otto", "operator", None),
            ("tina", "tenant_user", Some("acme")),
        ] {
            let secret = catalog::auth::new_totp_secret();
            let enc = st.totp.encrypt(n, &secret).unwrap();
            if let Some(t) = tenant {
                st.cat
                    .conn()
                    .execute("INSERT OR IGNORE INTO tenants (name) VALUES (?1)", [t])
                    .unwrap();
            }
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
                r#"INSERT INTO tenants (name) VALUES ('globex');
                   INSERT INTO sources (id, tenant, kind, name, config) VALUES (1, 'acme', 'pve', 'pve-a', '{}'),
                     (2, 'globex', 'pve', 'pve-g', '{}');
                   INSERT INTO policies (id, name, schedule, gfs, offsite) VALUES (1, 'daily', 'daily 22:00', '{"daily":7,"weekly":0,"monthly":0,"yearly":0}', 0);
                   INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES
                     (1, 'acme', 1, 1, 'g1', '[100,101,102]'), (2, 'globex', 2, 1, 'g2', '[200]');"#,
            )
            .unwrap();
        T {
            app: web_api::router(st.clone()),
            st,
            secrets,
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
    async fn put(&self, path: &str, s: &S, body: Value) -> R {
        self.call(Method::PUT, path, Some(s), Some(body)).await
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

    fn exec(&self, sql: &str) {
        self.st.cat.conn().execute_batch(sql).unwrap();
    }

    fn one<V: catalog::rusqlite::types::FromSql>(&self, sql: &str) -> V {
        self.st.cat.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }
}

const AG: &str = "0123456789abcdef";

fn fixture(t: &T) {
    t.exec(&format!(
        "INSERT INTO agents (id, tenant, name, host, port, cert_sha256, enrolled_at) VALUES
           ('{AG}', 'acme', 'web01', '10.0.0.9', 7444, '{fp}', 5);
         INSERT INTO sources (id, tenant, kind, name, config) VALUES
           (3, 'acme', 'linux', 'web01', '{{\"agent_id\":\"{AG}\",\"paths\":[\"/\"]}}');",
        fp = "ab".repeat(32)
    ));
}

#[tokio::test]
async fn group_exclude_disks_parallel_and_quorum() {
    let t = T::new();
    fixture(&t);
    let (alice, sam) = (t.login("alice").await, t.login("sam").await);
    let base = json!({"tenant": "acme", "source_id": 1, "policy_id": 1, "name": "vms", "guests": [100, 101]});
    // defaults
    let r = t.post("/api/v1/groups", &alice, base.clone()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(
        (
            &r.body["exclude_disks"],
            &r.body["exclude_disks_mode"],
            &r.body["parallel_guests"]
        ),
        (&json!({}), &json!("placeholder"), &json!(4)),
        "Phase 32: four guests at once by default"
    );
    let id = r.body["id"].as_i64().unwrap();
    for (k, v) in [
        ("exclude_disks", json!({"*": ["drive-scsi1"]})),
        ("exclude_disks", json!({"abc": ["scsi1"]})),
        ("exclude_disks", json!(["scsi1"])),
        ("exclude_disks_mode", json!("drop")),
        ("parallel_guests", json!(0)),
        ("parallel_guests", json!(9)),
    ] {
        let mut b = base.clone();
        b["name"] = json!("x");
        b[k] = v.clone();
        let r = t.post("/api/v1/groups", &alice, b).await;
        assert!(r.status.is_client_error(), "{k}={v}: {:?}", r.body);
    }
    // exclude disks only for PVE groups
    let r = t
        .post(
            "/api/v1/groups",
            &alice,
            json!({"tenant": "acme", "source_id": 3, "policy_id": 1, "name": "hosts", "guests": [AG],
                   "exclude_disks": {"*": ["scsi1"]}}),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    // parallelism and the restore mode apply directly
    let mut upd = base.clone();
    upd.as_object_mut().unwrap().remove("tenant");
    upd["parallel_guests"] = json!(2);
    upd["exclude_disks_mode"] = json!("omit");
    let r = t.put(&format!("/api/v1/groups/{id}"), &alice, upd.clone()).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        t.one::<i64>(&format!("SELECT parallel_guests FROM groups WHERE id = {id}")),
        2
    );
    // excluding a disk backs up less: approval
    upd["exclude_disks"] = json!({"*": ["scsi1", "scsi1"], "101": ["virtio2"]});
    let r = t.put(&format!("/api/v1/groups/{id}"), &alice, upd.clone()).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    assert_eq!(
        t.one::<String>(&format!("SELECT exclude_disks FROM groups WHERE id = {id}")),
        "{}"
    );
    let q = r.body["quorum_id"].as_i64().unwrap();
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let ex: Value =
        serde_json::from_str(&t.one::<String>(&format!("SELECT exclude_disks FROM groups WHERE id = {id}"))).unwrap();
    assert_eq!(ex, json!({"*": ["scsi1"], "101": ["virtio2"]}));
    assert_eq!(
        t.one::<String>(&format!("SELECT exclude_disks_mode FROM groups WHERE id = {id}")),
        "omit"
    );
    // removing an exclusion applies directly
    upd["exclude_disks"] = json!({"*": ["scsi1"]});
    let r = t.put(&format!("/api/v1/groups/{id}"), &alice, upd).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let r = t.get("/api/v1/groups", &alice).await;
    let g = r.body.as_array().unwrap().iter().find(|g| g["id"] == id).unwrap();
    assert_eq!(g["exclude_disks"], json!({"*": ["scsi1"]}));
}

#[tokio::test]
async fn policy_file_filters_and_source_filters() {
    let t = T::new();
    fixture(&t);
    let (alice, sam) = (t.login("alice").await, t.login("sam").await);
    let base = json!({"name": "files", "schedule": "daily 22:00",
                      "gfs": {"daily": 7, "weekly": 0, "monthly": 0, "yearly": 0}});
    let mut b = base.clone();
    b["file_filters"] = json!({"exclude": ["/var/cache/**"], "exclude_regex": ["("]});
    assert_eq!(
        t.post("/api/v1/policies", &alice, b).await.status,
        StatusCode::BAD_REQUEST
    );
    let mut b = base.clone();
    b["file_filters"] = json!({"exclude": ["/var/cache/**"], "bogus": []});
    assert!(t.post("/api/v1/policies", &alice, b).await.status.is_client_error());
    let mut b = base.clone();
    b["file_filters"] = json!({"exclude": ["/var/cache/**"]});
    let r = t.post("/api/v1/policies", &alice, b.clone()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(
        r.body["file_filters"],
        json!({"exclude": ["/var/cache/**"], "exclude_regex": []})
    );
    let id = r.body["id"].as_i64().unwrap();
    // a new global exclude: approval; removing one: direct
    b["file_filters"]["exclude_regex"] = json!(["~$"]);
    let r = t.put(&format!("/api/v1/policies/{id}"), &alice, b.clone()).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    assert_eq!(
        t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({}))
            .await
            .status,
        StatusCode::OK
    );
    let f: Value =
        serde_json::from_str(&t.one::<String>(&format!("SELECT file_filters FROM policies WHERE id = {id}"))).unwrap();
    assert_eq!(f, json!({"exclude": ["/var/cache/**"], "exclude_regex": ["~$"]}));
    b["file_filters"] = json!({"exclude_regex": ["~$"]});
    assert_eq!(
        t.put(&format!("/api/v1/policies/{id}"), &alice, b).await.status,
        StatusCode::OK
    );

    // linux source: include roots, regexes, nested mounts
    let cfg = json!({"agent_id": AG, "paths": ["/"], "include": ["/home", "/etc"], "exclude_regex": ["\\.bak$"],
                     "cross_mounts": true, "skip_fstypes": ["tmpfs", "fuse.sshfs"]});
    let r = t
        .put("/api/v1/sources/3", &alice, json!({"name": "web01", "config": cfg}))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let stored: Value = serde_json::from_str(&t.one::<String>("SELECT config FROM sources WHERE id = 3")).unwrap();
    assert_eq!(stored["include"], json!(["/home", "/etc"]));
    assert_eq!(stored["cross_mounts"], true);
    for (k, v) in [
        ("include", json!(["home"])),
        ("exclude_regex", json!(["[a-"])),
        ("skip_fstypes", json!(["no spaces"])),
    ] {
        let mut c = cfg.clone();
        c[k] = v.clone();
        let r = t
            .put("/api/v1/sources/3", &alice, json!({"name": "web01", "config": c}))
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{k}={v}: {:?}", r.body);
    }
}

#[tokio::test]
async fn agent_limits_renew_and_reenroll() {
    let t = T::new();
    fixture(&t);
    let (alice, otto) = (t.login("alice").await, t.login("otto").await);
    let r = t.get("/api/v1/agents", &alice).await;
    let a = &r.body[0];
    assert_eq!(
        (&a["limits"], &a["cert_expires"], &a["cert_renewal_pending"]),
        (&json!({}), &Value::Null, &json!(false))
    );
    // limits: admin only, bounded, audited
    let path = format!("/api/v1/agents/{AG}/limits");
    assert_eq!(
        t.put(&path, &otto, json!({"bwlimit": 1 << 20, "nice": 10}))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.put(&path, &alice, json!({"nice": 20})).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        t.put(&path, &alice, json!({"bwlimit": 1000})).await.status,
        StatusCode::BAD_REQUEST
    );
    let r = t.put(&path, &alice, json!({"bwlimit": 1 << 20, "nice": 10})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["limits"], json!({"bwlimit": 1 << 20, "nice": 10}));
    assert_eq!(
        t.one::<i64>("SELECT COUNT(*) FROM audit WHERE action = 'agent.limits'"),
        1
    );
    assert_eq!(
        t.put("/api/v1/agents/ffffffffffffffff/limits", &alice, json!({}))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    // "Renew certificate now": an admin job
    let job = json!({"kind": "agent_renew", "tenant": "acme", "params": {"agent_id": AG}});
    assert_eq!(
        t.post("/api/v1/jobs", &otto, job.clone()).await.status,
        StatusCode::FORBIDDEN
    );
    let r = t.post("/api/v1/jobs", &alice, job).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    assert_eq!(
        t.one::<String>("SELECT kind FROM jobs ORDER BY id DESC LIMIT 1"),
        "agent_renew"
    );
    // re-enrollment of an enrolled agent: a new token for the same id (no delete + create)
    let r = t.post(&format!("/api/v1/agents/{AG}/token"), &alice, json!({})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["id"], AG);
    let d: Value =
        serde_json::from_str(&t.one::<String>("SELECT details FROM audit WHERE action = 'agent.token'")).unwrap();
    assert_eq!(d["reenroll"], true);
    assert_eq!(t.one::<i64>("SELECT COUNT(*) FROM agents"), 1);
    let r = t.post(&format!("/api/v1/agents/{AG}/enroll"), &alice, json!({})).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    assert_eq!(
        t.one::<String>("SELECT json_extract(config, '$.agent_id') FROM sources WHERE id = 3"),
        AG,
        "the source keeps pointing at the agent"
    );
}

/// Phase 24a: endpoint status in the agent list, UI policy (admins), laptop
/// options (tenant writers), session summaries (tenant-scoped, read).
#[tokio::test]
async fn agent_endpoint_policy_laptop_and_sessions() {
    let t = T::new();
    fixture(&t);
    t.exec(&format!(
        "UPDATE agents SET reachable = 1, last_poll = 50, power = '{{\"on_battery\":true,\"battery_percent\":40}}' WHERE id = '{AG}';
         INSERT INTO tenants (name) VALUES ('other');
         INSERT INTO agents (id, tenant, name, host, port) VALUES ('fedcba9876543210', 'other', 'x', 'h', 7444);
         INSERT INTO agent_sessions (agent_id, job_id, tenant, summary, created) VALUES
           ('{AG}', 4, 'acme', '{{\"job\":4,\"result\":\"Success\",\"log_tail\":[\"a\"]}}', 9),
           ('{AG}', 5, 'acme', '{{\"job\":5,\"result\":\"Failed\",\"log_tail\":[\"b\"]}}', 10);"
    ));
    let (alice, otto, tina) = (t.login("alice").await, t.login("otto").await, t.login("tina").await);
    let r = t.get("/api/v1/agents", &tina).await;
    assert_eq!(r.body.as_array().unwrap().len(), 1, "tenant-scoped");
    let a = &r.body[0];
    assert_eq!(
        (&a["reachable"], &a["power"]["battery_percent"]),
        (&json!(true), &json!(40))
    );
    assert_eq!(
        (&a["ui_policy"], &a["ui_policy_version"], &a["laptop"]),
        (&json!({}), &json!(0), &json!({}))
    );

    // UI policy: admins only, validated, versioned, audited
    let path = format!("/api/v1/agents/{AG}/ui-policy");
    let pol = json!({"accent": "#0a7f5a", "header": "ACME IT", "hide_backup_now": true, "hide_tray": false});
    for who in [&otto, &tina] {
        assert_eq!(t.put(&path, who, pol.clone()).await.status, StatusCode::FORBIDDEN);
    }
    for bad in [
        json!({"accent": "red"}),
        json!({"header": "x".repeat(65)}),
        json!({"other": 1}),
    ] {
        let st = t.put(&path, &alice, bad.clone()).await.status;
        assert!(
            st == StatusCode::BAD_REQUEST || st == StatusCode::UNPROCESSABLE_ENTITY,
            "{bad}: {st}"
        );
    }
    let r = t.put(&path, &alice, pol.clone()).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!((&r.body["ui_policy"], &r.body["ui_policy_version"]), (&pol, &json!(1)));
    let r = t.put(&path, &alice, json!({})).await;
    assert_eq!(r.body["ui_policy_version"], 2);
    assert_eq!(
        t.one::<i64>("SELECT COUNT(*) FROM audit WHERE action = 'agent.ui_policy'"),
        2
    );
    assert_eq!(
        t.put("/api/v1/agents/ffffffffffffffff/ui-policy", &alice, json!({}))
            .await
            .status,
        StatusCode::NOT_FOUND
    );

    // laptop options: tenant writers (not operators), bounded
    let path = format!("/api/v1/agents/{AG}/laptop");
    let lap = json!({"min_battery": 20, "skip_metered": true, "run_missed": true, "retry_hours": 12});
    assert_eq!(t.put(&path, &otto, lap.clone()).await.status, StatusCode::FORBIDDEN);
    assert_eq!(
        t.put(&path, &alice, json!({"min_battery": 101})).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        t.put(&path, &alice, json!({"retry_hours": 400})).await.status,
        StatusCode::BAD_REQUEST
    );
    let r = t.put(&path, &alice, lap.clone()).await;
    assert_eq!((r.status, &r.body["laptop"]), (StatusCode::OK, &lap));
    assert_eq!(
        t.one::<i64>("SELECT COUNT(*) FROM audit WHERE action = 'agent.laptop'"),
        1
    );

    // sessions: newest first, no log lines; other tenants' agents are invisible
    let r = t.get(&format!("/api/v1/agents/{AG}/sessions"), &tina).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body[0]["job"], 5);
    assert!(r.body[0].get("log_tail").is_none());
    assert_eq!(r.body[1]["delivered"], Value::Null);
    assert_eq!(
        t.get("/api/v1/agents/fedcba9876543210/sessions", &tina).await.status,
        StatusCode::NOT_FOUND
    );
}
