//! Phase 28 (Commvault Tier 1): threat scan and file hash options, IOC hash lists
//! and hunts, tenant lockdown, new-device sign-in notice.

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
    ids: HashMap<String, i64>,
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
        let st = AppState::with_keys(cat, None, downloads, TotpKey::generate(), None);
        st.cat
            .conn()
            .execute_batch(
                r#"INSERT INTO tenants (name) VALUES ('acme'), ('globex');
                   INSERT INTO sources (id, tenant, kind, name, config) VALUES (1, 'acme', 'pve', 'pve-a', '{}'),
                     (2, 'globex', 'pve', 'pve-g', '{}');
                   INSERT INTO policies (id, name, schedule, gfs, offsite) VALUES
                     (1, 'daily', 'daily 22:00', '{"daily":7,"weekly":0,"monthly":0,"yearly":0}', 0);
                   INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES
                     (1, 'acme', 1, 1, 'a1', '[100]'), (2, 'acme', 1, 1, 'a2', '[101]'), (3, 'globex', 2, 1, 'g1', '[200]');
                   INSERT INTO snapshots (tenant, source, time, size, local, offsite) VALUES
                     ('acme', 'vm-100', 1000, 5, 1, 0), ('acme', 'vm-100', 2000, 5, 1, 0),
                     ('acme', 'vm-101', 1500, 5, 1, 0), ('globex', 'vm-200', 1500, 5, 1, 0);"#,
            )
            .unwrap();
        let mut t = T {
            app: web_api::router(st.clone()),
            st,
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
            let secret = catalog::auth::new_totp_secret();
            let enc = t.st.totp.encrypt(n, &secret).unwrap();
            let c = t.st.cat.conn();
            c.execute(
                "INSERT INTO users (name, password_hash, totp_secret, role, tenant, created) VALUES (?1,?2,?3,?4,?5,0)",
                params![n, pw_hash(), enc, role, tenant],
            )
            .unwrap();
            t.ids.insert(n.into(), c.last_insert_rowid());
            t.secrets.insert(n.into(), secret);
        }
        t
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

    fn reauth(&self, name: &str, extra: Value) -> Value {
        let mut v = json!({"current_password": PW, "current_totp": self.code(name)});
        v.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        v
    }

    fn exec(&self, sql: &str) {
        self.st.cat.conn().execute_batch(sql).unwrap();
    }

    fn one<V: catalog::rusqlite::types::FromSql>(&self, sql: &str) -> V {
        self.st.cat.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }
}

impl T {
    async fn login_ua(&self, name: &str, ua: &str) -> S {
        let body = json!({"name": name, "password": PW, "totp": self.code(name)});
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::USER_AGENT, ua)
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
    async fn delete(&self, path: &str, s: &S) -> R {
        self.call(Method::DELETE, path, Some(s), None).await
    }
    fn add_tenant_admin(&mut self) {
        let secret = catalog::auth::new_totp_secret();
        let enc = self.st.totp.encrypt("dana", &secret).unwrap();
        let c = self.st.cat.conn();
        c.execute(
            "INSERT INTO users (name, password_hash, totp_secret, role, tenant, created) VALUES ('dana',?1,?2,'tenant_admin','acme',0)",
            params![pw_hash(), enc],
        )
        .unwrap();
        self.ids.insert("dana".into(), c.last_insert_rowid());
        self.secrets.insert("dana".into(), secret);
    }
}

fn sha(d: &str) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(d.as_bytes()))
}

/// Scan schedule and file hashes per group: who may set them, validation, the
/// group list and the snapshots' scan state.
#[tokio::test]
async fn threat_scan_and_file_hash_options() {
    let mut t = T::new();
    t.add_tenant_admin();
    let (alice, sam, otto, tina, dana) = (
        t.login("alice").await,
        t.login("sam").await,
        t.login("otto").await,
        t.login("tina").await,
        t.login("dana").await,
    );
    let body = json!({"schedule": "daily 02:00", "budget_min": 60});
    for s in [&otto, &tina] {
        assert_eq!(
            t.put("/api/v1/groups/1/threat-scan", s, body.clone()).await.status,
            StatusCode::FORBIDDEN
        );
    }
    let r = t.put("/api/v1/groups/3/threat-scan", &dana, body.clone()).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "another tenant's group");
    for bad in [
        json!({"schedule": "sometimes"}),
        json!({"schedule": "daily 02:00", "budget_min": 0}),
    ] {
        assert_eq!(
            t.put("/api/v1/groups/1/threat-scan", &alice, bad).await.status,
            StatusCode::BAD_REQUEST
        );
    }
    let r = t.put("/api/v1/groups/1/threat-scan", &dana, body.clone()).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["rules"], false, "the UI warns: no YARA rules yet");
    let r = t
        .put(
            "/api/v1/groups/2/threat-scan",
            &sam,
            json!({"schedule": "Mon,Thu 03:00"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        t.put("/api/v1/groups/1/file-hashes", &sam, json!({"enabled": true}))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let r = t
        .put("/api/v1/groups/1/file-hashes", &alice, json!({"enabled": true}))
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let g = t.get("/api/v1/groups", &otto).await.body;
    let g1 = g.as_array().unwrap().iter().find(|g| g["id"] == 1).unwrap();
    assert_eq!(
        (
            g1["scan_schedule"].clone(),
            g1["scan_budget_min"].clone(),
            g1["file_hashes"].clone()
        ),
        (json!("daily 02:00"), json!(60), json!(true))
    );
    let g3 = g.as_array().unwrap().iter().find(|g| g["id"] == 3).unwrap();
    assert_eq!(
        (g3["scan_schedule"].clone(), g3["file_hashes"].clone()),
        (Value::Null, json!(false))
    );
    // off again
    let r = t
        .put("/api/v1/groups/1/threat-scan", &alice, json!({"schedule": null}))
        .await;
    assert_eq!(r.body["scan_schedule"], Value::Null);
    assert_eq!(
        t.one::<i64>("SELECT COUNT(*) FROM audit WHERE action IN ('group.threat_scan','group.file_hashes')"),
        4
    );
    // scan state per snapshot
    t.exec("UPDATE snapshots SET scan_state = 'clean' WHERE source = 'vm-100' AND time = 1000");
    let snaps = t.get("/api/v1/snapshots?tenant=acme&source=vm-100", &tina).await.body;
    let states: Vec<Value> = snaps
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["scan_state"].clone())
        .collect();
    assert_eq!(states, vec![Value::Null, json!("clean")]);
}

/// IOC lists (admins and security officers), hunts (admins, operators, officers,
/// tenant admins for their tenant), validation.
#[tokio::test]
async fn hash_lists_and_hunts() {
    let mut t = T::new();
    t.add_tenant_admin();
    let (alice, sam, otto, tina, dana) = (
        t.login("alice").await,
        t.login("sam").await,
        t.login("otto").await,
        t.login("tina").await,
        t.login("dana").await,
    );
    let hunt = json!({"tenant": "acme"});
    assert_eq!(
        t.post("/api/v1/hunts", &otto, hunt.clone()).await.status,
        StatusCode::CONFLICT,
        "no lists yet"
    );
    let text = format!(
        "sha256,name\n{},evil.exe\n{}\nmd5,{}\n",
        sha("evil"),
        sha("worse"),
        "ab".repeat(16)
    );
    for s in [&otto, &dana, &tina] {
        assert_eq!(
            t.put("/api/v1/hash-lists/feed", s, json!({"text": text})).await.status,
            StatusCode::FORBIDDEN
        );
    }
    let r = t.put("/api/v1/hash-lists/feed", &sam, json!({"text": text})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        (r.body["count"].clone(), r.body["skipped"].clone()),
        (json!(2), json!(1))
    );
    assert_eq!(
        t.put("/api/v1/hash-lists/empty", &sam, json!({"text": "md5 only\n"}))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        t.put("/api/v1/hash-lists/..x", &sam, json!({"text": text}))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    let stored: String = t.one("SELECT hashes FROM hash_lists WHERE name = 'feed'");
    let mut want = [sha("evil"), sha("worse")];
    want.sort();
    assert_eq!(stored, want.join("\n") + "\n");
    let l = t.get("/api/v1/hash-lists", &alice).await.body;
    assert_eq!((l[0]["name"].clone(), l[0]["count"].clone()), (json!("feed"), json!(2)));
    assert_eq!(t.get("/api/v1/hash-lists", &otto).await.status, StatusCode::FORBIDDEN);
    // hunts
    assert_eq!(
        t.post("/api/v1/hunts", &tina, hunt.clone()).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.post("/api/v1/hunts", &dana, json!({"tenant": "globex"})).await.status,
        StatusCode::FORBIDDEN
    );
    for bad in [
        json!({"tenant": "acme", "lists": ["nope"]}),
        json!({"tenant": "acme", "lists": []}),
        json!({"tenant": "acme", "from": 5, "to": 1}),
        json!({"tenant": "acme", "source": "../x"}),
        json!({"tenant": "nobody"}),
    ] {
        assert_eq!(
            t.post("/api/v1/hunts", &otto, bad.clone()).await.status,
            StatusCode::BAD_REQUEST,
            "{bad}"
        );
    }
    for s in [&otto, &dana, &sam] {
        let r = t
            .post(
                "/api/v1/hunts",
                s,
                json!({"tenant": "acme", "lists": ["feed"], "source": "vm-100", "from": 1}),
            )
            .await;
        assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    }
    let p: String = t.one("SELECT params FROM jobs WHERE kind = 'hash_hunt' ORDER BY id LIMIT 1");
    assert_eq!(
        serde_json::from_str::<Value>(&p).unwrap(),
        json!({"lists": ["feed"], "source": "vm-100", "from": 1})
    );
    assert_eq!(
        t.one::<i64>("SELECT COUNT(*) FROM audit WHERE action = 'hash_hunt.request'"),
        3
    );
    // tenant users see the results of their tenant's hunts through the jobs list
    let jobs = t.get("/api/v1/jobs?kind=hash_hunt", &tina).await.body;
    assert_eq!(jobs.as_array().unwrap().len(), 3);
    assert_eq!(
        t.delete("/api/v1/hash-lists/feed", &otto).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.delete("/api/v1/hash-lists/feed", &alice).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        t.delete("/api/v1/hash-lists/feed", &alice).await.status,
        StatusCode::NOT_FOUND
    );
}

/// Lockdown of one tenant: holds, pauses, its accounts out, changes refused;
/// the other tenant goes on; lifting needs a second person.
#[tokio::test]
async fn tenant_lockdown_and_lift() {
    let mut t = T::new();
    t.add_tenant_admin();
    let (alice, sam, otto, tina) = (
        t.login("alice").await,
        t.login("sam").await,
        t.login("otto").await,
        t.login("tina").await,
    );
    let dana = t.login("dana").await;
    t.exec(&format!(
        "INSERT INTO api_tokens (user_id, name, prefix, hash, scope, expires, created)
         VALUES ({}, 'ci', 'abcd1234', 'x', 'read', {}, 1), ({}, 'ops', 'efgh5678', 'y', 'read', {}, 1)",
        t.ids["dana"],
        catalog::now() + 3600,
        t.ids["otto"],
        catalog::now() + 3600
    ));
    let body = json!({"reason": "acme fileserver encrypted"});
    for s in [&otto, &tina, &dana] {
        assert_eq!(
            t.post("/api/v1/tenants/acme/lockdown", s, t.reauth("otto", body.clone()))
                .await
                .status,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        t.post("/api/v1/tenants/acme/lockdown", &sam, body.clone()).await.status,
        StatusCode::BAD_REQUEST,
        "re-authentication"
    );
    assert_eq!(
        t.post("/api/v1/tenants/nobody/lockdown", &sam, t.reauth("sam", body.clone()))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    let r = t
        .post("/api/v1/tenants/acme/lockdown", &sam, t.reauth("sam", body.clone()))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["held"], json!(["vm-100/1000", "vm-100/2000", "vm-101/1500"]));
    assert_eq!(
        r.body["paused"],
        json!([{"id": 1, "prev": null}, {"id": 2, "prev": null}])
    );
    assert_eq!(
        (r.body["sessions_ended"].clone(), r.body["tokens_revoked"].clone()),
        (json!(2), json!(1))
    );
    assert_eq!(t.one::<i64>("SELECT COUNT(*) FROM api_tokens"), 1, "otto's token stays");
    assert_eq!(
        t.one::<Option<i64>>("SELECT paused_until FROM groups WHERE id = 3"),
        None
    );
    for s in [&tina, &dana] {
        assert_eq!(t.get("/api/v1/auth/me", s).await.status, StatusCode::UNAUTHORIZED);
    }
    for s in [&alice, &otto] {
        assert_eq!(
            t.get("/api/v1/auth/me", s).await.status,
            StatusCode::OK,
            "appliance accounts stay"
        );
    }
    // the tenant's accounts cannot sign in
    let body_login = json!({"name": "tina", "password": PW, "totp": t.code("tina")});
    let r = t.call(Method::POST, "/api/v1/auth/login", None, Some(body_login)).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        t.one::<String>("SELECT severity || ' ' || kind || ' ' || tenant FROM alerts WHERE resolved_at IS NULL"),
        "critical tenant_lockdown acme"
    );
    assert_eq!(
        t.post("/api/v1/tenants/acme/lockdown", &alice, t.reauth("alice", body.clone()))
            .await
            .status,
        StatusCode::CONFLICT
    );
    // refused for acme
    let refused = [
        (
            Method::POST,
            "/api/v1/jobs",
            Some(json!({"kind": "backup", "tenant": "acme", "params": {"group_id": 1}})),
        ),
        (Method::DELETE, "/api/v1/snapshots/acme/vm-100/1000", None),
        (Method::POST, "/api/v1/groups/1/resume", Some(json!({}))),
        (Method::DELETE, "/api/v1/groups/1", None),
        (Method::DELETE, "/api/v1/sources/1", None),
        (
            Method::PUT,
            "/api/v1/groups/1/file-hashes",
            Some(json!({"enabled": true})),
        ),
        (Method::DELETE, "/api/v1/tenants/acme", None),
    ];
    for (m, path, b) in refused {
        let r = t.call(m.clone(), path, Some(&alice), b).await;
        assert_eq!(r.status, StatusCode::CONFLICT, "{m} {path}: {:?}", r.body);
        assert!(
            r.body["error"].as_str().unwrap_or_default().contains("locked down"),
            "{:?}",
            r.body
        );
    }
    // globex runs on
    let r = t
        .post(
            "/api/v1/jobs",
            &otto,
            json!({"kind": "backup", "tenant": "globex", "params": {"group_id": 3}}),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let l = t.get("/api/v1/lockdowns", &otto).await.body;
    assert_eq!(
        (l[0]["tenant"].clone(), l[0]["by"].clone()),
        (json!("acme"), json!("sam"))
    );
    assert_eq!(t.get("/api/v1/tenants/acme/lockdown", &otto).await.body["active"], true);

    // lift: approval by another person even with approvals disabled
    t.exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('approvals_enabled', 'false')");
    assert_eq!(
        t.post("/api/v1/tenants/acme/lockdown/lift", &otto, json!({}))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let r = t.post("/api/v1/tenants/acme/lockdown/lift", &sam, json!({})).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    assert_eq!(
        t.post("/api/v1/tenants/acme/lockdown/lift", &alice, json!({}))
            .await
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        t.get("/api/v1/lockdowns", &alice).await.body[0]["lift_quorum"],
        json!(q)
    );
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "not by the requester");
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &alice, json!({})).await;
    assert_eq!(r.body["state"], "executed", "{:?}", r.body);
    let v = t.get("/api/v1/tenants/acme/lockdown", &alice).await.body;
    assert_eq!(
        (v["active"].clone(), v["approved_by"].clone(), v["resumed"].clone()),
        (json!(false), json!("alice"), json!(2))
    );
    assert_eq!(t.one::<i64>("SELECT COUNT(*) FROM groups WHERE paused_until = -1"), 0);
    assert_eq!(t.one::<i64>("SELECT COUNT(*) FROM alerts WHERE resolved_at IS NULL"), 0);
    assert_eq!(
        t.one::<i64>("SELECT COUNT(*) FROM legal_holds WHERE state = 'active'"),
        3,
        "holds stay"
    );
    t.login("tina").await;
    assert_eq!(t.get("/api/v1/lockdowns", &alice).await.body, json!([]));
    assert_eq!(
        t.one::<i64>("SELECT COUNT(*) FROM audit WHERE action = 'tenant.lockdown'"),
        1
    );
}

const FIREFOX: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0";
const EDGE: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36 Edg/141.0";

/// The first sign-in sets the baseline; a new browser family raises
/// `login_new_device` once (warning for admins, info otherwise); devices can be
/// listed and forgotten; the account's own mail address.
#[tokio::test]
async fn new_device_sign_in_notice() {
    let t = T::new();
    let alice = t.login_ua("alice", FIREFOX).await;
    assert_eq!(t.one::<i64>("SELECT COUNT(*) FROM alerts"), 0, "baseline");
    t.login_ua("alice", FIREFOX).await;
    assert_eq!(t.one::<i64>("SELECT COUNT(*) FROM alerts"), 0, "known device");
    t.login_ua("alice", EDGE).await;
    let (sev, key, msg): (String, String, String) =
        t.st.cat
            .conn()
            .query_row(
                "SELECT severity, key, message FROM alerts WHERE kind = 'login_new_device'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
    assert_eq!(sev, "warning");
    assert!(
        key.starts_with(&format!("login_new_device:{}:", t.ids["alice"])),
        "{key}"
    );
    assert!(msg.contains("Edge on Windows from unknown"), "{msg}");
    assert_eq!(
        t.one::<i64>("SELECT COUNT(*) FROM forward_events WHERE payload LIKE '%login_new_device%'"),
        1,
        "forwarded to SIEM sinks"
    );
    t.login_ua("alice", EDGE).await;
    assert_eq!(t.one::<i64>("SELECT COUNT(*) FROM alerts"), 1);
    t.login_ua("tina", FIREFOX).await;
    let tina = t.login_ua("tina", EDGE).await;
    assert_eq!(
        t.one::<String>("SELECT severity || ' ' || tenant FROM alerts WHERE key LIKE 'login_new_device:%' AND id = 2"),
        "info acme"
    );
    // devices of the caller only
    let d = t.get("/api/v1/auth/devices", &alice).await.body;
    let fams: Vec<&str> = d["devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["family"].as_str().unwrap())
        .collect();
    assert_eq!(fams.len(), 2);
    assert!(fams.contains(&"Firefox on Linux") && fams.contains(&"Edge on Windows"));
    let fp = d["devices"][0]["fingerprint"].as_str().unwrap().to_owned();
    assert_eq!(
        t.delete("/api/v1/auth/devices/0123456789abcdef", &alice).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        t.delete(&format!("/api/v1/auth/devices/{fp}"), &alice).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        t.get("/api/v1/auth/devices", &alice).await.body["devices"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // own mail address
    assert_eq!(
        t.put("/api/v1/auth/email", &tina, json!({"email": "not an address"}))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    let r = t
        .put("/api/v1/auth/email", &tina, json!({"email": "tina@example.com"}))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        t.get("/api/v1/auth/devices", &tina).await.body["email"],
        "tina@example.com"
    );
    t.put("/api/v1/auth/email", &tina, json!({"email": null})).await;
    assert_eq!(
        t.one::<Option<String>>("SELECT email FROM users WHERE name = 'tina'"),
        None
    );
}
