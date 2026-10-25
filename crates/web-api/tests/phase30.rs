//! Phase 30 (NetBackup Tier 2): per-source anomaly sensitivity and the trend
//! fields, just-in-time role elevation, instant rollback requests, offsite
//! targets.

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
    /// the scheduler's key (opens what the web-api sealed)
    sk: catalog::secret::SchedulerKey,
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
        let sk = catalog::secret::SchedulerKey::generate();
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
                     (1, 'acme', 1, 1, 'a1', '[100]'), (2, 'acme', 1, 1, 'a2', '[101]'), (3, 'globex', 2, 1, 'g1', '[200]');
                   INSERT INTO snapshots (tenant, source, time, size, local, offsite) VALUES
                     ('acme', 'vm-100', 1000, 5, 1, 0), ('acme', 'vm-100', 2000, 5, 1, 0),
                     ('acme', 'vm-101', 1500, 5, 1, 0), ('globex', 'vm-200', 1500, 5, 1, 0);"#,
            )
            .unwrap();
        let mut t = T {
            sk,
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

/// Per-source sensitivity: raising applies at once, lowering is an approval
/// (`anomaly.sensitivity`); the trends carry duration, bytes read and the level.
#[tokio::test]
async fn anomaly_sensitivity_and_trends() {
    let mut t = T::new();
    t.add_tenant_admin();
    let (alice, sam, otto, tina, dana) = (
        t.login("alice").await,
        t.login("sam").await,
        t.login("otto").await,
        t.login("tina").await,
        t.login("dana").await,
    );
    t.exec(
        "INSERT INTO backup_stats (tenant, source, time, read, logical, new_chunks, new_plain, new_stored, secs) VALUES
           ('acme', 'vm-100', 1000, 50, 500, 1, 10, 5, 120), ('acme', 'vm-100', 2000, 60, 500, 1, 12, 6, NULL);",
    );
    let r = t.get("/api/v1/stats/trends", &alice).await;
    assert_eq!(r.status, StatusCode::OK);
    let tr = &r.body[0];
    assert_eq!(
        (tr["source"].clone(), tr["sensitivity"].clone()),
        (json!("vm-100"), json!("medium"))
    );
    assert_eq!(
        (
            tr["runs"][0]["secs"].clone(),
            tr["runs"][0]["read"].clone(),
            tr["runs"][1]["secs"].clone()
        ),
        (json!(120), json!(50), Value::Null)
    );
    let set = |level: &str| json!({"tenant": "acme", "source": "vm-100", "level": level});
    // raising: at once, by admins, security officers and tenant admins of the tenant
    let r = t.put("/api/v1/stats/sensitivity", &sam, set("high")).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["old"], "medium");
    assert_eq!(
        t.one::<String>("SELECT level FROM anomaly_sensitivity WHERE source = 'vm-100'"),
        "high"
    );
    for s in [&otto, &tina] {
        assert_eq!(
            t.put("/api/v1/stats/sensitivity", s, set("high")).await.status,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        t.put(
            "/api/v1/stats/sensitivity",
            &dana,
            json!({"tenant": "globex", "source": "vm-200", "level": "high"})
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.put("/api/v1/stats/sensitivity", &alice, set("max")).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        t.put(
            "/api/v1/stats/sensitivity",
            &alice,
            json!({"tenant": "nope", "source": "vm-100", "level": "high"})
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    // lowering: an approval by a second person
    let r = t.put("/api/v1/stats/sensitivity", &dana, set("low")).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    assert_eq!(
        t.one::<String>("SELECT level FROM anomaly_sensitivity WHERE source = 'vm-100'"),
        "high",
        "unchanged until approved"
    );
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["state"], "executed");
    assert_eq!(
        t.one::<String>("SELECT level FROM anomaly_sensitivity WHERE source = 'vm-100'"),
        "low"
    );
    // back to medium is raising: no row (the default)
    let r = t.put("/api/v1/stats/sensitivity", &alice, set("medium")).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(t.one::<i64>("SELECT COUNT(*) FROM anomaly_sensitivity"), 0);
    // a request made against an older level is refused when approved
    let r = t.put("/api/v1/stats/sensitivity", &alice, set("low")).await;
    let q = r.body["quorum_id"].as_i64().unwrap();
    t.put("/api/v1/stats/sensitivity", &alice, set("high")).await;
    assert_eq!(
        t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({}))
            .await
            .status,
        StatusCode::CONFLICT
    );
    // with approvals off a lowering executes directly (audited as such)
    t.exec("UPDATE settings SET value = 'false' WHERE key = 'approvals_enabled'");
    let r = t.put("/api/v1/stats/sensitivity", &alice, set("low")).await;
    assert_eq!((r.status, r.body["executed"].clone()), (StatusCode::OK, json!(true)));
    assert_eq!(
        t.one::<i64>(
            "SELECT COUNT(*) FROM audit WHERE action = 'anomaly.sensitivity' AND details LIKE '%\"approvals\":\"disabled\"%'"
        ),
        1
    );
}

/// Just-in-time elevation: eligibility is a gated grant; the session acts in
/// the eligible role after re-authentication until it ends, expires or the
/// person signs out; with the setting it is an approval; info alert per
/// elevation; tenant users and wrong credentials are refused.
#[tokio::test]
async fn role_elevation() {
    let t = T::new();
    let (alice, sam, tina) = (t.login("alice").await, t.login("sam").await, t.login("tina").await);
    let otto_id = t.ids["otto"];
    // a tenant user can never be eligible; an eligible role is admin or security_officer
    let r = t
        .put(
            &format!("/api/v1/users/{}", t.ids["tina"]),
            &alice,
            json!({"eligible_role": "admin"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    let r = t
        .put(
            &format!("/api/v1/users/{otto_id}"),
            &alice,
            json!({"eligible_role": "operator"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // granting eligibility is a privilege grant: approval
    let r = t
        .put(
            &format!("/api/v1/users/{otto_id}"),
            &alice,
            json!({"eligible_role": "admin"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        t.one::<String>(&format!("SELECT eligible_role FROM users WHERE id = {otto_id}")),
        "admin"
    );
    let otto = t.login("otto").await;
    let me = t.get("/api/v1/auth/me", &otto).await.body;
    assert_eq!(
        (me["user"]["eligible_role"].clone(), me["elevation"].clone()),
        (json!("admin"), Value::Null)
    );
    assert_eq!(
        t.get("/api/v1/settings/anomaly", &otto).await.status,
        StatusCode::FORBIDDEN
    );

    // refused: not eligible for that role, out-of-range time, no reason, wrong password
    let ask = |role: &str, minutes: i64| json!({"role": role, "minutes": minutes, "reason": "patch window"});
    let r = t
        .post(
            "/api/v1/auth/elevate",
            &otto,
            t.reauth("otto", ask("security_officer", 30)),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = t
        .post("/api/v1/auth/elevate", &otto, t.reauth("otto", ask("admin", 5)))
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = t
        .post(
            "/api/v1/auth/elevate",
            &otto,
            t.reauth("otto", json!({"role": "admin", "minutes": 30, "reason": " "})),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let mut bad = t.reauth("otto", ask("admin", 30));
    bad["current_password"] = json!("wrong");
    assert_eq!(
        t.post("/api/v1/auth/elevate", &otto, bad).await.status,
        StatusCode::FORBIDDEN
    );
    let r = t
        .post("/api/v1/auth/elevate", &tina, t.reauth("tina", ask("admin", 30)))
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    // elevated for 30 minutes
    let r = t
        .post("/api/v1/auth/elevate", &otto, t.reauth("otto", ask("admin", 30)))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let until = r.body["elevated"]["until"].as_i64().unwrap();
    assert!(until >= catalog::now() + 29 * 60);
    let me = t.get("/api/v1/auth/me", &otto).await.body;
    assert_eq!(me["user"]["role"], "admin");
    assert_eq!(
        (
            me["elevation"]["role"].clone(),
            me["elevation"]["standing_role"].clone()
        ),
        (json!("admin"), json!("operator"))
    );
    assert_eq!(t.get("/api/v1/settings/anomaly", &otto).await.status, StatusCode::OK);
    assert_eq!(
        t.one::<String>("SELECT severity FROM alerts WHERE kind = 'role_elevation' AND resolved_at IS NULL"),
        "info"
    );
    assert_eq!(
        t.one::<i64>("SELECT COUNT(*) FROM audit WHERE action = 'role.elevate'"),
        1
    );
    let users = t.get("/api/v1/users", &alice).await.body;
    let row = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["name"] == "otto")
        .unwrap()
        .clone();
    assert_eq!(
        (row["role"].clone(), row["elevated_until"].clone()),
        (json!("operator"), json!(until))
    );
    // once at a time
    let r = t
        .post("/api/v1/auth/elevate", &otto, t.reauth("otto", ask("admin", 30)))
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    // back to the standing role
    let r = t.post("/api/v1/auth/elevate/end", &otto, json!({})).await;
    assert_eq!((r.status, r.body["role"].clone()), (StatusCode::OK, json!("operator")));
    assert_eq!(
        t.get("/api/v1/settings/anomaly", &otto).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.one::<i64>("SELECT COUNT(*) FROM alerts WHERE kind = 'role_elevation' AND resolved_at IS NULL"),
        0
    );
    assert_eq!(
        t.post("/api/v1/auth/elevate/end", &otto, json!({})).await.status,
        StatusCode::CONFLICT
    );

    // expiry: noticed by the next request
    let r = t
        .post("/api/v1/auth/elevate", &otto, t.reauth("otto", ask("admin", 15)))
        .await;
    assert_eq!(r.status, StatusCode::OK);
    t.exec("UPDATE sessions SET elevated_until = 1 WHERE elevated_role IS NOT NULL");
    let me = t.get("/api/v1/auth/me", &otto).await.body;
    assert_eq!(
        (me["user"]["role"].clone(), me["elevation"].clone()),
        (json!("operator"), Value::Null)
    );
    assert_eq!(
        t.one::<i64>("SELECT COUNT(*) FROM audit WHERE action = 'role.elevate_end' AND details LIKE '%expired%'"),
        1
    );

    // with the approval setting: a request, applied to the requesting session when approved
    let r = t
        .put("/api/v1/settings/elevation", &alice, json!({"approval": true}))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let r = t
        .post("/api/v1/auth/elevate", &otto, t.reauth("otto", ask("admin", 60)))
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    assert_eq!(t.get("/api/v1/auth/me", &otto).await.body["user"]["role"], "operator");
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(
        (r.status, r.body["state"].clone()),
        (StatusCode::OK, json!("executed")),
        "{:?}",
        r.body
    );
    assert_eq!(t.get("/api/v1/auth/me", &otto).await.body["user"]["role"], "admin");
    // signing out ends it (and resolves the alert)
    t.post("/api/v1/auth/logout", &otto, json!({})).await;
    assert_eq!(
        t.one::<i64>("SELECT COUNT(*) FROM alerts WHERE kind = 'role_elevation' AND resolved_at IS NULL"),
        0
    );
    // switching the approval off again is a weakening: approval
    let r = t
        .put("/api/v1/settings/elevation", &alice, json!({"approval": false}))
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let sec = t.get("/api/v1/settings/security", &alice).await.body;
    assert_eq!(sec["elevation"]["settings"]["approval"], true);
    assert!(sec["elevation"]["pending"].is_i64());
    // removing the eligible role applies at once and ends the sessions
    let otto = t.login("otto").await;
    let r = t
        .put(
            &format!("/api/v1/users/{otto_id}"),
            &alice,
            json!({"eligible_role": null}),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(t.get("/api/v1/auth/me", &otto).await.status, StatusCode::UNAUTHORIZED);
}

/// Instant rollback: an option of "replace original" for VM restores, so the
/// approval `restore.replace` carries it; refused without replace and for containers.
#[tokio::test]
async fn rollback_is_a_replace_option() {
    let t = T::new();
    let alice = t.login("alice").await;
    t.exec(
        "INSERT INTO snapshots (tenant, source, time, size, local, offsite) VALUES ('acme', 'ct-120', 1000, 5, 1, 0);",
    );
    let job = |source: &str, extra: Value| {
        let mut p = json!({"source": source, "time": 1000, "node": "pve1", "target": 900, "storage": "local-lvm"});
        p.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        let kind = if source.starts_with("ct-") {
            "restore_ct"
        } else {
            "restore"
        };
        json!({"kind": kind, "tenant": "acme", "params": p})
    };
    let r = t
        .post(
            "/api/v1/jobs",
            &alice,
            job("vm-100", json!({"replace": true, "rollback": true})),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    let (action, params): (String, String) =
        t.st.cat
            .conn()
            .query_row("SELECT action, params FROM quorum WHERE id = ?1", [q], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
    let params: Value = serde_json::from_str(&params).unwrap();
    assert_eq!(action, "restore.replace");
    assert_eq!(params["params"]["rollback"], true);
    // #55: containers too
    let r = t
        .post(
            "/api/v1/jobs",
            &alice,
            job("ct-120", json!({"replace": true, "rollback": true})),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    for bad in [
        job("vm-100", json!({"rollback": true})),
        job("ct-120", json!({"rollback": true})),
    ] {
        let r = t.post("/api/v1/jobs", &alice, bad).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
        assert!(r.body["error"].as_str().unwrap().contains("rollback"), "{:?}", r.body);
    }
}

/// Second offsite target: needs a first one; set up directly, changed or
/// removed with approval; its S3 secret sealed at its own location and kept
/// when omitted for the same endpoint; the first target's form keeps it; its
/// own retention validated; copy status and jobs per target.
#[tokio::test]
async fn second_offsite_target() {
    let t = T::new();
    let (alice, sam) = (t.login("alice").await, t.login("sam").await);
    let s3 = |bucket: &str, secret: Option<&str>| {
        let mut r = json!({"type": "s3", "endpoint": "https://s3.example", "region": "eu-central-1",
                           "bucket": bucket, "access_key": "AK", "lock": true});
        if let Some(s) = secret {
            r["secret_key"] = json!(s);
        }
        r
    };
    let put2 = |target: Value| t.put("/api/v1/tenants/acme/offsite2", &alice, json!({"target": target}));
    let r = put2(json!({"remote": s3("archive", Some("SK2"))})).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "no first target yet: {:?}", r.body);
    let first = json!({"remote": {"type": "sftp", "host": "box.example", "user": "u1",
                                  "key_file": "/etc/nexus/ssh/offsite", "host_key": "ssh-ed25519 AAA"}, "bwlimit": 1000000});
    let r = t.put("/api/v1/tenants/acme", &alice, json!({"offsite": first})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    // own retention: classes and ranges checked
    let r = put2(json!({"remote": s3("archive", Some("SK2")), "gfs": {"hourly": 3}})).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = put2(json!({"remote": s3("archive", Some("SK2")), "gfs": {"monthly": -1}})).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // set up: at once
    let r = put2(json!({"remote": s3("archive", Some("SK2")), "gfs": {"monthly": 84, "yearly": 7}})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["offsite"]["second"]["remote"]["secret_key_set"], true);
    assert!(r.body["offsite"]["second"]["remote"].get("secret_key").is_none());
    let stored: Value =
        serde_json::from_str(&t.one::<String>("SELECT offsite FROM tenants WHERE name = 'acme'")).unwrap();
    let sealed = stored["second"]["remote"]["secret_key"].as_str().unwrap().to_owned();
    assert!(sealed.starts_with("sealed:v1:"));
    let mut opened = stored.clone();
    t.sk.open_all(&catalog::secret::tenant_owner("acme"), &mut opened)
        .unwrap();
    assert_eq!(opened["second"]["remote"]["secret_key"], "SK2");
    // a sealed secret moved to the first target does not open there
    let mut moved = stored.clone();
    moved["remote"] = stored["second"]["remote"].clone();
    assert!(t
        .sk
        .open_all(&catalog::secret::tenant_owner("acme"), &mut moved)
        .is_err());
    let tenants = t.get("/api/v1/tenants", &alice).await.body;
    let acme = tenants
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["name"] == "acme")
        .unwrap()
        .clone();
    assert_eq!(acme["offsite"]["second"]["gfs"]["monthly"], 84);
    assert!(!acme.to_string().contains("sealed:v1:"));
    // the first target's form keeps the second; it cannot carry one
    let mut tighter = first.clone();
    tighter["bwlimit"] = json!(500000);
    let r = t.put("/api/v1/tenants/acme", &alice, json!({"offsite": tighter})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["offsite"]["second"]["gfs"]["yearly"], 7);
    let mut with = first.clone();
    with["second"] = json!({"remote": s3("x", Some("y"))});
    assert_eq!(
        t.put("/api/v1/tenants/acme", &alice, json!({"offsite": with}))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        t.put("/api/v1/tenants/acme", &alice, json!({"offsite": {}}))
            .await
            .status,
        StatusCode::CONFLICT,
        "remove the second first"
    );
    // a change: approval; the secret may be omitted for the same endpoint
    let r = put2(json!({"remote": s3("archive", None), "gfs": {"monthly": 120}})).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    assert_eq!(
        t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({}))
            .await
            .status,
        StatusCode::OK
    );
    let stored: Value =
        serde_json::from_str(&t.one::<String>("SELECT offsite FROM tenants WHERE name = 'acme'")).unwrap();
    assert_eq!(stored["second"]["gfs"]["monthly"], 120);
    assert_eq!(stored["second"]["remote"]["secret_key"], sealed, "kept");
    // another bucket without the secret: refused (the key would follow it)
    let r = put2(json!({"remote": s3("elsewhere", None)})).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // jobs and copy status per target
    t.exec("UPDATE snapshots SET offsite2 = 1, local = 0 WHERE source = 'vm-101'");
    let r = t
        .post(
            "/api/v1/jobs",
            &alice,
            json!({"kind": "offsite_list", "tenant": "acme", "params": {"target": 2}}),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let r = t
        .post(
            "/api/v1/jobs",
            &alice,
            json!({"kind": "offsite_restore", "tenant": "acme", "params": {"source": "vm-101", "time": 1500, "target": 2}}),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let snaps = t.get("/api/v1/snapshots?source=vm-101", &alice).await.body;
    assert_eq!(
        (snaps[0]["offsite"].clone(), snaps[0]["offsite2"].clone()),
        (json!(false), json!(true))
    );
    assert_eq!(
        t.post(
            "/api/v1/jobs",
            &alice,
            json!({"kind": "offsite_list", "tenant": "globex", "params": {"target": 2}})
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
    // removing: approval
    let r = put2(Value::Null).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    assert_eq!(
        t.one::<i64>("SELECT COUNT(*) FROM audit WHERE action = 'tenant.offsite2'"),
        1
    );
}
