//! Plugin API: signed upload → quorum → installer, RBAC, dynamic config
//! validation, write-only sealed plugin secrets, plugin jobs, publisher keys.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use catalog::rusqlite::params;
use catalog::secret::{source_owner, SchedulerKey, TotpKey};
use catalog::Catalog;
use http_body_util::BodyExt;
use plugin_proto::bundle;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, OnceLock};
use tower::ServiceExt;
use web_api::plugins::PluginPaths;
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
    sk: SchedulerKey,
    paths: PluginPaths,
    project_key: String,
    _dir: tempfile::TempDir,
}

#[derive(Clone)]
struct S {
    cookie: String,
    csrf: String,
}

struct R {
    status: StatusCode,
    body: Value,
}

fn manifest(version: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "id": "pgx", "name": "PG test", "version": version, "publisher": "nexusbackup", "api": 1,
        "kinds": [{"kind": "pgx", "title": "PG", "config_schema": {"type": "object", "required": ["host", "user", "password"],
            "properties": {"host": {"type": "string", "format": "hostname"}, "port": {"type": "integer", "format": "port"},
                           "user": {"type": "string", "pattern": "^[a-z_][a-z0-9_]*$"}, "password": {"type": "string", "format": "password"},
                           "sslmode": {"type": "string", "enum": ["disable", "require"]}, "dbs": {"type": "array", "items": {"type": "string"}}}},
            "secret_fields": ["password"],
            "endpoints": [{"host": "/host", "port": "/port", "default_port": 5432, "proto": "tcp"}],
            "guests": {"title": "Databases", "list": true},
            "restores": [{"id": "download", "title": "Download"},
                         {"id": "to_target", "title": "Restore", "applies_to": "guest", "params_schema": {"type": "object", "required": ["database"],
                            "properties": {"database": {"type": "string", "pattern": "^[a-z]+$"}}}},
                         {"id": "mount", "title": "Mount", "params_schema": {"type": "object", "properties": {}}}]}]
    }))
    .unwrap()
}

fn bundle_of(version: &str) -> Vec<u8> {
    bundle::pack(&manifest(version), b"\x7fELF pg", &BTreeMap::new()).unwrap()
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
        let sk = SchedulerKey::generate();
        let secrets_pub = dir.path().join("secrets.pub");
        sk.write_public(&secrets_pub, None).unwrap();
        let downloads = dir.path().join("downloads");
        std::fs::create_dir(&downloads).unwrap();
        let st = AppState::with_keys(cat, None, downloads, TotpKey::generate(), Some(secrets_pub));
        let paths = PluginPaths {
            staging: dir.path().join("staging"),
            keys: dir.path().join("keys"),
            plugins: dir.path().join("plugins"),
        };
        for d in [&paths.staging, &paths.keys, &paths.plugins] {
            std::fs::create_dir_all(d).unwrap();
        }
        let (sk_pem, pk_pem) = bundle::generate_key().unwrap();
        std::fs::write(paths.keys.join("project.pub"), pk_pem).unwrap();
        st.plugins.set(paths.clone()).unwrap();
        let mut t = T {
            app: web_api::router(st.clone()),
            st,
            secrets: HashMap::new(),
            sk,
            paths,
            project_key: sk_pem,
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
            t.st.cat
                .conn()
                .execute(
                    "INSERT INTO users (name, password_hash, totp_secret, role, tenant, created) VALUES (?1,?2,?3,?4,?5,0)",
                    params![n, pw_hash(), enc, role, tenant],
                )
                .unwrap();
            t.secrets.insert(n.into(), secret);
        }
        t
    }

    async fn send(&self, req: Request<Body>) -> R {
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let raw = res.into_body().collect().await.unwrap().to_bytes().to_vec();
        R {
            status,
            body: serde_json::from_slice(&raw).unwrap_or(Value::Null),
        }
    }

    async fn call(&self, m: Method, path: &str, s: &S, body: Option<Value>) -> R {
        let mut b = Request::builder()
            .method(m.clone())
            .uri(path)
            .header(header::COOKIE, format!("nx_session={}", s.cookie));
        if m != Method::GET {
            b = b.header("x-csrf-token", &s.csrf);
        }
        let req = match body {
            Some(v) => b
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(v.to_string()))
                .unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        self.send(req).await
    }

    async fn upload(&self, s: &S, bytes: &[u8], sig: Option<&str>, ct: &str) -> R {
        let mut b = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/plugins")
            .header(header::COOKIE, format!("nx_session={}", s.cookie))
            .header("x-csrf-token", &s.csrf)
            .header(header::CONTENT_TYPE, ct);
        if let Some(sig) = sig {
            b = b.header("x-plugin-signature", sig);
        }
        self.send(b.body(Body::from(bytes.to_vec())).unwrap()).await
    }

    async fn login(&self, name: &str) -> S {
        self.st
            .cat
            .conn()
            .execute("UPDATE users SET totp_last_step = 0 WHERE name = ?1", [name])
            .unwrap();
        let code = catalog::auth::totp_now(&self.secrets[name]).unwrap();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({"name": name, "password": PW, "totp": code}).to_string(),
            ))
            .unwrap();
        let res = self.app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let sc = res.headers()[header::SET_COOKIE].to_str().unwrap().to_owned();
        let cookie = sc
            .strip_prefix("nx_session=")
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let raw = res.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&raw).unwrap();
        S {
            cookie,
            csrf: body["csrf"].as_str().unwrap().to_owned(),
        }
    }

    fn installer(&self) -> Vec<String> {
        plugin_manager::run_pending(
            &self.st.cat,
            &plugin_manager::Paths {
                staging: self.paths.staging.clone(),
                plugins: self.paths.plugins.clone(),
                project_keys: self.paths.keys.clone(),
            },
        )
        .unwrap()
    }
}

#[tokio::test]
async fn plugin_lifecycle_sources_and_jobs() {
    let t = T::new();
    let (admin, so, op, tina) = (
        t.login("alice").await,
        t.login("sam").await,
        t.login("otto").await,
        t.login("tina").await,
    );
    let b = bundle_of("1.0.0");
    let sig = bundle::sign(&b, &t.project_key).unwrap();
    let oct = "application/octet-stream";

    // RBAC + input checks
    for s in [&op, &tina, &so] {
        assert_eq!(t.upload(s, &b, Some(&sig), oct).await.status, StatusCode::FORBIDDEN);
    }
    assert_eq!(t.upload(&admin, &b, None, oct).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        t.upload(&admin, &b, Some(&sig), "application/json").await.status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    let (other, _) = bundle::generate_key().unwrap();
    let r = t
        .upload(&admin, &b, Some(&bundle::sign(&b, &other).unwrap()), oct)
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);

    // upload → quorum (four eyes) → installer
    let wrapped: String = sig
        .as_bytes()
        .chunks(20)
        .map(|c| format!("{}  ", String::from_utf8_lossy(c)))
        .collect();
    let r = t.upload(&admin, &b, Some(wrapped.trim()), oct).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    assert_eq!(r.body["plugin"]["state"], "pending");
    assert!(r.body["plugin"]["signer"].as_str().unwrap().contains("project.pub"));
    let q = r.body["quorum_id"].as_i64().unwrap();
    let own = t
        .call(Method::POST, &format!("/api/v1/quorum/{q}/approve"), &admin, None)
        .await;
    assert_eq!(own.status, StatusCode::FORBIDDEN);
    let ok = t
        .call(Method::POST, &format!("/api/v1/quorum/{q}/approve"), &so, None)
        .await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.body);
    assert!(t.paths.staging.join(".trigger").exists());
    assert_eq!(t.installer(), ["installed pgx 1.0.0"]);
    let l = t.call(Method::GET, "/api/v1/plugins", &tina, None).await;
    assert_eq!(
        (l.body[0]["state"].as_str(), l.body[0]["current"].as_bool()),
        (Some("installed"), Some(true))
    );

    // dynamic config validation
    let src = |cfg: Value| json!({"tenant": "acme", "kind": "plugin:pgx", "name": "pg1", "config": cfg});
    for (cfg, why) in [
        (json!({"host": "db1", "user": "backup"}), "password: required"),
        (json!({"host": "db1", "user": "Backup", "password": "x"}), "must match"),
        (json!({"host": "db 1", "user": "b", "password": "x"}), "host name"),
        (
            json!({"host": "db1", "user": "b", "password": "x", "port": 70000}),
            "1..=65535",
        ),
        (
            json!({"host": "db1", "user": "b", "password": "x", "sslmode": "maybe"}),
            "allowed values",
        ),
        (
            json!({"host": "db1", "user": "b", "password": "x", "evil": 1}),
            "unknown property",
        ),
        (
            json!({"host": "db1", "user": "b", "password": "x", "dbs": [1]}),
            "must be a string",
        ),
    ] {
        let r = t.call(Method::POST, "/api/v1/sources", &admin, Some(src(cfg))).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{why}");
        assert!(r.body["error"].as_str().unwrap().contains(why), "{why}: {:?}", r.body);
    }
    let r = t
        .call(
            Method::POST,
            "/api/v1/sources",
            &admin,
            Some(src(
                json!({"host": "db1", "port": 5433, "user": "backup", "password": "pg-s3cret", "dbs": ["a"]}),
            )),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let sid = r.body["id"].as_i64().unwrap();
    assert_eq!(r.body["config"]["password_set"], true);
    assert!(r.body["config"].get("password").is_none());
    // sealed at rest, opens only for the scheduler at this location
    let raw: String =
        t.st.cat
            .conn()
            .query_row("SELECT config FROM sources WHERE id = ?1", [sid], |r| r.get(0))
            .unwrap();
    assert!(!raw.contains("pg-s3cret") && raw.contains("sealed:v1:"));
    let mut v: Value = serde_json::from_str(&raw).unwrap();
    t.sk.open_all_with(&source_owner(sid), &mut v, &["password"]).unwrap();
    assert_eq!(v["password"], "pg-s3cret");
    // update without the secret keeps it; a new endpoint needs it again
    let upd = |cfg: Value| json!({"name": "pg1", "config": cfg});
    let r = t
        .call(
            Method::PUT,
            &format!("/api/v1/sources/{sid}"),
            &admin,
            Some(upd(json!({"host": "db1", "port": 5433, "user": "backup2"}))),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["config"]["password_set"], true);
    let r = t
        .call(
            Method::PUT,
            &format!("/api/v1/sources/{sid}"),
            &admin,
            Some(upd(json!({"host": "evil.example", "port": 5433, "user": "b"}))),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);

    // groups: guest ids only
    let p = t
        .call(
            Method::POST,
            "/api/v1/policies",
            &admin,
            Some(json!({"name": "p", "schedule": "daily 01:00", "gfs": {"daily": 7, "weekly": 4, "monthly": 6, "yearly": 1}})),
        )
        .await;
    let pid = p.body["id"].as_i64().unwrap();
    let g =
        |guests: Value| json!({"tenant": "acme", "source_id": sid, "policy_id": pid, "name": "g", "guests": guests});
    let r = t
        .call(Method::POST, "/api/v1/groups", &admin, Some(g(json!(["../x"]))))
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = t
        .call(
            Method::POST,
            "/api/v1/groups",
            &admin,
            Some(g(json!(["db2", "db1", "db1"]))),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["guests"], json!(["db1", "db2"]));

    // jobs
    let job = |kind: &str, params: Value| json!({"kind": kind, "tenant": "acme", "params": params});
    let r = t
        .call(
            Method::POST,
            "/api/v1/jobs",
            &op,
            Some(job("plugin_validate", json!({"source_id": sid}))),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let r = t
        .call(
            Method::POST,
            "/api/v1/jobs",
            &tina,
            Some(job("plugin_guests", json!({"source_id": sid}))),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = t
        .call(
            Method::POST,
            "/api/v1/jobs",
            &op,
            Some(job("plugin_backup", json!({"source_id": sid, "guests": ["a/b"]}))),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    t.st.cat
        .conn()
        .execute(
            "INSERT INTO snapshots (tenant, source, time, local, offsite) VALUES ('acme', ?1, 100, 1, 0)",
            [format!("plugin-pgx-{sid}-db1")],
        )
        .unwrap();
    let restore = |params: Value| {
        job(
            "plugin_restore",
            json!({"source": format!("plugin-pgx-{sid}-db1"), "time": 100, "restore": "to_target", "params": params}),
        )
    };
    let r = t
        .call(
            Method::POST,
            "/api/v1/jobs",
            &tina,
            Some(restore(json!({"database": "Bad!"}))),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = t
        .call(
            Method::POST,
            "/api/v1/jobs",
            &tina,
            Some(restore(json!({"database": "app"}))),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    // manifest v1.4 applies_to: to_target is a per-database (guest) restore, not
    // offered on a whole-source snapshot
    t.st.cat
        .conn()
        .execute(
            "INSERT INTO snapshots (tenant, source, time, local, offsite) VALUES ('acme', ?1, 100, 1, 0)",
            [format!("plugin-pgx-{sid}")],
        )
        .unwrap();
    let r = t
        .call(
            Method::POST,
            "/api/v1/jobs",
            &tina,
            Some(job(
                "plugin_restore",
                json!({"source": format!("plugin-pgx-{sid}"), "time": 100, "restore": "to_target", "params": {"database": "app"}}),
            )),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    assert!(r.body["error"].as_str().unwrap().contains("guest"), "{:?}", r.body);
    let r = t
        .call(
            Method::POST,
            "/api/v1/jobs",
            &tina,
            Some(job(
                "plugin_restore",
                json!({"source": format!("plugin-pgx-{sid}-db1"), "time": 100, "restore": "download"}),
            )),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // Phase 15b: the plugin's file tree (it offers `download`) onto an agent of the tenant
    t.st.cat
        .conn()
        .execute(
            "INSERT INTO agents (id, tenant, name, host, port) VALUES ('0123456789abcdef','acme','web01','web01.lan',7444)",
            [],
        )
        .unwrap();
    let to_host = |source: String| {
        job(
            "restore_files",
            json!({"source": source, "time": 100, "paths": ["/"], "target": "/srv/pg",
                   "overwrite": "never", "confirm": "web01", "agent_id": "0123456789abcdef"}),
        )
    };
    let r = t
        .call(
            Method::POST,
            "/api/v1/jobs",
            &tina,
            Some(to_host(format!("plugin-pgx-{sid}-db1"))),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let r = t
        .call(
            Method::POST,
            "/api/v1/jobs",
            &tina,
            Some(to_host(format!("plugin-other-{sid}-db1"))),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    let r = t
        .call(
            Method::POST,
            "/api/v1/jobs",
            &tina,
            Some(job(
                "plugin_mount",
                json!({"source": format!("plugin-pgx-{sid}-db1"), "time": 100, "minutes": 5}),
            )),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let r = t
        .call(
            Method::POST,
            "/api/v1/jobs",
            &tina,
            Some(job(
                "files_list",
                json!({"source": format!("plugin-pgx-{sid}-db1"), "time": 100, "path": "/"}),
            )),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);

    // remove refused while a source exists; disable is quorum-gated
    let r = t.call(Method::DELETE, "/api/v1/plugins/pgx", &admin, None).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    let r = t.call(Method::POST, "/api/v1/plugins/pgx/disable", &admin, None).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let q = r.body["quorum_id"].as_i64().unwrap();
    t.call(Method::POST, &format!("/api/v1/quorum/{q}/approve"), &so, None)
        .await;
    let r = t
        .call(
            Method::POST,
            "/api/v1/sources",
            &admin,
            Some(json!({"tenant": "acme", "kind": "plugin:pgx", "name": "pg2",
            "config": {"host": "db2", "user": "b", "password": "x"}})),
        )
        .await;
    assert!(r.body["error"].as_str().unwrap().contains("disabled"), "{:?}", r.body);
    let r = t.call(Method::POST, "/api/v1/plugins/pgx/enable", &admin, None).await;
    assert_eq!(r.status, StatusCode::OK);

    // downgrade refused at upload
    let old = bundle_of("0.9.0");
    let r = t
        .upload(&admin, &old, Some(&bundle::sign(&old, &t.project_key).unwrap()), oct)
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);

    // publisher keys: quorum, then listed; builtin keys cannot be removed
    let (_, acme_pub) = bundle::generate_key().unwrap();
    let r = t
        .call(
            Method::POST,
            "/api/v1/plugin-keys",
            &admin,
            Some(json!({"publisher": "acme", "public_key": acme_pub})),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    let r = t
        .call(
            Method::POST,
            "/api/v1/plugin-keys",
            &admin,
            Some(json!({"publisher": "nexusbackup", "public_key": acme_pub})),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "project publisher is reserved");
    t.call(Method::POST, &format!("/api/v1/quorum/{q}/approve"), &so, None)
        .await;
    let keys = t.call(Method::GET, "/api/v1/plugin-keys", &op, None).await;
    let keys = keys.body.as_array().unwrap().clone();
    assert_eq!(keys.len(), 2);
    let acme = keys.iter().find(|k| k["publisher"] == "acme").unwrap();
    assert_eq!(
        (acme["added_by"].as_str(), acme["approved_by"].as_str()),
        (Some("alice"), Some("sam"))
    );
    let builtin = keys.iter().find(|k| k["builtin"] == true).unwrap();
    let fp = builtin["fingerprint"].as_str().unwrap().replace(':', "%3A");
    let r = t
        .call(Method::DELETE, &format!("/api/v1/plugin-keys/{fp}"), &admin, None)
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    let r = t.call(Method::GET, "/api/v1/plugin-keys", &tina, None).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert!(t.st.cat.verify_audit().unwrap() > 10);
}

/// Approvals disabled: the upload is approved at once (no quorum row) and the
/// installer picks it up.
#[tokio::test]
async fn plugin_upload_without_approvals() {
    let t = T::new();
    catalog::set_setting(&t.st.cat.conn(), "approvals_enabled", "false").unwrap();
    let admin = t.login("alice").await;
    let b = bundle_of("1.0.0");
    let sig = bundle::sign(&b, &t.project_key).unwrap();
    let r = t.upload(&admin, &b, Some(&sig), "application/octet-stream").await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        (r.body["approvals"].as_str(), r.body["executed"].as_bool()),
        (Some("disabled"), Some(true))
    );
    assert_eq!(r.body["plugin"]["state"], "approved");
    assert!(t.paths.staging.join(".trigger").exists());
    assert_eq!(t.installer(), ["installed pgx 1.0.0"]);
}
