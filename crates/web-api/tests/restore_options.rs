//! Phase 15a/15d: restore options, replace original (approval), restoring several
//! guests at once, the snapshot consistency level and the policy requirement.

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
        let st = AppState::with_keys(cat, None, downloads, TotpKey::generate(), None);
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

fn snap(t: &T, source: &str, time: i64) {
    t.exec(&format!(
        "INSERT INTO snapshots (tenant, source, time, size, local, offsite, consistency) VALUES ('acme', '{source}', {time}, 1, 1, 0, 'crash')"
    ));
}

fn restore(source: &str, extra: Value) -> Value {
    let mut p = json!({"source": source, "time": 1000, "node": "pve1", "target": 905, "storage": "local-lvm"});
    for (k, v) in extra.as_object().unwrap() {
        p[k] = v.clone();
    }
    json!({"kind": if source.starts_with("ct-") { "restore_ct" } else { "restore" }, "tenant": "acme", "params": p})
}

#[tokio::test]
async fn restore_options_validated_and_stored() {
    let t = T::new();
    snap(&t, "vm-100", 1000);
    snap(&t, "ct-300", 1000);
    let otto = t.login("otto").await;
    let r = t
        .post(
            "/api/v1/jobs",
            &otto,
            restore(
                "vm-100",
                json!({"name_prefix": "dr-", "pool": "dr", "start": true, "link_down": true}),
            ),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let id = r.body["id"].as_i64().unwrap();
    let p: String = t.one(&format!("SELECT params FROM jobs WHERE id = {id}"));
    let p: Value = serde_json::from_str(&p).unwrap();
    assert_eq!(
        (&p["name_prefix"], &p["pool"], &p["start"], &p["link_down"]),
        (&json!("dr-"), &json!("dr"), &json!(true), &json!(true))
    );
    assert!(p.get("replace").is_none());
    // instant recovery: link_down / start / name prefix accepted (rejected before 15a)
    let mut ir = restore(
        "vm-100",
        json!({"link_down": true, "start": false, "name_prefix": "ir-"}),
    );
    ir["kind"] = json!("instant_recover");
    let r = t.post("/api/v1/jobs", &otto, ir).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let r = t
        .post("/api/v1/jobs", &otto, restore("ct-300", json!({"name": "ct1-dr"})))
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    for bad in [
        json!({"name": "a b"}),
        json!({"name": "-x"}),
        json!({"name": "x", "name_prefix": "y-"}),
        json!({"pool": "p/../q"}),
        json!({"name": "x".repeat(64)}),
        json!({"keep_original_links": true}),
        json!({"start": "yes"}),
        json!({"bogus": 1}),
    ] {
        let r = t.post("/api/v1/jobs", &otto, restore("vm-100", bad.clone())).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}: {:?}", r.body);
    }
    let mut ir = restore("vm-100", json!({"replace": true}));
    ir["kind"] = json!("instant_recover");
    assert_eq!(t.post("/api/v1/jobs", &otto, ir).await.status, StatusCode::BAD_REQUEST);
    // the snapshot list shows the level
    let l = t.get("/api/v1/snapshots?tenant=acme", &otto).await.body;
    assert!(l.as_array().unwrap().iter().all(|s| s["consistency"] == "crash"), "{l}");
    // plugin snapshot metadata (v23) comes back as JSON, absent = null
    assert!(l.as_array().unwrap().iter().all(|s| s["meta"].is_null()), "{l}");
    t.exec(r#"UPDATE snapshots SET meta = '{"recoverable":{"to_lsn":"0/3000000"}}' WHERE source = 'vm-100'"#);
    let l = t.get("/api/v1/snapshots?tenant=acme&source=vm-100", &otto).await.body;
    assert_eq!(l[0]["meta"]["recoverable"]["to_lsn"], "0/3000000", "{l}");
    // and the dashboard counts the newest snapshot per source
    let d = t.get("/api/v1/dashboard", &otto).await.body;
    assert_eq!(
        d["consistency"],
        json!({"application": 0, "crash": 2, "inconsistent": 0, "unknown": 0})
    );
}

#[tokio::test]
async fn replace_original_needs_approval() {
    let t = T::new();
    snap(&t, "vm-100", 1000);
    let (sam, otto, tina) = (t.login("sam").await, t.login("otto").await, t.login("tina").await);
    let jobs = |t: &T| -> i64 { t.one("SELECT COUNT(*) FROM jobs") };
    // tenant users may restore, not replace
    let r = t
        .post("/api/v1/jobs", &tina, restore("vm-100", json!({"replace": true})))
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{:?}", r.body);
    // same VMID as the original: refused
    let r = t
        .post(
            "/api/v1/jobs",
            &otto,
            restore("vm-100", json!({"replace": true, "target": 100})),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    let r = t
        .post(
            "/api/v1/jobs",
            &otto,
            restore(
                "vm-100",
                json!({"replace": true, "start": true, "keep_original_links": true}),
            ),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().expect("an approval request, not a job");
    assert_eq!(jobs(&t), 0, "no job before the approval");
    let (action, params): (String, String) =
        t.st.cat
            .conn()
            .query_row("SELECT action, params FROM quorum WHERE id = ?1", [q], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
    assert_eq!(action, "restore.replace");
    let p: Value = serde_json::from_str(&params).unwrap();
    assert_eq!((&p["tenant"], &p["kind"]), (&json!("acme"), &json!("restore")));
    assert_eq!(p["params"]["keep_original_links"], true);
    assert!(p["params"].get("replace").is_none(), "{p}");
    // an operator cannot approve; the security officer can; the scheduler then queues the job
    assert_eq!(
        t.post(&format!("/api/v1/quorum/{q}/approve"), &otto, json!({}))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(
        (r.status, r.body["state"].clone()),
        (StatusCode::OK, json!("approved")),
        "{:?}",
        r.body
    );
    assert_eq!(jobs(&t), 0, "executed by the scheduler, not the web-api");
    // audited
    let n: i64 =
        t.one("SELECT COUNT(*) FROM audit WHERE action = 'quorum.request' AND details LIKE '%restore.replace%'");
    assert_eq!(n, 1);
    // the scheduler's job: cancellable while queued, not while it runs (it may be mid-swap)
    t.exec(
        r#"INSERT INTO jobs (id, kind, tenant, params, state, requested_by, created) VALUES
             (50, 'restore', 'acme', '{"source":"vm-100","replace":true,"quorum_id":1}', 'running', 'scheduler', 0),
             (51, 'restore', 'acme', '{"source":"vm-100","replace":true,"quorum_id":2}', 'queued', 'scheduler', 0),
             (52, 'restore', 'acme', '{"source":"vm-100"}', 'running', 'otto', 0);"#,
    );
    let r = t.post("/api/v1/jobs/50/cancel", &otto, json!({})).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
    for id in [51, 52] {
        let r = t.post(&format!("/api/v1/jobs/{id}/cancel"), &otto, json!({})).await;
        assert_eq!(r.status, StatusCode::OK, "{id}: {:?}", r.body);
    }
}

#[tokio::test]
async fn restore_many_creates_one_job_per_guest() {
    let t = T::new();
    for s in ["vm-100", "vm-101", "ct-300"] {
        snap(&t, s, 1000);
    }
    t.exec(
        "INSERT INTO snapshots (tenant, source, time, size, local, offsite) VALUES ('globex', 'vm-200', 1000, 1, 1, 0)",
    );
    let (otto, tina) = (t.login("otto").await, t.login("tina").await);
    let body = json!({"tenant": "acme", "node": "pve1", "storage": "local-lvm", "target_base": 9000,
                      "name_prefix": "dr-", "start": true, "link_down": true,
                      "items": [{"source": "vm-100", "time": 1000}, {"source": "vm-101", "time": 1000},
                                {"source": "ct-300", "time": 1000}]});
    let r = t.post("/api/v1/restores", &tina, body.clone()).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let ids: Vec<i64> = r.body["ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_i64().unwrap())
        .collect();
    assert_eq!(ids.len(), 3);
    let rows: Vec<(String, String)> = {
        let c = t.st.cat.conn();
        let mut st = c.prepare("SELECT kind, params FROM jobs ORDER BY id").unwrap();
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    };
    let kinds: Vec<&str> = rows.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(kinds, ["restore", "restore", "restore_ct"]);
    let targets: Vec<i64> = rows
        .iter()
        .map(|(_, p)| serde_json::from_str::<Value>(p).unwrap()["target"].as_i64().unwrap())
        .collect();
    assert_eq!(targets, [9000, 9001, 9002]);
    let n: i64 = t.one("SELECT COUNT(*) FROM audit WHERE action = 'job.create_many'");
    assert_eq!(n, 1, "audited once");
    // all or nothing: one bad item creates no job
    let before: i64 = t.one("SELECT COUNT(*) FROM jobs");
    for (k, v) in [
        (
            "items",
            json!([{"source": "vm-100", "time": 1000}, {"source": "vm-999", "time": 1000}]),
        ),
        (
            "items",
            json!([{"source": "vm-100", "time": 1000}, {"source": "vm-100", "time": 1000}]),
        ),
        ("items", json!([])),
        ("target_base", json!(99)),
        ("name_prefix", json!("a b")),
    ] {
        let mut b = body.clone();
        b[k] = v.clone();
        let r = t.post("/api/v1/restores", &otto, b).await;
        assert!(r.status.is_client_error(), "{k}={v}: {:?}", r.body);
    }
    assert_eq!(t.one::<i64>("SELECT COUNT(*) FROM jobs"), before);
    // other tenants: not visible to a tenant user
    let mut g = body.clone();
    g["tenant"] = json!("globex");
    g["items"] = json!([{"source": "vm-200", "time": 1000}]);
    assert_eq!(t.post("/api/v1/restores", &tina, g).await.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn policy_require_consistency() {
    let t = T::new();
    let (alice, sam) = (t.login("alice").await, t.login("sam").await);
    let base = json!({"name": "strict", "schedule": "daily 22:00",
                      "gfs": {"daily": 7, "weekly": 0, "monthly": 0, "yearly": 0}});
    let r = t.post("/api/v1/policies", &alice, base.clone()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["require_consistency"], json!({"mode": "off", "level": "crash"}));
    let id = r.body["id"].as_i64().unwrap();
    for bad in [
        json!({"mode": "strict"}),
        json!({"mode": "warn", "level": "app"}),
        json!({"mode": "warn", "x": 1}),
    ] {
        let mut b = base.clone();
        b["name"] = json!("x");
        b["require_consistency"] = bad.clone();
        assert_eq!(
            t.post("/api/v1/policies", &alice, b).await.status,
            StatusCode::BAD_REQUEST,
            "{bad}"
        );
    }
    // stricter: direct
    let mut upd = base.clone();
    upd["require_consistency"] = json!({"mode": "fail", "level": "application"});
    let r = t.put(&format!("/api/v1/policies/{id}"), &alice, upd.clone()).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        t.one::<String>(&format!("SELECT require_consistency FROM policies WHERE id = {id}")),
        r#"{"level":"application","mode":"fail"}"#
    );
    // relaxed: approval, applied on approve
    upd["require_consistency"] = json!({"mode": "warn", "level": "application"});
    let r = t.put(&format!("/api/v1/policies/{id}"), &alice, upd).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let list = t.get("/api/v1/policies", &alice).await.body;
    let p = list.as_array().unwrap().iter().find(|p| p["id"] == id).unwrap().clone();
    assert_eq!(
        p["require_consistency"],
        json!({"mode": "warn", "level": "application"})
    );
}
