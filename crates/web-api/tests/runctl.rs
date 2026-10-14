//! Phase 13b run control: policy retry / blackout / SLA, group time zones,
//! pause and source maintenance, "back up now" for some guests, cancelling
//! running jobs, and the dashboard's "paused" status.

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

#[tokio::test]
async fn policy_run_control_fields_and_blackout_quorum() {
    let t = T::new();
    let (alice, sam) = (t.login("alice").await, t.login("sam").await);
    let base = json!({"name": "nightly", "schedule": "Mon-Fri 22:00",
                      "gfs": {"daily": 7, "weekly": 4, "monthly": 0, "yearly": 0}});
    // defaults
    let r = t.post("/api/v1/policies", &alice, base.clone()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["retry"], json!({"count": 3, "delay_min": 5}));
    assert_eq!(
        (r.body["blackout"].clone(), r.body["sla_minutes"].clone()),
        (json!([]), Value::Null)
    );
    let id = r.body["id"].as_i64().unwrap();
    for (k, v) in [
        ("schedule", json!("every 5h")),
        ("schedule", json!("weekly 01:00")),
        ("retry", json!({"count": 11, "delay_min": 5})),
        ("retry", json!({"count": 1, "delay_min": 0})),
        ("blackout", json!([{"from": "08:00", "to": "08:00"}])),
        ("blackout", json!([{"days": ["Xyz"], "from": "08:00", "to": "18:00"}])),
        ("blackout", json!([{"from": "08:00", "to": "18:00", "bogus": 1}])),
        ("sla_minutes", json!(0)),
    ] {
        let mut b = base.clone();
        b["name"] = json!("x");
        b[k] = v.clone();
        let r = t.post("/api/v1/policies", &alice, b).await;
        assert!(r.status.is_client_error(), "{k}={v}: {:?}", r.body);
    }
    // retry / SLA / schedule changes apply directly
    let mut upd = base.clone();
    upd["retry"] = json!({"count": 1, "delay_min": 10});
    upd["sla_minutes"] = json!(120);
    upd["schedule"] = json!("every 6h at 15");
    let r = t.put(&format!("/api/v1/policies/{id}"), &alice, upd.clone()).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        t.one::<String>(&format!("SELECT retry FROM policies WHERE id = {id}")),
        r#"{"count":1,"delay_min":10}"#
    );
    // Phase 18b: every 15 minutes + keep all snapshots of the last 24 h (raising: direct)
    let mut fast = upd.clone();
    fast["schedule"] = json!("every 15m");
    fast["gfs"]["recent"] = json!(24);
    let r = t.put(&format!("/api/v1/policies/{id}"), &alice, fast.clone()).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let list = t.get("/api/v1/policies", &alice).await.body;
    let p = list.as_array().unwrap().iter().find(|p| p["id"] == id).unwrap().clone();
    assert_eq!(
        (p["schedule"].clone(), p["gfs"]["recent"].clone()),
        (json!("every 15m"), json!(24))
    );
    fast["gfs"]["recent"] = json!(9000);
    assert_eq!(
        t.put(&format!("/api/v1/policies/{id}"), &alice, fast.clone())
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    // lowering it shortens retention: quorum (left pending; the plain update below keeps 24 h)
    fast["gfs"]["recent"] = json!(0);
    let r = t.put(&format!("/api/v1/policies/{id}"), &alice, fast).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    upd["gfs"]["recent"] = json!(24);
    // a new blackout window means fewer runs: quorum
    let w = json!([{"days": ["Mon", "Tue"], "from": "08:00", "to": "18:00", "abort": true}]);
    upd["blackout"] = w.clone();
    let r = t.put(&format!("/api/v1/policies/{id}"), &alice, upd.clone()).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let list = t.get("/api/v1/policies", &alice).await.body;
    let p = list.as_array().unwrap().iter().find(|p| p["id"] == id).unwrap().clone();
    assert_eq!((p["blackout"].clone(), p["sla_minutes"].clone()), (w, json!(120)));
    // removing it is direct
    upd["blackout"] = json!([]);
    let r = t.put(&format!("/api/v1/policies/{id}"), &alice, upd).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
}

#[tokio::test]
async fn group_timezone_pause_and_maintenance() {
    let t = T::new();
    let (alice, otto, tina) = (t.login("alice").await, t.login("otto").await, t.login("tina").await);
    let g = json!({"tenant": "acme", "source_id": 1, "policy_id": 1, "name": "g9", "guests": [100],
                   "timezone": "Europe/Berlin"});
    let r = t.post("/api/v1/groups", &alice, g.clone()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["timezone"], "Europe/Berlin");
    let mut bad = g.clone();
    bad["name"] = json!("g10");
    bad["timezone"] = json!("Mars/Base");
    assert_eq!(
        t.post("/api/v1/groups", &alice, bad).await.status,
        StatusCode::BAD_REQUEST
    );
    let r = t
        .put(
            "/api/v1/groups/1",
            &alice,
            json!({"source_id": 1, "policy_id": 1, "name": "g1", "guests": [100, 101, 102], "timezone": "America/New_York"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);

    // pause: operator yes, tenant user no; until must be in the future
    let until = catalog::now() + 3600;
    assert_eq!(
        t.post("/api/v1/groups/1/pause", &tina, json!({"until": until}))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.post("/api/v1/groups/1/pause", &otto, json!({"until": 5}))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    let r = t.post("/api/v1/groups/1/pause", &otto, json!({"until": until})).await;
    assert_eq!(
        (r.status, r.body["paused_until"].clone()),
        (StatusCode::OK, json!(until))
    );
    let r = t.post("/api/v1/groups/1/pause", &otto, json!({})).await;
    assert_eq!(r.body["paused_until"], -1, "indefinitely");
    let list = t.get("/api/v1/groups", &tina).await.body;
    let mine: Vec<&Value> = list.as_array().unwrap().iter().filter(|g| g["id"] == 1).collect();
    assert!(
        list.as_array().unwrap().iter().all(|g| g["tenant"] == "acme"),
        "tenant scope"
    );
    assert_eq!(mine[0]["paused_until"], -1);
    assert_eq!(mine[0]["timezone"], "America/New_York");
    assert_eq!(mine[0]["blackout_active"], false);
    let r = t.post("/api/v1/groups/1/resume", &otto, json!({})).await;
    assert_eq!(
        (r.status, r.body["paused_until"].clone()),
        (StatusCode::OK, Value::Null)
    );
    assert_eq!(
        t.post("/api/v1/groups/99/resume", &otto, json!({})).await.status,
        StatusCode::NOT_FOUND
    );

    // source maintenance
    assert_eq!(
        t.post("/api/v1/sources/1/maintenance", &tina, json!({})).await.status,
        StatusCode::FORBIDDEN
    );
    let r = t
        .post("/api/v1/sources/1/maintenance", &otto, json!({"until": until}))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let src = t.get("/api/v1/sources", &alice).await.body;
    let s1 = src.as_array().unwrap().iter().find(|s| s["id"] == 1).unwrap().clone();
    assert_eq!(s1["maintenance_until"], until);
    let groups = t.get("/api/v1/groups", &alice).await.body;
    let g1 = groups
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["id"] == 1)
        .unwrap()
        .clone();
    assert_eq!(g1["maintenance_until"], until);
    let r = t.post("/api/v1/sources/1/maintenance/end", &otto, json!({})).await;
    assert_eq!(r.body["maintenance_until"], Value::Null);
    for a in [
        "group.pause",
        "group.resume",
        "source.maintenance",
        "source.maintenance_end",
    ] {
        let n: i64 = t.one(&format!(
            "SELECT COUNT(*) FROM audit WHERE action = '{a}' AND actor = 'otto'"
        ));
        assert!(n >= 1, "{a}");
    }
    // blackout windows covering the whole day (UTC)
    t.exec(r#"UPDATE policies SET blackout = '[{"from":"00:00","to":"23:59"},{"from":"23:59","to":"00:00"}]'"#);
    let groups = t.get("/api/v1/groups", &alice).await.body;
    assert!(groups.as_array().unwrap().iter().all(|g| g["blackout_active"] == true));
}

#[tokio::test]
async fn backup_now_guests_failed_only_and_cancel_running() {
    let t = T::new();
    let (otto, tina) = (t.login("otto").await, t.login("tina").await);
    let job = |p: Value| json!({"kind": "backup", "tenant": "acme", "params": p});
    let r = t
        .post("/api/v1/jobs", &otto, job(json!({"group_id": 1, "guests": [101, 102]})))
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let id = r.body["id"].as_i64().unwrap();
    let p: String = t.one(&format!("SELECT params FROM jobs WHERE id = {id}"));
    assert_eq!(
        serde_json::from_str::<Value>(&p).unwrap(),
        json!({"group_id": 1, "guests": [101, 102]})
    );
    // "101" and 101 are the same guest; stored in the group's own form, once
    let r = t
        .post(
            "/api/v1/jobs",
            &otto,
            job(json!({"group_id": 1, "guests": ["101", 101]})),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let p: String = t.one(&format!("SELECT params FROM jobs WHERE id = {}", r.body["id"]));
    assert_eq!(serde_json::from_str::<Value>(&p).unwrap()["guests"], json!([101]));
    for p in [
        json!({"group_id": 1, "guests": [300]}),
        json!({"group_id": 1, "guests": []}),
        json!({"vmid": 100, "guests": [100]}),
        json!({"group_id": 1, "guests": [100], "failed_only": true}),
    ] {
        assert_eq!(
            t.post("/api/v1/jobs", &otto, job(p.clone())).await.status,
            StatusCode::BAD_REQUEST,
            "{p}"
        );
    }
    // failed_only: the last finished run must have failed
    t.exec(&format!("UPDATE jobs SET state = 'ok' WHERE id = {id}"));
    let r = t
        .post("/api/v1/jobs", &otto, job(json!({"group_id": 1, "failed_only": true})))
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    t.exec(
        r#"INSERT INTO jobs (kind, tenant, params, state, requested_by, created, result)
           VALUES ('backup', 'acme', '{"group_id":1}', 'failed', 'scheduler', 2, '{"failed_guests":[102]}');"#,
    );
    let r = t
        .post("/api/v1/jobs", &otto, job(json!({"group_id": 1, "failed_only": true})))
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let p: String = t.one(&format!("SELECT params FROM jobs WHERE id = {}", r.body["id"]));
    assert_eq!(
        serde_json::from_str::<Value>(&p).unwrap(),
        json!({"group_id": 1, "guests": [102]})
    );

    // cancel: queued at once, running by request, finished not at all
    t.exec(&format!(
        "UPDATE jobs SET state = 'running', started = 3 WHERE id = {id}"
    ));
    assert_eq!(
        t.post(&format!("/api/v1/jobs/{id}/cancel"), &tina, json!({}))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let r = t.post(&format!("/api/v1/jobs/{id}/cancel"), &otto, json!({})).await;
    assert_eq!(
        (r.status, r.body["state"].clone()),
        (StatusCode::OK, json!("cancelling"))
    );
    assert_eq!(
        t.one::<String>(&format!("SELECT cancel_by FROM jobs WHERE id = {id}")),
        "otto"
    );
    assert_eq!(
        t.one::<String>(&format!("SELECT state FROM jobs WHERE id = {id}")),
        "running"
    );
    assert_eq!(
        t.post(&format!("/api/v1/jobs/{id}/cancel"), &otto, json!({}))
            .await
            .status,
        StatusCode::CONFLICT
    );
    let r = t.get(&format!("/api/v1/jobs/{id}"), &otto).await;
    assert_eq!(
        (r.body["cancel_by"].clone(), r.body["attempt"].clone()),
        (json!("otto"), json!(1))
    );
    assert_eq!(r.body["progress"], Value::Null);
    // live progress (scheduler): the output so far follows what was logged before the start
    t.exec(&format!(
        r#"UPDATE jobs SET log = 'queued note' || char(10), live_log = 'item 1/2: vm-101 web' || char(10),
           progress = '{{"item":"vm-101","items":2,"percent":12.5,"rate":1048576}}' WHERE id = {id}"#
    ));
    let r = t.get(&format!("/api/v1/jobs/{id}"), &otto).await;
    assert_eq!(r.body["log"], "queued note\nitem 1/2: vm-101 web\n");
    assert_eq!(
        (
            r.body["progress"]["item"].clone(),
            r.body["progress"]["percent"].clone()
        ),
        (json!("vm-101"), json!(12.5))
    );
    let list = t.get("/api/v1/jobs?state=running", &otto).await.body;
    let row = list.as_array().unwrap().iter().find(|j| j["id"] == id).unwrap();
    assert_eq!(row["progress"]["rate"], 1048576);
    assert!(row.get("log").is_none());
    t.exec(&format!("UPDATE jobs SET state = 'ok' WHERE id = {id}"));
    assert_eq!(
        t.post(&format!("/api/v1/jobs/{id}/cancel"), &otto, json!({}))
            .await
            .status,
        StatusCode::CONFLICT
    );
    // an auto-protect group (13c): the guests are the resolved inventory guests
    t.exec(
        "UPDATE groups SET mode = 'all', guests = '[]', exclude = '[\"501\"]' WHERE id = 1;
         INSERT INTO inventory (source_id, guest, seen) VALUES (1, '500', 1), (1, '501', 1), (1, '502', 1);",
    );
    let r = t
        .post("/api/v1/jobs", &otto, job(json!({"group_id": 1, "guests": [502]})))
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    for g in [101, 501] {
        let r = t
            .post("/api/v1/jobs", &otto, job(json!({"group_id": 1, "guests": [g]})))
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{g}");
    }
}

#[test]
fn dashboard_paused_is_not_a_breach() {
    let t = T::new();
    let now = catalog::now();
    t.exec(&format!(
        "INSERT INTO snapshots (tenant, source, time, size, local, offsite) VALUES
           ('acme', 'vm-100', {old}, 1, 1, 0), ('globex', 'vm-200', {old}, 1, 1, 0);
         UPDATE groups SET paused_until = -1 WHERE id = 1;",
        old = now - 5 * 86400
    ));
    let d = web_api::dashboard::compute(&t.st.cat.conn(), None, 7, now).unwrap();
    let p = &d["protection"];
    assert_eq!(
        (p["sla_breach"].clone(), p["sla_paused"].clone()),
        (json!(1), json!(1)),
        "{p}"
    );
    let worst = p["worst"].as_array().unwrap();
    let s = |src: &str| worst.iter().find(|w| w["source"] == src).unwrap()["sla"].clone();
    assert_eq!((s("vm-100"), s("vm-200")), (json!("paused"), json!("breach")));
}

/// The jobs a job queued (`params.after_job`: retention / offsite / file index after a backup)
/// come with it, scoped like the job itself.
#[tokio::test]
async fn job_detail_lists_its_follow_ups() {
    let t = T::new();
    let (otto, tina) = (t.login("otto").await, t.login("tina").await);
    t.st.cat
        .conn()
        .execute_batch(
            "INSERT INTO jobs (id, kind, tenant, params, state, requested_by, created) VALUES
           (50, 'backup', 'acme', '{\"group_id\":1}', 'ok', 'scheduler', 10),
           (51, 'retention', 'acme', '{\"chain\":true,\"group_id\":1,\"after_job\":50}', 'ok', 'scheduler', 11),
           (52, 'file_index', 'acme', '{\"source\":\"vm-101\",\"time\":5,\"after_job\":50}', 'queued', 'scheduler', 11),
           (53, 'offsite', 'acme', '{\"chain\":true,\"after_job\":51}', 'queued', 'scheduler', 12);",
        )
        .unwrap();
    let r = t.get("/api/v1/jobs/50", &otto).await;
    let f: Vec<(i64, String)> = r.body["followups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| (x["id"].as_i64().unwrap(), x["kind"].as_str().unwrap().to_owned()))
        .collect();
    assert_eq!(f, vec![(51, "retention".into()), (52, "file_index".into())]);
    assert_eq!(t.get("/api/v1/jobs/51", &otto).await.body["followups"][0]["id"], 53);
    // the tenant's own users see them too (same scope as the job)
    assert_eq!(
        t.get("/api/v1/jobs/50", &tina).await.body["followups"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

/// The groups list says how the last backup went and when the next one starts.
#[tokio::test]
async fn groups_show_last_and_next_backup() {
    let t = T::new();
    let alice = t.login("alice").await;
    t.st.cat
        .conn()
        .execute_batch(
            "INSERT INTO jobs (id, kind, tenant, params, state, requested_by, created, started, finished) VALUES
               (60, 'backup', 'acme', '{\"group_id\":1}', 'failed', 'scheduler', 10, 11, 20),
               (61, 'backup', 'acme', '{\"group_id\":1}', 'ok', 'scheduler', 30, 31, 40),
               (62, 'retention', 'acme', '{\"group_id\":1,\"chain\":true}', 'ok', 'scheduler', 41, 41, 42);",
        )
        .unwrap();
    let list = t.get("/api/v1/groups", &alice).await.body;
    let g = |id: i64| list.as_array().unwrap().iter().find(|g| g["id"] == id).unwrap().clone();
    assert_eq!(
        (g(1)["last_backup"]["id"].clone(), g(1)["last_backup"]["state"].clone()),
        (json!(61), json!("ok"))
    );
    assert!(g(2)["last_backup"].is_null(), "never backed up");
    let next = g(1)["next_backup"].as_i64().unwrap();
    assert!(
        next > catalog::now() && next <= catalog::now() + 86400,
        "daily 22:00: within a day"
    );
}
