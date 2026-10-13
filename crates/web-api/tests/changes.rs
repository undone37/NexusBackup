//! Phase 21a ransomware signals: anomaly flags on snapshots (listed, cleared
//! by a security officer), the snapshot diff job, change trends, ransom-note
//! patterns in the anomaly setting.

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
            ("vic", "viewer", None),
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
                     (2, 'globex', 'pve', 'pve-g', '{}'), (3, 'acme', 'nfs', 'share-a', '{}');
                   INSERT INTO policies (id, name, schedule, gfs, offsite) VALUES (1, 'daily', 'daily 22:00', '{"daily":7,"weekly":0,"monthly":0,"yearly":0}', 0);
                   INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES
                     (1, 'acme', 1, 1, 'g1', '[100,101,102]'), (2, 'globex', 2, 1, 'g2', '[200]'),
                     (3, 'acme', 3, 1, 'g3', '[]');"#,
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

    fn one<V: catalog::rusqlite::types::FromSql>(&self, sql: &str) -> V {
        self.st.cat.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }
}

fn seed(t: &T) {
    t.st.cat
        .conn()
        .execute_batch(
            r#"INSERT INTO snapshots (tenant, source, time, local, offsite) VALUES
                 ('acme', 'share-3', 1, 1, 0), ('acme', 'share-3', 2, 1, 0), ('globex', 'vm-200', 5, 1, 0);
               UPDATE snapshots SET anomaly = 'mass rename: 150 of 200 files deleted', anomaly_at = 3 WHERE time = 2;
               UPDATE snapshots SET anomaly = 'x', anomaly_at = 6 WHERE time = 5;
               INSERT INTO backup_stats (tenant, source, time, read, logical, new_chunks, new_plain, new_stored,
                   files_added, files_changed, files_deleted) VALUES
                 ('acme', 'share-3', 1, 1, 1, 1, 100, 50, NULL, NULL, NULL),
                 ('acme', 'share-3', 2, 1, 1, 1, 900, 880, 150, 2, 150),
                 ('globex', 'vm-200', 5, 1, 1, 1, 7, 7, NULL, NULL, NULL);"#,
        )
        .unwrap();
}

/// The flag shows in `GET /snapshots`; only a security officer of the tenant
/// clears it, with a note, audited; the reason stays.
#[tokio::test]
async fn anomaly_flag_listed_and_cleared_by_security_officer() {
    let t = T::new();
    seed(&t);
    let (alice, sam, tina) = (t.login("alice").await, t.login("sam").await, t.login("tina").await);
    let r = t.get("/api/v1/snapshots?tenant=acme", &tina).await;
    let s2 = r
        .body
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["time"] == 2)
        .unwrap()
        .clone();
    assert_eq!(s2["anomalous"], true);
    assert_eq!(s2["anomaly"]["reason"], "mass rename: 150 of 200 files deleted");
    let s1 = r
        .body
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["time"] == 1)
        .unwrap()
        .clone();
    assert_eq!((&s1["anomalous"], &s1["anomaly"]), (&json!(false), &Value::Null));

    let url = "/api/v1/snapshots/acme/share-3/2/anomaly/clear";
    for s in [&alice, &tina] {
        assert_eq!(
            t.post(url, s, json!({"note": "ok"})).await.status,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        t.post(url, &sam, json!({"note": " "})).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        t.post(
            "/api/v1/snapshots/acme/share-3/1/anomaly/clear",
            &sam,
            json!({"note": "x"})
        )
        .await
        .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        t.post(
            "/api/v1/snapshots/acme/share-3/9/anomaly/clear",
            &sam,
            json!({"note": "x"})
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    let r = t
        .post(
            url,
            &sam,
            json!({"note": "planned migration to .docx.v2, checked with the owner"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        t.post(url, &sam, json!({"note": "again"})).await.status,
        StatusCode::CONFLICT
    );
    let r = t.get("/api/v1/snapshots?tenant=acme&source=share-3", &alice).await;
    let s2 = r
        .body
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["time"] == 2)
        .unwrap()
        .clone();
    assert_eq!(s2["anomalous"], false);
    assert_eq!(s2["anomaly"]["cleared_by"], "sam");
    assert_eq!(s2["anomaly"]["reason"], "mass rename: 150 of 200 files deleted");
    let n: i64 = t.one(
        "SELECT COUNT(*) FROM audit WHERE action = 'snapshot.anomaly_clear' AND target = 'snapshot/acme/share-3/2' \
         AND json_extract(details, '$.note') LIKE 'planned migration%'",
    );
    assert_eq!(n, 1);
}

/// `POST /snapshots/diff` queues a read-only `snapshot_diff` job for known
/// local snapshots of a visible tenant; audited.
#[tokio::test]
async fn diff_queues_a_job() {
    let t = T::new();
    seed(&t);
    let (otto, tina, vic, sam) = (
        t.login("otto").await,
        t.login("tina").await,
        t.login("vic").await,
        t.login("sam").await,
    );
    let q = json!({"tenant": "acme", "source": "share-3", "time": 2, "base": 1, "change": "deleted", "offset": 200});
    for s in [&otto, &tina] {
        let r = t.post("/api/v1/snapshots/diff", s, q.clone()).await;
        assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
        let job = t.get(&format!("/api/v1/jobs/{}", r.body["id"]), s).await;
        assert_eq!(job.body["kind"], "snapshot_diff");
        assert_eq!(job.body["params"]["limit"], 200);
        assert_eq!(job.body["params"]["change"], "deleted");
    }
    for s in [&vic, &sam] {
        assert_eq!(
            t.post("/api/v1/snapshots/diff", s, q.clone()).await.status,
            StatusCode::FORBIDDEN
        );
    }
    let g = json!({"tenant": "globex", "source": "vm-200", "time": 5});
    assert_eq!(
        t.post("/api/v1/snapshots/diff", &tina, g).await.status,
        StatusCode::FORBIDDEN
    );
    for (bad, code) in [
        (
            json!({"tenant": "acme", "source": "share-3", "time": 2, "base": 2}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"tenant": "acme", "source": "share-3", "time": 2, "change": "x"}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"tenant": "acme", "source": "share-3", "time": 2, "limit": 0}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"tenant": "acme", "source": "../x", "time": 2}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"tenant": "acme", "source": "share-3", "time": 3}),
            StatusCode::NOT_FOUND,
        ),
        (
            json!({"tenant": "acme", "source": "share-3", "time": 2, "base": 0}),
            StatusCode::NOT_FOUND,
        ),
    ] {
        assert_eq!(
            t.post("/api/v1/snapshots/diff", &otto, bad.clone()).await.status,
            code,
            "{bad}"
        );
    }
    let n: i64 = t.one("SELECT COUNT(*) FROM audit WHERE action = 'snapshot.diff'");
    assert_eq!(n, 2);
}

/// Trends: the last runs of each source, oldest first, changed files summed,
/// anomalous runs marked; tenant-scoped.
#[tokio::test]
async fn trends_per_source() {
    let t = T::new();
    seed(&t);
    let (alice, tina) = (t.login("alice").await, t.login("tina").await);
    let r = t.get("/api/v1/stats/trends", &alice).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body.as_array().unwrap().len(), 2);
    let r = t.get("/api/v1/stats/trends", &tina).await;
    assert_eq!(
        r.body,
        json!([{"tenant": "acme", "source": "share-3", "runs": [
            {"time": 1, "new_plain": 100, "new_stored": 50, "files_changed": null, "anomalous": false},
            {"time": 2, "new_plain": 900, "new_stored": 880, "files_changed": 302, "anomalous": true}]}])
    );
    let r = t.get("/api/v1/stats/trends?tenant=globex", &tina).await;
    assert_eq!(r.body, json!([]));
    // only the last 30 runs
    for i in 10..50 {
        t.st.cat
            .conn()
            .execute(
                "INSERT INTO backup_stats (tenant, source, time, read, logical, new_chunks, new_plain, new_stored) \
                 VALUES ('acme', 'share-3', ?1, 1, 1, 1, 1, 1)",
                [i],
            )
            .unwrap();
    }
    let r = t.get("/api/v1/stats/trends?tenant=acme", &alice).await;
    let runs = r.body[0]["runs"].as_array().unwrap();
    assert_eq!((runs.len(), &runs[0]["time"]), (30, &json!(20)));
}

/// The anomaly setting takes extra ransom-note patterns: adding applies at
/// once, removing one weakens the detection (approval).
#[tokio::test]
async fn ransom_note_patterns_in_the_setting() {
    let t = T::new();
    let alice = t.login("alice").await;
    let base = json!({"enabled": true, "factor": 3.0, "history": 14, "floor_bytes": 1u64 << 30});
    let mut with = base.clone();
    with["ransom_notes"] = json!(["*.crypt-note"]);
    let r = t.put("/api/v1/settings/anomaly", &alice, with.clone()).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        t.get("/api/v1/settings/anomaly", &alice).await.body["ransom_notes"],
        json!(["*.crypt-note"])
    );
    let r = t.put("/api/v1/settings/anomaly", &alice, base).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    with["ransom_notes"] = json!(["a/b"]);
    assert_eq!(
        t.put("/api/v1/settings/anomaly", &alice, with).await.status,
        StatusCode::BAD_REQUEST
    );
}
