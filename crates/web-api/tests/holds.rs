//! Phase 15c legal holds: set by a security officer (immediate, audited),
//! released through approval, bulk holds, the snapshot list and filter,
//! `snapshot.delete` refused, the alert's "hold last good snapshot" target and
//! applying a replication advisory.

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
                   INSERT INTO snapshots (tenant, source, time, size, local, offsite, lock_until, origin) VALUES
                     ('acme', 'vm-100', 1, 10, 1, 0, 0, NULL), ('acme', 'vm-100', 2, 10, 1, 1, 0, NULL),
                     ('acme', 'vm-101', 2, 10, 1, 0, 0, NULL), ('acme', 'vm-101', 9, 10, 1, 0, 0, NULL),
                     ('globex', 'vm-200', 1, 10, 1, 0, 0, NULL), ('globex', 'vm-200', 5, 10, 1, 0, 0, 'prim');"#,
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
    async fn del(&self, path: &str, s: &S) -> R {
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

    fn exec(&self, sql: &str) {
        self.st.cat.conn().execute_batch(sql).unwrap();
    }

    fn one<V: catalog::rusqlite::types::FromSql>(&self, sql: &str) -> V {
        self.st.cat.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }

    fn audit_count(&self, action: &str) -> i64 {
        self.one(&format!("SELECT COUNT(*) FROM audit WHERE action = '{action}'"))
    }
}

const HOLD: &str = "/api/v1/snapshots/acme/vm-100/1/hold";

#[tokio::test]
async fn security_officer_sets_holds_release_needs_approval() {
    let t = T::new();
    let (alice, sam, otto, tina) = (
        t.login("alice").await,
        t.login("sam").await,
        t.login("otto").await,
        t.login("tina").await,
    );
    let body = json!({"reason": "litigation 2026-17"});
    // only the security officer sets holds
    for s in [&alice, &otto, &tina] {
        assert_eq!(t.post(HOLD, s, body.clone()).await.status, StatusCode::FORBIDDEN);
    }
    for bad in [
        json!({"reason": " "}),
        json!({"reason": "a\nb"}),
        json!({"reason": "x".repeat(501)}),
        json!({}),
    ] {
        let r = t.post(HOLD, &sam, bad.clone()).await;
        assert!(
            r.status.is_client_error() && r.status != StatusCode::FORBIDDEN,
            "{bad}: {:?}",
            r.body
        );
    }
    let r = t.post("/api/v1/snapshots/acme/vm-100/7/hold", &sam, body.clone()).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = t.post(HOLD, &sam, body.clone()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(t.post(HOLD, &sam, body.clone()).await.status, StatusCode::CONFLICT);
    assert_eq!(t.audit_count("snapshot.hold"), 1);

    // the list shows it to everyone who sees the snapshot; ?held=true filters
    let r = t.get("/api/v1/snapshots?tenant=acme&source=vm-100", &tina).await;
    let h = &r.body.as_array().unwrap().iter().find(|s| s["time"] == 1).unwrap()["hold"];
    assert_eq!(
        (h["state"].as_str(), h["held_by"].as_str()),
        (Some("active"), Some("sam"))
    );
    assert_eq!(h["reason"], "litigation 2026-17");
    let r = t.get("/api/v1/snapshots?held=true", &alice).await;
    assert_eq!(r.body.as_array().unwrap().len(), 1, "{:?}", r.body);

    // snapshot.delete is refused while held
    let r = t.del("/api/v1/snapshots/acme/vm-100/1", &alice).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
    assert!(r.body["error"].as_str().unwrap().contains("legal hold"));

    // release: requested by the officer or an admin, approved by another approver
    for s in [&otto, &tina] {
        assert_eq!(t.del(HOLD, s).await.status, StatusCode::FORBIDDEN);
    }
    assert_eq!(
        t.del("/api/v1/snapshots/acme/vm-100/2/hold", &sam).await.status,
        StatusCode::NOT_FOUND
    );
    let r = t.del(HOLD, &sam).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    assert_eq!(
        t.del(HOLD, &alice).await.status,
        StatusCode::CONFLICT,
        "one request at a time"
    );
    let r = t.get("/api/v1/snapshots?held=true", &alice).await;
    assert_eq!(r.body[0]["hold"]["release_quorum"], json!(q), "pending release shown");
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "not by the requester");
    let one: String = t.one("SELECT state FROM legal_holds");
    assert_eq!(one, "active", "still held until approved");
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &alice, json!({})).await;
    assert_eq!(
        (r.status, r.body["state"].as_str()),
        (StatusCode::OK, Some("executed")),
        "{:?}",
        r.body
    );
    let r = t.get("/api/v1/holds", &alice).await;
    let h = &r.body[0];
    assert_eq!(
        (
            h["state"].as_str(),
            h["released_by"].as_str(),
            h["approved_by"].as_str()
        ),
        (Some("released"), Some("sam"), Some("alice"))
    );
    assert_eq!(t.audit_count("snapshot.hold_release"), 1);
    let r = t.get("/api/v1/snapshots?held=true", &alice).await;
    assert_eq!(r.body, json!([]));
    // held again later: a new history row
    assert_eq!(t.post(HOLD, &sam, body).await.status, StatusCode::CREATED);
    assert_eq!(t.get("/api/v1/holds", &tina).await.body.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn bulk_hold_for_an_incident_and_tenant_scope() {
    let t = T::new();
    let (sam, tina) = (t.login("sam").await, t.login("tina").await);
    t.exec(
        "INSERT INTO legal_holds (tenant, source, time, state, reason, held_by, held_at)
         VALUES ('acme', 'vm-101', 9, 'active', 'earlier', 'sam', 1)",
    );
    let req = json!({"tenant": "acme", "from": 2, "to": 9, "reason": "ransomware incident"});
    assert_eq!(
        t.post("/api/v1/holds", &tina, req.clone()).await.status,
        StatusCode::FORBIDDEN
    );
    let mut bad = req.clone();
    bad["from"] = json!(10);
    assert_eq!(t.post("/api/v1/holds", &sam, bad).await.status, StatusCode::BAD_REQUEST);
    let r = t.post("/api/v1/holds", &sam, req).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        r.body["snapshots"],
        json!(["vm-100/2", "vm-101/2"]),
        "already held ones skipped"
    );
    let r = t
        .post(
            "/api/v1/holds",
            &sam,
            json!({"tenant": "globex", "source": "vm-200", "from": 0, "to": 100, "reason": "x"}),
        )
        .await;
    assert_eq!(r.body["held"], json!(2));
    assert_eq!(t.audit_count("snapshot.hold"), 2, "one entry per request");
    // the tenant user sees only their tenant's holds
    let r = t.get("/api/v1/holds", &tina).await;
    assert!(
        r.body.as_array().unwrap().iter().all(|h| h["tenant"] == "acme"),
        "{:?}",
        r.body
    );
    assert_eq!(r.body.as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn alerts_offer_the_snapshot_and_advisories_apply_with_one_click() {
    let t = T::new();
    let (sam, alice) = (t.login("sam").await, t.login("alice").await);
    t.exec(
        "INSERT INTO alerts (ts, severity, kind, key, tenant, message) VALUES
           (1, 'critical', 'anomaly', 'anomaly:acme/vm-101', 'acme',
            'change-rate anomaly on acme/vm-101: snapshot 12: 9 GiB new data; last snapshot before: vm-101/9'),
           (2, 'warning', 'legal_hold_advisory', 'legal_hold_advisory:globex/vm-200/5', 'globex', 'primary prim holds …'),
           (3, 'critical', 'anomaly', 'anomaly:acme/vm-102', 'acme', 'anomaly …; no earlier snapshot is kept');
         INSERT INTO legal_holds (tenant, source, time, state, reason, held_by, held_at, origin)
           VALUES ('globex', 'vm-200', 5, 'advisory', 'case 9', 'pat', 1, 'prim');",
    );
    let r = t.get("/api/v1/alerts", &alice).await;
    let snap = |id: i64| r.body.as_array().unwrap().iter().find(|a| a["id"] == id).unwrap()["snapshot"].clone();
    assert_eq!(snap(1), json!({"tenant": "acme", "source": "vm-101", "time": 9}));
    assert_eq!(snap(2), json!({"tenant": "globex", "source": "vm-200", "time": 5}));
    assert_eq!(snap(3), Value::Null);
    // the advisory is listed but not enforced
    let r = t.get("/api/v1/snapshots?held=true", &alice).await;
    assert_eq!(r.body[0]["hold"]["state"], "advisory");
    // applying it: the officer's hold, the advisory alert resolved
    let r = t
        .post(
            "/api/v1/snapshots/globex/vm-200/5/hold",
            &sam,
            json!({"reason": "case 9 (from prim)"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(
        (r.body["advisory_from"].as_str(), r.body["primary_held_by"].as_str()),
        (Some("prim"), Some("pat"))
    );
    let (state, by): (String, String) =
        t.st.cat
            .conn()
            .query_row("SELECT state, held_by FROM legal_holds", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
    assert_eq!((state.as_str(), by.as_str()), ("active", "sam"));
    let resolved: Option<i64> = t.one("SELECT resolved_at FROM alerts WHERE id = 2");
    assert!(resolved.is_some());
}
