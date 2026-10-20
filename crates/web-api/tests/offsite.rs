//! Phase 17d offsite in the UI: `offsite_list` / `offsite_restore` jobs (RBAC,
//! only offsite-only snapshots), and attaching an offsite copy in two steps
//! (approval `tenant.attach_offsite`, then the recovery key from the requester,
//! sealed into the job and never stored in clear or audited).

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use catalog::rusqlite::params;
use catalog::secret::{SchedulerKey, TotpKey};
use catalog::Catalog;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use tower::ServiceExt;
use web_api::AppState;

const PW: &str = "correct horse battery";
/// BIP39 vector of 32 bytes 0x7f
const RK: &str = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful \
                  legal winner thank year wave sausage worth title";

fn pw_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| catalog::auth::hash_password(PW).unwrap())
}

struct T {
    app: Router,
    st: Arc<AppState>,
    sk: SchedulerKey,
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
}

impl T {
    fn new() -> T {
        let dir = tempfile::tempdir().unwrap();
        let cat = Catalog::open(&dir.path().join("catalog.db")).unwrap();
        let downloads = dir.path().join("downloads");
        std::fs::create_dir(&downloads).unwrap();
        let sk = SchedulerKey::generate();
        let secrets_pub = dir.path().join("secrets.pub");
        sk.write_public(&secrets_pub, None).unwrap();
        let st = AppState::with_keys(cat, None, downloads, TotpKey::generate(), Some(secrets_pub));
        st.cat
            .conn()
            .execute_batch(
                r#"INSERT INTO tenants (name, offsite) VALUES
                     ('acme', '{"remote": {"type": "sftp", "host": "box.example", "user": "u1", "key_file": "/etc/nexus/ssh/offsite", "host_key": "ssh-ed25519 AAA"}}'),
                     ('globex', '{}');
                   INSERT INTO snapshots (tenant, source, time, size, local, offsite, lock_until) VALUES
                     ('acme', 'vm-100', 1, 10, 0, 1, 0), ('acme', 'vm-100', 2, 10, 1, 1, 0),
                     ('acme', 'vm-100', 3, 10, 1, 0, 0), ('globex', 'vm-200', 1, 10, 0, 1, 0);"#,
            )
            .unwrap();
        let mut secrets = HashMap::new();
        for (n, role, tenant) in [
            ("alice", "admin", None),
            ("ada", "admin", None),
            ("sam", "security_officer", None),
            ("otto", "operator", None),
            ("tina", "tenant_user", Some("acme")),
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
            sk,
            secrets,
            _dir: dir,
        }
    }

    async fn call(&self, method: Method, path: &str, s: Option<&S>, body: Option<Value>) -> (R, Option<String>) {
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
        let body = serde_json::from_slice(&raw).unwrap_or(Value::Null);
        (R { status, body }, cookie)
    }

    async fn get(&self, path: &str, s: &S) -> R {
        self.call(Method::GET, path, Some(s), None).await.0
    }
    async fn post(&self, path: &str, s: &S, body: Value) -> R {
        self.call(Method::POST, path, Some(s), Some(body)).await.0
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
}

#[tokio::test]
async fn offsite_jobs_rbac_and_checks() {
    let t = T::new();
    let (alice, sam, otto, tina) = (
        t.login("alice").await,
        t.login("sam").await,
        t.login("otto").await,
        t.login("tina").await,
    );
    let job = |kind: &str, tenant: &str, p: Value| json!({"kind": kind, "tenant": tenant, "params": p});
    let fetch = |time: i64| job("offsite_restore", "acme", json!({"source": "vm-100", "time": time}));
    // admin, operator and the tenant's own user fetch back and list
    for s in [&alice, &otto, &tina] {
        assert_eq!(t.post("/api/v1/jobs", s, fetch(1)).await.status, StatusCode::ACCEPTED);
        assert_eq!(
            t.post("/api/v1/jobs", s, job("offsite_list", "acme", json!({})))
                .await
                .status,
            StatusCode::ACCEPTED
        );
    }
    assert_eq!(
        t.post("/api/v1/jobs", &sam, fetch(1)).await.status,
        StatusCode::FORBIDDEN
    );
    let other = job("offsite_restore", "globex", json!({"source": "vm-200", "time": 1}));
    assert_eq!(
        t.post("/api/v1/jobs", &tina, other.clone()).await.status,
        StatusCode::FORBIDDEN
    );
    // globex has no offsite target
    assert_eq!(
        t.post("/api/v1/jobs", &alice, other).await.status,
        StatusCode::BAD_REQUEST
    );
    // local copy exists / not offsite / unknown
    assert_eq!(
        t.post("/api/v1/jobs", &alice, fetch(2)).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        t.post("/api/v1/jobs", &alice, fetch(3)).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        t.post("/api/v1/jobs", &alice, fetch(9)).await.status,
        StatusCode::NOT_FOUND
    );
    let bad = job("offsite_restore", "acme", json!({"source": "../x", "time": 1}));
    assert_eq!(
        t.post("/api/v1/jobs", &alice, bad).await.status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn attach_offsite_copy_two_steps() {
    let t = T::new();
    let (alice, ada, sam, otto, tina) = (
        t.login("alice").await,
        t.login("ada").await,
        t.login("sam").await,
        t.login("otto").await,
        t.login("tina").await,
    );
    let sftp = json!({"remote": {"type": "sftp", "host": "box2.example", "port": 23, "user": "u2",
                                 "key_file": "/etc/nexus/ssh/offsite", "host_key": "ssh-ed25519 BBB"}});
    let req = json!({"name": "newco", "offsite": sftp});
    for s in [&otto, &tina] {
        assert_eq!(
            t.post("/api/v1/tenants/attach", s, req.clone()).await.status,
            StatusCode::FORBIDDEN
        );
    }
    let r = t
        .post(
            "/api/v1/tenants/attach",
            &alice,
            json!({"name": "acme", "offsite": sftp}),
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "existing tenant");
    let s3 = json!({"remote": {"type": "s3", "endpoint": "https://s3.example", "region": "eu-1", "bucket": "nx",
                               "access_key": "ak"}});
    let r = t
        .post("/api/v1/tenants/attach", &alice, json!({"name": "s3co", "offsite": s3}))
        .await;
    assert_eq!(
        r.status,
        StatusCode::BAD_REQUEST,
        "S3 needs its secret key: {:?}",
        r.body
    );
    let r = t
        .post("/api/v1/tenants/attach", &alice, json!({"name": "x", "offsite": {}}))
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    // the security officer requests, an admin approves
    let r = t.post("/api/v1/tenants/attach", &sam, req.clone()).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    assert_eq!(
        t.post("/api/v1/tenants/attach", &alice, req.clone()).await.status,
        StatusCode::CONFLICT,
        "one open request per tenant"
    );
    let run = format!("/api/v1/tenants/attach/{q}/run");
    let key = json!({"recovery_key": RK});
    assert_eq!(
        t.post(&run, &sam, key.clone()).await.status,
        StatusCode::CONFLICT,
        "pending"
    );
    assert_eq!(
        t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({}))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &ada, json!({})).await;
    assert_eq!((r.status, r.body["state"].as_str()), (StatusCode::OK, Some("approved")));

    // only the requester submits the key, in keyd's format
    assert_eq!(t.post(&run, &ada, key.clone()).await.status, StatusCode::FORBIDDEN);
    assert_eq!(t.post(&run, &otto, key.clone()).await.status, StatusCode::FORBIDDEN);
    let r = t.post(&run, &sam, json!({"recovery_key": "1234"})).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = t
        .post(
            &run,
            &sam,
            json!({"recovery_key": RK.replace(' ', "\n").to_uppercase()}),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let job = r.body["id"].as_i64().unwrap();
    assert_eq!(
        t.post(&run, &sam, key.clone()).await.status,
        StatusCode::CONFLICT,
        "already queued"
    );

    // sealed to the scheduler, bound to this request; nowhere in clear
    let (tenant, sealed): (String, String) =
        t.st.cat
            .conn()
            .query_row(
                "SELECT tenant, json_extract(params, '$.recovery_key') FROM jobs WHERE id = ?1",
                [job],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
    assert_eq!(tenant, "newco");
    let loc = catalog::secret::attach_key_location(q, "newco");
    assert_eq!(*t.sk.open(&loc, &sealed).unwrap(), RK);
    assert!(t
        .sk
        .open(&catalog::secret::attach_key_location(q + 1, "newco"), &sealed)
        .is_err());
    let r = t.get(&format!("/api/v1/jobs/{job}"), &sam).await;
    assert_eq!(r.body["params"]["recovery_key"], "<redacted>");
    for sql in [
        "SELECT COUNT(*) FROM audit WHERE details LIKE '%1a2b-3c4d%' OR details LIKE '%sealed:v1:%'",
        "SELECT COUNT(*) FROM quorum WHERE params LIKE '%1a2b-3c4d%'",
    ] {
        assert_eq!(t.one::<i64>(sql), 0, "{sql}");
    }
    assert_eq!(
        t.one::<i64>("SELECT COUNT(*) FROM audit WHERE action = 'tenant.attach_offsite.run'"),
        1
    );
}
