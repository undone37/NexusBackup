//! Phase 27: agent updates (release store upload / list / installer downloads, tags,
//! rollouts with roles and states, the approved rollback, automatic-mode settings).

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
            ("tam", "tenant_admin", Some("acme")),
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


const A1: &str = "a000000000000001";
const A2: &str = "a000000000000002";
const W1: &str = "a000000000000003";

impl T {
    /// Release store below the test dir, signed with `signer`'s key.
    fn store(&self, signer: &agent_core::releases::testing::Signer) -> std::path::PathBuf {
        let root = self._dir.path().join("releases");
        let keys = root.join("keys");
        std::fs::create_dir_all(&keys).unwrap();
        std::fs::write(keys.join("release.pub"), signer.public_pem()).unwrap();
        let _ = self.st.agent_releases.set(web_api::agent_updates::ReleasePaths {
            image: root.join("image"),
            upload: root.join("upload"),
            keys,
        });
        root
    }

    async fn raw(&self, path: &str, s: &S, body: Vec<u8>) -> R {
        let req = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::HOST, "nexus.test")
            .header(header::COOKIE, format!("nx_session={}", s.cookie))
            .header("x-csrf-token", &s.csrf)
            .header(header::CONTENT_TYPE, "application/x-tar")
            .body(Body::from(body))
            .unwrap();
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let raw = res.into_body().collect().await.unwrap().to_bytes().to_vec();
        R {
            status,
            body: serde_json::from_slice(&raw).unwrap_or(Value::Null),
            cookie: None,
        }
    }

    async fn download(&self, url: &str, s: &S) -> (StatusCode, Vec<u8>) {
        let req = Request::builder()
            .method(Method::GET)
            .uri(url)
            .header(header::HOST, "nexus.test")
            .header(header::COOKIE, format!("nx_session={}", s.cookie))
            .body(Body::empty())
            .unwrap();
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        (status, res.into_body().collect().await.unwrap().to_bytes().to_vec())
    }
}

fn agents(t: &T) {
    t.exec(&format!(
        "INSERT INTO tenants (name) VALUES ('globex');
         INSERT INTO agents (id, tenant, name, host, port, cert_sha256, enrolled_at, version, os, caps) VALUES
           ('{A1}', 'acme', 'web1', 'h1', 7444, 'x', 1, '0.1.0', 'Debian GNU/Linux 13', '[\"update2\",\"arch=x86_64\",\"install=deb\"]'),
           ('{A2}', 'acme', 'web2', 'h2', 7444, 'x', 1, '0.2.0', 'Debian GNU/Linux 13', '[\"lz4\"]'),
           ('{W1}', 'globex', 'win1', 'h3', 7444, 'x', 1, '0.1.0', 'Windows Server 2022', '[\"update2\",\"install=msi\"]');"
    ));
}

fn tar_of(dir: &std::path::Path, prefix: &str) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    b.append_dir_all(prefix, dir).unwrap();
    b.into_inner().unwrap()
}

#[tokio::test]
async fn releases_upload_list_download_and_tags() {
    use agent_core::releases::testing::Signer;
    let t = T::new();
    agents(&t);
    let signer = Signer::new();
    let root = t.store(&signer);
    signer.write_release(
        &root.join("image"),
        "0.1.0",
        &[("linux-x86_64/nexus-agent", "binary", "linux", "x86_64", b"v1")],
    );
    let (alice, otto, tam, tina) = (
        t.login("alice").await,
        t.login("otto").await,
        t.login("tam").await,
        t.login("tina").await,
    );
    // every role sees the releases (the Add agent dialog offers installers)
    for s in [&alice, &otto, &tam, &tina] {
        let r = t.get("/api/v1/agent-releases", s).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.body["recommended"], "0.1.0");
    }
    // upload: admin only, verified against the pinned keys
    let src = tempfile::tempdir().unwrap();
    signer.write_release(
        src.path(),
        "0.2.0",
        &[
            ("linux-x86_64/nexus-agent", "binary", "linux", "x86_64", b"v2"),
            ("linux-x86_64/nexus-agent_0.2.0_amd64.deb", "deb", "linux", "x86_64", b"!<arch>v2"),
        ],
    );
    let body = tar_of(&src.path().join("0.2.0"), "0.2.0");
    for s in [&otto, &tam] {
        assert_eq!(t.raw("/api/v1/agent-releases", s, body.clone()).await.status, StatusCode::FORBIDDEN);
    }
    let r = t.raw("/api/v1/agent-releases", &alice, body.clone()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["version"], "0.2.0");
    assert_eq!(
        t.raw("/api/v1/agent-releases", &alice, body.clone()).await.status,
        StatusCode::CONFLICT,
        "already there"
    );
    // foreign key, tampered artifact, path tricks: refused, nothing left behind
    let other = tempfile::tempdir().unwrap();
    Signer::new().write_release(other.path(), "0.3.0", &[("a", "binary", "linux", "x86_64", b"x")]);
    let r = t.raw("/api/v1/agent-releases", &alice, tar_of(&other.path().join("0.3.0"), ".")).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    assert!(r.body["error"].as_str().unwrap().contains("manifest"));
    let d = signer.write_release(other.path(), "0.4.0", &[("a", "binary", "linux", "x86_64", b"x")]);
    std::fs::write(d.join("a"), b"y").unwrap();
    let r = t.raw("/api/v1/agent-releases", &alice, tar_of(&d, "0.4.0")).await;
    assert!(r.body["error"].as_str().unwrap().contains("SHA-256"), "{:?}", r.body);
    assert_eq!(
        t.raw("/api/v1/agent-releases", &alice, b"not a tar".to_vec()).await.status,
        StatusCode::BAD_REQUEST
    );
    let up: Vec<String> = std::fs::read_dir(root.join("upload"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(up, ["0.2.0"]);
    let l = t.get("/api/v1/agent-releases", &alice).await;
    assert_eq!(l.body["recommended"], "0.2.0");
    assert_eq!(l.body["releases"][0]["source"], "upload");
    assert_eq!(l.body["releases"][0]["artifacts"].as_array().unwrap().len(), 2);

    // installer download: token, then the existing /downloads route (own token only)
    let r = t
        .post(
            "/api/v1/agent-releases/0.2.0/download",
            &tam,
            json!({"artifact": "linux-x86_64/nexus-agent_0.2.0_amd64.deb"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["name"], "nexus-agent_0.2.0_amd64.deb");
    let url = r.body["url"].as_str().unwrap().to_owned();
    let (st, data) = t.download(&url.replace("/api/", "/api/v1/"), &tam).await;
    assert_eq!((st, data.as_slice()), (StatusCode::OK, &b"!<arch>v2"[..]));
    assert_eq!(t.download(&url.replace("/api/", "/api/v1/"), &alice).await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        t.post("/api/v1/agent-releases/0.2.0/download", &tina, json!({"artifact": "x"}))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.post("/api/v1/agent-releases/0.2.0/download", &tam, json!({"artifact": "x"}))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );

    // tags: tenant writers of the agent's tenant
    let tr = &t;
    let put = |s: &S, id: &str, tags: Value| {
        let (path, s) = (format!("/api/v1/agents/{id}/tags"), S { cookie: s.cookie.clone(), csrf: s.csrf.clone() });
        async move { tr.call(Method::PUT, &path, Some(&s), Some(json!({"tags": tags}))).await }
    };
    assert_eq!(put(&tam, A1, json!(["web", "eu"])).await.status, StatusCode::OK);
    assert_eq!(put(&tam, W1, json!(["x"])).await.status, StatusCode::FORBIDDEN);
    assert_eq!(put(&otto, A1, json!(["x"])).await.status, StatusCode::FORBIDDEN);
    assert_eq!(put(&alice, A1, json!(["Bad Tag"])).await.status, StatusCode::BAD_REQUEST);
    let a = t.get("/api/v1/agents", &alice).await;
    let web1 = a.body.as_array().unwrap().iter().find(|a| a["id"] == A1).unwrap().clone();
    assert_eq!(web1["tags"], json!(["eu", "web"]));
    assert_eq!((web1["protocol"].as_str(), web1["install"].as_str()), (Some("1.8"), None));

    // single-agent update job: the recommended release, never a downgrade
    let job = |id: &str, v: Option<&str>| {
        let mut p = json!({"agent_id": id});
        if let Some(v) = v {
            p["version"] = json!(v);
        }
        json!({"kind": "agent_update", "tenant": "acme", "params": p})
    };
    let r = t.post("/api/v1/jobs", &alice, job(A1, None)).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let params: String = t.one(&format!("SELECT params FROM jobs WHERE id = {}", r.body["id"]));
    assert_eq!(serde_json::from_str::<Value>(&params).unwrap()["version"], "0.2.0");
    assert_eq!(t.post("/api/v1/jobs", &alice, job(A2, None)).await.status, StatusCode::CONFLICT);
    assert_eq!(
        t.post("/api/v1/jobs", &alice, job(A1, Some("9.9.9"))).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(t.post("/api/v1/jobs", &otto, job(A1, None)).await.status, StatusCode::FORBIDDEN);

    // delete: uploaded only, not while a rollout needs it
    assert_eq!(
        t.call(Method::DELETE, "/api/v1/agent-releases/0.1.0", Some(&alice), None).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        t.call(Method::DELETE, "/api/v1/agent-releases/0.2.0", Some(&otto), None).await.status,
        StatusCode::FORBIDDEN
    );
    let r = t.post("/api/v1/agent-rollouts", &alice, json!({"version": "0.2.0"})).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(
        t.call(Method::DELETE, "/api/v1/agent-releases/0.2.0", Some(&alice), None).await.status,
        StatusCode::CONFLICT
    );
    let id = r.body["id"].as_i64().unwrap();
    t.post(&format!("/api/v1/agent-rollouts/{id}/cancel"), &alice, json!({})).await;
    assert_eq!(
        t.call(Method::DELETE, "/api/v1/agent-releases/0.2.0", Some(&alice), None).await.status,
        StatusCode::OK
    );
    let audit: i64 = t.one("SELECT COUNT(*) FROM audit WHERE action IN ('agent.release.upload','agent.release.delete','agent.tags')");
    assert_eq!(audit, 3);
}

#[tokio::test]
async fn rollouts_roles_states_and_approved_rollback() {
    use agent_core::releases::testing::Signer;
    let t = T::new();
    agents(&t);
    let signer = Signer::new();
    let root = t.store(&signer);
    for v in ["0.1.0", "0.2.0"] {
        signer.write_release(
            &root.join("image"),
            v,
            &[("linux-x86_64/nexus-agent", "binary", "linux", "x86_64", v.as_bytes())],
        );
    }
    let (alice, sam, otto, tam) = (
        t.login("alice").await,
        t.login("sam").await,
        t.login("otto").await,
        t.login("tam").await,
    );
    let spec = json!({"version": "0.2.0", "scope": {"tenant": "acme"}, "canary": 1, "windows": [{"days": ["Sat"], "from": "01:00", "to": "05:00"}]});
    for s in [&otto, &tam, &sam] {
        assert_eq!(t.post("/api/v1/agent-rollouts", s, spec.clone()).await.status, StatusCode::FORBIDDEN);
    }
    assert_eq!(t.get("/api/v1/agent-rollouts", &tam).await.status, StatusCode::FORBIDDEN);
    assert_eq!(
        t.post("/api/v1/agent-rollouts", &alice, json!({"version": "7.0.0"})).await.status,
        StatusCode::BAD_REQUEST,
        "not in the store"
    );
    assert_eq!(
        t.post("/api/v1/agent-rollouts", &alice, json!({"version": "0.2.0", "concurrency": 0}))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    let r = t.post("/api/v1/agent-rollouts", &alice, spec.clone()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let id = r.body["id"].as_i64().unwrap();
    assert_eq!(r.body["state"], "running");
    // web2 already runs 0.2.0
    assert_eq!(r.body["counts"], json!({"total": 2, "waiting": 1, "queued": 0, "running": 0, "ok": 0, "failed": 0, "skipped": 1, "cancelled": 0}));
    let d = t.get(&format!("/api/v1/agent-rollouts/{id}"), &otto).await;
    assert_eq!(d.status, StatusCode::OK);
    assert_eq!(d.body["items"].as_array().unwrap().len(), 2);
    assert_eq!(d.body["items"][0]["wave"], 0);
    // pause / resume / cancel
    let (tr, al) = (&t, &alice);
    let act = |a: &str| {
        let path = format!("/api/v1/agent-rollouts/{id}/{a}");
        async move { tr.post(&path, al, json!({})).await }
    };
    assert_eq!(act("resume").await.status, StatusCode::CONFLICT);
    assert_eq!(act("pause").await.body["state"], "paused");
    assert_eq!(
        t.post(&format!("/api/v1/agent-rollouts/{id}/pause"), &otto, json!({})).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(act("resume").await.body["state"], "running");
    let c = act("cancel").await;
    assert_eq!(c.body["state"], "cancelled");
    assert_eq!(c.body["counts"]["cancelled"], 1);
    assert_eq!(act("bogus").await.status, StatusCode::NOT_FOUND);

    // rollback: needs approval (quorum agent.rollback), runs once approved
    let rb = json!({"version": "0.1.0", "rollback": true, "scope": {"tenant": "acme"}});
    let r = t.post("/api/v1/agent-rollouts", &alice, rb.clone()).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let (q, rid) = (r.body["quorum_id"].as_i64().unwrap(), r.body["id"].as_i64().unwrap());
    let g = t.get(&format!("/api/v1/agent-rollouts/{rid}"), &alice).await;
    assert_eq!((g.body["state"].as_str(), g.body["quorum_id"].as_i64()), (Some("pending_approval"), Some(q)));
    assert_eq!(g.body["counts"]["waiting"], 1, "only web2 runs something newer");
    assert_eq!(
        t.post(&format!("/api/v1/quorum/{q}/approve"), &alice, json!({})).await.status,
        StatusCode::FORBIDDEN,
        "not the requester"
    );
    let a = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(a.status, StatusCode::OK, "{:?}", a.body);
    assert_eq!(a.body["state"], "executed");
    let g = t.get(&format!("/api/v1/agent-rollouts/{rid}"), &alice).await;
    assert_eq!(g.body["state"], "running");
    assert_eq!(
        t.post("/api/v1/agent-rollouts", &alice, json!({"version": "0.2.0", "rollback": true}))
            .await
            .status,
        StatusCode::BAD_REQUEST,
        "a rollback goes to an older release"
    );
    // approvals off: the rollback runs at once (still recorded)
    catalog::set_setting(&t.st.cat.conn(), "approvals_enabled", "false").unwrap();
    let r = t.post("/api/v1/agent-rollouts", &alice, rb).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["approvals"], "disabled");
    let rid = r.body["id"].as_i64().unwrap();
    assert_eq!(t.get(&format!("/api/v1/agent-rollouts/{rid}"), &alice).await.body["state"], "running");

    // automatic mode settings
    let put = |s, b: Value| t.call(Method::PUT, "/api/v1/agent-update-settings", Some(s), Some(b));
    let st = json!({"tenant": "acme", "mode": "automatic", "windows": [{"days": [], "from": "02:00", "to": "04:00"}], "canary": 2, "soak_minutes": 30});
    assert_eq!(put(&otto, st.clone()).await.status, StatusCode::FORBIDDEN);
    assert_eq!(put(&alice, json!({"tenant": "nope", "mode": "automatic"})).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(put(&alice, json!({"tenant": "acme", "mode": "often"})).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(put(&alice, json!({"tenant": "acme", "group_id": 999, "mode": "manual"})).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(put(&alice, st).await.status, StatusCode::OK);
    let l = t.get("/api/v1/agent-update-settings", &otto).await;
    assert_eq!(l.body[0]["mode"], "automatic");
    assert_eq!(l.body[0]["canary"], 2);
    let n: i64 = t.one("SELECT COUNT(*) FROM audit WHERE action LIKE 'agent.rollout.%' OR action = 'agent.update_settings'");
    assert_eq!(n, 7, "3 creates, pause, resume, cancel and the setting");
}
