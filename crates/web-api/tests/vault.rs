//! Phase 17c vault mode (preconditions, approval to enable, enforced approvals,
//! restores through `vault.restore`, refused local objects and peers, the
//! web-side half of switching it off) and 17f tenant deactivation (approval,
//! sessions, logins and tokens refused, backup jobs refused, dashboard state,
//! reactivation).

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use catalog::rusqlite::params;
use catalog::secret::TotpKey;
use catalog::Catalog;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
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
}

impl T {
    /// `tenant` is the one the tenant user `tina` belongs to.
    fn new(tenant: &str) -> T {
        let dir = tempfile::tempdir().unwrap();
        let cat = Catalog::open(&dir.path().join("catalog.db")).unwrap();
        let downloads = dir.path().join("downloads");
        std::fs::create_dir(&downloads).unwrap();
        let st = AppState::with_keys(cat, None, downloads, TotpKey::generate(), None);
        st.cat
            .conn()
            .execute("INSERT INTO tenants (name) VALUES (?1)", [tenant])
            .unwrap();
        let mut secrets = HashMap::new();
        for (n, role, t) in [
            ("alice", "admin", None),
            ("bob", "admin", None),
            ("sam", "security_officer", None),
            ("otto", "operator", None),
            ("tina", "tenant_user", Some(tenant)),
        ] {
            let secret = catalog::auth::new_totp_secret();
            let enc = st.totp.encrypt(n, &secret).unwrap();
            st.cat
                .conn()
                .execute(
                    "INSERT INTO users (name, password_hash, totp_secret, role, tenant, can_download, created)
                     VALUES (?1,?2,?3,?4,?5,1,0)",
                    params![n, pw_hash(), enc, role, t],
                )
                .unwrap();
            secrets.insert(n.to_owned(), secret);
        }
        st.cat
            .conn()
            .execute(
                "INSERT INTO snapshots (tenant, source, time, size, local, offsite, lock_until) VALUES (?1, 'vm-100', 1, 10, 1, 0, 0)",
                [tenant],
            )
            .unwrap();
        T {
            app: web_api::router(st.clone()),
            st,
            secrets,
            _dir: dir,
        }
    }

    async fn call(&self, method: Method, path: &str, s: Option<&S>, bearer: Option<&str>, body: Option<Value>) -> R {
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
        if let Some(t) = bearer {
            b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
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
        let mut body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
        if let Some(c) = cookie {
            body["_cookie"] = json!(c);
        }
        R { status, body }
    }

    async fn get(&self, path: &str, s: &S) -> R {
        self.call(Method::GET, path, Some(s), None, None).await
    }
    async fn post(&self, path: &str, s: &S, body: Value) -> R {
        self.call(Method::POST, path, Some(s), None, Some(body)).await
    }
    async fn put(&self, path: &str, s: &S, body: Value) -> R {
        self.call(Method::PUT, path, Some(s), None, Some(body)).await
    }

    async fn try_login(&self, name: &str) -> R {
        let code = catalog::auth::totp_now(&self.secrets[name]).unwrap();
        // one TOTP step per login: allow a second login in the same step
        self.exec(&format!("UPDATE users SET totp_last_step = 0 WHERE name = '{name}'"));
        self.call(
            Method::POST,
            "/api/v1/auth/login",
            None,
            None,
            Some(json!({"name": name, "password": PW, "totp": code})),
        )
        .await
    }

    async fn login(&self, name: &str) -> S {
        let r = self.try_login(name).await;
        assert_eq!(r.status, StatusCode::OK, "{name}: {:?}", r.body);
        S {
            cookie: r.body["_cookie"].as_str().unwrap().to_owned(),
            csrf: r.body["csrf"].as_str().unwrap().to_owned(),
        }
    }

    fn exec(&self, sql: &str) {
        self.st.cat.conn().execute_batch(sql).unwrap();
    }

    fn one<V: catalog::rusqlite::types::FromSql>(&self, sql: &str) -> V {
        self.st.cat.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }

    async fn dash(&self, token: &str) -> R {
        self.call(Method::GET, "/api/v1/dashboard", None, Some(token), None)
            .await
    }

    async fn approve(&self, s: &S, id: &Value) -> R {
        self.post(&format!("/api/v1/quorum/{id}/approve"), s, json!({})).await
    }
}

fn restore() -> Value {
    json!({"source": "vm-100", "time": 1, "node": "pve1", "target": 9100, "storage": "local"})
}

#[tokio::test]
async fn vault_mode_preconditions_enforcement_and_disable_request() {
    let t = T::new("rep");
    let (alice, bob, sam, tina) = (
        t.login("alice").await,
        t.login("bob").await,
        t.login("sam").await,
        t.login("tina").await,
    );
    let enable = json!({"enabled": true});
    let v = t.get("/api/v1/vault", &alice).await.body;
    assert_eq!((v["enabled"].clone(), v["ready"].clone()), (json!(false), json!(false)));
    // tenant users see the state only
    let v = t.get("/api/v1/vault", &tina).await.body;
    assert_eq!(v["enabled"], false);
    assert!(v.get("checks").is_none());
    assert_eq!(
        t.put("/api/v1/vault", &sam, enable.clone()).await.status,
        StatusCode::FORBIDDEN
    );

    // 1. not a secondary
    let r = t.put("/api/v1/vault", &alice, enable.clone()).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert!(
        r.body["error"].as_str().unwrap_or_default().contains("secondary"),
        "{:?}",
        r.body
    );
    t.exec(
        r#"INSERT INTO replication_sources (name, url, peer_id, cert_pin, tenants, schedule, state, created)
           VALUES ('prim', 'https://prim:8443', '0123456789abcdef', 'ab', '["rep"]', 'hourly', 'enrolled', 1);
           INSERT INTO tenants (name) VALUES ('local');"#,
    );
    // 2. a local tenant
    let r = t.put("/api/v1/vault", &alice, enable.clone()).await;
    assert!(
        r.body["error"].as_str().unwrap_or_default().contains("not replicated"),
        "{:?}",
        r.body
    );
    let v = t.get("/api/v1/vault", &alice).await.body;
    assert_eq!(v["checks"]["no_local_tenants"]["tenants"], json!(["local"]));
    assert_eq!(v["checks"]["secondary"]["ok"], true);
    t.exec(
        "DELETE FROM tenants WHERE name = 'local';
         INSERT INTO replication_peers (id, name, tenants, state, created, created_by)
           VALUES ('fedcba9876543210', 'dr', '[\"rep\"]', 'pending', 1, 'alice');",
    );
    // 3. a peer (this appliance would be a primary)
    let r = t.put("/api/v1/vault", &alice, enable.clone()).await;
    assert!(
        r.body["error"].as_str().unwrap_or_default().contains("primary"),
        "{:?}",
        r.body
    );
    t.exec("DELETE FROM replication_peers;");
    // 4. the web inbound rule is not restricted
    let r = t.put("/api/v1/vault", &alice, enable.clone()).await;
    assert!(
        r.body["error"].as_str().unwrap_or_default().contains("web inbound"),
        "{:?}",
        r.body
    );
    {
        let c = t.st.cat.conn();
        let mut i = catalog::firewall::load(&c).unwrap();
        i.services.insert(
            "web".into(),
            catalog::firewall::Rule {
                allow: vec!["10.0.0.0/8".into()],
                enabled: Some(true),
            },
        );
        catalog::firewall::store(&c, &i).unwrap();
    }
    assert_eq!(t.get("/api/v1/vault", &alice).await.body["ready"], true);

    // enabling needs approval by someone else
    let r = t.put("/api/v1/vault", &alice, enable.clone()).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].clone();
    assert_eq!(
        t.put("/api/v1/vault", &alice, enable.clone()).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(t.get("/api/v1/vault", &alice).await.body["pending_enable"], q);
    assert_eq!(t.approve(&alice, &q).await.status, StatusCode::FORBIDDEN);
    let r = t.approve(&bob, &q).await;
    assert_eq!(r.body["state"], "executed", "{:?}", r.body);
    let v = t.get("/api/v1/vault", &alice).await.body;
    assert_eq!((v["enabled"].clone(), v["by"].clone()), (json!(true), json!("alice")));
    assert_eq!(t.get("/api/v1/auth/me", &tina).await.body["vault_mode"], true);

    // approvals stay on
    let r = t
        .put("/api/v1/settings/approvals", &alice, json!({"enabled": false}))
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
    // a disable request from before vault mode cannot be approved either
    t.exec(
        "INSERT INTO quorum (action, params, requested_by, created, state)
         VALUES ('approvals.disable', '{\"enabled\":false}', 'alice', strftime('%s','now'), 'pending');",
    );
    let old: i64 = t.one("SELECT MAX(id) FROM quorum WHERE action = 'approvals.disable'");
    assert_eq!(t.approve(&bob, &json!(old)).await.status, StatusCode::CONFLICT);
    assert!(catalog::approvals_enabled(&t.st.cat.conn()).unwrap());

    // no new local objects, no peers, the web rule stays restricted
    for (path, body) in [
        ("/api/v1/tenants", json!({"name": "new"})),
        (
            "/api/v1/sources",
            json!({"tenant": "rep", "kind": "pve", "name": "x", "config": {}}),
        ),
        (
            "/api/v1/groups",
            json!({"tenant": "rep", "source_id": 1, "policy_id": 1, "name": "g", "guests": []}),
        ),
        ("/api/v1/replication/peers", json!({"name": "p", "tenants": ["rep"]})),
    ] {
        let r = t.post(path, &alice, body).await;
        assert_eq!(r.status, StatusCode::CONFLICT, "{path}: {:?}", r.body);
        assert!(
            r.body["error"].as_str().unwrap_or_default().contains("vault"),
            "{path}: {:?}",
            r.body
        );
    }
    let r = t
        .put("/api/v1/firewall/inbound/web", &alice, json!({"allow": []}))
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);

    // restores and downloads become requests; browsing stays direct
    let jobs = |t: &T| -> i64 { t.one("SELECT COUNT(*) FROM jobs") };
    let r = t
        .post(
            "/api/v1/jobs",
            &tina,
            json!({"kind": "restore", "tenant": "rep", "params": restore()}),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    assert_eq!(r.body["vault"], true);
    let rq = r.body["quorum_id"].clone();
    let r = t
        .post(
            "/api/v1/jobs",
            &tina,
            json!({"kind": "files_get", "tenant": "rep",
                   "params": {"source": "vm-100", "time": 1, "paths": ["/etc"], "format": "tar"}}),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    assert!(r.body.get("download_token").is_none());
    let dq = r.body["quorum_id"].clone();
    // the approver does not see the download token
    let list = t.get("/api/v1/quorum?state=pending", &sam).await.body;
    let shown = list.as_array().unwrap().iter().find(|q| q["id"] == dq).unwrap().clone();
    assert_eq!(shown["params"]["jobs"][0]["params"]["download_token"], "<redacted>");
    let r = t
        .post(
            "/api/v1/restores",
            &tina,
            json!({"tenant": "rep", "items": [{"source": "vm-100", "time": 1}], "node": "pve1",
                   "storage": "local", "target_base": 9200}),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    assert!(r.body["quorum_id"].is_i64());
    assert_eq!(jobs(&t), 0);
    let r = t
        .post(
            "/api/v1/jobs",
            &tina,
            json!({"kind": "files_list", "tenant": "rep", "params": {"source": "vm-100", "time": 1, "path": "/"}}),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    assert!(r.body["id"].is_i64());
    assert_eq!(jobs(&t), 1);
    // on approval the web-api queues the job as the requester
    let r = t.approve(&sam, &rq).await;
    assert_eq!(r.body["state"], "executed", "{:?}", r.body);
    let id = r.body["job_ids"][0].as_i64().unwrap();
    let (kind, by): (String, String) =
        t.st.cat
            .conn()
            .query_row("SELECT kind, requested_by FROM jobs WHERE id = ?1", [id], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
    assert_eq!((kind.as_str(), by.as_str()), ("restore", "tina"));
    let r = t.approve(&sam, &dq).await;
    let id = r.body["job_ids"][0].as_i64().unwrap();
    let job = t.get(&format!("/api/v1/jobs/{id}"), &tina).await.body;
    assert_eq!(job["params"]["download_token"].as_str().unwrap().len(), 64);
    assert_eq!(job["requested_by"], "tina");

    // switching off: approval, then the console (never executed by the web-api)
    let off = json!({"enabled": false});
    let r = t.put("/api/v1/vault", &alice, off.clone()).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let q = r.body["quorum_id"].clone();
    assert_eq!(t.get("/api/v1/vault", &alice).await.body["pending_disable"], q);
    let r = t.approve(&sam, &q).await;
    assert_eq!(r.body["state"], "approved", "{:?}", r.body);
    let v = t.get("/api/v1/vault", &alice).await.body;
    assert_eq!((v["enabled"].clone(), v["approved_disable"].clone()), (json!(true), q));
    let r = t.put("/api/v1/vault", &alice, off).await;
    assert!(
        r.body["error"].as_str().unwrap_or_default().contains("console"),
        "{:?}",
        r.body
    );
    assert!(t.st.cat.verify_audit().is_ok());
}

#[tokio::test]
async fn tenant_deactivation_blocks_accounts_and_backups() {
    let t = T::new("acme");
    t.exec(
        r#"INSERT INTO tenants (name) VALUES ('globex');
           INSERT INTO sources (id, tenant, kind, name, config) VALUES (1, 'acme', 'pve', 'pve-a', '{}');
           INSERT INTO policies (id, name, schedule, gfs, offsite) VALUES (1, 'daily', 'daily 22:00', '{"daily":7,"weekly":0,"monthly":0,"yearly":0}', 0);
           INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES (1, 'acme', 1, 1, 'g1', '[100]');"#,
    );
    // an API token of the tenant user
    let secret = "s".repeat(40);
    let hash: String = Sha256::digest(secret.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    t.st.cat
        .conn()
        .execute(
            "INSERT INTO api_tokens (user_id, name, prefix, hash, scope, expires, created)
             VALUES ((SELECT id FROM users WHERE name = 'tina'), 'ci', 'abcdef01', ?1, 'read', 4102444800, 1)",
            [hash],
        )
        .unwrap();
    let token = format!("nxt_abcdef01_{secret}");
    assert_eq!(t.dash(&token).await.status, StatusCode::OK);
    let (alice, sam, otto, tina) = (
        t.login("alice").await,
        t.login("sam").await,
        t.login("otto").await,
        t.login("tina").await,
    );
    let reason = json!({"reason": "contract paused"});
    assert_eq!(
        t.post("/api/v1/tenants/acme/deactivate", &otto, reason.clone())
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.post("/api/v1/tenants/acme/deactivate", &tina, reason.clone())
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.post("/api/v1/tenants/acme/deactivate", &alice, json!({"reason": " "}))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        t.post("/api/v1/tenants/nope/deactivate", &alice, reason.clone())
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    // approvals on (default): a request
    let r = t.post("/api/v1/tenants/acme/deactivate", &alice, reason.clone()).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].clone();
    assert_eq!(
        t.post("/api/v1/tenants/acme/deactivate", &alice, reason.clone())
            .await
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(t.get("/api/v1/dashboard", &tina).await.status, StatusCode::OK);
    let r = t.approve(&sam, &q).await;
    assert_eq!(r.body["state"], "executed", "{:?}", r.body);

    // the tenant's session, login and token are refused
    assert_eq!(t.get("/api/v1/dashboard", &tina).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(t.try_login("tina").await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(t.dash(&token).await.status, StatusCode::UNAUTHORIZED);
    let tenants = t.get("/api/v1/tenants", &alice).await.body;
    let acme = tenants
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["name"] == "acme")
        .unwrap()
        .clone();
    assert_eq!(
        (
            acme["disabled"].clone(),
            acme["disabled_by"].clone(),
            acme["disabled_reason"].clone()
        ),
        (json!(true), json!("alice"), json!("contract paused"))
    );
    assert_eq!(tenants[1]["disabled"], false);
    // no backups; restores of its snapshots still work for admins
    let r = t
        .post(
            "/api/v1/jobs",
            &alice,
            json!({"kind": "backup", "tenant": "acme", "params": {"group_id": 1}}),
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
    let r = t
        .post(
            "/api/v1/jobs",
            &alice,
            json!({"kind": "restore", "tenant": "acme", "params": restore()}),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    // dashboard: deactivated, not an RPO breach
    let d = t.get("/api/v1/dashboard", &alice).await.body;
    let p = &d["protection"];
    assert_eq!(p["deactivated_tenants"], json!(["acme"]), "{d}");
    assert_eq!(
        (p["sla_breach"].clone(), p["sla_deactivated"].clone()),
        (json!(0), json!(1))
    );
    assert_eq!(
        t.post("/api/v1/tenants/acme/deactivate", &alice, reason.clone())
            .await
            .status,
        StatusCode::CONFLICT
    );

    // reactivation: direct, audited
    assert_eq!(
        t.post("/api/v1/tenants/acme/reactivate", &otto, json!({})).await.status,
        StatusCode::FORBIDDEN
    );
    let r = t.post("/api/v1/tenants/acme/reactivate", &alice, json!({})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        t.post("/api/v1/tenants/acme/reactivate", &alice, json!({}))
            .await
            .status,
        StatusCode::CONFLICT
    );
    t.login("tina").await;
    assert_eq!(t.dash(&token).await.status, StatusCode::OK);
    let n: i64 = t.one("SELECT COUNT(*) FROM audit WHERE action = 'tenant.enable'");
    assert_eq!(n, 1);
    let n: i64 = t.one("SELECT COUNT(*) FROM audit WHERE action = 'tenant.disable'");
    assert_eq!(n, 1);
    assert!(t.st.cat.verify_audit().is_ok());
}
