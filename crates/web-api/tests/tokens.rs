//! Phase 14d API tokens: creation (re-authentication, limits), the scope/role
//! matrix, the allow-list (every category tokens must never reach), expiry,
//! disabled users, revocation and the audit actor.

use axum::body::Body;
use axum::extract::ConnectInfo;
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

enum Auth<'a> {
    Session(&'a S),
    Bearer(&'a str),
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
        let mut secrets = HashMap::new();
        st.cat
            .conn()
            .execute_batch("INSERT INTO tenants (name) VALUES ('acme'), ('globex');")
            .unwrap();
        for (n, role, tenant) in [
            ("alice", "admin", None),
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
        st.cat
            .conn()
            .execute_batch(
                r#"INSERT INTO sources (id, tenant, kind, name, config) VALUES (1, 'acme', 'pve', 'pve-a', '{}');
                   INSERT INTO policies (id, name, schedule, gfs, offsite) VALUES (1, 'daily', 'daily 22:00', '{"daily":7,"weekly":0,"monthly":0,"yearly":0}', 0);
                   INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES (1, 'acme', 1, 1, 'g1', '[100]');"#,
            )
            .unwrap();
        T {
            app: web_api::router(st.clone()),
            st,
            secrets,
            _dir: dir,
        }
    }

    async fn call(&self, method: Method, path: &str, auth: Option<Auth<'_>>, body: Option<Value>) -> R {
        let mut b = Request::builder()
            .method(method.clone())
            .uri(path)
            .header(header::HOST, "nexus.test");
        match auth {
            Some(Auth::Session(s)) => {
                b = b.header(header::COOKIE, format!("nx_session={}", s.cookie));
                if method != Method::GET {
                    b = b.header("x-csrf-token", &s.csrf);
                }
            }
            // no CSRF header: tokens do not need one
            Some(Auth::Bearer(t)) => b = b.header(header::AUTHORIZATION, format!("Bearer {t}")),
            None => {}
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

    fn code(&self, name: &str) -> String {
        self.st
            .cat
            .conn()
            .execute("UPDATE users SET totp_last_step = 0 WHERE name = ?1", [name])
            .unwrap();
        catalog::auth::totp_now(&self.secrets[name]).unwrap()
    }

    async fn login(&self, name: &str) -> S {
        let code = self.code(name);
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
        let cookie = res.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .strip_prefix("nx_session=")
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let raw = res.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&raw).unwrap();
        S {
            cookie,
            csrf: v["csrf"].as_str().unwrap().to_owned(),
        }
    }

    /// Creates a token as `name` (with re-authentication); returns the secret.
    async fn token(&self, name: &str, s: &S, token: &str, scope: &str) -> String {
        let body = json!({"name": token, "scope": scope, "days": 30,
                          "current_password": PW, "current_totp": self.code(name)});
        let r = self
            .call(Method::POST, "/api/v1/auth/tokens", Some(Auth::Session(s)), Some(body))
            .await;
        assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
        r.body["token"].as_str().unwrap().to_owned()
    }

    async fn bearer(&self, method: Method, path: &str, tok: &str, body: Option<Value>) -> R {
        self.call(method, path, Some(Auth::Bearer(tok)), body).await
    }

    /// GET with the token from a client address (the risk rule's networks).
    async fn bearer_from(&self, path: &str, tok: &str, ip: &str) -> StatusCode {
        let mut req = Request::builder()
            .method(Method::GET)
            .uri(path)
            .header(header::HOST, "nexus.test")
            .header(header::AUTHORIZATION, format!("Bearer {tok}"))
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(std::net::SocketAddr::new(ip.parse().unwrap(), 50000)));
        self.app.clone().oneshot(req).await.unwrap().status()
    }

    async fn dash(&self, tok: &str) -> StatusCode {
        self.bearer(Method::GET, "/api/v1/dashboard", tok, None).await.status
    }

    async fn del(&self, s: &S, id: i64) -> StatusCode {
        let p = format!("/api/v1/auth/tokens/{id}");
        self.call(Method::DELETE, &p, Some(Auth::Session(s)), None).await.status
    }

    fn one<V: catalog::rusqlite::types::FromSql>(&self, sql: &str) -> V {
        self.st.cat.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }
}

#[tokio::test]
async fn create_list_and_revoke() {
    let t = T::new();
    let (alice, otto, sam) = (t.login("alice").await, t.login("otto").await, t.login("sam").await);
    let post = |s, b: Value| t.call(Method::POST, "/api/v1/auth/tokens", Some(Auth::Session(s)), Some(b));
    // re-authentication required (local account)
    let r = post(&alice, json!({"name": "ci", "scope": "read", "days": 30})).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    let wrong =
        json!({"name": "ci", "scope": "read", "days": 30, "current_password": "nope", "current_totp": t.code("alice")});
    assert_eq!(post(&alice, wrong).await.status, StatusCode::FORBIDDEN);
    for (bad, what) in [
        (json!({"name": "ci", "scope": "read", "days": 366}), "days"),
        (json!({"name": "ci", "scope": "admin", "days": 30}), "scope"),
        (json!({"name": "c i", "scope": "read", "days": 30}), "name"),
    ] {
        let mut b = bad;
        b["current_password"] = json!(PW);
        b["current_totp"] = json!(t.code("alice"));
        assert_eq!(post(&alice, b).await.status, StatusCode::BAD_REQUEST, "{what}");
    }
    // a security officer's tokens are read-only
    let so_op =
        json!({"name": "x", "scope": "operator", "days": 30, "current_password": PW, "current_totp": t.code("sam")});
    assert_eq!(post(&sam, so_op).await.status, StatusCode::BAD_REQUEST);

    let tok = t.token("alice", &alice, "ci", "operator").await;
    assert!(tok.starts_with("nxt_") && tok.len() == 4 + 8 + 1 + 64, "{tok}");
    let other = t.token("otto", &otto, "mon", "read").await;
    // shown once: stored hashed, never listed
    let hash: String = t.one("SELECT hash FROM api_tokens WHERE name = 'ci'");
    assert!(!tok.contains(&hash) && hash.len() == 64);
    let r = t
        .call(Method::GET, "/api/v1/auth/tokens", Some(Auth::Session(&alice)), None)
        .await;
    assert_eq!(r.body.as_array().unwrap().len(), 1, "own tokens only: {:?}", r.body);
    let row = &r.body[0];
    assert_eq!(
        (row["name"].as_str(), row["scope"].as_str()),
        (Some("ci"), Some("operator"))
    );
    assert!(row.get("hash").is_none() && row.get("token").is_none());
    assert!(!r.body.to_string().contains(&hash));
    let all = t
        .call(
            Method::GET,
            "/api/v1/auth/tokens?all=true",
            Some(Auth::Session(&alice)),
            None,
        )
        .await;
    assert_eq!(all.body.as_array().unwrap().len(), 2);
    let r = t
        .call(
            Method::GET,
            "/api/v1/auth/tokens?all=true",
            Some(Auth::Session(&otto)),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // duplicate name
    let dup =
        json!({"name": "ci", "scope": "read", "days": 30, "current_password": PW, "current_totp": t.code("alice")});
    assert_eq!(post(&alice, dup).await.status, StatusCode::CONFLICT);

    // used: last_used / last_ip recorded
    assert_eq!(
        t.bearer(Method::GET, "/api/v1/dashboard", &tok, None).await.status,
        StatusCode::OK
    );
    let used: Option<i64> = t.one("SELECT last_used FROM api_tokens WHERE name = 'ci'");
    assert!(used.is_some());

    // revoke: someone else's is invisible to non-admins; admins may
    let alice_id = row["id"].as_i64().unwrap();
    let otto_id: i64 = t.one("SELECT id FROM api_tokens WHERE name = 'mon'");
    assert_eq!(t.del(&otto, alice_id).await, StatusCode::NOT_FOUND);
    assert_eq!(t.del(&alice, otto_id).await, StatusCode::OK);
    assert_eq!(
        t.bearer(Method::GET, "/api/v1/dashboard", &other, None).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(t.del(&alice, alice_id).await, StatusCode::OK);
    assert_eq!(
        t.bearer(Method::GET, "/api/v1/dashboard", &tok, None).await.status,
        StatusCode::UNAUTHORIZED
    );
    let n: i64 = t.one("SELECT COUNT(*) FROM audit WHERE action IN ('token.create', 'token.revoke')");
    assert_eq!(n, 4);
    let n: i64 = t.one(
        "SELECT COUNT(*) FROM audit WHERE action = 'token.revoke' AND actor = 'alice' AND target = 'token/otto/mon'",
    );
    assert_eq!(n, 1);
}

#[tokio::test]
async fn scope_matrix_and_allow_list() {
    let t = T::new();
    let (alice, tina_s) = (t.login("alice").await, t.login("tina").await);
    let op = t.token("alice", &alice, "ops", "operator").await;
    let read = t.token("alice", &alice, "mon", "read").await;
    let tina = t.token("tina", &tina_s, "t", "operator").await;

    // an admin's operator token acts as operator
    let me = t.bearer(Method::GET, "/api/v1/auth/me", &op, None).await;
    assert_eq!(me.body["user"]["role"], "operator", "{:?}", me.body);
    assert_eq!(
        t.bearer(Method::GET, "/api/v1/auth/me", &read, None).await.body["user"]["role"],
        "admin"
    );

    // operator work, without a CSRF header; audited as "alice via token ops"
    let backup = json!({"kind": "backup", "tenant": "acme", "params": {"group_id": 1}});
    let r = t.bearer(Method::POST, "/api/v1/jobs", &op, Some(backup.clone())).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let job = r.body["id"].as_i64().unwrap();
    let actor: String = t.one("SELECT actor FROM audit WHERE action = 'job.create' ORDER BY seq DESC LIMIT 1");
    assert_eq!(actor, "alice via token ops");
    let by: String = t.one("SELECT requested_by FROM jobs ORDER BY id DESC LIMIT 1");
    assert_eq!(by, "alice", "identity stays the user (four-eyes checks compare names)");
    let r = t
        .bearer(
            Method::POST,
            &format!("/api/v1/jobs/{job}/cancel"),
            &op,
            Some(json!({})),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    for (m, p) in [
        (Method::POST, "/api/v1/groups/1/pause"),
        (Method::POST, "/api/v1/groups/1/resume"),
    ] {
        let r = t.bearer(m, p, &op, Some(json!({}))).await;
        assert!(r.status.is_success(), "{p}: {:?}", r.body);
    }
    // downloads and mounts never through a token, even as a job
    let files = json!({"kind": "files_get", "tenant": "acme", "params": {}});
    assert_eq!(
        t.bearer(Method::POST, "/api/v1/jobs", &op, Some(files)).await.status,
        StatusCode::FORBIDDEN
    );
    // admin-only job kinds: the token is operator
    let enroll = json!({"kind": "agent_enroll", "tenant": "acme", "params": {}});
    assert_eq!(
        t.bearer(Method::POST, "/api/v1/jobs", &op, Some(enroll)).await.status,
        StatusCode::FORBIDDEN
    );

    // backup scope (Phase 43, PegaProx): read, and start backups, nothing else that writes
    let bk = t.token("alice", &alice, "pegaprox", "backup").await;
    let listed = t
        .call(Method::GET, "/api/v1/auth/tokens", Some(Auth::Session(&alice)), None)
        .await;
    assert!(
        listed
            .body
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["name"] == "pegaprox" && x["scope"] == "backup"),
        "{:?}",
        listed.body
    );
    assert_eq!(
        t.bearer(Method::GET, "/api/v1/snapshots", &bk, None).await.status,
        StatusCode::OK
    );
    let r = t.bearer(Method::POST, "/api/v1/jobs", &bk, Some(backup.clone())).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let started = r.body["id"].as_i64().unwrap();
    let restore = json!({"kind": "restore", "tenant": "acme", "params": {"source": "vm-100", "time": 1}});
    let r = t.bearer(Method::POST, "/api/v1/jobs", &bk, Some(restore)).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{:?}", r.body);
    assert!(
        r.body["error"].as_str().unwrap().contains("only start backups"),
        "{:?}",
        r.body
    );
    for p in [
        format!("/api/v1/jobs/{started}/cancel"),
        "/api/v1/groups/1/pause".into(),
        "/api/v1/alerts/1/ack".into(),
    ] {
        let r = t.bearer(Method::POST, &p, &bk, Some(json!({}))).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{p}: {:?}", r.body);
    }

    // read scope: GET only
    for p in [
        "/api/v1/dashboard",
        "/api/v1/jobs",
        "/api/v1/snapshots",
        "/api/v1/alerts",
        "/api/v1/audit",
    ] {
        assert_eq!(
            t.bearer(Method::GET, p, &read, None).await.status,
            StatusCode::OK,
            "{p}"
        );
    }
    assert_eq!(
        t.bearer(Method::POST, "/api/v1/jobs", &read, Some(backup)).await.status,
        StatusCode::FORBIDDEN
    );
    let r = t
        .bearer(
            Method::POST,
            &format!("/api/v1/jobs/{job}/cancel"),
            &read,
            Some(json!({})),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    // never, whatever the scope: approvals, settings, users, tokens, plugins,
    // certificate, downloads, replication keys, updates, SSH keys, tenants, logout
    let never: &[(Method, &str)] = &[
        (Method::POST, "/api/v1/quorum/1/approve"),
        (Method::POST, "/api/v1/quorum/1/reject"),
        (Method::GET, "/api/v1/settings/approvals"),
        (Method::PUT, "/api/v1/settings/approvals"),
        (Method::GET, "/api/v1/settings/oidc"),
        (Method::PUT, "/api/v1/settings/alerts"),
        (Method::GET, "/api/v1/users"),
        (Method::POST, "/api/v1/users"),
        (Method::PUT, "/api/v1/users/1"),
        (Method::GET, "/api/v1/auth/tokens"),
        (Method::POST, "/api/v1/auth/tokens"),
        (Method::DELETE, "/api/v1/auth/tokens/1"),
        (Method::POST, "/api/v1/plugins"),
        (Method::POST, "/api/v1/plugin-keys"),
        (Method::GET, "/api/v1/certificate"),
        (Method::POST, "/api/v1/certificate/install"),
        (Method::GET, "/api/v1/downloads/00ff"),
        (Method::POST, "/api/v1/replication/peers/x/export-keys"),
        (Method::POST, "/api/v1/replication/peers"),
        (Method::POST, "/api/v1/updates/apply"),
        (Method::POST, "/api/v1/ssh-keys/pve/rotate"),
        (Method::POST, "/api/v1/tenants"),
        (Method::DELETE, "/api/v1/snapshots/acme/vm-100/1"),
        (Method::POST, "/api/v1/alerts/1/resolve"),
        (Method::POST, "/api/v1/auth/logout"),
        (Method::POST, "/api/v1/auth/login"),
        // endpoints that do not exist (yet) are closed too
        (Method::POST, "/api/v1/console/unlock"),
        (Method::GET, "/health"),
    ];
    for tok in [&op, &read] {
        for (m, p) in never {
            let r = t.bearer(m.clone(), p, tok, Some(json!({}))).await;
            assert_eq!(r.status, StatusCode::FORBIDDEN, "{m} {p}: {:?}", r.body);
            assert!(r.body["error"].as_str().unwrap().contains("API tokens"), "{p}");
        }
    }

    // a tenant user's operator token stays a tenant user, in its tenant
    let r = t.bearer(Method::GET, "/api/v1/tenants", &tina, None).await;
    let names: Vec<&str> = r
        .body
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["acme"]);
    let b = json!({"kind": "backup", "tenant": "acme", "params": {"group_id": 1}});
    assert_eq!(
        t.bearer(Method::POST, "/api/v1/jobs", &tina, Some(b)).await.status,
        StatusCode::FORBIDDEN
    );

    // the session still works next to a token (and still needs its CSRF header)
    let r = t
        .call(Method::GET, "/api/v1/auth/tokens", Some(Auth::Session(&alice)), None)
        .await;
    assert_eq!(r.status, StatusCode::OK);
}

#[tokio::test]
async fn expired_wrong_and_disabled() {
    let t = T::new();
    let alice = t.login("alice").await;
    let tok = t.token("alice", &alice, "ci", "read").await;
    assert_eq!(t.dash(&tok).await, StatusCode::OK);
    // wrong secret, unknown prefix, malformed
    let (head, secret) = tok.rsplit_once('_').unwrap();
    let wrong = format!("{head}_{}", secret.replace('a', "b").replace('0', "1"));
    assert_eq!(t.dash(&wrong).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        t.dash(&format!("nxt_00000000_{secret}")).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(t.dash("nxt_garbage").await, StatusCode::UNAUTHORIZED);
    // expired
    t.st.cat
        .conn()
        .execute("UPDATE api_tokens SET expires = 1", [])
        .unwrap();
    assert_eq!(t.dash(&tok).await, StatusCode::UNAUTHORIZED);
    t.st.cat
        .conn()
        .execute("UPDATE api_tokens SET expires = 4102444800", [])
        .unwrap();
    assert_eq!(t.dash(&tok).await, StatusCode::OK);
    // disabled user, user pending activation (reset)
    t.st.cat
        .conn()
        .execute("UPDATE users SET disabled = 1 WHERE name = 'alice'", [])
        .unwrap();
    assert_eq!(t.dash(&tok).await, StatusCode::UNAUTHORIZED);
    t.st.cat
        .conn()
        .execute(
            "UPDATE users SET disabled = 0, activation_hash = 'x' WHERE name = 'alice'",
            [],
        )
        .unwrap();
    assert_eq!(t.dash(&tok).await, StatusCode::UNAUTHORIZED);
    t.st.cat
        .conn()
        .execute("UPDATE users SET activation_hash = NULL WHERE name = 'alice'", [])
        .unwrap();
    assert_eq!(t.dash(&tok).await, StatusCode::OK);
}

/// Phase 39 S2: a token used from a network it was not used from before marks the account; the
/// token's first network is the baseline; the rule can be switched off (gated, counts as weakening).
#[tokio::test]
async fn token_from_a_new_network() {
    let t = T::new();
    let alice = t.login("alice").await;
    let tok = t.token("alice", &alice, "auto", "read").await;
    let marks =
        || -> i64 { t.one("SELECT COUNT(*) FROM alerts WHERE kind = 'user_risk' AND key LIKE '%:token_network'") };
    assert_eq!(
        t.bearer_from("/api/v1/dashboard", &tok, "192.0.2.10").await,
        StatusCode::OK
    );
    assert_eq!(
        t.bearer_from("/api/v1/dashboard", &tok, "192.0.2.99").await,
        StatusCode::OK
    );
    assert_eq!(
        marks(),
        0,
        "the first network is the baseline, the same /24 is no new network"
    );
    assert_eq!(
        t.bearer_from("/api/v1/dashboard", &tok, "198.51.100.7").await,
        StatusCode::OK,
        "reading stays"
    );
    assert_eq!(marks(), 1);
    let (sev, msg): (String, String) =
        t.st.cat
            .conn()
            .query_row(
                "SELECT severity, message FROM alerts WHERE key LIKE '%:token_network'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
    assert_eq!(sev, "warning");
    assert!(msg.contains("API token auto used from 198.51.100.0/24"), "{msg}");
    let nets: i64 = t.one("SELECT COUNT(*) FROM token_networks");
    assert_eq!(nets, 2);

    // switched off (approvals off here: applied at once, audited as weakening): no new mark
    catalog::set_setting(&t.st.cat.conn(), "approvals_enabled", "false").unwrap();
    t.st.cat
        .conn()
        .execute("UPDATE users SET risk_since = NULL, risk_until = NULL", [])
        .unwrap();
    let r = t
        .call(
            Method::PUT,
            "/api/v1/settings/risk",
            Some(Auth::Session(&alice)),
            Some(json!({"thresholds": {"token_networks": false}})),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let d: String = t.one("SELECT details FROM audit WHERE action = 'settings.risk'");
    assert!(d.contains("\"loosens\":true"), "{d}");
    assert_eq!(
        t.bearer_from("/api/v1/dashboard", &tok, "203.0.113.5").await,
        StatusCode::OK
    );
    assert_eq!(marks(), 1);
    let g = t
        .call(Method::GET, "/api/v1/settings/risk", Some(Auth::Session(&alice)), None)
        .await;
    assert_eq!(g.body["thresholds"]["token_networks"], false);
    assert_eq!(g.body["defaults"]["delete_burst"], 10);
    // out of range: refused at once
    let r = t
        .call(
            Method::PUT,
            "/api/v1/settings/risk",
            Some(Auth::Session(&alice)),
            Some(json!({"thresholds": {"delete_burst": 1}})),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}
