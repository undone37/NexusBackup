//! OIDC against a real Keycloak (tests/oidc-testbox/run.sh, rootless podman):
//! discovery, PKCE S256 enforced by the client, the Keycloak login form posted
//! like a browser would, RS256 ID tokens, group claims with full paths, JIT
//! accounts per mapping, and a user whose groups map to nothing.
//!
//! Without podman (or with NEXUS_OIDC_TESTBOX=skip) the test prints why and passes.

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use catalog::rusqlite::params;
use catalog::secret::TotpKey;
use catalog::Catalog;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::collections::HashMap;
use tower::ServiceExt;
use web_api::AppState;

const RUN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/oidc-testbox/run.sh");
const ISSUER: &str = "http://127.0.0.1:18080/realms/nexus";
const PW: &str = "correct horse battery";

fn testbox() -> bool {
    if std::env::var("NEXUS_OIDC_TESTBOX").as_deref() == Ok("skip")
        || std::process::Command::new("podman").arg("--version").output().is_err()
    {
        eprintln!("SKIP oidc_keycloak: podman not available (or NEXUS_OIDC_TESTBOX=skip)");
        return false;
    }
    let st = std::process::Command::new(RUN).arg("start").status().unwrap();
    assert!(st.success(), "tests/oidc-testbox/run.sh start failed");
    true
}

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

impl Resp {
    fn location(&self) -> String {
        self.headers[header::LOCATION].to_str().unwrap().to_owned()
    }
    fn cookie(&self, name: &str) -> Option<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|c| {
                c.strip_prefix(&format!("{name}="))?
                    .split(';')
                    .next()
                    .map(str::to_owned)
            })
            .filter(|v| !v.is_empty())
    }
}

async fn call(
    app: &axum::Router,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    csrf: Option<&str>,
    body: Option<Value>,
) -> Resp {
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "nexus.test");
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    if let Some(c) = csrf {
        b = b.header("x-csrf-token", c);
    }
    let req = match body {
        Some(v) => b
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(v.to_string()))
            .unwrap(),
        None => b.body(Body::empty()).unwrap(),
    };
    let res = app.clone().oneshot(req).await.unwrap();
    let (status, headers) = (res.status(), res.headers().clone());
    let raw = res.into_body().collect().await.unwrap().to_bytes();
    Resp {
        status,
        headers,
        body: serde_json::from_slice(&raw).unwrap_or(Value::Null),
    }
}

/// Cookies a browser would keep for Keycloak (name → value).
fn keep_cookies(jar: &mut HashMap<String, String>, h: &reqwest::header::HeaderMap) {
    for c in h
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
    {
        if let Some((k, v)) = c.split(';').next().and_then(|kv| kv.split_once('=')) {
            jar.insert(k.trim().to_owned(), v.to_owned());
        }
    }
}

fn cookie_header(jar: &HashMap<String, String>) -> String {
    jar.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// start → Keycloak login page → POST the form → callback. Returns the callback answer.
async fn login(app: &axum::Router, user: &str, password: &str) -> Resp {
    let r = call(
        app,
        "GET",
        "/api/v1/auth/oidc/start?next=/%23/dashboard",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::FOUND, "{:?}", r.body);
    let binder = r.cookie("nx_oidc").unwrap();
    let auth_url = r.location();
    assert!(
        auth_url.starts_with(&format!("{ISSUER}/protocol/openid-connect/auth?")),
        "{auth_url}"
    );
    assert!(auth_url.contains("code_challenge_method=S256"));
    let kc = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let mut jar = HashMap::new();
    let page = kc.get(&auth_url).send().await.unwrap();
    assert_eq!(page.status(), 200);
    keep_cookies(&mut jar, page.headers());
    let html = page.text().await.unwrap();
    let form = &html[html.find("kc-form-login").expect("Keycloak login form")..];
    let action = form
        .split("action=\"")
        .nth(1)
        .and_then(|a| a.split('"').next())
        .unwrap()
        .replace("&amp;", "&");
    let back = kc
        .post(&action)
        .header(reqwest::header::COOKIE, cookie_header(&jar))
        .form(&[("username", user), ("password", password), ("credentialId", "")])
        .send()
        .await
        .unwrap();
    assert_eq!(back.status(), 302, "Keycloak did not accept the login of {user}");
    let to = back.headers()[reqwest::header::LOCATION].to_str().unwrap().to_owned();
    let path = to
        .strip_prefix("https://nexus.test")
        .unwrap_or_else(|| panic!("redirect to {to}"))
        .to_owned();
    call(app, "GET", &path, Some(&format!("nx_oidc={binder}")), None, None).await
}

#[tokio::test]
async fn keycloak_login_jit_and_mapping() {
    if !testbox() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let cat = Catalog::open(&dir.path().join("catalog.db")).unwrap();
    cat.conn()
        .execute("INSERT INTO tenants (name) VALUES ('acme')", [])
        .unwrap();
    catalog::set_setting(&cat.conn(), "approvals_enabled", "false").unwrap();
    let secret = catalog::auth::new_totp_secret();
    let totp = TotpKey::generate();
    cat.conn()
        .execute(
            "INSERT INTO users (name, password_hash, totp_secret, role, created) VALUES ('admin', ?1, ?2, 'admin', 0)",
            params![
                catalog::auth::hash_password(PW).unwrap(),
                totp.encrypt("admin", &secret).unwrap()
            ],
        )
        .unwrap();
    let st = AppState::with_keys(cat, None, dir.path().to_owned(), totp, None);
    let app = web_api::router(st.clone());
    let r = call(
        &app,
        "POST",
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({"name": "admin", "password": PW, "totp": catalog::auth::totp_now(&secret).unwrap()})),
    )
    .await;
    let (cookie, csrf) = (
        format!("nx_session={}", r.cookie("nx_session").unwrap()),
        r.body["csrf"].as_str().unwrap().to_owned(),
    );
    let r = call(
        &app,
        "PUT",
        "/api/v1/settings/oidc",
        Some(&cookie),
        Some(&csrf),
        Some(json!({"enabled": true, "issuer": ISSUER, "client_id": "nexusbackup",
                    "client_secret": "nexus-testbox-client-secret", "scopes": ["openid", "profile", "email"],
                    "label": "Sign in with Keycloak",
                    "mappings": [{"group": "nexus-admins", "role": "admin", "tenants": []},
                                 {"group": "acme-users", "role": "tenant_user", "tenants": ["acme"]}]})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let r = call(
        &app,
        "POST",
        "/api/v1/settings/oidc/test",
        Some(&cookie),
        Some(&csrf),
        Some(json!({})),
    )
    .await;
    assert_eq!(r.body["discovery"], "ok", "{:?}", r.body);
    assert!(r.body["jwks"].as_str().unwrap().starts_with("ok: "), "{:?}", r.body);

    // admin by group (also in acme-users: the higher privilege wins), JIT-created
    let r = login(&app, "kc-alice", "alice-testbox-pw").await;
    assert_eq!(r.location(), "/#/dashboard");
    let s = format!("nx_session={}", r.cookie("nx_session").expect("session"));
    let me = call(&app, "GET", "/api/v1/auth/me", Some(&s), None, None).await;
    assert_eq!(me.body["user"]["name"], "kc-alice");
    assert_eq!(me.body["user"]["role"], "admin");
    assert_eq!(me.body["user"]["auth"], "oidc");
    // the session is a normal one: admin endpoints work with its CSRF token
    let csrf2 = me.body["csrf"].as_str().unwrap().to_owned();
    let r = call(&app, "GET", "/api/v1/settings/oidc", Some(&s), None, None).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = call(&app, "POST", "/api/v1/auth/logout", Some(&s), Some(&csrf2), None).await;
    assert_eq!(r.status, StatusCode::OK);

    // tenant user from acme-users
    let r = login(&app, "kc-tina", "tina-testbox-pw").await;
    let s = format!("nx_session={}", r.cookie("nx_session").expect("session"));
    let me = call(&app, "GET", "/api/v1/auth/me", Some(&s), None, None).await;
    assert_eq!(
        (me.body["user"]["role"].as_str(), me.body["user"]["tenant"].as_str()),
        (Some("tenant_user"), Some("acme"))
    );

    // groups without a mapping: denied, no account
    let r = login(&app, "kc-nobody", "nobody-testbox-pw").await;
    assert_eq!(r.location(), "/#/login?oidc_error=denied");
    assert!(r.cookie("nx_session").is_none());
    let n: i64 = st
        .cat
        .conn()
        .query_row("SELECT COUNT(*) FROM users WHERE auth = 'oidc'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 2);
    let subs: Vec<String> = st
        .cat
        .conn()
        .prepare("SELECT oidc_sub FROM users WHERE auth = 'oidc' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(subs.iter().all(|s| s.starts_with(&format!("{ISSUER}|"))), "{subs:?}");
    assert!(st.cat.verify_audit().is_ok());
}
