//! Phase 21c passkeys: a software authenticator (ES256 / Ed25519 keys made
//! here, clientDataJSON and authenticator data built by hand) registers and
//! signs; counters, origin and relying party checks, the policy that refuses
//! TOTP for admins and security officers, activation with a passkey.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use catalog::rusqlite::params;
use catalog::secret::TotpKey;
use catalog::Catalog;
use http_body_util::BodyExt;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use tower::ServiceExt;
use web_api::AppState;

const PW: &str = "correct horse battery";
const HOST: &str = "backup.example.com";
const ORIGIN: &str = "https://backup.example.com:8443";

fn pw_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| catalog::auth::hash_password(PW).unwrap())
}

// ---------------------------------------------------------------- CBOR encoder

fn head(major: u8, n: u64) -> Vec<u8> {
    let m = major << 5;
    match n {
        0..=23 => vec![m | n as u8],
        24..=0xff => vec![m | 24, n as u8],
        0x100..=0xffff => [&[m | 25][..], &(n as u16).to_be_bytes()].concat(),
        _ => [&[m | 26][..], &(n as u32).to_be_bytes()].concat(),
    }
}
fn int(i: i64) -> Vec<u8> {
    if i >= 0 {
        head(0, i as u64)
    } else {
        head(1, (-1 - i) as u64)
    }
}
fn bytes(b: &[u8]) -> Vec<u8> {
    [head(2, b.len() as u64), b.to_vec()].concat()
}
fn text(s: &str) -> Vec<u8> {
    [head(3, s.len() as u64), s.as_bytes().to_vec()].concat()
}
fn map(kv: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<u8> {
    let mut out = head(5, kv.len() as u64);
    for (k, v) in kv {
        out.extend(k);
        out.extend(v);
    }
    out
}

// ---------------------------------------------------------------- software authenticator

enum Key {
    Es(EcdsaKeyPair),
    Ed(Ed25519KeyPair),
}

struct Authn {
    key: Key,
    cred: Vec<u8>,
    count: u32,
    /// counts up on every signature (false: always 0, as synced passkeys)
    counting: bool,
    origin: String,
    rp: Option<String>,
}

impl Authn {
    fn es256() -> Authn {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        Authn::new(Key::Es(kp), true)
    }
    fn ed25519() -> Authn {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Authn::new(Key::Ed(Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()), false)
    }
    fn new(key: Key, counting: bool) -> Authn {
        Authn {
            key,
            cred: rand::random::<[u8; 20]>().to_vec(),
            count: 0,
            counting,
            origin: ORIGIN.into(),
            rp: None,
        }
    }
    fn cose(&self) -> Vec<u8> {
        match &self.key {
            Key::Es(k) => {
                let p = k.public_key().as_ref();
                map(vec![
                    (int(1), int(2)),
                    (int(3), int(-7)),
                    (int(-1), int(1)),
                    (int(-2), bytes(&p[1..33])),
                    (int(-3), bytes(&p[33..65])),
                ])
            }
            Key::Ed(k) => map(vec![
                (int(1), int(1)),
                (int(3), int(-8)),
                (int(-1), int(6)),
                (int(-2), bytes(k.public_key().as_ref())),
            ]),
        }
    }
    fn client_data(&self, typ: &str, challenge: &Value) -> Vec<u8> {
        json!({"type": typ, "challenge": challenge, "origin": self.origin, "crossOrigin": false})
            .to_string()
            .into_bytes()
    }
    fn auth_data(&mut self, rp: &str, flags: u8) -> Vec<u8> {
        if self.counting {
            self.count += 1;
        }
        let rp = self.rp.clone().unwrap_or_else(|| rp.to_owned());
        [&Sha256::digest(rp.as_bytes())[..], &[flags], &self.count.to_be_bytes()].concat()
    }
    /// `navigator.credentials.create()` for these options.
    fn create(&mut self, opts: &Value) -> Value {
        let cdj = self.client_data("webauthn.create", &opts["challenge"]);
        let mut ad = self.auth_data(opts["rp"]["id"].as_str().unwrap(), 0x41);
        ad.extend([0u8; 16]);
        ad.extend((self.cred.len() as u16).to_be_bytes());
        ad.extend(&self.cred);
        ad.extend(self.cose());
        let att = map(vec![
            (text("fmt"), text("none")),
            (text("attStmt"), map(vec![])),
            (text("authData"), bytes(&ad)),
        ]);
        json!({"id": B64.encode(&self.cred), "clientDataJSON": B64.encode(cdj), "attestationObject": B64.encode(att)})
    }
    /// `navigator.credentials.get()` for these options.
    fn get(&mut self, opts: &Value) -> Value {
        let cdj = self.client_data("webauthn.get", &opts["challenge"]);
        let ad = self.auth_data(opts["rpId"].as_str().unwrap(), 0x01);
        let msg = [&ad[..], &Sha256::digest(&cdj)[..]].concat();
        let sig = match &self.key {
            Key::Es(k) => k.sign(&SystemRandom::new(), &msg).unwrap().as_ref().to_vec(),
            Key::Ed(k) => k.sign(&msg).as_ref().to_vec(),
        };
        json!({"id": B64.encode(&self.cred), "clientDataJSON": B64.encode(cdj),
               "authenticatorData": B64.encode(ad), "signature": B64.encode(sig)})
    }
}

// ---------------------------------------------------------------- harness

struct T {
    app: Router,
    st: Arc<AppState>,
    secrets: HashMap<String, String>,
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
    cookie: Option<String>,
}

impl T {
    fn new() -> T {
        let dir = tempfile::tempdir().unwrap();
        let cat = Catalog::open(&dir.path().join("catalog.db")).unwrap();
        let downloads = dir.path().join("downloads");
        std::fs::create_dir(&downloads).unwrap();
        let st = AppState::with_keys(cat, None, downloads, TotpKey::generate(), None);
        let mut t = T {
            app: web_api::router(st.clone()),
            st,
            secrets: HashMap::new(),
            _dir: dir,
        };
        for (n, role) in [("alice", "admin"), ("sam", "security_officer"), ("otto", "operator")] {
            let secret = catalog::auth::new_totp_secret();
            let enc = t.st.totp.encrypt(n, &secret).unwrap();
            t.st.cat
                .conn()
                .execute(
                    "INSERT INTO users (name, password_hash, totp_secret, role, created) VALUES (?1,?2,?3,?4,0)",
                    params![n, pw_hash(), enc, role],
                )
                .unwrap();
            t.secrets.insert(n.into(), secret);
        }
        t
    }

    async fn call_host(&self, method: Method, path: &str, s: Option<&S>, body: Option<Value>, host: &str) -> R {
        let mut b = Request::builder()
            .method(method.clone())
            .uri(path)
            .header(header::HOST, format!("{host}:8443"));
        if let Some(s) = s {
            b = b.header(header::COOKIE, format!("nx_session={}", s.cookie));
            if method != Method::GET {
                b = b.header("x-csrf-token", &s.csrf);
            }
        }
        let mut req = match body {
            Some(v) => b
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(v.to_string()))
                .unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new("192.0.2.10".parse().unwrap(), 50000)));
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
    async fn call(&self, method: Method, path: &str, s: Option<&S>, body: Option<Value>) -> R {
        self.call_host(method, path, s, body, HOST).await
    }
    async fn post(&self, path: &str, s: &S, body: Value) -> R {
        self.call(Method::POST, path, Some(s), Some(body)).await
    }
    async fn public(&self, path: &str, body: Value) -> R {
        self.call(Method::POST, path, None, Some(body)).await
    }

    fn code(&self, name: &str) -> String {
        self.exec(&format!("UPDATE users SET totp_last_step = 0 WHERE name = '{name}'"));
        catalog::auth::totp_now(&self.secrets[name]).unwrap()
    }
    fn exec(&self, sql: &str) {
        self.st.cat.conn().execute_batch(sql).unwrap();
    }
    fn one<V: catalog::rusqlite::types::FromSql>(&self, sql: &str) -> V {
        self.st.cat.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }

    fn session(r: &R) -> S {
        S {
            cookie: r.cookie.clone().unwrap(),
            csrf: r.body["csrf"].as_str().unwrap().to_owned(),
        }
    }
    async fn totp_login(&self, name: &str) -> R {
        let body = json!({"name": name, "password": PW, "totp": self.code(name)});
        self.public("/api/v1/auth/login", body).await
    }
    async fn login(&self, name: &str) -> S {
        let r = self.totp_login(name).await;
        assert_eq!(r.status, StatusCode::OK, "{name}: {:?}", r.body);
        T::session(&r)
    }
    async fn login_options(&self, name: &str) -> Value {
        let r = self.public("/api/v1/auth/login/passkey", json!({"name": name})).await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
        r.body
    }
    async fn passkey_login(&self, name: &str, a: &mut Authn) -> R {
        let opts = self.login_options(name).await;
        let body = json!({"name": name, "password": PW, "passkey": a.get(&opts)});
        self.public("/api/v1/auth/login", body).await
    }
    /// Registers `a` for the signed-in user (re-authenticated with TOTP or `with`).
    async fn register(&self, s: &S, name: &str, a: &mut Authn, with: Option<&mut Authn>) -> R {
        let second = match with {
            None => self.code(name),
            Some(k) => {
                let o = self.post("/api/v1/auth/passkeys/challenge", s, json!({})).await;
                assert_eq!(o.status, StatusCode::OK, "{:?}", o.body);
                k.get(&o.body).to_string()
            }
        };
        let o = self
            .post(
                "/api/v1/auth/passkeys/register/begin",
                s,
                json!({"current_password": PW, "current_totp": second}),
            )
            .await;
        if o.status != StatusCode::OK {
            return o;
        }
        let cred = a.create(&o.body);
        self.post(
            "/api/v1/auth/passkeys/register",
            s,
            json!({"name": "key", "credential": cred}),
        )
        .await
    }
}

// ---------------------------------------------------------------- tests

#[tokio::test]
async fn register_and_sign_in_with_a_passkey() {
    let t = T::new();
    let s = t.login("alice").await;
    let mut key = Authn::es256();
    let r = t.register(&s, "alice", &mut key, None).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let id = r.body["id"].as_i64().unwrap();
    let list = t.call(Method::GET, "/api/v1/auth/passkeys", Some(&s), None).await;
    assert_eq!(list.body["passkeys"][0]["alg"], "ES256");
    assert_eq!(list.body["passkeys"][0]["rp_id"], HOST);

    // the same authenticator again is refused (excludeCredentials in the browser)
    let again = t.register(&s, "alice", &mut key, None).await;
    assert_eq!(again.status, StatusCode::CONFLICT, "{:?}", again.body);

    let opts = t.login_options("alice").await;
    assert_eq!(opts["rpId"], HOST);
    assert_eq!(opts["allowCredentials"][0]["id"], B64.encode(&key.cred));
    let assertion = key.get(&opts);
    let body = json!({"name": "alice", "password": PW, "passkey": assertion});
    let r = t.public("/api/v1/auth/login", body.clone()).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        t.one::<String>(
            "SELECT json_extract(details, '$.method') FROM audit WHERE action = 'auth.login' ORDER BY seq DESC LIMIT 1"
        ),
        "passkey"
    );
    let r = t.public("/api/v1/auth/login", body).await;
    assert_eq!(
        r.status,
        StatusCode::UNAUTHORIZED,
        "replayed assertion (challenge used)"
    );

    // wrong password with a valid passkey
    let opts = t.login_options("alice").await;
    let r = t
        .public(
            "/api/v1/auth/login",
            json!({"name": "alice", "password": "wrong password!", "passkey": key.get(&opts)}),
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    // counter regression: a clone of the authenticator
    key.count = 0;
    let r = t.passkey_login("alice", &mut key).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "counter must increase");
    assert!(
        t.one::<i64>(
            "SELECT COUNT(*) FROM audit WHERE action = 'auth.login_failed' AND details LIKE '%cloned authenticator%'"
        ) == 1
    );
    key.count = 100;
    assert_eq!(t.passkey_login("alice", &mut key).await.status, StatusCode::OK);

    // another account's passkey does not sign in alice; TOTP still works without the policy
    let so = t.login("sam").await;
    let mut sams = Authn::ed25519();
    assert_eq!(t.register(&so, "sam", &mut sams, None).await.status, StatusCode::OK);
    let opts = t.login_options("alice").await;
    let r = t
        .public(
            "/api/v1/auth/login",
            json!({"name": "alice", "password": PW, "passkey": sams.get(&opts)}),
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // Ed25519 without a counter (always 0) signs in repeatedly
    for _ in 0..2 {
        assert_eq!(t.passkey_login("sam", &mut sams).await.status, StatusCode::OK);
    }
    assert_eq!(t.totp_login("alice").await.status, StatusCode::OK);

    // rename, remove (audited)
    let r = t
        .call(
            Method::PUT,
            &format!("/api/v1/auth/passkeys/{id}"),
            Some(&s),
            Some(json!({"name": "YubiKey"})),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let r = t
        .call(Method::DELETE, &format!("/api/v1/auth/passkeys/{id}"), Some(&so), None)
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "only the owner removes a passkey");
    let r = t
        .call(Method::DELETE, &format!("/api/v1/auth/passkeys/{id}"), Some(&s), None)
        .await;
    assert_eq!(r.status, StatusCode::OK);
    for a in ["passkey.register", "passkey.rename", "passkey.remove"] {
        assert!(
            t.one::<i64>(&format!("SELECT COUNT(*) FROM audit WHERE action = '{a}'")) >= 1,
            "{a}"
        );
    }
}

#[tokio::test]
async fn origin_and_relying_party_are_checked() {
    let t = T::new();
    let s = t.login("alice").await;
    let mut evil = Authn::es256();
    evil.origin = "https://evil.example.net".into();
    let r = t.register(&s, "alice", &mut evil, None).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    assert!(r.body["error"].as_str().unwrap().contains("origin"));
    let mut other_rp = Authn::es256();
    other_rp.rp = Some("evil.example.net".into());
    let r = t.register(&s, "alice", &mut other_rp, None).await;
    assert!(
        r.body["error"].as_str().unwrap().contains("relying party"),
        "{:?}",
        r.body
    );
    let mut http = Authn::es256();
    http.origin = format!("http://{HOST}");
    assert_eq!(
        t.register(&s, "alice", &mut http, None).await.status,
        StatusCode::BAD_REQUEST
    );

    let mut key = Authn::es256();
    assert_eq!(t.register(&s, "alice", &mut key, None).await.status, StatusCode::OK);
    key.origin = "https://evil.example.net".into();
    assert_eq!(
        t.passkey_login("alice", &mut key).await.status,
        StatusCode::UNAUTHORIZED
    );
    key.origin = ORIGIN.into();
    key.rp = Some("evil.example.net".into());
    assert_eq!(
        t.passkey_login("alice", &mut key).await.status,
        StatusCode::UNAUTHORIZED
    );
    key.rp = None;
    // served under another host name: the passkey (bound to HOST) is not offered and does not verify
    let opts = t
        .call_host(
            Method::POST,
            "/api/v1/auth/login/passkey",
            None,
            Some(json!({"name": "alice"})),
            "other.example.com",
        )
        .await
        .body;
    assert_eq!(opts["rpId"], "other.example.com");
    assert_ne!(opts["allowCredentials"][0]["id"], B64.encode(&key.cred));
    key.origin = "https://other.example.com".into();
    let body = json!({"name": "alice", "password": PW, "passkey": key.get(&opts)});
    let r = t
        .call_host(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(body),
            "other.example.com",
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    key.origin = ORIGIN.into();
    assert_eq!(t.passkey_login("alice", &mut key).await.status, StatusCode::OK);
    // an IP address is no relying party
    let r = t
        .call_host(
            Method::POST,
            "/api/v1/auth/login/passkey",
            None,
            Some(json!({"name": "alice"})),
            "192.0.2.1",
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // unknown names get a stable decoy credential (no enumeration)
    let a = t.login_options("nobody").await;
    let b = t.login_options("nobody").await;
    assert_eq!(a["allowCredentials"], b["allowCredentials"]);
    assert_eq!(a["allowCredentials"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn policy_requires_passkeys_for_admins_and_security_officers() {
    let t = T::new();
    let (s, so) = (t.login("alice").await, t.login("sam").await);
    let on = json!({"require_privileged": true, "rp_id": ""});
    let r = t
        .call(Method::PUT, "/api/v1/settings/passkeys", Some(&s), Some(on.clone()))
        .await;
    assert_eq!(
        r.status,
        StatusCode::CONFLICT,
        "would lock the acting admin out: {:?}",
        r.body
    );
    let (mut ak, mut sk) = (Authn::es256(), Authn::es256());
    assert_eq!(t.register(&s, "alice", &mut ak, None).await.status, StatusCode::OK);
    let r = t.call(Method::GET, "/api/v1/settings/passkeys", Some(&so), None).await;
    assert_eq!(r.body["without_passkey"], json!(["sam"]));
    assert_eq!(r.body["rp_id"], HOST);
    let r = t
        .call(Method::PUT, "/api/v1/settings/passkeys", Some(&so), Some(on.clone()))
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "admins change the setting");
    assert_eq!(t.register(&so, "sam", &mut sk, None).await.status, StatusCode::OK);
    // strengthening: at once
    let r = t
        .call(Method::PUT, "/api/v1/settings/passkeys", Some(&s), Some(on))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);

    let r = t.totp_login("alice").await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "TOTP refused for admins");
    assert!(r.body["error"].as_str().unwrap().contains("passkey"));
    assert_eq!(t.totp_login("sam").await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(t.totp_login("otto").await.status, StatusCode::OK, "operators keep TOTP");
    let r = t.passkey_login("alice", &mut ak).await;
    assert_eq!(r.status, StatusCode::OK);
    let s = T::session(&r);
    // re-authentication: TOTP refused, passkey accepted
    let mut second = Authn::ed25519();
    assert_eq!(
        t.register(&s, "alice", &mut second, None).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.register(&s, "alice", &mut second, Some(&mut ak)).await.status,
        StatusCode::OK
    );
    // the last passkey stays
    let ids: Vec<i64> = {
        let c = t.st.cat.conn();
        let mut q = c
            .prepare("SELECT id FROM passkeys WHERE user_id = (SELECT id FROM users WHERE name = 'alice')")
            .unwrap();
        q.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect()
    };
    let del = |id: i64| format!("/api/v1/auth/passkeys/{id}");
    assert_eq!(
        t.call(Method::DELETE, &del(ids[0]), Some(&s), None).await.status,
        StatusCode::OK
    );
    assert_eq!(
        t.call(Method::DELETE, &del(ids[1]), Some(&s), None).await.status,
        StatusCode::CONFLICT
    );
    // granting admin to an account without a passkey is refused
    let otto: i64 = t.one("SELECT id FROM users WHERE name = 'otto'");
    let r = t
        .call(
            Method::PUT,
            &format!("/api/v1/users/{otto}"),
            Some(&s),
            Some(json!({"role": "admin"})),
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);

    // weakening: approval by the security officer (who signs in with a passkey)
    let off = json!({"require_privileged": false, "rp_id": ""});
    let r = t
        .call(Method::PUT, "/api/v1/settings/passkeys", Some(&s), Some(off))
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    let so = T::session(&t.passkey_login("sam", &mut sk).await);
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &so, json!({})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(t.totp_login("alice").await.status, StatusCode::OK);
}

#[tokio::test]
async fn activation_registers_the_required_passkey() {
    let t = T::new();
    let mut ak = Authn::es256();
    let s = t.login("alice").await;
    assert_eq!(t.register(&s, "alice", &mut ak, None).await.status, StatusCode::OK);
    let on = json!({"require_privileged": true});
    let r = t
        .call(Method::PUT, "/api/v1/settings/passkeys", Some(&s), Some(on))
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let code = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    t.st.cat
        .conn()
        .execute(
            "INSERT INTO users (name, password_hash, totp_secret, role, created, activation_hash, activation_expires)
             VALUES ('nora', '-', '', 'admin', 0, ?1, ?2)",
            params![web_api::sha256_hex(code.as_bytes()), catalog::now() + 3600],
        )
        .unwrap();
    let r = t
        .public("/api/v1/auth/activate/begin", json!({"name": "nora", "code": code}))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["passkey_required"], true);
    let secret = r.body["totp_secret"].as_str().unwrap().to_owned();
    let pw = "a long new password";
    let r = t
        .public(
            "/api/v1/auth/activate/complete",
            json!({"name": "nora", "code": code, "password": pw, "totp": catalog::auth::totp_now(&secret).unwrap()}),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "passkey missing: {:?}", r.body);
    let opts = t
        .public("/api/v1/auth/activate/passkey", json!({"name": "nora", "code": code}))
        .await;
    assert_eq!(opts.status, StatusCode::OK);
    let mut nk = Authn::es256();
    let cred = nk.create(&opts.body);
    let r = t
        .public(
            "/api/v1/auth/activate/complete",
            json!({"name": "nora", "code": code, "password": pw, "totp": catalog::auth::totp_now(&secret).unwrap(),
                   "passkey": cred, "passkey_name": "Laptop"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let o = t.login_options("nora").await;
    let r = t
        .public(
            "/api/v1/auth/login",
            json!({"name": "nora", "password": pw, "passkey": nk.get(&o)}),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let q = format!("SELECT name FROM passkeys WHERE cred_id = '{}'", B64.encode(&nk.cred));
    assert_eq!(t.one::<String>(&q), "Laptop");
}
