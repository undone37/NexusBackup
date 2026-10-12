//! Phase 14d web certificate: Settings → Certificate through the nexus-tls
//! request files (the helper runs in a thread here), and the TLS resolver that
//! serves an imported certificate without a restart while replication
//! connections keep the pinned identity certificate.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use catalog::rusqlite::params;
use catalog::secret::TotpKey;
use catalog::Catalog;
use http_body_util::BodyExt;
use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tower::ServiceExt;
use web_api::AppState;

const PW: &str = "correct horse battery";

fn pw_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| catalog::auth::hash_password(PW).unwrap())
}

fn ca() -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::default();
    p.distinguished_name.push(DnType::CommonName, "Example Root");
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    (p.self_signed(&key).unwrap(), key)
}

fn signed(key: &KeyPair, sans: &[&str], issuer: &(rcgen::Certificate, KeyPair)) -> rcgen::Certificate {
    let mut p = CertificateParams::default();
    p.distinguished_name.push(DnType::CommonName, sans[0]);
    for s in sans {
        p.subject_alt_names.push(match s.parse() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName((*s).try_into().unwrap()),
        });
    }
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    p.signed_by(key, &issuer.0, &issuer.1).unwrap()
}

struct T {
    app: Router,
    st: Arc<AppState>,
    secrets: std::collections::HashMap<String, String>,
    paths: webtls::Paths,
    stop: Arc<AtomicBool>,
    _dir: tempfile::TempDir,
}

impl Drop for T {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl T {
    fn new() -> T {
        let dir = tempfile::tempdir().unwrap();
        let cat = Catalog::open(&dir.path().join("catalog.db")).unwrap();
        let st = AppState::with_keys(cat, None, dir.path().into(), TotpKey::generate(), None);
        let mut secrets = std::collections::HashMap::new();
        for (n, role) in [("alice", "admin"), ("sam", "security_officer"), ("otto", "operator")] {
            let secret = catalog::auth::new_totp_secret();
            let enc = st.totp.encrypt(n, &secret).unwrap();
            st.cat
                .conn()
                .execute(
                    "INSERT INTO users (name, password_hash, totp_secret, role, created) VALUES (?1,?2,?3,?4,0)",
                    params![n, pw_hash(), enc, role],
                )
                .unwrap();
            secrets.insert(n.to_owned(), secret);
        }
        let paths = webtls::Paths {
            tls: dir.path().join("tls"),
            req: dir.path().join("req"),
        };
        std::fs::create_dir_all(&paths.tls).unwrap();
        std::fs::create_dir_all(&paths.req).unwrap();
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec!["backup.example.com".into()]).unwrap();
        p.distinguished_name.push(DnType::CommonName, "backup.example.com");
        std::fs::write(paths.identity(), p.self_signed(&key).unwrap().pem()).unwrap();
        st.tls.set(paths.clone()).unwrap();
        // nexus-tls, as nexus-tls.path would start it
        let stop = Arc::new(AtomicBool::new(false));
        std::thread::spawn({
            let (p, stop) = (paths.clone(), stop.clone());
            move || {
                while !stop.load(Ordering::Relaxed) {
                    webtls::process(&p).unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
            }
        });
        T {
            app: web_api::router(st.clone()),
            st,
            secrets,
            paths,
            stop,
            _dir: dir,
        }
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        s: Option<&(String, String)>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut b = Request::builder().method(method).uri(path);
        if let Some((cookie, csrf)) = s {
            b = b
                .header(header::COOKIE, format!("nx_session={cookie}"))
                .header("x-csrf-token", csrf);
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
        let raw = res.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&raw).unwrap_or(Value::Null))
    }

    async fn login(&self, name: &str) -> (String, String) {
        let code = catalog::auth::totp_now(&self.secrets[name]).unwrap();
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
        let cookie = res.headers()[header::SET_COOKIE].to_str().unwrap().to_owned();
        let cookie = cookie["nx_session=".len()..].split(';').next().unwrap().to_owned();
        let raw = res.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&raw).unwrap();
        (cookie, v["csrf"].as_str().unwrap().to_owned())
    }

    fn pending_key(&self) -> KeyPair {
        KeyPair::from_pem(&std::fs::read_to_string(self.paths.tls.join("pending/key.pem")).unwrap()).unwrap()
    }
}

#[tokio::test]
async fn csr_install_and_revert() {
    let t = T::new();
    let (alice, sam, otto) = (t.login("alice").await, t.login("sam").await, t.login("otto").await);
    let (s, v) = t.call(Method::GET, "/api/v1/certificate", Some(&sam), None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["active"], "self_signed");
    let identity = v["identity"]["sha256"].as_str().unwrap().to_owned();
    assert_eq!(v["pins"]["replication_identity"], identity);
    assert_eq!(
        t.call(Method::GET, "/api/v1/certificate", Some(&otto), None).await.0,
        StatusCode::FORBIDDEN
    );
    let csr = json!({"cn": "backup.example.com", "sans": ["198.51.100.5"]});
    let (s, _) = t
        .call(Method::POST, "/api/v1/certificate/csr", Some(&sam), Some(csr.clone()))
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "security officers only look");

    let (s, v) = t
        .call(Method::POST, "/api/v1/certificate/csr", Some(&alice), Some(csr))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["csr_pem"].as_str().unwrap().contains("CERTIFICATE REQUEST"));
    let (_, st) = t.call(Method::GET, "/api/v1/certificate", Some(&alice), None).await;
    assert_eq!(st["pending"]["sans"], json!(["backup.example.com", "198.51.100.5"]));
    let bad = json!({"cn": "bad name"});
    let (s, v) = t
        .call(Method::POST, "/api/v1/certificate/csr", Some(&alice), Some(bad))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert!(v["error"].as_str().unwrap().contains("DNS name"), "{v}");

    // the CA's answer: a chain without the IP is refused, with the reason
    let (root, key) = (ca(), t.pending_key());
    let short = signed(&key, &["backup.example.com"], &root);
    let (s, v) = t
        .call(
            Method::POST,
            "/api/v1/certificate/install",
            Some(&alice),
            Some(json!({"chain_pem": short.pem()})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(
        v["error"].as_str().unwrap().contains("does not cover 198.51.100.5"),
        "{v}"
    );
    let leaf = signed(&key, &["backup.example.com", "198.51.100.5"], &root);
    let chain = format!("{}{}", leaf.pem(), root.0.pem());
    let (s, v) = t
        .call(
            Method::POST,
            "/api/v1/certificate/install",
            Some(&alice),
            Some(json!({"chain_pem": chain})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["chain"].as_array().unwrap().len(), 2);
    let (_, st) = t.call(Method::GET, "/api/v1/certificate", Some(&alice), None).await;
    assert_eq!(st["active"], "imported");
    assert_eq!(st["chain"][0]["sha256"], webtls::fingerprint(leaf.der()));
    assert_eq!(st["identity"]["sha256"], identity, "the pinned identity is unchanged");
    assert!(st["pending"].is_null());
    let published: String =
        t.st.cat
            .conn()
            .query_row("SELECT value FROM settings WHERE key = 'tls_status'", [], |r| r.get(0))
            .unwrap();
    let published: Value = serde_json::from_str(&published).unwrap();
    assert_eq!(published["web"]["imported"], true);
    assert_eq!(published["web"]["sha256"], webtls::fingerprint(leaf.der()));

    let (s, v) = t
        .call(
            Method::POST,
            "/api/v1/certificate/revert",
            Some(&alice),
            Some(json!({})),
        )
        .await;
    assert_eq!((s, v["active"].as_str()), (StatusCode::OK, Some("self_signed")));
    let actions: Vec<String> = {
        let c = t.st.cat.conn();
        let mut q = c
            .prepare("SELECT action FROM audit WHERE action LIKE 'tls.%' ORDER BY seq")
            .unwrap();
        q.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect()
    };
    assert_eq!(actions, vec!["tls.csr", "tls.install", "tls.revert"]);
}

// ---------------------------------------------------------------- resolver

#[derive(Debug, Default)]
struct Record(Mutex<Option<Vec<u8>>>);

impl ServerCertVerifier for Record {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.0.lock().unwrap() = Some(end_entity.to_vec());
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// (leaf SHA-256, negotiated ALPN) of a handshake offering `alpn`.
async fn handshake(port: u16, alpn: &[u8]) -> (String, Option<Vec<u8>>) {
    let rec = Arc::new(Record::default());
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(rec.clone())
        .with_no_client_auth();
    cfg.alpn_protocols = vec![alpn.to_vec()];
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let s = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(ServerName::try_from("backup.example.com").unwrap(), tcp)
        .await
        .unwrap();
    let alpn = s.get_ref().1.alpn_protocol().map(|a| a.to_vec());
    let der = rec.0.lock().unwrap().clone().unwrap();
    (webtls::fingerprint(&der), alpn)
}

#[tokio::test(flavor = "multi_thread")]
async fn resolver_reloads_imported_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let web = dir.path().join("web.pem");
    let key = KeyPair::generate().unwrap();
    let identity = CertificateParams::new(vec!["backup.example.com".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let id_fp = webtls::fingerprint(identity.der());
    let tls = web_api::tls::Tls::with_web(
        vec![identity.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        Some(web.clone()),
        None,
    )
    .unwrap();
    let cat = Catalog::open_memory().unwrap();
    let app = web_api::router(AppState::new(cat, None, dir.path().into()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(web_api::tls::serve(listener, tls, app, std::future::pending()));

    assert_eq!(handshake(port, b"h2").await, (id_fp.clone(), Some(b"h2".to_vec())));
    // nexus-tls installs a chain: the next handshake gets it, HTTP/2 still negotiated
    let root = ca();
    let wkey = KeyPair::generate().unwrap();
    let leaf = signed(&wkey, &["backup.example.com"], &root);
    let write = |pem: String| webtls::write_atomic(&web, pem.as_bytes(), 0o600).unwrap();
    write(format!("{}{}{}", leaf.pem(), root.0.pem(), wkey.serialize_pem()));
    let leaf_fp = webtls::fingerprint(leaf.der());
    assert_eq!(handshake(port, b"h2").await, (leaf_fp.clone(), Some(b"h2".to_vec())));
    assert_eq!(handshake(port, b"http/1.1").await.0, leaf_fp);
    // replication enrollment keeps the pinned identity certificate
    let (fp, alpn) = handshake(port, repl_proto::ALPN_ENROLL).await;
    assert_eq!((fp, alpn.as_deref()), (id_fp.clone(), Some(repl_proto::ALPN_ENROLL)));
    // a broken file keeps the current certificate
    write(format!(
        "{}{}",
        leaf.pem(),
        KeyPair::generate().unwrap().serialize_pem()
    ));
    assert_eq!(handshake(port, b"h2").await.0, leaf_fp, "mismatched key: kept");
    // reverted to self-signed
    std::fs::remove_file(&web).unwrap();
    assert_eq!(handshake(port, b"h2").await.0, id_fp);
}
