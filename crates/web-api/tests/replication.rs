//! Appliance replication end to end in one process (docs/replication.md): a
//! primary (catalog, keyd, chunk stores, nexus-replicad, the real TLS server of
//! nexus-web-api with ALPN-selected mTLS, the scheduler for key exports) and a
//! secondary (its own keyd and store, the nexus-replica client library).
//! Management calls go through the router (session cookies created directly).

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use catalog::rusqlite::params;
use catalog::schedule::{Action, Bandwidth, RateWindow};
use catalog::secret::{SchedulerKey, TotpKey};
use catalog::Catalog;
use chunkstore::{Index, Keyring, Options, Store};
use http_body_util::BodyExt;
use repl_proto::client::{self, EnrollParams, KeysMissing, SyncParams, VerifyFailed};
use repl_proto::http::{client_config, Conn, Target};
use repl_proto::replicad::Replicad;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;
use web_api::replication::ReplPaths;
use web_api::AppState;

const DAY: u64 = 86400;
const CHUNK: usize = 64 << 10;

fn me() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

/// keyd serving `dir` on `dir/keyd.sock` for this uid (thread runs forever).
fn keyd(dir: &Path) -> PathBuf {
    keyd::init(dir).unwrap();
    let sock = dir.join("keyd.sock");
    let l = UnixListener::bind(&sock).unwrap();
    let d = dir.to_owned();
    std::thread::spawn(move || keyd::serve(l, &d, me()));
    sock
}

fn self_signed() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>, String) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let fp = repl_proto::sha256_hex(cert.der());
    (
        vec![cert.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        fp,
    )
}

fn image(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

struct Sess {
    cookie: String,
    csrf: String,
}

struct Primary {
    dir: tempfile::TempDir,
    rt: tokio::runtime::Runtime,
    app: axum::Router,
    st: Arc<AppState>,
    keyd_sock: PathBuf,
    store_base: PathBuf,
    port: u16,
    pin: String,
    sched: std::cell::RefCell<scheduler::Scheduler>,
    admin: Sess,
    so: Sess,
    replicad_sock: PathBuf,
}

fn session(cat: &Catalog, name: &str, role: &str) -> Sess {
    let c = cat.conn();
    c.execute(
        "INSERT INTO users (name, password_hash, totp_secret, role, created) VALUES (?1, 'x', 'x', ?2, 0)",
        params![name, role],
    )
    .unwrap();
    let uid = c.last_insert_rowid();
    let cookie = web_api::random_hex();
    let csrf = web_api::random_hex();
    c.execute(
        "INSERT INTO sessions (id_hash, user_id, csrf, created, last_seen) VALUES (?1, ?2, ?3, ?4, ?4)",
        params![web_api::sha256_hex(cookie.as_bytes()), uid, csrf, catalog::now()],
    )
    .unwrap();
    Sess { cookie, csrf }
}

fn opts() -> Options {
    Options {
        min_lock_secs: 0,
        gc_grace_secs: 0,
        ..Default::default()
    }
}

impl Primary {
    fn new() -> Primary {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        for d in ["keyd", "store", "replicad", "run", "state", "downloads", "cat"] {
            std::fs::create_dir_all(p.join(d)).unwrap();
        }
        let keyd_sock = keyd(&p.join("keyd"));
        let store_base = p.join("store");
        // nexus-replicad on its socket; publishes ca.pem + seal.pub
        let r = Arc::new(Replicad::open(&p.join("replicad"), &store_base).unwrap());
        r.publish(&p.join("run"), None).unwrap();
        let replicad_sock = p.join("run/replicad.sock");
        let l = UnixListener::bind(&replicad_sock).unwrap();
        std::thread::spawn(move || r.serve(l, me()));
        // scheduler (key exports) publishes secrets.pub next to the catalog
        let cat_path = p.join("cat/catalog.db");
        let cfg = scheduler::Config {
            catalog: cat_path.clone(),
            store_base: store_base.clone(),
            keyd_socket: keyd_sock.clone(),
            runtime_dir: p.join("run/sched"),
            state_dir: p.join("state"),
            downloads: p.join("downloads"),
            alerts_config: p.join("alerts.json"),
            offsite_state_base: p.join("offsite"),
            escrow_base: p.join("escrow"),
            nft_allowed: p.join("nft/allowed.json"),
            ..Default::default()
        };
        let db = Arc::new(Catalog::open(&cat_path).unwrap());
        let ks = keyd_sock.clone();
        let sched =
            scheduler::Scheduler::new(cfg, db, Arc::new(move |t: &str| keyd::ensure_keyring(&ks, t)), opts).unwrap();
        let cat = Catalog::open(&cat_path).unwrap();
        for t in ["acme", "other"] {
            cat.conn()
                .execute("INSERT INTO tenants (name) VALUES (?1)", [t])
                .unwrap();
        }
        let admin = session(&cat, "alice", "admin");
        let so = session(&cat, "sam", "security_officer");
        let st = AppState::with_replication(
            cat,
            None,
            p.join("downloads"),
            TotpKey::generate(),
            Some(p.join("cat/secrets.pub")),
            ReplPaths {
                socket: Some(replicad_sock.clone()),
                seal_pub: Some(p.join("run/seal.pub")),
                tls_cert: Some(p.join("run/cert.pem")),
            },
        );
        let app = web_api::router(st.clone());
        let (certs, key, pin) = self_signed();
        // the appliance certificate as PEM: its fingerprint is returned on peer creation
        {
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD.encode(certs[0].as_ref());
            let lines: Vec<&str> = b64
                .as_bytes()
                .chunks(64)
                .map(|c| std::str::from_utf8(c).unwrap())
                .collect();
            let pem = format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                lines.join("\n")
            );
            std::fs::write(p.join("run/cert.pem"), pem).unwrap();
        }
        let tls = web_api::tls::Tls::new(certs, key, Some(p.join("run/ca.pem"))).unwrap();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
        let port = listener.local_addr().unwrap().port();
        rt.spawn(web_api::tls::serve(listener, tls, app.clone(), std::future::pending()));
        Primary {
            dir,
            rt,
            app,
            st,
            keyd_sock,
            store_base,
            port,
            pin,
            sched: std::cell::RefCell::new(sched),
            admin,
            so,
            replicad_sock,
        }
    }

    fn store(&self, tenant: &str) -> Store {
        let k = keyd::ensure_keyring(&self.keyd_sock, tenant).unwrap();
        Store::open(self.store_base.join(tenant), k, opts()).unwrap()
    }

    /// One VM snapshot of `img` at `time`.
    fn backup(&self, tenant: &str, time: u64, img: &[u8]) {
        let s = self.store(tenant);
        let idx = s.store_image(img, CHUNK).unwrap();
        s.commit_snapshot("vm-100", time, &[("drive-scsi0", idx)]).unwrap();
    }

    fn call(&self, method: Method, path: &str, s: &Sess, body: Option<Value>) -> (StatusCode, Value) {
        let mut b = Request::builder()
            .method(method.clone())
            .uri(path)
            .header(header::COOKIE, format!("nx_session={}", s.cookie));
        if method != Method::GET {
            b = b.header("x-csrf-token", &s.csrf);
        }
        let req = match body {
            Some(v) => b
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(v.to_string()))
                .unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        self.rt.block_on(async {
            let res = self.app.clone().oneshot(req).await.unwrap();
            let status = res.status();
            let raw = res.into_body().collect().await.unwrap().to_bytes();
            (status, serde_json::from_slice(&raw).unwrap_or(Value::Null))
        })
    }

    fn approve(&self, q: i64) {
        let (s, b) = self.call(Method::POST, &format!("/api/v1/quorum/{q}/approve"), &self.so, None);
        assert_eq!(s, StatusCode::OK, "{b}");
    }

    /// Creates an approved peer; returns (peer id, code).
    fn peer(&self, name: &str, tenants: &[&str]) -> (String, String) {
        let (s, b) = self.call(
            Method::POST,
            "/api/v1/replication/peers",
            &self.admin,
            Some(json!({"name": name, "tenants": tenants})),
        );
        assert_eq!(s, StatusCode::ACCEPTED, "{b}");
        assert_eq!(
            b["primary_cert_sha256"],
            self.pin.as_str(),
            "admin sees the fingerprint the secondary must pin"
        );
        self.approve(b["quorum_id"].as_i64().unwrap());
        (
            b["peer"]["id"].as_str().unwrap().to_owned(),
            b["code"].as_str().unwrap().to_owned(),
        )
    }

    fn target(&self) -> Target {
        let mut t = Target::parse(&format!("127.0.0.1:{}", self.port), &self.pin).unwrap();
        t.timeout = Duration::from_secs(20);
        t
    }

    fn pending(&self, action: &str) -> Vec<i64> {
        let c = self.st.cat.conn();
        let mut q = c
            .prepare("SELECT id FROM quorum WHERE action = ?1 AND state = 'pending' ORDER BY id")
            .unwrap();
        q.query_map([action], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    fn audit_actions(&self) -> Vec<String> {
        let c = self.st.cat.conn();
        let mut q = c.prepare("SELECT action FROM audit ORDER BY seq").unwrap();
        q.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect()
    }
}

struct Secondary {
    dir: tempfile::TempDir,
    keyd_sock: PathBuf,
}

impl Secondary {
    fn new() -> Secondary {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("keyd")).unwrap();
        let keyd_sock = keyd(&dir.path().join("keyd"));
        Secondary { dir, keyd_sock }
    }

    fn creds(&self) -> PathBuf {
        self.dir.path().join("replica/1")
    }

    fn enroll(&self, t: &Target, code: &str) -> anyhow::Result<client::Enrolled> {
        let (peer, token) = repl_proto::split_code(code).unwrap();
        client::enroll(&EnrollParams {
            target: t,
            peer_id: peer,
            token_digest: &repl_proto::token_digest(token),
            name: "secondary",
            cred_dir: &self.creds(),
            keyd_pub: keyd::fetch_replica_pubkey(&self.keyd_sock).unwrap(),
            // Phase 30: hybrid DEK exports
            keyd_pub_pq: Some(keyd::fetch_replica_pubkey_pq(&self.keyd_sock).unwrap()),
        })
    }

    fn sync(&self, t: &Target, tenant: &str) -> anyhow::Result<client::SyncReport> {
        self.sync_bw(t, tenant, Default::default())
    }

    fn sync_bw(&self, t: &Target, tenant: &str, bandwidth: Bandwidth) -> anyhow::Result<client::SyncReport> {
        self.sync_with(t, tenant, bandwidth, None)
    }

    fn sync_with(
        &self,
        t: &Target,
        tenant: &str,
        bandwidth: Bandwidth,
        tenant_uid: Option<String>,
    ) -> anyhow::Result<client::SyncReport> {
        client::sync(
            &SyncParams {
                target: t.clone(),
                cred_dir: self.creds(),
                tenant: tenant.into(),
                store: self.dir.path().join("store").join(tenant),
                keyd_socket: self.keyd_sock.clone(),
                gfs: Default::default(),
                parallel: 4,
                bandwidth,
                held: Default::default(),
                tenant_uid,
                prune: true,
            },
            &mut |l| eprintln!("replica: {l}"),
        )
    }

    fn store(&self, tenant: &str) -> Store {
        let k = keyd::fetch_keyring(&self.keyd_sock, tenant).unwrap();
        Store::open(self.dir.path().join("store").join(tenant), k, opts()).unwrap()
    }
}

/// Primary with tenant `acme` (3 daily VM snapshots) and `other` (1); an
/// enrolled secondary for `acme` whose key export was approved and executed.
fn enrolled() -> (Primary, Secondary, Vec<u8>, u64) {
    let p = Primary::new();
    let now = catalog::now() as u64;
    let base = image(1, 4 << 20);
    for (i, d) in [3u64, 2, 1].iter().enumerate() {
        let mut img = base.clone();
        img[i * CHUNK..i * CHUNK + 16].copy_from_slice(&[i as u8 + 1; 16]);
        p.backup("acme", now - d * DAY, &img);
    }
    p.backup("other", now - DAY, &image(9, 1 << 20));
    let (_, code) = p.peer("dr-site", &["acme"]);
    let s = Secondary::new();
    s.enroll(&p.target(), &code).unwrap();
    let q = p.pending("replication.key_export");
    assert_eq!(q.len(), 1, "enrollment requests the key export");
    p.approve(q[0]);
    p.sched.borrow_mut().execute_key_exports().unwrap();
    (p, s, base, now)
}

#[test]
fn enroll_sync_incremental_restore_on_secondary_only() {
    let (p, s, base, now) = enrolled();
    let t = p.target();
    // first sync: all three snapshots, every chunk verified on insert
    let r = s.sync(&t, "acme").unwrap();
    assert_eq!(r.imported.len(), 3, "{r:?}");
    assert!(r.chunks_fetched >= 64 && r.chunks_fetched <= 67, "{r:?}");
    // incremental: one changed chunk
    let mut img = base.clone();
    img[10 * CHUNK..10 * CHUNK + 8].copy_from_slice(b"changed!");
    p.backup("acme", now - 60, &img);
    let r = s.sync(&t, "acme").unwrap();
    assert_eq!(r.imported, vec![format!("vm-100/{}", now - 60)]);
    assert_eq!(r.chunks_fetched, 1, "only the new chunk travels: {r:?}");
    assert_eq!(s.sync(&t, "acme").unwrap().imported.len(), 0, "nothing new");
    // the primary deletes a snapshot: the secondary keeps it
    let gone = now - 3 * DAY;
    // (min lock 0 in this test, but the compliance clock may still be a second behind)
    let ps = p.store("acme");
    for i in 0.. {
        match ps.delete_snapshot("vm-100", gone) {
            Ok(()) => break,
            // slow runners: the compliance clock can lag several seconds
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied && i < 300 => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("{e}"),
        }
    }
    s.sync(&t, "acme").unwrap();
    assert!(
        s.store("acme").load_manifest("vm-100", gone).is_ok(),
        "deletion does not propagate"
    );
    // audit on the primary: sessions with bytes served
    let acts = p.audit_actions();
    for a in [
        "replication_peer.create",
        "replication_peer.enrolled",
        "replication.key_export",
        "replication.session_start",
        "replication.session_end",
    ] {
        assert!(acts.iter().any(|x| x == a), "{a} missing in {acts:?}");
    }
    let served: i64 = p
        .st
        .cat
        .conn()
        .query_row(
            "SELECT SUM(json_extract(details, '$.bytes_served')) FROM audit WHERE action = 'replication.session_end'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(served > 4 << 20, "served {served}");

    // restore on the secondary with its own keyd only: the primary is gone
    let sec_store = s.store("acme");
    drop(p);
    let m = sec_store.load_manifest("vm-100", now - 60).unwrap();
    let idx = sec_store.load_index(&m, "drive-scsi0").unwrap();
    let mut out = Vec::new();
    sec_store.write_chunks(idx.chunk_ids(), &mut out).unwrap();
    assert_eq!(out, img, "restored image equals the original");
    let Index::Fixed { size, .. } = idx else { panic!() };
    assert_eq!(size as usize, img.len());
    // the secondary's keyd wraps the DEK under its own KEK (DR with its recovery key)
    assert!(s.dir.path().join("keyd/tenants/acme/origin").exists());
    assert!(sec_store.verify(|_| true).unwrap().corrupt.is_empty());
}

/// Phase 17a: the chunk download follows the bandwidth windows; a sync that
/// was cancelled (window closed, vault closed) after fetching chunks but before
/// committing the snapshot resumes: the chunks stay, only the manifest is missing.
#[test]
fn bandwidth_windows_and_resume_after_cancel() {
    let (p, s, _, now) = enrolled();
    let t = p.target();
    let hhmm = |x: u64| format!("{:02}:{:02}", (x % DAY) / 3600, (x % 3600) / 60);
    let limit = Bandwidth {
        windows: vec![RateWindow {
            days: vec![],
            from: hhmm(now - 120),
            to: hhmm(now + 900),
            action: Action::Limit,
            rate_bytes: Some(4_000_000),
        }],
        ..Default::default()
    };
    let t0 = std::time::Instant::now();
    let r = s.sync_bw(&t, "acme", limit).unwrap();
    assert_eq!(r.imported.len(), 3);
    let secs = t0.elapsed().as_secs_f64();
    assert!(
        secs >= 0.8 * r.bytes_fetched as f64 / 4e6,
        "{} bytes in {secs} s",
        r.bytes_fetched
    );
    // what a cancelled sync leaves behind: the newest snapshot's chunks, no manifest
    let newest = now - DAY;
    // (the snapshot directory without its manifest, as the store writes it last)
    let snap = s.dir.path().join(format!("store/acme/snapshots/vm-100/{newest}"));
    std::fs::remove_dir_all(&snap).unwrap();
    assert!(s.store("acme").load_manifest("vm-100", newest).is_err());
    let r = s.sync(&t, "acme").unwrap();
    assert_eq!(r.imported, vec![format!("vm-100/{newest}")]);
    assert_eq!(r.chunks_fetched, 0, "resumed without fetching again: {r:?}");
    assert!(r.chunks_present > 0);
}

/// Legal holds (Phase 15c): the primary's active holds reach the secondary in
/// every sync report (advisory, applied there by its own security officer);
/// a released hold is no longer reported. Peers only see their tenants' holds.
#[test]
fn legal_holds_travel_as_advisory_metadata() {
    let (p, s, _, now) = enrolled();
    let t = p.target();
    assert!(s.sync(&t, "acme").unwrap().holds.is_empty());
    let held = now - 2 * DAY;
    p.st.cat
        .conn()
        .execute_batch(&format!(
            "INSERT INTO snapshots (tenant, source, time, local, offsite) VALUES ('acme', 'vm-100', {held}, 1, 0),
               ('other', 'vm-100', {}, 1, 0)",
            now - DAY
        ))
        .unwrap();
    for (tenant, time) in [("acme", held), ("other", now - DAY)] {
        let (st, b) = p.call(
            Method::POST,
            &format!("/api/v1/snapshots/{tenant}/vm-100/{time}/hold"),
            &p.so,
            Some(json!({"reason": "case 4711"})),
        );
        assert_eq!(st, StatusCode::CREATED, "{b}");
    }
    let r = s.sync(&t, "acme").unwrap();
    assert_eq!(r.holds.len(), 1, "only the peer's tenant: {r:?}");
    let h = &r.holds[0];
    assert_eq!(
        (h.source.as_str(), h.time, h.reason.as_str(), h.held_by.as_str()),
        ("vm-100", held, "case 4711", "sam")
    );
    // nothing applied on the secondary: its store still follows its own retention
    assert!(s.store("acme").load_manifest("vm-100", held).is_ok());
    // released on the primary (requested by the admin, approved by the officer)
    let (st, b) = p.call(
        Method::DELETE,
        &format!("/api/v1/snapshots/acme/vm-100/{held}/hold"),
        &p.admin,
        None,
    );
    assert_eq!(st, StatusCode::ACCEPTED, "{b}");
    p.approve(b["quorum_id"].as_i64().unwrap());
    assert!(s.sync(&t, "acme").unwrap().holds.is_empty());
}

#[test]
fn tampered_chunk_is_not_imported() {
    let (p, s, _, _) = enrolled();
    // flip one byte in one sealed chunk on the primary
    let chunks = p.store_base.join("acme/chunks");
    let d = std::fs::read_dir(&chunks).unwrap().next().unwrap().unwrap().path();
    let f = std::fs::read_dir(&d).unwrap().next().unwrap().unwrap().path();
    let mut b = std::fs::read(&f).unwrap();
    let n = b.len();
    b[n - 3] ^= 0x40;
    std::fs::write(&f, &b).unwrap();
    let e = s.sync(&p.target(), "acme").unwrap_err();
    assert!(e.downcast_ref::<VerifyFailed>().is_some(), "{e:#}");
    // the snapshot that references it was not committed
    let st = s.store("acme");
    let name = f.file_name().unwrap().to_str().unwrap();
    for m in st.list_snapshots().unwrap() {
        let idx = st.load_index(&m, "drive-scsi0").unwrap();
        assert!(
            !idx.chunk_ids().iter().any(|c| repl_proto::hex(*c) == name),
            "a snapshot referencing the tampered chunk was imported"
        );
    }
    assert!(!st.has_chunk(&repl_proto::unhex(name).unwrap().try_into().unwrap()));
    // session end recorded the error
    assert!(p.audit_actions().iter().any(|a| a == "replication.session_end"));
}

/// Phase 19b: the primary reports the tenant's immutable uid; a secondary that
/// replicated another uid under the same name (deleted and re-created tenant)
/// fetches nothing; no recorded uid (first sync, legacy) syncs as before.
#[test]
fn tenant_uid_is_checked_by_the_secondary() {
    let (p, s, _, _) = enrolled();
    let t = p.target();
    let uid = catalog::tenancy::uid(&p.st.cat.conn(), "acme").unwrap().unwrap();
    let r = s.sync_with(&t, "acme", Default::default(), None).unwrap();
    assert_eq!(r.tenant_uid.as_deref(), Some(uid.as_str()));
    let e = s
        .sync_with(&t, "acme", Default::default(), Some("0".repeat(32)))
        .unwrap_err();
    assert!(
        e.downcast_ref::<VerifyFailed>().is_some() && format!("{e:#}").contains("uid"),
        "{e:#}"
    );
    assert!(s.sync_with(&t, "acme", Default::default(), Some(uid)).is_ok());
}

#[test]
fn tenant_scope_revocation_and_connection_kinds() {
    let (p, s, _, _) = enrolled();
    let t = p.target();
    let cfg = client_config(
        &t.pin,
        repl_proto::ALPN_PEER,
        Some(client::load_creds(&s.creds()).unwrap()),
    )
    .unwrap();
    let mut c = Conn::connect(&t, cfg).unwrap();
    let get = |c: &mut Conn, path: &str| {
        let r = c.request("GET", path, None, b"").unwrap();
        let st = r.status;
        let _ = r.bytes(64 << 20).unwrap();
        st
    };
    assert_eq!(get(&mut c, "/replication/v1/tenants/acme/snapshots"), 200);
    assert_eq!(
        get(&mut c, "/replication/v1/tenants/other/snapshots"),
        403,
        "out of scope"
    );
    assert_eq!(get(&mut c, "/replication/v1/tenants/other/keys"), 403);
    let r = c
        .request(
            "POST",
            "/replication/v1/tenants/other/chunks",
            Some("application/octet-stream"),
            &[0u8; 32],
        )
        .unwrap();
    assert_eq!(r.status, 403);
    let _ = r.bytes(1 << 20);
    assert_eq!(
        get(
            &mut c,
            "/replication/v1/tenants/acme/snapshots/vm-100/1/..%2F..%2Fkeycheck"
        ),
        400
    );
    assert_eq!(
        get(&mut c, "/replication/v1/tenants/acme/snapshots/..%2Fother/1/manifest"),
        400
    );
    assert_eq!(
        get(&mut c, "/api/v1/auth/me"),
        404,
        "peer connections reach only the peer API"
    );
    // an ordinary TLS connection (browser ALPN) never reaches the peer API
    let plain = client_config(&t.pin, b"http/1.1", None).unwrap();
    let mut b = Conn::connect(&t, plain).unwrap();
    assert_eq!(get(&mut b, "/replication/v1/tenants/acme/snapshots"), 403);
    assert_eq!(get(&mut b, "/health"), 200);
    // a peer-ALPN handshake without a client certificate fails
    let nocert = client_config(&t.pin, repl_proto::ALPN_PEER, None).unwrap();
    assert!(Conn::connect(&t, nocert)
        .and_then(|mut c| {
            let r = c.request("GET", "/replication/v1/peer", None, b"")?;
            Ok(r.status)
        })
        .is_err());

    // revoke (quorum) → refused immediately, on the same keep-alive connection
    let peer_id =
        p.st.cat
            .conn()
            .query_row("SELECT id FROM replication_peers", [], |r| r.get::<_, String>(0))
            .unwrap();
    let (st, body) = p.call(
        Method::DELETE,
        &format!("/api/v1/replication/peers/{peer_id}"),
        &p.admin,
        None,
    );
    assert_eq!(st, StatusCode::ACCEPTED, "{body}");
    assert_eq!(get(&mut c, "/replication/v1/peer"), 200, "not before the approval");
    p.approve(body["quorum_id"].as_i64().unwrap());
    assert_eq!(get(&mut c, "/replication/v1/peer"), 403);
    assert!(s.sync(&t, "acme").is_err());
    assert!(p.audit_actions().iter().any(|a| a == "replication.denied"));
    let (st, peers) = p.call(Method::GET, "/api/v1/replication/peers", &p.admin, None);
    assert_eq!(st, StatusCode::OK);
    assert_eq!(peers[0]["state"], "revoked");
    assert_eq!(peers[0]["keys"], json!({}), "key exports dropped");
}

/// A TLS-terminating relay with its own certificate between the secondary and
/// the primary: the secondary pins the relay (the admin was given the wrong
/// fingerprint). The proofs are bound to each leg's TLS exporter: refused.
#[test]
fn enrollment_through_a_man_in_the_middle_fails() {
    let p = Primary::new();
    let (peer_id, code) = p.peer("dr-site", &["acme"]);
    let (certs, key, mitm_pin) = self_signed();
    let mut sc = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    sc.alpn_protocols = vec![repl_proto::ALPN_ENROLL.to_vec()];
    let sc = Arc::new(sc);
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mitm_port = l.local_addr().unwrap().port();
    let upstream = p.target();
    std::thread::spawn(move || {
        for tcp in l.incoming() {
            let tcp = tcp.unwrap();
            let conn = rustls::ServerConnection::new(sc.clone()).unwrap();
            let mut s = rustls::StreamOwned::new(conn, tcp);
            // read one request (head + Content-Length body), relay it, relay the answer
            let mut r = BufReader::new(&mut s);
            let mut first = String::new();
            if r.read_line(&mut first).is_err() {
                continue;
            }
            let (method, path) = {
                let mut it = first.split_whitespace();
                (it.next().unwrap().to_owned(), it.next().unwrap().to_owned())
            };
            let mut len = 0;
            loop {
                let mut h = String::new();
                r.read_line(&mut h).unwrap();
                if h.trim().is_empty() {
                    break;
                }
                if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
            }
            let mut body = vec![0u8; len];
            r.read_exact(&mut body).unwrap();
            let cfg = client_config(&upstream.pin, repl_proto::ALPN_ENROLL, None).unwrap();
            let mut up = Conn::connect(&upstream, cfg).unwrap();
            let resp = up.request(&method, &path, Some("application/json"), &body).unwrap();
            let status = resp.status;
            let out = resp.bytes(1 << 20).unwrap();
            write!(
                s,
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n",
                out.len()
            )
            .unwrap();
            s.write_all(&out).unwrap();
            s.flush().unwrap();
        }
    });
    let s = Secondary::new();
    let mut via_mitm = Target::parse(&format!("127.0.0.1:{mitm_port}"), &mitm_pin).unwrap();
    via_mitm.timeout = Duration::from_secs(20);
    let e = s.enroll(&via_mitm, &code).unwrap_err();
    assert!(format!("{e:#}").contains("403"), "{e:#}");
    let (state, fails): (String, i64) =
        p.st.cat
            .conn()
            .query_row(
                "SELECT state, enroll_failures FROM replication_peers WHERE id = ?1",
                [&peer_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
    assert_eq!((state.as_str(), fails), ("approved", 1));
    assert!(p.audit_actions().iter().any(|a| a == "replication_peer.enroll_failed"));
    // wrong code: refused as well
    let wrong = format!("{peer_id}.AAAAAAAAAAAAAAAAAAAAAAAAAA");
    assert!(s.enroll(&p.target(), &wrong).is_err());
    // the wrong pin (the real primary with a pin of something else) never even talks
    let mut bad_pin = p.target();
    bad_pin.pin = "00".repeat(32);
    assert!(s.enroll(&bad_pin, &code).is_err());
    // direct: works, once
    let e = s.enroll(&p.target(), &code).unwrap();
    assert_eq!(e.tenants, vec!["acme".to_string()]);
    assert!(s.enroll(&p.target(), &code).is_err(), "single use");
    // the fingerprint the primary recorded is the secondary's certificate
    let fp: String =
        p.st.cat
            .conn()
            .query_row(
                "SELECT cert_sha256 FROM replication_peers WHERE id = ?1",
                [&peer_id],
                |r| r.get(0),
            )
            .unwrap();
    assert_eq!(fp, e.cert_sha256);
}

#[test]
fn key_export_needs_an_approved_quorum_and_follows_rotation() {
    let p = Primary::new();
    let now = catalog::now() as u64;
    p.backup("acme", now - DAY, &image(3, 1 << 20));
    let (_, code) = p.peer("dr", &["acme"]);
    // enrollment before approval of the peer itself is refused
    let (s2, b2) = p.call(
        Method::POST,
        "/api/v1/replication/peers",
        &p.admin,
        Some(json!({"name": "unapproved", "tenants": ["acme"]})),
    );
    assert_eq!(s2, StatusCode::ACCEPTED);
    let s = Secondary::new();
    assert!(
        s.enroll(&p.target(), b2["code"].as_str().unwrap()).is_err(),
        "pending peer"
    );
    s.enroll(&p.target(), &code).unwrap();
    let t = p.target();
    // no export yet: the secondary gets nothing and says why
    let e = s.sync(&t, "acme").unwrap_err();
    assert!(e.downcast_ref::<KeysMissing>().is_some(), "{e:#}");
    // pending request: the scheduler does not export
    let q = p.pending("replication.key_export");
    assert_eq!(q.len(), 1);
    p.sched.borrow_mut().execute_key_exports().unwrap();
    assert!(s.sync(&t, "acme").unwrap_err().downcast_ref::<KeysMissing>().is_some());
    // the requester (alice) cannot approve; a second person can
    let (st, _) = p.call(
        Method::POST,
        &format!("/api/v1/quorum/{}/approve", q[0]),
        &p.admin,
        None,
    );
    assert_eq!(st, StatusCode::FORBIDDEN);
    p.approve(q[0]);
    p.sched.borrow_mut().execute_key_exports().unwrap();
    let state: String =
        p.st.cat
            .conn()
            .query_row("SELECT state FROM quorum WHERE id = ?1", [q[0]], |r| r.get(0))
            .unwrap();
    assert_eq!(state, "executed");
    // the stored export is not the DEK in clear
    let exports: String =
        p.st.cat
            .conn()
            .query_row("SELECT key_exports FROM replication_peers WHERE name = 'dr'", [], |r| {
                r.get(0)
            })
            .unwrap();
    assert!(exports.contains("\"versions\":[1]"), "{exports}");
    // Phase 30: sealed hybrid (X25519 + ML-KEM-768) to the secondary's keyd
    let ex: serde_json::Value = serde_json::from_str(&exports).unwrap();
    assert_eq!(ex["acme"]["post_quantum"], true);
    let blob = repl_proto::unhex(ex["acme"]["blob"].as_str().unwrap()).unwrap();
    assert!(keyd::hybrid::is_hybrid(&blob));
    let pq: Option<String> =
        p.st.cat
            .conn()
            .query_row("SELECT keyd_pub_pq FROM replication_peers WHERE name = 'dr'", [], |r| {
                r.get(0)
            })
            .unwrap();
    assert_eq!(pq.map(|h| h.len()), Some(2 * keyd::hybrid::PUBLIC_LEN));
    assert_eq!(s.sync(&t, "acme").unwrap().imported.len(), 1);

    // rotation on the primary: the new snapshot is skipped and reported until re-export
    keyd::rotate_tenant(&p.dir.path().join("keyd"), "acme").unwrap();
    p.backup("acme", now - 100, &image(4, 1 << 20));
    let e = s.sync(&t, "acme").unwrap_err();
    assert!(e.downcast_ref::<KeysMissing>().is_some(), "{e:#}");
    assert_eq!(
        s.store("acme").list_snapshots().unwrap().len(),
        1,
        "nothing imported with an unknown key"
    );
    let peer_id: String =
        p.st.cat
            .conn()
            .query_row("SELECT id FROM replication_peers WHERE name = 'dr'", [], |r| r.get(0))
            .unwrap();
    let (st, b) = p.call(
        Method::POST,
        &format!("/api/v1/replication/peers/{peer_id}/export-keys"),
        &p.admin,
        None,
    );
    assert_eq!(st, StatusCode::ACCEPTED, "{b}");
    p.approve(b["quorum_id"].as_i64().unwrap());
    p.sched.borrow_mut().execute_key_exports().unwrap();
    let r = s.sync(&t, "acme").unwrap();
    assert_eq!(r.imported.len(), 1);
    assert_eq!(r.key_versions, vec![1, 2]);
    let st = s.store("acme");
    assert_eq!(st.list_snapshots().unwrap().len(), 2);
    let k = Keyring::new("acme", &[(1, [0; 32])]);
    assert!(
        Store::open(s.dir.path().join("store/acme"), k, opts()).is_err(),
        "a wrong keyring is refused"
    );
}

/// The forwarding design: the web-api crate cannot link the chunk store or keyd
/// (protocol types only), and without replicad it serves no data although the
/// store files exist.
#[test]
fn web_api_never_opens_store_files() {
    let manifest = include_str!("../Cargo.toml");
    let deps = manifest.split("[dev-dependencies]").next().unwrap();
    assert!(
        !deps
            .lines()
            .any(|l| l.starts_with("chunkstore") || l.starts_with("keyd") || l.starts_with("replication ")),
        "web-api must not depend on chunkstore/keyd"
    );
    assert!(
        deps.lines()
            .any(|l| l.starts_with("repl_proto") && l.contains("default-features = false")),
        "only the protocol part of the replication crate"
    );
    let (p, s, _, _) = enrolled();
    std::fs::remove_file(&p.replicad_sock).unwrap();
    let t = p.target();
    let cfg = client_config(
        &t.pin,
        repl_proto::ALPN_PEER,
        Some(client::load_creds(&s.creds()).unwrap()),
    )
    .unwrap();
    let mut c = Conn::connect(&t, cfg).unwrap();
    let one = std::fs::read_dir(p.store_base.join("acme/snapshots/vm-100"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .file_name();
    let file = format!(
        "/replication/v1/tenants/acme/snapshots/vm-100/{}/manifest",
        one.to_str().unwrap()
    );
    for path in ["/replication/v1/tenants/acme/snapshots", &file] {
        let r = c.request("GET", path, None, b"").unwrap();
        assert_eq!(r.status, 503, "{path}");
        let _ = r.bytes(1 << 20);
    }
    assert!(p.store_base.join("acme/snapshots/vm-100").exists());
}

/// Secondary management API: tenant exclusivity, sealed code, enrollment job;
/// replicated tenants take no local backups.
#[test]
fn secondary_source_api() {
    let p = Primary::new(); // used as a plain catalog + router here
    let c = |m: Method, path: &str, b: Option<Value>| p.call(m, path, &p.admin, b);
    p.st.cat
        .conn()
        .execute_batch(
            "INSERT INTO tenants (name) VALUES ('busy');
             INSERT INTO sources (id, tenant, kind, name, config) VALUES (5, 'busy', 'pve', 'x', '{}');
             INSERT INTO policies (id, name, schedule, gfs) VALUES (1, 'p', 'daily 01:00', '{}');
             INSERT INTO groups (tenant, source_id, policy_id, name, guests) VALUES ('busy', 5, 1, 'g', '[1]');",
        )
        .unwrap();
    let req = |tenants: Value| {
        json!({"name": "prim", "url": "https://10.0.2.2:28443/", "code": "0123456789abcdef.ABCDEFGHIJKLMNOPQRSTUVWXYZ",
               "fingerprint": "AB:".repeat(31) + "AB", "tenants": tenants, "schedule": "hourly 05"})
    };
    let (st, _) = c(Method::POST, "/api/v1/replication/sources", Some(req(json!(["busy"]))));
    assert_eq!(
        st,
        StatusCode::CONFLICT,
        "a tenant with backups cannot be replicated into"
    );
    let (st, b) = c(Method::POST, "/api/v1/replication/sources", Some(req(json!(["dr1"]))));
    assert_eq!(st, StatusCode::CREATED, "{b}");
    assert_eq!(b["source"]["url"], "10.0.2.2:28443");
    assert_eq!(b["source"]["cert_pin"], "ab".repeat(32));
    let (kind, params): (String, String) =
        p.st.cat
            .conn()
            .query_row(
                "SELECT kind, params FROM jobs WHERE id = ?1",
                [b["job"].as_i64().unwrap()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
    assert_eq!(kind, "replica_enroll");
    assert!(params.contains("replication_source_id"));
    let token: String =
        p.st.cat
            .conn()
            .query_row("SELECT token_hash FROM replication_sources", [], |r| r.get(0))
            .unwrap();
    assert!(token.starts_with("sealed:v1:"));
    // the scheduler can open it (bound to source, primary address, peer id, pin)
    let sk = SchedulerKey::load_or_create(&p.dir.path().join("state/secrets.key"))
        .unwrap()
        .0;
    let loc = catalog::secret::replication_source_token_location(
        b["source"]["id"].as_i64().unwrap(),
        "10.0.2.2:28443",
        "0123456789abcdef",
        &"ab".repeat(32),
    );
    assert_eq!(
        *sk.open(&loc, &token).unwrap(),
        repl_proto::token_digest("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    );
    let (st, _) = c(
        Method::POST,
        "/api/v1/replication/sources",
        Some(
            json!({"name": "again", "url": "h", "code": "0123456789abcdef.ABCDEFGHIJKLMNOPQRSTUVWXYZ", "fingerprint": "ab".repeat(32), "tenants": ["dr1"], "schedule": "hourly 05"}),
        ),
    );
    assert_eq!(st, StatusCode::CONFLICT, "a tenant is replicated from one source");
    // replicated tenant: no groups, agents or backup jobs
    p.st.cat
        .conn()
        .execute(
            "INSERT INTO sources (id, tenant, kind, name, config) VALUES (6, 'dr1', 'pve', 'restore-target', '{}')",
            [],
        )
        .unwrap();
    let (st, _) = c(
        Method::POST,
        "/api/v1/groups",
        Some(json!({"tenant": "dr1", "source_id": 6, "policy_id": 1, "name": "g", "guests": [1]})),
    );
    assert_eq!(st, StatusCode::CONFLICT);
    let (st, _) = c(
        Method::POST,
        "/api/v1/agents",
        Some(json!({"tenant": "dr1", "name": "a", "host": "h"})),
    );
    assert_eq!(st, StatusCode::CONFLICT);
    let (st, _) = c(
        Method::POST,
        "/api/v1/jobs",
        Some(json!({"kind": "backup", "tenant": "dr1", "params": {"vmid": 100}})),
    );
    assert_eq!(st, StatusCode::CONFLICT);
    // lowering GFS needs a quorum, raising does not
    let id = b["source"]["id"].as_i64().unwrap();
    let (st, _) = c(
        Method::PUT,
        &format!("/api/v1/replication/sources/{id}"),
        Some(json!({"gfs": {"daily": 30, "weekly": 4, "monthly": 6, "yearly": 2}})),
    );
    assert_eq!(st, StatusCode::OK);
    let (st, b) = c(
        Method::PUT,
        &format!("/api/v1/replication/sources/{id}"),
        Some(json!({"gfs": {"daily": 7, "weekly": 4, "monthly": 6, "yearly": 2}})),
    );
    assert_eq!(st, StatusCode::ACCEPTED, "{b}");
    // sync needs an enrolled source; delete of a not enrolled one is direct
    let (st, _) = c(Method::POST, &format!("/api/v1/replication/sources/{id}/sync"), None);
    assert_eq!(st, StatusCode::CONFLICT);
    let (st, list) = c(Method::GET, "/api/v1/replication/sources", None);
    assert_eq!(st, StatusCode::OK);
    assert!(list[0].get("token_hash").is_none(), "token never returned");
}

/// Approvals disabled (plan §2): creating the peer, the key export after
/// enrollment, a re-export and the revocation happen on the admin's request,
/// audited with `"approvals": "disabled"`; the scheduler still executes the
/// export (an `approved` quorum row decided by the requester is its work item).
#[test]
fn replication_without_approvals_runs_on_the_admins_request() {
    let p = Primary::new();
    catalog::set_setting(&p.st.cat.conn(), "approvals_enabled", "false").unwrap();
    let now = catalog::now() as u64;
    p.backup("acme", now - DAY, &image(5, 1 << 20));
    let (s, b) = p.call(
        Method::POST,
        "/api/v1/replication/peers",
        &p.admin,
        Some(json!({"name": "dr", "tenants": ["acme"]})),
    );
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(
        (b["approvals"].as_str(), b["executed"].as_bool()),
        (Some("disabled"), Some(true))
    );
    assert_eq!(b["peer"]["state"], "approved");
    let peer_id = b["peer"]["id"].as_str().unwrap().to_owned();
    let sec = Secondary::new();
    sec.enroll(&p.target(), b["code"].as_str().unwrap()).unwrap();
    // the export follows directly: no pending request, an approved work item
    assert!(p.pending("replication.key_export").is_empty());
    let (state, by, decided): (String, String, String) =
        p.st.cat
            .conn()
            .query_row(
                "SELECT state, requested_by, decided_by FROM quorum WHERE action = 'replication.key_export'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
    assert_eq!(
        (state.as_str(), by.as_str(), decided.as_str()),
        ("approved", "alice", "alice")
    );
    p.sched.borrow_mut().execute_key_exports().unwrap();
    let t = p.target();
    assert_eq!(sec.sync(&t, "acme").unwrap().imported.len(), 1);
    // an explicit re-export: 200 with the work item's id
    let (s, b) = p.call(
        Method::POST,
        &format!("/api/v1/replication/peers/{peer_id}/export-keys"),
        &p.admin,
        None,
    );
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(
        (b["state"].as_str(), b["executed"].as_bool()),
        (Some("approved"), Some(false))
    );
    assert!(b["quorum_id"].is_i64());
    // revocation: direct
    let (s, b) = p.call(
        Method::DELETE,
        &format!("/api/v1/replication/peers/{peer_id}"),
        &p.admin,
        None,
    );
    assert_eq!(s, StatusCode::OK, "{b}");
    let state: String =
        p.st.cat
            .conn()
            .query_row("SELECT state FROM replication_peers WHERE id = ?1", [&peer_id], |r| {
                r.get(0)
            })
            .unwrap();
    assert_eq!(state, "revoked");
    let disabled: i64 =
        p.st.cat
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM audit WHERE json_extract(details, '$.approvals') = 'disabled'
             AND action IN ('replication_peer.create', 'replication.key_export', 'replication_peer.delete')",
                [],
                |r| r.get(0),
            )
            .unwrap();
    assert_eq!(disabled, 4, "create, export after enrollment, re-export, revoke");
    assert!(sec.sync(&t, "acme").is_err(), "revoked");
}

/// Phase 17a/b on the secondary: windows and sync window (weakening needs
/// approval, tightening is direct), "close vault now" (admin or security
/// officer, direct, cancels syncs, never shortened) and reopening (quorum
/// `replication.reopen`, approved by someone else).
#[test]
fn source_windows_close_and_reopen() {
    let p = Primary::new();
    let op = session(&p.st.cat, "olga", "operator");
    let viewer = session(&p.st.cat, "vera", "viewer");
    let c = |s: &Sess, m: Method, path: &str, b: Option<Value>| p.call(m, path, s, b);
    let (st, b) = c(
        &p.admin,
        Method::POST,
        "/api/v1/replication/sources",
        Some(
            json!({"name": "prim", "url": "10.0.2.2:28443", "code": "0123456789abcdef.ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                    "fingerprint": "ab".repeat(32), "tenants": ["dr1"], "schedule": "hourly 05",
                    "sync_window": [{"from": "22:00", "to": "06:00"}], "timezone": "Europe/Berlin",
                    "windows": [{"from": "08:00", "to": "18:00", "action": "pause"}]}),
        ),
    );
    assert_eq!(st, StatusCode::CREATED, "{b}");
    let id = b["source"]["id"].as_i64().unwrap();
    assert_eq!(b["source"]["timezone"], "Europe/Berlin");
    assert_eq!(b["source"]["sync_window"][0]["from"], "22:00");
    let path = format!("/api/v1/replication/sources/{id}");
    let put = |body: Value| c(&p.admin, Method::PUT, &path, Some(body));
    for bad in [
        json!({"windows": [{"from": "08:00", "to": "08:00", "action": "pause"}]}),
        json!({"windows": [{"from": "08:00", "to": "09:00", "action": "limit"}]}),
        json!({"sync_window": [{"days": ["Xyz"], "from": "08:00", "to": "09:00"}]}),
        json!({"timezone": "Mars/Base"}),
    ] {
        assert_eq!(put(bad.clone()).0, StatusCode::BAD_REQUEST, "{bad}");
    }
    // tightening: a longer pause, a narrower sync window, a lower limit: direct
    let (st, b) = put(json!({"windows": [{"from": "07:00", "to": "19:00", "action": "pause"},
                                       {"from": "19:00", "to": "22:00", "action": "limit", "rate_bytes": 1000}],
                            "sync_window": [{"from": "23:00", "to": "05:00"}]}));
    assert_eq!(st, StatusCode::OK, "{b}");
    assert_eq!(b["windows"][1]["rate_bytes"], 1000);
    // weakening: the pause removed, the sync window widened, another time zone: approval
    for weak in [
        json!({"windows": [{"from": "19:00", "to": "22:00", "action": "limit", "rate_bytes": 1000}]}),
        json!({"sync_window": []}),
        json!({"sync_window": [{"from": "22:00", "to": "05:00"}]}),
        json!({"timezone": "America/New_York"}),
    ] {
        let (st, b) = put(weak.clone());
        assert_eq!(st, StatusCode::ACCEPTED, "{weak}: {b}");
    }
    let q = p.pending("replication_source.update");
    assert_eq!(q.len(), 4);
    p.approve(q[1]);
    let (_, list) = c(&p.admin, Method::GET, "/api/v1/replication/sources", None);
    assert_eq!(list[0]["sync_window"], json!([]), "approved: always");
    assert_eq!(list[0]["windows"][0]["action"], "pause", "the rest unchanged");

    // close: not by operators or viewers; by a security officer, direct
    let close = format!("{path}/close");
    assert_eq!(c(&op, Method::POST, &close, None).0, StatusCode::FORBIDDEN);
    assert_eq!(c(&viewer, Method::POST, &close, None).0, StatusCode::FORBIDDEN);
    let soon = catalog::now() + 3600;
    let (st, b) = c(&p.so, Method::POST, &close, Some(json!({"until": soon})));
    assert_eq!(st, StatusCode::OK, "{b}");
    assert_eq!(b["closed_until"].as_i64(), Some(soon));
    assert!(b["closed_by"].is_string());
    let shorter = c(&p.admin, Method::POST, &close, Some(json!({"until": soon - 60})));
    assert_eq!(shorter.0, StatusCode::CONFLICT, "never shortened");
    // closing for good cancels queued syncs
    p.st.cat
        .conn()
        .execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) \
             VALUES ('replica_sync', 'dr1', ?1, 'queued', 'scheduler', 0)",
            [json!({"replication_source_id": id, "tenant": "dr1"}).to_string()],
        )
        .unwrap();
    let (st, b) = c(&p.admin, Method::POST, &close, None);
    assert_eq!(st, StatusCode::OK, "{b}");
    assert_eq!(b["closed_until"], -1);
    let jobs: String =
        p.st.cat
            .conn()
            .query_row("SELECT state FROM jobs WHERE kind = 'replica_sync'", [], |r| r.get(0))
            .unwrap();
    assert_eq!(jobs, "cancelled");
    assert_eq!(c(&p.admin, Method::POST, &close, None).0, StatusCode::CONFLICT);
    // manual sync refused while closed (the source is not enrolled here: fake it)
    p.st.cat
        .conn()
        .execute("UPDATE replication_sources SET state = 'enrolled'", [])
        .unwrap();
    let (st, b) = c(&p.admin, Method::POST, &format!("{path}/sync"), None);
    assert_eq!(st, StatusCode::CONFLICT);
    assert!(b.to_string().contains("closed"), "{b}");

    // reopen: quorum, not approvable by the requester, executed by another approver
    assert_eq!(
        c(&op, Method::POST, &format!("{path}/reopen"), None).0,
        StatusCode::FORBIDDEN
    );
    let (st, b) = c(&p.admin, Method::POST, &format!("{path}/reopen"), None);
    assert_eq!(st, StatusCode::ACCEPTED, "{b}");
    let qid = b["quorum_id"].as_i64().unwrap();
    let (st, _) = c(&p.admin, Method::POST, &format!("/api/v1/quorum/{qid}/approve"), None);
    assert_eq!(st, StatusCode::FORBIDDEN, "own request");
    let (_, list) = c(&p.admin, Method::GET, "/api/v1/replication/sources", None);
    assert_eq!(list[0]["closed_until"], -1, "still closed while pending");
    p.approve(qid);
    let (_, list) = c(&p.admin, Method::GET, "/api/v1/replication/sources", None);
    assert!(list[0]["closed_until"].is_null() && list[0]["closed_by"].is_null());
    assert_eq!(
        c(&p.admin, Method::POST, &format!("{path}/reopen"), None).0,
        StatusCode::CONFLICT,
        "not closed"
    );
    let acts = p.audit_actions();
    for a in ["replication_source.close", "quorum.request", "replication.reopen"] {
        assert!(acts.iter().any(|x| x == a), "{a} missing in {acts:?}");
    }
}

/// Phase 21d: a chunk that failed verify on the secondary is fetched again from
/// the primary (verified before it is stored).
#[test]
fn bad_chunk_on_the_secondary_repaired_from_the_primary() {
    let (p, s, _, _) = enrolled();
    let t = p.target();
    s.sync(&t, "acme").unwrap();
    let st = s.store("acme");
    let m = st.list_snapshots().unwrap().remove(0);
    let id = *st.load_index(&m, "drive-scsi0").unwrap().chunk_ids()[0];
    let h = repl_proto::hex(&id);
    let f = s.dir.path().join("store/acme/chunks").join(&h[..4]).join(&h);
    let mut b = std::fs::read(&f).unwrap();
    b[40] ^= 0xff;
    std::fs::write(&f, &b).unwrap();
    let v = st.verify(|_| true).unwrap();
    assert_eq!(v.corrupt, vec![id]);
    st.mark_bad(&v.corrupt).unwrap();
    assert!(st.is_damaged(&m).unwrap());
    let r = client::repair(&SyncParams {
        target: t,
        cred_dir: s.creds(),
        tenant: "acme".into(),
        store: s.dir.path().join("store/acme"),
        keyd_socket: s.keyd_sock.clone(),
        gfs: Default::default(),
        parallel: 1,
        bandwidth: Default::default(),
        held: Default::default(),
        tenant_uid: None,
        prune: true,
    })
    .unwrap();
    assert_eq!((r.repaired, r.unavailable), (1, 0));
    assert!(!st.is_damaged(&m).unwrap());
    assert!(st.verify(|_| true).unwrap().corrupt.is_empty());
}
