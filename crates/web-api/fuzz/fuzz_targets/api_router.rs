//! The whole REST router with arbitrary method / path / query / body, as an
//! anonymous caller or with a valid session of each role. Invariants: no
//! panic, no 5xx, anonymous callers never get past auth on `/api/v1` (except
//! health / login / metrics), and the audit chain stays intact.
//!
//! Input: `[who][method][path len][path][body…]`.
#![no_main]

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use catalog::rusqlite::params;
use catalog::Catalog;
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use tower::ServiceExt;

const ROLES: [(&str, &str, Option<&str>); 5] = [
    ("alice", "admin", None),
    ("sam", "security_officer", None),
    ("otto", "operator", None),
    ("tina", "tenant_user", Some("acme")),
    ("olga", "operator", Some("globex")),
];

struct Env {
    rt: tokio::runtime::Runtime,
    app: axum::Router,
    st: std::sync::Arc<web_api::AppState>,
    _dir: tempfile::TempDir,
}

fn env() -> &'static Env {
    static E: OnceLock<Env> = OnceLock::new();
    E.get_or_init(|| {
        let dir = tempfile::tempdir_in("/dev/shm").unwrap();
        let cat = Catalog::open(&dir.path().join("catalog.db")).unwrap();
        {
            let c = cat.conn();
            for t in ["acme", "globex"] {
                c.execute("INSERT INTO tenants (name) VALUES (?1)", [t]).unwrap();
            }
            // a cheap hash: logins are not fuzzed here, sessions are inserted directly
            for (i, (n, role, tenant)) in ROLES.iter().enumerate() {
                c.execute(
                    "INSERT INTO users (name, password_hash, totp_secret, role, tenant, created) VALUES (?1,'x','JBSWY3DPEHPK3PXP',?2,?3,0)",
                    params![n, role, tenant],
                )
                .unwrap();
                let uid = c.last_insert_rowid();
                c.execute(
                    "INSERT INTO sessions (id_hash, user_id, csrf, created, last_seen) VALUES (?1, ?2, 'csrf', ?3, ?3)",
                    params![web_api::sha256_hex(format!("tok{i}").as_bytes()), uid, i64::MAX / 4],
                )
                .unwrap();
            }
            c.execute(
                "INSERT INTO policies (name, schedule, gfs, offsite) VALUES ('std', 'daily 01:00', '{\"daily\":7,\"weekly\":4,\"monthly\":12,\"yearly\":1}', 1)",
                [],
            )
            .unwrap();
            c.execute(
                "INSERT INTO snapshots (tenant, source, time, size, local, offsite) VALUES ('acme', 'vm-100', 1000, 5, 1, 0)",
                [],
            )
            .unwrap();
        }
        let downloads = dir.path().join("downloads");
        std::fs::create_dir(&downloads).unwrap();
        // the scheduler's public key is published: secret writes succeed (no 503)
        let secrets_pub = dir.path().join("secrets.pub");
        catalog::secret::SchedulerKey::generate()
            .write_public(&secrets_pub, None)
            .unwrap();
        let st = web_api::AppState::with_keys(
            cat,
            Some("metrics-token".into()),
            downloads,
            catalog::secret::TotpKey::generate(),
            Some(secrets_pub),
        );
        Env {
            rt: tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap(),
            app: web_api::router(st.clone()),
            st,
            _dir: dir,
        }
    })
}

const METHODS: [Method; 5] = [Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::HEAD];

fuzz_target!(|data: &[u8]| {
    let [who, m, pl, rest @ ..] = data else { return };
    let pl = (*pl as usize).min(rest.len());
    let (path, body) = rest.split_at(pl);
    let path = String::from_utf8_lossy(path);
    let uri = format!("/api/v1/{}", path.trim_start_matches('/'));
    let method = METHODS[*m as usize % METHODS.len()].clone();
    let mut b = Request::builder().method(method.clone()).uri(&uri);
    let anon = *who as usize % (ROLES.len() + 1) == ROLES.len();
    if !anon {
        b = b
            .header(
                header::COOKIE,
                format!("nx_session=tok{}", *who as usize % (ROLES.len() + 1)),
            )
            .header("x-csrf-token", "csrf");
    }
    let Ok(req) = b
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_vec()))
    else {
        return;
    };
    let e = env();
    // the SPA has no logins either: keep the login handler (argon2) out of the loop
    if uri.starts_with("/api/v1/auth/login") {
        return;
    }
    let res = e.rt.block_on(e.app.clone().oneshot(req)).unwrap();
    let status = res.status();
    assert!(!status.is_server_error(), "{method} {uri} -> {status}");
    // `/api/v1/` itself (and `//…`) does not hit the nested API router: the SPA index answers
    let spa = res
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|v| v.as_bytes().starts_with(b"text/html"));
    if anon && !spa {
        let open = ["/api/v1/health", "/api/v1/metrics"].iter().any(|p| uri.starts_with(p));
        assert!(
            open || status == StatusCode::UNAUTHORIZED
                || status == StatusCode::NOT_FOUND
                || status == StatusCode::METHOD_NOT_ALLOWED
                || status == StatusCode::BAD_REQUEST,
            "anonymous {method} {uri} -> {status}"
        );
    }
    static N: AtomicU64 = AtomicU64::new(0);
    if N.fetch_add(1, Ordering::Relaxed) % 5000 == 0 {
        e.st.cat.verify_audit().expect("audit chain");
    }
});
