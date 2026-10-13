//! Phase 15g file search: `POST /search` queues a `file_search` job (RBAC,
//! tenant isolation, audit), the per-group VM/CT `index_files` flag.

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
            ("vic", "viewer", None),
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
                     (2, 'globex', 'pve', 'pve-g', '{}'), (3, 'acme', 'nfs', 'share-a', '{}');
                   INSERT INTO policies (id, name, schedule, gfs, offsite) VALUES (1, 'daily', 'daily 22:00', '{"daily":7,"weekly":0,"monthly":0,"yearly":0}', 0);
                   INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES
                     (1, 'acme', 1, 1, 'g1', '[100,101,102]'), (2, 'globex', 2, 1, 'g2', '[200]'),
                     (3, 'acme', 3, 1, 'g3', '[]');"#,
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
    async fn put(&self, path: &str, s: &S, body: Value) -> R {
        self.call(Method::PUT, path, Some(s), Some(body)).await
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

    fn one<V: catalog::rusqlite::types::FromSql>(&self, sql: &str) -> V {
        self.st.cat.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }
}

#[tokio::test]
async fn search_queues_a_job_rbac_tenant_isolation_and_audit() {
    let t = T::new();
    let (alice, otto, tina, vic, sam) = (
        t.login("alice").await,
        t.login("otto").await,
        t.login("tina").await,
        t.login("vic").await,
        t.login("sam").await,
    );
    let q = |tenant: &str| json!({"tenant": tenant, "query": "*.docx", "source": "share-3", "from": 1, "to": 2});
    for s in [&alice, &otto, &tina] {
        let r = t.post("/api/v1/search", s, q("acme")).await;
        assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
        let id = r.body["id"].as_i64().unwrap();
        let job = t.get(&format!("/api/v1/jobs/{id}"), s).await;
        assert_eq!(job.body["kind"], "file_search");
        assert_eq!(job.body["tenant"], "acme");
        assert_eq!(job.body["params"]["query"], "*.docx");
        assert_eq!(job.body["params"]["limit"], 500);
        assert_eq!(job.body["params"]["case_sensitive"], false);
    }
    // viewers and security officers request no jobs; tenant users only their tenant
    for s in [&vic, &sam] {
        assert_eq!(
            t.post("/api/v1/search", s, q("acme")).await.status,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        t.post("/api/v1/search", &tina, q("globex")).await.status,
        StatusCode::FORBIDDEN
    );
    // a tenant user cannot read another tenant's search
    let r = t.post("/api/v1/search", &alice, q("globex")).await;
    let other = r.body["id"].as_i64().unwrap();
    assert_eq!(
        t.get(&format!("/api/v1/jobs/{other}"), &tina).await.status,
        StatusCode::NOT_FOUND
    );
    for bad in [
        json!({"tenant": "acme", "query": ""}),
        json!({"tenant": "acme", "query": "a".repeat(257)}),
        json!({"tenant": "acme", "query": "a\nb"}),
        json!({"tenant": "acme", "query": "a", "limit": 0}),
        json!({"tenant": "acme", "query": "a", "limit": 2001}),
        json!({"tenant": "acme", "query": "a", "source": "../etc"}),
        json!({"tenant": "acme", "query": "a", "from": 5, "to": 4}),
        json!({"tenant": "acme", "query": "a", "bogus": 1}),
        json!({"tenant": "nope", "query": "a"}),
    ] {
        let r = t.post("/api/v1/search", &alice, bad.clone()).await;
        assert!(r.status.is_client_error(), "{bad}: {:?}", r.body);
    }
    // the query is in the audit trail
    let n: i64 = t
        .one("SELECT COUNT(*) FROM audit WHERE action = 'file.search' AND json_extract(details, '$.query') = '*.docx'");
    assert_eq!(n, 4);
}

#[tokio::test]
async fn index_files_flag_pve_groups_admin_only() {
    let t = T::new();
    let (alice, otto, tina) = (t.login("alice").await, t.login("otto").await, t.login("tina").await);
    let r = t.get("/api/v1/groups", &alice).await;
    assert!(r.body.as_array().unwrap().iter().all(|g| g["index_files"] == false));
    for s in [&otto, &tina] {
        let r = t.put("/api/v1/groups/1/index-files", s, json!({"enabled": true})).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN);
    }
    let r = t
        .put("/api/v1/groups/1/index-files", &alice, json!({"enabled": true}))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body, json!({"id": 1, "index_files": true}));
    let r = t.get("/api/v1/groups", &alice).await;
    let g1 = r
        .body
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["id"] == 1)
        .unwrap()
        .clone();
    assert_eq!(g1["index_files"], true);
    // a share group's files are always indexed: no flag
    let r = t
        .put("/api/v1/groups/3/index-files", &alice, json!({"enabled": true}))
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        t.put("/api/v1/groups/99/index-files", &alice, json!({"enabled": true}))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    let n: i64 = t.one("SELECT COUNT(*) FROM audit WHERE action = 'group.index_files' AND target = 'group/1'");
    assert_eq!(n, 1);
}

/// A stand-in for nexus-index on a Unix socket: records the requests, answers
/// a search with two versions of one VM file and a status.
fn fake_index(dir: &std::path::Path) -> (std::path::PathBuf, Arc<std::sync::Mutex<Vec<Value>>>) {
    use std::io::{BufRead, Write};
    let sock = dir.join("index.sock");
    let l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let s2 = seen.clone();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let mut line = String::new();
            std::io::BufReader::new(&c).read_line(&mut line).unwrap();
            let req: Value = serde_json::from_str(&line).unwrap();
            let out = match req["op"].as_str() {
                Some("search") if req["q"] == "boom" => json!({"err": "q: regex too large"}),
                Some("search") => json!({"ok": {
                    "hits": [{"source": "vm-100", "path": "/home/ann/report.docx", "browse": "vda2/ann/report.docx",
                              "kind": "file", "versions": [
                                  {"size": 9, "mtime": 30, "first": 300},
                                  {"size": 5, "mtime": 10, "first": 100, "gone": 300}]}],
                    "next": "50", "elapsed_ms": 3, "pending": 1,
                    "sources": {"vm-100": {"indexed": [100, 200, 300], "unindexed": [400]}}}}),
                _ => json!({"ok": {"tenants": [{"tenant": "acme", "docs": 2, "bytes": 4096, "sources": 1,
                    "snapshots_indexed": 3, "snapshots_pending": 1, "snapshots_unindexed": 0}],
                    "free_bytes": 1, "floor_bytes": 0, "paused": false, "cache_bytes": 0, "cache_limit": 1}}),
            };
            s2.lock().unwrap().push(req);
            let _ = c.write_all(format!("{out}\n").as_bytes());
        }
    });
    (sock, seen)
}

#[tokio::test]
async fn instant_search_through_nexus_index() {
    let t = T::new();
    let (sock, seen) = fake_index(t._dir.path());
    t.st.index_socket.set(sock).unwrap();
    t.st.cat
        .conn()
        .execute_batch(
            r#"INSERT INTO snapshots (tenant, source, time, size, local, offsite) VALUES
                 ('acme', 'vm-100', 100, 1, 1, 0), ('acme', 'vm-100', 200, 1, 1, 0),
                 ('acme', 'vm-100', 300, 1, 1, 0), ('acme', 'vm-100', 400, 1, 1, 0);
               INSERT INTO snapshot_index (tenant, source, time, state, reason, queued, updated) VALUES
                 ('acme', 'vm-100', 400, 'partial', 'vdb1: BitLocker-encrypted volume', 1, 1),
                 ('acme', 'vm-100', 300, 'indexed', NULL, 1, 1);
               INSERT INTO group_sources (group_id, tenant, source) VALUES (1, 'acme', 'vm-100'), (1, 'acme', 'ct-100');"#,
        )
        .unwrap();
    let (alice, tina, vic) = (t.login("alice").await, t.login("tina").await, t.login("vic").await);
    let r = t.get("/api/v1/files/search?q=report&group=1&ext=.DOCX,pdf&deleted=any", &tina).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let h = &r.body["hits"][0];
    assert_eq!(h["path"], "/home/ann/report.docx");
    // the local, indexed snapshots holding each version
    assert_eq!(h["versions"][0]["times"], json!([300]));
    assert_eq!(h["versions"][1]["times"], json!([200, 100]));
    assert_eq!(r.body["next"], "50");
    let marks = &r.body["snapshots"]["vm-100"];
    assert_eq!(marks[0], json!({"time": 400, "state": "partial", "reason": "vdb1: BitLocker-encrypted volume"}));
    assert_eq!(marks[1], json!({"time": 300, "state": "indexed"}));
    // what nexus-index got: the tenant user's own tenant, the group's sources, clean extensions
    let req = seen.lock().unwrap().last().unwrap().clone();
    assert_eq!(req["tenant"], "acme");
    assert_eq!(req["sources"], json!(["ct-100", "vm-100"]));
    assert_eq!(req["ext"], json!(["docx", "pdf"]));
    // scoping, roles, validation
    assert_eq!(t.get("/api/v1/files/search?q=x&tenant=globex", &tina).await.status, StatusCode::FORBIDDEN);
    assert_eq!(t.get("/api/v1/files/search?q=x&tenant=acme", &vic).await.status, StatusCode::FORBIDDEN);
    assert_eq!(t.get("/api/v1/files/search?q=x", &alice).await.status, StatusCode::BAD_REQUEST, "tenant needed");
    for bad in ["q=", "q=x&mode=regex", "q=x&limit=0", "q=x&source=../x", "q=x&group=2", "q=x&kind=disk", "q=x&bogus=1"] {
        let r = t.get(&format!("/api/v1/files/search?tenant=acme&{bad}"), &alice).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}: {:?}", r.body);
    }
    // errors of the service itself are 400 with its message
    let r = t.get("/api/v1/files/search?tenant=acme&q=boom", &alice).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.body["error"].as_str().unwrap().contains("regex"));
    // audited with the query
    let n: i64 = t.one("SELECT COUNT(*) FROM audit WHERE action = 'file.search' AND json_extract(details, '$.q') = 'report'");
    assert_eq!(n, 1);
    // status for the Storage page
    let r = t.get("/api/v1/files/index-status", &tina).await;
    assert_eq!((r.body["available"].clone(), r.body["tenants"][0]["docs"].clone()), (json!(true), json!(2)));
    assert_eq!(seen.lock().unwrap().last().unwrap()["tenant"], "acme", "tenant users: their tenant");

    // index rules per group
    let r = t.get("/api/v1/groups/1/index-rules", &tina).await;
    assert_eq!((r.body["defaults"].clone(), r.body["include"].clone()), (json!(true), json!([])));
    assert!(r.body["default_excludes"].as_array().unwrap().contains(&json!("/Users/*/AppData")));
    let otto = t.login("otto").await;
    assert_eq!(
        t.put("/api/v1/groups/1/index-rules", &otto, json!({"exclude": ["/srv/tmp"]})).await.status,
        StatusCode::FORBIDDEN
    );
    for bad in [json!({"exclude": ["srv"]}), json!({"include": ["/a/../b"]}), json!({"exclude": vec!["/x"; 65]})] {
        assert_eq!(t.put("/api/v1/groups/1/index-rules", &alice, bad).await.status, StatusCode::BAD_REQUEST);
    }
    let r = t
        .put("/api/v1/groups/1/index-rules", &alice, json!({"defaults": false, "include": ["/var/log/"], "exclude": ["/C/Temp", "/C/Temp"]}))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!((r.body["include"].clone(), r.body["exclude"].clone()), (json!(["/var/log"]), json!(["/C/Temp"])));
    assert_eq!(t.get("/api/v1/groups/2/index-rules", &tina).await.status, StatusCode::NOT_FOUND, "other tenant");
    let n: i64 = t.one("SELECT COUNT(*) FROM audit WHERE action = 'group.index_rules' AND target = 'group/1'");
    assert_eq!(n, 1);
    // the snapshot list carries the index state
    let r = t.get("/api/v1/snapshots?source=vm-100", &alice).await;
    let s400 = r.body.as_array().unwrap().iter().find(|s| s["time"] == 400).unwrap().clone();
    assert_eq!((s400["index_state"].clone(), s400["index_reason"].clone()), (json!("partial"), json!("vdb1: BitLocker-encrypted volume")));
}

#[tokio::test]
async fn search_without_nexus_index_is_503() {
    let t = T::new();
    t.st.index_socket.set(t._dir.path().join("missing.sock")).unwrap();
    let alice = t.login("alice").await;
    let r = t.get("/api/v1/files/search?tenant=acme&q=x", &alice).await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE, "{:?}", r.body);
    let r = t.get("/api/v1/files/index-status", &alice).await;
    assert_eq!(r.body, json!({"available": false}));
}
