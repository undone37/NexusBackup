//! Phase 16a/b hardware: the status of nexus-disks, rescans and SMART self-tests (request
//! files for the helper), the layout requests (typed confirmation, empty disks only, store
//! empty, approval, then the request file), RBAC. The helper is simulated by writing its
//! status.json / ops.json.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use catalog::rusqlite::params;
use catalog::secret::TotpKey;
use catalog::Catalog;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use tower::ServiceExt;
use web_api::AppState;

const PW: &str = "correct horse battery";
const DATA_UUID: &str = "3f0c1a2b:4d5e6f70:81920a1b:2c3d4e5f";

fn pw_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| catalog::auth::hash_password(PW).unwrap())
}

struct T {
    app: Router,
    st: Arc<AppState>,
    secrets: HashMap<String, String>,
    disks: PathBuf,
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

fn hdd(name: &str, serial: &str, role: &str, array: Option<&str>, smart: Value) -> Value {
    json!({"name": name, "path": format!("/dev/{name}"), "model": "WDC WD40EFPX-68C6CN0", "serial": serial,
           "size": 4000787030016_i64, "type": "hdd", "transport": "sata", "rotational": true, "removable": false,
           "role": role, "array": array, "why": null, "wwn": null, "smart": smart})
}

fn smart_ok() -> Value {
    json!({"available": true, "health": "passed", "temperature": 36, "power_on_hours": 15000, "pending": 0,
           "reallocated": 0, "offline_uncorrectable": 0, "self_test": null, "attributes": [], "error": null,
           "standby": false, "checked": 1})
}

/// The fixture host of the helper's tests: system mirror, a degraded RAID6 rebuilding, one empty
/// HDD, one disk with a partition table, two empty NVMe; the store on the array.
fn status(now: i64) -> Value {
    let mut pending = smart_ok();
    pending["pending"] = json!(8);
    pending["reallocated"] = json!(24);
    let mut failed = smart_ok();
    failed["health"] = json!("failed");
    let nvme = |name: &str, serial: &str| {
        json!({"name": name, "path": format!("/dev/{name}"), "model": "Samsung SSD 990 PRO 1TB", "serial": serial,
               "size": 1000204886016_i64, "type": "nvme", "transport": "nvme", "rotational": false, "removable": false,
               "role": "empty", "array": null, "why": null, "wwn": null,
               "smart": {"available": true, "health": "passed", "percentage_used": 3, "critical_warning": 0, "media_errors": 0}})
    };
    let mut sdi = hdd(
        "sdi",
        "ZFL1A2B3",
        "in_use",
        None,
        json!({"available": false, "error": "x"}),
    );
    sdi["why"] = json!("has partitions");
    json!({
        "version": 1, "scanned": now, "smart_scanned": now, "tools": {"smartctl": true, "mdadm": true},
        "store": {"path": "/var/lib/nexus/chunkstore", "array": "md126", "array_uuid": DATA_UUID, "mounted": true, "empty": false},
        "disks": [
            hdd("sda", "S6PN-A", "system", Some("md127"), smart_ok()),
            hdd("sdc", "WD-01", "data", Some("md126"), smart_ok()),
            hdd("sde", "WD-03", "data", Some("md126"), pending),
            hdd("sdf", "WD-04", "data", Some("md126"), failed),
            hdd("sdh", "WD-06", "empty", None, smart_ok()),
            hdd("sdj", "WD-07", "empty", None, smart_ok()),
            hdd("sdk", "WD-08", "empty", None, smart_ok()),
            hdd("sdl", "WD-09", "empty", None, smart_ok()),
            hdd("vdb", "VIRT-1", "empty", None, json!({"available": false, "error": "Unable to detect device type"})),
            sdi,
            nvme("nvme0n1", "S7-1"),
            nvme("nvme1n1", "S7-2"),
        ],
        "arrays": [
            {"name": "md126", "path": "/dev/md126", "md_name": "nexus-data", "uuid": DATA_UUID, "role": "data",
             "level": "raid6", "state": "recovering", "degraded": true, "raid_devices": 4, "active_devices": 3,
             "failed_devices": 1, "spare_devices": 1, "size": 8001574060032_i64, "used_dev_size": 4000587055104_i64,
             "action": "recover", "progress": 24.8, "finish_minutes": 301.2, "mounts": ["/var/lib/nexus/chunkstore"],
             "members": [{"disk": "sdc", "dev": "sdc", "serial": "WD-01", "state": "active", "slot": 0},
                         {"disk": "sdf", "dev": "sdf", "serial": "WD-04", "state": "faulty", "slot": null}]},
            {"name": "md127", "path": "/dev/md127", "md_name": "root", "uuid": "9a8b7c6d:5e4f3a2b:1c0d9e8f:7a6b5c4d",
             "role": "system", "level": "raid1", "state": "clean", "degraded": false, "raid_devices": 2,
             "active_devices": 2, "action": null, "progress": null, "mounts": ["/sysroot"], "members": []}
        ]
    })
}

impl T {
    fn new() -> T {
        let dir = tempfile::tempdir().unwrap();
        let cat = Catalog::open(&dir.path().join("catalog.db")).unwrap();
        let downloads = dir.path().join("downloads");
        std::fs::create_dir(&downloads).unwrap();
        let st = AppState::with_keys(cat, None, downloads, TotpKey::generate(), None);
        let disks = dir.path().join("disks");
        std::fs::create_dir(&disks).unwrap();
        st.disks_dir.set(disks.clone()).unwrap();
        st.cat
            .conn()
            .execute("INSERT INTO tenants (name) VALUES ('acme')", [])
            .unwrap();
        let mut secrets = HashMap::new();
        for (n, role, tenant) in [
            ("alice", "admin", None),
            ("ada", "admin", None),
            ("sam", "security_officer", None),
            ("otto", "operator", None),
            ("vic", "viewer", None),
            ("vera", "viewer", Some("acme")),
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
            secrets,
            disks,
            _dir: dir,
        }
    }

    fn helper_status(&self, s: &Value) {
        std::fs::write(self.disks.join("status.json"), s.to_string()).unwrap();
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
        let raw = res.into_body().collect().await.unwrap().to_bytes().to_vec();
        R {
            status,
            body: serde_json::from_slice(&raw).unwrap_or(Value::Null),
        }
    }

    async fn get(&self, path: &str, s: &S) -> R {
        self.call(Method::GET, path, Some(s), None).await
    }
    async fn post(&self, path: &str, s: &S, body: Value) -> R {
        self.call(Method::POST, path, Some(s), Some(body)).await
    }

    /// The request files nexus-disks would pick up.
    fn requests(&self) -> Vec<Value> {
        let mut v: Vec<Value> = std::fs::read_dir(&self.disks)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("req-"))
            .map(|e| serde_json::from_slice(&std::fs::read(e.path()).unwrap()).unwrap())
            .collect();
        v.sort_by_key(|r| r["op"].as_str().unwrap_or_default().to_owned());
        v
    }

    fn clear_requests(&self) {
        for r in self.requests() {
            std::fs::remove_file(self.disks.join(format!("req-{}.json", r["id"].as_str().unwrap()))).unwrap();
        }
    }

    fn audit_count(&self, action: &str) -> i64 {
        self.st
            .cat
            .conn()
            .query_row("SELECT COUNT(*) FROM audit WHERE action = ?1", [action], |r| r.get(0))
            .unwrap()
    }
}

/// Logs in through the real endpoint (cookie from Set-Cookie).
async fn login(t: &T, name: &str) -> S {
    let code = catalog::auth::totp_now(&t.secrets[name]).unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/login")
        .header(header::HOST, "nexus.test")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"name": name, "password": PW, "totp": code}).to_string(),
        ))
        .unwrap();
    let res = t.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK, "{name}");
    let cookie = res
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| c.strip_prefix("nx_session=")?.split(';').next().map(str::to_owned))
        .unwrap();
    let raw = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&raw).unwrap();
    S {
        cookie,
        csrf: body["csrf"].as_str().unwrap().to_owned(),
    }
}

#[tokio::test]
async fn status_summary_and_roles() {
    let t = T::new();
    let (alice, sam, otto, vic, vera, tina) = (
        login(&t, "alice").await,
        login(&t, "sam").await,
        login(&t, "otto").await,
        login(&t, "vic").await,
        login(&t, "vera").await,
        login(&t, "tina").await,
    );
    // no status yet
    let r = t.get("/api/v1/hardware", &alice).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(
        (r.body["available"].clone(), r.body["summary"]["state"].clone()),
        (json!(false), json!("unknown"))
    );
    t.helper_status(&status(catalog::now()));
    std::fs::write(
        t.disks.join("ops.json"),
        json!([{"id": "a".repeat(32), "op": "selftest", "by": "alice", "quorum_id": null, "state": "done", "created": 10,
                "finished": 11, "detail": "short self-test started", "error": null, "params": {}}])
        .to_string(),
    )
    .unwrap();
    for s in [&alice, &sam, &otto, &vic] {
        let r = t.get("/api/v1/hardware", s).await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    }
    for s in [&vera, &tina] {
        assert_eq!(t.get("/api/v1/hardware", s).await.status, StatusCode::FORBIDDEN);
    }
    let r = t.get("/api/v1/hardware", &vic).await.body;
    assert_eq!(r["available"], true);
    assert_eq!(r["stale"], false);
    assert_eq!(r["summary"]["state"], "critical");
    assert_eq!(r["summary"]["critical"], 2); // sdf failing, md126 degraded
    assert_eq!(r["summary"]["warnings"], 1); // sde sectors
    let sde = r["disks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == "sde")
        .unwrap();
    assert_eq!(sde["issues"][0]["severity"], "warning");
    let md = &r["arrays"][0];
    assert_eq!(md["issues"][0]["severity"], "critical");
    assert_eq!(md["issues"][1]["message"], "rebuilding 24.8 % (about 301 min left)");
    assert_eq!(r["ops"][0]["op"], "selftest");
    // stale
    t.helper_status(&status(catalog::now() - 3600));
    assert_eq!(t.get("/api/v1/hardware", &vic).await.body["stale"], true);
}

#[tokio::test]
async fn scan_and_selftest() {
    let t = T::new();
    let (alice, sam, otto) = (
        login(&t, "alice").await,
        login(&t, "sam").await,
        login(&t, "otto").await,
    );
    t.helper_status(&status(catalog::now()));
    assert_eq!(
        t.post("/api/v1/hardware/scan", &sam, json!({})).await.status,
        StatusCode::FORBIDDEN
    );
    let r = t.post("/api/v1/hardware/scan", &otto, json!({})).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    assert_eq!(t.requests()[0]["op"], "scan");
    assert_eq!(t.audit_count("hardware.scan"), 1);
    // queued requests show up as operations
    let ops = t.get("/api/v1/hardware", &otto).await.body["ops"].clone();
    assert_eq!(
        (ops[0]["op"].clone(), ops[0]["state"].clone()),
        (json!("scan"), json!("queued"))
    );
    t.clear_requests();

    let st = |disk: &str, kind: &str| json!({"disk": disk, "type": kind});
    assert_eq!(
        t.post("/api/v1/hardware/selftest", &otto, st("WD-01", "short"))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.post("/api/v1/hardware/selftest", &alice, st("WD-01", "conveyance"))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        t.post("/api/v1/hardware/selftest", &alice, st("NOPE", "short"))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        t.post("/api/v1/hardware/selftest", &alice, st("VIRT-1", "short"))
            .await
            .status,
        StatusCode::CONFLICT
    );
    let r = t.post("/api/v1/hardware/selftest", &alice, st("WD-01", "long")).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = &t.requests()[0];
    assert_eq!(
        (q["op"].clone(), q["disk"].clone(), q["type"].clone(), q["by"].clone()),
        (json!("selftest"), json!("WD-01"), json!("long"), json!("alice"))
    );
    assert_eq!(t.audit_count("hardware.selftest"), 1);
    // request files are group-readable for the helper (the web-api runs with UMask=0077)
    use std::os::unix::fs::PermissionsExt;
    let f = std::fs::read_dir(&t.disks)
        .unwrap()
        .filter_map(Result::ok)
        .find(|e| e.file_name().to_string_lossy().starts_with("req-"))
        .unwrap();
    assert_eq!(f.metadata().unwrap().permissions().mode() & 0o777, 0o640);
}

fn create(disks: &[&str], confirm: &str) -> Value {
    json!({"role": "data", "level": "raid6", "disks": disks, "confirm": confirm})
}

#[tokio::test]
async fn create_array_checks_and_approval() {
    let t = T::new();
    let (alice, ada, sam, otto) = (
        login(&t, "alice").await,
        login(&t, "ada").await,
        login(&t, "sam").await,
        login(&t, "otto").await,
    );
    // a fresh appliance: the HDDs empty, no data array, empty store
    let mut s = status(catalog::now());
    s["arrays"].as_array_mut().unwrap().remove(0);
    s["store"] = json!({"path": "/var/lib/nexus/chunkstore", "array": null, "mounted": false, "empty": true});
    for d in s["disks"].as_array_mut().unwrap() {
        if d["role"] == "data" {
            d["role"] = json!("empty");
            d["array"] = Value::Null;
        }
    }
    t.helper_status(&s);
    let four = ["WD-01", "WD-03", "WD-06", "WD-07"];
    let url = "/api/v1/hardware/arrays";
    assert_eq!(
        t.post(url, &otto, create(&four, "WD-01 WD-03 WD-06 WD-07"))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.post(url, &sam, create(&four, "WD-01 WD-03 WD-06 WD-07")).await.status,
        StatusCode::FORBIDDEN
    );
    // typed confirmation: every selected serial, nothing else
    let r = t.post(url, &alice, create(&four, "WD-01 WD-03 WD-06")).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.body["error"].as_str().unwrap().contains("type the serial numbers"));
    // levels, counts, roles
    let bad = [
        (
            json!({"role": "metadata", "level": "raid1", "disks": ["S7-1", "S7-2"], "confirm": "S7-1 S7-2"}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"role": "data", "level": "raid0", "disks": four, "confirm": "WD-01 WD-03 WD-06 WD-07"}),
            StatusCode::BAD_REQUEST,
        ),
        (create(&four[..3], "WD-01 WD-03 WD-06"), StatusCode::BAD_REQUEST),
        (
            json!({"role": "data", "level": "raid10", "disks": ["WD-01", "WD-03", "WD-06", "WD-07", "WD-08"],
                "confirm": "WD-01 WD-03 WD-06 WD-07 WD-08"}),
            StatusCode::BAD_REQUEST,
        ),
        (
            create(&["S6PN-A", "WD-03", "WD-06", "WD-07"], "S6PN-A WD-03 WD-06 WD-07"),
            StatusCode::CONFLICT,
        ),
        (
            create(&["ZFL1A2B3", "WD-03", "WD-06", "WD-07"], "ZFL1A2B3 WD-03 WD-06 WD-07"),
            StatusCode::CONFLICT,
        ),
        (
            create(&["NOPE", "WD-03", "WD-06", "WD-07"], "NOPE WD-03 WD-06 WD-07"),
            StatusCode::NOT_FOUND,
        ),
    ];
    for (body, want) in bad {
        let r = t.post(url, &alice, body.clone()).await;
        assert_eq!(r.status, want, "{body}: {:?}", r.body);
    }
    let r = t
        .post(
            url,
            &alice,
            create(&["S6PN-A", "WD-03", "WD-06", "WD-07"], "S6PN-A WD-03 WD-06 WD-07"),
        )
        .await;
    assert!(
        r.body["error"].as_str().unwrap().contains("is not empty: system"),
        "{:?}",
        r.body
    );
    // a store with backups: refused
    s["store"]["empty"] = json!(false);
    t.helper_status(&s);
    let r = t.post(url, &alice, create(&four, "WD-07 WD-06 WD-03 WD-01")).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert!(r.body["error"].as_str().unwrap().contains("the store is not empty"));
    s["store"]["empty"] = json!(true);
    t.helper_status(&s);
    assert!(t.requests().is_empty());

    // approvals on (default): pending, nothing for the helper yet
    let r = t.post(url, &alice, create(&four, "WD-07, WD-06, WD-03, WD-01")).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let qid = r.body["quorum_id"].as_i64().unwrap();
    assert!(t.requests().is_empty());
    let q = &t.get("/api/v1/quorum", &sam).await.body[0];
    assert_eq!(q["action"], "disks.create_array");
    assert_eq!(q["params"]["disk_info"][0]["model"], "WDC WD40EFPX-68C6CN0");
    // not the requester
    assert_eq!(
        t.post(&format!("/api/v1/quorum/{qid}/approve"), &alice, json!({}))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let r = t.post(&format!("/api/v1/quorum/{qid}/approve"), &ada, json!({})).await;
    assert_eq!(
        (r.status, r.body["state"].clone()),
        (StatusCode::OK, json!("executed")),
        "{:?}",
        r.body
    );
    let req = t.requests();
    assert_eq!(req.len(), 1);
    let q = &req[0];
    assert_eq!(
        (q["op"].clone(), q["by"].clone(), q["quorum_id"].clone()),
        (json!("create_array"), json!("alice"), json!(qid))
    );
    assert_eq!(
        (q["role"].clone(), q["level"].clone(), q["disks"].clone()),
        (json!("data"), json!("raid6"), json!(four))
    );
    assert!(q.get("disk_info").is_none());
    assert_eq!(t.audit_count("disks.create_array"), 1);
}

#[tokio::test]
async fn array_operations() {
    let t = T::new();
    let alice = login(&t, "alice").await;
    t.helper_status(&status(catalog::now()));
    catalog::set_setting(&t.st.cat.conn(), "approvals_enabled", "false").unwrap();
    let url = |name: &str, op: &str| format!("/api/v1/hardware/arrays/{name}/{op}");
    let body = |disk: &str| json!({"disk": disk, "confirm": disk});
    // system arrays are shown only; unknown arrays 404
    assert_eq!(
        t.post(&url("md127", "spare"), &alice, body("WD-06")).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        t.post(&url("md9", "spare"), &alice, body("WD-06")).await.status,
        StatusCode::NOT_FOUND
    );
    // confirmation of the new disk
    assert_eq!(
        t.post(
            &url("md126", "spare"),
            &alice,
            json!({"disk": "WD-06", "confirm": "WD-07"})
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
    // too small (NVMe 1 TB for 4 TB members), not empty, a member
    assert_eq!(
        t.post(&url("md126", "spare"), &alice, body("S7-1")).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        t.post(&url("md126", "spare"), &alice, body("WD-01")).await.status,
        StatusCode::CONFLICT
    );
    // grow only a clean array
    let r = t.post(&url("md126", "grow"), &alice, body("WD-06")).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert!(r.body["error"].as_str().unwrap().contains("grow only a clean array"));
    // replace: approvals disabled -> executed at once, the request is written
    let r = t
        .post(
            &url("md126", "replace"),
            &alice,
            json!({"disk": "WD-06", "confirm": "WD-06", "failed": "WD-04"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        (r.body["approvals"].clone(), r.body["executed"].clone()),
        (json!("disabled"), json!(true))
    );
    let q = &t.requests()[0];
    assert_eq!(
        (
            q["op"].clone(),
            q["array"].clone(),
            q["disk"].clone(),
            q["failed"].clone(),
            q["quorum_id"].clone()
        ),
        (
            json!("replace"),
            json!(DATA_UUID),
            json!("WD-06"),
            json!("WD-04"),
            Value::Null
        )
    );
    assert!(q.get("array_name").is_none());
    t.clear_requests();
    // a non-member to replace
    let r = t
        .post(
            &url("md126", "replace"),
            &alice,
            json!({"disk": "WD-06", "confirm": "WD-06", "failed": "WD-99"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    // spare
    assert_eq!(
        t.post(&url("md126", "spare"), &alice, body("WD-06")).await.status,
        StatusCode::OK
    );
    assert_eq!(t.requests()[0]["op"], "add_spare");
    t.clear_requests();
    // grow a clean raid6
    let mut s = status(catalog::now());
    s["arrays"][0]["state"] = json!("clean");
    s["arrays"][0]["degraded"] = json!(false);
    s["arrays"][0]["action"] = Value::Null;
    t.helper_status(&s);
    assert_eq!(
        t.post(&url("md126", "grow"), &alice, body("WD-06")).await.status,
        StatusCode::OK
    );
    assert_eq!(t.requests()[0]["op"], "grow");
    assert_eq!(t.audit_count("disks.grow"), 1);
}

#[tokio::test]
async fn token_may_read_hardware_only() {
    assert!(web_api::tokens::allowed(false, &Method::GET, "/hardware"));
    assert!(!web_api::tokens::allowed(true, &Method::POST, "/hardware/scan"));
    assert!(!web_api::tokens::allowed(true, &Method::POST, "/hardware/arrays"));
}
