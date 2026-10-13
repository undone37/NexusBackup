//! Phase 22b: source concurrency caps and read limits, the restore-priority
//! switch, TrueNAS "use existing snapshots", NAS sizing / overlap / split /
//! skipped-files CSV, instant disk recovery requests.

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
    text: String,
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
                     (2, 'globex', 'pve', 'pve-g', '{}');
                   INSERT INTO policies (id, name, schedule, gfs, offsite) VALUES (1, 'daily', 'daily 22:00', '{"daily":7,"weekly":0,"monthly":0,"yearly":0}', 0);
                   INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES
                     (1, 'acme', 1, 1, 'g1', '[100,101,102]'), (2, 'globex', 2, 1, 'g2', '[200]');"#,
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
            text: String::from_utf8_lossy(&raw).into_owned(),
        }
    }

    async fn get(&self, path: &str, s: &S) -> R {
        self.call(Method::GET, path, Some(s), None).await
    }
    async fn post(&self, path: &str, s: &S, body: Value) -> R {
        self.call(Method::POST, path, Some(s), Some(body)).await
    }
    async fn delete(&self, path: &str, s: &S) -> R {
        self.call(Method::DELETE, path, Some(s), None).await
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

    fn exec(&self, sql: &str) {
        self.st.cat.conn().execute_batch(sql).unwrap();
    }

    fn one<V: catalog::rusqlite::types::FromSql>(&self, sql: &str) -> V {
        self.st.cat.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }
}

fn pve_cfg() -> Value {
    json!({
        "host": "pve1.lab.local", "port": 8006,
        "ca_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        "token_id": "nexus@pve!backup", "token_secret": "s3cr3t",
        "nodes": {"pve1": {"host": "10.0.0.1", "port": 22, "key": "/etc/nexus/ssh/id", "known_hosts": "/etc/nexus/ssh/kh"}},
        "storage": "nexus"
    })
}

#[tokio::test]
async fn restore_priority_switch() {
    let t = T::new();
    let (alice, otto, tina) = (t.login("alice").await, t.login("otto").await, t.login("tina").await);
    let r = t.get("/api/v1/restore-priority", &tina).await;
    assert_eq!((r.status, r.body["active"].clone()), (StatusCode::OK, json!(false)));
    assert_eq!(r.body["max_hours"], 24);
    let on = json!({"hours": 4, "reason": "DR of the ERP cluster"});
    assert_eq!(
        t.put("/api/v1/restore-priority", &tina, on.clone()).await.status,
        StatusCode::FORBIDDEN
    );
    for bad in [json!({"hours": 0}), json!({"hours": 25}), json!({"hours": 2, "x": 1})] {
        assert!(
            t.put("/api/v1/restore-priority", &otto, bad.clone())
                .await
                .status
                .is_client_error(),
            "{bad}"
        );
    }
    let r = t.put("/api/v1/restore-priority", &otto, on.clone()).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        (r.body["active"].clone(), r.body["by"].clone()),
        (json!(true), json!("otto"))
    );
    let until = r.body["until"].as_i64().unwrap();
    assert!((until - catalog::now() - 4 * 3600).abs() < 5);
    let since = r.body["since"].as_i64().unwrap();
    // renewal keeps `since`, audited as renewed
    let r = t.put("/api/v1/restore-priority", &alice, json!({"hours": 24})).await;
    assert_eq!(r.body["since"].as_i64(), Some(since));
    assert_eq!(r.body["by"], "alice");
    let r = t.get("/api/v1/restore-priority", &tina).await;
    assert_eq!(r.body["active"], true, "everyone sees the banner");
    let n: i64 = t.one("SELECT COUNT(*) FROM audit WHERE action = 'restore_priority.on'");
    assert_eq!(n, 2);
    let renewed: i64 = t.one(
        "SELECT COUNT(*) FROM audit WHERE action = 'restore_priority.on' AND json_extract(details, '$.renewed') = 1",
    );
    assert_eq!(renewed, 1);
    assert_eq!(
        t.delete("/api/v1/restore-priority", &tina).await.status,
        StatusCode::FORBIDDEN
    );
    let r = t.delete("/api/v1/restore-priority", &otto).await;
    assert_eq!((r.status, r.body["active"].clone()), (StatusCode::OK, json!(false)));
    let n: i64 = t.one("SELECT COUNT(*) FROM audit WHERE action = 'restore_priority.off'");
    assert_eq!(n, 1);
    // an expired switch reads as off
    t.exec(r#"INSERT INTO settings (key, value) VALUES ('restore_priority', '{"until": 1, "since": 0, "by": "x"}')"#);
    assert_eq!(t.get("/api/v1/restore-priority", &otto).await.body["active"], false);
}

#[tokio::test]
async fn source_caps_and_read_limits() {
    let t = T::new();
    let alice = t.login("alice").await;
    let src = |cfg: Value| json!({"tenant": "acme", "kind": "pve", "name": "pve-x", "config": cfg});
    for (k, v) in [
        ("max_parallel", json!(0)),
        ("max_parallel", json!(9)),
        ("storage_caps", json!({"ceph": 0})),
        ("storage_caps", json!({"bad name": 1})),
        ("read_limit", json!({"bwlimit": 0})),
        (
            "read_limit",
            json!({"windows": [{"from": "08:00", "to": "18:00", "action": "pause"}]}),
        ),
        ("read_limit", json!({"timezone": "Nowhere/City"})),
        ("read_limit", json!({"rate": 1})),
    ] {
        let mut c = pve_cfg();
        c[k] = v.clone();
        let r = t.post("/api/v1/sources", &alice, src(c)).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{k}={v}: {:?}", r.body);
    }
    let mut c = pve_cfg();
    c["max_parallel"] = json!(3);
    c["storage_caps"] = json!({"ceph-ssd": 2});
    c["read_limit"] = json!({"bwlimit": 200_000_000, "timezone": "Europe/Berlin",
        "windows": [{"days": ["Mon","Tue","Wed","Thu","Fri"], "from": "07:00", "to": "19:00", "action": "limit", "rate_bytes": 50_000_000}]});
    let r = t.post("/api/v1/sources", &alice, src(c)).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["config"]["max_parallel"], 3);
    assert_eq!(r.body["config"]["storage_caps"]["ceph-ssd"], 2);
    assert_eq!(r.body["config"]["read_limit"]["windows"][0]["rate_bytes"], 50_000_000);
    // shares take a read limit too
    let smb = json!({"host": "fs1.lab", "share": "Data", "user": "backup", "password": "pw",
                     "read_limit": {"bwlimit": 10_000_000}});
    let r = t
        .post(
            "/api/v1/sources",
            &alice,
            json!({"tenant": "acme", "kind": "smb", "name": "s", "config": smb}),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["config"]["read_limit"]["bwlimit"], 10_000_000);
}

fn truenas_cfg() -> Value {
    json!({
        "host": "nas.lab", "port": 443, "connect_addr": "192.0.2.20:443",
        "ca_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        "user": "nexusbackup", "token_secret": "1-key",
        "ssh": {"host": "192.0.2.20", "port": 22, "user": "nexusbackup",
                "host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostKey",
                "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIApplianceKey nexus@appliance",
                "key_pem": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn\n-----END OPENSSH PRIVATE KEY-----\n"},
        "datasets": ["tank/data"], "recursive": true
    })
}

#[tokio::test]
async fn truenas_existing_snapshots() {
    let t = T::new();
    let alice = t.login("alice").await;
    let src = |cfg: Value| json!({"tenant": "acme", "kind": "truenas", "name": "nas", "config": cfg});
    for bad in ["", "-auto", "auto snap", "a/b", "x".repeat(33).as_str()] {
        let mut c = truenas_cfg();
        c["existing_snapshots"] = json!(bad);
        assert_eq!(
            t.post("/api/v1/sources", &alice, src(c)).await.status,
            StatusCode::BAD_REQUEST,
            "{bad:?}"
        );
    }
    let r = t.post("/api/v1/sources", &alice, src(truenas_cfg())).await;
    assert!(!r.body["config"]["authorized_keys"]
        .as_str()
        .unwrap()
        .contains("E=\\\"auto-"));
    let mut c = truenas_cfg();
    c["existing_snapshots"] = json!("auto-");
    c["read_limit"] = json!({"bwlimit": 1_000_000});
    let mut s = src(c);
    s["name"] = json!("nas2");
    let r = t.post("/api/v1/sources", &alice, s).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["config"]["existing_snapshots"], "auto-");
    // the forced command must allow the periodic snapshots: re-paste the line on TrueNAS
    let line = r.body["config"]["authorized_keys"].as_str().unwrap();
    assert!(line.contains("E=\\\"auto-\\\""), "{line}");
}

#[tokio::test]
async fn nas_overlap_split_sizing_and_skipped_csv() {
    let t = T::new();
    let (alice, tina) = (t.login("alice").await, t.login("tina").await);
    let smb = json!({"host": "fs1.lab", "share": "Data", "user": "backup", "password": "pw",
                     "include": ["/projects", "/home"]});
    let r = t
        .post(
            "/api/v1/sources",
            &alice,
            json!({"tenant": "acme", "kind": "smb", "name": "data", "config": smb}),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let id = r.body["id"].as_i64().unwrap();
    t.exec(&format!(
        "INSERT INTO groups (tenant, source_id, policy_id, name, guests, timezone) VALUES ('acme', {id}, 1, 'files', '[]', 'Europe/Berlin')"
    ));
    let url = format!("/api/v1/sources/{id}/split");
    for (b, why) in [
        (json!({"roots": ["/projects"], "password": "pw"}), "one root"),
        (
            json!({"roots": ["/projects/a", "/projects"], "password": "pw"}),
            "overlapping roots",
        ),
        (
            json!({"roots": ["/projects/a", "/srv"], "password": "pw"}),
            "outside the include roots",
        ),
        (json!({"roots": ["/projects/a", "/home"]}), "SMB without the password"),
    ] {
        let r = t.post(&url, &alice, b).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{why}: {:?}", r.body);
    }
    assert_eq!(
        t.post(
            &url,
            &tina,
            json!({"roots": ["/projects/a", "/home"], "password": "pw"})
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    let r = t
        .post(
            &url,
            &alice,
            json!({"roots": ["/projects/a", "/home"], "password": "pw"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let ids: Vec<i64> = r.body["sources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_i64().unwrap())
        .collect();
    assert_eq!(ids.len(), 2);
    let g: (String, i64, String) =
        t.st.cat
            .conn()
            .query_row(
                &format!(
                    "SELECT name, policy_id, timezone FROM groups WHERE source_id = {}",
                    ids[0]
                ),
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
    assert_eq!(
        g,
        ("files-1".to_string(), 1, "Europe/Berlin".to_string()),
        "group copied"
    );
    let n: i64 = t.one("SELECT COUNT(*) FROM audit WHERE action = 'source.split'");
    assert_eq!(n, 1);
    // the list warns: the original still covers both new sources
    t.exec(&format!(
        "INSERT INTO jobs (kind, tenant, params, state, requested_by, created, result, log) VALUES
           ('backup', 'acme', '{{}}', 'ok', 'scheduler', 1,
            '{{\"snapshots\":[{{\"source\":\"share-{id}\",\"time\":1,\"entries\":2500000}}]}}',
            'error docs/x: open: Permission denied\nerror note: mnt: nested mount\ncommitted share-{id}/1 in 1s: 2500000 entries, 0 inconsistent, 3 errors, 1 entries/s, live share\n')"
    ));
    let job: i64 = t.one("SELECT MAX(id) FROM jobs");
    let list = t.get("/api/v1/sources", &alice).await.body;
    let row = |sid: i64| {
        list.as_array()
            .unwrap()
            .iter()
            .find(|s| s["id"] == sid)
            .unwrap()
            .clone()
    };
    let orig = row(id);
    let over: Vec<i64> = orig["overlaps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["id"].as_i64().unwrap())
        .collect();
    assert_eq!(over, ids);
    assert_eq!(row(ids[0])["overlaps"][0]["id"], id);
    assert!(
        row(ids[0])["overlaps"].as_array().unwrap().len() == 1,
        "/projects/a and /home do not overlap"
    );
    assert_eq!(orig["sizing"]["entries"], 2_500_000);
    assert_eq!(orig["sizing"]["est_ram_bytes"], 2_500_000u64 * 800);
    assert!(row(ids[1])["sizing"].is_null());
    // skipped files of that run as CSV
    let r = t.get(&format!("/api/v1/jobs/{job}/skipped.csv"), &tina).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(
        r.text,
        "path,reason,kind\r\ndocs/x,open: Permission denied,error\r\nmnt,nested mount,note\r\n,2 more not listed (the connector lists the first 1; the job log may be truncated),error\r\n"
    );
    t.exec("INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES ('backup', 'globex', '{}', 'ok', 'x', 1)");
    let other: i64 = t.one("SELECT MAX(id) FROM jobs");
    assert_eq!(
        t.get(&format!("/api/v1/jobs/{other}/skipped.csv"), &tina).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn instant_disk_requests() {
    let t = T::new();
    let tina = t.login("tina").await;
    t.exec("INSERT INTO snapshots (tenant, source, time, local, offsite) VALUES ('acme', 'vm-100', 1700000000, 1, 0)");
    let ok = json!({"source": "vm-100", "time": 1700000000, "device": "drive-scsi1", "node": "pve1", "target": 101,
                    "key": "scsi5", "move_to": "local-lvm"});
    for (k, v) in [
        ("device", json!("config")),
        ("device", json!("drive-efidisk0")),
        ("key", json!("tpmstate0")),
        ("source", json!("ct-100")),
        ("time", json!(1)),
        ("target", json!(0)),
        ("move_to", json!("a b")),
    ] {
        let mut p = ok.clone();
        p[k] = v.clone();
        let r = t
            .post(
                "/api/v1/jobs",
                &tina,
                json!({"kind": "instant_disk", "tenant": "acme", "params": p}),
            )
            .await;
        assert!(r.status.is_client_error(), "{k}={v}: {:?}", r.body);
    }
    let r = t
        .post(
            "/api/v1/jobs",
            &tina,
            json!({"kind": "instant_disk", "tenant": "acme", "params": ok}),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let p: String = t.one("SELECT params FROM jobs WHERE kind = 'instant_disk'");
    assert!(
        p.contains("\"key\":\"scsi5\"") && p.contains("\"move_to\":\"local-lvm\""),
        "{p}"
    );
}
