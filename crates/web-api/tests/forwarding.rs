//! Phase 14a: Settings → Forwarding (sealed headers, weakening through
//! approval), the forwarding status, audit filters and the CSV export.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use catalog::rusqlite::params;
use catalog::secret::{SchedulerKey, TotpKey};
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
    sk: SchedulerKey,
    _dir: tempfile::TempDir,
}

struct S {
    cookie: String,
    csrf: String,
}

struct R {
    status: StatusCode,
    body: Value,
    text: String,
    content_type: String,
    cookie: Option<String>,
}

impl T {
    fn new() -> T {
        let dir = tempfile::tempdir().unwrap();
        let cat = Catalog::open(&dir.path().join("catalog.db")).unwrap();
        let downloads = dir.path().join("downloads");
        std::fs::create_dir(&downloads).unwrap();
        let sk = SchedulerKey::generate();
        let secrets_pub = dir.path().join("secrets.pub");
        sk.write_public(&secrets_pub, None).unwrap();
        let st = AppState::with_keys(cat, None, downloads, TotpKey::generate(), Some(secrets_pub));
        let mut secrets = HashMap::new();
        for (n, role) in [
            ("alice", "admin"),
            ("adam", "admin"),
            ("sam", "security_officer"),
            ("otto", "operator"),
        ] {
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
        T {
            app: web_api::router(st.clone()),
            st,
            secrets,
            sk,
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
        let content_type = res
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
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
            text: String::from_utf8_lossy(&raw).into_owned(),
            content_type,
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

    fn setting(&self) -> Value {
        let raw = catalog::setting(&self.st.cat.conn(), "forwarding").unwrap().unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    fn audit_details(&self, action: &str) -> Vec<String> {
        self.st
            .cat
            .conn()
            .prepare("SELECT details FROM audit WHERE action = ?1 ORDER BY seq")
            .unwrap()
            .query_map([action], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }
}

const PIN: &str = "AB:CD:ef:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc";

#[tokio::test]
async fn forwarding_settings_sealing_and_weakening_approval() {
    let t = T::new();
    let (alice, adam, sam, otto) = (
        t.login("alice").await,
        t.login("adam").await,
        t.login("sam").await,
        t.login("otto").await,
    );
    assert_eq!(
        t.get("/api/v1/settings/forwarding", &otto).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.get("/api/v1/audit/forwarding", &otto).await.status,
        StatusCode::FORBIDDEN
    );
    let r = t.get("/api/v1/settings/forwarding", &sam).await;
    assert_eq!(
        (r.status, r.body.clone()),
        (StatusCode::OK, json!({"syslog": null, "https": null}))
    );
    let url = "https://siem.example/ingest";
    let cfg = json!({
        "syslog": {"host": "log.example", "pin_sha256": PIN},
        "https": {"url": url, "headers": {"Authorization": "Bearer s3cret"}, "batch_max": 50}
    });
    assert_eq!(
        t.put("/api/v1/settings/forwarding", &sam, cfg.clone()).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.post("/api/v1/settings/forwarding/test", &otto, json!({}))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    for (path, v) in [
        ("/https/url", json!("http://siem.example/x")),
        ("/https/url", json!("https://u:p@siem.example/x")),
        ("/https/batch_max", json!(0)),
        ("/syslog/pin_sha256", json!("abc")),
        ("/syslog/ca_pem", json!("-----BEGIN NOTHING-----")),
        ("/syslog/facility", json!(24)),
        ("/syslog/host", json!("bad host")),
        ("/syslog/app_name", json!("two words")),
        ("/https/format", json!("xml")),
        ("/https/index", json!("main")), // json_array has no index
    ] {
        let mut b = cfg.clone();
        let (sink, field) = path[1..].split_once('/').unwrap();
        b[sink][field] = v.clone();
        let r = t.put("/api/v1/settings/forwarding", &alice, b).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{path}={v}: {:?}", r.body);
    }
    // adding sinks applies at once; header sealed (opens at its URL), shown as null
    let r = t.put("/api/v1/settings/forwarding", &alice, cfg.clone()).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["https"]["headers"], json!({"Authorization": null}));
    assert_eq!(r.body["syslog"]["port"], 6514);
    assert_eq!(r.body["syslog"]["pin_sha256"], PIN.replace(':', "").to_lowercase());
    let stored = t.setting();
    let sealed = stored["https"]["headers"]["Authorization"].as_str().unwrap().to_owned();
    assert!(catalog::secret::is_sealed(&sealed));
    let loc = catalog::forwarding::header_location("Authorization", url);
    assert_eq!(&*t.sk.open(&loc, &sealed).unwrap(), "Bearer s3cret");
    assert!(t
        .audit_details("settings.forwarding")
        .iter()
        .all(|d| !d.contains("s3cret") && !d.contains("sealed:")));
    let r = t.get("/api/v1/settings/forwarding", &sam).await;
    assert_eq!(r.body["https"]["headers"], json!({"Authorization": null}));

    // header kept with null; format options apply at once
    let mut keep = cfg.clone();
    keep["https"]["headers"]["Authorization"] = Value::Null;
    keep["syslog"]["facility"] = json!(16);
    let r = t.put("/api/v1/settings/forwarding", &alice, keep.clone()).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(t.setting()["https"]["headers"]["Authorization"], json!(sealed));
    // Splunk HEC body with an index: a format option too (no approval)
    let mut hec = keep.clone();
    hec["https"]["format"] = json!("splunk_hec");
    hec["https"]["index"] = json!("Main");
    assert_eq!(
        t.put("/api/v1/settings/forwarding", &alice, hec.clone()).await.status,
        StatusCode::BAD_REQUEST,
        "Splunk index names are lower-case"
    );
    hec["https"]["index"] = json!("nexus_audit");
    let r = t.put("/api/v1/settings/forwarding", &alice, hec).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        (r.body["https"]["format"].as_str(), r.body["https"]["index"].as_str()),
        (Some("splunk_hec"), Some("nexus_audit"))
    );
    let r = t.put("/api/v1/settings/forwarding", &alice, keep.clone()).await;
    assert_eq!(
        (r.status, r.body["https"]["format"].as_str()),
        (StatusCode::OK, Some("json_array"))
    );
    assert!(r.body["https"].get("index").is_none());
    // null with a changed URL: a value is required
    let mut moved = keep.clone();
    moved["https"]["url"] = json!("https://other.example/in");
    assert_eq!(
        t.put("/api/v1/settings/forwarding", &alice, moved).await.status,
        StatusCode::BAD_REQUEST
    );

    // weakening: disabling syslog needs approval
    let mut off = keep.clone();
    off["syslog"]["enabled"] = json!(false);
    let r = t.put("/api/v1/settings/forwarding", &alice, off.clone()).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let q = r.body["quorum_id"].as_i64().unwrap();
    assert_eq!(t.setting()["syslog"]["enabled"], true, "unchanged until approved");
    let list = t.get("/api/v1/quorum?state=pending", &sam).await;
    let shown = list.body[0]["params"].to_string();
    assert!(!shown.contains("sealed:"), "{shown}");
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &alice, json!({})).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "not by the requester");
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(
        (r.status, r.body["state"].as_str()),
        (StatusCode::OK, Some("executed")),
        "{:?}",
        r.body
    );
    assert_eq!(t.setting()["syslog"]["enabled"], false);
    assert_eq!(t.setting()["https"]["headers"]["Authorization"], json!(sealed));

    // a request that no longer matches the setting is refused on approval
    let mut gone = off.clone();
    gone["https"] = Value::Null;
    let r = t.put("/api/v1/settings/forwarding", &alice, gone).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let q = r.body["quorum_id"].as_i64().unwrap();
    let mut fac = off.clone();
    fac["syslog"]["facility"] = json!(17);
    assert_eq!(
        t.put("/api/v1/settings/forwarding", &adam, fac).await.status,
        StatusCode::OK
    );
    let r = t.post(&format!("/api/v1/quorum/{q}/approve"), &sam, json!({})).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);

    // status: per configured sink, with the chain head
    t.st.cat
        .conn()
        .execute(
            "INSERT INTO forward_state (sink, dest, audit_seq, event_seq, last_ok, last_error) VALUES ('https', ?1, 3, 1, 99, NULL)",
            [url],
        )
        .unwrap();
    let r = t.get("/api/v1/audit/forwarding", &sam).await;
    assert_eq!(r.status, StatusCode::OK);
    let head: i64 =
        t.st.cat
            .conn()
            .query_row("SELECT MAX(seq) FROM audit", [], |r| r.get(0))
            .unwrap();
    assert_eq!(r.body["head_seq"], head);
    let sinks = r.body["sinks"].as_array().unwrap();
    assert_eq!(sinks.len(), 2);
    assert_eq!(
        (
            sinks[0]["sink"].as_str(),
            sinks[0]["enabled"].as_bool(),
            sinks[0]["audit_seq"].as_i64()
        ),
        (Some("syslog"), Some(false), Some(0))
    );
    assert_eq!(
        (
            sinks[1]["dest"].as_str(),
            sinks[1]["audit_seq"].as_i64(),
            sinks[1]["last_ok"].as_i64()
        ),
        (Some(url), Some(3), Some(99))
    );
}

#[tokio::test]
async fn audit_filters_and_csv_export() {
    let t = T::new();
    let (sam, otto) = (t.login("sam").await, t.login("otto").await);
    let cat = &t.st.cat;
    cat.audit("bob", "user.create", "user/carol", &json!({"role": "operator"}))
        .unwrap();
    cat.audit(
        "bob",
        "user.update",
        "user/carol",
        &json!({"note": "a, \"quoted\" value"}),
    )
    .unwrap();
    cat.audit("alice", "tenant.create", "tenant/acme", &json!({})).unwrap();
    cat.audit("alice", "usermod", "tenant/acme-2", &json!({})).unwrap();
    let list = |q: &'static str| {
        let t = &t;
        let sam = &sam;
        async move {
            let r = t.get(&format!("/api/v1/audit?{q}"), sam).await;
            assert_eq!(r.status, StatusCode::OK, "{q}: {:?}", r.body);
            r.body
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["action"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        }
    };
    assert_eq!(list("actor=bob").await, ["user.create", "user.update"]);
    assert_eq!(list("action=user.").await, ["user.create", "user.update"]);
    assert_eq!(list("action=user").await, ["user.create", "user.update", "usermod"]);
    assert_eq!(list("target=acme&order=desc").await, ["usermod", "tenant.create"]);
    assert_eq!(list("actor=alice&target=acme-").await, ["usermod"]);
    assert_eq!(
        list("actor=&action=").await.len(),
        4 + 2,
        "empty = any (plus the logins)"
    );
    let now = catalog::now();
    assert!(list(Box::leak(format!("from={}", now + 3600).into_boxed_str()))
        .await
        .is_empty());
    assert_eq!(
        list(Box::leak(
            format!("actor=bob&from={}&to={}", now - 60, now + 60).into_boxed_str()
        ))
        .await
        .len(),
        2
    );
    let r = t.get("/api/v1/audit?actor=bob&bogus=1", &sam).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        t.get("/api/v1/audit?actor=bob", &otto).await.status,
        StatusCode::FORBIDDEN
    );

    // CSV: admin + security officer, audited, prev_hash / hash per row
    assert_eq!(t.get("/api/v1/audit.csv", &otto).await.status, StatusCode::FORBIDDEN);
    let r = t.get("/api/v1/audit.csv?actor=bob", &sam).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.content_type.starts_with("text/csv"), "{}", r.content_type);
    let lines: Vec<&str> = r.text.split("\r\n").filter(|l| !l.is_empty()).collect();
    assert_eq!(lines[0], "seq,ts,actor,action,target,details,prev_hash,hash");
    assert_eq!(lines.len(), 3, "{lines:?}");
    let one = |sql: &str| -> String { cat.conn().query_row(sql, [], |r| r.get(0)).unwrap() };
    let hash1 = one("SELECT hash FROM audit WHERE action = 'user.create'");
    let prev2 = one("SELECT prev_hash FROM audit WHERE action = 'user.update'");
    assert!(lines[1].starts_with("3,") && lines[1].ends_with(&hash1), "{}", lines[1]);
    assert!(
        lines[1].contains(",bob,user.create,user/carol,\"{\"\"role\"\":\"\"operator\"\"}\","),
        "{}",
        lines[1]
    );
    assert!(lines[2].contains(&format!(",{prev2},")), "{}", lines[2]);
    assert!(
        lines[2].contains(r#""{""note"":""a, \""quoted\"" value""}""#),
        "{}",
        lines[2]
    );
    let ex = t.audit_details("audit.export");
    assert_eq!(ex.len(), 1);
    assert_eq!(serde_json::from_str::<Value>(&ex[0]).unwrap(), json!({"actor": "bob"}));
    // more than one page, oldest first
    cat.conn().pragma_update(None, "synchronous", "OFF").unwrap(); // test speed only
    for i in 0..2100 {
        cat.audit("bulk", "bulk.entry", &format!("x/{i}"), &json!({})).unwrap();
    }
    let r = t.get("/api/v1/audit.csv?actor=bulk", &sam).await;
    let rows: Vec<&str> = r.text.split("\r\n").skip(1).filter(|l| !l.is_empty()).collect();
    assert_eq!(rows.len(), 2100);
    let seqs: Vec<i64> = rows
        .iter()
        .map(|l| l.split(',').next().unwrap().parse().unwrap())
        .collect();
    assert!(seqs.windows(2).all(|w| w[0] < w[1]));
    assert_eq!(
        t.get("/api/v1/audit.csv?limit=5", &sam).await.status,
        StatusCode::BAD_REQUEST
    );
}
