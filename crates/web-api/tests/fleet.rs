//! Phase 24d: fleet secrets (admin only, shown once, sealed), candidates (tenant
//! scoped, accept → agent + source/group from the template + enrollment job, max
//! uses, reject), scans, revocation, and CSV bulk enrollment (all or nothing).

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
            ("tam", "tenant_admin", Some("acme")),
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
        }
    }

    async fn get(&self, path: &str, s: &S) -> R {
        self.call(Method::GET, path, Some(s), None).await
    }
    async fn post(&self, path: &str, s: &S, body: Value) -> R {
        self.call(Method::POST, path, Some(s), Some(body)).await
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

const AG: &str = "0123456789abcdef";

/// A template: linux source `tmpl` (agent web01) with group `web-tmpl` in acme.
fn fixture(t: &T) {
    t.exec(&format!(
        "INSERT INTO agents (id, tenant, name, host, port, cert_sha256, enrolled_at) VALUES
           ('{AG}', 'acme', 'web01', '10.0.0.9', 7444, '{fp}', 5);
         INSERT INTO sources (id, tenant, kind, name, config) VALUES
           (3, 'acme', 'linux', 'tmpl', '{{\"agent_id\":\"{AG}\",\"paths\":[\"/etc\",\"/home\"],\"excludes\":[\"*.tmp\"]}}');
         INSERT INTO groups (id, tenant, source_id, policy_id, name, guests, timezone) VALUES
           (3, 'acme', 3, 1, 'web-tmpl', '[\"{AG}\"]', 'Europe/Berlin');",
        fp = "ab".repeat(32)
    ));
}

fn candidate(t: &T, fleet: &str, host: &str, hostname: &str) -> i64 {
    let c = t.st.cat.conn();
    catalog::fleet::record(
        &c,
        fleet,
        &json!({"host": host, "port": 7444, "hostname": hostname, "os": "Debian 13", "version": "0.1.0"}),
        10,
    )
    .unwrap()
    .unwrap()
}

#[tokio::test]
async fn fleet_secrets_candidates_and_acceptance() {
    let t = T::new();
    fixture(&t);
    let (alice, tam, tina) = (t.login("alice").await, t.login("tam").await, t.login("tina").await);
    let base = json!({"name": "clients", "tenant": "acme", "expires_days": 7, "max_uses": 1,
                      "ranges": ["10.0.0.0/24", "db-1.example"], "group": "web-tmpl",
                      "group_rules": [{"pattern": "db-*", "group": "web-tmpl"}]});
    // admins only
    assert_eq!(
        t.post("/api/v1/fleets", &tam, base.clone()).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(t.get("/api/v1/fleets", &tam).await.status, StatusCode::FORBIDDEN);
    for (k, v) in [
        ("expires_days", json!(31)),
        ("expires_days", json!(0)),
        ("max_uses", json!(0)),
        ("ranges", json!(["10.0.0.0/21"])),
        ("ranges", json!(["not valid!"])),
        ("group", json!("nope")),
        ("group_rules", json!([{"pattern": "a b", "group": "web-tmpl"}])),
        ("group_rules", json!([{"pattern": "*", "group": "g1"}])),
        ("tenant", json!("nope")),
    ] {
        let mut b = base.clone();
        b[k] = v.clone();
        let r = t.post("/api/v1/fleets", &alice, b).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{k}={v}: {:?}", r.body);
    }
    let r = t.post("/api/v1/fleets", &alice, base.clone()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let id = r.body["id"].as_str().unwrap().to_owned();
    let secret = r.body["secret"].as_str().unwrap().to_owned();
    assert_eq!(agent_proto::fleet_id(&secret), Some(id.as_str()));
    assert!(r.body["install"]["windows"]
        .as_str()
        .unwrap()
        .contains("FLEETSECRET=<secret>"));
    assert_eq!(
        (r.body["uses"].as_i64(), r.body["revoked"].as_bool()),
        (Some(0), Some(false))
    );
    // stored sealed, never in the audit log, not in the list
    let stored: String = t.one(&format!("SELECT secret_hash FROM fleets WHERE id = '{id}'"));
    assert!(stored.starts_with("sealed:v1:") && !stored.contains(&agent_proto::token_digest(&secret)));
    let audit: String = t.one("SELECT group_concat(details, ' ') FROM audit");
    assert!(!audit.contains(&secret) && audit.contains("\"clients\""));
    let l = t.get("/api/v1/fleets", &alice).await;
    assert_eq!(l.body.as_array().unwrap().len(), 1);
    assert!(l.body[0].get("secret").is_none() && l.body[0].get("secret_hash").is_none());

    // candidates: tenant scoped
    let c1 = candidate(&t, &id, "10.0.0.20", "db-1.example.com");
    let c2 = candidate(&t, &id, "10.0.0.21", "ws-2");
    t.exec(
        "INSERT INTO fleets (id, tenant, name, secret_hash, created, created_by, expires, port)
           VALUES ('ffffffffffffffff', 'globex', 'g', 'x', 1, 'alice', 9999999999, 7444);",
    );
    candidate(&t, "ffffffffffffffff", "10.9.0.1", "other");
    assert_eq!(
        t.get("/api/v1/fleet/candidates", &alice)
            .await
            .body
            .as_array()
            .unwrap()
            .len(),
        3
    );
    let mine = t.get("/api/v1/fleet/candidates", &tina).await.body;
    assert_eq!(mine.as_array().unwrap().len(), 2);
    assert_eq!(
        (mine[0]["state"].as_str(), mine[0]["fleet"].as_str()),
        (Some("awaiting"), Some("clients"))
    );
    // tenant users read, tenant admins decide
    let accept = |c: i64| format!("/api/v1/fleet/candidates/{c}/accept");
    assert_eq!(
        t.post(&accept(c1), &tina, json!({})).await.status,
        StatusCode::FORBIDDEN
    );
    let other: i64 = t.one("SELECT id FROM fleet_candidates WHERE fleet_id = 'ffffffffffffffff'");
    assert_eq!(
        t.post(&accept(other), &tam, json!({})).await.status,
        StatusCode::FORBIDDEN
    );
    let r = t.post(&accept(c1), &tam, json!({})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let agent = r.body["agent_id"].as_str().unwrap().to_owned();
    assert_eq!(
        (r.body["name"].as_str(), r.body["group"].as_str()),
        (Some("db-1"), Some("web-tmpl"))
    );
    let (host, fleet, tenant): (String, String, String) =
        t.st.cat
            .conn()
            .query_row(
                "SELECT host, fleet_id, tenant FROM agents WHERE id = ?1",
                [&agent],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
    assert_eq!(
        (host.as_str(), fleet.as_str(), tenant.as_str()),
        ("10.0.0.20", id.as_str(), "acme")
    );
    // own source (template's paths) and group (template's settings)
    let cfg: String = t.one("SELECT config FROM sources WHERE name = 'db-1'");
    let cfg: Value = serde_json::from_str(&cfg).unwrap();
    assert_eq!(
        (&cfg["agent_id"], &cfg["paths"]),
        (&json!(agent), &json!(["/etc", "/home"]))
    );
    let (guests, tz, policy): (String, String, i64) =
        t.st.cat
            .conn()
            .query_row(
                "SELECT guests, timezone, policy_id FROM groups WHERE name = 'db-1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
    assert_eq!(
        (guests, tz.as_str(), policy),
        (json!([agent]).to_string(), "Europe/Berlin", 1)
    );
    let params: String = t.one("SELECT params FROM jobs WHERE kind = 'agent_enroll'");
    assert_eq!(
        serde_json::from_str::<Value>(&params).unwrap(),
        json!({"agent_id": agent, "fleet_id": id})
    );
    assert_eq!(t.one::<i64>(&format!("SELECT uses FROM fleets WHERE id = '{id}'")), 1);
    assert_eq!(
        t.one::<i64>("SELECT COUNT(*) FROM audit WHERE action = 'fleet.accept'"),
        1
    );
    // decided once; max_uses = 1 is used up now
    assert_eq!(t.post(&accept(c1), &tam, json!({})).await.status, StatusCode::CONFLICT);
    let r = t.post(&accept(c2), &tam, json!({})).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
    assert!(
        r.body["error"].as_str().unwrap_or_default().contains("maximum"),
        "{:?}",
        r.body
    );
    let r = t
        .post(&format!("/api/v1/fleet/candidates/{c2}/reject"), &tam, json!({}))
        .await;
    assert_eq!(r.body["state"], "rejected");
    // a rescan does not resurrect it
    assert!(catalog::fleet::record(
        &t.st.cat.conn(),
        &id,
        &json!({"host": "10.0.0.21", "port": 7444, "hostname": "ws-2", "os": "x", "version": "x"}),
        20
    )
    .unwrap()
    .is_none());
    // enrollment retry of the accepted agent: still with the fleet secret (uses do not matter)
    let r = t.post(&format!("/api/v1/agents/{agent}/enroll"), &tam, json!({})).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let params: String = t.one("SELECT params FROM jobs WHERE kind = 'agent_enroll' ORDER BY id DESC LIMIT 1");
    assert_eq!(serde_json::from_str::<Value>(&params).unwrap()["fleet_id"], json!(id));
    // generic job API cannot smuggle a fleet into an enrollment
    let r = t
        .post(
            "/api/v1/jobs",
            &alice,
            json!({"kind": "agent_enroll", "tenant": "acme",
                                             "params": {"agent_id": AG, "fleet_id": id}}),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);

    // scans: not for a used-up fleet, yes for an open one; revoked: no more
    let scan = |f: &str| format!("/api/v1/fleets/{f}/scan");
    assert_eq!(t.post(&scan(&id), &alice, json!({})).await.status, StatusCode::CONFLICT);
    let mut open = base.clone();
    open["name"] = json!("open");
    open.as_object_mut().unwrap().remove("max_uses");
    let f2 = t.post("/api/v1/fleets", &alice, open).await.body["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(t.post(&scan(&f2), &tam, json!({})).await.status, StatusCode::FORBIDDEN);
    let r = t.post(&scan(&f2), &alice, json!({})).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let job: String = t.one(&format!(
        "SELECT kind || ' ' || params FROM jobs WHERE id = {}",
        r.body["id"]
    ));
    assert_eq!(job, format!("fleet_scan {{\"fleet_id\":\"{f2}\"}}"));
    let r = t
        .call(Method::DELETE, &format!("/api/v1/fleets/{f2}"), Some(&alice), None)
        .await;
    assert_eq!(r.body["revoked"], true);
    assert_eq!(t.post(&scan(&f2), &alice, json!({})).await.status, StatusCode::CONFLICT);
    assert_eq!(
        t.one::<i64>("SELECT COUNT(*) FROM audit WHERE action = 'fleet.revoke'"),
        1
    );
}

#[tokio::test]
async fn csv_bulk_enrollment_all_or_nothing() {
    let t = T::new();
    fixture(&t);
    let (alice, tam) = (t.login("alice").await, t.login("tam").await);
    let bulk = |csv: &str| json!({ "csv": csv });
    for (csv, want) in [
        ("", "empty"),
        ("name,tenant\nx,acme", "host and tenant"),
        ("host,tenant,color\nh1,acme,red", "unknown column"),
        ("host,tenant\nh1,acme\nh2,nope", "line 3"),
        ("host,tenant,group\nh1,acme,nope", "line 2"),
        ("host,tenant,port\nh1,acme,0", "line 2: port"),
        ("host,tenant\nh 1,acme", "line 2: host"),
        ("host,tenant,name\nh1,acme,web01", "line 2: an agent named web01"),
    ] {
        let r = t.post("/api/v1/agents/bulk", &alice, bulk(csv)).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{csv}: {:?}", r.body);
        assert!(
            r.body["error"].as_str().unwrap_or_default().contains(want),
            "{csv}: {:?}",
            r.body
        );
    }
    assert_eq!(t.one::<i64>("SELECT COUNT(*) FROM agents"), 1, "nothing created");
    // a tenant admin only for the own tenant
    let r = t
        .post("/api/v1/agents/bulk", &tam, bulk("host,tenant\nh1,globex"))
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let csv = "# clients\nhost,tenant,name,port,group\n10.0.0.31,acme,ws-31,,web-tmpl\n\nws32.example,globex,,7555,\n";
    let r = t.post("/api/v1/agents/bulk", &alice, bulk(csv)).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["created"], 2);
    let out = r.body["csv"].as_str().unwrap();
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines[0],
        "name,tenant,host,port,group,agent_id,token,token_expires,install_command"
    );
    let f: Vec<&str> = lines[1].split(',').collect();
    assert_eq!(&f[..5], &["ws-31", "acme", "10.0.0.31", "7444", "web-tmpl"]);
    assert_eq!(f[6].len(), 26, "one-time token");
    assert_eq!(f[8], "sudo nexus-agent init --token -");
    let f: Vec<&str> = lines[2].split(',').collect();
    assert_eq!(&f[..5], &["ws32.example", "globex", "ws32.example", "7555", ""]);
    // tokens sealed like single agents; ws-31 got its source + group from the template
    assert_eq!(
        t.one::<i64>("SELECT COUNT(*) FROM agents WHERE token_hash LIKE 'sealed:v1:%'"),
        2
    );
    assert_eq!(
        t.one::<i64>("SELECT COUNT(*) FROM groups WHERE name = 'ws-31' AND tenant = 'acme'"),
        1
    );
    assert_eq!(
        t.one::<i64>("SELECT COUNT(*) FROM audit WHERE action = 'agent.create' AND json_extract(details, '$.bulk')"),
        2
    );
    let audit: String = t.one("SELECT group_concat(details, ' ') FROM audit");
    assert!(!audit.contains(f[6]));
}
