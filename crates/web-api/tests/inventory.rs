//! Phase 13c: guest inventory and auto-protect groups (mode / selector / exclude
//! validation, RBAC and tenant scope of `GET /sources/{id}/inventory` and the
//! `inventory` job, the dashboard's "not in a group" count from the inventory).

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use catalog::inventory::{update, Item};
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
        T {
            app: web_api::router(st.clone()),
            st,
            secrets,
            _dir: dir,
        }
    }

    async fn call(&self, method: Method, path: &str, s: &S, body: Option<Value>) -> R {
        let mut b = Request::builder()
            .method(method.clone())
            .uri(path)
            .header(header::HOST, "nexus.test")
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
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let raw = res.into_body().collect().await.unwrap().to_bytes().to_vec();
        R {
            status,
            body: serde_json::from_slice(&raw).unwrap_or(Value::Null),
        }
    }

    async fn login(&self, name: &str) -> S {
        let code = catalog::auth::totp_now(&self.secrets[name]).unwrap();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/auth/login")
            .header(header::HOST, "nexus.test")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({"name": name, "password": PW, "totp": code}).to_string(),
            ))
            .unwrap();
        let res = self.app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{name}");
        let cookie = res
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|c| c.strip_prefix("nx_session=")?.split(';').next().map(str::to_owned))
            .unwrap();
        let raw = res.into_body().collect().await.unwrap().to_bytes().to_vec();
        let body: Value = serde_json::from_slice(&raw).unwrap();
        S {
            cookie,
            csrf: body["csrf"].as_str().unwrap().to_owned(),
        }
    }
}

fn item(g: &str, tags: &[&str]) -> Item {
    Item {
        guest: g.into(),
        name: format!("vm{g}"),
        kind: "qemu".into(),
        tags: tags.iter().map(std::string::ToString::to_string).collect(),
    }
}

#[tokio::test]
async fn auto_protect_groups_inventory_and_dashboard() {
    let t = T::new();
    t.st.cat
        .conn()
        .execute_batch(
            "INSERT INTO tenants (name) VALUES ('globex');
             INSERT INTO sources (id, tenant, kind, name, config) VALUES
               (1, 'acme', 'pve', 'pve-a', '{}'), (3, 'acme', 'nfs', 'share-a', '{}'), (4, 'globex', 'pve', 'pve-g', '{}');
             INSERT INTO policies (id, name, schedule, gfs, offsite) VALUES (1, 'daily', 'daily 22:00', '{}', 0);",
        )
        .unwrap();
    {
        let c = t.st.cat.conn();
        update(
            &c,
            1,
            &[
                item("100", &["pool:prod"]),
                item("101", &["tag:web"]),
                item("102", &["pool:prod"]),
            ],
            10,
        )
        .unwrap();
        update(&c, 4, &[item("400", &[])], 10).unwrap();
    }
    let (alice, otto, tina) = (t.login("alice").await, t.login("otto").await, t.login("tina").await);
    let group = |name: &str, extra: Value| {
        let mut g = json!({"tenant": "acme", "source_id": 1, "policy_id": 1, "name": name});
        g.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        g
    };

    // validation
    for (src, extra, why) in [
        (1, json!({"mode": "some"}), "unknown mode"),
        (1, json!({"mode": "tags"}), "tags without selector"),
        (1, json!({"mode": "tags", "selector": ["bad\ntag"]}), "invalid tag"),
        (
            1,
            json!({"mode": "all", "selector": ["pool:prod"]}),
            "selector with all",
        ),
        (1, json!({"mode": "all", "guests": [100]}), "guests with all"),
        (1, json!({"mode": "all", "exclude": ["abc"]}), "exclude not a vmid"),
        (1, json!({"guests": [100], "exclude": [101]}), "exclude with explicit"),
        (3, json!({"mode": "all"}), "share source: explicit only"),
    ] {
        let mut g = group("x", extra);
        g["source_id"] = json!(src);
        let r = t.call(Method::POST, "/api/v1/groups", &alice, Some(g)).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{why}: {:?}", r.body);
    }
    // RBAC: groups are admin-only
    let r = t
        .call(
            Method::POST,
            "/api/v1/groups",
            &otto,
            Some(group("x", json!({"mode": "all"}))),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = t
        .call(
            Method::POST,
            "/api/v1/groups",
            &alice,
            Some(group("auto", json!({"mode": "all", "exclude": [101, "101"]}))),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(
        (&r.body["mode"], &r.body["guests"], &r.body["exclude"]),
        (&json!("all"), &json!([]), &json!(["101"]))
    );
    let auto_id = r.body["id"].as_i64().unwrap();

    // inventory: tenant scope, the groups covering each guest
    let r = t.call(Method::GET, "/api/v1/sources/1/inventory", &tina, None).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let gs = r.body["guests"].as_array().unwrap();
    assert_eq!(gs.len(), 3);
    let groups_of = |id: &str| gs.iter().find(|g| g["guest"] == id).unwrap()["groups"].clone();
    assert_eq!(groups_of("100"), json!(["auto"]));
    assert_eq!(groups_of("101"), json!([]), "excluded");
    assert_eq!(gs[1]["tags"], json!(["tag:web"]));
    let r = t.call(Method::GET, "/api/v1/sources/4/inventory", &tina, None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "other tenant");

    // refresh = `inventory` job: operators, sources with an inventory only
    let job = |sid: i64| json!({"kind": "inventory", "tenant": "acme", "params": {"source_id": sid}});
    let r = t.call(Method::POST, "/api/v1/jobs", &otto, Some(job(1))).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let r = t.call(Method::POST, "/api/v1/jobs", &tina, Some(job(1))).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    for sid in [3, 4] {
        let r = t.call(Method::POST, "/api/v1/jobs", &otto, Some(job(sid))).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "source {sid}");
    }

    // dashboard: 100 + 102 protected; 101 (excluded), 400 (no group) and the
    // share without a group are not
    let r = t.call(Method::GET, "/api/v1/dashboard?days=7", &alice, None).await;
    let p = &r.body["protection"];
    assert_eq!(
        (p["protected"].as_i64(), p["unprotected"].as_i64()),
        (Some(2), Some(3)),
        "{p}"
    );
    let open: Vec<Value> = p["unprotected_list"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| json!([o["source"], o["guest"]]))
        .collect();
    assert_eq!(
        open,
        [
            json!(["share-a", null]),
            json!(["pve-a", "101"]),
            json!(["pve-g", "400"])
        ]
    );
    let r = t.call(Method::GET, "/api/v1/dashboard?days=7", &tina, None).await;
    assert_eq!(r.body["protection"]["unprotected"], 2, "tenant scope");

    // a tags group covers 101; the update keeps mode / selector
    let r = t
        .call(
            Method::POST,
            "/api/v1/groups",
            &alice,
            Some(group(
                "web",
                json!({"mode": "tags", "selector": ["tag:web", "tag:web"]}),
            )),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["selector"], json!(["tag:web"]));
    let r = t.call(Method::GET, "/api/v1/dashboard?days=30", &alice, None).await;
    assert_eq!(r.body["protection"]["unprotected"], 2);
    assert_eq!(r.body["protection"]["protected"], 3);
    let r = t
        .call(
            Method::PUT,
            &format!("/api/v1/groups/{auto_id}"),
            &alice,
            Some(json!({"source_id": 1, "policy_id": 1, "name": "auto", "mode": "tags", "selector": ["pool:prod"]})),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let g = t.call(Method::GET, "/api/v1/groups", &alice, None).await.body;
    let g = g
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["id"] == auto_id)
        .unwrap()
        .clone();
    assert_eq!(
        (&g["mode"], &g["selector"], &g["exclude"]),
        (&json!("tags"), &json!(["pool:prod"]), &json!([]))
    );
}

/// `GET /names`: guests by their PVE name (containers as `ct-`), agents by name, per tenant; a tenant user
/// sees only their tenant; one VMID in two clusters of a tenant gets both names.
#[tokio::test]
async fn source_names_for_the_ui() {
    let t = T::new();
    {
        let c = t.st.cat.conn();
        c.execute_batch(
            "INSERT OR IGNORE INTO tenants (name) VALUES ('acme'), ('globex');
             INSERT INTO sources (id, tenant, kind, name, config) VALUES
               (1, 'acme', 'pve', 'pve-a', '{}'), (2, 'acme', 'pve', 'pve-b', '{}'), (3, 'globex', 'pve', 'pve-g', '{}');
             INSERT INTO agents (id, tenant, name, host, port) VALUES ('a1', 'acme', 'fs02', 'fs02', 7444);",
        )
        .unwrap();
        let it = |g: &str, name: &str, kind: &str| Item {
            guest: g.into(),
            name: name.into(),
            kind: kind.into(),
            tags: Vec::new(),
        };
        update(
            &c,
            1,
            &[
                it("100", "erp-app", "qemu"),
                it("101", "proxy", "lxc"),
                it("102", "web", "qemu"),
            ],
            1,
        )
        .unwrap();
        update(&c, 2, &[it("102", "web-b", "qemu")], 1).unwrap();
        update(&c, 3, &[it("100", "other-erp", "qemu")], 1).unwrap();
    }
    let alice = t.login("alice").await;
    let r = t.call(Method::GET, "/api/v1/names", &alice, None).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["acme"]["vm-100"], "erp-app");
    assert_eq!(r.body["acme"]["ct-101"], "proxy");
    assert_eq!(r.body["acme"]["host-a1"], "fs02");
    let both = r.body["acme"]["vm-102"].as_str().unwrap();
    assert!(both == "web / web-b" || both == "web-b / web", "{both}");
    assert_eq!(r.body["globex"]["vm-100"], "other-erp");
    let tina = t.login("tina").await;
    let r = t.call(Method::GET, "/api/v1/names", &tina, None).await;
    assert!(
        r.body.get("globex").is_none() && r.body["acme"]["vm-100"] == "erp-app",
        "{:?}",
        r.body
    );
    let r = t.call(Method::GET, "/api/v1/names?tenant=globex", &tina, None).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}
