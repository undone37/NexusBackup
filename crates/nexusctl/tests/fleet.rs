//! `nexusctl fleet` (Phase 33) against two real web-api routers (plain HTTP on
//! loopback) with read tokens, an operator token that is refused and an
//! appliance that cannot be reached.

use catalog::rusqlite::params;
use catalog::secret::TotpKey;
use catalog::Catalog;
use nexusctl::fleet;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use web_api::AppState;

fn token(st: &Arc<AppState>, user: &str, scope: &str, prefix: &str) -> String {
    let c = st.cat.conn();
    c.execute(
        "INSERT INTO users (name, password_hash, totp_secret, role, created) VALUES (?1, 'x', '', 'admin', 0)",
        params![user],
    )
    .unwrap();
    let secret = "q".repeat(48);
    c.execute(
        "INSERT INTO api_tokens (user_id, name, prefix, hash, scope, expires, created)
         VALUES (?1, 'fleet', ?2, ?3, ?4, ?5, 0)",
        params![
            c.last_insert_rowid(),
            prefix,
            web_api::sha256_hex(secret.as_bytes()),
            scope,
            catalog::now() + 86400
        ],
    )
    .unwrap();
    format!("nxt_{prefix}_{secret}")
}

/// One appliance: a tenant, a failed backup an hour ago, an old failed job, open alerts.
async fn appliance(dir: &std::path::Path, name: &str, hostile: bool) -> (Arc<AppState>, String) {
    let cat = Catalog::open(&dir.join(format!("{name}.db"))).unwrap();
    let st = AppState::with_keys(cat, None, dir.join(format!("{name}-dl")), TotpKey::generate(), None);
    let now = catalog::now();
    let msg = if hostile {
        "<img src=x onerror=alert(1)> backup failed"
    } else {
        "backup failed: no route to host"
    };
    st.cat
        .conn()
        .execute_batch(&format!(
            "INSERT INTO tenants (name) VALUES ('{name}');
             INSERT INTO jobs (kind, tenant, params, state, requested_by, created, finished) VALUES
               ('backup', '{name}', '{{}}', 'failed', 'scheduler', {a}, {a}),
               ('verify', '{name}', '{{}}', 'failed', 'scheduler', {b}, {b}),
               ('backup', '{name}', '{{}}', 'ok', 'scheduler', {a}, {a});
             INSERT INTO alerts (ts, last_ts, severity, kind, key, message, tenant) VALUES
               ({a}, {a}, 'critical', 'job_failed', 'k1', '{m}', '{name}'),
               ({a}, {a}, 'info', 'orphaned', 'k2', 'old object', '{name}');",
            a = now - 3600,
            b = now - 5 * 86400,
            m = msg.replace('\'', "''")
        ))
        .unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
    let app = web_api::router(st.clone());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (st, url)
}

#[tokio::test(flavor = "multi_thread")]
async fn fleet_overview() {
    let dir = tempfile::tempdir().unwrap();
    let (a, a_url) = appliance(dir.path(), "acme", false).await;
    let (g, g_url) = appliance(dir.path(), "globex", true).await;
    let read_a = token(&a, "rita", "read", "0000aaaa");
    let op_g = token(&g, "otto", "operator", "0000bbbb");
    let read_g = token(&g, "gina", "read", "0000cccc");
    let dead = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let tok = |name: &str, t: &str| {
        let p = dir.path().join(format!("{name}.token"));
        std::fs::write(&p, format!("{t}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        p
    };
    let (ta, tg_op, tg) = (tok("a", &read_a), tok("g-op", &op_g), tok("g", &read_g));
    let cfg = |g_token: &std::path::Path| {
        serde_json::json!({"appliances": [
            {"name": "acme", "url": a_url, "token_file": ta},
            {"name": "globex", "url": g_url, "token_file": g_token},
            {"name": "gone", "url": format!("http://127.0.0.1:{dead}"), "token_file": ta}]})
        .to_string()
    };
    let (with_op, with_read) = (cfg(&tg_op), cfg(&tg));
    let d = dir.path().to_path_buf();
    tokio::task::spawn_blocking(move || {
        // an operator token is refused: the overview never holds write access
        let entries = fleet::parse_config(&with_op).unwrap();
        let r = fleet::collect(&entries, 24, catalog::now());
        assert!(r[0].result.is_ok(), "{:?}", r[0].result);
        let e = r[1].result.as_ref().unwrap_err();
        assert!(e.contains("scope operator"), "{e}");
        assert!(
            r[2].result.as_ref().unwrap_err().contains("127.0.0.1"),
            "{:?}",
            r[2].result
        );
        // read tokens: both appliances, the failed job of the last day only
        let cfg_path = d.join("fleet.json");
        std::fs::write(&cfg_path, &with_read).unwrap();
        let html = d.join("fleet.html");
        let args: Vec<String> = [
            "--config",
            cfg_path.to_str().unwrap(),
            "--html",
            html.to_str().unwrap(),
            "--check",
        ]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
        let (out, code) = fleet::cli(&args, false).unwrap();
        assert_eq!(code, 2, "an appliance is unreachable and both have failed jobs");
        let line = |n: &str| {
            out.lines()
                .find(|l| l.starts_with(n))
                .unwrap_or_default()
                .split_whitespace()
                .collect::<Vec<_>>()
        };
        assert_eq!(
            line("acme")[..6],
            ["acme", "ATTENTION", "0/0", "0", "1/0/1", "1"],
            "{out}"
        );
        assert_eq!(line("gone")[1], "UNREACHABLE", "{out}");
        assert!(
            out.contains("alert 1 critical job_failed (acme): backup failed: no route to host"),
            "{out}"
        );
        assert_eq!(
            out.matches("failed job").count(),
            2,
            "one per appliance (the 5-day-old verify is out): {out}"
        );
        assert!(!out.contains("orphaned"), "info alerts are only counted: {out}");
        let page = std::fs::read_to_string(&html).unwrap();
        assert!(page.contains("&lt;img src=x onerror=alert(1)&gt;") && !page.contains("<img"));
        assert_eq!(std::fs::metadata(&html).unwrap().permissions().mode() & 0o777, 0o600);
        let (json, _) = fleet::cli(&args[..2], true).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v[1]["data"]["me"]["token"]["scope"], "read");
        assert_eq!(v[2]["ok"], false);
    })
    .await
    .unwrap();
    // only reads reached the appliances (no audit entries of changes)
    for st in [&a, &g] {
        let n: i64 = st
            .cat
            .conn()
            .query_row("SELECT COUNT(*) FROM audit WHERE action NOT LIKE 'auth.%'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(n, 0);
    }
}
