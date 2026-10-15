//! nexusctl against the real web-api router (plain HTTP on loopback) with API
//! tokens inserted into the catalog.

use catalog::rusqlite::params;
use catalog::secret::TotpKey;
use catalog::Catalog;
use nexusctl::{run, Client, Conn};
use std::sync::Arc;
use web_api::AppState;

fn token(st: &Arc<AppState>, user: &str, role: &str, scope: &str, prefix: &str) -> String {
    let c = st.cat.conn();
    c.execute(
        "INSERT INTO users (name, password_hash, totp_secret, role, created) VALUES (?1, 'x', '', ?2, 0)",
        params![user, role],
    )
    .unwrap();
    let secret = "z".repeat(48);
    c.execute(
        "INSERT INTO api_tokens (user_id, name, prefix, hash, scope, expires, created)
         VALUES (?1, 'ci', ?2, ?3, ?4, ?5, 0)",
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

#[tokio::test(flavor = "multi_thread")]
async fn commands_against_the_api() {
    let dir = tempfile::tempdir().unwrap();
    let cat = Catalog::open(&dir.path().join("catalog.db")).unwrap();
    let st = AppState::with_keys(cat, None, dir.path().join("dl"), TotpKey::generate(), None);
    st.cat
        .conn()
        .execute_batch(
            r#"INSERT INTO tenants (name) VALUES ('acme');
               INSERT INTO sources (id, tenant, kind, name, config) VALUES (1, 'acme', 'pve', 'pve-a', '{}');
               INSERT INTO policies (id, name, schedule, gfs, offsite) VALUES (1, 'daily', 'daily 22:00', '{}', 0);
               INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES (1, 'acme', 1, 1, 'web', '[100]');
               INSERT INTO snapshots (tenant, source, time, size, local, offsite) VALUES ('acme', 'vm-100', 1791763200, 2048, 1, 0);"#,
        )
        .unwrap();
    let read = token(&st, "rita", "operator", "read", "0000aaaa");
    let op = token(&st, "otto", "operator", "operator", "0000bbbb");
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
    let app = web_api::router(st.clone());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    let st2 = st.clone();
    tokio::task::spawn_blocking(move || {
        let cl = |t: &str| {
            Client::new(Conn {
                url: url.clone(),
                token: t.into(),
                ca_pem: None,
            })
            .unwrap()
        };
        let cmd = |v: &[&str]| v.iter().map(std::string::ToString::to_string).collect::<Vec<_>>();
        let (r, o) = (cl(&read), cl(&op));
        let out = run(&r, &cmd(&["sources"]), false).unwrap();
        assert!(
            out.starts_with("ID  TENANT  KIND  NAME\n1   acme    pve   pve-a"),
            "{out}"
        );
        let out = run(&r, &cmd(&["snapshots", "--tenant", "acme"]), false).unwrap();
        assert!(
            out.contains("vm-100") && out.contains("2026-10-12 00:00") && out.contains("2.0 KiB"),
            "{out}"
        );
        assert!(run(&r, &cmd(&["groups"]), false).unwrap().contains("web"));
        // a read token cannot start jobs
        let e = run(&r, &cmd(&["run", "1"]), false).unwrap_err().to_string();
        assert!(e.contains("403"), "{e}");
        let out = run(&o, &cmd(&["run", "1", "--keep-until", "2099-01-01"]), false);
        assert!(
            out.unwrap_err().to_string().contains("keep_until"),
            "past the 10-year limit"
        );
        let out = run(&o, &cmd(&["run", "1"]), false).unwrap();
        assert!(out.starts_with("job "), "{out}");
        let id: i64 = out.split(' ').nth(1).unwrap().parse().unwrap();
        let out = run(&r, &cmd(&["job", &id.to_string()]), false).unwrap();
        assert!(out.contains("backup (acme): queued"), "{out}");
        let out = run(&r, &cmd(&["jobs", "--state", "queued"]), true).unwrap();
        assert!(out.trim_start().starts_with('['), "{out}");
        let out = run(&r, &cmd(&["usage"]), false).unwrap();
        assert!(out.starts_with("usage ") && out.contains("acme"), "{out}");
        let out = run(&r, &cmd(&["usage", "--csv"]), false).unwrap();
        assert!(out.starts_with("period_start,period_end,tenant,"), "{out}");
        assert!(run(&r, &cmd(&["openapi"]), false).unwrap().contains("\"openapi\""));
        assert!(run(&r, &cmd(&["nope"]), false).is_err());
        let by: String = st2
            .cat
            .conn()
            .query_row("SELECT actor FROM audit WHERE action = 'job.create'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(by, "otto via token ci");
    })
    .await
    .unwrap();
    // refused before any request: wrong scheme or no token
    let bad = |url: &str, token: &str| {
        Client::new(Conn {
            url: url.into(),
            token: token.into(),
            ca_pem: None,
        })
        .is_err()
    };
    assert!(bad("http://backup.example.com", "nxt_0000aaaa_x"));
    assert!(bad("https://backup.example.com", "secret"));
}
