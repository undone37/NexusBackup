use super::*;
use crate::expiry::DAY;

fn open(s: &Scheduler) -> Vec<(String, String, String)> {
    let c = s.db.conn();
    let mut q = c
        .prepare(
            "SELECT key, severity, message FROM alerts WHERE kind = 'cert_expiry' AND resolved_at IS NULL ORDER BY key",
        )
        .unwrap();
    let rows = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
    rows.map(Result::unwrap).collect()
}

fn tls_status(s: &Scheduler, web: Option<i64>, identity: i64) {
    let mut v = json!({"identity": {"not_after": identity, "subject": "CN=nexus"}, "web": {"imported": false}});
    if let Some(w) = web {
        v["web"] = json!({"not_after": w, "subject": "CN=backup.example.com", "imported": true});
    }
    catalog::set_setting(&s.db.conn(), "tls_status", &v.to_string()).unwrap();
}

/// Phase 14d: 90/30/7-day alerts for the web and identity certificates, agent
/// and replication peer certificates (from their enrollment), the agent CA,
/// the IdP client secret and API tokens; one alert per level, escalated,
/// resolved once renewed.
#[test]
fn expiry_alerts() {
    let e = env(1);
    let s = sched(&e);
    let now = catalog::now();
    assert_eq!(crate::expiry::severity(now + 91 * DAY, now), None);
    assert_eq!(crate::expiry::severity(now + 60 * DAY, now), Some("info"));
    assert_eq!(crate::expiry::severity(now + 20 * DAY, now), Some("warning"));
    assert_eq!(crate::expiry::severity(now - DAY, now), Some("critical"));

    tls_status(&s, Some(now + 60 * DAY), now + 3000 * DAY);
    let agent_enrolled = now - 3650 * DAY + 20 * DAY; // 10-year cert, 20 days left
    s.db.conn()
        .execute_batch(&format!(
            "INSERT INTO agents (id, tenant, name, host, port, cert_sha256, enrolled_at)
               VALUES ('00112233aabbccdd', 't1', 'web1', 'h', 7444, 'x', {agent_enrolled});
             INSERT INTO replication_peers (id, name, tenants, state, created, created_by, enrolled_at)
               VALUES ('p1', 'dr', '[]', 'enrolled', 0, 'a', {now});
             INSERT INTO users (id, name, password_hash, totp_secret, role, created) VALUES (9, 'alice', 'x', '', 'admin', 0);
             INSERT INTO api_tokens (id, user_id, name, prefix, hash, scope, expires, created)
               VALUES (4, 9, 'ci', 'abcd1234', 'h', 'read', {}, 0), (5, 9, 'long', 'abcd1235', 'h', 'read', {}, 0);",
            now + 3 * DAY,
            now + 100 * DAY
        ))
        .unwrap();
    catalog::set_setting(
        &s.db.conn(),
        "oidc",
        &json!({"issuer": "https://idp", "client_secret_expires": now + 5 * DAY}).to_string(),
    )
    .unwrap();
    s.check_expiry(now).unwrap();
    s.check_expiry(now).unwrap();
    let a = open(&s);
    let keys: Vec<(&str, &str)> = a.iter().map(|(k, s, _)| (k.as_str(), s.as_str())).collect();
    assert_eq!(
        keys,
        vec![
            ("cert_expiry:agent:00112233aabbccdd", "warning"),
            // the CA came with the first enrollment
            ("cert_expiry:agent_ca", "warning"),
            ("cert_expiry:oidc_secret", "critical"),
            ("cert_expiry:token:4", "info"),
            ("cert_expiry:web", "info"),
        ]
    );
    assert!(
        a[0].2.contains("agent t1/web1") && a[0].2.contains("expires in 2"),
        "{}",
        a[0].2
    );
    let count: i64 =
        s.db.conn()
            .query_row("SELECT count FROM alerts WHERE key = 'cert_expiry:web'", [], |r| {
                r.get(0)
            })
            .unwrap();
    assert_eq!(count, 1, "not counted up on every refresh");

    // the web certificate gets close: escalated in place; the agent CA's first
    // enrollment is remembered after the agent is deleted
    tls_status(&s, Some(now + 6 * DAY), now + 3000 * DAY);
    s.db.conn().execute("DELETE FROM agents", []).unwrap();
    s.check_expiry(now).unwrap();
    let a = open(&s);
    assert!(a.iter().any(|x| x.0 == "cert_expiry:web" && x.1 == "critical"));
    assert!(a.iter().any(|x| x.0 == "cert_expiry:agent_ca"));
    assert!(
        !a.iter().any(|x| x.0.starts_with("cert_expiry:agent:")),
        "agent gone: resolved"
    );

    // renewed: a new certificate, a new IdP secret date, the token revoked
    tls_status(&s, Some(now + 365 * DAY), now + 3000 * DAY);
    catalog::set_setting(&s.db.conn(), "oidc", r#"{"issuer": "https://idp"}"#).unwrap();
    s.db.conn().execute("DELETE FROM api_tokens WHERE id = 4", []).unwrap();
    s.check_expiry(now).unwrap();
    let a = open(&s);
    assert_eq!(
        a.iter().map(|x| x.0.as_str()).collect::<Vec<_>>(),
        vec!["cert_expiry:agent_ca"]
    );

    // without an import only the identity certificate counts
    tls_status(&s, None, now + 10 * DAY);
    s.check_expiry(now).unwrap();
    assert!(open(&s)
        .iter()
        .any(|x| x.0 == "cert_expiry:identity" && x.1 == "warning"));
}
