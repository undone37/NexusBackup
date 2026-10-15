//! Account housekeeping (crate::accounts).
use super::*;

const DAY: i64 = 86400;

/// The inbound policy (setting `inbound`, or the 14d `mgmt_allow` before it
/// exists) goes into the firewall file, every available service explicitly.
#[test]
fn inbound_rules_reach_the_firewall_file() {
    let mut e = env(1);
    fs::create_dir_all(e.d.path().join("nft")).unwrap();
    e.cfg.nft_allowed = e.d.path().join("nft/allowed.json");
    let s = sched(&e);
    let inbound = |s: &Scheduler| {
        s.sync_firewall().unwrap();
        let m = nftsync::Allowed::load(&s.cfg.nft_allowed).unwrap().inbound.unwrap();
        m.into_iter()
            .map(|(k, r)| (k, (r.enabled, r.allow)))
            .collect::<Vec<_>>()
    };
    let v = |l: &[&str]| l.iter().map(std::string::ToString::to_string).collect::<Vec<_>>();
    assert_eq!(
        inbound(&s),
        [("icmp".into(), (false, v(&[]))), ("web".into(), (true, v(&[])))],
        "defaults: web from any address, no ping"
    );
    catalog::set_setting(
        &s.db.conn(),
        catalog::access::MGMT_ALLOW,
        r#"["10.1.2.3/16","2001:db8::/32"]"#,
    )
    .unwrap();
    assert_eq!(
        inbound(&s)[1],
        ("web".into(), (true, v(&["10.1.0.0/16", "2001:db8::/32"])))
    );
    catalog::set_setting(
        &s.db.conn(),
        catalog::firewall::SETTING,
        r#"{"services":{"icmp":{"allow":["192.0.2.0/24"],"enabled":true}}}"#,
    )
    .unwrap();
    assert_eq!(
        inbound(&s),
        [
            ("icmp".into(), (true, v(&["192.0.2.0/24"]))),
            ("web".into(), (true, v(&[])))
        ]
    );
}

#[test]
fn dormant_accounts_and_expired_sessions() {
    let e = env(1);
    let s = sched(&e);
    let now = 1_000 * DAY;
    {
        let c = s.db.conn();
        for (name, role, last) in [
            ("root-admin", "admin", 0),
            ("idle-op", "operator", 0),
            ("busy-op", "operator", now - DAY),
            ("sam", "security_officer", 0),
            ("sue", "security_officer", now),
        ] {
            c.execute(
                "INSERT INTO users (name, password_hash, totp_secret, role, created, last_login) VALUES (?1,'h','s',?2,0,?3)",
                params![name, role, last],
            )
            .unwrap();
        }
        c.execute(
            "INSERT INTO users (name, password_hash, totp_secret, role, created, activation_hash) VALUES ('pend','!','','viewer',0,'x')",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO users (name, password_hash, totp_secret, role, created, expires) VALUES ('gone','h','s','viewer',0,?1)",
            [now - 1],
        )
        .unwrap();
        c.execute(
            "INSERT INTO sessions (id_hash, user_id, csrf, created, last_seen) SELECT 'h' || id, id, 'c', 0, 0 FROM users",
            [],
        )
        .unwrap();
    }
    // off by default: only the expired account's session ends
    s.check_accounts(now).unwrap();
    let disabled = |s: &Scheduler| -> Vec<String> {
        let c = s.db.conn();
        let mut q = c
            .prepare("SELECT name FROM users WHERE disabled = 1 ORDER BY name")
            .unwrap();
        q.query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert!(disabled(&s).is_empty());
    let sessions = |s: &Scheduler| -> i64 {
        s.db.conn()
            .query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(sessions(&s), 6);
    catalog::set_setting(&s.db.conn(), catalog::access::DORMANT_DAYS, "90").unwrap();
    s.check_accounts(now).unwrap();
    // the only local admin stays; expired and pending accounts are not "dormant";
    // sam goes (sue and root-admin can still approve)
    assert_eq!(disabled(&s), vec!["idle-op", "sam"]);
    let alerts: i64 =
        s.db.conn()
            .query_row("SELECT COUNT(*) FROM alerts WHERE kind = 'account_dormant'", [], |r| {
                r.get(0)
            })
            .unwrap();
    assert_eq!(alerts, 2);
    assert_eq!(sessions(&s), 4, "expired, idle-op and sam lost theirs");
    // another local admin: root-admin may go now; sue stays (approvers ada + sue)
    {
        let c = s.db.conn();
        c.execute(
            "INSERT INTO users (name, password_hash, totp_secret, role, created, last_login) VALUES ('ada','h','s','admin',0,?1)",
            [now],
        )
        .unwrap();
        c.execute("UPDATE users SET last_login = 0 WHERE name = 'sue'", [])
            .unwrap();
    }
    s.check_accounts(now).unwrap();
    assert_eq!(disabled(&s), vec!["idle-op", "root-admin", "sam"]);
    let audits: i64 =
        s.db.conn()
            .query_row(
                "SELECT COUNT(*) FROM audit WHERE action = 'user.dormant_disabled'",
                [],
                |r| r.get(0),
            )
            .unwrap();
    assert_eq!(audits, 3);
}

/// DEK rotation reminder (Phase 21b): info alert past the interval, resolved
/// after a rotation, off with 0.
#[test]
fn dek_rotation_reminder() {
    let e = env(1);
    let s = sched(&e);
    let now = 1_000 * DAY;
    let open = |s: &Scheduler| -> Vec<(String, String, Option<String>)> {
        let c = s.db.conn();
        let mut q = c
            .prepare(
                "SELECT key, severity, tenant FROM alerts WHERE kind = 'dek_rotation' AND resolved_at IS NULL ORDER BY key",
            )
            .unwrap();
        q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    let ages = |t1: i64| {
        vec![
            ("t1".to_owned(), 1, now - t1 * DAY),
            ("t2".to_owned(), 3, now - 10 * DAY),
        ]
    };
    s.dek_reminders(now, &ages(365)).unwrap();
    assert_eq!(
        open(&s),
        [("dek_rotation:t1".into(), "info".into(), Some("t1".into()))],
        "default 365 days"
    );
    s.dek_reminders(now, &ages(2)).unwrap();
    assert!(open(&s).is_empty(), "rotated: resolved");
    catalog::set_setting(&s.db.conn(), catalog::access::DEK_ROTATION_DAYS, "0").unwrap();
    s.dek_reminders(now, &ages(5000)).unwrap();
    assert!(open(&s).is_empty(), "off");
    // without keyd (tests) the periodic check is silent
    s.check_dek_rotation(now).unwrap();
}
