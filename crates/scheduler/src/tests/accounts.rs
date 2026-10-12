//! Account housekeeping (crate::accounts).
use super::*;

const DAY: i64 = 86400;

/// The management allow-list (setting `mgmt_allow`) goes into the firewall file.
#[test]
fn mgmt_allow_list_reaches_the_firewall_file() {
    let mut e = env(1);
    fs::create_dir_all(e.d.path().join("nft")).unwrap();
    e.cfg.nft_allowed = e.d.path().join("nft/allowed.json");
    let s = sched(&e);
    let mgmt = |s: &Scheduler| {
        s.sync_firewall().unwrap();
        nftsync::Allowed::load(&s.cfg.nft_allowed).unwrap().mgmt
    };
    assert_eq!(mgmt(&s), Some(vec![]), "empty = any");
    catalog::set_setting(
        &s.db.conn(),
        catalog::access::MGMT_ALLOW,
        r#"["10.1.2.3/16","2001:db8::/32"]"#,
    )
    .unwrap();
    assert_eq!(
        mgmt(&s),
        Some(vec!["10.1.0.0/16".to_owned(), "2001:db8::/32".to_owned()])
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
