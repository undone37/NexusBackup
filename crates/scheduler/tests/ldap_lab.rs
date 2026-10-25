//! Against a real directory (lab/pvehost/samba-ad.sh): the users and groups with their SIDs over LDAPS. Ignored by
//! default; env: LDAP_HOST, LDAP_CA (the server's certificate, PEM file), LDAP_BIND, LDAP_PASSWORD_FILE, LDAP_BASE,
//! LDAP_EXPECT (`<SID> <name>` lines that must be found, `samba-ad.sh users` writes them).
//! `cargo test --release -p scheduler --test ldap_lab -- --ignored --nocapture`

use std::time::{Duration, Instant};

#[test]
#[ignore]
fn accounts_of_a_directory() {
    let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} not set"));
    let ca = std::fs::read_to_string(env("LDAP_CA")).unwrap();
    let pw = std::fs::read_to_string(env("LDAP_PASSWORD_FILE")).unwrap();
    let (host, bind, base) = (env("LDAP_HOST"), env("LDAP_BIND"), env("LDAP_BASE"));
    let d = scheduler::ldap::Directory {
        host: &host,
        port: 636,
        ca_pem: &ca,
        bind_dn: &bind,
        password: pw.trim(),
        base_dn: &base,
    };
    let t0 = Instant::now();
    let got = scheduler::ldap::accounts(&d, Duration::from_secs(30)).unwrap();
    eprintln!("{} accounts in {:.1?}", got.len(), t0.elapsed());
    for line in std::fs::read_to_string(env("LDAP_EXPECT")).unwrap().lines() {
        let (sid, name) = line.split_once(' ').unwrap();
        assert_eq!(got.get(sid).map(String::as_str), Some(name), "{sid}");
    }
    // a wrong password is refused, not an anonymous success
    let bad = scheduler::ldap::Directory { password: "wrong", ..d };
    let e = scheduler::ldap::accounts(&bad, Duration::from_secs(30)).unwrap_err();
    eprintln!("wrong password: {e:#}");
    assert!(format!("{e:#}").contains("result 49"), "{e:#}");
}
