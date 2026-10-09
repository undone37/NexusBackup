//! Drives `nexus-setup --script answers.json --root <tmp> --dry-run` end to end.

use catalog::{auth, Catalog};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const PW_ADMIN: &str = "correct horse battery admin";
const PW_SO: &str = "correct horse battery officer";

struct Env {
    _dir: tempfile::TempDir,
    root: PathBuf,
    answers: PathBuf,
    admin_secret: String,
    so_secret: String,
}

fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    fs::create_dir(&root).unwrap();
    Env {
        answers: dir.path().join("answers.json"), // outside root: only setup's own writes are scanned
        root,
        _dir: dir,
        admin_secret: auth::new_totp_secret(),
        so_secret: auth::new_totp_secret(),
    }
}

impl Env {
    fn p(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }
    fn account(&self, name: &str, pw: &str, secret: &str) -> Value {
        json!({"name": name, "password": pw, "totp_secret": secret, "totp_code": auth::totp_now(secret).unwrap()})
    }
    fn answers(&self, address: &str) -> Value {
        json!({
            "network": {"nic": "eth0", "method": "static", "address": address, "prefix": 24,
                        "gateway": "192.0.2.1", "dns": ["192.0.2.53"], "hostname": "nexus01"},
            "admin": self.account("admin", PW_ADMIN, &self.admin_secret),
            "security_officer": self.account("officer", PW_SO, &self.so_secret),
        })
    }
    fn run(&self, answers: &Value, extra: &[&str]) -> (Output, String, String) {
        fs::write(&self.answers, answers.to_string()).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_nexus-setup"))
            .args([
                "--script",
                self.answers.to_str().unwrap(),
                "--root",
                self.root.to_str().unwrap(),
                "--dry-run",
            ])
            .args(extra)
            .env_remove("NEXUS_SETUP_ROOT")
            .output()
            .unwrap();
        let (o, e) = (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        );
        (out, o, e)
    }
    fn catalog(&self) -> Catalog {
        Catalog::open(&self.p("var/lib/nexus/catalog/catalog.db")).unwrap()
    }
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o7777
}

fn users(c: &Catalog) -> Vec<(String, String, String, String)> {
    let conn = c.conn();
    let mut st = conn
        .prepare("SELECT name, role, password_hash, totp_secret FROM users ORDER BY id")
        .unwrap();
    st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn audit_actions(c: &Catalog) -> Vec<(String, String, Value)> {
    let conn = c.conn();
    let mut st = conn
        .prepare("SELECT actor, action, details FROM audit ORDER BY seq")
        .unwrap();
    st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, String>(2)?)))
        .unwrap()
        .map(|r| {
            let (a, b, d) = r.unwrap();
            (a, b, serde_json::from_str(&d).unwrap())
        })
        .collect()
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            walk(&p, out)
        } else {
            out.push(p)
        }
    }
}

fn recovery_key(stdout: &str) -> String {
    stdout
        .lines()
        .find_map(|l| l.strip_prefix("RECOVERY KEY (shown once, record it now): "))
        .expect("recovery key printed once")
        .to_owned()
}

/// No file under root (nor stderr, which goes to the journal) contains the key in any spelling.
fn assert_key_not_persisted(e: &Env, key: &str, stderr: &str) {
    let plain = key.replace('-', "");
    let raw = keyd::parse_recovery_key(key).unwrap();
    let needles: Vec<Vec<u8>> = vec![
        key.as_bytes().to_vec(),
        key.to_uppercase().into_bytes(),
        plain.as_bytes().to_vec(),
        plain.to_uppercase().into_bytes(),
        raw.to_vec(),
        // a single group sequence long enough not to collide by chance
        key.as_bytes()[..9].to_vec(),
    ];
    let mut files = vec![];
    walk(&e.root, &mut files);
    assert!(files.len() > 5, "{files:?}");
    for f in files {
        let data = fs::read(&f).unwrap();
        for n in &needles {
            assert!(
                !data.windows(n.len()).any(|w| w == &n[..]),
                "recovery key material in {}",
                f.display()
            );
        }
    }
    assert!(!stderr.contains(key) && !stderr.contains(&plain));
}

#[test]
fn full_run_then_refuse_then_reconfigure_network() {
    let e = env();
    let (out, stdout, stderr) = e.run(&e.answers("192.0.2.10"), &[]);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");

    // commands only printed (dry-run)
    assert!(
        stdout.contains("+ (dry-run) hostnamectl set-hostname nexus01"),
        "{stdout}"
    );
    assert!(stdout
        .contains("nmcli connection add type ethernet con-name nexus-mgmt ifname eth0 connection.autoconnect yes"));
    assert!(
        stdout.contains("ipv4.method manual ipv4.addresses 192.0.2.10/24 ipv4.gateway 192.0.2.1 ipv4.dns 192.0.2.53")
    );
    assert!(stdout.contains("+ (dry-run) nmcli --wait 30 connection up nexus-mgmt"));
    assert!(stdout.contains("+ (dry-run) systemctl enable --now nexus-web-api.service nexus-scheduler.service"));

    // recovery key: printed once, matches the KEK, never persisted
    let key = recovery_key(&stdout);
    assert_eq!(stdout.matches(key.as_str()).count(), 1);
    keyd::check_recovery_key(&e.p("var/lib/nexus/keyd"), &key).unwrap();
    assert_key_not_persisted(&e, &key, &stderr);

    // catalog rows
    let c = e.catalog();
    let u = users(&c);
    assert_eq!(u.len(), 2);
    assert_eq!((u[0].0.as_str(), u[0].1.as_str()), ("admin", "admin"));
    assert_eq!((u[1].0.as_str(), u[1].1.as_str()), ("officer", "security_officer"));
    assert!(auth::verify_password(PW_ADMIN, &u[0].2) && auth::verify_password(PW_SO, &u[1].2));
    assert_eq!(u[0].3, e.admin_secret);
    assert_eq!(u[1].3, e.so_secret);

    // audit chain: intact, every entry by `setup`, one per step
    let n = c.verify_audit().unwrap();
    let a = audit_actions(&c);
    assert_eq!(a.len() as i64, n);
    assert!(a.iter().all(|(actor, ..)| actor == "setup"));
    let actions: Vec<&str> = a.iter().map(|(_, act, _)| act.as_str()).collect();
    for want in [
        "setup.run",
        "setup.network",
        "setup.user.create",
        "setup.keyd.init",
        "setup.keyd.confirmed",
        "setup.tls",
        "setup.metrics_token",
        "setup.done",
    ] {
        assert!(actions.contains(&want), "{want} missing in {actions:?}");
    }
    let tls = &a.iter().find(|(_, act, _)| act == "setup.tls").unwrap().2;
    assert_eq!(tls["san"], json!(["nexus01", "192.0.2.10"]));
    let fp1 = tls["fingerprint_sha256"].as_str().unwrap().to_owned();
    assert!(stdout.contains(&fp1));

    // files and permissions
    assert_eq!(mode(&e.p("etc/nexus/tls/key.pem")), 0o600);
    assert_eq!(mode(&e.p("etc/nexus/tls/cert.pem")), 0o644);
    assert!(fs::read_to_string(e.p("etc/nexus/tls/cert.pem"))
        .unwrap()
        .starts_with("-----BEGIN CERTIFICATE-----"));
    assert_eq!(mode(&e.p("etc/nexus/metrics-token")), 0o640);
    let tok = fs::read_to_string(e.p("etc/nexus/metrics-token")).unwrap();
    assert!(tok.trim().len() == 64 && tok.trim().bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(mode(&e.p("var/lib/nexus/keyd")), 0o700);
    assert_eq!(mode(&e.p("var/lib/nexus/keyd/kek.recovery")), 0o600);
    assert_eq!(mode(&e.p("var/lib/nexus/keyd/kek.local")), 0o600);
    assert_eq!(mode(&e.p("var/lib/nexus/catalog")), 0o2770);
    assert_eq!(mode(&e.p("var/lib/nexus/catalog/catalog.db")), 0o660);
    assert!(e.p("var/lib/nexus/setup-done").exists());
    for p in walk_all(&e.root) {
        assert_eq!(mode(&p) & 0o002, 0, "world-writable {}", p.display());
    }
    let kek_recovery = fs::read(e.p("var/lib/nexus/keyd/kek.recovery")).unwrap();
    drop(c);

    // a finished appliance refuses a second run …
    let (out, _, stderr) = e.run(&e.answers("192.0.2.10"), &[]);
    assert!(!out.status.success());
    assert!(stderr.contains("setup already completed"), "{stderr}");

    // … except to reconfigure the network: new address, new certificate, web-api restarted
    let (out, stdout, stderr) = e.run(&e.answers("192.0.2.20"), &["--force-reconfigure-network"]);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("ipv4.addresses 192.0.2.20/24"));
    assert!(stdout.contains("+ (dry-run) systemctl try-restart nexus-web-api.service"));
    assert!(!stdout.contains("RECOVERY KEY"));
    let c = e.catalog();
    c.verify_audit().unwrap();
    let a = audit_actions(&c);
    let tls = &a.iter().rev().find(|(_, act, _)| act == "setup.tls").unwrap().2;
    assert_eq!(tls["san"], json!(["nexus01", "192.0.2.20"]));
    assert_ne!(tls["fingerprint_sha256"].as_str().unwrap(), fp1);
    assert_eq!(users(&c).len(), 2);
    assert_eq!(
        fs::read(e.p("var/lib/nexus/keyd/kek.recovery")).unwrap(),
        kek_recovery,
        "keyd untouched"
    );
    assert_eq!(mode(&e.p("etc/nexus/tls/key.pem")), 0o600);
}

fn walk_all(root: &Path) -> Vec<PathBuf> {
    let mut v = vec![];
    walk(root, &mut v);
    v
}

#[test]
fn resume_keeps_existing_admin_unless_replace_is_explicit() {
    let e = env();
    // interrupted: no security officer in the answers
    let mut ans = e.answers("192.0.2.10");
    ans.as_object_mut().unwrap().remove("security_officer");
    let (out, stdout, stderr) = e.run(&ans, &[]);
    assert!(!out.status.success());
    assert!(stderr.contains("answers lack \"security_officer\""), "{stderr}");
    assert!(
        !stdout.contains("RECOVERY KEY"),
        "keyd untouched before the accounts exist"
    );
    let admin_hash = users(&e.catalog())[0].2.clone();

    // rerun with a different admin password but no `replace`: the admin is kept
    let mut ans = e.answers("192.0.2.10");
    ans["admin"]["password"] = json!("another password entirely");
    let (out, stdout, stderr) = e.run(&ans, &[]);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("network: already configured, kept"));
    assert!(stdout.contains("Administrator: admin exists, kept"));
    let c = e.catalog();
    assert_eq!(users(&c)[0].2, admin_hash);
    assert_eq!(
        audit_actions(&c)
            .iter()
            .filter(|(_, a, _)| a == "setup.network")
            .count(),
        1
    );
    assert_eq!(
        audit_actions(&c)
            .iter()
            .filter(|(_, a, _)| a == "setup.keyd.init")
            .count(),
        1
    );
    c.verify_audit().unwrap();
}

#[test]
fn explicit_replace_updates_the_existing_admin() {
    let e = env();
    let mut ans = e.answers("192.0.2.10");
    ans.as_object_mut().unwrap().remove("security_officer");
    assert!(!e.run(&ans, &[]).0.status.success());

    let new_secret = auth::new_totp_secret();
    let mut ans = e.answers("192.0.2.10");
    ans["admin"] = e.account("root-admin", "a brand new admin password", &new_secret);
    ans["admin"]["replace"] = json!(true);
    let (out, stdout, stderr) = e.run(&ans, &[]);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("Administrator: root-admin replaced"));
    let c = e.catalog();
    let u = users(&c);
    assert_eq!(u.len(), 2);
    assert_eq!((u[0].0.as_str(), u[0].1.as_str()), ("root-admin", "admin"));
    assert!(auth::verify_password("a brand new admin password", &u[0].2));
    assert_eq!(u[0].3, new_secret);
    let a = audit_actions(&c);
    let r = a.iter().find(|(_, act, _)| act == "setup.user.replace").unwrap();
    assert_eq!(r.2["previous_name"], "admin");
}

#[test]
fn invalid_totp_and_shared_names_are_rejected() {
    let e = env();
    let mut ans = e.answers("192.0.2.10");
    let wrong = if auth::totp_now(&e.admin_secret).unwrap() == "123456" {
        "654321"
    } else {
        "123456"
    };
    ans["admin"]["totp_code"] = json!(wrong);
    let (out, _, stderr) = e.run(&ans, &[]);
    assert!(!out.status.success());
    assert!(stderr.contains("TOTP code is not valid"), "{stderr}");
    assert!(users(&e.catalog()).is_empty());

    // four-eyes: the security officer cannot be the admin account
    let mut ans = e.answers("192.0.2.10");
    ans["security_officer"] = e.account("admin", PW_SO, &e.so_secret);
    let (out, _, stderr) = e.run(&ans, &[]);
    assert!(!out.status.success());
    assert!(stderr.contains("four-eyes"), "{stderr}");
    assert_eq!(users(&e.catalog()).len(), 1);

    // password rules from catalog::auth
    let mut ans = e.answers("192.0.2.10");
    ans["security_officer"]["password"] = json!("too short");
    let (out, _, stderr) = e.run(&ans, &[]);
    assert!(!out.status.success());
    assert!(stderr.contains("at least 12 characters"), "{stderr}");
}

#[test]
fn interrupted_keyd_init_is_never_reinitialised() {
    let e = env();
    // simulate a crash right after `keyd init`, before the key was confirmed
    let keyd_dir = e.p("var/lib/nexus/keyd");
    let key = keyd::init(&keyd_dir).unwrap();
    let blob = fs::read(keyd_dir.join("kek.recovery")).unwrap();

    let (out, stdout, stderr) = e.run(&e.answers("192.0.2.10"), &[]);
    assert!(!out.status.success());
    assert!(stderr.contains("cannot be shown again"), "{stderr}");
    assert!(!stdout.contains("RECOVERY KEY"));

    let mut ans = e.answers("192.0.2.10");
    ans["recovery_key"] = json!({"confirm_full": "00".repeat(32)});
    let (out, _, stderr) = e.run(&ans, &[]);
    assert!(!out.status.success());
    assert!(stderr.contains("recovery key rejected"), "{stderr}");

    ans["recovery_key"] = json!({"confirm_full": key.to_uppercase().replace('-', " ")});
    let (out, stdout, stderr) = e.run(&ans, &[]);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("recovery key: confirmed (full re-entry)"));
    assert_eq!(fs::read(keyd_dir.join("kek.recovery")).unwrap(), blob);
    let c = e.catalog();
    let a = audit_actions(&c);
    assert!(!a.iter().any(|(_, act, _)| act == "setup.keyd.init"));
    assert!(a
        .iter()
        .any(|(_, act, d)| act == "setup.keyd.challenge_failed" && d["method"] == "full"));
    assert!(a
        .iter()
        .any(|(_, act, d)| act == "setup.keyd.confirmed" && d["method"] == "full"));
    c.verify_audit().unwrap();
}

#[test]
fn dhcp_queries_the_address_and_cert_has_hostname_only_in_dry_run() {
    let e = env();
    let mut ans = e.answers("192.0.2.10");
    ans["network"] = json!({"nic": "eno1", "method": "dhcp", "hostname": "backup-01"});
    let (out, stdout, stderr) = e.run(&ans, &[]);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("ifname eno1") && stdout.contains("ipv4.method auto"),
        "{stdout}"
    );
    assert!(stdout.contains("+ (dry-run) nmcli -g IP4.ADDRESS device show eno1"));
    let a = audit_actions(&e.catalog());
    let tls = &a.iter().find(|(_, act, _)| act == "setup.tls").unwrap().2;
    assert_eq!(tls["san"], json!(["backup-01"]));
}

#[test]
fn usage_errors() {
    let out = Command::new(env!("CARGO_BIN_EXE_nexus-setup"))
        .arg("--bogus")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let e = env();
    let out = Command::new(env!("CARGO_BIN_EXE_nexus-setup"))
        .args([
            "--root",
            e.root.to_str().unwrap(),
            "--script",
            "/nonexistent/answers.json",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("reading /nonexistent/answers.json"));
}
