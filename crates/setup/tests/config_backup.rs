//! Configuration backup end to end in temp roots: the helper binary answers a
//! scheduler request (bundle without the recovery key), the bundle goes to a
//! local "offsite" target, and `nexus-setup restore-config --offsite` brings it
//! back on a new appliance with the recovery key.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn old_appliance(root: &Path) -> String {
    let keyd = root.join("var/lib/nexus/keyd");
    fs::create_dir_all(&keyd).unwrap();
    let rk = keyd::init(&keyd).unwrap();
    let run = root.join("run/nexus-keyd");
    fs::create_dir_all(&run).unwrap();
    keyd::config_bundle::publish(&keyd, &run).unwrap();
    let db = root.join("var/lib/nexus/catalog/catalog.db");
    fs::create_dir_all(db.parent().unwrap()).unwrap();
    let cat = catalog::Catalog::open(&db).unwrap();
    cat.conn()
        .execute(
            "INSERT INTO users (name, password_hash, totp_secret, role, created) VALUES ('alice', 'h', 'enc', 'admin', 1)",
            [],
        )
        .unwrap();
    for (p, d) in [
        ("var/lib/nexus/webapi/totp.key", "totp"),
        ("var/lib/nexus/scheduler/secrets.key", "secrets"),
        ("etc/nexus/ssh/offsite-acme", "ssh"),
        ("etc/nexus/tls/key.pem", "tls-key"),
    ] {
        let p = root.join(p);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, d).unwrap();
    }
    rk
}

#[test]
fn helper_bundle_offsite_and_restore_config() {
    let old = tempfile::tempdir().unwrap();
    let rk = old_appliance(old.path());
    let ctl = old.path().join("var/lib/nexus/config-backup");
    fs::create_dir_all(&ctl).unwrap();
    fs::write(ctl.join("request.json"), r#"{"id": 7, "appliance": "0a1b2c"}"#).unwrap();
    let st = Command::new(env!("CARGO_BIN_EXE_nexus-config-backup"))
        .args(["tick"])
        .arg(&ctl)
        .arg(old.path())
        .arg(old.path().join("run/nexus-keyd"))
        .status()
        .unwrap();
    assert!(st.success());
    assert!(!ctl.join("request.json").exists(), "request consumed");
    let status: serde_json::Value = serde_json::from_slice(&fs::read(ctl.join("status.json")).unwrap()).unwrap();
    assert_eq!(status["state"], "done", "{status}");
    assert_eq!(status["id"], 7);
    let bundle = fs::read(ctl.join("latest.bundle")).unwrap();
    assert_eq!(status["bytes"], bundle.len());

    // an invalid request is answered with an error status, not a crash
    fs::write(ctl.join("request.json"), r#"{"id": 8, "appliance": "../x"}"#).unwrap();
    Command::new(env!("CARGO_BIN_EXE_nexus-config-backup"))
        .args(["tick"])
        .arg(&ctl)
        .arg(old.path())
        .arg(old.path().join("run/nexus-keyd"))
        .status()
        .unwrap();
    let status: serde_json::Value = serde_json::from_slice(&fs::read(ctl.join("status.json")).unwrap()).unwrap();
    assert_eq!(
        (status["id"].as_i64(), status["state"].as_str()),
        (Some(8), Some("error"))
    );

    // the scheduler's upload (offsite::config) into a local target
    let box_dir = tempfile::tempdir().unwrap();
    let remote = offsite::remote::LocalDir(box_dir.path().to_owned());
    offsite::config::put(&remote, "0a1b2c", 1_800_000_000, &bundle, 1_800_000_000).unwrap();
    let target = old.path().join("target.json");
    fs::write(
        &target,
        serde_json::json!({"remote": {"type": "local", "path": box_dir.path()}}).to_string(),
    )
    .unwrap();

    let new = tempfile::tempdir().unwrap();
    let restore = |key: &str| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nexus-setup"))
            .args(["restore-config", "--offsite"])
            .arg(&target)
            .args(["--dry-run", "--root"])
            .arg(new.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin
            .take()
            .unwrap()
            .write_all(format!("{key}\n").as_bytes())
            .unwrap();
        c.wait_with_output().unwrap()
    };
    let out = restore(&keyd::format_recovery_key(&[1; 32]));
    assert!(!out.status.success(), "wrong recovery key accepted");
    assert!(String::from_utf8_lossy(&out.stderr).contains("recovery key does not open"));
    assert!(!new.path().join("var/lib/nexus/setup-done").exists());

    let out = restore(&rk);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    for (p, d) in [
        ("var/lib/nexus/webapi/totp.key", "totp"),
        ("var/lib/nexus/scheduler/secrets.key", "secrets"),
        ("etc/nexus/ssh/offsite-acme", "ssh"),
        ("etc/nexus/tls/key.pem", "tls-key"),
    ] {
        assert_eq!(fs::read_to_string(new.path().join(p)).unwrap(), d, "{p}");
    }
    keyd::check_recovery_key(&new.path().join("var/lib/nexus/keyd"), &rk).unwrap();
    let cat = catalog::Catalog::open(&new.path().join("var/lib/nexus/catalog/catalog.db")).unwrap();
    let n: i64 = cat
        .conn()
        .query_row("SELECT COUNT(*) FROM users WHERE name = 'alice'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1);
    assert!(new.path().join("var/lib/nexus/setup-done").exists());
}
