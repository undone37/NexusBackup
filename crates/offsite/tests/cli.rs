//! `nexus-offsite` end to end with two keyd instances (Phase 17d): appliance A
//! uploads to a local "box"; appliance B (its own KEK) attaches the copy with
//! A's recovery key over its keyd socket, lists it and fetches a snapshot back.

mod common;

use chunkstore::{Options as StoreOptions, Store};
use common::*;
use serde_json::{json, Value};
use std::fs;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;

fn keyd(dir: &Path) -> (String, PathBuf) {
    let rk = keyd::init(dir).unwrap();
    let sock = dir.join("k.sock");
    let l = UnixListener::bind(&sock).unwrap();
    let (dir, me) = (dir.to_owned(), unsafe { libc::getuid() });
    std::thread::spawn(move || keyd::serve(l, &dir, me));
    (rk, sock)
}

fn config(root: &Path, name: &str, sock: &Path, box_: &Path) -> PathBuf {
    let cfg = json!({
        "store": root.join(name).join("store"), "tenant": "acme", "keyd_socket": sock,
        "escrow_dir": root.join(name).join("escrow"), "state": root.join(name).join("state"),
        "remote": {"type": "local", "path": box_},
    });
    let p = root.join(format!("{name}.json"));
    fs::write(&p, cfg.to_string()).unwrap();
    p
}

fn run(cfg: &Path, args: &[&str]) -> (bool, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_nexus-offsite"))
        .arg(cfg)
        .args(args)
        .output()
        .unwrap();
    let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&o.stderr));
    (o.status.success(), s)
}

#[test]
fn attach_list_and_fetch_with_a_second_keyd() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path();
    let box_ = root.join("box");
    let (ka, kb) = (root.join("keyd-a"), root.join("keyd-b"));
    fs::create_dir_all(&ka).unwrap();
    fs::create_dir_all(&kb).unwrap();

    // appliance A: one backup, escrow exported, uploaded
    let (rk, sock_a) = keyd(&ka);
    let cfg_a = config(root, "a", &sock_a, &box_);
    let time = {
        let keys = keyd::ensure_keyring(&sock_a, "acme").unwrap();
        let a = Store::open(root.join("a/store"), keys, StoreOptions::default()).unwrap();
        let t = a.compliance_now().unwrap() - 3 * DAY;
        backup(&a, t, 1);
        t
    };
    for (name, bytes) in keyd::export_escrow(&ka, "acme").unwrap() {
        let p = root.join("a/escrow").join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, bytes).unwrap();
    }
    let (ok, out) = run(&cfg_a, &["upload"]);
    assert!(ok, "{out}");

    // appliance B: own KEK; attach with A's recovery key
    let (_, sock_b) = keyd(&kb);
    let cfg_b = config(root, "b", &sock_b, &box_);
    let key_file = root.join("rk");
    fs::write(&key_file, keyd::format_recovery_key(&[3; 32])).unwrap();
    let (ok, out) = run(&cfg_b, &["attach", key_file.to_str().unwrap()]);
    assert!(!ok && out.contains("keyd refused"), "wrong key: {out}");
    assert!(!key_file.exists(), "the key file is consumed even on failure");
    fs::write(&key_file, &rk).unwrap();
    let (ok, out) = run(&cfg_b, &["attach", key_file.to_str().unwrap()]);
    assert!(ok, "{out}");
    assert!(out.contains("1 snapshots indexed"), "{out}");
    assert!(!out.contains(&rk), "the recovery key is never printed");
    assert!(!key_file.exists());

    let (ok, out) = run(&cfg_b, &["list", "--json"]);
    assert!(ok, "{out}");
    let l: Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(l[0]["source"], "vm-1");
    assert_eq!(l[0]["time"], time);
    assert_eq!(
        (l[0]["local"].as_bool(), l[0]["remote"].as_bool()),
        (Some(false), Some(true))
    );

    let (ok, out) = run(&cfg_b, &["restore", "vm-1", &time.to_string(), "604800"]);
    assert!(ok, "{out}");
    let keys = keyd::fetch_keyring(&sock_b, "acme").unwrap();
    let b = Store::open(root.join("b/store"), keys, StoreOptions::default()).unwrap();
    assert_eq!(restored(&b, time), image(1));
    assert!(b.load_manifest("vm-1", time).unwrap().lock_until >= b.compliance_now().unwrap() + 604000);
}

/// After a configuration restore appliance C has A's KEK (kek.recovery from the
/// bundle + the recovery key): `rekey` installs the tenant's wrapped DEKs from the
/// box without the recovery key and indexes the copy; a foreign KEK is refused.
#[test]
fn rekey_after_config_restore() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path();
    let box_ = root.join("box");
    let (ka, kc, kx) = (root.join("keyd-a"), root.join("keyd-c"), root.join("keyd-x"));
    for k in [&ka, &kc, &kx] {
        fs::create_dir_all(k).unwrap();
    }
    let (rk, sock_a) = keyd(&ka);
    let cfg_a = config(root, "a", &sock_a, &box_);
    let keys = keyd::ensure_keyring(&sock_a, "acme").unwrap();
    let a = Store::open(root.join("a/store"), keys, StoreOptions::default()).unwrap();
    backup(&a, a.compliance_now().unwrap() - DAY, 1);
    for (name, bytes) in keyd::export_escrow(&ka, "acme").unwrap() {
        let p = root.join("a/escrow").join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, bytes).unwrap();
    }
    assert!(run(&cfg_a, &["upload"]).0);

    // a foreign appliance (own KEK) cannot rekey from A's escrow
    let (_, sock_x) = keyd(&kx);
    let (ok, out) = run(&config(root, "x", &sock_x, &box_), &["rekey"]);
    assert!(!ok && out.contains("keyd refused"), "{out}");

    fs::write(kc.join("kek.recovery"), fs::read(ka.join("kek.recovery")).unwrap()).unwrap();
    keyd::recover(&kc, &rk).unwrap();
    let sock_c = kc.join("k.sock");
    let l = UnixListener::bind(&sock_c).unwrap();
    let (dir, me) = (kc.clone(), unsafe { libc::getuid() });
    std::thread::spawn(move || keyd::serve(l, &dir, me));
    let (ok, out) = run(&config(root, "c", &sock_c, &box_), &["rekey"]);
    assert!(ok, "{out}");
    assert!(out.contains("1 snapshots indexed"), "{out}");
    assert!(!out.contains(&rk));
}
