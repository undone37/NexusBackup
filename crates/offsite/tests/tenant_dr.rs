//! Phase 17e: tenant-level DR with the tenant recovery key against a local
//! "box" (the same `keys/` layout `nexus-offsite upload` writes).
mod common;

use chunkstore::{Keyring, Options as StoreOptions, Store};
use common::*;
use offsite::dr;
use offsite::remote::{LocalDir, Remote};
use offsite::target::{Options, Target};
use std::fs;
use std::path::Path;

fn tenant_store(dir: &Path, deks: &[(u32, [u8; 32])]) -> Store {
    Store::open(dir, Keyring::new("acme", deks), StoreOptions::default()).unwrap()
}

fn deks(keyd: &Path, t: &str) -> Vec<(u32, [u8; 32])> {
    keyd::tenant_deks(keyd, t)
        .unwrap()
        .into_iter()
        .map(|(v, k)| (v, *k))
        .collect()
}

/// What `nexus-offsite upload` does with the escrow (put if missing, prune old tenant escrow).
fn upload_escrow(box_: &dyn Remote, keyd: &Path, tenant: &str) -> Vec<String> {
    let esc = keyd::export_escrow(keyd, tenant).unwrap();
    for (n, b) in &esc {
        match box_.put(&format!("keys/{n}"), b) {
            Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => panic!("{e}"),
            _ => {}
        }
    }
    dr::prune_tenant_escrow(box_, tenant, &esc)
}

#[test]
fn dr_with_tenant_key_only_that_tenant() {
    let d = tempfile::tempdir().unwrap();
    let ka = d.path().join("keyd-a");
    let rk = keyd::init(&ka).unwrap();
    keyd::create_tenant(&ka, "acme").unwrap();
    keyd::create_tenant(&ka, "other").unwrap();
    let (tk, public) = keyd::tenant_key::generate();
    keyd::tenant_key::set(&ka, "acme", Some(&public)).unwrap();
    // rotation after the key was set: v2 is sealed with the public key alone
    keyd::rotate_tenant(&ka, "acme").unwrap();

    let a = tenant_store(&d.path().join("a"), &deks(&ka, "acme"));
    let t0 = a.compliance_now().unwrap() - DAY;
    backup(&a, t0, 1);
    let box_ = LocalDir(d.path().join("box"));
    let mut t = Target::open(&a, &box_, d.path().join("state-a"), Options::default()).unwrap();
    t.upload().unwrap();
    assert!(upload_escrow(&box_, &ka, "acme").is_empty());
    upload_escrow(&box_, &ka, "other"); // a shared box would also carry other tenants' keys
    let names: Vec<_> = box_
        .list("keys/tenants/acme")
        .unwrap()
        .into_iter()
        .map(|e| e.0)
        .collect();
    assert_eq!(names.iter().filter(|n| n.starts_with("tenant-escrow.")).count(), 2);

    // fresh appliance with its own KEK: tenant key -> acme only
    let kb = d.path().join("keyd-b");
    keyd::init(&kb).unwrap();
    let own_escrow = fs::read(kb.join("kek.recovery")).unwrap();
    assert!(
        dr::tenant_keys(&box_, "acme", &kb, &rk).is_err(),
        "the appliance key is not a tenant key"
    );
    assert!(
        dr::tenant_keys(&box_, "other", &kb, &tk).is_err(),
        "other tenants stay locked"
    );
    let got = dr::tenant_keys(&box_, "acme", &kb, &tk).unwrap();
    assert_eq!(got, deks(&ka, "acme"));
    assert_eq!(deks(&kb, "acme"), deks(&ka, "acme"));
    assert_eq!(
        fs::read(kb.join("kek.recovery")).unwrap(),
        own_escrow,
        "appliance escrow untouched"
    );
    assert!(!kb.join("tenants/other").exists());
    assert!(
        keyd::check_recovery_key(&kb, &rk).is_err(),
        "the old KEK was not recovered"
    );

    let b = tenant_store(&d.path().join("b"), &got);
    let mut tb = Target::open(&b, &box_, d.path().join("state-b"), Options::default()).unwrap();
    tb.rebuild_from_remote().unwrap();
    tb.restore("vm-1", t0).unwrap();
    assert_eq!(restored(&b, t0), image(1));

    // without an initialized keyd: refused
    assert!(dr::tenant_keys(&box_, "acme", &d.path().join("empty"), &tk).is_err());

    // the appliance-wide DR still works with the tenant escrow on the box
    let kc = d.path().join("keyd-c");
    assert_eq!(dr::appliance_keys(&box_, "acme", &kc, &rk).unwrap(), deks(&ka, "acme"));

    // replacing the key: the next upload removes the old escrow, the old key opens nothing
    let (tk2, p2) = keyd::tenant_key::generate();
    keyd::tenant_key::set(&ka, "acme", Some(&p2)).unwrap();
    assert_eq!(upload_escrow(&box_, &ka, "acme").len(), 2);
    let kd = d.path().join("keyd-d");
    keyd::init(&kd).unwrap();
    assert!(dr::tenant_keys(&box_, "acme", &kd, &tk).is_err());
    assert_eq!(dr::tenant_keys(&box_, "acme", &kd, &tk2).unwrap(), deks(&ka, "acme"));
}
