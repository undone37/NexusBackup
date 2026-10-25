//! Against a real XCP-ng host (lab/pvehost/xcpng.sh): a full backup of a VM whose first disk starts with known data,
//! read back from the store. Ignored by default; env: XCPNG_HOST, XCPNG_CA (the host's certificate, PEM file),
//! XCPNG_PASSWORD_FILE (root), XCPNG_VM (UUID), XCPNG_SHA256 (of the disk's first 64 MiB).
//! `cargo test --release -p xcpng --test lab -- --ignored --nocapture`

use chunkstore::{Index, Keyring, Options, Store};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

#[test]
#[ignore]
fn full_backup_of_a_vm() {
    let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} not set"));
    let ca = std::fs::read(env("XCPNG_CA")).unwrap();
    let pw = std::fs::read_to_string(env("XCPNG_PASSWORD_FILE")).unwrap();
    let x = xcpng::xapi::Xapi::login(&env("XCPNG_HOST"), 443, &ca, "root", pw.trim()).unwrap();
    let inv = xcpng::backup::inventory(&x).unwrap();
    eprintln!("inventory: {inv:?}");
    let d = tempfile::tempdir().unwrap();
    let store = Store::open(d.path(), Keyring::new("t", &[(1, [9; 32])]), Options::default()).unwrap();
    let t0 = Instant::now();
    let done = xcpng::backup::backup_vm(&x, &store, &env("XCPNG_VM"), 1, Duration::from_secs(120)).unwrap();
    eprintln!("{}: {} bytes in {:.1?}", done.name, done.bytes_read, t0.elapsed());
    let m = &done.manifest;
    assert!(
        m.indexes.iter().any(|i| i == "xvda") && m.indexes.iter().any(|i| i == "config"),
        "{:?}",
        m.indexes
    );
    let Index::Fixed { size, .. } = store.load_index(m, "xvda").unwrap() else {
        panic!("xvda not fixed")
    };
    let idx = store.load_index(m, "xvda").unwrap();
    let mut first = Vec::new();
    store
        .write_chunks(idx.chunk_ids().iter().take(16).copied(), &mut first)
        .unwrap(); // 16 x 4 MiB
    assert_eq!(format!("{:x}", Sha256::digest(&first[..64 << 20])), env("XCPNG_SHA256"));
    eprintln!("xvda: {size} bytes, the first 64 MiB as written");
    let cfg = store.load_index(m, "config").unwrap();
    let Index::Dynamic { entries } = cfg else {
        panic!("config")
    };
    let mut j = Vec::new();
    store.write_chunks(&entries[0].chunks, &mut j).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&j).unwrap();
    assert_eq!(v["disks"][0]["name"], "xvda");
    // no snapshot left behind on the host
    let left: Vec<_> = x
        .call("VM.get_all_records", &[])
        .unwrap()
        .as_object()
        .unwrap()
        .values()
        .filter(|r| {
            r["is_a_snapshot"].as_bool() == Some(true)
                && r["name_label"].as_str().is_some_and(|n| n.starts_with("nexus-backup-"))
        })
        .map(|r| r["name_label"].clone())
        .collect();
    assert!(left.is_empty(), "{left:?}");
}
