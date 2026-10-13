//! `cargo test -p fileindex --release --test bench -- --ignored --nocapture`:
//! 30 daily snapshots of 200,000 files each (about 2 % changed per day) in
//! one source, the first ingest (rebuild), searches, one incremental append,
//! the sealed index size.

use chunkstore::{Keyring, NameIndex, Options, Store};
use fileindex::service::{Config, Service};
use index_proto::SearchReq;
use std::sync::Arc;
use std::time::Instant;

#[test]
#[ignore]
fn ingest_and_search() {
    let d = tempfile::tempdir().unwrap();
    let keys = || Keyring::new("acme", &[(1, [3; 32])]);
    let store = Store::open(d.path().join("store/acme"), keys(), Options::default()).unwrap();
    let (snaps, files) = (30u64, 200_000u64);
    let t = Instant::now();
    for s in 0..=snaps {
        let mut n = NameIndex::default();
        for i in 0..files {
            // every 50th file changes each day
            let ver = if i % 50 == (s % 50) { s } else { 0 };
            n.push(
                &format!("home/user{}/projects/p{}/src/module_{i}.rs", i % 50, i % 997),
                i * 7 + ver,
                1_700_000_000 + ver as i64,
                0,
            );
        }
        store.commit_snapshot("host-bench", s + 1, &[]).unwrap();
        store.write_names("host-bench", s + 1, &n).unwrap();
        if s == snaps - 1 {
            break;
        }
    }
    println!("setup {:.1?}", t.elapsed());
    let cfg = Config {
        store_base: d.path().join("store"),
        index_base: d.path().join("index"),
        floor_mb: 0,
        ..Config::default()
    };
    let svc = Service::new(cfg, Arc::new(move |_| Ok(keys())));
    let t = Instant::now();
    svc.sync("acme").unwrap();
    let st = svc.status(Some("acme")).unwrap();
    println!(
        "first ingest {:.1?}: {} versions, {} MiB sealed",
        t.elapsed(),
        st.tenants[0].docs,
        st.tenants[0].bytes >> 20
    );
    for q in [
        "module_4711.rs",
        "*.rs",
        "/home/user7/projects/p42/**",
        "nothing-matches-this",
        "module 4711",
    ] {
        let t = Instant::now();
        let r = svc
            .search(&SearchReq {
                tenant: "acme".into(),
                q: q.into(),
                limit: 50,
                ..Default::default()
            })
            .unwrap();
        println!(
            "{q:?}: {:.1?}, {} hits, more: {}",
            t.elapsed(),
            r.hits.len(),
            r.next.is_some()
        );
    }
    // one more day: incremental append
    let mut n = NameIndex::default();
    for i in 0..files {
        let ver = if i % 50 == ((snaps + 1) % 50) { snaps + 1 } else { 0 };
        n.push(
            &format!("home/user{}/projects/p{}/src/module_{i}.rs", i % 50, i % 997),
            i * 7 + ver,
            1_700_000_000 + ver as i64,
            0,
        );
    }
    store.commit_snapshot("host-bench", snaps + 1, &[]).unwrap();
    store.write_names("host-bench", snaps + 1, &n).unwrap();
    let t = Instant::now();
    svc.sync("acme").unwrap();
    let st = svc.status(Some("acme")).unwrap();
    println!(
        "append one snapshot {:.1?}: {} versions",
        t.elapsed(),
        st.tenants[0].docs
    );
    assert_eq!(st.tenants[0].snapshots_pending, 0);
}
