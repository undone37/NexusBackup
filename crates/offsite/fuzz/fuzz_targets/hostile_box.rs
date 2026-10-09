//! A malicious Storage Box: listings, pack footers/indexes and snapshot files
//! all come from the fuzz input. DR rebuild, inventory check, sampled verify,
//! restore and GC must never panic, never write outside the appliance's store
//! and state directories, and never lose the local snapshot.
#![no_main]

use chunkstore::{Options, Store};
use libfuzzer_sys::fuzz_target;
use offsite::target::{self, Target};
use offsite_fuzz::{keys, MemBox};

fuzz_target!(|data: &[u8]| {
    let remote = MemBox::decode(data);
    let base = tempfile::tempdir_in("/dev/shm").unwrap();
    let root = base.path().join("appliance");
    let store = Store::open(
        root.join("store"),
        keys(),
        Options {
            min_lock_secs: 0,
            gc_grace_secs: 0,
            ..Default::default()
        },
    )
    .unwrap();
    let idx = store.store_image(&[7u8; 3000][..], 1024).unwrap();
    store.commit_snapshot("vm-local", 1, &[("disk", idx)]).unwrap();

    if let Ok(mut t) = Target::open(&store, &remote, root.join("state"), target::Options::default()) {
        let _ = t.rebuild_from_remote();
        let _ = t.check_inventory();
        let _ = t.verify_sample(4);
        for (source, time) in t.snapshots().unwrap_or_default() {
            let _ = t.restore(&source, time);
        }
        let _ = t.gc();
    }

    // the local snapshot survives, and nothing was created next to the store / state
    let m = store.load_manifest("vm-local", 1).expect("local snapshot lost");
    store.load_index(&m, "disk").expect("local index lost");
    let mut top: Vec<String> = std::fs::read_dir(base.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    top.sort();
    assert_eq!(top, ["appliance"], "file written outside the appliance dir");
    let mut inner: Vec<String> = std::fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    inner.sort();
    assert!(inner.iter().all(|n| n == "state" || n == "store"), "escaped: {inner:?}");
    if let Ok(rd) = std::fs::read_dir(root.join("state")) {
        for e in rd {
            let n = e.unwrap().file_name();
            assert!(n == "packs" || n == "snapshots", "escaped into state/{n:?}");
        }
    }
});
