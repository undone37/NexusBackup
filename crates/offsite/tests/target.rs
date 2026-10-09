use chunkstore::retention::Gfs;
use chunkstore::{Keyring, Options as StoreOptions, Store};
use offsite::remote::{LocalDir, Remote};
use offsite::target::{Options, Target};
use std::path::Path;

fn keys() -> Keyring {
    Keyring::new("tenant1", &[(1, [5; 32])])
}

fn store(dir: &Path) -> Store {
    Store::open(
        dir,
        keys(),
        StoreOptions {
            min_lock_secs: 0,
            gc_grace_secs: 0,
            ..Default::default()
        },
    )
    .unwrap()
}

/// 48 pseudo-random 64 KiB chunks; snapshot `v` changes chunk `v % 48`.
fn image(v: u64) -> Vec<u8> {
    let mut x = 0x2545F4914F6CDD1Du64;
    (0..48 * 65536usize)
        .map(|i| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            if i / 65536 == (v % 48) as usize {
                (x as u8) ^ (v as u8 | 1)
            } else {
                x as u8
            }
        })
        .collect()
}

fn backup(s: &Store, t: u64, v: u64) {
    let idx = s.store_image(&image(v)[..], 65536).unwrap();
    s.commit_snapshot("vm-1", t, &[("disk", idx)]).unwrap();
}

fn restored(s: &Store, t: u64) -> Vec<u8> {
    let m = s.load_manifest("vm-1", t).unwrap();
    let mut out = Vec::new();
    s.write_chunks(s.load_index(&m, "disk").unwrap().chunk_ids(), &mut out)
        .unwrap();
    out
}

#[test]
fn upload_dr_retention_gc_verify() {
    let d = tempfile::tempdir().unwrap();
    let box_ = LocalDir(d.path().join("box"));
    let a = store(&d.path().join("a"));
    let now = a.compliance_now().unwrap();
    let day = 86400;
    let opts = || Options {
        uploaders: 3,
        ..Default::default()
    };

    for v in 0..3 {
        backup(&a, now - (5 - v) * day, v);
    }
    let mut t = Target::open(&a, &box_, d.path().join("state-a"), opts()).unwrap();
    let st = t.upload().unwrap();
    assert_eq!(
        (st.snapshots, st.chunks),
        (3, 48 + 3),
        "48 base chunks + one changed chunk per snapshot"
    );
    assert_eq!(t.upload().unwrap().snapshots, 0, "idempotent");
    backup(&a, now - 2 * day, 3);
    let st = t.upload().unwrap();
    assert_eq!((st.snapshots, st.chunks), (1, 1), "dedup against offsite inventory");
    assert!(t.check_inventory().unwrap().ok());

    // DR: fresh appliance, same tenant keys, only the box
    let b = store(&d.path().join("b"));
    let mut tb = Target::open(&b, &box_, d.path().join("state-b"), opts()).unwrap();
    assert_eq!(tb.rebuild_from_remote().unwrap(), t.pack_count());
    assert_eq!(tb.snapshots().unwrap().len(), 4);
    tb.restore("vm-1", now - 2 * day).unwrap();
    assert_eq!(restored(&b, now - 2 * day), image(3));
    b.verify(|_| true)
        .map(|r| assert!(r.missing.is_empty() && r.corrupt.is_empty()))
        .unwrap();

    // independent offsite retention: keep 1 daily -> 3 snapshots go (their locks were "now")
    let (kept, deleted, locked) = t
        .apply_retention(&Gfs {
            daily: 1,
            weekly: 0,
            monthly: 0,
            yearly: 0,
        })
        .unwrap();
    assert_eq!((kept, deleted, locked), (1, 3, 0));
    assert!(box_.list("snapshots/vm-1").unwrap().len() == 1);
    // the kept one is locked for 14 days from its time now
    let (_, _, locked) = t
        .apply_retention(&Gfs {
            daily: 0,
            weekly: 0,
            monthly: 0,
            yearly: 0,
        })
        .unwrap();
    assert_eq!(locked, 1, "offsite lock holds");

    // GC: packs are mostly live -> force a repack with threshold 0
    let mut t = Target::open(
        &a,
        &box_,
        d.path().join("state-a"),
        Options {
            repack_threshold: 0.0,
            ..opts()
        },
    )
    .unwrap();
    let g = t.gc().unwrap();
    assert!(g.packs_repacked >= 1 && g.packs_deleted >= 1, "{g:?}");
    assert!(t.check_inventory().unwrap().ok());
    assert_eq!(t.verify_sample(10).unwrap().1, 0);

    // after GC, a second DR still restores the kept snapshot bit-exactly
    let c = store(&d.path().join("c"));
    let mut tc = Target::open(&c, &box_, d.path().join("state-c"), opts()).unwrap();
    tc.rebuild_from_remote().unwrap();
    tc.restore("vm-1", now - 2 * day).unwrap();
    assert_eq!(restored(&c, now - 2 * day), image(3));

    // monitoring: a pack deleted behind our back is reported
    let (id, pack) = box_
        .list("packs")
        .unwrap()
        .into_iter()
        .find_map(|(pp, _, _)| {
            box_.list(&format!("packs/{pp}"))
                .unwrap()
                .first()
                .map(|f| (pp, f.0.clone()))
        })
        .unwrap();
    box_.delete(&format!("packs/{id}/{pack}")).unwrap();
    assert!(!t.check_inventory().unwrap().ok());
}

#[test]
fn wrong_tenant_cannot_read_box() {
    let d = tempfile::tempdir().unwrap();
    let box_ = LocalDir(d.path().join("box"));
    let a = store(&d.path().join("a"));
    a.commit_snapshot("vm-1", 1, &[("disk", a.store_image(&image(0)[..], 65536).unwrap())])
        .unwrap();
    Target::open(&a, &box_, d.path().join("s"), Options::default())
        .unwrap()
        .upload()
        .unwrap();
    let other = Store::open(
        d.path().join("x"),
        Keyring::new("tenant1", &[(1, [6; 32])]),
        StoreOptions::default(),
    )
    .unwrap();
    let mut t = Target::open(&other, &box_, d.path().join("s2"), Options::default()).unwrap();
    assert!(
        t.rebuild_from_remote().is_err(),
        "pack index does not open with another key"
    );
}
