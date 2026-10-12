mod common;

use chunkstore::retention::Gfs;
use chunkstore::{Keyring, Options as StoreOptions, Store};
use common::*;
use offsite::pack;
use offsite::remote::{LocalDir, Remote};
use offsite::target::{Options, Target};

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
        .apply_retention(
            &Gfs {
                recent: 0,
                daily: 1,
                weekly: 0,
                monthly: 0,
                yearly: 0,
            },
            &Default::default(),
        )
        .unwrap();
    assert_eq!((kept, deleted, locked), (1, 3, 0));
    assert!(box_.list("snapshots/vm-1").unwrap().len() == 1);
    // the kept one is locked for 14 days from its time now
    let (_, _, locked) = t
        .apply_retention(
            &Gfs {
                recent: 0,
                daily: 0,
                weekly: 0,
                monthly: 0,
                yearly: 0,
            },
            &Default::default(),
        )
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

/// Regression (fuzzing, hostile_box): foreign names in a box listing made
/// `remote_path` panic, a lying footer underflowed `size - FOOTER - ilen`, and
/// every `*.idx` next to a manifest was copied into the local state.
#[test]
fn hostile_box_listing_and_footer() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("box");
    let box_ = LocalDir(root.clone());
    let a = store(&d.path().join("a"));
    a.commit_snapshot("vm-1", 1, &[("disk", a.store_image(&image(0)[..], 65536).unwrap())])
        .unwrap();
    Target::open(&a, &box_, d.path().join("s"), Options::default())
        .unwrap()
        .upload()
        .unwrap();
    // junk planted by the box: short / non-hex / misplaced pack names, a hidden source,
    // an unauthenticated extra index next to a real manifest
    box_.put("packs/a/a.pack", b"x").unwrap();
    box_.put("packs/zy/\u{e9}.pack", b"x").unwrap();
    box_.put("packs/zz/ff112233445566778899aabbccddeeff.pack", b"x")
        .unwrap();
    box_.put("snapshots/.x/5/manifest", b"x").unwrap();
    box_.put("snapshots/vm-1/1/evil.idx", b"not sealed").unwrap();

    let b = store(&d.path().join("b"));
    let mut t = Target::open(&b, &box_, d.path().join("s2"), Options::default()).unwrap();
    t.rebuild_from_remote().unwrap();
    assert!(!d.path().join("s2/snapshots/vm-1/1/evil.idx").exists());
    assert!(!d.path().join("s2/snapshots/.x").exists());
    let inv = t.check_inventory().unwrap();
    assert!(inv.ok(), "{inv:?}");
    assert_eq!(inv.unknown.len(), 3, "{inv:?}");
    t.restore("vm-1", 1).unwrap();
    assert_eq!(restored(&b, 1), image(0));

    // a footer claiming an index larger than the pack is an error, not a panic
    let (pp, _, _) = box_
        .list("packs")
        .unwrap()
        .into_iter()
        .find(|(p, _, _)| p.len() == 2 && p != "zy" && p != "zz")
        .unwrap();
    let (name, size, _) = box_.list(&format!("packs/{pp}")).unwrap()[0].clone();
    let path = root.join(format!("packs/{pp}/{name}"));
    let mut bytes = std::fs::read(&path).unwrap();
    let n = bytes.len();
    bytes[n - 8..n - 4].copy_from_slice(&(size as u32).to_le_bytes());
    std::fs::write(&path, &bytes).unwrap();
    let c = store(&d.path().join("c"));
    let mut t = Target::open(&c, &box_, d.path().join("s3"), Options::default()).unwrap();
    assert!(t.rebuild_from_remote().is_err());
}

fn gfs(daily: u32) -> Gfs {
    Gfs {
        recent: 0,
        daily,
        weekly: 0,
        monthly: 0,
        yearly: 0,
    }
}

/// Remote retention locks (S3 Object Lock semantics, enforced strictly by the
/// `Locking` double): uploads lock packs and snapshot files until the
/// snapshot's lock, shared packs are extended, retention extends remote locks
/// before the local one, GC never tries to delete a locked object, DR reads
/// the locks back.
#[test]
fn remote_locks_follow_offsite_locks() {
    let d = tempfile::tempdir().unwrap();
    let rem = Locking::new(&d.path().join("box"));
    let a = store_locked(&d.path().join("a"), 3600);
    let now = a.compliance_now().unwrap();
    let opts = || Options {
        uploaders: 2,
        repack_threshold: 0.0,
        ..Default::default()
    };
    let (t0, t1) = (now - 3 * DAY, now - 2 * DAY);
    backup(&a, t0, 0);
    let mut t = Target::open(&a, &rem, d.path().join("state"), opts()).unwrap();
    t.upload().unwrap();
    let first: Vec<String> = t.pack_ids();
    assert_eq!(first.len(), 1);
    let l0 = a.load_manifest("vm-1", t0).unwrap().lock_until;
    assert!(l0 >= now + 3600);
    assert_eq!(rem.lock(&pack::remote_path(&first[0])), Some(l0));
    assert_eq!(rem.lock(&format!("snapshots/vm-1/{t0}/manifest")), Some(l0));
    assert_eq!(rem.lock(&format!("snapshots/vm-1/{t0}/disk.idx")), Some(l0));

    // the second snapshot shares the first pack: extended to its own lock
    std::thread::sleep(std::time::Duration::from_millis(1100));
    backup(&a, t1, 1);
    t.upload().unwrap();
    let l1 = a.load_manifest("vm-1", t1).unwrap().lock_until;
    assert!(l1 > l0);
    assert_eq!(rem.lock(&pack::remote_path(&first[0])), Some(l1));
    let second: Vec<String> = t.pack_ids().into_iter().filter(|p| !first.contains(p)).collect();
    assert_eq!(rem.lock(&pack::remote_path(&second[0])), Some(l1));
    assert_eq!(t.pack_lock(&second[0]), l1);

    // GFS promotion: 14-day locks, on the remote first
    let (kept, deleted, _) = t.apply_retention(&gfs(2), &Default::default()).unwrap();
    assert_eq!((kept, deleted), (2, 0));
    let (w0, w1) = (t0 + 14 * DAY, t1 + 14 * DAY);
    assert_eq!(rem.lock(&format!("snapshots/vm-1/{t0}/manifest")), Some(w0));
    assert_eq!(rem.lock(&format!("snapshots/vm-1/{t1}/disk.idx")), Some(w1));
    assert_eq!(
        rem.lock(&pack::remote_path(&first[0])),
        Some(w1),
        "max over its snapshots"
    );
    assert_eq!(rem.lock(&pack::remote_path(&second[0])), Some(w1));

    // GC: everything is locked, nothing is touched (threshold 0 would repack)
    let g = t.gc().unwrap();
    assert_eq!((g.packs_deleted, g.packs_repacked), (0, 0), "{g:?}");
    assert!(g.packs_locked >= 1, "{g:?}");
    // retention with nothing to keep: the locks hold
    let (_, deleted, locked) = t.apply_retention(&gfs(0), &Default::default()).unwrap();
    assert_eq!((deleted, locked), (0, 2));
    assert_eq!(rem.refused(), 0, "the engine never tries to delete locked objects");

    // escrow files are locked as long as the longest snapshot
    t.put_if_missing("keys/kek.recovery", b"k").unwrap();
    t.protect("keys/kek.recovery").unwrap();
    assert_eq!(rem.lock("keys/kek.recovery"), Some(w1));

    // DR: locks come back from the remote
    let b = store(&d.path().join("b"));
    let mut tb = Target::open(&b, &rem, d.path().join("state-b"), opts()).unwrap();
    tb.rebuild_from_remote().unwrap();
    assert_eq!(tb.pack_lock(&first[0]), w1);
    assert_eq!(tb.max_lock().unwrap(), w1);
    let (_, deleted, locked) = tb.apply_retention(&gfs(0), &Default::default()).unwrap();
    assert_eq!((deleted, locked), (0, 2), "the DR copy knows the extended locks");
    assert!(tb.check_inventory().unwrap().ok());
    tb.restore("vm-1", t1).unwrap();
    assert_eq!(restored(&b, t1), image(1));
    assert_eq!(rem.refused(), 0);
}

/// Dead packs whose locks have ended are deleted; locked ones wait.
#[test]
fn gc_deletes_expired_and_skips_locked_packs() {
    let d = tempfile::tempdir().unwrap();
    let rem = Locking::new(&d.path().join("box"));
    let a = store(&d.path().join("a"));
    let now = a.compliance_now().unwrap();
    let mut t = Target::open(
        &a,
        &rem,
        d.path().join("state"),
        Options {
            repack_threshold: 0.0,
            ..Default::default()
        },
    )
    .unwrap();
    // one upload per snapshot: A = base with chunk 0', B = {1', base 0}, C = {2'}, D = {3'}
    for v in 0..4 {
        backup(&a, now - (5 - v) * DAY, v);
        t.upload().unwrap();
    }
    assert_eq!(t.pack_count(), 4);
    // keep the newest only: 14-day lock on the packs it needs (A, B, D)
    let (kept, deleted, _) = t.apply_retention(&gfs(1), &Default::default()).unwrap();
    assert_eq!((kept, deleted), (1, 3));
    let g = t.gc().unwrap();
    assert_eq!(g.packs_deleted, 1, "C: dead, never locked; {g:?}");
    assert_eq!(
        g.packs_locked, 3,
        "A, B, D are repack candidates (threshold 0) but locked; {g:?}"
    );
    assert_eq!(rem.refused(), 0);
    assert!(t.check_inventory().unwrap().ok());
    assert_eq!(t.verify_sample(10).unwrap().1, 0);
}

/// Legal hold (Phase 15c): offsite retention never deletes a held snapshot,
/// GC keeps its packs, and it restores from the box; released, it is pruned.
#[test]
fn held_snapshots_survive_offsite_retention_and_gc() {
    let d = tempfile::tempdir().unwrap();
    let box_ = LocalDir(d.path().join("box"));
    let a = store(&d.path().join("a"));
    let now = a.compliance_now().unwrap();
    let opts = || Options {
        repack_threshold: 0.0,
        ..Default::default()
    };
    let times: Vec<u64> = (0..3).map(|v| now - (5 - v) * DAY).collect();
    for (v, t) in times.iter().enumerate() {
        backup(&a, *t, v as u64);
    }
    let mut t = Target::open(&a, &box_, d.path().join("state-a"), opts()).unwrap();
    t.upload().unwrap();
    let held = std::collections::BTreeSet::from([("vm-1".to_owned(), times[0])]);
    let (kept, deleted, locked) = t.apply_retention(&gfs(1), &held).unwrap();
    assert_eq!((kept, deleted, locked), (2, 1, 0));
    let left = t.snapshots().unwrap();
    assert_eq!(left, vec![("vm-1".to_owned(), times[0]), ("vm-1".to_owned(), times[2])]);
    t.gc().unwrap();
    assert!(t.check_inventory().unwrap().ok());
    let b = store(&d.path().join("b"));
    let mut tb = Target::open(&b, &box_, d.path().join("state-b"), opts()).unwrap();
    tb.rebuild_from_remote().unwrap();
    tb.restore("vm-1", times[0]).unwrap();
    assert_eq!(restored(&b, times[0]), image(0));
    // released: the next run prunes it
    let (_, deleted, _) = t.apply_retention(&gfs(1), &Default::default()).unwrap();
    assert_eq!(deleted, 1);
}

/// Offsite in the UI (Phase 17d): the listing cross-checks inventory, box and
/// local store; a fetched-back snapshot is locked locally for the keep time,
/// so local retention leaves it alone until then.
#[test]
fn listing_and_fetch_back_survives_local_retention() {
    let d = tempfile::tempdir().unwrap();
    let box_ = LocalDir(d.path().join("box"));
    let a = store(&d.path().join("a"));
    let now = a.compliance_now().unwrap();
    for v in 0..3 {
        backup(&a, now - (5 - v) * DAY, v);
    }
    let t = {
        let mut t = Target::open(&a, &box_, d.path().join("state"), Options::default()).unwrap();
        t.upload().unwrap();
        t
    };
    let (t0, t1, t2) = (now - 5 * DAY, now - 4 * DAY, now - 3 * DAY);
    // local retention removed the oldest one; the box lost the newest manifest
    a.delete_snapshot("vm-1", t0).unwrap();
    std::fs::remove_file(d.path().join(format!("box/snapshots/vm-1/{t2}/manifest"))).unwrap();
    let l = t.listing().unwrap();
    let flags: Vec<(u64, bool, bool, bool)> = l.iter().map(|x| (x.time, x.inventory, x.remote, x.local)).collect();
    assert_eq!(
        flags,
        [(t0, true, true, false), (t1, true, true, true), (t2, true, false, true)]
    );
    assert_eq!(l[0].size, Some(48 * 65536), "logical size from the sealed indexes");

    // box snapshots this appliance's inventory does not know (another state dir)
    let other = Target::open(&a, &box_, d.path().join("state-2"), Options::default()).unwrap();
    let l = other.listing().unwrap();
    assert_eq!(l.len(), 2);
    assert!(l.iter().all(|x| !x.inventory && x.remote && x.size.is_none()));

    // fetch back with a 7-day keep, then a retention that keeps nothing
    t.fetch("vm-1", t0, 7 * DAY).unwrap();
    assert_eq!(restored(&a, t0), image(0));
    assert!(a.load_manifest("vm-1", t0).unwrap().lock_until >= now + 7 * DAY);
    let (_, deleted, locked) = a.apply_retention("vm-1", &gfs(0)).unwrap();
    assert_eq!((deleted, locked), (2, 1), "the fetched copy stays while its lock runs");
    assert!(a.load_manifest("vm-1", t0).is_ok());
}
