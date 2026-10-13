use chunkstore::{FileEntry, Index, Keyring, Options, Store};
use std::io::ErrorKind;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

fn keys() -> Keyring {
    Keyring::new("tenant1", &[(1, [9; 32])])
}

fn open(dir: &Path, min_lock_secs: u64, gc_grace_secs: u64) -> Store {
    Store::open(
        dir,
        keys(),
        Options {
            min_lock_secs,
            gc_grace_secs,
            ..Default::default()
        },
    )
    .unwrap()
}

/// Deterministic pseudo-random image; chunk `t % 6` differs per snapshot.
fn image(t: u64) -> Vec<u8> {
    let mut x = 0x9e3779b97f4a7c15u64;
    (0..6 * 65536usize)
        .map(|i| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            if i / 65536 == (t % 6) as usize {
                (x as u8) ^ (t as u8)
            } else {
                x as u8
            }
        })
        .collect()
}

fn restore(s: &Store, m: &chunkstore::Manifest, name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    s.write_chunks(s.load_index(m, name).unwrap().chunk_ids(), &mut out)
        .unwrap();
    out
}

#[test]
fn image_and_files_roundtrip_with_dedup() {
    let d = tempfile::tempdir().unwrap();
    let s = open(d.path(), 0, 0);
    let img = s.store_image(&image(1)[..], 65536).unwrap();
    let file = vec![7u8; 3 << 20];
    let (chunks, size) = s.store_file(&file[..]).unwrap();
    let files = Index::Dynamic {
        entries: vec![FileEntry {
            path: "a/b".into(),
            mode: 0o644,
            size,
            mtime: 0,
            chunks,
        }],
    };
    let m = s
        .commit_snapshot("vm-100", 1, &[("disk0", img), ("files", files)])
        .unwrap();
    assert_eq!(restore(&s, &m, "disk0"), image(1));
    assert_eq!(restore(&s, &m, "files"), file);

    // image(2) differs from image(1) in chunks 1 and 2 only
    let new = image(2)
        .chunks(65536)
        .map(|c| s.insert_chunk(c).unwrap().1)
        .filter(|&n| n)
        .count();
    assert_eq!(new, 2);
    assert!(s.commit_snapshot("vm-100", 1, &[]).unwrap_err().kind() == ErrorKind::AlreadyExists);
    assert!(s.commit_snapshot("../etc", 2, &[]).is_err(), "path traversal rejected");
}

#[test]
fn wrong_keyring_rejected() {
    let d = tempfile::tempdir().unwrap();
    open(d.path(), 0, 0);
    let other = Keyring::new("tenant1", &[(1, [8; 32])]);
    assert!(Store::open(d.path(), other, Options::default()).is_err());
}

#[test]
fn locks_only_extend_and_block_delete() {
    let d = tempfile::tempdir().unwrap();
    let s = open(d.path(), 3600, 0);
    let m = s.commit_snapshot("vm-1", 10, &[]).unwrap();
    assert_eq!(s.extend_lock("vm-1", 10, 0).unwrap(), m.lock_until, "cannot shorten");
    assert_eq!(s.extend_lock("vm-1", 10, m.lock_until + 99).unwrap(), m.lock_until + 99);
    assert_eq!(
        s.delete_snapshot("vm-1", 10).unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );
    drop(s);
    let s = open(d.path(), 0, 0); // reopening with weaker options changes nothing
    assert!(s.delete_snapshot("vm-1", 10).is_err());
    s.commit_snapshot("vm-1", 11, &[]).unwrap();
    s.delete_snapshot("vm-1", 11).unwrap();
    assert_eq!(s.list_snapshots().unwrap().len(), 1);
}

#[test]
fn gc_sweeps_only_unreferenced_and_needs_quorum_for_mass_delete() {
    let d = tempfile::tempdir().unwrap();
    let s = open(d.path(), 0, 0);
    for t in 1..=3 {
        let idx = s.store_image(&image(t)[..], 65536).unwrap();
        s.commit_snapshot("vm", t, &[("disk", idx)]).unwrap();
    }
    s.delete_snapshot("vm", 1).unwrap();
    std::thread::sleep(Duration::from_millis(20));
    let st = s.gc(false).unwrap(); // 6 base + 3 variants; 1 of 9 dead: under 20 %
    assert_eq!((st.total, st.deleted), (9, 1));
    s.delete_snapshot("vm", 2).unwrap();
    s.delete_snapshot("vm", 3).unwrap();
    assert_eq!(s.gc(false).unwrap_err().kind(), ErrorKind::PermissionDenied);
    assert_eq!(s.gc(true).unwrap().deleted, 8);

    // grace period protects fresh unreferenced chunks (in-flight backup)
    let s = open(d.path(), 0, 3600);
    s.insert_chunk(b"in flight").unwrap();
    assert_eq!(s.gc(true).unwrap().deleted, 0);
}

#[test]
fn verify_detects_corruption_and_missing() {
    let d = tempfile::tempdir().unwrap();
    let s = open(d.path(), 0, 0);
    let idx = s.store_image(&image(1)[..], 65536).unwrap();
    let ids: Vec<_> = idx.chunk_ids().into_iter().copied().collect();
    s.commit_snapshot("vm", 1, &[("disk", idx)]).unwrap();
    let path = |id: &[u8; 32]| {
        let h = chunkstore::crypto::hex(id);
        d.path().join("chunks").join(&h[..4]).join(h)
    };
    let mut b = std::fs::read(path(&ids[0])).unwrap();
    b[40] ^= 0xff;
    std::fs::write(path(&ids[0]), b).unwrap();
    std::fs::remove_file(path(&ids[1])).unwrap();
    let r = s.verify(|_| true).unwrap();
    assert_eq!((r.checked, r.corrupt, r.missing), (5, vec![ids[0]], vec![ids[1]]));
}

/// Child half of the crash test: writes snapshots until killed.
#[test]
fn crash_child() {
    let Ok(dir) = std::env::var("CHUNKSTORE_CRASH_DIR") else {
        return;
    };
    let s = open(Path::new(&dir), 0, 0);
    let mut t = s.list_snapshots().unwrap().last().map_or(0, |m| m.time);
    let progress = Path::new(&dir).join("progress");
    loop {
        t += 1;
        let idx = s.store_image(&image(t)[..], 65536).unwrap();
        s.commit_snapshot("vm", t, &[("disk", idx)]).unwrap();
        // one byte per commit: the parent kills only after this round made progress
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&progress)
            .unwrap();
        std::io::Write::write_all(&mut f, b".").unwrap();
    }
}

/// kill -9 the writer at random points; every committed snapshot must restore
/// bit-exact and GC + verify must leave a consistent store.
#[test]
fn survives_kill_9() {
    let d = tempfile::tempdir().unwrap();
    for round in 0..6u64 {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["crash_child", "--exact", "--nocapture", "--test-threads=1"])
            .env("CHUNKSTORE_CRASH_DIR", d.path())
            .spawn()
            .unwrap();
        // wait for this round's first commit (slow CI runners need more than a fixed delay), then kill
        // at a varying point of a later write
        let progress = d.path().join("progress");
        let before = std::fs::metadata(&progress).map_or(0, |m| m.len());
        let start = std::time::Instant::now();
        while std::fs::metadata(&progress).map_or(0, |m| m.len()) <= before {
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "child made no progress in round {round}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(20 + round * 37));
        child.kill().unwrap(); // SIGKILL on unix
        child.wait().unwrap();
    }
    let s = open(d.path(), 0, 0);
    let snaps = s.list_snapshots().unwrap();
    assert!(snaps.len() > 6, "child made progress: {}", snaps.len());
    for m in &snaps {
        assert_eq!(restore(&s, m, "disk"), image(m.time), "snapshot {}", m.time);
    }
    std::thread::sleep(Duration::from_millis(20));
    s.gc(true).unwrap();
    let r = s.verify(|_| true).unwrap();
    assert!(r.corrupt.is_empty() && r.missing.is_empty(), "{r:?}");
    for m in &snaps {
        assert_eq!(restore(&s, m, "disk"), image(m.time));
    }
}

/// read_at that fails outside the allowed extents, like a PVE snapshot-access export.
fn reader<'a>(data: &'a [u8], allowed: &'a [(u64, u64)]) -> impl FnMut(u64, &mut [u8]) -> std::io::Result<()> + 'a {
    move |off, buf| {
        let end = off + buf.len() as u64;
        assert!(
            allowed.iter().any(|&(o, l)| off >= o && end <= o + l),
            "read of clean area {off}..{end}"
        );
        buf.copy_from_slice(&data[off as usize..end as usize]);
        Ok(())
    }
}

#[test]
fn dirty_extents_incremental_matches_full_read() {
    let d = tempfile::tempdir().unwrap();
    let s = open(d.path(), 0, 0);
    let cs = 65536usize;
    let v1 = image(1);
    let full = |data: &[u8]| s.store_image(data, cs).unwrap();
    let all = [(0u64, u64::MAX / 2)];
    let i1 = s
        .store_image_extents(None, cs, v1.len() as u64, &all, reader(&v1, &all))
        .unwrap();
    assert_eq!(i1, full(&v1));

    // image(2) differs in chunks 1 and 2; disk grows by 1000 bytes (tail must be read)
    let mut v2 = image(2);
    v2.extend(vec![5u8; 1000]);
    let dirty = [(65536u64, 131072u64)];
    let allowed = [(65536u64, 131072u64), (6 * 65536, 1000)];
    let i2 = s
        .store_image_extents(Some(&i1), cs, v2.len() as u64, &dirty, reader(&v2, &allowed))
        .unwrap();
    assert_eq!(i2, full(&v2));

    // 10 bytes change inside chunk 3: only those sectors are read, rest of chunk from base
    let mut v3 = v2.clone();
    v3[3 * 65536 + 100..3 * 65536 + 110].fill(0x77);
    let dirty = [(3 * 65536 + 96u64, 16u64)];
    let i3 = s
        .store_image_extents(Some(&i2), cs, v3.len() as u64, &dirty, reader(&v3, &dirty))
        .unwrap();
    assert_eq!(i3, full(&v3));

    // shrink: last chunk truncated from base without reads
    let v4 = v3[..5 * 65536 + 10].to_vec();
    let i4 = s
        .store_image_extents(Some(&i3), cs, v4.len() as u64, &[], reader(&v4, &[]))
        .unwrap();
    assert_eq!(i4, full(&v4));
}

/// Every byte is read once (no base: the whole disk; base: dirty extents plus
/// the grown tail), and `image_extents_bytes` predicts it (live progress total).
#[test]
fn dirty_extents_read_each_byte_once() {
    let d = tempfile::tempdir().unwrap();
    let s = open(d.path(), 0, 0);
    let cs = 65536usize;
    let v1 = image(1);
    let count = |prev: Option<&Index>, data: &[u8], dirty: &[(u64, u64)]| {
        let mut read = 0u64;
        let idx = s
            .store_image_extents(prev, cs, data.len() as u64, dirty, |off, buf| {
                read += buf.len() as u64;
                buf.copy_from_slice(&data[off as usize..off as usize + buf.len()]);
                Ok(())
            })
            .unwrap();
        assert_eq!(read, Store::image_extents_bytes(prev, cs, data.len() as u64, dirty));
        (idx, read)
    };
    let (i1, r) = count(None, &v1, &[(0, v1.len() as u64)]);
    assert_eq!(r, v1.len() as u64, "full read: once, not twice");
    assert_eq!(i1, s.store_image(&v1[..], cs).unwrap());
    let mut v2 = image(2);
    v2.extend(vec![5u8; 1000]);
    // dirty extent reaching into the grown tail: counted once
    let dirty = [(65536u64, 131072u64), (6 * 65536 - 100, 1100)];
    let (i2, r) = count(Some(&i1), &v2, &dirty);
    assert_eq!(r, 131072 + 1100);
    assert_eq!(i2, s.store_image(&v2[..], cs).unwrap());
}

#[test]
fn image_reader_random_access() {
    let d = tempfile::tempdir().unwrap();
    let s = open(d.path(), 0, 0);
    let mut img = image(3);
    img.extend(vec![9u8; 777]);
    let idx = s.store_image(&img[..], 65536).unwrap();
    let mut r = s.image_reader(&idx).unwrap();
    assert_eq!(r.size(), img.len() as u64);
    for (off, len) in [
        (0usize, 10usize),
        (65530, 20),
        (65536 * 6, 777),
        (1, 65536 * 3),
        (100, 0),
    ] {
        let mut b = vec![0u8; len];
        r.read_at(off as u64, &mut b).unwrap();
        assert_eq!(b, img[off..off + len]);
    }
    assert!(r.read_at(img.len() as u64 - 1, &mut [0, 0]).is_err());
}

#[test]
fn chunk_reader_streams_file() {
    use std::io::Read;
    let d = tempfile::tempdir().unwrap();
    let s = open(d.path(), 0, 0);
    let mut x = 88172645463325252u64;
    let data: Vec<u8> = (0..3_000_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    let (chunks, _) = s.store_file(&data[..]).unwrap();
    assert!(chunks.len() > 1);
    let mut out = Vec::new();
    s.chunk_reader(&chunks).read_to_end(&mut out).unwrap();
    assert_eq!(out, data);
}

#[test]
fn retention_prunes_unlocked_and_extends_locks() {
    use chunkstore::retention::Gfs;
    let d = tempfile::tempdir().unwrap();
    let s = open(d.path(), 0, 0);
    let day = 86400;
    let base = s.compliance_now().unwrap() - 10 * day; // last 10 days
    for i in 0..10 {
        s.commit_snapshot("vm-1", base + i * day, &[] as &[(&str, Index)])
            .unwrap();
    }
    let gfs = Gfs {
        recent: 0,
        daily: 3,
        weekly: 0,
        monthly: 0,
        yearly: 0,
    };
    assert_eq!(s.apply_retention("vm-1", &gfs).unwrap(), (3, 7, 0));
    let left: Vec<u64> = s.list_snapshots().unwrap().iter().map(|m| m.time).collect();
    assert_eq!(left, vec![base + 7 * day, base + 8 * day, base + 9 * day]);
    assert_eq!(
        s.load_manifest("vm-1", base + 9 * day).unwrap().lock_until,
        base + 9 * day + 14 * day
    );
    // locked snapshots survive a stricter policy
    let gfs1 = Gfs { daily: 1, ..gfs };
    let (_, deleted, locked) = s.apply_retention("vm-1", &gfs1).unwrap();
    assert_eq!((deleted, locked), (0, 2), "14-day locks from the first run hold");
}

/// Legal hold (Phase 15c): a held snapshot survives retention that would
/// delete it and GC keeps its chunks; without the hold the next run prunes it.
#[test]
fn retention_skips_held_snapshots_and_gc_keeps_their_chunks() {
    use chunkstore::retention::Gfs;
    use std::collections::BTreeSet;
    let d = tempfile::tempdir().unwrap();
    let s = open(d.path(), 0, 0);
    let day = 86400;
    let base = s.compliance_now().unwrap() - 10 * day;
    let (chunks, size) = s.store_file(&b"evidence"[..]).unwrap();
    let files = Index::Dynamic {
        entries: vec![FileEntry {
            path: "f".into(),
            mode: 0o644,
            size,
            mtime: 0,
            chunks,
        }],
    };
    let m = s.commit_snapshot("vm-1", base, &[("files", files)]).unwrap();
    for i in 1..4 {
        s.commit_snapshot("vm-1", base + i * day, &[] as &[(&str, Index)])
            .unwrap();
    }
    let gfs = Gfs {
        recent: 0,
        daily: 1,
        weekly: 0,
        monthly: 0,
        yearly: 0,
    };
    let held = BTreeSet::from([base]);
    assert_eq!(s.apply_retention_held("vm-1", &gfs, &held).unwrap(), (2, 2, 0));
    let left: Vec<u64> = s.list_snapshots().unwrap().iter().map(|m| m.time).collect();
    assert_eq!(left, vec![base, base + 3 * day]);
    assert_eq!(
        s.load_manifest("vm-1", base).unwrap().lock_until,
        m.lock_until,
        "no lock added"
    );
    s.gc(true).unwrap();
    assert_eq!(restore(&s, &m, "files"), b"evidence");
    // released: the next run prunes it
    assert_eq!(s.apply_retention("vm-1", &gfs).unwrap(), (1, 1, 0));
    assert!(s.load_manifest("vm-1", base).is_err());
}

#[test]
fn tree_index_roundtrip_and_old_variants_still_decode() {
    use chunkstore::{TreeEntry, TreeKind};
    let d = tempfile::tempdir().unwrap();
    let s = open(d.path(), 0, 0);
    let (chunks, size) = s.store_file(&b"hello agent"[..]).unwrap();
    let tree = Index::Tree {
        entries: vec![TreeEntry {
            path: b"etc/motd".to_vec(),
            kind: TreeKind::File,
            mode: 0o100644,
            uid: 0,
            gid: 0,
            size,
            mtime_ns: 1,
            ctime_ns: 2,
            inode: 3,
            rdev: 0,
            link_target: None,
            xattrs: vec![],
            chunks: chunks.clone(),
            inconsistent: false,
        }],
    };
    let fixed = s.store_image(&image(1)[..], 65536).unwrap();
    let m = s
        .commit_snapshot("host-a", 1, &[("root", tree.clone()), ("disk", fixed.clone())])
        .unwrap();
    assert_eq!(s.load_index(&m, "root").unwrap(), tree);
    assert_eq!(s.load_index(&m, "disk").unwrap(), fixed, "Fixed (variant 0) unaffected");
    assert_eq!(tree.chunk_ids(), chunks.iter().collect::<Vec<_>>());
    std::thread::sleep(std::time::Duration::from_millis(20));
    assert_eq!(s.gc(true).unwrap().deleted, 0, "tree chunks are marked");
}

/// New-data accounting (docs/storage-accounting.md): plain vs. sealed bytes of
/// new chunks, nothing new on a repeat, and the `nexus-stats` line.
#[test]
fn written_stats_count_plain_and_sealed_bytes() {
    let d = tempfile::tempdir().unwrap();
    let s = open(d.path(), 0, 0);
    let before = s.written();
    // zeros compress to almost nothing; pseudo-random data stays plain + overhead
    let st = s.store_file_stats(&vec![0u8; 1 << 20][..]).unwrap();
    assert_eq!((st.new_chunks, st.new_bytes), (st.chunks.len(), 1 << 20));
    assert!(st.new_stored > 0 && st.new_stored < st.new_bytes / 10, "{st:?}");
    let rnd = image(1);
    let img = s.store_image(&rnd[..], 65536).unwrap();
    let w = s.written().since(before);
    assert_eq!(w.plain, (1 << 20) + rnd.len() as u64);
    assert!(
        w.stored > st.new_stored + rnd.len() as u64,
        "random data does not compress: {w:?}"
    );
    // the same data again: nothing new
    let again = s.written();
    let st2 = s.store_file_stats(&vec![0u8; 1 << 20][..]).unwrap();
    assert_eq!((st2.new_chunks, st2.new_bytes, st2.new_stored), (0, 0, 0));
    assert_eq!(s.written().since(again), chunkstore::Written::default());

    let files = Index::Dynamic {
        entries: vec![FileEntry {
            path: "z".into(),
            mode: 0o644,
            size: st.size,
            mtime: 0,
            chunks: st.chunks,
        }],
    };
    let m = s
        .commit_snapshot("vm-7", 5, &[("disk0", img), ("files", files)])
        .unwrap();
    let line = s.stats_line(&m, 42, w).unwrap();
    let want = format!(
        "nexus-stats {{\"source\":\"vm-7\",\"time\":5,\"read\":42,\"logical\":{},\"new_chunks\":{},\"new_plain\":{},\"new_stored\":{}}}",
        (1 << 20) + rnd.len(),
        w.chunks,
        w.plain,
        w.stored
    );
    assert_eq!(line, want);
}

/// A full backup (fresh bitmap: every extent dirty, no base) reads each byte once; a grown
/// disk with dirty extents in the new tail reads the tail once too (both were read twice).
#[test]
fn extents_are_read_once() {
    let d = tempfile::tempdir().unwrap();
    let s = open(d.path(), 0, 0);
    let cs = 65536usize;
    let v1 = image(1);
    let count = |data: &[u8], prev: Option<&Index>, dirty: &[(u64, u64)]| {
        let mut n = 0u64;
        let idx = s
            .store_image_extents(prev, cs, data.len() as u64, dirty, |off, buf| {
                n += buf.len() as u64;
                buf.copy_from_slice(&data[off as usize..off as usize + buf.len()]);
                Ok(())
            })
            .unwrap();
        assert_eq!(idx, s.store_image(data, cs).unwrap());
        (idx, n)
    };
    let (i1, n) = count(&v1, None, &[(0, v1.len() as u64)]);
    assert_eq!(n, v1.len() as u64, "full backup");
    let mut v2 = v1.clone();
    v2.extend(vec![9u8; 3 * 65536]);
    let tail = (v1.len() as u64, 3 * 65536u64);
    let (_, n) = count(&v2, Some(&i1), &[tail]);
    assert_eq!(n, tail.1, "grown disk, tail dirty");
}
