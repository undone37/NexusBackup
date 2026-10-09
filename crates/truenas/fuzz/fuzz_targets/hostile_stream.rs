//! A hostile TrueNAS (threat model T12-like): whatever the forced command or
//! zfs returns, the parsers must not panic or allocate without bound, and
//! everything they accept must be a valid relative path. The same bytes are
//! fed to the `zfs diff` parser, the walk parser, the tar reader, and the tree
//! builder's `fill` (content stream for a fixed plan of one file + one dir).
#![no_main]

use chunkstore::{Keyring, Options, Store, TreeKind};
use libfuzzer_sys::fuzz_target;
use std::io::Read;
use std::sync::OnceLock;
use truenas::walk::WalkEntry;
use truenas::{diff, stream, tree, valid_rel_path, walk};

fn store() -> &'static Store {
    static S: OnceLock<(tempfile::TempDir, Store)> = OnceLock::new();
    let (_, s) = S.get_or_init(|| {
        let d = tempfile::tempdir_in("/dev/shm").unwrap();
        let s = Store::open(d.path(), Keyring::new("fuzz", &[(1, [1; 32])]), Options::default()).unwrap();
        (d, s)
    });
    s
}

fn w(path: &str, kind: TreeKind, inode: u64, size: u64) -> WalkEntry {
    WalkEntry {
        kind,
        mode: 0o644,
        uid: 0,
        gid: 0,
        size,
        mtime_ns: 0,
        ctime_ns: 0,
        inode,
        nlink: 1,
        path: path.as_bytes().to_vec(),
        link: None,
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(lines) = diff::parse(data, b"/mnt/tank/data") {
        for l in &lines {
            if let Some(p) = l.changed_path() {
                assert!(p.is_empty() || valid_rel_path(p));
            }
        }
    }

    if let Ok(entries) = walk::read_all(&mut &data[..]) {
        let mut seen = std::collections::HashSet::new();
        for e in &entries {
            assert!(valid_rel_path(&e.path) && seen.insert(e.path.clone()));
            assert_eq!(e.link.is_some(), e.kind == TreeKind::Symlink);
        }
        // the plan never panics on what the walk accepted
        let _ = tree::plan(entries, None, None, &|_| true);
    }

    let mut r = stream::Reader::new(data);
    let mut n = 0;
    while let Ok(Some(m)) = r.next_member() {
        assert!(valid_rel_path(&m.path));
        assert!(m.xattrs.len() <= stream::MAX_XATTRS);
        let mut sink = Vec::new();
        if r.data().take(1 << 20).read_to_end(&mut sink).is_err() {
            break;
        }
        n += 1;
        if n > 10_000 {
            break;
        }
    }
    let _ = r.finish(1 << 20);

    let mut p = tree::plan(
        vec![w("d", TreeKind::Dir, 2, 0), w("d/f", TreeKind::File, 3, 5)],
        None,
        None,
        &|_| true,
    );
    if tree::fill(store(), &mut p, &mut stream::Reader::new(data)).is_ok() {
        assert!(!p.entries[1].chunks.is_empty());
    }
});
