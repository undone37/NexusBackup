//! Builds the `Index::Tree` of one dataset snapshot from the metadata walk,
//! the previous snapshot's tree and the `zfs diff` change list.
//!
//! Files are matched to the previous tree by ZFS object number (inode), which
//! survives renames of the file and of any directory above it (`zfs diff` lists
//! a renamed directory as one line, not its content). A file reuses the
//! previous keyed chunk IDs only if its object is not named by `zfs diff`, it
//! was a regular file with the same size and mtime before, and all its chunks
//! are still in the store; everything else is read. Without a reference
//! snapshot (first run, reference deleted on TrueNAS) everything is read.
//! Directories carry ACLs/xattrs: they are re-read when their object changed.
//! Hard links: the first name (walk order) is the file, later names are
//! `Hardlink` entries pointing to it (as agent snapshots).

use crate::diff::Line;
use crate::stream::{self, Member};
use crate::walk::WalkEntry;
use anyhow::{bail, Context, Result};
use chunkstore::{ChunkId, Store, TreeEntry, TreeKind};
use std::collections::{HashMap, HashSet};
use std::io::Read;

pub struct Plan {
    /// walk order; files to read have no chunks yet
    pub entries: Vec<TreeEntry>,
    /// indices into `entries` whose content (files) or xattrs (directories) must be read
    pub need: Vec<usize>,
    pub reused_files: usize,
    pub reused_bytes: u64,
}

/// Objects (inodes) `zfs diff` reports as added/modified/renamed, resolved through the walk.
pub fn changed_inodes(walk: &[WalkEntry], diff: &[Line]) -> HashSet<u64> {
    let by_path: HashMap<&[u8], u64> = walk.iter().map(|e| (e.path.as_slice(), e.inode)).collect();
    diff.iter()
        .filter_map(Line::changed_path)
        .filter_map(|p| by_path.get(p).copied())
        .collect()
}

/// `changed`: None = no usable reference (read everything).
pub fn plan(
    walk: Vec<WalkEntry>,
    prev: Option<&[TreeEntry]>,
    changed: Option<&HashSet<u64>>,
    has_chunk: &dyn Fn(&ChunkId) -> bool,
) -> Plan {
    let prev_by_inode: HashMap<u64, &TreeEntry> = match (prev, changed) {
        (Some(p), Some(_)) => p
            .iter()
            .filter(|e| matches!(e.kind, TreeKind::File | TreeKind::Dir))
            .map(|e| (e.inode, e))
            .collect(),
        _ => HashMap::new(),
    };
    let unchanged = |inode: u64| changed.is_some_and(|c| !c.contains(&inode));
    let mut first_name: HashMap<u64, Vec<u8>> = HashMap::new();
    let mut p = Plan {
        entries: Vec::with_capacity(walk.len()),
        need: Vec::new(),
        reused_files: 0,
        reused_bytes: 0,
    };
    for w in walk {
        let mut e = TreeEntry {
            path: w.path,
            kind: w.kind,
            mode: w.mode,
            uid: w.uid,
            gid: w.gid,
            size: w.size,
            mtime_ns: w.mtime_ns,
            ctime_ns: w.ctime_ns,
            inode: w.inode,
            rdev: 0,
            link_target: w.link,
            xattrs: Vec::new(),
            chunks: Vec::new(),
            inconsistent: false,
        };
        let i = p.entries.len();
        match e.kind {
            TreeKind::File => {
                if let Some(first) = first_name.get(&e.inode) {
                    e.kind = TreeKind::Hardlink;
                    e.link_target = Some(first.clone());
                    e.size = 0;
                } else {
                    first_name.insert(e.inode, e.path.clone());
                    match prev_by_inode.get(&e.inode) {
                        Some(o)
                            if unchanged(e.inode)
                                && o.kind == TreeKind::File
                                && o.size == e.size
                                && o.mtime_ns == e.mtime_ns
                                && o.chunks.iter().all(has_chunk) =>
                        {
                            e.chunks = o.chunks.clone();
                            e.xattrs = o.xattrs.clone();
                            p.reused_files += 1;
                            p.reused_bytes += e.size;
                        }
                        _ => p.need.push(i),
                    }
                }
            }
            TreeKind::Dir => match prev_by_inode.get(&e.inode) {
                Some(o) if unchanged(e.inode) && o.kind == TreeKind::Dir => e.xattrs = o.xattrs.clone(),
                _ => p.need.push(i),
            },
            _ => {}
        }
        p.entries.push(e);
    }
    p
}

/// Consumes the tar stream of `read` for `plan.need` (same order): files are
/// FastCDC-chunked into the store, xattrs recorded. Every member must be the
/// next requested path with the walk's type and size. Returns (bytes stored
/// as content, new chunks, new bytes).
pub fn fill<R: Read>(store: &Store, plan: &mut Plan, tar: &mut stream::Reader<R>) -> Result<(u64, usize, u64)> {
    let (mut bytes, mut new_chunks, mut new_bytes) = (0u64, 0usize, 0u64);
    for &i in &plan.need {
        let e = &mut plan.entries[i];
        let m = next_requested(tar, &e.path, &e.kind, e.size)?;
        if m.kind == stream::Kind::File {
            let st = store.store_file_stats(tar.data())?;
            if st.size != e.size {
                bail!("{:?}: short content", String::from_utf8_lossy(&e.path));
            }
            e.chunks = st.chunks;
            bytes += st.size;
            new_chunks += st.new_chunks;
            new_bytes += st.new_bytes;
        }
        e.xattrs = m.xattrs;
    }
    end_of_requested(tar)?;
    Ok((bytes, new_chunks, new_bytes))
}

/// The next member of a `read` stream, which must be the requested `path` with
/// the walk's type (regular file or directory) and, for files, size. The
/// caller consumes a file's content via `tar.data()`.
pub fn next_requested<R: Read>(tar: &mut stream::Reader<R>, path: &[u8], kind: &TreeKind, size: u64) -> Result<Member> {
    let m: Member = tar
        .next_member()?
        .with_context(|| format!("tar stream ended before {:?}", String::from_utf8_lossy(path)))?;
    if m.path != path {
        bail!(
            "tar member {:?} where {:?} was requested",
            String::from_utf8_lossy(&m.path),
            String::from_utf8_lossy(path)
        );
    }
    match (&m.kind, kind) {
        (stream::Kind::File, TreeKind::File) if m.size != size => bail!(
            "{:?}: {} bytes in the stream, {size} in the walk",
            String::from_utf8_lossy(path),
            m.size
        ),
        (stream::Kind::File, TreeKind::File) | (stream::Kind::Dir, TreeKind::Dir) => Ok(m),
        _ => bail!("{:?}: type differs from the walk", String::from_utf8_lossy(path)),
    }
}

/// After the last requested member: nothing else may follow.
pub fn end_of_requested<R: Read>(tar: &mut stream::Reader<R>) -> Result<()> {
    if tar.next_member()?.is_some() {
        bail!("tar stream has more members than requested");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff;
    use crate::stream::tests::{end, member};
    use chunkstore::{Keyring, Options};

    fn w(path: &str, kind: TreeKind, inode: u64, size: u64, mtime: i64) -> WalkEntry {
        WalkEntry {
            kind,
            mode: 0o644,
            uid: 0,
            gid: 0,
            size,
            mtime_ns: mtime,
            ctime_ns: mtime,
            inode,
            nlink: 1,
            path: path.as_bytes().to_vec(),
            link: None,
        }
    }

    fn store(dir: &std::path::Path) -> Store {
        Store::open(dir, Keyring::new("t", &[(1, [7; 32])]), Options::default()).unwrap()
    }

    #[test]
    fn reuses_by_inode_across_renames_and_reads_changes() {
        let td = tempfile::tempdir().unwrap();
        let s = store(td.path());
        // previous snapshot: dir d (2), d/a (3), d/b (4), x (5) with xattrs, hl (6)
        let walk1 = vec![
            w("d", TreeKind::Dir, 2, 0, 1),
            w("d/a", TreeKind::File, 3, 5, 1),
            w("d/b", TreeKind::File, 4, 3, 1),
            w("x", TreeKind::File, 5, 1, 1),
            w("hl", TreeKind::File, 6, 2, 1),
        ];
        let mut p1 = plan(walk1, None, None, &|_| true);
        assert_eq!(p1.need, vec![0, 1, 2, 3, 4]);
        let mut t = Vec::new();
        member(
            &mut t,
            b"d",
            b'5',
            b"",
            &[(b"SCHILY.xattr.system.posix_acl_default", b"acl")],
        );
        member(&mut t, b"d/a", b'0', b"aaaaa", &[]);
        member(&mut t, b"d/b", b'0', b"bbb", &[]);
        member(&mut t, b"x", b'0', b"x", &[(b"SCHILY.xattr.user.c", b"v")]);
        member(&mut t, b"hl", b'0', b"hh", &[]);
        end(&mut t);
        let (bytes, new, _) = fill(&s, &mut p1, &mut stream::Reader::new(&t[..])).unwrap();
        assert_eq!((bytes, new), (11, 4));
        let prev = p1.entries;

        // round 2: d renamed to e (zfs diff: one R line), d/b modified in place,
        // x renamed by hard link only (shows up as M of another name), new file n,
        // hl gets a second name
        let out = b"R\t/\t/mnt/t/d\t/mnt/t/e\nM\tF\t/mnt/t/e/b\n+\tF\t/mnt/t/n\nM\tF\t/mnt/t/hl\t(+1)\n";
        let lines = diff::parse(out, b"/mnt/t").unwrap();
        let walk2 = vec![
            w("e", TreeKind::Dir, 2, 0, 1),
            w("e/a", TreeKind::File, 3, 5, 1),
            w("e/b", TreeKind::File, 4, 4, 2),
            w("hl", TreeKind::File, 6, 2, 1),
            w("hl2", TreeKind::File, 6, 2, 1),
            w("n", TreeKind::File, 7, 1, 2),
            w("y", TreeKind::File, 5, 1, 1),
        ];
        let ch = changed_inodes(&walk2, &lines);
        assert_eq!(ch, HashSet::from([2, 4, 7, 6]));
        let mut p2 = plan(walk2, Some(&prev), Some(&ch), &|_| true);
        // e (renamed dir: object changed -> xattrs re-read), e/b, hl (link change), n
        assert_eq!(p2.need, vec![0, 2, 3, 5]);
        assert_eq!(p2.reused_files, 2); // e/a and y (renamed file not in the diff)
        assert_eq!(p2.entries[1].chunks, prev[1].chunks);
        assert_eq!(p2.entries[6].xattrs, prev[3].xattrs);
        assert_eq!(p2.entries[4].kind, TreeKind::Hardlink);
        assert_eq!(p2.entries[4].link_target.as_deref(), Some(&b"hl"[..]));
        let mut t = Vec::new();
        member(&mut t, b"e", b'5', b"", &[]);
        member(&mut t, b"e/b", b'0', b"bbbb", &[]);
        member(&mut t, b"hl", b'0', b"hh", &[]);
        member(&mut t, b"n", b'0', b"n", &[]);
        end(&mut t);
        let (bytes, new, _) = fill(&s, &mut p2, &mut stream::Reader::new(&t[..])).unwrap();
        assert_eq!((bytes, new), (7, 2)); // "hh" is deduplicated
        assert!(p2.entries[0].xattrs.is_empty()); // ACL removed with the rename

        // metadata disagreeing with the previous tree forces a read even if zfs diff is silent
        let walk3 = vec![w("e", TreeKind::Dir, 2, 0, 1), w("e/a", TreeKind::File, 3, 5, 99)];
        let p3 = plan(walk3, Some(&p2.entries), Some(&HashSet::new()), &|_| true);
        assert_eq!(p3.need, vec![1]);
        // a chunk missing from the store forces a read
        let walk4 = vec![w("e/a", TreeKind::File, 3, 5, 1)];
        let p4 = plan(walk4, Some(&prev), Some(&HashSet::new()), &|_| false);
        assert_eq!(p4.need, vec![0]);
        // no reference: everything is read even with a previous tree
        let p5 = plan(vec![w("e/a", TreeKind::File, 3, 5, 1)], Some(&prev), None, &|_| true);
        assert_eq!(p5.need, vec![0]);
    }

    #[test]
    fn fill_refuses_mismatching_streams() {
        let td = tempfile::tempdir().unwrap();
        let s = store(td.path());
        let walk = || vec![w("a", TreeKind::File, 3, 2, 1), w("d", TreeKind::Dir, 4, 0, 1)];
        let cases: Vec<Vec<u8>> = vec![
            {
                let mut t = Vec::new();
                member(&mut t, b"b", b'0', b"xx", &[]); // other path
                end(&mut t);
                t
            },
            {
                let mut t = Vec::new();
                member(&mut t, b"a", b'0', b"xxx", &[]); // other size
                end(&mut t);
                t
            },
            {
                let mut t = Vec::new();
                member(&mut t, b"a", b'5', b"", &[]); // dir instead of file
                end(&mut t);
                t
            },
            {
                let mut t = Vec::new();
                member(&mut t, b"a", b'0', b"xx", &[]); // missing d
                end(&mut t);
                t
            },
            {
                let mut t = Vec::new();
                member(&mut t, b"a", b'0', b"xx", &[]);
                member(&mut t, b"d", b'5', b"", &[]);
                member(&mut t, b"z", b'0', b"", &[]); // extra member
                end(&mut t);
                t
            },
        ];
        for (i, t) in cases.iter().enumerate() {
            let mut p = plan(walk(), None, None, &|_| true);
            assert!(fill(&s, &mut p, &mut stream::Reader::new(&t[..])).is_err(), "case {i}");
        }
    }
}
