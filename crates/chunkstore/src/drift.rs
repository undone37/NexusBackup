//! Change-tracking drift check of a scheduled full read (Phase 29).
//!
//! Incremental backups trust a change tracker: the dirty bitmap of a VM disk,
//! the metadata cache of an agent or NAS share (a file with the same size,
//! mtime, ctime and inode keeps its chunks), the USN journal, `zfs diff`. A
//! tracker that misses a change keeps stale data in every later snapshot
//! without any error. A full read ignores the tracker, reads everything and
//! compares the result with the previous snapshot: content that differs while
//! the tracker did not report it is "unreported" (the incremental would have
//! kept the old data).
//!
//! The connectors print one line per snapshot read in full ([`Drift::line`]);
//! the scheduler records it and alerts on `unreported > 0`. Pure functions:
//! the connectors decide what the tracker reported.

use crate::store::{Index, TreeEntry, TreeKind};
use serde::Serialize;
use std::collections::HashMap;

/// paths / offsets listed in a result
pub const MAX_EXAMPLES: usize = 10;

/// Result of one full read compared against the previous snapshot (see the module doc).
#[derive(Serialize, Debug, Clone, PartialEq, Default)]
pub struct Drift {
    /// "dirty-bitmap", "metadata-cache", "usn", "zfs-diff" or "none"
    pub tracker: String,
    /// time of the previous snapshot compared against (None: nothing to compare)
    pub baseline: Option<u64>,
    /// files or chunks present in both snapshots
    pub compared: u64,
    /// of those, with different content
    pub changed: u64,
    /// of those, not reported by the tracker
    pub unreported: u64,
    /// plain bytes of the unreported changes
    pub unreported_bytes: u64,
    /// paths, or `<device>@<offset>` for disk chunks
    pub examples: Vec<String>,
}

impl Drift {
    /// Empty result for `tracker`; the connector fills the counters while reading.
    pub fn new(tracker: &str, baseline: Option<u64>) -> Drift {
        Drift {
            tracker: tracker.into(),
            baseline,
            ..Default::default()
        }
    }

    /// No usable tracker or no previous snapshot: nothing compared.
    pub fn none() -> Drift {
        Drift::new("none", None)
    }

    /// `full-read <source>/<time> {json}` (job log, parsed by the scheduler).
    pub fn line(&self, source: &str, time: u64) -> String {
        format!(
            "full-read {source}/{time} {}",
            serde_json::to_string(self).unwrap_or_default()
        )
    }

    fn unreported(&mut self, example: impl FnOnce() -> String, bytes: u64) {
        self.unreported += 1;
        self.unreported_bytes += bytes;
        if self.examples.len() < MAX_EXAMPLES {
            self.examples.push(example());
        }
    }
}

/// Fixed (disk) indexes: chunk by chunk over the range both snapshots cover
/// with the same chunk bounds. `reported` = the tracker's `(offset, length)`
/// extents; a changed chunk no extent overlaps is unreported. Indexes of
/// another kind or chunk size are not compared.
pub fn fixed(d: &mut Drift, prev: &Index, cur: &Index, reported: &[(u64, u64)], device: &str) {
    let (
        Index::Fixed {
            chunk_size: pc,
            size: ps,
            chunks: pchunks,
        },
        Index::Fixed {
            chunk_size: cc,
            size: cs,
            chunks: cchunks,
        },
    ) = (prev, cur)
    else {
        return;
    };
    if pc != cc || *cc == 0 {
        return;
    }
    let mut ext: Vec<(u64, u64)> = reported
        .iter()
        .filter(|(_, l)| *l > 0)
        .map(|&(o, l)| (o, o.saturating_add(l)))
        .collect();
    ext.sort_unstable();
    // merged: ends sorted too, so the first extent ending after `start` decides
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ext.len());
    for (a, b) in ext {
        match merged.last_mut() {
            Some(last) if a <= last.1 => last.1 = last.1.max(b),
            _ => merged.push((a, b)),
        }
    }
    let c = u64::from(*cc);
    for (n, (p, q)) in pchunks.iter().zip(cchunks).enumerate() {
        let start = n as u64 * c;
        let end = (start + c).min(*cs);
        if end != (start + c).min(*ps) {
            break; // resized: the last common chunk has other bounds
        }
        d.compared += 1;
        if p == q {
            continue;
        }
        d.changed += 1;
        let i = merged.partition_point(|&(_, b)| b <= start);
        if merged.get(i).is_none_or(|&(a, _)| a >= end) {
            d.unreported(|| format!("{device}@{start}"), end - start);
        }
    }
}

/// The metadata cache key of agents and NAS shares: size, mtime, ctime, inode.
pub fn metadata_differs(a: &TreeEntry, b: &TreeEntry) -> bool {
    (a.size, a.mtime_ns, a.ctime_ns, a.inode) != (b.size, b.mtime_ns, b.ctime_ns, b.inode)
}

/// Tree indexes: regular files present at the same path in both snapshots.
/// Changed content (chunk list) is unreported unless `reported(prev, cur)`.
/// Files read while they changed (`inconsistent`, either side) are compared
/// but never counted as unreported: their content is not a reliable witness.
pub fn tree(d: &mut Drift, prev: &[TreeEntry], cur: &[TreeEntry], reported: impl Fn(&TreeEntry, &TreeEntry) -> bool) {
    let before: HashMap<&[u8], &TreeEntry> = prev
        .iter()
        .filter(|e| e.kind == TreeKind::File)
        .map(|e| (e.path.as_slice(), e))
        .collect();
    for e in cur.iter().filter(|e| e.kind == TreeKind::File) {
        let Some(p) = before.get(e.path.as_slice()) else {
            continue;
        };
        d.compared += 1;
        if p.chunks == e.chunks {
            continue;
        }
        d.changed += 1;
        if !p.inconsistent && !e.inconsistent && !reported(p, e) {
            d.unreported(|| String::from_utf8_lossy(&e.path).into_owned(), e.size);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_index(size: u64, ids: &[u8]) -> Index {
        Index::Fixed {
            chunk_size: 4,
            size,
            chunks: ids.iter().map(|&b| [b; 32]).collect(),
        }
    }

    #[test]
    fn fixed_chunks_against_reported_extents() {
        // chunks 0..4 of 4 bytes; 1 and 3 changed, 1 reported (one byte overlaps)
        let prev = fixed_index(16, &[1, 2, 3, 4]);
        let cur = fixed_index(16, &[1, 9, 3, 9]);
        let mut d = Drift::new("dirty-bitmap", Some(7));
        fixed(&mut d, &prev, &cur, &[(7, 1), (20, 4)], "drive-scsi0");
        assert_eq!((d.compared, d.changed, d.unreported, d.unreported_bytes), (4, 2, 1, 4));
        assert_eq!(d.examples, ["drive-scsi0@12"]);
        // an extent ending exactly at a chunk start does not cover it
        let mut d = Drift::default();
        fixed(&mut d, &prev, &cur, &[(0, 4), (8, 4)], "x");
        assert_eq!(d.unreported, 2);
        // overlapping, unsorted extents are merged
        let mut d = Drift::default();
        fixed(&mut d, &prev, &cur, &[(13, 2), (2, 3), (4, 1)], "x");
        assert_eq!(d.unreported, 0);
    }

    #[test]
    fn fixed_compares_only_the_common_range() {
        // grown from 10 to 16 bytes: chunks 0 and 1 compared, 2 (bounds 8..10 vs 8..12) not
        let prev = fixed_index(10, &[1, 2, 3]);
        let cur = fixed_index(16, &[1, 5, 6, 7]);
        let mut d = Drift::default();
        fixed(&mut d, &prev, &cur, &[], "d");
        assert_eq!((d.compared, d.changed, d.unreported), (2, 1, 1));
        // other chunk size: nothing
        let other = Index::Fixed {
            chunk_size: 8,
            size: 16,
            chunks: vec![[0; 32]; 2],
        };
        let mut d = Drift::default();
        fixed(&mut d, &other, &cur, &[], "d");
        assert_eq!(d, Drift::default());
    }

    fn file(path: &str, size: u64, mtime: i64, chunk: u8) -> TreeEntry {
        TreeEntry {
            path: path.as_bytes().to_vec(),
            kind: TreeKind::File,
            mode: 0o644,
            uid: 0,
            gid: 0,
            size,
            mtime_ns: mtime,
            ctime_ns: mtime,
            inode: size,
            rdev: 0,
            link_target: None,
            xattrs: vec![],
            chunks: vec![[chunk; 32]],
            inconsistent: false,
        }
    }

    #[test]
    fn tree_files_by_metadata() {
        let prev = vec![
            file("same", 1, 1, 1),
            file("touched", 2, 1, 2),
            file("silent", 3, 1, 3),
            file("gone", 4, 1, 4),
        ];
        let mut odd = file("odd", 5, 1, 5);
        odd.inconsistent = true;
        let mut prev = prev;
        prev.push(odd.clone());
        odd.chunks = vec![[6; 32]];
        let cur = vec![
            file("same", 1, 1, 1),
            file("touched", 2, 2, 9),
            file("silent", 3, 1, 9),
            file("new", 6, 1, 6),
            odd,
        ];
        let mut d = Drift::new("metadata-cache", Some(5));
        tree(&mut d, &prev, &cur, metadata_differs);
        assert_eq!((d.compared, d.changed, d.unreported, d.unreported_bytes), (4, 3, 1, 3));
        assert_eq!(d.examples, ["silent"]);
        assert_eq!(
            d.line("host-a", 9),
            r#"full-read host-a/9 {"tracker":"metadata-cache","baseline":5,"compared":4,"changed":3,"unreported":1,"unreported_bytes":3,"examples":["silent"]}"#
        );
    }

    #[test]
    fn examples_are_capped() {
        let prev: Vec<TreeEntry> = (0..20).map(|i| file(&format!("f{i}"), 1, 1, 1)).collect();
        let cur: Vec<TreeEntry> = (0..20).map(|i| file(&format!("f{i}"), 1, 1, 2)).collect();
        let mut d = Drift::default();
        tree(&mut d, &prev, &cur, |_, _| false);
        assert_eq!((d.unreported, d.examples.len()), (20, MAX_EXAMPLES));
        assert_eq!(
            Drift::none().line("x", 1),
            r#"full-read x/1 {"tracker":"none","baseline":null,"compared":0,"changed":0,"unreported":0,"unreported_bytes":0,"examples":[]}"#
        );
    }
}
