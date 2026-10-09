//! Metadata cache: path → (size, mtime, ctime, inode, chunk list) of the last
//! successful backup. A scan builds a new cache in memory; it is written only on
//! `Release { success: true }`, so a failed or aborted backup never poisons it.
//!
//! The appliance names its previous snapshot by `BaseRef.time`. The agent cannot map
//! that time to one of its own scans (the appliance's snapshot time is never sent to
//! the agent), so it keeps exactly one committed cache, records the base it was built
//! against, and uses it for any `Scan` with a base. This is safe even if the appliance
//! rolled back to an older base: unchanged entries carry their full chunk list, and
//! every chunk the appliance does not have can still be requested with `Want` (the
//! agent re-reads it from the file and verifies the hash).

use crate::config::{ensure_dir, write_atomic, Paths};
use agent_proto::Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

/// Format 2 appends `journals`; a format 1 cache (Linux agent 0.1) still loads.
const FORMAT: u32 = 2;
const FORMAT_V1: u32 = 1;

/// Change-journal position a scan is valid up to (Windows: NTFS/ReFS USN journal of a
/// volume). The next scan reads the journal from `next_usn` on; if the journal id
/// differs or the journal no longer reaches back to `next_usn`, that volume is read in
/// full. Unused (empty) on Linux.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct JournalMark {
    /// volume identity (Windows: volume GUID path `\\?\Volume{...}\`)
    pub volume: String,
    pub journal_id: u64,
    pub next_usn: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Cached {
    pub size: u64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    pub inode: u64,
    pub chunks: Vec<(Hash, u32)>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Cache {
    pub format: u32,
    /// job that produced this cache
    pub job: u64,
    /// `BaseRef.time` the producing scan was incremental to (None = full scan)
    pub base_time: Option<u64>,
    pub files: HashMap<Vec<u8>, Cached>,
    pub journals: Vec<JournalMark>,
}

#[derive(Deserialize)]
struct CacheV1 {
    format: u32,
    job: u64,
    base_time: Option<u64>,
    files: HashMap<Vec<u8>, Cached>,
}

impl Cache {
    pub fn new(job: u64, base_time: Option<u64>) -> Cache {
        Cache {
            format: FORMAT,
            job,
            base_time,
            files: HashMap::new(),
            journals: vec![],
        }
    }

    pub fn journal(&self, volume: &str) -> Option<&JournalMark> {
        self.journals.iter().find(|j| j.volume == volume)
    }

    pub fn lookup(&self, path: &[u8], size: u64, mtime_ns: i64, ctime_ns: i64, inode: u64) -> Option<&Cached> {
        self.files
            .get(path)
            .filter(|c| c.size == size && c.mtime_ns == mtime_ns && c.ctime_ns == ctime_ns && c.inode == inode)
    }

    pub fn load(paths: &Paths) -> Option<Cache> {
        let data = fs::read(paths.cache_dir().join("committed.bin")).ok()?;
        Self::decode(&data)
    }

    pub fn decode(data: &[u8]) -> Option<Cache> {
        if let Some(c) = postcard::from_bytes::<Cache>(data).ok().filter(|c| c.format == FORMAT) {
            return Some(c);
        }
        let v1 = postcard::from_bytes::<CacheV1>(data)
            .ok()
            .filter(|c| c.format == FORMAT_V1)?;
        Some(Cache {
            format: FORMAT,
            job: v1.job,
            base_time: v1.base_time,
            files: v1.files,
            journals: vec![],
        })
    }

    pub fn commit(&self, paths: &Paths) -> std::io::Result<()> {
        ensure_dir(&paths.cache_dir(), 0o700)?;
        let data = postcard::to_stdvec(self).map_err(std::io::Error::other)?;
        write_atomic(&paths.cache_dir().join("committed.bin"), &data, 0o600)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_load_lookup() {
        let t = tempfile::tempdir().unwrap();
        let p = Paths {
            config: t.path().join("c"),
            state: t.path().join("s"),
            run: t.path().join("r"),
        };
        assert!(Cache::load(&p).is_none());
        let mut c = Cache::new(7, Some(1000));
        c.files.insert(
            b"etc/hosts".to_vec(),
            Cached {
                size: 3,
                mtime_ns: 5,
                ctime_ns: 6,
                inode: 9,
                chunks: vec![([1; 32], 3)],
            },
        );
        c.commit(&p).unwrap();
        let l = Cache::load(&p).unwrap();
        assert_eq!(l, c);
        assert!(l.lookup(b"etc/hosts", 3, 5, 6, 9).is_some());
        assert!(l.lookup(b"etc/hosts", 3, 5, 7, 9).is_none(), "ctime change = re-read");
        assert!(l.lookup(b"etc/hosts", 3, 5, 6, 10).is_none(), "inode change = re-read");
        assert!(l.lookup(b"etc/hostx", 3, 5, 6, 9).is_none());
    }

    #[test]
    fn loads_format_1_and_keeps_journals() {
        #[derive(Serialize)]
        struct V1 {
            format: u32,
            job: u64,
            base_time: Option<u64>,
            files: HashMap<Vec<u8>, Cached>,
        }
        let mut files = HashMap::new();
        files.insert(
            b"a".to_vec(),
            Cached {
                size: 1,
                mtime_ns: 2,
                ctime_ns: 3,
                inode: 4,
                chunks: vec![([7; 32], 1)],
            },
        );
        let old = postcard::to_stdvec(&V1 {
            format: 1,
            job: 9,
            base_time: Some(5),
            files: files.clone(),
        })
        .unwrap();
        let c = Cache::decode(&old).unwrap();
        assert_eq!((c.job, c.base_time, c.files, c.journals.len()), (9, Some(5), files, 0));
        let mut n = Cache::new(1, None);
        n.journals.push(JournalMark {
            volume: "v".into(),
            journal_id: 1,
            next_usn: 77,
        });
        let back = Cache::decode(&postcard::to_stdvec(&n).unwrap()).unwrap();
        assert_eq!(back.journal("v").unwrap().next_usn, 77);
        assert!(back.journal("w").is_none());
        assert!(Cache::decode(b"garbage").is_none());
    }
}
