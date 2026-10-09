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

const FORMAT: u32 = 1;

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
}

impl Cache {
    pub fn new(job: u64, base_time: Option<u64>) -> Cache {
        Cache {
            format: FORMAT,
            job,
            base_time,
            files: HashMap::new(),
        }
    }

    pub fn lookup(&self, path: &[u8], size: u64, mtime_ns: i64, ctime_ns: i64, inode: u64) -> Option<&Cached> {
        self.files
            .get(path)
            .filter(|c| c.size == size && c.mtime_ns == mtime_ns && c.ctime_ns == ctime_ns && c.inode == inode)
    }

    pub fn load(paths: &Paths) -> Option<Cache> {
        let data = fs::read(paths.cache_dir().join("committed.bin")).ok()?;
        postcard::from_bytes::<Cache>(&data).ok().filter(|c| c.format == FORMAT)
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
}
