//! Shared helpers for the Target engine tests (local dir, lock double, S3).
#![allow(dead_code)]

use chunkstore::{Keyring, Options as StoreOptions, Store};
use offsite::remote::{LocalDir, Remote};
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const DAY: u64 = 86400;

pub fn keys() -> Keyring {
    Keyring::new("tenant1", &[(1, [5; 32])])
}

pub fn store(dir: &Path) -> Store {
    store_locked(dir, 0)
}

/// Store whose snapshots are locked `min_lock_secs` after their commit.
pub fn store_locked(dir: &Path, min_lock_secs: u64) -> Store {
    Store::open(
        dir,
        keys(),
        StoreOptions {
            min_lock_secs,
            gc_grace_secs: 0,
            ..Default::default()
        },
    )
    .unwrap()
}

/// 48 pseudo-random 64 KiB chunks; snapshot `v` changes chunk `v % 48`.
pub fn image(v: u64) -> Vec<u8> {
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

pub fn backup(s: &Store, t: u64, v: u64) {
    let idx = s.store_image(&image(v)[..], 65536).unwrap();
    s.commit_snapshot("vm-1", t, &[("disk", idx)]).unwrap();
}

pub fn restored(s: &Store, t: u64) -> Vec<u8> {
    let m = s.load_manifest("vm-1", t).unwrap();
    let mut out = Vec::new();
    s.write_chunks(s.load_index(&m, "disk").unwrap().chunk_ids(), &mut out)
        .unwrap();
    out
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// A local directory that enforces retention locks the strict way: deleting
/// or overwriting a locked file fails, and every such attempt is counted (the
/// engine must never try). Locks only ever grow.
pub struct Locking {
    pub dir: LocalDir,
    pub locks: Mutex<HashMap<String, u64>>,
    pub refused: AtomicUsize,
}

impl Locking {
    pub fn new(dir: &Path) -> Self {
        Locking {
            dir: LocalDir(dir.to_owned()),
            locks: Mutex::new(HashMap::new()),
            refused: AtomicUsize::new(0),
        }
    }
    pub fn lock(&self, path: &str) -> Option<u64> {
        self.locks.lock().unwrap().get(path).copied()
    }
    pub fn refused(&self) -> usize {
        self.refused.load(Ordering::SeqCst)
    }
}

impl Remote for Locking {
    fn put(&self, path: &str, data: &[u8]) -> io::Result<()> {
        self.dir.put(path, data)
    }
    fn get(&self, path: &str, offset: u64, len: Option<u64>) -> io::Result<Vec<u8>> {
        self.dir.get(path, offset, len)
    }
    fn list(&self, dir: &str) -> io::Result<Vec<(String, u64, bool)>> {
        self.dir.list(dir)
    }
    fn delete(&self, path: &str) -> io::Result<()> {
        if self.lock(path).is_some_and(|l| l > now()) {
            self.refused.fetch_add(1, Ordering::SeqCst);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{path} is locked"),
            ));
        }
        self.locks.lock().unwrap().remove(path);
        self.dir.delete(path)
    }
    fn supports_locks(&self) -> bool {
        true
    }
    fn put_locked(&self, path: &str, data: &[u8], until: u64) -> io::Result<()> {
        self.dir.put(path, data)?;
        if until > now() {
            self.locks.lock().unwrap().insert(path.to_owned(), until);
        }
        Ok(())
    }
    fn extend_lock(&self, path: &str, until: u64) -> io::Result<()> {
        self.dir.get(path, 0, Some(0))?; // NotFound for missing objects
        if until > now() {
            let mut l = self.locks.lock().unwrap();
            let e = l.entry(path.to_owned()).or_default();
            *e = (*e).max(until);
        }
        Ok(())
    }
    fn lock_of(&self, path: &str) -> io::Result<Option<u64>> {
        self.dir.get(path, 0, Some(0))?;
        Ok(self.lock(path))
    }
}
