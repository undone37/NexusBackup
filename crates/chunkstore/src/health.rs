//! Health check with repair (Phase 21d, docs/veeam-comparison.md row 3): chunks
//! that failed verify (corrupt or missing) go on the tenant's bad-chunk list
//! (`<root>/badchunks`, one hex id per line) and a corrupt file is moved aside
//! to `<hex>.bad`. With the chunk file gone, every writer stores the chunk again
//! when a source supplies the same plaintext (the id is the keyed hash of it),
//! and the dedup shortcuts that reuse chunk ids without the plaintext (PVE dirty
//! bitmap base, agent / plugin base snapshot) skip a damaged base
//! ([`Store::is_damaged`]). A chunk is healthy again as soon as a valid file is
//! back in place: re-stored by a backup or fetched by [`Store::repair_from`].

use crate::crypto::{hex, parse_hex, ChunkId};
use crate::store::{write_atomic, Manifest, Store};
use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::io;
use std::path::PathBuf;

const BAD_LIST: &str = "badchunks";

/// One snapshot that references bad chunks.
#[derive(Debug, Clone, PartialEq)]
pub struct Damaged {
    pub source: String,
    pub time: u64,
    /// distinct bad chunks it references
    pub chunks: usize,
}

#[derive(Debug, Default, PartialEq)]
pub struct Repair {
    pub repaired: usize,
    /// no copy at the repair source, or the copy failed verification
    pub unavailable: usize,
}

impl Store {
    fn bad_list_path(&self) -> PathBuf {
        self.root().join(BAD_LIST)
    }

    fn quarantine_path(&self, id: &ChunkId) -> PathBuf {
        self.chunk_path(id).with_extension("bad")
    }

    fn read_bad_list(&self) -> io::Result<BTreeSet<ChunkId>> {
        match fs::read_to_string(self.bad_list_path()) {
            Ok(s) => Ok(s.lines().filter_map(|l| parse_hex(l.trim())).collect()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BTreeSet::new()),
            Err(e) => Err(e),
        }
    }

    fn write_bad_list(&self, ids: &BTreeSet<ChunkId>) -> io::Result<()> {
        let text: String = ids.iter().map(|id| hex(id) + "\n").collect();
        write_atomic(&self.bad_list_path(), text.as_bytes())
    }

    /// Puts chunks on the bad list; an existing (corrupt) file is moved aside so
    /// nothing dedups against it any more. Returns how many were new on the list.
    // ponytail: a backup that touched the chunk just before the move references
    // a missing chunk; the next verify finds it.
    pub fn mark_bad<'a>(&self, ids: impl IntoIterator<Item = &'a ChunkId>) -> io::Result<usize> {
        let _m = self.meta_lock();
        let mut list = self.read_bad_list()?;
        let before = list.len();
        for id in ids {
            {
                let _g = self.chunk_lock();
                match fs::rename(self.chunk_path(id), self.quarantine_path(id)) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                }
            }
            list.insert(*id);
        }
        if list.len() != before {
            self.write_bad_list(&list)?;
        }
        Ok(list.len() - before)
    }

    /// Listed chunks without a valid file in place.
    pub fn bad_chunks(&self) -> io::Result<BTreeSet<ChunkId>> {
        let mut list = self.read_bad_list()?;
        list.retain(|id| !self.chunk_path(id).exists());
        Ok(list)
    }

    /// True if the snapshot references a bad chunk: it must not serve as the
    /// base of an incremental backup that reuses chunk ids.
    pub fn is_damaged(&self, m: &Manifest) -> io::Result<bool> {
        let bad = self.bad_chunks()?;
        if bad.is_empty() {
            return Ok(false);
        }
        for name in &m.indexes {
            if self.load_index(m, name)?.chunk_ids().iter().any(|id| bad.contains(*id)) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Committed snapshots that reference bad chunks.
    pub fn damaged_snapshots(&self) -> io::Result<Vec<Damaged>> {
        let bad = self.bad_chunks()?;
        let mut out = Vec::new();
        if bad.is_empty() {
            return Ok(out);
        }
        for m in self.list_snapshots()? {
            let mut hit: HashSet<ChunkId> = HashSet::new();
            for name in &m.indexes {
                hit.extend(self.load_index(&m, name)?.chunk_ids().into_iter().filter(|id| bad.contains(*id)).copied());
            }
            if !hit.is_empty() {
                out.push(Damaged {
                    source: m.source,
                    time: m.time,
                    chunks: hit.len(),
                });
            }
        }
        Ok(out)
    }

    /// Drops list entries that are healthy again (a valid file is back) or no
    /// longer referenced by any snapshot, with their quarantined copies. A file
    /// back in place that does not read is moved aside again. Returns the
    /// number of entries dropped.
    pub fn prune_bad(&self) -> io::Result<usize> {
        let _m = self.meta_lock();
        let list = self.read_bad_list()?;
        if list.is_empty() {
            return Ok(0);
        }
        let referenced = self.mark()?;
        let mut keep = BTreeSet::new();
        for id in &list {
            let healed = !referenced.contains(id)
                || (self.chunk_path(id).exists() && {
                    let ok = self.read_chunk(id).is_ok();
                    if !ok {
                        let _g = self.chunk_lock();
                        fs::rename(self.chunk_path(id), self.quarantine_path(id))?;
                    }
                    ok
                });
            if healed {
                match fs::remove_file(self.quarantine_path(id)) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                }
            } else {
                keep.insert(*id);
            }
        }
        if keep.len() != list.len() {
            self.write_bad_list(&keep)?;
        }
        Ok(list.len() - keep.len())
    }

    /// Fetches every bad chunk as sealed bytes from a repair source (offsite
    /// pack, replication primary) and puts it back after full verification
    /// (AEAD + keyed hash, [`Store::insert_chunk_raw`]). `fetch` returns `None`
    /// when the source has no copy. Then prunes the list.
    pub fn repair_from(&self, mut fetch: impl FnMut(&ChunkId) -> io::Result<Option<Vec<u8>>>) -> io::Result<Repair> {
        let mut r = Repair::default();
        for id in self.bad_chunks()? {
            match fetch(&id)? {
                Some(sealed) if self.insert_chunk_raw(&id, &sealed).is_ok() => r.repaired += 1,
                _ => r.unavailable += 1,
            }
        }
        self.prune_bad()?;
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Keyring, Options};

    fn open(dir: &std::path::Path) -> Store {
        let o = Options {
            min_lock_secs: 0,
            gc_grace_secs: 0,
            ..Default::default()
        };
        Store::open(dir, Keyring::new("t", &[(1, [3; 32])]), o).unwrap()
    }

    fn data(n: u8) -> Vec<u8> {
        (0..65536u32).map(|i| (i as u8) ^ n).collect()
    }

    fn snap(s: &Store, time: u64, chunks: &[u8]) -> Manifest {
        let mut img = Vec::new();
        for c in chunks {
            img.extend(data(*c));
        }
        let idx = s.store_image(&img[..], 65536).unwrap();
        s.commit_snapshot("vm-1", time, &[("disk", idx)]).unwrap()
    }

    fn corrupt(s: &Store, id: &ChunkId) {
        let p = s.chunk_path(id);
        let mut b = fs::read(&p).unwrap();
        b[40] ^= 0xff;
        fs::write(p, b).unwrap();
    }

    #[test]
    fn bad_chunk_is_restored_by_the_next_writer_and_heals_old_snapshots() {
        let d = tempfile::tempdir().unwrap();
        let s = open(d.path());
        let m1 = snap(&s, 1, &[1, 2]);
        let id = s.keys().chunk_id(&data(2));
        corrupt(&s, &id);
        let v = s.verify(|_| true).unwrap();
        assert_eq!(v.corrupt, vec![id]);
        assert_eq!(s.mark_bad(&v.corrupt).unwrap(), 1);
        assert_eq!(s.mark_bad(&v.corrupt).unwrap(), 0, "listed once");
        assert!(!s.has_chunk(&id) && s.quarantine_path(&id).exists());
        assert!(s.is_damaged(&m1).unwrap());
        assert_eq!(
            s.damaged_snapshots().unwrap(),
            vec![Damaged {
                source: "vm-1".into(),
                time: 1,
                chunks: 1
            }]
        );
        // a snapshot without the bad chunk is a fine base
        let m2 = snap(&s, 2, &[1, 3]);
        assert!(!s.is_damaged(&m2).unwrap());
        // a writer with the same plaintext stores it again: no dedup against the bad copy
        let (_, new) = s.insert_chunk(&data(2)).unwrap();
        assert!(new);
        assert!(!s.is_damaged(&m1).unwrap());
        assert_eq!(s.prune_bad().unwrap(), 1);
        assert!(s.read_bad_list().unwrap().is_empty() && !s.quarantine_path(&id).exists());
        assert!(s.verify(|_| true).unwrap().corrupt.is_empty());
    }

    #[test]
    fn repair_from_another_copy_verifies_and_skips_unavailable() {
        let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (s, replica) = (open(d1.path()), open(d2.path()));
        snap(&s, 1, &[1, 2, 4]);
        snap(&replica, 1, &[1, 2, 4]);
        let (a, b, c) = (
            s.keys().chunk_id(&data(1)),
            s.keys().chunk_id(&data(2)),
            s.keys().chunk_id(&data(4)),
        );
        corrupt(&s, &a);
        fs::remove_file(s.chunk_path(&b)).unwrap();
        corrupt(&s, &c);
        let v = s.verify(|_| true).unwrap();
        s.mark_bad(v.corrupt.iter().chain(&v.missing)).unwrap();
        assert_eq!(s.bad_chunks().unwrap().len(), 3);
        let r = s
            .repair_from(|id| {
                if *id == c {
                    // a tampered copy is refused
                    let mut x = replica.read_chunk_raw(id)?;
                    x[40] ^= 1;
                    return Ok(Some(x));
                }
                Ok(Some(replica.read_chunk_raw(id)?))
            })
            .unwrap();
        assert_eq!(r, Repair { repaired: 2, unavailable: 1 });
        assert_eq!(s.bad_chunks().unwrap(), BTreeSet::from([c]));
        let r = s.repair_from(|_| Ok(None)).unwrap();
        assert_eq!(r, Repair { repaired: 0, unavailable: 1 });
        // once no snapshot references it, the entry goes
        let snaps = s.list_snapshots().unwrap();
        s.delete_snapshot(&snaps[0].source, snaps[0].time).unwrap();
        assert_eq!(s.prune_bad().unwrap(), 1);
        assert!(s.bad_chunks().unwrap().is_empty());
    }
}
