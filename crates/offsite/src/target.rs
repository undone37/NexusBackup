//! One offsite target (one Storage Box per tenant): upload, independent
//! retention, GC with repacking, sampled verify, inventory check, restore.
//!
//! The box is dumb. The appliance keeps the offsite inventory locally in
//! `state` (sealed copies of every pack index and uploaded snapshot file), and
//! the box holds the same sealed files, so the copy is self-describing:
//! ```text
//! remote: packs/<pp>/<id>.pack   snapshots/<source>/<time>/{<name>.idx,manifest}   keys/…
//! state:  packs/<id>.idx         snapshots/<source>/<time>/{<name>.idx,manifest,lock}
//! ```
//! Ordering rules: a pack is uploaded before its local index copy is written
//! (orphans are harmless, phantoms would lose data); a snapshot's manifest is
//! uploaded after all its chunks and indexes; on deletion the manifest goes first.

use crate::pack::{self, Entry};
use crate::remote::Remote;
use anyhow::{bail, Context, Result};
use chunkstore::retention::{self, Gfs};
use chunkstore::store::write_atomic;
use chunkstore::{ChunkId, Manifest, Store};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::mpsc::sync_channel;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct Options {
    /// Parallel uploads (Storage Box allows 10 connections; keep some for restore/verify).
    pub uploaders: usize,
    /// Bytes per second over all uploaders (`None` = unlimited).
    pub bwlimit: Option<u64>,
    /// Repack a pack when more than this share of its bytes is dead.
    pub repack_threshold: f64,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            uploaders: 4,
            bwlimit: None,
            repack_threshold: 0.5,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Loc {
    pub pack: String,
    pub offset: u64,
    pub len: u32,
}

#[derive(Debug, Default)]
pub struct UploadStats {
    pub snapshots: usize,
    pub packs: usize,
    pub chunks: usize,
    pub bytes: u64,
}

#[derive(Debug, Default)]
pub struct GcStats {
    pub packs_deleted: usize,
    pub packs_repacked: usize,
    pub bytes_freed: u64,
}

#[derive(Debug, Default)]
pub struct InventoryReport {
    /// In the local inventory but missing (or wrong size) on the box: alert!
    pub missing: Vec<String>,
    /// On the box but unknown locally (crash leftovers or foreign files).
    pub unknown: Vec<String>,
}

impl InventoryReport {
    pub fn ok(&self) -> bool {
        self.missing.is_empty()
    }
}

pub struct Target<'a> {
    store: &'a Store,
    remote: &'a dyn Remote,
    state: PathBuf,
    opts: Options,
    inv: HashMap<ChunkId, Loc>,
    /// pack id -> (entries, total pack size)
    packs: BTreeMap<String, (Vec<Entry>, u64)>,
}

fn snap_key(source: &str, time: u64) -> String {
    format!("snapshots/{source}/{time}")
}

impl<'a> Target<'a> {
    /// Loads the local inventory. Run `rebuild_from_remote` first on a fresh appliance (DR).
    pub fn open(store: &'a Store, remote: &'a dyn Remote, state: PathBuf, opts: Options) -> Result<Self> {
        fs::create_dir_all(state.join("packs"))?;
        fs::create_dir_all(state.join("snapshots"))?;
        let mut t = Target {
            store,
            remote,
            state,
            opts,
            inv: HashMap::new(),
            packs: BTreeMap::new(),
        };
        for e in fs::read_dir(t.state.join("packs"))? {
            let e = e?;
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(id) = name.strip_suffix(".idx") else { continue };
            let raw = fs::read(e.path())?;
            let size_file = t.state.join("packs").join(format!("{id}.size"));
            let size: u64 = fs::read_to_string(&size_file)?
                .trim()
                .parse()
                .context("pack size file")?;
            let entries = pack::open_index(store.keys(), id, &raw)?;
            t.add_pack(id.to_owned(), entries, size);
        }
        Ok(t)
    }

    fn add_pack(&mut self, id: String, entries: Vec<Entry>, size: u64) {
        for e in &entries {
            self.inv.insert(
                e.id,
                Loc {
                    pack: id.clone(),
                    offset: e.offset,
                    len: e.len,
                },
            );
        }
        self.packs.insert(id, (entries, size));
    }

    fn record_pack(&mut self, id: &str, sealed_idx: &[u8], entries: Vec<Entry>, size: u64) -> Result<()> {
        let dir = self.state.join("packs");
        write_atomic(&dir.join(format!("{id}.size")), size.to_string().as_bytes())?;
        write_atomic(&dir.join(format!("{id}.idx")), sealed_idx)?;
        self.add_pack(id.to_owned(), entries, size);
        Ok(())
    }

    pub fn has_chunk(&self, id: &ChunkId) -> bool {
        self.inv.contains_key(id)
    }

    pub fn pack_count(&self) -> usize {
        self.packs.len()
    }

    /// Offsite snapshots known locally: (source, time).
    pub fn snapshots(&self) -> Result<Vec<(String, u64)>> {
        let mut out = Vec::new();
        for s in fs::read_dir(self.state.join("snapshots"))? {
            let s = s?;
            let source = s.file_name().to_string_lossy().into_owned();
            for t in fs::read_dir(s.path())? {
                let t = t?;
                if let Ok(time) = t.file_name().to_string_lossy().parse() {
                    if t.path().join("manifest").exists() {
                        out.push((source.clone(), time));
                    }
                }
            }
        }
        out.sort();
        Ok(out)
    }

    fn lock_path(&self, source: &str, time: u64) -> PathBuf {
        self.state.join(snap_key(source, time)).join("lock")
    }

    fn offsite_lock(&self, source: &str, time: u64) -> Result<u64> {
        Ok(fs::read_to_string(self.lock_path(source, time))?.trim().parse()?)
    }

    /// Uploads every local snapshot that is not offsite yet, oldest first.
    pub fn upload(&mut self) -> Result<UploadStats> {
        let done: HashSet<(String, u64)> = self.snapshots()?.into_iter().collect();
        let mut st = UploadStats::default();
        for m in self.store.list_snapshots()? {
            if done.contains(&(m.source.clone(), m.time)) {
                continue;
            }
            self.upload_snapshot(&m, &mut st)
                .with_context(|| format!("upload {}/{}", m.source, m.time))?;
            st.snapshots += 1;
        }
        Ok(st)
    }

    fn upload_snapshot(&mut self, m: &Manifest, st: &mut UploadStats) -> Result<()> {
        // chunks not yet offsite, in index order (keeps a protection group's packs together)
        let mut seen = HashSet::new();
        let mut missing = Vec::new();
        for name in &m.indexes {
            for id in self.store.load_index(m, name)?.chunk_ids() {
                if !self.inv.contains_key(id) && seen.insert(*id) {
                    missing.push(*id);
                }
            }
        }
        let keys = self.store.keys();
        let (remote, uploaders) = (self.remote, self.opts.uploaders.max(1));
        let per_thread_bw = self.opts.bwlimit.map(|b| (b / uploaders as u64).max(1));
        let (tx, rx) = sync_channel::<(String, Vec<u8>, Vec<u8>, Vec<Entry>)>(uploaders);
        let rx = Mutex::new(rx);
        let finished = Mutex::new(Vec::new());
        let builder_result: Result<()> = std::thread::scope(|sc| {
            for _ in 0..uploaders {
                sc.spawn(|| loop {
                    let Ok((id, bytes, idx, entries)) = rx.lock().unwrap().recv() else {
                        return;
                    };
                    let t0 = Instant::now();
                    let r = remote.put(&pack::remote_path(&id), &bytes);
                    if let (Ok(()), Some(bw)) = (&r, per_thread_bw) {
                        let want = Duration::from_secs_f64(bytes.len() as f64 / bw as f64);
                        std::thread::sleep(want.saturating_sub(t0.elapsed()));
                    }
                    finished.lock().unwrap().push((id, bytes.len() as u64, idx, entries, r));
                });
            }
            let mut b = pack::Builder::default();
            for id in &missing {
                let raw = self.store.read_chunk_raw(id)?;
                b.add(*id, &raw);
                if b.len() >= pack::TARGET_SIZE {
                    tx.send(std::mem::take(&mut b).finish(keys))
                        .map_err(|_| io::Error::other("uploader gone"))?;
                }
            }
            if !b.is_empty() {
                tx.send(b.finish(keys)).map_err(|_| io::Error::other("uploader gone"))?;
            }
            drop(tx);
            Ok(())
        });
        let mut first_err = builder_result.err();
        for (id, size, idx, entries, r) in finished.into_inner().unwrap() {
            match r {
                Ok(()) => {
                    st.packs += 1;
                    st.chunks += entries.len();
                    st.bytes += size;
                    self.record_pack(&id, &idx, entries, size)?;
                }
                Err(e) => {
                    first_err.get_or_insert(anyhow::Error::from(e).context(format!("pack {id}")));
                }
            }
        }
        if let Some(e) = first_err {
            return Err(e); // uploaded packs stay recorded; the retry only sends the rest
        }
        // snapshot files, manifest last; AlreadyExists = earlier attempt got that far
        let key = snap_key(&m.source, m.time);
        let files = self.store.snapshot_raw_files(m)?;
        for (name, bytes) in &files {
            match self.remote.put(&format!("{key}/{name}"), bytes) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        let local = self.state.join(&key);
        fs::create_dir_all(&local)?;
        write_atomic(&local.join("lock"), m.lock_until.to_string().as_bytes())?;
        for (name, bytes) in &files {
            write_atomic(&local.join(name), bytes)?; // manifest last = recorded as offsite
        }
        Ok(())
    }

    /// Independent offsite retention with the same GFS semantics; locks are
    /// tracked per offsite copy and only ever extended.
    pub fn apply_retention(&mut self, gfs: &Gfs) -> Result<(usize, usize, usize)> {
        let now = self.store.compliance_now()?;
        let mut by_source: BTreeMap<String, Vec<u64>> = BTreeMap::new();
        for (s, t) in self.snapshots()? {
            by_source.entry(s).or_default().push(t);
        }
        let (mut kept, mut deleted, mut locked) = (0, 0, 0);
        for (source, times) in by_source {
            let keep = retention::keep(&times, gfs);
            for t in times {
                let lock = self.offsite_lock(&source, t)?;
                if let Some(classes) = keep.get(&t) {
                    kept += 1;
                    let want = retention::lock_until(t, classes);
                    if want > lock {
                        write_atomic(&self.lock_path(&source, t), want.to_string().as_bytes())?;
                    }
                } else if now < lock {
                    locked += 1;
                } else {
                    self.delete_snapshot(&source, t)?;
                    deleted += 1;
                }
            }
        }
        Ok((kept, deleted, locked))
    }

    fn delete_snapshot(&self, source: &str, time: u64) -> Result<()> {
        let key = snap_key(source, time);
        for (name, _, _) in self.remote.list(&key)? {
            if name == "manifest" {
                self.remote.delete(&format!("{key}/manifest"))?; // gone from the box's point of view first
            }
        }
        for (name, _, dir) in self.remote.list(&key)? {
            if !dir {
                self.remote.delete(&format!("{key}/{name}"))?;
            }
        }
        let _ = self.remote.remove_dir(&key); // empty dirs would pile up over the years
        let local = self.state.join(&key);
        fs::remove_file(local.join("manifest"))?;
        fs::remove_dir_all(local)?;
        Ok(())
    }

    /// Chunks referenced by offsite snapshots. Unreadable state aborts (never sweep on an incomplete mark).
    fn mark(&self) -> Result<HashSet<ChunkId>> {
        let mut marked = HashSet::new();
        for (source, time) in self.snapshots()? {
            let dir = self.state.join(snap_key(&source, time));
            let m = self
                .store
                .decode_manifest(&source, time, &fs::read(dir.join("manifest"))?)?;
            for name in &m.indexes {
                let idx = self
                    .store
                    .decode_index(&source, time, name, &fs::read(dir.join(format!("{name}.idx")))?)?;
                marked.extend(idx.chunk_ids().into_iter().copied());
            }
        }
        Ok(marked)
    }

    /// Deletes dead packs, repacks packs that are mostly dead. Live chunks are
    /// taken from the local store when present, else range-read from the box.
    pub fn gc(&mut self) -> Result<GcStats> {
        let marked = self.mark()?;
        let mut st = GcStats::default();
        let ids: Vec<String> = self.packs.keys().cloned().collect();
        for id in ids {
            let (entries, size) = self.packs[&id].clone();
            let live: Vec<&Entry> = entries.iter().filter(|e| marked.contains(&e.id)).collect();
            let live_bytes: u64 = live.iter().map(|e| e.len as u64).sum();
            let dead_share = 1.0 - live_bytes as f64 / size.max(1) as f64;
            if !live.is_empty() && dead_share <= self.opts.repack_threshold {
                continue;
            }
            if !live.is_empty() {
                let mut b = pack::Builder::default();
                for e in &live {
                    let raw = match self.store.read_chunk_raw(&e.id) {
                        Ok(r) => r,
                        Err(_) => self.remote.get(&pack::remote_path(&id), e.offset, Some(e.len as u64))?,
                    };
                    self.store
                        .keys()
                        .open_chunk(&e.id, &raw)
                        .context("repack: live chunk corrupt")?;
                    b.add(e.id, &raw);
                }
                let (nid, bytes, idx, nentries) = b.finish(self.store.keys());
                self.remote.put(&pack::remote_path(&nid), &bytes)?;
                self.record_pack(&nid, &idx, nentries, bytes.len() as u64)?;
                st.packs_repacked += 1;
            }
            // old pack: forget locally first, then delete remotely (orphan > phantom)
            let dir = self.state.join("packs");
            fs::remove_file(dir.join(format!("{id}.idx")))?;
            fs::remove_file(dir.join(format!("{id}.size")))?;
            let (old, _) = self.packs.remove(&id).unwrap();
            for e in old {
                if self.inv.get(&e.id).is_some_and(|l| l.pack == id) {
                    self.inv.remove(&e.id);
                }
            }
            match self.remote.delete(&pack::remote_path(&id)) {
                Ok(()) => {
                    let _ = self.remote.remove_dir(&format!("packs/{}", &id[..2]));
                    // fails while not empty
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            st.packs_deleted += 1;
            st.bytes_freed += size;
        }
        Ok(st)
    }

    /// Downloads `n` random packs completely and verifies every chunk in them.
    /// Returns (packs checked, corrupt chunk count).
    pub fn verify_sample(&self, n: usize) -> Result<(usize, usize)> {
        use rand::seq::IteratorRandom;
        let picks = self.packs.keys().choose_multiple(&mut rand::thread_rng(), n);
        let mut bad = 0;
        for id in &picks {
            let bytes = self.remote.get(&pack::remote_path(id), 0, None)?;
            let entries = pack::parse(self.store.keys(), id, &bytes)?;
            for e in entries {
                let raw = &bytes[e.offset as usize..(e.offset + e.len as u64) as usize];
                if self.store.keys().open_chunk(&e.id, raw).is_err() {
                    bad += 1;
                }
            }
        }
        Ok((picks.len(), bad))
    }

    /// Compares the box with the local inventory (plan §9.2 "independent offsite monitoring").
    pub fn check_inventory(&self) -> Result<InventoryReport> {
        let mut r = InventoryReport::default();
        let mut remote_packs = HashMap::new();
        for (pp, _, dir) in self.remote.list("packs")? {
            if dir {
                for (name, size, _) in self.remote.list(&format!("packs/{pp}"))? {
                    if let Some(id) = name.strip_suffix(".pack") {
                        remote_packs.insert(id.to_owned(), size);
                    } else {
                        r.unknown.push(format!("packs/{pp}/{name}"));
                    }
                }
            }
        }
        for (id, (_, size)) in &self.packs {
            if remote_packs.get(id) != Some(size) {
                r.missing.push(pack::remote_path(id));
            }
        }
        r.unknown.extend(
            remote_packs
                .keys()
                .filter(|id| !self.packs.contains_key(*id))
                .map(|id| pack::remote_path(id)),
        );
        for (source, time) in self.snapshots()? {
            let key = snap_key(&source, time);
            if !self.remote.list(&key)?.iter().any(|(n, _, _)| n == "manifest") {
                r.missing.push(format!("{key}/manifest"));
            }
        }
        r.unknown.sort();
        Ok(r)
    }

    /// Fetches an offsite snapshot into the local store (chunks verified on insert).
    pub fn restore(&self, source: &str, time: u64) -> Result<Manifest> {
        let dir = self.state.join(snap_key(source, time));
        let mut files = Vec::new();
        for e in fs::read_dir(&dir).with_context(|| format!("{source}/{time} is not offsite"))? {
            let e = e?;
            let name = e.file_name().to_string_lossy().into_owned();
            if name != "lock" {
                files.push((name, fs::read(e.path())?));
            }
        }
        let m = self
            .store
            .decode_manifest(source, time, &fs::read(dir.join("manifest"))?)?;
        let mut need: BTreeMap<String, Vec<(ChunkId, Loc)>> = BTreeMap::new();
        for (name, bytes) in files.iter().filter(|(n, _)| n.ends_with(".idx")) {
            let idx = self
                .store
                .decode_index(source, time, name.trim_end_matches(".idx"), bytes)?;
            for id in idx.chunk_ids() {
                if !self.store.has_chunk(id) {
                    let loc = self
                        .inv
                        .get(id)
                        .with_context(|| format!("chunk {} not offsite", chunkstore::crypto::hex(id)))?;
                    need.entry(loc.pack.clone()).or_default().push((*id, loc.clone()));
                }
            }
        }
        for (pack_id, mut chunks) in need {
            chunks.sort_by_key(|(_, l)| l.offset);
            chunks.dedup_by_key(|(id, _)| *id);
            // ponytail: one range read per chunk; coalesce neighbours if latency dominates
            for (id, loc) in chunks {
                let raw = self
                    .remote
                    .get(&pack::remote_path(&pack_id), loc.offset, Some(loc.len as u64))?;
                self.store.insert_chunk_raw(&id, &raw)?;
            }
        }
        if self.store.load_manifest(source, time).is_err() {
            self.store.import_snapshot_raw(source, time, &files)?;
        }
        Ok(m)
    }

    /// DR: rebuilds the local inventory from the box alone (pack footers +
    /// snapshot files). Needs only the tenant keyring.
    pub fn rebuild_from_remote(&mut self) -> Result<usize> {
        let mut n = 0;
        for (pp, _, dir) in self.remote.list("packs")? {
            if !dir {
                continue;
            }
            for (name, size, _) in self.remote.list(&format!("packs/{pp}"))? {
                let Some(id) = name.strip_suffix(".pack") else { continue };
                if self.packs.contains_key(id) || size < 12 {
                    continue;
                }
                let path = pack::remote_path(id);
                let ilen = pack::footer_index_len(&self.remote.get(&path, size - pack::FOOTER, Some(pack::FOOTER))?)?;
                let sealed = self.remote.get(&path, size - pack::FOOTER - ilen, Some(ilen))?;
                let entries = pack::open_index(self.store.keys(), id, &sealed)?;
                self.record_pack(id, &sealed, entries, size)?;
                n += 1;
            }
        }
        for (source, _, dir) in self.remote.list("snapshots")? {
            if !dir {
                continue;
            }
            for (time, _, _) in self.remote.list(&format!("snapshots/{source}"))? {
                let Ok(t) = time.parse::<u64>() else { continue };
                let key = snap_key(&source, t);
                let names: Vec<String> = self.remote.list(&key)?.into_iter().map(|(n, _, _)| n).collect();
                if !names.iter().any(|n| n == "manifest") || self.state.join(&key).join("manifest").exists() {
                    continue;
                }
                let local = self.state.join(&key);
                fs::create_dir_all(&local)?;
                let manifest = self.remote.get(&format!("{key}/manifest"), 0, None)?;
                let m = self.store.decode_manifest(&source, t, &manifest)?; // verifies tenant + integrity
                write_atomic(&local.join("lock"), m.lock_until.to_string().as_bytes())?;
                for name in names.iter().filter(|n| n.ends_with(".idx")) {
                    write_atomic(&local.join(name), &self.remote.get(&format!("{key}/{name}"), 0, None)?)?;
                }
                write_atomic(&local.join("manifest"), &manifest)?;
            }
        }
        Ok(n)
    }

    /// Uploads small extra files (key escrow) if not present yet.
    pub fn put_if_missing(&self, path: &str, data: &[u8]) -> Result<()> {
        match self.remote.put(path, data) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => bail!("put {path}: {e}"),
        }
    }
}
