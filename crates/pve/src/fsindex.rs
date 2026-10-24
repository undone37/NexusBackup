//! VM file index without the restore micro-VM (Phase 31a,
//! docs/file-index-v2-plan.md): the sandboxed helper `nexus-fsindex` parses
//! the guest file systems; this side reads the snapshot from the chunk store
//! (the helper gets bytes, never keys), reuses the listing of every volume
//! whose metadata chunks did not change since the previous snapshot, falls
//! back to the micro-VM for the volumes the helper cannot read (ZFS,
//! multi-device btrfs) when its image is installed, and writes the sealed name index plus
//! the sealed volume report (`fsindex`).
//!
//! Name-index paths stay the file browser's paths (`vda1/etc/hosts`,
//! `lvm/vg-root/home/…`), so open / download / restore work unchanged; the
//! guest paths (`/etc/hosts`, `C:/Users/…`) come from the report's mount
//! mapping (the search index shows those).

use anyhow::{bail, Context, Result};
use chunkstore::names::KIND_DIR;
use chunkstore::{ChunkId, Index, Manifest, NameIndex, Store};
use fsindex::parent::{self, Helper, Listed, Source};
use fsindex::{DirRec, Entry, Limits, Report, Volume, VolumeRec, REPORT_FILE};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Decrypted chunks kept for the helper's reads, least recently used out (it
/// reads metadata spread over the disk, often several times: an NTFS walk jumps
/// between the MFT and the directory indexes). 128 x 4 MiB = 512 MiB per job.
const CHUNK_CACHE: usize = 128;
/// Report format version; a report of another version is not reused (every volume is listed again once).
/// Bumped when the parse extracts more than the reused records carry: 2 = Windows account names also from
/// the SOFTWARE hive's ProfileList (#52; unchanged volumes kept the old names forever).
const VERSION: u32 = 2;

/// File systems the micro-VM mounts that the helper does not parse (btrfs: only
/// multi-device file systems reach this).
const VM_FALLBACK: &[&str] = &["btrfs", "zfs_member"];

/// (disk, chunk index) and the decoded chunk
type Cached = ((usize, u64), Arc<Vec<u8>>);

struct StoreSource<'a> {
    store: &'a Store,
    names: Vec<String>,
    disks: Vec<(u64, u64, &'a [ChunkId])>,
    /// shared by the helpers of one listing; a miss decodes outside the lock (in parallel)
    cache: Mutex<VecDeque<Cached>>,
    /// chunks read from the store (cache misses)
    loads: AtomicU64,
    /// Phase 31c: the previous snapshot's directories nothing of whose listing changed
    history: Hist,
    /// directories taken over from it
    taken: AtomicU64,
    /// Phase 31c: content hashes asked for (only records listed with hashes are taken over)
    hashes: bool,
}

/// (volume key, directory) -> (its entries, its record in this snapshot's disk numbers)
type Hist = HashMap<(String, String), (Vec<Entry>, DirRec)>;

/// Side file of the directory records (Phase 31c, postcard, sealed like the report).
const DIRS_FILE: &str = "fsindex-dirs";
const DIRS_VERSION: u32 = 1;

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct DirTable {
    version: u32,
    /// disk index names the records' `deps` count in
    disks: Vec<String>,
    /// (volume key, its directories)
    volumes: Vec<(String, Vec<DirRec>)>,
}

/// The directories of the previous snapshot (`pm`, report `pr`) whose listing read
/// only chunks that are still the same in this snapshot (disks `names` / `cur`),
/// with their entries from its name index.
fn history(store: &Store, pm: &Manifest, pr: &Report, names: &[String], cur: &[&[ChunkId]]) -> Result<Hist> {
    let mut out = Hist::new();
    let Some(b) = store.read_snap_file(&pm.source, pm.time, DIRS_FILE)? else {
        return Ok(out);
    };
    let Ok(table) = postcard::from_bytes::<DirTable>(&b) else {
        return Ok(out);
    };
    if table.version != DIRS_VERSION {
        return Ok(out);
    }
    // the previous snapshot's chunk ids per disk, matched by index name
    let mut prev_ids: HashMap<String, Vec<ChunkId>> = HashMap::new();
    for d in &table.disks {
        if let (true, Ok(Index::Fixed { chunks, .. })) = (pm.indexes.contains(d), store.load_index(pm, d)) {
            prev_ids.insert(d.clone(), chunks);
        }
    }
    let disk_now: HashMap<&str, usize> = names.iter().enumerate().map(|(i, n)| (n.as_str(), i)).collect();
    let unchanged = |pd: u32, c: u64| -> Option<(u32, u64)> {
        let name = table.disks.get(pd as usize)?;
        let now = *disk_now.get(name.as_str())?;
        let (a, b) = (prev_ids.get(name)?.get(c as usize)?, cur[now].get(c as usize)?);
        (a == b).then_some((now as u32, c))
    };
    for (key, recs) in table.volumes {
        for r in recs {
            let deps: Option<Vec<(u32, u64)>> = r.deps.iter().map(|&(d, c)| unchanged(d, c)).collect();
            // no deps means nothing was recorded: list it again
            if let Some(deps) = deps.filter(|d| !d.is_empty()) {
                out.insert((key.clone(), r.rel.clone()), (Vec::new(), DirRec { deps, ..r }));
            }
        }
    }
    if out.is_empty() {
        return Ok(out);
    }
    // their entries: the previous name index below each volume's browse path, by directory
    let browse: HashMap<&str, &str> = pr
        .volumes
        .iter()
        .map(|v| (v.volume.key.as_str(), v.volume.browse.as_str()))
        .collect();
    let prefixes: Vec<(String, String)> = out
        .keys()
        .map(|(k, _)| k.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|k| Some((format!("{}/", browse.get(k.as_str())?), k)))
        .collect();
    let names_idx = store.load_names(pm)?.unwrap_or_default();
    for (i, (p, size, mtime, kind)) in names_idx.iter().enumerate() {
        for (pre, key) in &prefixes {
            let Some(rest) = p.strip_prefix(pre.as_str()) else {
                continue;
            };
            let dir = rest.rsplit_once('/').map_or("", |(d, _)| d);
            if let Some((entries, _)) = out.get_mut(&(key.clone(), dir.to_owned())) {
                entries.extend(entry_at(&names_idx, i, p, size, mtime, kind, pre));
            }
            break;
        }
    }
    // a volume the previous report does not know by its key has no entries to take over
    out.retain(|(k, _), _| browse.contains_key(k.as_str()));
    Ok(out)
}

/// Entry `i` (`p`, …) of a name index below `prefix` (`vda1/`), with its owner and hash.
#[allow(clippy::too_many_arguments)]
fn entry_at(n: &NameIndex, i: usize, p: &str, size: u64, mtime: i64, kind: u8, prefix: &str) -> Option<Entry> {
    Some(Entry {
        path: p.strip_prefix(prefix)?.to_owned(),
        size,
        mtime,
        kind,
        owner: n.owner(i).map(str::to_owned),
        sha256: n.hash(i).copied(),
    })
}

impl StoreSource<'_> {
    /// Chunk `n` of disk `d`, decoded (cache, else the store).
    fn chunk(&self, d: usize, n: u64) -> io::Result<Arc<Vec<u8>>> {
        {
            let mut c = self.cache.lock().unwrap();
            if let Some(i) = c.iter().position(|(k, _)| *k == (d, n)) {
                // least recently used out: a hit moves to the front
                let hit = c.remove(i).expect("position in range");
                let data = hit.1.clone();
                c.push_front(hit);
                return Ok(data);
            }
        }
        // ponytail: two helpers missing the same chunk at once decode it twice; an in-flight set if that shows
        self.loads.fetch_add(1, Ordering::Relaxed);
        let id = self.disks[d]
            .2
            .get(n as usize)
            .ok_or_else(|| io::Error::other("chunk outside the index"))?;
        let data = Arc::new(self.store.read_chunk(id)?);
        let mut c = self.cache.lock().unwrap();
        if !c.iter().any(|(k, _)| *k == (d, n)) {
            if c.len() >= CHUNK_CACHE {
                c.pop_back();
            }
            c.push_front(((d, n), data.clone()));
        }
        Ok(data)
    }
}

impl Source for StoreSource<'_> {
    fn names(&self) -> Vec<String> {
        self.names.clone()
    }
    fn size(&self, d: usize) -> u64 {
        self.disks[d].1
    }
    fn chunk_size(&self, d: usize) -> u64 {
        self.disks[d].0
    }
    fn dir(&self, key: &str, rel: &str) -> Option<(Vec<Entry>, DirRec)> {
        let hit = self
            .history
            .get(&(key.to_owned(), rel.to_owned()))
            .filter(|(_, r)| r.hashed || !self.hashes)
            .cloned();
        if hit.is_some() {
            self.taken.fetch_add(1, Ordering::Relaxed);
        }
        hit
    }

    fn read(&self, d: usize, off: u64, buf: &mut [u8]) -> io::Result<()> {
        let (cs, size, _) = self.disks[d];
        if off.checked_add(buf.len() as u64).is_none_or(|e| e > size) {
            return Err(io::Error::other("read beyond the image end"));
        }
        let mut done = 0;
        while done < buf.len() {
            let pos = off + done as u64;
            let data = self.chunk(d, pos / cs)?;
            let at = (pos % cs) as usize;
            if at >= data.len() {
                return Err(io::Error::other("short chunk"));
            }
            let k = (data.len() - at).min(buf.len() - done);
            buf[done..done + k].copy_from_slice(&data[at..at + k]);
            done += k;
        }
        Ok(())
    }
}

/// The helper binary: `NEXUS_FSINDEX`, next to this program, or the appliance's.
pub fn helper_bin() -> PathBuf {
    if let Some(p) = std::env::var_os("NEXUS_FSINDEX") {
        return p.into();
    }
    if let Some(p) = std::env::current_exe()
        .ok()
        .and_then(|e| Some(e.parent()?.join("nexus-fsindex")))
    {
        if p.is_file() {
            return p;
        }
    }
    "/usr/libexec/nexus/nexus-fsindex".into()
}

/// The newest earlier snapshot of the source with a volume report: (manifest, report).
fn previous(store: &Store, m: &Manifest) -> Option<(Manifest, Report)> {
    let mut times: Vec<u64> = store
        .snapshot_keys()
        .ok()?
        .into_iter()
        .filter(|(s, t)| *s == m.source && *t < m.time)
        .map(|(_, t)| t)
        .collect();
    times.sort_unstable_by(|a, b| b.cmp(a));
    for t in times.into_iter().take(8) {
        if let Ok(Some(b)) = store.read_snap_file(&m.source, t, REPORT_FILE) {
            if let (Ok(r), Ok(pm)) = (serde_json::from_slice::<Report>(&b), store.load_manifest(&m.source, t)) {
                if r.version == VERSION {
                    return Some((pm, r));
                }
            }
        }
    }
    None
}

/// Lists the guest file systems of a VM snapshot and writes its name index
/// and volume report. Returns the job result.
pub fn index(store: &Store, m: &Manifest, limits: Limits) -> Result<Value> {
    let t0 = Instant::now();
    let mut idx = Vec::new();
    for name in &m.indexes {
        let i = store.load_index(m, name)?;
        if matches!(i, Index::Fixed { .. }) {
            idx.push((name.clone(), i));
        }
    }
    if idx.is_empty() {
        bail!("snapshot has no disk images");
    }
    let mut src = StoreSource {
        store,
        names: idx.iter().map(|(n, _)| n.clone()).collect(),
        disks: idx
            .iter()
            .map(|(_, i)| match i {
                Index::Fixed {
                    chunk_size,
                    size,
                    chunks,
                } => (*chunk_size as u64, *size, chunks.as_slice()),
                _ => unreachable!(),
            })
            .collect(),
        cache: Mutex::new(VecDeque::new()),
        loads: AtomicU64::new(0),
        history: Hist::new(),
        taken: AtomicU64::new(0),
        hashes: limits.hashes.is_some(),
    };
    let disk_no: HashMap<String, usize> = src.names.iter().enumerate().map(|(i, n)| (n.clone(), i)).collect();
    let prev = previous(store, m);
    if let Some((pm, pr)) = &prev {
        let cur: Vec<&[ChunkId]> = src.disks.iter().map(|d| d.2).collect();
        // a broken history only costs time: list everything
        src.history = history(store, pm, pr, &src.names, &cur).unwrap_or_else(|e| {
            eprintln!("fsindex: directory records of the previous snapshot unusable: {e:#}");
            Hist::new()
        });
    }
    // a volume is reused when every chunk its last parse read is unchanged
    let unchanged = |rec: &VolumeRec| {
        rec.volume.state == "indexed"
            && (rec.volume.hashed || limits.hashes.is_none())
            && !rec.reads.is_empty()
            && rec.reads.iter().all(|(disk, c, id)| {
                disk_no.get(disk).is_some_and(|&d| {
                    src.disks[d]
                        .2
                        .get(*c as usize)
                        .is_some_and(|cur| chunkstore::crypto::hex(cur) == *id)
                })
            })
    };
    let reusable: HashMap<String, VolumeRec> = prev
        .as_ref()
        .map(|(_, r)| {
            r.volumes
                .iter()
                .filter(|v| unchanged(v))
                .map(|v| (v.volume.key.clone(), v.clone()))
                .collect()
        })
        .unwrap_or_default();
    // Phase 32: one helper per CPU (up to 8) walks the NTFS / ext4 trees together
    let helper = Helper {
        parts: std::thread::available_parallelism().map_or(1, |n| n.get().min(8)) as u32,
        ..Helper::new(&helper_bin())
    };
    // live progress (docs/control-plane.md "Live progress"): the volume being listed, its
    // entries so far and an estimate of all (the previous snapshot's count of the same
    // volume, else the walker's from the file system metadata), at most every EVERY
    let before: HashMap<String, u64> = prev
        .as_ref()
        .map(|(_, r)| {
            r.volumes
                .iter()
                .map(|v| (v.volume.key.clone(), v.volume.entries))
                .collect()
        })
        .unwrap_or_default();
    let mut n = 0u32;
    let mut last: Option<std::time::Instant> = None;
    let started = std::time::Instant::now();
    let mut listed = parent::list_with_progress(
        &src,
        &helper,
        limits,
        &mut |v: &Volume| reusable.contains_key(&v.key),
        &mut |v: &Volume, entries, expect| {
            if entries == 0 && expect.is_none() {
                n += 1; // a volume starts
            } else if last.is_some_and(|t| t.elapsed() < chunkstore::progress::EVERY) {
                return;
            }
            last = Some(std::time::Instant::now());
            chunkstore::progress::Line {
                item: Some(m.source.clone()),
                part: Some(format!("{} ({})", v.browse, v.fs)),
                part_index: Some(n),
                entries: Some(entries),
                entries_total: before.get(&v.key).copied().filter(|&e| e > 0).or(expect),
                ..Default::default()
            }
            .print();
        },
    )
    .context("guest file systems")?;
    // where the time goes: every cache miss decrypts and decompresses one chunk (stderr:
    // stdout is the job result)
    eprintln!(
        "fsindex: volumes listed in {:.1?}, {} chunk(s) read from the store, {} of {} directories taken over from the previous snapshot",
        started.elapsed(),
        src.loads.load(Ordering::Relaxed),
        src.taken.load(Ordering::Relaxed),
        listed.iter().map(|l| l.dirs.len()).sum::<usize>()
    );
    // fill the reused volumes from the previous snapshot's name index
    let mut reused = 0;
    if listed.iter().any(|l| l.reused) {
        let (pm, _) = prev.as_ref().expect("reuse without a previous report");
        let names = store.load_names(pm)?.unwrap_or_default();
        for l in listed.iter_mut().filter(|l| l.reused) {
            let rec = &reusable[&l.volume.key];
            let pre = format!("{}/", rec.volume.browse);
            l.entries = names
                .iter()
                .enumerate()
                .filter_map(|(i, (p, size, mtime, kind))| entry_at(&names, i, p, size, mtime, kind, &pre))
                .collect();
            let browse = l.volume.browse.clone();
            l.volume = Volume {
                browse,
                entries: l.entries.len() as u64,
                ..rec.volume.clone()
            };
            l.reads = rec
                .reads
                .iter()
                .filter_map(|(d, c, _)| Some((*disk_no.get(d)?, *c)))
                .collect();
            // its directory records go on to the next snapshot (Phase 31c)
            l.dirs = src
                .history
                .iter()
                .filter(|((k, _), _)| *k == l.volume.key)
                .map(|(_, (_, r))| r.clone())
                .collect();
            reused += 1;
        }
    }
    let parsed = listed
        .iter()
        .filter(|l| !l.reused && l.volume.state == "indexed")
        .count();
    let fallback = vm_fallback(store, &idx, &mut listed, limits);
    let mut vols: Vec<Volume> = listed.iter().map(|l| l.volume.clone()).collect();
    fsindex::mapping::assign(&mut vols);
    for (l, v) in listed.iter_mut().zip(&vols) {
        l.volume.mount = v.mount.clone();
    }
    // name index: the browse paths, with the directories above the volumes; owners
    // (Phase 31c) as a table, each text once
    let mut names = NameIndex::default();
    let (mut owners, mut owner_no): (Vec<String>, HashMap<String, u32>) = (Vec::new(), HashMap::new());
    let mut owner: Vec<u32> = Vec::new();
    let mut dirs = BTreeSet::new();
    let mut complete = true;
    for l in &listed {
        complete &= !l.volume.problem() || l.volume.state == "unsupported";
        if l.entries.is_empty() && !matches!(l.volume.state.as_str(), "indexed" | "partial") {
            continue;
        }
        let mut acc = String::new();
        for c in l.volume.browse.split('/') {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(c);
            if dirs.insert(acc.clone()) {
                names.push(&acc, 0, 0, KIND_DIR);
                owner.push(0);
            }
        }
        for e in &l.entries {
            let i = names.len();
            names.push(&format!("{}/{}", l.volume.browse, e.path), e.size, e.mtime, e.kind);
            if names.len() == i {
                continue;
            }
            if let Some(h) = e.sha256.filter(|_| e.kind == chunkstore::names::KIND_FILE) {
                names.set_hash(i, h);
            }
            owner.push(match &e.owner {
                Some(o) => *owner_no.entry(o.clone()).or_insert_with(|| {
                    owners.push(o.clone());
                    owners.len() as u32
                }),
                None => 0,
            });
        }
    }
    if !owners.is_empty() {
        names.set_owners(owners, owner);
    }
    let report = Report {
        version: VERSION,
        volumes: listed
            .iter()
            .map(|l| VolumeRec {
                volume: l.volume.clone(),
                reads: l
                    .reads
                    .iter()
                    .filter_map(|(d, c)| {
                        let id = src.disks.get(*d)?.2.get(*c as usize)?;
                        Some((src.names[*d].clone(), *c, chunkstore::crypto::hex(id)))
                    })
                    .collect(),
            })
            .collect(),
    };
    store.write_names(&m.source, m.time, &names)?;
    store.write_snap_file(&m.source, m.time, REPORT_FILE, &serde_json::to_vec(&report)?)?;
    // Phase 31c: what each directory's listing read, for the next snapshot
    let table = DirTable {
        version: DIRS_VERSION,
        disks: src.names.clone(),
        volumes: listed
            .iter()
            .filter(|l| !l.dirs.is_empty())
            .map(|l| (l.volume.key.clone(), l.dirs.clone()))
            .collect(),
    };
    store.write_snap_file(&m.source, m.time, DIRS_FILE, &postcard::to_stdvec(&table)?)?;
    Ok(json!({
        "entries": names.len(),
        "complete": complete,
        "volumes": listed.iter().map(|l| summary(&l.volume)).collect::<Vec<_>>(),
        "parsed": parsed,
        "reused": reused,
        "dirs_taken_over": src.taken.load(Ordering::Relaxed),
        "hashes": names.sha256.len(),
        "unhashed": listed.iter().map(|l| l.volume.unhashed_files).sum::<u64>(),
        "micro_vm": fallback,
        "elapsed_ms": t0.elapsed().as_millis() as u64,
    }))
}

/// What the job result (catalog, plaintext) says about a volume: no labels,
/// UUIDs or fstab contents.
pub fn summary(v: &Volume) -> Value {
    json!({
        "browse": v.browse, "device": v.device, "fs": v.fs, "mount": v.mount, "state": v.state,
        "reason": v.reason, "entries": v.entries, "dedup_files": v.dedup_files,
        "owner_ids": v.owner_ids, "owned_entries": v.owned_entries,
    })
}

/// Lists the volumes only the micro-VM can read (ZFS, multi-device btrfs) through it,
/// if its image is installed. Returns whether it ran.
fn vm_fallback(store: &Store, idx: &[(String, Index)], listed: &mut [Listed], limits: Limits) -> bool {
    let want: Vec<usize> = (0..listed.len())
        .filter(|&i| listed[i].volume.state == "unsupported" && VM_FALLBACK.contains(&listed[i].volume.fs.as_str()))
        .collect();
    let cfg = crate::restorevm::Config::from_env();
    if want.is_empty() || std::env::var_os("NEXUS_FSINDEX_NO_VM").is_some() || !cfg.image_dir.join("vmlinuz").is_file()
    {
        return false;
    }
    let mut roots: Vec<String> = want
        .iter()
        .filter(|&&i| listed[i].volume.fs != "zfs_member")
        .map(|&i| listed[i].volume.browse.clone())
        .collect();
    if want.iter().any(|&i| listed[i].volume.fs == "zfs_member") {
        roots.push("zfs".into());
    }
    let disks: Vec<(&str, &Index)> = idx.iter().map(|(n, i)| (n.as_str(), i)).collect();
    let res = crate::restorevm::with_vm(store, &disks, &cfg, |vm| {
        crate::restorevm::index_roots(
            vm,
            &roots,
            limits.max_entries as usize,
            std::time::Duration::from_secs(limits.budget_secs),
        )
    });
    let (names, complete) = match res {
        Ok(x) => x,
        Err(e) => {
            eprintln!("fsindex: micro-VM fallback failed: {e:#}");
            return false;
        }
    };
    let first_zfs = want.iter().copied().find(|&i| listed[i].volume.fs == "zfs_member");
    for &i in &want {
        let zfs = listed[i].volume.fs == "zfs_member";
        let l = &mut listed[i];
        l.volume.state = if complete { "indexed" } else { "partial" }.into();
        l.volume.reason = Some("listed by the restore micro-VM".into());
        l.reads.clear();
        if zfs && Some(i) != first_zfs {
            // all datasets of the pools appear once, below zfs/ (first member)
            l.volume.reason = Some("ZFS pool member, listed by the restore micro-VM below zfs/".into());
            continue;
        }
        if zfs {
            l.volume.browse = "zfs".into();
        }
        let pre = format!("{}/", l.volume.browse);
        l.entries = names
            .iter()
            .filter_map(|(p, size, mtime, kind)| {
                p.strip_prefix(&pre).map(|r| fsindex::Entry {
                    path: r.to_owned(),
                    size,
                    mtime,
                    kind,
                    ..Default::default()
                })
            })
            .collect();
        l.volume.entries = l.entries.len() as u64;
    }
    true
}

/// `nexus-pve … files <vmid> <time> index [hashes]`: see [`index`]; `hashes`: the
/// SHA-256 of every regular file too (groups with `file_hashes`, Phase 31c).
pub fn cli(store: &Store, source: &str, time: u64, hashes: bool) -> Result<()> {
    let m = store.load_manifest(source, time)?;
    let mut limits = Limits::default();
    if hashes {
        limits.hashes = Some(fsindex::HashBudget::for_listing(limits.budget_secs));
    }
    let out = index(store, &m, limits)?;
    println!("{out}");
    Ok(())
}
