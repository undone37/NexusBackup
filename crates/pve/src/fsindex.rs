//! VM file index without the restore micro-VM (Phase 31a,
//! docs/file-index-v2-plan.md): the sandboxed helper `nexus-fsindex` parses
//! the guest file systems; this side reads the snapshot from the chunk store
//! (the helper gets bytes, never keys), reuses the listing of every volume
//! whose metadata chunks did not change since the previous snapshot, falls
//! back to the micro-VM for the volumes the helper cannot read (XFS, btrfs,
//! ZFS) when its image is installed, and writes the sealed name index plus
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
use fsindex::{Limits, Report, Volume, VolumeRec, REPORT_FILE};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::io;
use std::path::PathBuf;
use std::time::Instant;

/// Decrypted chunks kept for the helper's reads, least recently used out (it
/// reads metadata spread over the disk, often several times: an NTFS walk jumps
/// between the MFT and the directory indexes). 128 x 4 MiB = 512 MiB per job.
const CHUNK_CACHE: usize = 128;
/// Report format version.
const VERSION: u32 = 1;

/// File systems the micro-VM mounts that the helper does not parse.
const VM_FALLBACK: &[&str] = &["xfs", "btrfs", "zfs_member"];

struct StoreSource<'a> {
    store: &'a Store,
    names: Vec<String>,
    disks: Vec<(u64, u64, &'a [ChunkId])>,
    cache: VecDeque<((usize, u64), Vec<u8>)>,
    /// chunks read from the store (cache misses)
    loads: u64,
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
    fn read(&mut self, d: usize, off: u64, buf: &mut [u8]) -> io::Result<()> {
        let (cs, size, ids) = self.disks[d];
        if off.checked_add(buf.len() as u64).is_none_or(|e| e > size) {
            return Err(io::Error::other("read beyond the image end"));
        }
        let mut done = 0;
        while done < buf.len() {
            let pos = off + done as u64;
            let n = pos / cs;
            let i = match self.cache.iter().position(|(k, _)| *k == (d, n)) {
                Some(i) => {
                    // least recently used out: a hit moves to the front
                    let hit = self.cache.remove(i).expect("position in range");
                    self.cache.push_front(hit);
                    0
                }
                None => {
                    self.loads += 1;
                    let id = ids
                        .get(n as usize)
                        .ok_or_else(|| io::Error::other("chunk outside the index"))?;
                    let data = self.store.read_chunk(id)?;
                    if self.cache.len() >= CHUNK_CACHE {
                        self.cache.pop_back();
                    }
                    self.cache.push_front(((d, n), data));
                    0
                }
            };
            let data = &self.cache[i].1;
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
        cache: VecDeque::new(),
        loads: 0,
    };
    let disk_no: HashMap<String, usize> = src.names.iter().enumerate().map(|(i, n)| (n.clone(), i)).collect();
    let prev = previous(store, m);
    // a volume is reused when every chunk its last parse read is unchanged
    let unchanged = |rec: &VolumeRec| {
        rec.volume.state == "indexed"
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
    let helper = Helper::new(&helper_bin());
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
        &mut src,
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
        "fsindex: volumes listed in {:.1?}, {} chunk(s) read from the store",
        started.elapsed(),
        src.loads
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
                .filter_map(|(p, size, mtime, kind)| {
                    p.strip_prefix(&pre).map(|rest| fsindex::Entry {
                        path: rest.to_owned(),
                        size,
                        mtime,
                        kind,
                    })
                })
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
    // name index: the browse paths, with the directories above the volumes
    let mut names = NameIndex::default();
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
            }
        }
        for e in &l.entries {
            names.push(&format!("{}/{}", l.volume.browse, e.path), e.size, e.mtime, e.kind);
        }
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
    Ok(json!({
        "entries": names.len(),
        "complete": complete,
        "volumes": listed.iter().map(|l| summary(&l.volume)).collect::<Vec<_>>(),
        "parsed": parsed,
        "reused": reused,
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
    })
}

/// Lists the volumes only the micro-VM can read (XFS, btrfs, ZFS) through it,
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
                })
            })
            .collect();
        l.volume.entries = l.entries.len() as u64;
    }
    true
}

/// `nexus-pve … files <vmid> <time> index`: see [`index`].
pub fn cli(store: &Store, source: &str, time: u64) -> Result<()> {
    let m = store.load_manifest(source, time)?;
    let out = index(store, &m, Limits::default())?;
    println!("{out}");
    Ok(())
}
