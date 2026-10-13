//! File-level backup of one agent into a `host-<agent-id>` tree snapshot.
//!
//! Prepare → Scan (base = newest local snapshot of this agent) → collect and
//! validate all entries → `Want` only plain hashes that are neither mapped nor
//! present in the store → verify `blake3(data) == hash` and the announced
//! length → `insert_chunk` → record plain → keyed → build `Index::Tree` →
//! commit → `Release { success: true }`. Any failure before the commit ends
//! with `Release { success: false }` and nothing committed.

use crate::map::MapDb;
use crate::tls::Session;
use crate::{hex, name, source_name, valid_rel_path, TREE_INDEX};
use agent_proto::{BaseRef, Entry, Filters, Hash, Kind, Limits, Message, ScanStats, CAP_PREPARE2, MAX_BATCH};
use anyhow::{bail, Context, Result};
use chunkstore::{ChunkId, Index, Manifest, Store, TreeEntry, TreeKind};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct Spec {
    pub job: u64,
    pub paths: Vec<String>,
    pub excludes: Vec<String>,
    pub hooks: bool,
    /// sent with `PrepareEx` (agents with CAP_PREPARE2), ignored by older agents
    pub filters: Filters,
    pub limits: Limits,
}

#[derive(Debug, Default)]
pub struct Report {
    pub source: String,
    pub time: u64,
    pub entries: u64,
    pub files: u64,
    pub bytes: u64,
    pub unchanged: u64,
    /// chunks / bytes transferred (requested via Want)
    pub wanted_chunks: u64,
    pub wanted_bytes: u64,
    /// bytes actually received for those chunks (smaller with LZ4 on the wire)
    pub wire_bytes: u64,
    /// of those, not in the store before
    pub new_chunks: u64,
    /// agent: snapshots + hooks gave a consistent view
    pub consistent: bool,
    pub inconsistent_files: u64,
    pub base: Option<u64>,
    pub prepare_hook_log: String,
    pub release_hook_log: String,
    pub scan: ScanStats,
    /// machine layout JSON (agents with CAP_LAYOUT), stored as `.nexus-system/layout.json`
    pub layout: Option<String>,
}

/// Newest committed snapshot of this agent (the `base` of the next scan).
pub fn last_snapshot(store: &Store, agent_id: &str) -> Result<Option<u64>> {
    let src = source_name(agent_id);
    Ok(store
        .list_snapshots()?
        .into_iter()
        .filter(|m| m.source == src)
        .map(|m| m.time)
        .max())
}

fn tree_kind(k: Kind) -> TreeKind {
    match k {
        Kind::File => TreeKind::File,
        Kind::Dir => TreeKind::Dir,
        Kind::Symlink => TreeKind::Symlink,
        Kind::Hardlink => TreeKind::Hardlink,
        Kind::Device => TreeKind::Device,
        Kind::Fifo => TreeKind::Fifo,
        Kind::Socket => TreeKind::Socket,
    }
}

/// Structural checks of one entry from a (possibly hostile) agent.
fn check_entry(e: &Entry) -> Result<()> {
    let p = String::from_utf8_lossy(&e.path);
    if !valid_rel_path(&e.path) {
        bail!("agent sent an invalid path {p:?}");
    }
    match e.kind {
        Kind::File => {
            let sum: u64 = e.chunks.iter().map(|(_, l)| u64::from(*l)).sum();
            if sum != e.size {
                bail!("{p:?}: chunk lengths add up to {sum}, size is {}", e.size);
            }
            if e.chunks.iter().any(|(_, l)| *l == 0) {
                bail!("{p:?}: empty chunk");
            }
        }
        _ if !e.chunks.is_empty() => bail!("{p:?}: only regular files have chunks"),
        Kind::Symlink if e.link_target.as_ref().is_none_or(|t| t.is_empty() || t.contains(&0)) => {
            bail!("{p:?}: symlink without a valid target")
        }
        Kind::Hardlink if !e.link_target.as_deref().is_some_and(valid_rel_path) => {
            bail!("{p:?}: hard link without a valid target")
        }
        _ => {}
    }
    if e.xattrs.iter().any(|(k, _)| k.is_empty() || k.contains(&0)) {
        bail!("{p:?}: invalid xattr name");
    }
    Ok(())
}

/// Runs one backup. `log` receives progress lines (they end up in the job log).
pub fn backup(
    store: &Store,
    map: &mut MapDb,
    s: &mut Session,
    agent_id: &str,
    spec: &Spec,
    log: &mut dyn FnMut(&str),
) -> Result<Report> {
    let base = last_snapshot(store, agent_id)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut r = Report {
        source: source_name(agent_id),
        time: now.max(base.map_or(0, |b| b + 1)),
        base,
        ..Default::default()
    };
    if s.has_cap(agent_proto::CAP_LAYOUT) {
        r.layout = fetch_layout(s, log)?;
    }
    if s.has_cap(CAP_PREPARE2) {
        s.send(&Message::PrepareEx {
            job: spec.job,
            paths: spec.paths.clone(),
            excludes: spec.excludes.clone(),
            hooks: spec.hooks,
            filters: spec.filters.clone(),
            limits: spec.limits,
        })?;
    } else {
        // an agent before v1.3: globs only, no limits (docs/agent-protocol.md "Filters")
        if spec.filters != Filters::default() {
            log("warning: this agent version ignores include paths, regex excludes and cross-mount settings: update the agent");
        }
        if spec.limits != Limits::default() {
            log("warning: this agent version ignores the bandwidth / CPU limits: update the agent");
        }
        s.send(&Message::Prepare {
            job: spec.job,
            paths: spec.paths.clone(),
            excludes: spec.excludes.clone(),
            hooks: spec.hooks,
        })?;
    }
    match s.recv()? {
        Message::Prepared {
            job,
            snapshots,
            consistent,
            hook_log,
        } if job == spec.job => {
            r.consistent = consistent;
            r.prepare_hook_log = hook_log;
            for sn in &snapshots {
                log(&format!(
                    "snapshot {:?} of {:?} ({:?})",
                    sn.name, sn.mountpoint, sn.kind
                ));
            }
            if !consistent {
                log("agent: no consistent view (snapshot or hooks missing/failed); files are read live");
            }
        }
        m => bail!("unexpected answer to Prepare: {}", name(&m)),
    }
    // From here on the agent holds snapshots / ran hooks: always release.
    match collect_and_commit(store, map, s, spec, &mut r, log) {
        Ok(m) => {
            match release(s, spec.job, true) {
                Ok(h) => r.release_hook_log = h,
                // the snapshot is committed; the agent only misses its cache update
                Err(e) => log(&format!("warning: release after commit failed: {e:#}")),
            }
            r.time = m.time;
            Ok(r)
        }
        Err(e) => {
            if let Err(e2) = release(s, spec.job, false) {
                log(&format!("release after failure: {e2:#}"));
            }
            Err(e)
        }
    }
}

/// `GetLayout` (docs/bmr.md "Layout"). A layout that does not parse is logged and
/// left out: the backup itself does not depend on it.
fn fetch_layout(s: &mut Session, log: &mut dyn FnMut(&str)) -> Result<Option<String>> {
    s.send(&Message::GetLayout)?;
    match s.recv()? {
        Message::Layout { json } => match serde_json::from_str::<agent_proto::layout::Layout>(&json) {
            Ok(l) => {
                log(&format!(
                    "layout: {} disk(s), {} volume group(s), {} file system(s), {} firmware{}",
                    l.disks.len(),
                    l.vgs.len(),
                    l.filesystems.len(),
                    if l.firmware.is_empty() { "?" } else { &l.firmware },
                    if l.warnings.is_empty() {
                        String::new()
                    } else {
                        format!(", {} note(s)", l.warnings.len())
                    }
                ));
                for w in &l.warnings {
                    log(&format!("layout note: {w:?}"));
                }
                Ok(Some(json))
            }
            Err(e) => {
                log(&format!(
                    "warning: the agent's machine layout does not parse ({e}); not stored"
                ));
                Ok(None)
            }
        },
        Message::Error { message, .. } => {
            log(&format!("warning: no machine layout: {message:?}"));
            Ok(None)
        }
        m => bail!("unexpected answer to GetLayout: {}", name(&m)),
    }
}

/// The synthetic `.nexus-system/layout.json` entries (replacing any the host had).
fn add_layout(store: &Store, tree: &mut Vec<TreeEntry>, json: &str, time: u64) -> Result<()> {
    use agent_proto::layout::LAYOUT_PATH;
    let dir = LAYOUT_PATH.rsplit_once('/').map(|x| x.0).unwrap_or_default().as_bytes();
    tree.retain(|e| e.path != LAYOUT_PATH.as_bytes());
    let ns = i64::try_from(time).unwrap_or(0).saturating_mul(1_000_000_000);
    let base = TreeEntry {
        path: dir.to_vec(),
        kind: TreeKind::Dir,
        mode: 0o700,
        uid: 0,
        gid: 0,
        size: 0,
        mtime_ns: ns,
        ctime_ns: ns,
        inode: 0,
        rdev: 0,
        link_target: None,
        xattrs: vec![],
        chunks: vec![],
        inconsistent: false,
    };
    if !tree.iter().any(|e| e.path == dir) {
        tree.push(base.clone());
    }
    let mut chunks = vec![];
    for c in json.as_bytes().chunks(agent_proto::MAX_CHUNK) {
        chunks.push(store.insert_chunk(c)?.0);
    }
    tree.push(TreeEntry {
        path: LAYOUT_PATH.as_bytes().to_vec(),
        kind: TreeKind::File,
        mode: 0o600,
        size: json.len() as u64,
        chunks,
        ..base
    });
    Ok(())
}

fn release(s: &mut Session, job: u64, success: bool) -> Result<String> {
    s.send(&Message::Release { job, success })?;
    if !success {
        s.set_timeout(Duration::from_secs(60));
    }
    // a failed transfer may leave chunk messages in flight: skip them
    for _ in 0..1_000_000 {
        match s.recv()? {
            Message::Released { job: j, hook_log } if j == job => return Ok(hook_log),
            Message::Chunk { .. } | Message::WantDone | Message::Entries { .. } | Message::ScanDone { .. }
                if !success => {}
            m => bail!("unexpected answer to Release: {}", name(&m)),
        }
    }
    bail!("agent did not answer Release")
}

fn collect_and_commit(
    store: &Store,
    map: &mut MapDb,
    s: &mut Session,
    spec: &Spec,
    r: &mut Report,
    log: &mut dyn FnMut(&str),
) -> Result<Manifest> {
    s.send(&Message::Scan {
        job: spec.job,
        base: r.base.map(|time| BaseRef { time }),
    })?;
    // ponytail: the whole entry list is held in memory (≈200 B/entry); spill to disk for >10M files
    let mut entries: Vec<Entry> = Vec::new();
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut lens: HashMap<Hash, u32> = HashMap::new();
    loop {
        match s.recv()? {
            Message::Entries { batch } => {
                for e in batch {
                    if e.path.is_empty() || e.path == b"." {
                        continue; // the root itself
                    }
                    check_entry(&e)?;
                    if !seen.insert(e.path.clone()) {
                        bail!("agent sent {:?} twice", String::from_utf8_lossy(&e.path));
                    }
                    for (h, l) in &e.chunks {
                        if *lens.entry(*h).or_insert(*l) != *l {
                            bail!("agent announced chunk {} with two different lengths", hex(h));
                        }
                    }
                    r.entries += 1;
                    if e.kind == Kind::File {
                        r.files += 1;
                        r.bytes += e.size;
                    }
                    r.unchanged += u64::from(e.unchanged);
                    r.inconsistent_files += u64::from(e.inconsistent);
                    entries.push(e);
                }
            }
            Message::ScanDone { stats } => {
                r.scan = stats;
                break;
            }
            m => bail!("unexpected message during scan: {}", name(&m)),
        }
    }
    for e in &r.scan.errors {
        log(&format!("agent: {e:?}")); // escaped: agent text never starts a log line
    }
    log(&format!(
        "scan: {} entries, {} files, {} bytes, {} unchanged, {} distinct chunks",
        r.entries,
        r.files,
        r.bytes,
        r.unchanged,
        lens.len()
    ));

    // what the store already has: mapped and present (touched: GC keeps it until we commit)
    let mut keyed: HashMap<Hash, ChunkId> = HashMap::with_capacity(lens.len());
    let mut want: Vec<Hash> = Vec::new();
    for h in lens.keys() {
        match map.get(h)? {
            Some(id) if store.touch_chunk(&id)? => {
                keyed.insert(*h, id);
            }
            _ => want.push(*h),
        }
    }
    want.sort_unstable(); // deterministic order (tests, agent-side locality is the agent's job)
    let lz4 = s.has_cap(agent_proto::CAP_LZ4);
    for batch in want.chunks(MAX_BATCH) {
        let (job, hashes) = (spec.job, batch.to_vec());
        s.send(&if lz4 {
            Message::WantLz4 { job, hashes }
        } else {
            Message::Want { job, hashes }
        })?;
        let mut pending: HashSet<Hash> = batch.iter().copied().collect();
        let mut learned = Vec::with_capacity(batch.len());
        loop {
            let (hash, data, wire) = match s.recv()? {
                Message::Chunk { hash, data } => {
                    let n = data.len();
                    (hash, data, n)
                }
                Message::ChunkLz4 { hash, raw_len, data } => {
                    if !lz4 {
                        bail!("agent sent ChunkLz4 although it was not asked to compress");
                    }
                    // size-bounded by raw_len (frame check: ≤ MAX_CHUNK); the hash check below covers content
                    let raw = agent_proto::lz4_unpack(&data, raw_len)
                        .with_context(|| format!("chunk {}: bad LZ4 data", hex(&hash)))?;
                    (hash, raw, data.len())
                }
                Message::WantDone => break,
                m => bail!("unexpected message during chunk transfer: {}", name(&m)),
            };
            {
                {
                    if !pending.remove(&hash) {
                        bail!("agent sent chunk {} that was not requested (or twice)", hex(&hash));
                    }
                    if data.len() != lens[&hash] as usize {
                        bail!(
                            "chunk {}: {} bytes received, {} announced",
                            hex(&hash),
                            data.len(),
                            lens[&hash]
                        );
                    }
                    if blake3::hash(&data).as_bytes() != &hash {
                        bail!("chunk {}: data does not match its BLAKE3 hash; rejected", hex(&hash));
                    }
                    let (id, new) = store.insert_chunk(&data)?;
                    r.wanted_chunks += 1;
                    r.wanted_bytes += data.len() as u64;
                    r.wire_bytes += wire as u64;
                    r.new_chunks += u64::from(new);
                    keyed.insert(hash, id);
                    learned.push((hash, id, data.len() as u32));
                }
            }
        }
        if !pending.is_empty() {
            bail!("agent did not deliver {} of the requested chunks", pending.len());
        }
        map.put_all(&learned).context("mapping index")?;
    }
    log(&format!(
        "transfer: {} chunks ({} bytes) requested, {} bytes on the wire{}, {} new in the store",
        r.wanted_chunks,
        r.wanted_bytes,
        r.wire_bytes,
        if lz4 { " (lz4)" } else { "" },
        r.new_chunks
    ));
    let mut tree: Vec<TreeEntry> = entries
        .into_iter()
        .map(|e| TreeEntry {
            chunks: e.chunks.iter().map(|(h, _)| keyed[h]).collect(),
            path: e.path,
            kind: tree_kind(e.kind),
            mode: e.mode,
            uid: e.uid,
            gid: e.gid,
            size: e.size,
            mtime_ns: e.mtime_ns,
            ctime_ns: e.ctime_ns,
            inode: e.inode,
            rdev: e.rdev,
            link_target: e.link_target,
            xattrs: e.xattrs,
            inconsistent: e.inconsistent,
        })
        .collect();
    if let Some(json) = &r.layout {
        add_layout(store, &mut tree, json, r.time)?;
    }
    Ok(store.commit_snapshot(&r.source, r.time, &[(TREE_INDEX, Index::Tree { entries: tree })])?)
}
