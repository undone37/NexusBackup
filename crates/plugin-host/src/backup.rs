//! Backup op: validates the plugin's item stream and writes one snapshot.
//!
//! Ordering (anything else is a protocol violation and kills the plugin):
//! `FileBegin` → `Data`* → `FileEnd` (data only for regular files, exactly
//! `meta.size` bytes), `Unchanged` (only for a path of the base snapshot whose
//! metadata matches — the chunk list is taken from the base snapshot, never from
//! the plugin), `Stream` → `Data`* → `StreamEnd`, `BaseQuery` / `BaseList`
//! (answered with `BaseEntries`), `Log`/`Progress` at any time, finally `Done`
//! outside any item.
//! Paths are unique, relative, without `.`/`..`, not below [`plugin_proto::STREAMS_DIR`].
//!
//! Data is chunked with the store's FastCDC parameters as it arrives (≤ 4 MiB
//! buffered per open item), sealed and deduplicated. Snapshot: `files`
//! (`Index::Tree`), `streams` (`Index::Dynamic`, one entry per stream, if any),
//! `state` (the plugin's state blob, if any); the manifest is written last.

use crate::sandbox::Peer;
use crate::{escape, level_name, meta_of, tree_kind, FILES_INDEX, STATE_INDEX, STREAMS_INDEX};
use anyhow::{bail, Context, Result};
use chunkstore::store::{CDC_AVG, CDC_MAX, CDC_MIN};
use chunkstore::{ChunkId, FileEntry, Index, Store, TreeEntry, TreeKind};
use plugin_proto::{BaseEntry, BaseInfo, Message, Meta, Op, API, MAX_BATCH, MAX_FRAME, STREAMS_DIR};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Upper bounds the host enforces beyond the protocol's per-message limits.
#[derive(Clone, Debug)]
pub struct Bounds {
    /// Entries (files, directories, links, ...) per snapshot.
    pub max_entries: usize,
    /// Streams per snapshot.
    pub max_streams: usize,
    /// summed path bytes of one `BaseQuery`
    pub max_query_bytes: usize,
    /// plugin log text kept per job
    pub max_log_bytes: usize,
}

impl Default for Bounds {
    fn default() -> Self {
        Bounds {
            max_entries: 20_000_000,
            max_streams: 100_000,
            max_query_bytes: 1 << 20,
            max_log_bytes: 4 << 20,
        }
    }
}

/// The previous snapshot of the same source.
pub struct Base {
    /// Snapshot time, Unix seconds.
    pub time: u64,
    /// Entries of its `files` index.
    pub entries: Vec<TreeEntry>,
    by_path: HashMap<Vec<u8>, usize>,
    /// entry indexes in path order (built on the first `BaseList`)
    sorted: std::cell::OnceCell<Vec<usize>>,
    /// Its state blob (index `state`), returned to the plugin in `Init.state`.
    pub state: Option<Vec<u8>>,
}

impl Base {
    /// The entry at `path`, if the base snapshot has one.
    pub fn get(&self, path: &[u8]) -> Option<&TreeEntry> {
        self.by_path.get(path).map(|&i| &self.entries[i])
    }

    /// One `BaseList` page: entries after `after` in path order, as many as fit one
    /// frame with their full metadata (at least one; ≤ `MAX_BATCH`).
    fn list_page(&self, after: Option<&[u8]>) -> Vec<BaseEntry> {
        let sorted = self.sorted.get_or_init(|| {
            let mut v: Vec<usize> = (0..self.entries.len()).collect();
            v.sort_by(|&a, &b| self.entries[a].path.cmp(&self.entries[b].path));
            v
        });
        let start = after.map_or(0, |a| sorted.partition_point(|&i| self.entries[i].path.as_slice() <= a));
        let mut out = Vec::new();
        let mut bytes = 0;
        for &i in &sorted[start..] {
            let e = &self.entries[i];
            let size = entry_size(&e.path, &meta_of(e));
            if out.len() >= MAX_BATCH || (!out.is_empty() && bytes + size > MAX_FRAME - (64 << 10)) {
                break;
            }
            bytes += size;
            out.push(BaseEntry {
                path: e.path.clone(),
                meta: meta_of(e),
            });
        }
        out
    }
}

/// Upper bound of an entry's encoded size in a `BaseEntries` frame.
pub(crate) fn entry_size(path: &[u8], m: &Meta) -> usize {
    path.len()
        + 96
        + m.link_target.as_ref().map_or(0, Vec::len)
        + m.xattrs.iter().map(|(k, v)| k.len() + v.len() + 8).sum::<usize>()
}

/// Newest committed snapshot of `source` (files index + state).
pub fn load_base(store: &Store, source: &str) -> Result<Option<Base>> {
    let Some(m) = store
        .list_snapshots()?
        .into_iter()
        .filter(|m| m.source == source)
        .max_by_key(|m| m.time)
    else {
        return Ok(None);
    };
    // a base with bad chunks (verify) is not built upon: the plugin sends everything again
    if store.is_damaged(&m)? {
        return Ok(None);
    }
    let entries = match store.load_index(&m, FILES_INDEX)? {
        Index::Tree { entries } => entries,
        _ => bail!("{source}/{}: `files` is not a tree index", m.time),
    };
    let by_path = entries.iter().enumerate().map(|(i, e)| (e.path.clone(), i)).collect();
    Ok(Some(Base {
        time: m.time,
        entries,
        by_path,
        sorted: std::cell::OnceCell::new(),
        state: read_state(store, &m)?,
    }))
}

/// The backup params as the plugin sees them: the host's own plus `caps`, the optional messages this host
/// accepts (v1.10: [`plugin_proto::CAP_ITEM_META`]).
fn with_caps(params: &serde_json::Value) -> serde_json::Value {
    let mut p = params.clone();
    if let Some(o) = p.as_object_mut() {
        o.insert("caps".into(), serde_json::json!([plugin_proto::CAP_ITEM_META]));
    }
    p
}

/// The item metadata of a committed snapshot (path → record); empty when it has none.
pub fn read_item_meta(store: &Store, source: &str, time: u64) -> Result<BTreeMap<String, serde_json::Value>> {
    Ok(
        match store.read_snap_file(source, time, plugin_proto::ITEM_META_FILE)? {
            Some(b) => serde_json::from_slice(&b).context("item metadata")?,
            None => BTreeMap::new(),
        },
    )
}

/// The state blob stored with a snapshot.
pub fn read_state(store: &Store, m: &chunkstore::Manifest) -> Result<Option<Vec<u8>>> {
    if !m.indexes.iter().any(|i| i == STATE_INDEX) {
        return Ok(None);
    }
    match store.load_index(m, STATE_INDEX)? {
        Index::Dynamic { entries } => {
            let Some(e) = entries.first() else { return Ok(None) };
            let mut out = Vec::with_capacity(e.size as usize);
            std::io::copy(&mut store.chunk_reader(&e.chunks), &mut out)?;
            if out.len() > plugin_proto::MAX_STATE {
                bail!("stored plugin state exceeds the limit");
            }
            Ok(Some(out))
        }
        _ => bail!("`state` is not a dynamic index"),
    }
}

/// Push-based FastCDC with the store's parameters (same cut points as `Store::store_file`).
pub(crate) struct Chunker {
    buf: Vec<u8>,
    start: usize,
    pub chunks: Vec<ChunkId>,
    pub size: u64,
    pub new_bytes: u64,
    pub new_chunks: u64,
}

impl Chunker {
    pub fn new() -> Chunker {
        Chunker {
            buf: Vec::new(),
            start: 0,
            chunks: Vec::new(),
            size: 0,
            new_bytes: 0,
            new_chunks: 0,
        }
    }

    fn emit(&mut self, store: &Store, n: usize) -> std::io::Result<()> {
        let data = &self.buf[self.start..self.start + n];
        let (id, new) = store.insert_chunk(data)?;
        self.chunks.push(id);
        self.size += n as u64;
        if new {
            self.new_bytes += n as u64;
            self.new_chunks += 1;
        }
        self.start += n;
        Ok(())
    }

    fn cut(&self) -> usize {
        let rest = &self.buf[self.start..];
        fastcdc::v2020::FastCDC::new(rest, CDC_MIN as usize, CDC_AVG as usize, CDC_MAX as usize)
            .next()
            .map_or(rest.len(), |c| c.length)
    }

    pub fn push(&mut self, store: &Store, data: &[u8]) -> std::io::Result<()> {
        self.buf.extend_from_slice(data);
        while self.buf.len() - self.start >= CDC_MAX as usize {
            let n = self.cut();
            self.emit(store, n)?;
        }
        if self.start > 0 && self.start * 2 >= self.buf.len() {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        Ok(())
    }

    pub fn finish(mut self, store: &Store) -> std::io::Result<Chunker> {
        while self.start < self.buf.len() {
            let n = self.cut();
            self.emit(store, n)?;
        }
        self.buf = Vec::new();
        self.start = 0;
        Ok(self)
    }
}

/// Outcome of one committed backup (printed as part of the `result {json}` line).
#[derive(Debug, Default, Clone)]
pub struct Report {
    /// Snapshot source name (`plugin-<id>-<source>[-<guest>]`).
    pub source: String,
    /// Snapshot time, Unix seconds (later than the base's).
    pub time: u64,
    /// Time of the base snapshot, if there was one.
    pub base: Option<u64>,
    /// Entries in the `files` index.
    pub entries: u64,
    /// Regular files (sent or unchanged).
    pub files: u64,
    /// Application streams.
    pub streams: u64,
    /// Entries reused from the base with `Unchanged`.
    pub unchanged: u64,
    /// logical bytes (files + streams)
    pub bytes: u64,
    /// bytes received from the plugin
    pub transferred: u64,
    /// bytes in chunks that were new to the store
    pub new_bytes: u64,
    /// `Done.consistent` of the plugin.
    pub consistent: bool,
    /// `Done.summary` as sent (escape it before printing).
    pub summary: String,
    /// items the plugin skipped (v1.7 `Warnings`) and the first few of them
    pub warnings: u64,
    /// Samples of the skipped items as sent, at most 20 (escape before printing).
    pub warning_samples: Vec<String>,
    /// v1.8 `SnapshotMeta` (a JSON object), kept in the appliance catalog
    pub meta: Option<serde_json::Value>,
}

/// Plugin log/progress output with a per-job budget.
pub(crate) struct LogSink<'a> {
    pub out: &'a mut dyn FnMut(&str),
    pub left: usize,
    pub last_progress: Option<Instant>,
}

impl LogSink<'_> {
    pub fn log(&mut self, level: u8, text: &str) {
        if self.left == 0 {
            return;
        }
        self.left = self.left.saturating_sub(text.len() + 16);
        (self.out)(&format!("plugin[{}]: {}", level_name(level), escape(text, 4000)));
        if self.left == 0 {
            (self.out)("plugin: [… further plugin log dropped (limit) …]");
        }
    }
    /// The plugin's progress as a machine line (`progress {json}` on stderr, docs/control-plane.md
    /// "Live progress"): the text is the part, `done`/`total` as the plugin counts them (0 total:
    /// unknown). The former `progress d/t: text` log line was not JSON, so the scheduler dropped it
    /// (Phase 39 C7).
    pub fn progress(&mut self, done: u64, total: u64, text: &str) {
        if self
            .last_progress
            .is_some_and(|t| t.elapsed() < chunkstore::progress::EVERY)
        {
            return;
        }
        self.last_progress = Some(Instant::now());
        progress_line(done, total, text).print();
    }
}

pub(crate) fn progress_line(done: u64, total: u64, text: &str) -> chunkstore::progress::Line {
    chunkstore::progress::Line {
        part: Some(escape(text, 64)).filter(|p| !p.is_empty()),
        done: Some(done),
        total: (total > 0).then_some(total),
        ..Default::default()
    }
    .with_item()
}

enum Open {
    Idle,
    File {
        path: Vec<u8>,
        meta: Meta,
        kind: TreeKind,
        chunker: Chunker,
        got: u64,
    },
    Stream {
        name: String,
        chunker: Chunker,
    },
}

/// Answer to a `BaseQuery` (xattrs dropped if the answer would not fit one frame).
fn base_answer(base: Option<&Base>, paths: &[Vec<u8>]) -> Message {
    let Some(b) = base else {
        return Message::BaseEntries { entries: Vec::new() };
    };
    let mut entries: Vec<BaseEntry> = paths
        .iter()
        .filter_map(|p| {
            b.get(p).map(|e| BaseEntry {
                path: p.clone(),
                meta: meta_of(e),
            })
        })
        .collect();
    let size: usize = entries.iter().map(|e| entry_size(&e.path, &e.meta)).sum();
    if size > MAX_FRAME - (64 << 10) {
        for e in &mut entries {
            e.meta.xattrs.clear();
        }
    }
    Message::BaseEntries { entries }
}

/// Unchanged is only accepted for an entry of the base with the same type and metadata.
fn same_meta(base: &TreeEntry, m: &Meta) -> bool {
    let k = tree_kind(m.kind);
    base.kind == k
        && base.mode == m.mode
        && base.uid == m.uid
        && base.gid == m.gid
        && base.mtime_ns == m.mtime_ns
        && base.link_target == m.link_target
        && (k != TreeKind::File || base.size == m.size)
}

/// Input of [`run`].
pub struct Params<'a> {
    /// Job id (`Init.job`).
    pub job: u64,
    /// Manifest kind of the source (`Init.kind`).
    pub kind: &'a str,
    /// source config (JSON) with secrets opened
    pub config: &'a str,
    /// op parameters (JSON), e.g. `{"guest": "db1"}`
    pub params: serde_json::Value,
    /// Snapshot source name to write; its latest snapshot is the base (none if damaged).
    pub source: &'a str,
    /// Limits beyond the protocol's.
    pub bounds: Bounds,
}

/// Runs one backup (one plugin process = one snapshot of `p.source`).
pub fn run(store: &Store, peer: &mut dyn Peer, p: &Params, out: &mut dyn FnMut(&str)) -> Result<Report> {
    // the source is the job's item (progress lines carry it)
    chunkstore::progress::name_item(p.source, None);
    let base = load_base(store, p.source).context("loading the base snapshot")?;
    let written = store.written();
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut r = Report {
        source: p.source.to_owned(),
        time: now.max(base.as_ref().map_or(0, |b| b.time + 1)),
        base: base.as_ref().map(|b| b.time),
        ..Default::default()
    };
    if let Some(b) = &base {
        out(&format!("base {}/{} ({} entries)", p.source, b.time, b.entries.len()));
    }
    peer.send(&Message::Init {
        api: API,
        job: p.job,
        kind: p.kind.to_owned(),
        op: Op::Backup,
        config: p.config.to_owned(),
        params: with_caps(&p.params).to_string(),
        base: base.as_ref().map(|b| BaseInfo { time: b.time }),
        state: base.as_ref().and_then(|b| b.state.clone()),
    })?;
    let mut log = LogSink {
        out,
        left: p.bounds.max_log_bytes,
        last_progress: None,
    };
    let mut entries: Vec<TreeEntry> = Vec::new();
    let mut seen: HashMap<Vec<u8>, TreeKind> = HashMap::new();
    // v1.10: item metadata by path, the base snapshot's carried over for unchanged items
    let mut item_meta: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    let base_meta = match &base {
        Some(b) => read_item_meta(store, p.source, b.time)?,
        None => BTreeMap::new(),
    };
    let mut streams: Vec<FileEntry> = Vec::new();
    let mut stream_names: HashSet<String> = HashSet::new();
    let mut touched: HashSet<ChunkId> = HashSet::new();
    let mut open = Open::Idle;
    let (state, consistent, summary) = loop {
        let m = peer.recv()?;
        match m {
            Message::Log { level, text } => log.log(level, &text),
            Message::Progress { done, total, text } => log.progress(done, total, &text),
            Message::BaseQuery { paths } => {
                if paths.iter().map(Vec::len).sum::<usize>() > p.bounds.max_query_bytes {
                    return Err(peer.violation("BaseQuery too large (> 1 MiB of paths)"));
                }
                peer.send(&base_answer(base.as_ref(), &paths))?;
            }
            Message::BaseList { after } => {
                let entries = base.as_ref().map_or_else(Vec::new, |b| b.list_page(after.as_deref()));
                peer.send(&Message::BaseEntries { entries })?;
            }
            Message::FileBegin { path, meta } => {
                if !matches!(open, Open::Idle) {
                    return Err(peer.violation("FileBegin inside another item"));
                }
                if path.split(|b| *b == b'/').next() == Some(STREAMS_DIR.as_bytes()) {
                    return Err(peer.violation(&format!("path below the reserved {STREAMS_DIR}/")));
                }
                if seen.contains_key(&path) {
                    return Err(peer.violation(&format!("path {:?} sent twice", String::from_utf8_lossy(&path))));
                }
                if entries.len() >= p.bounds.max_entries {
                    return Err(peer.violation("too many entries"));
                }
                let kind = tree_kind(meta.kind);
                match kind {
                    TreeKind::Symlink if meta.link_target.as_ref().is_none_or(std::vec::Vec::is_empty) => {
                        return Err(peer.violation("symlink without target"));
                    }
                    TreeKind::Hardlink => {
                        let ok = meta
                            .link_target
                            .as_deref()
                            .is_some_and(|t| plugin_proto::valid_path(t) && seen.get(t) == Some(&TreeKind::File));
                        if !ok {
                            return Err(peer.violation("hard link to a file that was not sent before"));
                        }
                    }
                    _ => {}
                }
                if meta.mode > 0o177777 {
                    return Err(peer.violation("invalid mode"));
                }
                open = Open::File {
                    path,
                    meta,
                    kind,
                    chunker: Chunker::new(),
                    got: 0,
                };
            }
            Message::Data { bytes } => match &mut open {
                Open::File {
                    kind: TreeKind::File,
                    meta,
                    chunker,
                    got,
                    ..
                } => {
                    *got += bytes.len() as u64;
                    if *got > meta.size {
                        return Err(peer.violation("more data than the announced file size"));
                    }
                    r.transferred += bytes.len() as u64;
                    chunker.push(store, &bytes)?;
                }
                Open::File { .. } => return Err(peer.violation("Data for an entry that is not a regular file")),
                Open::Stream { chunker, .. } => {
                    r.transferred += bytes.len() as u64;
                    chunker.push(store, &bytes)?;
                }
                Open::Idle => return Err(peer.violation("Data outside a file or stream")),
            },
            Message::FileEnd => {
                let Open::File {
                    path,
                    meta,
                    kind,
                    chunker,
                    got,
                } = std::mem::replace(&mut open, Open::Idle)
                else {
                    return Err(peer.violation("FileEnd without FileBegin"));
                };
                if kind == TreeKind::File && got != meta.size {
                    return Err(peer.violation(&format!(
                        "{:?}: {got} bytes received, {} announced",
                        String::from_utf8_lossy(&path),
                        meta.size
                    )));
                }
                let c = chunker.finish(store)?;
                r.new_bytes += c.new_bytes;
                if kind == TreeKind::File {
                    r.files += 1;
                    r.bytes += c.size;
                }
                seen.insert(path.clone(), kind.clone());
                entries.push(TreeEntry {
                    path,
                    size: if kind == TreeKind::File { c.size } else { 0 },
                    kind,
                    mode: meta.mode,
                    uid: meta.uid,
                    gid: meta.gid,
                    mtime_ns: meta.mtime_ns,
                    ctime_ns: meta.ctime_ns,
                    inode: meta.inode,
                    rdev: 0,
                    link_target: meta.link_target,
                    xattrs: meta.xattrs,
                    chunks: c.chunks,
                    inconsistent: false,
                });
            }
            Message::Unchanged { path, meta } => {
                if !matches!(open, Open::Idle) {
                    return Err(peer.violation("Unchanged inside another item"));
                }
                if seen.contains_key(&path) {
                    return Err(peer.violation("path sent twice"));
                }
                let shown = String::from_utf8_lossy(&path).into_owned();
                let Some(b) = base.as_ref().and_then(|b| b.get(&path)) else {
                    return Err(peer.violation(&format!("Unchanged {shown:?}: not in the base snapshot")));
                };
                if !same_meta(b, &meta) {
                    return Err(
                        peer.violation(&format!("Unchanged {shown:?}: metadata differs from the base snapshot"))
                    );
                }
                for c in &b.chunks {
                    // bump the chunk so a concurrent GC keeps it until this snapshot commits
                    if touched.insert(*c) && !store.touch_chunk(c)? {
                        bail!("{shown:?}: a chunk of the base snapshot is missing (run verify; the next backup should send the file again)");
                    }
                }
                if b.kind == TreeKind::File {
                    r.files += 1;
                    r.bytes += b.size;
                }
                r.unchanged += 1;
                seen.insert(path.clone(), b.kind.clone());
                if let Some(m) = base_meta.get(&shown) {
                    item_meta.insert(shown.clone(), m.clone());
                }
                let mut e = b.clone();
                e.ctime_ns = meta.ctime_ns;
                e.inode = meta.inode;
                e.xattrs = meta.xattrs;
                entries.push(e);
            }
            Message::Stream { name } => {
                if !matches!(open, Open::Idle) {
                    return Err(peer.violation("Stream inside another item"));
                }
                if !stream_names.insert(name.clone()) {
                    return Err(peer.violation(&format!("stream {name:?} sent twice")));
                }
                if streams.len() >= p.bounds.max_streams {
                    return Err(peer.violation("too many streams"));
                }
                open = Open::Stream {
                    name,
                    chunker: Chunker::new(),
                };
            }
            Message::StreamEnd => {
                let Open::Stream { name, chunker } = std::mem::replace(&mut open, Open::Idle) else {
                    return Err(peer.violation("StreamEnd without Stream"));
                };
                let c = chunker.finish(store)?;
                r.new_bytes += c.new_bytes;
                r.bytes += c.size;
                r.streams += 1;
                streams.push(FileEntry {
                    path: name,
                    mode: 0o600,
                    size: c.size,
                    mtime: r.time as i64,
                    chunks: c.chunks,
                });
            }
            Message::Warnings { count, samples } => {
                r.warnings = r.warnings.saturating_add(count);
                for x in samples {
                    if r.warning_samples.len() < plugin_proto::MAX_WARNING_SAMPLES {
                        r.warning_samples.push(x);
                    }
                }
            }
            Message::ItemMeta { path, json } => {
                if !seen.get(path.as_bytes()).is_some_and(|k| *k == TreeKind::File) {
                    return Err(peer.violation("ItemMeta for an item not written in this backup"));
                }
                let v = serde_json::from_str(&json).map_err(|_| peer.violation("ItemMeta: bad JSON"))?;
                if item_meta.insert(path, v).is_some() {
                    return Err(peer.violation("ItemMeta sent twice for one item"));
                }
            }
            Message::SnapshotMeta { json } => {
                if r.meta.is_some() {
                    return Err(peer.violation("SnapshotMeta sent twice"));
                }
                r.meta = Some(serde_json::from_str(&json).map_err(|_| peer.violation("SnapshotMeta: bad JSON"))?);
            }
            Message::Done {
                state,
                consistent,
                summary,
            } => {
                if !matches!(open, Open::Idle) {
                    return Err(peer.violation("Done inside an item"));
                }
                break (state, consistent, summary);
            }
            Message::Error { code, message } => {
                peer.finish();
                bail!("plugin reported an error ({code}): {}", escape(&message, 2000));
            }
            other => return Err(peer.violation(&format!("unexpected message {}", msg_name(&other)))),
        }
    };
    peer.finish();
    r.entries = entries.len() as u64;
    r.consistent = consistent;
    r.summary = summary;
    let mut idx = vec![(FILES_INDEX, Index::Tree { entries })];
    if !streams.is_empty() {
        idx.push((STREAMS_INDEX, Index::Dynamic { entries: streams }));
    }
    if let Some(s) = state {
        let st = store.store_file_stats(&s[..])?;
        idx.push((
            STATE_INDEX,
            Index::Dynamic {
                entries: vec![FileEntry {
                    path: "state".into(),
                    mode: 0o600,
                    size: st.size,
                    mtime: r.time as i64,
                    chunks: st.chunks,
                }],
            },
        ));
    }
    let m = store.commit_snapshot(p.source, r.time, &idx)?;
    if !item_meta.is_empty() {
        // ponytail: one JSON object for the whole snapshot (about 0.5 KiB per mail); split it when mailboxes
        // with millions of items make it slow to read
        let data = serde_json::to_vec(&item_meta)?;
        store
            .write_snap_file(p.source, r.time, plugin_proto::ITEM_META_FILE, &data)
            .context("writing the item metadata")?;
    }
    let id = format!("{}/{}", r.source, r.time);
    log.left = usize::MAX;
    (log.out)(&format!(
        "committed {id} {} entries ({} files, {} unchanged), {} streams, {} bytes, {} bytes transferred, {} bytes new, consistent={}",
        r.entries, r.files, r.unchanged, r.streams, r.bytes, r.transferred, r.new_bytes, r.consistent
    ));
    (log.out)(&store.stats_line(&m, r.transferred, store.written().since(written))?);
    if let Some(h) = store.take_hash_stats() {
        (log.out)(&h.to_string());
    }
    if !r.consistent {
        (log.out)(&format!(
            "inconsistent {id}: the plugin reported no consistent view ({})",
            escape(&r.summary, 500)
        ));
    }
    if r.warnings > 0 {
        // `warnings <id>: <n> …` is parsed by the scheduler (job result `warnings`)
        (log.out)(&format!(
            "warnings {id}: {} items could not be read and are missing from the snapshot: {}",
            r.warnings,
            escape(&r.warning_samples.join("; "), 4000)
        ));
    }
    if !r.summary.is_empty() {
        (log.out)(&format!("summary {id}: {}", escape(&r.summary, 4000)));
    }
    Ok(r)
}

pub(crate) fn msg_name(m: &Message) -> &'static str {
    match m {
        Message::Init { .. } => "Init",
        Message::Valid => "Valid",
        Message::Invalid { .. } => "Invalid",
        Message::Guests { .. } => "Guests",
        Message::FileBegin { .. } => "FileBegin",
        Message::Data { .. } => "Data",
        Message::FileEnd => "FileEnd",
        Message::Unchanged { .. } => "Unchanged",
        Message::Stream { .. } => "Stream",
        Message::StreamEnd => "StreamEnd",
        Message::Done { .. } => "Done",
        Message::BaseQuery { .. } => "BaseQuery",
        Message::BaseEntries { .. } => "BaseEntries",
        Message::NeedFiles { .. } => "NeedFiles",
        Message::NeedStreams { .. } => "NeedStreams",
        Message::NeedDone => "NeedDone",
        Message::Progress { .. } => "Progress",
        Message::MountReady { .. } => "MountReady",
        Message::ReadFile { .. } => "ReadFile",
        Message::FileData { .. } => "FileData",
        Message::Unmount => "Unmount",
        Message::Log { .. } => "Log",
        Message::Error { .. } => "Error",
        Message::BaseList { .. } => "BaseList",
        Message::TaggedGuests { .. } => "TaggedGuests",
        Message::Warnings { .. } => "Warnings",
        Message::SnapshotMeta { .. } => "SnapshotMeta",
        Message::Output { .. } => "Output",
        Message::ItemMeta { .. } => "ItemMeta",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chunkstore::{Keyring, Options};

    #[test]
    fn plugin_progress_is_a_machine_line() {
        let (_, lines) = chunkstore::progress::capture(|| {
            chunkstore::progress::name_item("plugin-1-db", None);
            progress_line(5, 10, "dumping db").print();
            progress_line(7, 0, "").print();
        });
        assert_eq!(lines[1].item.as_deref(), Some("plugin-1-db"));
        assert_eq!(
            (lines[1].part.as_deref(), lines[1].done, lines[1].total),
            (Some("dumping db"), Some(5), Some(10))
        );
        assert_eq!(
            (lines[2].part.as_deref(), lines[2].total),
            (None, None),
            "no text, unknown total"
        );
        let wire = lines[1].render();
        assert!(chunkstore::progress::Line::parse(wire.trim_end()).is_some(), "{wire}");
    }

    #[test]
    fn push_chunker_matches_store_file() {
        let d = tempfile::tempdir().unwrap();
        let store = Store::open(d.path(), Keyring::new("t", &[(1, [7; 32])]), Options::default()).unwrap();
        let mut data = vec![0u8; 9 << 20];
        let mut x = 1u64;
        for b in data.iter_mut() {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *b = (x >> 33) as u8;
        }
        let (want, size) = store.store_file(&data[..]).unwrap();
        let mut c = Chunker::new();
        for piece in data.chunks(777_777) {
            c.push(&store, piece).unwrap();
        }
        let c = c.finish(&store).unwrap();
        assert_eq!((c.chunks, c.size), (want, size));
        let empty = Chunker::new().finish(&store).unwrap();
        assert!(empty.chunks.is_empty() && empty.size == 0);
    }
}
