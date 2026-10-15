//! Export op (contract v1.9): the generic download with plugin-side conversion
//! (e.g. Microsoft 365 mail as mbox or PST). The plugin pages through the selected
//! entries (`BaseList` → `BaseEntries`), reads files (`ReadFile` → `FileData`) and
//! writes the download's files with `Output { name, offset, bytes }`; the host writes
//! them below a private staging directory (relative names only, no links, bounded
//! count and size) and, after `Done`, packs them as the download's tar or zip
//! ([`pack`]), removing each staged file once packed. Disk use: the staged files
//! plus the archive, at most the export size plus its largest file at the end.

use crate::backup::{entry_size, msg_name, LogSink};
use crate::ops::Reader;
use crate::restore::Snapshot;
use crate::sandbox::Peer;
use crate::{escape, meta_of};
use anyhow::{bail, Context, Result};
use chunkstore::{Store, TreeEntry, TreeKind};
use plugin_proto::{BaseEntry, BaseInfo, Message, Op, API, MAX_BATCH, MAX_DATA, MAX_FRAME};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// Input of [`run`].
pub struct Params<'a> {
    /// Job id (`Init.job`).
    pub job: u64,
    /// Manifest kind of the source (`Init.kind`).
    pub kind: &'a str,
    /// Source config as JSON text; the scheduler passes `{}` (no secrets for an export).
    pub config: &'a str,
    /// the user's export parameters (validated against the `download` params_schema)
    pub params: Value,
    /// selected snapshot paths (`/` or empty = everything)
    pub paths: &'a [String],
    /// Most output files the plugin may create.
    pub max_files: usize,
    /// Most bytes of all output files together.
    pub max_bytes: u64,
}

/// Outcome of one export (before packing).
#[derive(Debug, Default)]
pub struct Report {
    /// Output files staged.
    pub files: usize,
    /// Bytes of all staged output files.
    pub bytes: u64,
    /// `Done.summary` of the plugin, escaped.
    pub summary: String,
}

/// The selected entries (path order, no duplicates).
pub fn select<'a>(snap: &'a Snapshot, paths: &[String]) -> Vec<&'a TreeEntry> {
    let mut sel: BTreeMap<&[u8], &TreeEntry> = BTreeMap::new();
    for p in paths {
        let p = p.trim_matches('/');
        if p.is_empty() {
            return snap.files.iter().collect();
        }
        for e in snap.subtree(p.as_bytes()) {
            sel.insert(&e.path, e);
        }
    }
    sel.into_values().collect()
}

/// Sequential reads of one file at a time (the usual export pattern) without the
/// random-access reader's offset scan; anything else falls back to it.
struct Seq<'a> {
    store: &'a Store,
    path: Vec<u8>,
    next: u64,
    idx: usize,
    chunk: Vec<u8>,
    at: usize,
    random: Reader<'a>,
}

impl Seq<'_> {
    fn read(&mut self, e: &TreeEntry, off: u64, len: u32) -> Result<Vec<u8>> {
        if off == 0 && (self.path != e.path || self.next != 0) {
            self.path = e.path.clone();
            (self.next, self.idx, self.at) = (0, 0, 0);
            self.chunk.clear();
        }
        if self.path != e.path || self.next != off {
            return self.random.read(e, off, len);
        }
        let mut out = Vec::with_capacity(len as usize);
        while out.len() < len as usize {
            if self.at == self.chunk.len() {
                let Some(c) = e.chunks.get(self.idx) else { break };
                self.chunk = self.store.read_chunk(c)?;
                self.idx += 1;
                self.at = 0;
                continue;
            }
            let n = (len as usize - out.len()).min(self.chunk.len() - self.at);
            out.extend_from_slice(&self.chunk[self.at..self.at + n]);
            self.at += n;
        }
        self.next += out.len() as u64;
        Ok(out)
    }
}

/// Staged output files (bounded number open at once).
struct Staging<'a> {
    dir: &'a Path,
    open: HashMap<String, File>,
    sizes: HashMap<String, u64>,
    bytes: u64,
    max_files: usize,
    max_bytes: u64,
}

impl Staging<'_> {
    fn write(&mut self, name: &str, offset: u64, bytes: &[u8]) -> Result<()> {
        let end = offset + bytes.len() as u64;
        let old = self.sizes.get(name).copied();
        if old.is_none() && self.sizes.len() >= self.max_files {
            bail!("the export has more than {} files", self.max_files);
        }
        let grow = end.saturating_sub(old.unwrap_or(0));
        if self.bytes + grow > self.max_bytes {
            bail!("the export is larger than {} bytes", self.max_bytes);
        }
        if !self.open.contains_key(name) {
            if self.open.len() >= 64 {
                self.open.clear();
            }
            let path = self.dir.join(name);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).with_context(|| format!("output {name:?}"))?;
            }
            let f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)
                .with_context(|| format!("output {name:?}"))?;
            if !f.metadata()?.is_file() {
                bail!("output {name:?} is not a file");
            }
            self.open.insert(name.to_owned(), f);
        }
        self.open[name].write_all_at(bytes, offset)?;
        self.sizes.insert(name.to_owned(), old.unwrap_or(0).max(end));
        self.bytes += grow;
        Ok(())
    }
}

/// Runs the export; the staged files end up in `dir` (created, must not exist;
/// removed again on failure).
pub fn run(
    store: &Store,
    peer: &mut dyn Peer,
    snap: &Snapshot,
    p: &Params,
    dir: &Path,
    out: &mut dyn FnMut(&str),
) -> Result<Report> {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("staging dir {}", dir.display()))?;
    let r = staged_run(store, peer, snap, p, dir, out);
    if r.is_err() {
        let _ = fs::remove_dir_all(dir);
    }
    r
}

fn staged_run(
    store: &Store,
    peer: &mut dyn Peer,
    snap: &Snapshot,
    p: &Params,
    dir: &Path,
    out: &mut dyn FnMut(&str),
) -> Result<Report> {
    let sel = select(snap, p.paths);
    let by_path: HashMap<&[u8], &TreeEntry> = sel.iter().map(|e| (e.path.as_slice(), *e)).collect();
    let mut params = snap.init_params(json!({"params": p.params, "paths": p.paths}));
    params["files"] = json!(sel.len());
    peer.send(&Message::Init {
        api: API,
        job: p.job,
        kind: p.kind.to_owned(),
        op: Op::Export,
        config: p.config.to_owned(),
        params: params.to_string(),
        base: Some(BaseInfo { time: snap.time }),
        state: snap.state.clone(),
    })?;
    let mut log = LogSink {
        out,
        left: 4 << 20,
        last_progress: None,
    };
    let mut seq = Seq {
        store,
        path: Vec::new(),
        next: 0,
        idx: 0,
        chunk: Vec::new(),
        at: 0,
        random: Reader::new(store),
    };
    let mut st = Staging {
        dir,
        open: HashMap::new(),
        sizes: HashMap::new(),
        bytes: 0,
        max_files: p.max_files,
        max_bytes: p.max_bytes,
    };
    loop {
        match peer.recv()? {
            Message::Log { level, text } => log.log(level, &text),
            Message::Progress { done, total, text } => log.progress(done, total, &text),
            Message::BaseList { after } => {
                let start = after.map_or(0, |a| sel.partition_point(|e| e.path <= a));
                let mut page = Vec::new();
                let mut bytes = 0;
                for e in &sel[start..] {
                    let meta = meta_of(e);
                    let size = entry_size(&e.path, &meta);
                    if page.len() >= MAX_BATCH || (!page.is_empty() && bytes + size > MAX_FRAME - (64 << 10)) {
                        break;
                    }
                    bytes += size;
                    page.push(BaseEntry {
                        path: e.path.clone(),
                        meta,
                    });
                }
                peer.send(&Message::BaseEntries { entries: page })?;
            }
            Message::ReadFile { path, offset, len } => {
                match by_path.get(path.as_slice()).filter(|e| e.kind == TreeKind::File) {
                    Some(e) => {
                        let data = seq.read(e, offset, len.min(MAX_DATA as u32))?;
                        peer.send(&Message::FileData { bytes: data })?;
                    }
                    None => peer.send(&Message::Error {
                        code: 2,
                        message: "no such file in the selection".into(),
                    })?,
                }
            }
            Message::Output { name, offset, bytes } => {
                if let Err(e) = st.write(&name, offset, &bytes) {
                    peer.finish();
                    return Err(e);
                }
            }
            Message::Done { summary, .. } => {
                peer.finish();
                return Ok(Report {
                    files: st.sizes.len(),
                    bytes: st.bytes,
                    summary: escape(&summary, 4000),
                });
            }
            Message::Error { code, message } => {
                peer.finish();
                bail!("plugin reported an error ({code}): {}", escape(&message, 2000));
            }
            other => return Err(peer.violation(&format!("unexpected message {} during export", msg_name(&other)))),
        }
    }
}

/// Staged files below `dir` (relative names, sorted).
fn staged(dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut out = Vec::new();
    let mut stack = vec![PathBuf::new()];
    while let Some(rel) = stack.pop() {
        for e in fs::read_dir(dir.join(&rel))? {
            let e = e?;
            let r = rel.join(e.file_name());
            let t = e.file_type()?;
            if t.is_dir() {
                stack.push(r);
            } else if t.is_file() {
                out.push((r.to_string_lossy().into_owned(), e.path()));
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Packs the staged files of `dir` into `out` (tar or zip, by extension) and removes
/// `dir`. Returns the number of files.
pub fn pack(dir: &Path, out: &Path) -> Result<usize> {
    let r = pack_files(dir, out);
    let _ = fs::remove_dir_all(dir);
    if r.is_err() {
        let _ = fs::remove_file(out);
    }
    r
}

fn pack_files(dir: &Path, out: &Path) -> Result<usize> {
    let files = staged(dir)?;
    let f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o640)
        .open(out)
        .with_context(|| format!("{}", out.display()))?;
    match agent_conn::files::Format::from_path(out)? {
        agent_conn::files::Format::Tar => {
            let mut b = tar::Builder::new(io::BufWriter::new(f));
            b.mode(tar::HeaderMode::Deterministic);
            for (name, path) in &files {
                let mut src = File::open(path)?;
                let mut h = tar::Header::new_gnu();
                h.set_size(src.metadata()?.len());
                h.set_mode(0o644);
                h.set_mtime(now());
                h.set_entry_type(tar::EntryType::Regular);
                b.append_data(&mut h, name, &mut src)?;
                fs::remove_file(path)?;
            }
            b.into_inner()?
                .into_inner()
                .map_err(std::io::IntoInnerError::into_error)?
                .sync_all()?;
        }
        agent_conn::files::Format::Zip => {
            let mut z = zip::ZipWriter::new(f);
            for (name, path) in &files {
                let mut src = File::open(path)?;
                let len = src.metadata()?.len();
                let opts = zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated)
                    .unix_permissions(0o644)
                    .large_file(len >= u32::MAX as u64);
                z.start_file(name.as_str(), opts)?;
                io::copy(&mut src, &mut z)?;
                fs::remove_file(path)?;
            }
            z.finish()?.sync_all()?;
        }
    }
    Ok(files.len())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staging_bounds_and_pack() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("x.d");
        fs::create_dir(&dir).unwrap();
        let mut st = Staging {
            dir: &dir,
            open: HashMap::new(),
            sizes: HashMap::new(),
            bytes: 0,
            max_files: 3,
            max_bytes: 100,
        };
        st.write("a/one.mbox", 0, b"hello").unwrap();
        st.write("a/one.mbox", 0, b"J").unwrap(); // rewrite: no growth
        st.write("b.pst", 10, b"tail").unwrap();
        assert_eq!(st.bytes, 5 + 14);
        assert!(st.write("a", 0, b"x").is_err(), "a is a directory");
        st.write("c", 0, b"").unwrap(); // an empty file
        assert!(st.write("d", 0, b"x").is_err(), "file limit");
        assert!(st.write("b.pst", 90, b"0123456789").is_err(), "size limit");
        drop(st);
        let out = d.path().join("x.tar");
        assert_eq!(pack(&dir, &out).unwrap(), 3);
        assert!(!dir.exists());
        let mut a = tar::Archive::new(File::open(&out).unwrap());
        let mut got: Vec<(String, Vec<u8>)> = a
            .entries()
            .unwrap()
            .map(|e| {
                let mut e = e.unwrap();
                let mut b = Vec::new();
                io::Read::read_to_end(&mut e, &mut b).unwrap();
                (e.path().unwrap().to_string_lossy().into_owned(), b)
            })
            .collect();
        got.sort();
        assert_eq!(got[0], ("a/one.mbox".into(), b"Jello".to_vec()));
        assert_eq!(got[1].1, b"\0\0\0\0\0\0\0\0\0\0tail");
    }
}
