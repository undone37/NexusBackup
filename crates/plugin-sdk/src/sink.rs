//! Backup side: sending files, `Unchanged` decisions and application streams.

use crate::meta::meta_of;
use crate::{Result, Shared};
use anyhow::{anyhow, bail};
use plugin_proto::{BaseEntry, Kind, Message, Meta, MAX_DATA};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Paths per `BaseQuery` (and at most 512 KiB of path bytes; the host allows 1 MiB).
const QUERY_PATHS: usize = 1000;
const QUERY_BYTES: usize = 512 << 10;

pub struct Sink {
    chan: Shared,
    has_base: bool,
    /// files whose size changed while read (the backup is reported not consistent)
    pub inconsistent: u64,
}

fn send(chan: &Shared, m: &Message) -> Result<()> {
    chan.borrow_mut().send(m).map_err(|e| anyhow!("host connection: {e}"))
}

impl Sink {
    pub(crate) fn new(chan: Shared, has_base: bool) -> Sink {
        Sink {
            chan,
            has_base,
            inconsistent: 0,
        }
    }

    /// Is there a previous snapshot (Unchanged / base queries make sense)?
    pub fn has_base(&self) -> bool {
        self.has_base
    }

    /// A regular file: exactly `meta.size` bytes are read from `data`. A shorter
    /// read is padded with zeros, a longer one cut; either marks the backup not consistent.
    pub fn file(&mut self, path: &[u8], meta: Meta, data: &mut dyn Read) -> Result<()> {
        let size = meta.size;
        send(
            &self.chan,
            &Message::FileBegin {
                path: path.to_vec(),
                meta: Meta {
                    kind: Some(Kind::File),
                    ..meta
                },
            },
        )?;
        let mut left = size;
        let mut buf = vec![0u8; MAX_DATA.min(1 << 20)];
        let mut short = false;
        while left > 0 {
            let want = (left as usize).min(buf.len());
            let n = if short { 0 } else { data.read(&mut buf[..want])? };
            if n == 0 {
                short = true;
                buf[..want].fill(0);
                send(
                    &self.chan,
                    &Message::Data {
                        bytes: buf[..want].to_vec(),
                    },
                )?;
                left -= want as u64;
                continue;
            }
            send(
                &self.chan,
                &Message::Data {
                    bytes: buf[..n].to_vec(),
                },
            )?;
            left -= n as u64;
        }
        let grew = !short && data.read(&mut [0u8; 1])? > 0;
        if short || grew {
            self.inconsistent += 1;
        }
        send(&self.chan, &Message::FileEnd)
    }

    /// Anything that is not a regular file (directory, symlink, fifo, hard link …).
    pub fn entry(&mut self, path: &[u8], meta: Meta) -> Result<()> {
        if meta.kind.unwrap_or(Kind::File) == Kind::File {
            bail!("entry() is for non-regular files; use file()");
        }
        send(
            &self.chan,
            &Message::FileBegin {
                path: path.to_vec(),
                meta,
            },
        )?;
        send(&self.chan, &Message::FileEnd)
    }

    /// The file is the same as in the base snapshot (the host checks the metadata
    /// and reuses its stored data; a wrong claim fails the backup).
    pub fn unchanged(&mut self, path: &[u8], meta: Meta) -> Result<()> {
        send(
            &self.chan,
            &Message::Unchanged {
                path: path.to_vec(),
                meta,
            },
        )
    }

    /// v1.6: metadata the appliance keeps with this snapshot in its catalog (a JSON
    /// object ≤ 16 KiB, at most once per backup; needs a v1.6 host).
    pub fn snapshot_meta(&mut self, meta: &serde_json::Value) -> Result<()> {
        if !meta.is_object() {
            bail!("snapshot metadata must be a JSON object");
        }
        send(&self.chan, &Message::SnapshotMeta { json: meta.to_string() })
    }

    /// Metadata of these paths in the base snapshot (missing paths are omitted).
    pub fn base(&mut self, paths: &[Vec<u8>]) -> Result<Vec<BaseEntry>> {
        if !self.has_base || paths.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let mut start = 0;
        while start < paths.len() {
            let mut end = start;
            let mut bytes = 0;
            while end < paths.len() && end - start < QUERY_PATHS && bytes + paths[end].len() <= QUERY_BYTES {
                bytes += paths[end].len();
                end += 1;
            }
            end = end.max(start + 1);
            send(
                &self.chan,
                &Message::BaseQuery {
                    paths: paths[start..end].to_vec(),
                },
            )?;
            let m = self.chan.borrow_mut().recv()?;
            match m {
                Message::BaseEntries { entries } => out.extend(entries),
                m => bail!("unexpected host message {m:?} (expected BaseEntries)"),
            }
            start = end;
        }
        Ok(out)
    }

    /// Every entry of the base snapshot in path order, with full metadata (paged by
    /// the host; contract v1.3). For plugins that rebuild their previous view of the
    /// source from the base (e.g. item ids kept in xattrs) instead of the state blob.
    pub fn base_list(&mut self) -> Result<Vec<BaseEntry>> {
        let mut out: Vec<BaseEntry> = Vec::new();
        if !self.has_base {
            return Ok(out);
        }
        loop {
            send(
                &self.chan,
                &Message::BaseList {
                    after: out.last().map(|e| e.path.clone()),
                },
            )?;
            let m = self.chan.borrow_mut().recv()?;
            match m {
                Message::BaseEntries { entries } if entries.is_empty() => return Ok(out),
                Message::BaseEntries { entries } => out.extend(entries),
                m => bail!("unexpected host message {m:?} (expected BaseEntries)"),
            }
        }
    }

    /// An application stream (dump, WAL segment, …); write to it, then `finish()`.
    pub fn stream(&mut self, name: &str) -> Result<StreamWriter> {
        if !plugin_proto::valid_stream_name(name) {
            bail!("invalid stream name {name:?}");
        }
        send(&self.chan, &Message::Stream { name: name.into() })?;
        Ok(StreamWriter {
            chan: self.chan.clone(),
            buf: Vec::with_capacity(1 << 20),
            done: false,
        })
    }

    /// Backs up a local directory tree below `root` (paths relative to it). Regular
    /// files whose base entry has the same type, size, mtime, ctime, inode, mode and
    /// owner are sent as `Unchanged`; hard links as links to their first path.
    pub fn walk_dir(&mut self, root: &Path, opts: &WalkOptions) -> Result<WalkStats> {
        let mut st = WalkStats::default();
        let mut links: HashMap<(u64, u64), Vec<u8>> = HashMap::new();
        self.walk(root, &[], opts, &mut st, &mut links)?;
        Ok(st)
    }

    fn walk(
        &mut self,
        dir: &Path,
        rel: &[u8],
        opts: &WalkOptions,
        st: &mut WalkStats,
        links: &mut HashMap<(u64, u64), Vec<u8>>,
    ) -> Result<()> {
        let mut names: Vec<_> = match fs::read_dir(dir) {
            Ok(rd) => rd.filter_map(|e| e.ok().map(|e| e.file_name())).collect(),
            Err(e) => {
                st.error(dir, &e);
                return Err(anyhow!("{}: {e}", dir.display()));
            }
        };
        names.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        let mut children = Vec::new();
        for name in names {
            let mut p = rel.to_vec();
            if !p.is_empty() {
                p.push(b'/');
            }
            p.extend_from_slice(name.as_bytes());
            if opts.excluded(&p, name.as_bytes()) {
                st.excluded += 1;
                continue;
            }
            let full = dir.join(&name);
            match fs::symlink_metadata(&full) {
                Ok(m) => children.push((p, full, m)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => st.vanished += 1,
                Err(e) => st.error(&full, &e),
            }
        }
        let base: HashMap<Vec<u8>, Meta> = if self.has_base {
            let files: Vec<Vec<u8>> = children
                .iter()
                .filter(|(_, _, m)| m.is_file())
                .map(|(p, _, _)| p.clone())
                .collect();
            self.base(&files)?.into_iter().map(|b| (b.path, b.meta)).collect()
        } else {
            HashMap::new()
        };
        for (p, full, m) in children {
            let meta = match meta_of(&full, &m, opts.xattrs) {
                Ok(x) => x,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    st.vanished += 1;
                    continue;
                }
                Err(e) => {
                    st.error(&full, &e);
                    continue;
                }
            };
            match meta.kind {
                Some(Kind::File) => {
                    if m.nlink() > 1 {
                        if let Some(first) = links.get(&(m.dev(), m.ino())) {
                            let mut l = meta.clone();
                            l.kind = Some(Kind::Hardlink);
                            l.size = 0;
                            l.link_target = Some(first.clone());
                            self.entry(&p, l)?;
                            st.entries += 1;
                            continue;
                        }
                        links.insert((m.dev(), m.ino()), p.clone());
                    }
                    let same = base.get(&p).is_some_and(|b| {
                        b.kind == meta.kind
                            && b.size == meta.size
                            && b.mtime_ns == meta.mtime_ns
                            && b.ctime_ns == meta.ctime_ns
                            && b.inode == meta.inode
                            && b.mode == meta.mode
                            && b.uid == meta.uid
                            && b.gid == meta.gid
                    });
                    if same {
                        self.unchanged(&p, meta.clone())?;
                        st.unchanged += 1;
                        st.bytes += meta.size;
                    } else {
                        match fs::File::open(&full) {
                            Ok(mut f) => {
                                st.bytes += meta.size;
                                st.read_bytes += meta.size;
                                self.file(&p, meta, &mut f)?;
                                st.files_read += 1;
                            }
                            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                                st.vanished += 1;
                                continue;
                            }
                            Err(e) => {
                                st.error(&full, &e);
                                continue;
                            }
                        }
                    }
                    st.files += 1;
                }
                Some(Kind::Dir) => {
                    self.entry(&p, meta)?;
                    st.dirs += 1;
                    self.walk(&full, &p, opts, st, links)?;
                }
                _ => {
                    self.entry(&p, meta)?;
                }
            }
            st.entries += 1;
        }
        Ok(())
    }
}

/// Options of [`Sink::walk_dir`].
#[derive(Clone, Debug, Default)]
pub struct WalkOptions {
    /// glob patterns (`*`, `?`); with a `/` they match the relative path, else the name
    pub excludes: Vec<String>,
    pub xattrs: bool,
}

impl WalkOptions {
    fn excluded(&self, rel: &[u8], name: &[u8]) -> bool {
        self.excludes.iter().any(|pat| {
            let s = if pat.contains('/') { rel } else { name };
            glob(pat.trim_start_matches('/').as_bytes(), s)
        })
    }
}

/// `*` matches any run (also `/`), `?` one byte.
pub fn glob(p: &[u8], s: &[u8]) -> bool {
    let (mut pi, mut si, mut star, mut mark) = (0, 0, None, 0);
    while si < s.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            pi += 1;
            mark = si;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

#[derive(Debug, Default, Clone)]
pub struct WalkStats {
    pub entries: u64,
    pub files: u64,
    pub dirs: u64,
    pub unchanged: u64,
    pub files_read: u64,
    pub bytes: u64,
    pub read_bytes: u64,
    pub excluded: u64,
    pub vanished: u64,
    pub errors: u64,
    /// the first 20 errors (`path: error`), for the job log
    pub messages: Vec<String>,
}

impl WalkStats {
    fn error(&mut self, path: &Path, e: &io::Error) {
        self.errors += 1;
        if self.errors <= 20 {
            self.messages.push(format!("{}: {e}", path.display()));
        }
    }
}

/// Bounded buffer (1 MiB) in front of `Data` frames; `finish()` sends `StreamEnd`.
pub struct StreamWriter {
    chan: Shared,
    buf: Vec<u8>,
    done: bool,
}

impl StreamWriter {
    fn flush_buf(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            let bytes = std::mem::take(&mut self.buf);
            self.chan.borrow_mut().send(&Message::Data { bytes })?;
            self.buf.reserve(1 << 20);
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<()> {
        self.flush_buf()?;
        self.done = true;
        send(&self.chan, &Message::StreamEnd)
    }
}

impl Write for StreamWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let n = data.len().min((1 << 20) - self.buf.len());
        self.buf.extend_from_slice(&data[..n]);
        if self.buf.len() >= 1 << 20 {
            self.flush_buf()?;
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flush_buf()
    }
}

impl Drop for StreamWriter {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.flush_buf();
            let _ = self.chan.borrow_mut().send(&Message::StreamEnd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::glob;

    #[test]
    fn globbing() {
        assert!(glob(b"*.tmp", b"a.tmp"));
        assert!(!glob(b"*.tmp", b"a.tmpx"));
        assert!(glob(b"cache/*", b"cache/x/y"));
        assert!(glob(b"a?c", b"abc"));
        assert!(glob(b"*", b""));
        assert!(!glob(b"x", b""));
    }
}
