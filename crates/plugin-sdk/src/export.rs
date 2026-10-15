//! Export op (contract v1.9): the generic download with plugin-side conversion. The
//! host lists the selected part of the snapshot (`BaseList`), serves reads
//! (`ReadFile`) and writes what the plugin sends as `Output` into the download,
//! which it packs as tar/zip after `Done`. Request/answer only, so the plugin may
//! write output between any two reads.
//!
//! ```no_run
//! use plugin_sdk::{Ctx, Export, Result};
//! use std::io::Write;
//!
//! // Body of `Plugin::export`: one `.txt` per selected regular file.
//! fn export(_ctx: &Ctx, ex: &mut Export) -> Result<String> {
//!     let mut files = Vec::new();
//!     ex.list(|e| {
//!         if e.meta.kind == Some(plugin_sdk::Kind::File) {
//!             files.push(e.path);
//!         }
//!         Ok(())
//!     })?;
//!     for path in &files {
//!         let data = ex.read_all(path, 64 << 20)?;
//!         let mut out = ex.output(&format!("{}.txt", String::from_utf8_lossy(path)))?;
//!         out.write_all(&data)?;
//!         out.finish()?;
//!     }
//!     Ok(format!("{} files", files.len()))
//! }
//! ```

use crate::{Result, Shared};
use anyhow::{anyhow, bail};
use plugin_proto::{BaseEntry, Message, MAX_DATA, MAX_OUTPUT_FILE};
use std::io::{self, Read, Seek, SeekFrom, Write};

/// The host side of an export, passed to [`crate::Plugin::export`]. The plugin
/// runs without network and without the source's credentials (`ctx.config` is `{}`).
pub struct Export {
    chan: Shared,
}

impl Export {
    pub(crate) fn new(chan: Shared) -> Export {
        Export { chan }
    }

    /// The selected snapshot entries (files, directories, …) in path order, page by page.
    pub fn list(&mut self, mut f: impl FnMut(BaseEntry) -> Result<()>) -> Result<()> {
        let mut after: Option<Vec<u8>> = None;
        loop {
            self.chan
                .borrow_mut()
                .send(&Message::BaseList { after: after.take() })?;
            let entries = match self.chan.borrow_mut().recv()? {
                Message::BaseEntries { entries } => entries,
                m => bail!("unexpected host message {m:?} (expected BaseEntries)"),
            };
            let Some(last) = entries.last() else {
                return Ok(());
            };
            after = Some(last.path.clone());
            for e in entries {
                f(e)?;
            }
        }
    }

    /// Up to `len` (≤ 4 MiB) bytes at `offset` of a snapshot file; None if it is not
    /// a selected file. Fewer bytes only at the end of the file.
    pub fn read_file(&mut self, path: &[u8], offset: u64, len: u32) -> Result<Option<Vec<u8>>> {
        self.chan.borrow_mut().send(&Message::ReadFile {
            path: path.to_vec(),
            offset,
            len: len.min(MAX_DATA as u32),
        })?;
        match self.chan.borrow_mut().recv()? {
            Message::FileData { bytes } => Ok(Some(bytes)),
            Message::Error { .. } => Ok(None),
            m => bail!("unexpected host message {m:?}"),
        }
    }

    /// A whole snapshot file (at most `max` bytes, else an error).
    pub fn read_all(&mut self, path: &[u8], max: u64) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.reader(path).take(max + 1).read_to_end(&mut out)?;
        if out.len() as u64 > max {
            bail!("{} is larger than {max} bytes", String::from_utf8_lossy(path));
        }
        Ok(out)
    }

    /// Sequential reader over a snapshot file (4 MiB reads).
    pub fn reader<'a>(&'a mut self, path: &[u8]) -> FileReader<'a> {
        FileReader {
            ex: self,
            path: path.to_vec(),
            pos: 0,
            buf: Vec::new(),
            at: 0,
            end: false,
        }
    }

    /// An output file of the download (a relative path, created on first write).
    /// Writes are buffered; seeking back is allowed. Call [`Output::finish`].
    pub fn output(&self, name: &str) -> Result<Output> {
        if !plugin_proto::valid_path(name.as_bytes()) || name.split('/').next() == Some(plugin_proto::STREAMS_DIR) {
            bail!("invalid output name {name:?}");
        }
        Ok(Output {
            chan: self.chan.clone(),
            name: name.into(),
            start: 0,
            buf: Vec::with_capacity(1 << 20),
            pos: 0,
        })
    }

    /// Progress for the job page, as [`crate::Ctx::progress`]. Send errors are ignored.
    pub fn progress(&self, done: u64, total: u64, text: &str) {
        let _ = self.chan.borrow_mut().send(&Message::Progress {
            done,
            total,
            text: text.into(),
        });
    }
}

/// [`Read`] over one snapshot file, from [`Export::reader`]. A path that is not a
/// selected regular file fails the first read with `NotFound`.
pub struct FileReader<'a> {
    ex: &'a mut Export,
    path: Vec<u8>,
    pos: u64,
    buf: Vec<u8>,
    at: usize,
    end: bool,
}

impl Read for FileReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.at == self.buf.len() {
            if self.end {
                return Ok(0);
            }
            let b = self
                .ex
                .read_file(&self.path, self.pos, MAX_DATA as u32)
                .map_err(io::Error::other)?
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such file in the snapshot"))?;
            self.end = b.len() < MAX_DATA;
            self.pos += b.len() as u64;
            self.buf = b;
            self.at = 0;
            if self.buf.is_empty() {
                return Ok(0);
            }
        }
        let n = out.len().min(self.buf.len() - self.at);
        out[..n].copy_from_slice(&self.buf[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

/// One output file: buffered writes sent as `Output` frames (≤ 4 MiB).
/// `SeekFrom::End` is not supported; a file may grow to 64 GiB. Dropping it without
/// [`Output::finish`] loses what is still buffered (up to 4 MiB).
pub struct Output {
    chan: Shared,
    name: String,
    /// file offset of `buf[0]`
    start: u64,
    buf: Vec<u8>,
    /// current position
    pos: u64,
}

impl Output {
    fn send(&mut self) -> io::Result<()> {
        for piece in self.buf.chunks(MAX_DATA) {
            self.chan
                .borrow_mut()
                .send(&Message::Output {
                    name: self.name.clone(),
                    offset: self.start,
                    bytes: piece.to_vec(),
                })
                .map_err(|e| io::Error::other(anyhow!("host connection: {e}")))?;
            self.start += piece.len() as u64;
        }
        self.buf.clear();
        self.start = self.pos;
        Ok(())
    }

    /// Sends what is buffered (also an empty file: one empty write creates it).
    pub fn finish(mut self) -> Result<()> {
        if self.buf.is_empty() && self.pos == 0 {
            self.chan.borrow_mut().send(&Message::Output {
                name: self.name.clone(),
                offset: 0,
                bytes: Vec::new(),
            })?;
            return Ok(());
        }
        self.send()?;
        Ok(())
    }
}

impl Write for Output {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.pos + data.len() as u64 > MAX_OUTPUT_FILE {
            return Err(io::Error::other("output file larger than 64 GiB"));
        }
        if self.start + self.buf.len() as u64 != self.pos {
            self.send()?;
        }
        self.buf.extend_from_slice(data);
        self.pos += data.len() as u64;
        if self.buf.len() >= MAX_DATA {
            self.send()?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send()
    }
}

impl Seek for Output {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let p = match to {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
            SeekFrom::End(_) => None,
        };
        let p = p.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "unsupported seek"))?;
        if p != self.pos {
            self.send()?;
            self.pos = p;
            self.start = p;
        }
        Ok(p)
    }
}
