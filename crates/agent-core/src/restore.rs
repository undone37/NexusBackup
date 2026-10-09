//! Restore stream handling shared by all agents: entry bookkeeping, chunk placement,
//! the overwrite policy, and the order of the final steps. The file system side is
//! the platform's [`RestoreFs`] (Linux: `openat2(RESOLVE_BENEATH)`; Windows: component
//! walk with reparse-point checks).
//!
//! Order as sent by `agent-conn`: each `RestoreEntries` batch is followed by its chunks
//! (entry and chunk order, repeats resent); a chunk is placed wherever a pending file
//! needs that hash, so any order works as long as a file's entry precedes its chunks.
//! Regular files are written to a temporary name and committed (metadata + rename)
//! when their last chunk arrived; hard links and directory metadata are applied at
//! the end (directories deepest first).

use agent_proto::{Entry, Hash, Kind, Overwrite, ScanStats, MAX_PATH};
use std::collections::HashMap;
use std::io;

const MAX_ERRORS: usize = 1000;

/// What is at a destination path right now (never following a final link).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Existing {
    Missing,
    Dir,
    Other { mtime_ns: i64 },
}

pub fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

/// Split an entry path into validated components: not empty, no `.`/`..`/empty
/// component, no NUL, at most `MAX_PATH` bytes.
pub fn components(path: &[u8]) -> io::Result<Vec<&[u8]>> {
    if path.is_empty() || path.len() > MAX_PATH || path.contains(&0) {
        return Err(invalid("invalid path"));
    }
    let comps: Vec<&[u8]> = path.split(|b| *b == b'/').collect();
    if comps.iter().any(|c| c.is_empty() || *c == b"." || *c == b"..") {
        return Err(invalid(format!("refusing path {}", String::from_utf8_lossy(path))));
    }
    Ok(comps)
}

/// parent directory of an entry path ("" for top-level entries)
pub fn parent_bytes(p: &[u8]) -> &[u8] {
    p.iter().rposition(|b| *b == b'/').map(|i| &p[..i]).unwrap_or_default()
}

/// The overwrite policy. Ok(true) = write the entry, Ok(false) = keep what is there.
/// A directory in the way of a non-directory is never removed (error).
pub fn may_replace(existing: Existing, e: &Entry, overwrite: Overwrite) -> io::Result<bool> {
    let is_dir = match existing {
        Existing::Missing => return Ok(true),
        Existing::Dir => true,
        Existing::Other { .. } => false,
    };
    if e.kind == Kind::Dir {
        return Ok(is_dir || overwrite == Overwrite::Always);
    }
    if is_dir {
        return Err(invalid("a directory is in the way (not removed)"));
    }
    Ok(match (overwrite, existing) {
        (Overwrite::Never, _) => false,
        (Overwrite::Always, _) => true,
        (Overwrite::IfOlder, Existing::Other { mtime_ns }) => mtime_ns < e.mtime_ns,
        (Overwrite::IfOlder, _) => false,
    })
}

/// File system operations of one restore, all confined below the target.
pub trait RestoreFs {
    /// a regular file being filled under a temporary name
    type Tmp;
    /// an open handle for writing a `Tmp`
    type Writer;

    /// target directory (for logs)
    fn target_display(&self) -> String;
    /// Validate an entry path for this platform (at least [`components`]).
    fn check_path(&self, path: &[u8]) -> io::Result<()>;
    /// State of the destination; creates missing parent directories (restrictive
    /// permissions; their real metadata arrives with their own entries).
    fn existing(&mut self, path: &[u8]) -> io::Result<Existing>;
    /// Create the directory (replacing a non-directory if `existing` says so).
    fn make_dir(&mut self, e: &Entry, existing: Existing) -> io::Result<()>;
    /// Temporary file of `e.size` bytes next to the destination.
    fn create_file(&mut self, e: &Entry) -> io::Result<Self::Tmp>;
    fn open_tmp(&mut self, t: &Self::Tmp) -> io::Result<Self::Writer>;
    fn write_at(&mut self, w: &Self::Writer, off: u64, data: &[u8]) -> io::Result<()>;
    /// Metadata on the temp file, then move it over the destination. Non-fatal
    /// problems (single xattrs) go to `warn`. Must remove the temp file on error.
    fn commit_file(&mut self, t: Self::Tmp, e: &Entry, warn: &mut Vec<String>) -> io::Result<()>;
    /// Remove an incomplete temp file.
    fn discard(&mut self, t: Self::Tmp);
    /// Symlinks, devices, FIFOs, sockets (platform permitting), with metadata.
    fn create_other(&mut self, e: &Entry, warn: &mut Vec<String>) -> io::Result<()>;
    /// Hard link `e.path` → `e.link_target` (both relative to the target).
    fn hardlink(&mut self, e: &Entry) -> io::Result<()>;
    /// Directory metadata at the end; `existed` = the directory was there before.
    fn dir_metadata(&mut self, e: &Entry, existed: bool, warn: &mut Vec<String>) -> io::Result<()>;
    /// Flush everything to disk.
    fn finish(&mut self);
}

struct Pending<T> {
    entry: Entry,
    tmp: T,
    remaining: usize,
}

pub struct Stream<F: RestoreFs> {
    pub fs: F,
    overwrite: Overwrite,
    files: Vec<Option<Pending<F::Tmp>>>,
    want: HashMap<Hash, Vec<(usize, u64, u32)>>,
    dirs: Vec<(Entry, bool)>,
    links: Vec<Entry>,
    open: Option<(usize, F::Writer)>,
    pub stats: ScanStats,
    /// existing destinations left alone by the overwrite policy
    pub kept: u64,
}

impl<F: RestoreFs> Stream<F> {
    pub fn new(fs: F, overwrite: Overwrite) -> Stream<F> {
        Stream {
            fs,
            overwrite,
            files: vec![],
            want: HashMap::new(),
            dirs: vec![],
            links: vec![],
            open: None,
            stats: ScanStats::default(),
            kept: 0,
        }
    }

    pub fn overwrite(&self) -> Overwrite {
        self.overwrite
    }

    fn error(&mut self, path: &[u8], e: impl std::fmt::Display) {
        if self.stats.errors.len() < MAX_ERRORS {
            self.stats
                .errors
                .push(format!("{}: {e}", String::from_utf8_lossy(path)));
        }
    }

    fn warnings(&mut self, path: &[u8], w: Vec<String>) {
        for x in w {
            self.error(path, x);
        }
    }

    pub fn entries(&mut self, batch: Vec<Entry>) {
        for e in batch {
            let path = e.path.clone();
            if let Err(x) = self.entry(e) {
                self.error(&path, x);
            }
        }
    }

    fn entry(&mut self, e: Entry) -> io::Result<()> {
        if e.kind == Kind::Hardlink {
            self.fs.check_path(&e.path)?;
            self.fs.check_path(e.link_target.as_deref().unwrap_or_default())?;
            self.links.push(e);
            return Ok(());
        }
        // the appliance may send the root itself as "" / "."; it is the target
        if e.path.is_empty() || e.path == b"." {
            return Ok(());
        }
        self.fs.check_path(&e.path)?;
        let existing = self.fs.existing(&e.path)?;
        if !may_replace(existing, &e, self.overwrite)? {
            // policy decision, not an error (errors fail the restore job)
            self.kept += 1;
            return Ok(());
        }
        match e.kind {
            Kind::Dir => {
                self.fs.make_dir(&e, existing)?;
                self.stats.dirs += 1;
                self.dirs.push((e, existing == Existing::Dir));
            }
            Kind::File => {
                let sum: u64 = e.chunks.iter().map(|(_, l)| *l as u64).sum();
                if sum != e.size {
                    return Err(invalid("chunk lengths do not add up to the size"));
                }
                let tmp = self.fs.create_file(&e)?;
                let idx = self.files.len();
                let mut off = 0;
                for (h, l) in &e.chunks {
                    self.want.entry(*h).or_default().push((idx, off, *l));
                    off += *l as u64;
                }
                let p = Pending {
                    remaining: e.chunks.len(),
                    tmp,
                    entry: e,
                };
                self.stats.files += 1;
                if p.remaining == 0 {
                    self.files.push(None);
                    self.finish_file(p)?;
                } else {
                    self.files.push(Some(p));
                }
            }
            _ => {
                let mut warn = vec![];
                self.fs.create_other(&e, &mut warn)?;
                self.warnings(&e.path, warn);
            }
        }
        Ok(())
    }

    fn finish_file(&mut self, p: Pending<F::Tmp>) -> io::Result<()> {
        let mut warn = vec![];
        self.fs.commit_file(p.tmp, &p.entry, &mut warn)?;
        self.warnings(&p.entry.path, warn);
        Ok(())
    }

    fn pending_path(&self, idx: usize) -> Vec<u8> {
        self.files[idx]
            .as_ref()
            .map(|p| p.entry.path.clone())
            .unwrap_or_default()
    }

    pub fn chunk(&mut self, hash: Hash, data: &[u8]) {
        if blake3::hash(data).as_bytes() != &hash {
            self.error(b"<chunk>", format!("hash mismatch for {}", hex::encode(hash)));
            return;
        }
        let Some(places) = self.want.remove(&hash) else { return };
        for (idx, off, len) in places {
            if len as usize != data.len() {
                let p = self.pending_path(idx);
                self.error(&p, "chunk length mismatch");
                continue;
            }
            if let Err(x) = self.write_at(idx, off, data) {
                let p = self.pending_path(idx);
                self.error(&p, x);
                continue;
            }
            self.stats.bytes += len as u64;
            let done = self.files[idx].as_mut().is_some_and(|p| {
                p.remaining -= 1;
                p.remaining == 0
            });
            if done {
                let p = self.files[idx].take().expect("pending");
                if self.open.as_ref().is_some_and(|(i, _)| *i == idx) {
                    self.open = None;
                }
                let path = p.entry.path.clone();
                if let Err(x) = self.finish_file(p) {
                    self.error(&path, x);
                }
            }
        }
    }

    fn write_at(&mut self, idx: usize, off: u64, data: &[u8]) -> io::Result<()> {
        if self.open.as_ref().map(|(i, _)| *i) != Some(idx) {
            self.open = None;
            let p = self.files[idx]
                .as_ref()
                .ok_or_else(|| invalid("file already completed"))?;
            let w = self.fs.open_tmp(&p.tmp)?;
            self.open = Some((idx, w));
        }
        let (_, w) = self.open.as_ref().expect("opened");
        self.fs.write_at(w, off, data)
    }

    /// Incomplete files, hard links, directory metadata (deepest first), sync.
    pub fn end(self) -> ScanStats {
        self.end_with_fs().0
    }

    pub fn end_with_fs(mut self) -> (ScanStats, F) {
        self.open = None;
        for i in 0..self.files.len() {
            if let Some(p) = self.files[i].take() {
                self.fs.discard(p.tmp);
                self.error(
                    &p.entry.path,
                    format!("incomplete: {} chunk(s) never received", p.remaining),
                );
            }
        }
        for e in std::mem::take(&mut self.links) {
            let r = (|| -> io::Result<bool> {
                let existing = self.fs.existing(&e.path)?;
                if !may_replace(existing, &e, self.overwrite)? {
                    return Ok(false);
                }
                self.fs.hardlink(&e)?;
                Ok(true)
            })();
            match r {
                Ok(true) => self.stats.files += 1,
                Ok(false) => self.kept += 1,
                Err(x) => self.error(&e.path, x),
            }
        }
        let mut dirs = std::mem::take(&mut self.dirs);
        dirs.sort_by_key(|(e, _)| std::cmp::Reverse(e.path.iter().filter(|b| **b == b'/').count()));
        for (e, existed) in dirs {
            let mut warn = vec![];
            if let Err(x) = self.fs.dir_metadata(&e, existed, &mut warn) {
                self.error(&e.path, x);
            }
            self.warnings(&e.path, warn);
        }
        if self.kept > 0 {
            eprintln!(
                "nexus-agent: restore to {}: {} existing entries kept ({:?})",
                self.fs.target_display(),
                self.kept,
                self.overwrite
            );
        }
        self.fs.finish();
        (self.stats, self.fs)
    }
}

impl<F: RestoreFs> crate::server::RestoreJob for Stream<F> {
    fn entries(&mut self, batch: Vec<Entry>) {
        Stream::entries(self, batch)
    }
    fn chunk(&mut self, hash: Hash, data: &[u8]) {
        Stream::chunk(self, hash, data)
    }
    fn end(self) -> ScanStats {
        Stream::end(self)
    }
    fn target(&self) -> String {
        self.fs.target_display()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// In-memory file system: path → node.
    #[derive(Default)]
    struct MemFs {
        nodes: BTreeMap<Vec<u8>, (Kind, Vec<u8>, i64)>,
        tmps: BTreeMap<u32, Vec<u8>>,
        seq: u32,
        meta_dirs: Vec<(Vec<u8>, bool)>,
        synced: bool,
    }

    impl RestoreFs for MemFs {
        type Tmp = u32;
        type Writer = u32;
        fn target_display(&self) -> String {
            "mem".into()
        }
        fn check_path(&self, path: &[u8]) -> io::Result<()> {
            components(path).map(drop)
        }
        fn existing(&mut self, path: &[u8]) -> io::Result<Existing> {
            Ok(match self.nodes.get(path) {
                None => Existing::Missing,
                Some((Kind::Dir, _, _)) => Existing::Dir,
                Some((_, _, m)) => Existing::Other { mtime_ns: *m },
            })
        }
        fn make_dir(&mut self, e: &Entry, _: Existing) -> io::Result<()> {
            self.nodes.insert(e.path.clone(), (Kind::Dir, vec![], e.mtime_ns));
            Ok(())
        }
        fn create_file(&mut self, e: &Entry) -> io::Result<u32> {
            self.seq += 1;
            self.tmps.insert(self.seq, vec![0; e.size as usize]);
            Ok(self.seq)
        }
        fn open_tmp(&mut self, t: &u32) -> io::Result<u32> {
            Ok(*t)
        }
        fn write_at(&mut self, w: &u32, off: u64, data: &[u8]) -> io::Result<()> {
            let b = self.tmps.get_mut(w).unwrap();
            b[off as usize..off as usize + data.len()].copy_from_slice(data);
            Ok(())
        }
        fn commit_file(&mut self, t: u32, e: &Entry, _: &mut Vec<String>) -> io::Result<()> {
            let d = self.tmps.remove(&t).unwrap();
            self.nodes.insert(e.path.clone(), (Kind::File, d, e.mtime_ns));
            Ok(())
        }
        fn discard(&mut self, t: u32) {
            self.tmps.remove(&t);
        }
        fn create_other(&mut self, e: &Entry, w: &mut Vec<String>) -> io::Result<()> {
            w.push("warned".into());
            self.nodes.insert(e.path.clone(), (e.kind, vec![], e.mtime_ns));
            Ok(())
        }
        fn hardlink(&mut self, e: &Entry) -> io::Result<()> {
            let t = self.nodes.get(e.link_target.as_ref().unwrap()).cloned().unwrap();
            self.nodes.insert(e.path.clone(), t);
            Ok(())
        }
        fn dir_metadata(&mut self, e: &Entry, existed: bool, _: &mut Vec<String>) -> io::Result<()> {
            self.meta_dirs.push((e.path.clone(), existed));
            Ok(())
        }
        fn finish(&mut self) {
            self.synced = true;
        }
    }

    fn entry(path: &str, kind: Kind, data: &[u8], mtime_ns: i64) -> (Entry, Vec<(Hash, Vec<u8>)>) {
        let chunks: Vec<(Hash, Vec<u8>)> = data
            .chunks(3)
            .map(|c| (*blake3::hash(c).as_bytes(), c.to_vec()))
            .collect();
        (
            Entry {
                path: path.as_bytes().to_vec(),
                kind,
                mode: 0o644,
                uid: 0,
                gid: 0,
                size: data.len() as u64,
                mtime_ns,
                ctime_ns: 0,
                inode: 0,
                rdev: 0,
                link_target: None,
                xattrs: vec![],
                chunks: chunks.iter().map(|(h, d)| (*h, d.len() as u32)).collect(),
                unchanged: false,
                inconsistent: false,
            },
            chunks,
        )
    }

    #[test]
    fn policy() {
        let (f, _) = entry("f", Kind::File, b"", 10);
        let (d, _) = entry("d", Kind::Dir, b"", 10);
        use Existing::*;
        assert!(may_replace(Missing, &f, Overwrite::Never).unwrap());
        assert!(!may_replace(Other { mtime_ns: 1 }, &f, Overwrite::Never).unwrap());
        assert!(may_replace(Other { mtime_ns: 1 }, &f, Overwrite::IfOlder).unwrap());
        assert!(!may_replace(Other { mtime_ns: 10 }, &f, Overwrite::IfOlder).unwrap());
        assert!(may_replace(Other { mtime_ns: 99 }, &f, Overwrite::Always).unwrap());
        assert!(
            may_replace(Dir, &f, Overwrite::Always).is_err(),
            "directories are never removed"
        );
        assert!(
            may_replace(Dir, &d, Overwrite::Never).unwrap(),
            "merge into existing dirs"
        );
        assert!(!may_replace(Other { mtime_ns: 1 }, &d, Overwrite::IfOlder).unwrap());
        assert!(may_replace(Other { mtime_ns: 1 }, &d, Overwrite::Always).unwrap());
    }

    #[test]
    fn stream_places_shared_and_repeated_chunks_and_orders_the_end() {
        let mut s = Stream::new(MemFs::default(), Overwrite::IfOlder);
        let (d, _) = entry("a", Kind::Dir, b"", 1);
        let (dd, _) = entry("a/b", Kind::Dir, b"", 1);
        let (f1, c1) = entry("a/b/f1", Kind::File, b"abcabcxyz", 5);
        let (f2, _) = entry("a/f2", Kind::File, b"abc", 5);
        let (mut l, _) = entry("a/l", Kind::Hardlink, b"", 5);
        l.link_target = Some(b"a/f2".to_vec());
        let (sym, _) = entry("a/s", Kind::Symlink, b"", 5);
        let (empty, _) = entry("e", Kind::File, b"", 5);
        let (bad, _) = entry("a/../x", Kind::File, b"", 5);
        s.entries(vec![d, dd, f1, f2, l, sym, empty, bad]);
        // chunks of f1 in order; "abc" is wanted three times (f1 twice, f2 once)
        for (h, data) in &c1 {
            s.chunk(*h, data);
        }
        s.chunk([0; 32], b"forged");
        let (st, fs) = s.end_with_fs();
        assert_eq!(st.files, 4, "f1, f2, empty, hardlink");
        assert_eq!(st.bytes, 12);
        assert_eq!(st.errors.len(), 3, "{:?}", st.errors); // bad path, symlink warning, forged
        assert_eq!(fs.nodes[&b"a/b/f1".to_vec()].1, b"abcabcxyz");
        assert_eq!(fs.nodes[&b"a/l".to_vec()].1, b"abc");
        assert!(fs.tmps.is_empty());
        let mut s = Stream::new(MemFs::default(), Overwrite::IfOlder);
        let (f, c) = entry("x", Kind::File, b"abcdef", 5);
        s.entries(vec![f]);
        s.chunk(c[0].0, &c[0].1);
        let st = s.end();
        assert!(st.errors[0].contains("incomplete"), "{:?}", st.errors);
    }

    #[test]
    fn directories_finish_deepest_first_and_policy_keeps_newer_files() {
        let mut m = MemFs::default();
        m.nodes.insert(b"keep".to_vec(), (Kind::File, b"new".to_vec(), 100));
        m.nodes.insert(b"d".to_vec(), (Kind::Dir, vec![], 0));
        let mut s = Stream::new(m, Overwrite::IfOlder);
        let (a, _) = entry("d", Kind::Dir, b"", 1);
        let (b, _) = entry("d/e/f", Kind::Dir, b"", 1);
        let (c, _) = entry("d/e", Kind::Dir, b"", 1);
        let (k, kc) = entry("keep", Kind::File, b"old", 50);
        s.entries(vec![a, b, c, k]);
        for (h, d) in kc {
            s.chunk(h, &d);
        }
        assert_eq!(s.kept, 1);
        let (st, fs) = s.end_with_fs();
        assert!(st.errors.is_empty(), "{:?}", st.errors);
        let order: Vec<(&[u8], bool)> = fs.meta_dirs.iter().map(|(p, e)| (&p[..], *e)).collect();
        assert_eq!(order, vec![(&b"d/e/f"[..], false), (b"d/e", false), (b"d", true)]);
        assert_eq!(fs.nodes[&b"keep".to_vec()].1, b"new");
        assert!(fs.synced);
    }

    #[test]
    fn path_validation() {
        for bad in ["", "../x", "a/../b", "/abs", "a//b", "./a", "a/.", "a\0b"] {
            assert!(components(bad.as_bytes()).is_err(), "{bad}");
        }
        assert_eq!(components(b"a/b c/d").unwrap().len(), 3);
        assert_eq!(parent_bytes(b"a/b/c"), b"a/b");
        assert_eq!(parent_bytes(b"c"), b"");
    }
}
