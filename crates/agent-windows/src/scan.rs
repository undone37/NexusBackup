//! The Windows walk, generic over a [`Source`] so that everything except the Win32
//! calls (entry building, ADS, reparse points, hard links, excludes, the cache / USN
//! decision, fallback inconsistency detection) is tested on Linux with a simulated
//! source. The Win32 source reads a VSS shadow copy (`win/source.rs`).

use crate::meta::{self, Reparse};
use crate::paths::utf16_to_wtf8;
use crate::usn::Changes;
use agent_core::cache::{Cache, Cached};
use agent_core::chunk::{self, ChunkList, Locator};
use agent_core::filter::{Filter, Visit};
use agent_proto::{Entry, Kind, ScanStats, MAX_PATH, MAX_XATTR};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

const MAX_ERRORS: usize = 1000;

/// Everything the walk needs to know about one file system object (opened without
/// following reparse points).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Facts {
    pub attrs: u32,
    pub size: u64,
    /// FILETIMEs
    pub created: i64,
    pub written: i64,
    pub changed: i64,
    pub file_id: u128,
    /// volume serial number (hard links are matched on (volume, file id))
    pub volume: u64,
    pub links: u32,
    /// raw REPARSE_DATA_BUFFER if the object is a reparse point
    pub reparse: Option<Vec<u8>>,
    pub reparse_tag: u32,
    /// self-relative security descriptor (None if it could not be read)
    pub sd: Option<Vec<u8>>,
    /// named `$DATA` streams: (name, size)
    pub streams: Vec<(Vec<u16>, u64)>,
}

impl Facts {
    pub fn is_dir(&self) -> bool {
        self.attrs & meta::FILE_ATTRIBUTE_DIRECTORY != 0
    }

    pub fn is_link(&self) -> bool {
        self.attrs & meta::FILE_ATTRIBUTE_REPARSE_POINT != 0 && meta::is_link_tag(self.reparse_tag)
    }
}

pub trait Source {
    /// Facts of the object at `p` (never following it).
    fn stat(&mut self, p: &Path) -> io::Result<Facts>;
    /// Names in a directory (any order; the walk sorts).
    fn list(&mut self, dir: &Path) -> io::Result<Vec<Vec<u16>>>;
    /// `dir\name`
    fn child(&self, dir: &Path, name: &[u16]) -> PathBuf;
    /// `file:stream` (what the locator re-opens for `Want`)
    fn stream(&self, file: &Path, name: &[u16]) -> PathBuf;
    /// Open the main data (or a stream path) for reading.
    fn open(&mut self, p: &Path) -> io::Result<std::fs::File>;
}

#[derive(Clone, Debug)]
pub struct Root {
    /// entry path of the root (`C/Users/alice`)
    pub entry: Vec<u8>,
    /// where it is read (shadow copy path, or the live path in fallback mode)
    pub src: PathBuf,
    /// index into the per-volume [`Changes`]
    pub volume: usize,
    /// fallback mode (no snapshot): detect changes during read, spool chunk data
    pub live: bool,
}

pub struct Walker<'a, S: Source> {
    pub source: &'a mut S,
    pub filter: &'a Filter,
    pub cache: Option<&'a Cache>,
    pub changes: &'a [Changes],
    pub locator: Locator,
    pub new_cache: Cache,
    pub stats: ScanStats,
    links: HashMap<(u64, u128), Vec<u8>>,
}

fn join(parent: &[u8], name: &[u8]) -> Vec<u8> {
    let mut p = parent.to_vec();
    p.push(b'/');
    p.extend_from_slice(name);
    p
}

impl<'a, S: Source> Walker<'a, S> {
    pub fn new(
        source: &'a mut S,
        filter: &'a Filter,
        cache: Option<&'a Cache>,
        changes: &'a [Changes],
        locator: Locator,
        new_cache: Cache,
    ) -> Self {
        Walker {
            source,
            filter,
            cache,
            changes,
            locator,
            new_cache,
            stats: ScanStats::default(),
            links: HashMap::new(),
        }
    }

    fn error(&mut self, path: &[u8], msg: impl std::fmt::Display) {
        if self.stats.errors.len() < MAX_ERRORS {
            self.stats
                .errors
                .push(format!("{}: {msg}", String::from_utf8_lossy(path)));
        } else if self.stats.errors.len() == MAX_ERRORS {
            self.stats.errors.push("further errors suppressed".into());
        }
    }

    fn visit(&self, entry: &[u8]) -> Visit {
        let mut abs = Vec::with_capacity(entry.len() + 1);
        abs.push(b'/');
        abs.extend_from_slice(entry);
        self.filter.visit(&abs)
    }

    /// Walk all roots (depth first, names sorted, a directory before its children).
    pub fn run(&mut self, roots: &[Root], emit: &mut dyn FnMut(Entry) -> io::Result<()>) -> io::Result<()> {
        for root in roots {
            let facts = match self.source.stat(&root.src) {
                Ok(f) => f,
                Err(e) => {
                    self.error(&root.entry, e);
                    continue;
                }
            };
            let descend = facts.is_dir() && !facts.is_link();
            match self.visit(&root.entry) {
                Visit::Skip => continue,
                Visit::Pass if !descend => continue,
                _ => {}
            }
            self.object(root, &root.entry, &root.src, facts, emit)?;
            if !descend {
                continue;
            }
            let mut stack = vec![(root.entry.clone(), root.src.clone())];
            while let Some((entry, src)) = stack.pop() {
                let mut names = match self.source.list(&src) {
                    Ok(n) => n,
                    Err(e) => {
                        self.error(&entry, e);
                        continue;
                    }
                };
                names.sort();
                let mut subdirs = vec![];
                for name in names {
                    let e = join(&entry, &utf16_to_wtf8(&name));
                    let visit = self.visit(&e);
                    if visit == Visit::Skip {
                        continue;
                    }
                    let s = self.source.child(&src, &name);
                    let facts = match self.source.stat(&s) {
                        Ok(f) => f,
                        Err(x) => {
                            self.error(&e, x);
                            continue;
                        }
                    };
                    let descend = facts.is_dir() && !facts.is_link();
                    if visit == Visit::Pass && !descend {
                        continue;
                    }
                    if self.object(root, &e, &s, facts, emit)? && descend {
                        subdirs.push((e, s));
                    }
                }
                stack.extend(subdirs.into_iter().rev());
            }
        }
        Ok(())
    }

    /// Emit the entry for one object and its alternate data streams. Returns whether
    /// it was emitted.
    fn object(
        &mut self,
        root: &Root,
        path: &[u8],
        src: &Path,
        f: Facts,
        emit: &mut dyn FnMut(Entry) -> io::Result<()>,
    ) -> io::Result<bool> {
        if path.len() > MAX_PATH {
            self.error(path, format!("path longer than {MAX_PATH} bytes, skipped"));
            return Ok(false);
        }
        let mut e = Entry {
            path: path.to_vec(),
            kind: Kind::File,
            mode: meta::synth_mode(f.attrs),
            uid: 0,
            gid: 0,
            size: 0,
            mtime_ns: meta::filetime_to_unix_ns(f.written),
            ctime_ns: meta::filetime_to_unix_ns(f.changed),
            inode: meta::inode_of(f.file_id),
            rdev: 0,
            link_target: None,
            xattrs: vec![
                (meta::X_ATTRS.to_vec(), f.attrs.to_le_bytes().to_vec()),
                (meta::X_CREATED.to_vec(), f.created.to_le_bytes().to_vec()),
            ],
            chunks: vec![],
            unchanged: false,
            inconsistent: false,
        };
        if let Some(sd) = &f.sd {
            if sd.len() + 64 <= MAX_XATTR {
                e.xattrs.push((meta::X_SD.to_vec(), sd.clone()));
            } else {
                self.error(path, "security descriptor larger than the xattr limit, not saved");
            }
        }
        if f.is_link() {
            let raw = f.reparse.clone().unwrap_or_default();
            match Reparse::parse(&raw) {
                Ok(r) => {
                    let t = utf16_to_wtf8(&r.display_target());
                    if t.len() > MAX_PATH {
                        self.error(path, "link target too long, skipped");
                        return Ok(false);
                    }
                    e.kind = Kind::Symlink;
                    e.link_target = Some(t);
                    e.xattrs.push((meta::X_REPARSE.to_vec(), raw));
                }
                Err(x) => {
                    self.error(path, x);
                    return Ok(false);
                }
            }
            emit(e)?;
            return Ok(true);
        }
        if f.is_dir() {
            e.kind = Kind::Dir;
            self.stats.dirs += 1;
            emit(e)?;
            self.streams(root, path, src, &f, emit)?;
            return Ok(true);
        }
        self.stats.files += 1;
        if f.links > 1 {
            if let Some(first) = self.links.get(&(f.volume, f.file_id)) {
                e.kind = Kind::Hardlink;
                e.link_target = Some(first.clone());
                emit(e)?;
                return Ok(true);
            }
            self.links.insert((f.volume, f.file_id), path.to_vec());
        }
        e.size = f.size;
        let p = src.to_path_buf();
        if !self.content(root, &mut e, &p, &f, None)? {
            return Ok(false);
        }
        self.stats.bytes += e.size;
        emit(e)?;
        self.streams(root, path, src, &f, emit)?;
        Ok(true)
    }

    fn streams(
        &mut self,
        root: &Root,
        path: &[u8],
        src: &Path,
        f: &Facts,
        emit: &mut dyn FnMut(Entry) -> io::Result<()>,
    ) -> io::Result<()> {
        for (name, size) in &f.streams {
            let mut p = path.to_vec();
            p.push(b':');
            p.extend(utf16_to_wtf8(name));
            if p.len() > MAX_PATH {
                self.error(&p, "path too long, skipped");
                continue;
            }
            let mut e = Entry {
                path: p,
                kind: Kind::File,
                mode: 0o644,
                uid: 0,
                gid: 0,
                size: *size,
                mtime_ns: meta::filetime_to_unix_ns(f.written),
                ctime_ns: meta::filetime_to_unix_ns(f.changed),
                inode: meta::inode_of(f.file_id),
                rdev: 0,
                link_target: None,
                xattrs: vec![(meta::X_ADS.to_vec(), vec![])],
                chunks: vec![],
                unchanged: false,
                inconsistent: false,
            };
            let sp = self.source.stream(src, name);
            if self.content(root, &mut e, &sp, f, Some(src))? {
                self.stats.bytes += e.size;
                emit(e)?;
            }
        }
        Ok(())
    }

    /// Fill `e.chunks`: from the cache if the metadata matches and the volume's journal
    /// shows no change, otherwise by reading. `base` = the file a stream belongs to
    /// (re-stat'ed for the live consistency check). Returns false if unreadable.
    fn content(&mut self, root: &Root, e: &mut Entry, src: &Path, f: &Facts, base: Option<&Path>) -> io::Result<bool> {
        let hit = chunk::reuse(self.cache, &e.path, e.size, e.mtime_ns, e.ctime_ns, e.inode);
        let unchanged = self
            .changes
            .get(root.volume)
            .is_some_and(|c| c.unchanged(hit.is_some(), f.file_id));
        let idx = self.locator.add_file(src.to_path_buf());
        if let (true, Some(c)) = (unchanged, hit) {
            if let Err(x) = self.locator.add_list(idx, &c.chunks) {
                self.error(&e.path, x);
            }
            e.chunks = c.chunks.clone();
            e.unchanged = true;
            self.stats.unchanged += 1;
            self.new_cache.files.insert(e.path.clone(), c);
            return Ok(true);
        }
        match self.read(root, src, idx, base.unwrap_or(src), f) {
            Ok((chunks, size, changed)) => {
                self.stats.read_bytes += size;
                e.size = size;
                e.chunks = chunks;
                if changed {
                    e.inconsistent = true;
                    self.stats.inconsistent += 1;
                } else {
                    self.new_cache.files.insert(
                        e.path.clone(),
                        Cached {
                            size,
                            mtime_ns: e.mtime_ns,
                            ctime_ns: e.ctime_ns,
                            inode: e.inode,
                            chunks: e.chunks.clone(),
                        },
                    );
                }
                Ok(true)
            }
            Err(x) => {
                self.error(&e.path, x);
                Ok(false)
            }
        }
    }

    /// Returns (chunks, bytes, changed during read — live mode only).
    fn read(
        &mut self,
        root: &Root,
        src: &Path,
        idx: u32,
        stat_path: &Path,
        pre: &Facts,
    ) -> io::Result<(ChunkList, u64, bool)> {
        let file = self.source.open(src)?;
        let (chunks, total) = chunk::chunk_file(&mut self.locator, idx, &file, root.live)?;
        if !root.live {
            return Ok((chunks, total, false));
        }
        let post = self.source.stat(stat_path)?;
        let changed = post.written != pre.written || post.changed != pre.changed || post.file_id != pre.file_id || {
            // for the main stream the size must match what was read
            stat_path == src && (post.size != pre.size || total != pre.size)
        };
        Ok((chunks, total, changed))
    }
}

#[cfg(test)]
pub mod sim {
    //! A simulated Windows source: metadata from a map, content from real temp files
    //! (so the locator can re-read chunks for `Want`).
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    pub struct SimSource {
        pub dir: PathBuf,
        pub facts: BTreeMap<PathBuf, Facts>,
        /// changes applied to `facts` right after a file was opened (writer during read)
        pub mutate_on_open: BTreeMap<PathBuf, Facts>,
    }

    impl SimSource {
        pub fn new(dir: PathBuf) -> SimSource {
            SimSource {
                dir,
                ..Default::default()
            }
        }
        pub fn path(&self, rel: &str) -> PathBuf {
            if rel.is_empty() {
                self.dir.clone()
            } else {
                self.dir.join(rel)
            }
        }
        pub fn dir_(&mut self, rel: &str, id: u128) {
            std::fs::create_dir_all(self.path(rel)).unwrap();
            self.facts.insert(
                self.path(rel),
                Facts {
                    attrs: meta::FILE_ATTRIBUTE_DIRECTORY,
                    file_id: id,
                    links: 1,
                    written: 132_539_328_000_000_000,
                    changed: 132_539_328_000_000_000,
                    sd: Some(vec![1, 0, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                    ..Default::default()
                },
            );
        }
        pub fn file(&mut self, rel: &str, id: u128, data: &[u8]) -> &mut Facts {
            let p = self.path(rel);
            std::fs::write(&p, data).unwrap();
            self.facts.insert(
                p.clone(),
                Facts {
                    attrs: meta::FILE_ATTRIBUTE_ARCHIVE,
                    size: data.len() as u64,
                    file_id: id,
                    links: 1,
                    created: 132_539_328_000_000_000,
                    written: 132_539_328_000_000_000,
                    changed: 132_539_328_000_000_000,
                    ..Default::default()
                },
            );
            self.facts.get_mut(&p).unwrap()
        }
        pub fn stream_data(&mut self, rel: &str, name: &str, data: &[u8]) {
            let p = self.path(rel);
            let w: Vec<u16> = name.encode_utf16().collect();
            std::fs::write(self.stream(&p, &w), data).unwrap();
            self.facts.get_mut(&p).unwrap().streams.push((w, data.len() as u64));
        }
    }

    impl Source for SimSource {
        fn stat(&mut self, p: &Path) -> io::Result<Facts> {
            self.facts.get(p).cloned().ok_or_else(|| io::ErrorKind::NotFound.into())
        }
        fn list(&mut self, dir: &Path) -> io::Result<Vec<Vec<u16>>> {
            Ok(self
                .facts
                .keys()
                .filter(|k| k.parent() == Some(dir))
                .map(|k| k.file_name().unwrap().to_string_lossy().encode_utf16().collect())
                .collect())
        }
        fn child(&self, dir: &Path, name: &[u16]) -> PathBuf {
            dir.join(String::from_utf16_lossy(name))
        }
        fn stream(&self, file: &Path, name: &[u16]) -> PathBuf {
            // streams live in a side directory so `list` does not see them
            let mut s = file.as_os_str().to_owned();
            s.push(format!(".stream.{}", String::from_utf16_lossy(name)));
            self.dir.parent().unwrap().join("streams").join(
                PathBuf::from(s)
                    .strip_prefix("/")
                    .unwrap()
                    .to_string_lossy()
                    .replace('/', "_"),
            )
        }
        fn open(&mut self, p: &Path) -> io::Result<std::fs::File> {
            if let Some(m) = self.mutate_on_open.remove(p) {
                self.facts.insert(p.to_path_buf(), m);
            }
            std::fs::File::open(p)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::sim::SimSource;
    use super::*;
    use crate::usn::Changes;
    use std::collections::HashSet;

    fn walk(
        src: &mut SimSource,
        excludes: &[&str],
        cache: Option<&Cache>,
        changes: Changes,
        live: bool,
    ) -> (Vec<Entry>, ScanStats, Cache, Locator) {
        let ex = agent_core::glob::Excludes::new_case_insensitive(
            &excludes
                .iter()
                .map(|s| crate::paths::normalize_exclude(s))
                .collect::<Vec<_>>(),
        );
        walk_f(src, Filter::globs(ex), cache, changes, live)
    }

    fn walk_f(
        src: &mut SimSource,
        ex: Filter,
        cache: Option<&Cache>,
        changes: Changes,
        live: bool,
    ) -> (Vec<Entry>, ScanStats, Cache, Locator) {
        let changes = [changes];
        let root = Root {
            entry: b"C/Data".to_vec(),
            src: src.path(""),
            volume: 0,
            live,
        };
        let mut w = Walker::new(src, &ex, cache, &changes, Locator::default(), Cache::new(1, None));
        let mut out = vec![];
        w.run(&[root], &mut |e| {
            out.push(e);
            Ok(())
        })
        .unwrap();
        (out, w.stats, w.new_cache, w.locator)
    }

    fn get<'e>(es: &'e [Entry], p: &str) -> &'e Entry {
        es.iter().find(|e| e.path == p.as_bytes()).unwrap_or_else(|| {
            panic!(
                "{p} missing: {:?}",
                es.iter().map(|e| String::from_utf8_lossy(&e.path)).collect::<Vec<_>>()
            )
        })
    }

    fn sample() -> (tempfile::TempDir, SimSource) {
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(t.path().join("streams")).unwrap();
        let mut s = SimSource::new(t.path().join("vol"));
        s.dir_("", 5);
        s.dir_("Docs", 6);
        s.file("Docs/report.docx", 100, b"report body");
        s.stream_data("Docs/report.docx", "Zone.Identifier", b"[ZoneTransfer]\r\nZoneId=3\r\n");
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let big: Vec<u8> = (0..2_000_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        s.file("Docs/big.bin", 101, &big);
        s.file("Docs/hard1.txt", 102, b"same").links = 2;
        s.file("hard2.txt", 102, b"same").links = 2;
        s.file("Temp.TMP", 103, b"junk");
        let link = Reparse::Symlink {
            substitute: r"\??\C:\Windows".encode_utf16().collect(),
            print: r"C:\Windows".encode_utf16().collect(),
            relative: false,
        };
        s.dir_("link", 104);
        let f = s.facts.get_mut(&s.path("link")).unwrap();
        f.attrs |= meta::FILE_ATTRIBUTE_REPARSE_POINT;
        f.reparse_tag = meta::IO_REPARSE_TAG_SYMLINK;
        f.reparse = Some(link.build());
        // something "inside" the link must never be visited
        s.file("link/secret", 105, b"never");
        // a dedup'ed file: data reparse point, read normally
        let d = s.file("dedup.dat", 106, b"dedup content");
        d.attrs |= meta::FILE_ATTRIBUTE_REPARSE_POINT;
        d.reparse_tag = 0x8000_0013;
        (t, s)
    }

    #[test]
    fn include_roots_and_regex_excludes() {
        let (_t, mut s) = sample();
        let f = crate::filter(
            &[],
            &agent_proto::Filters {
                include: vec![r"c:\data\docs".into()],
                exclude_regex: vec![r"\.BIN$".into()],
                ..Default::default()
            },
        )
        .unwrap();
        let (es, _, _, _) = walk_f(&mut s, f, None, Changes::Unsupported, false);
        let names: Vec<_> = es
            .iter()
            .map(|e| String::from_utf8_lossy(&e.path).into_owned())
            .collect();
        assert_eq!(
            names,
            [
                "C/Data",
                "C/Data/Docs",
                "C/Data/Docs/hard1.txt",
                "C/Data/Docs/report.docx",
                "C/Data/Docs/report.docx:Zone.Identifier"
            ],
            "the way to the include root, its content minus the regex exclude (case-insensitive)"
        );
    }

    #[test]
    fn entries_metadata_streams_links_and_hardlinks() {
        let (_t, mut s) = sample();
        let (es, st, _, mut loc) = walk(&mut s, &["*.tmp"], None, Changes::Unsupported, false);
        let root = get(&es, "C/Data");
        assert_eq!(root.kind, Kind::Dir);
        assert!(meta::xattr(&root.xattrs, meta::X_SD).is_some());
        let r = get(&es, "C/Data/Docs/report.docx");
        assert_eq!(r.kind, Kind::File);
        assert_eq!(r.chunks, vec![(*blake3::hash(b"report body").as_bytes(), 11)]);
        assert_eq!(r.mtime_ns, 1_609_459_200_000_000_000);
        assert_eq!(meta::attrs_of(&r.xattrs), Some(meta::FILE_ATTRIBUTE_ARCHIVE));
        assert_eq!(r.mode, 0o644);
        let ads = get(&es, "C/Data/Docs/report.docx:Zone.Identifier");
        assert!(meta::is_ads(&ads.xattrs));
        assert_eq!(ads.size, 26);
        assert_eq!(ads.inode, r.inode);
        // the stream follows its file directly
        let pos = |p: &str| es.iter().position(|e| e.path == p.as_bytes()).unwrap();
        assert_eq!(
            pos("C/Data/Docs/report.docx:Zone.Identifier"),
            pos("C/Data/Docs/report.docx") + 1
        );
        assert!(pos("C/Data/Docs") < pos("C/Data/Docs/big.bin"));
        let l = get(&es, "C/Data/link");
        assert_eq!(l.kind, Kind::Symlink);
        assert_eq!(l.link_target.as_deref(), Some(&br"C:\Windows"[..]));
        assert!(meta::xattr(&l.xattrs, meta::X_REPARSE).is_some());
        assert!(
            !es.iter().any(|e| e.path.ends_with(b"secret")),
            "links are not followed"
        );
        let h1 = get(&es, "C/Data/Docs/hard1.txt");
        let h2 = get(&es, "C/Data/hard2.txt");
        // a directory's files are emitted before its subdirectories are walked
        assert_eq!(h2.kind, Kind::File, "first path seen carries the data");
        assert_eq!(h1.kind, Kind::Hardlink);
        assert_eq!(h1.link_target.as_deref(), Some(&b"C/Data/hard2.txt"[..]));
        assert!(
            !es.iter().any(|e| e.path.ends_with(b"Temp.TMP")),
            "case-insensitive exclude"
        );
        assert_eq!(
            get(&es, "C/Data/dedup.dat").chunks.len(),
            1,
            "data reparse points are read"
        );
        let big = get(&es, "C/Data/Docs/big.bin");
        assert!(big.chunks.len() >= 2);
        for (h, l) in &big.chunks {
            assert_eq!(loc.get(h).unwrap().len(), *l as usize);
        }
        assert_eq!(loc.get(&ads.chunks[0].0).unwrap(), b"[ZoneTransfer]\r\nZoneId=3\r\n");
        assert!(st.errors.is_empty(), "{:?}", st.errors);
        assert_eq!(st.dirs, 2);
    }

    #[test]
    fn usn_and_cache_decide_unchanged() {
        let (_t, mut s) = sample();
        let (_, st1, cache, _) = walk(&mut s, &[], None, Changes::Reset("first".into()), false);
        assert_eq!(st1.unchanged, 0);
        // journal: only the report changed (id 100) — but metadata also matches for it
        let changes = Changes::Since(HashSet::from([100u128]));
        let (es, st2, cache2, mut loc) = walk(&mut s, &[], Some(&cache), changes, false);
        assert!(
            !get(&es, "C/Data/Docs/report.docx").unchanged,
            "journal record forces a read"
        );
        assert!(
            !get(&es, "C/Data/Docs/report.docx:Zone.Identifier").unchanged,
            "streams follow their file id"
        );
        assert!(get(&es, "C/Data/Docs/big.bin").unchanged);
        assert!(get(&es, "C/Data/hard2.txt").unchanged);
        assert_eq!(st2.unchanged, 4, "big, hard2, Temp.TMP, dedup");
        assert!(cache2.files.contains_key(b"C/Data/Docs/big.bin".as_slice()));
        // unchanged files are still served for Want (re-read + verified)
        let big = get(&es, "C/Data/Docs/big.bin");
        assert!(loc.get(&big.chunks[0].0).is_some());
        // metadata change without a journal record (cannot happen on a healthy volume,
        // but the cache check still applies)
        s.facts.get_mut(&s.path("Docs/big.bin")).unwrap().written += 1;
        let (es, _, _, _) = walk(&mut s, &[], Some(&cache), Changes::Since(HashSet::new()), false);
        assert!(!get(&es, "C/Data/Docs/big.bin").unchanged);
        // journal reset: everything is read
        let (_, st, _, _) = walk(&mut s, &[], Some(&cache), Changes::Reset("wrapped".into()), false);
        assert_eq!(st.unchanged, 0);
    }

    #[test]
    fn live_mode_flags_files_changed_while_read() {
        let (_t, mut s) = sample();
        let p = s.path("Docs/report.docx");
        let mut later = s.facts[&p].clone();
        later.written += 10;
        s.mutate_on_open.insert(p, later);
        let (es, st, cache, _) = walk(&mut s, &[], None, Changes::Unsupported, true);
        assert!(get(&es, "C/Data/Docs/report.docx").inconsistent);
        assert!(
            get(&es, "C/Data/Docs/report.docx:Zone.Identifier").inconsistent,
            "its stream was read while the file changed"
        );
        assert!(!get(&es, "C/Data/Docs/big.bin").inconsistent);
        assert_eq!(st.inconsistent, 2);
        assert!(
            !cache.files.contains_key(b"C/Data/Docs/report.docx".as_slice()),
            "never cached"
        );
    }

    #[test]
    fn unreadable_objects_are_errors_not_aborts() {
        let (_t, mut s) = sample();
        std::fs::remove_file(s.path("Docs/big.bin")).unwrap();
        let mut bad = s.facts[&s.path("link")].clone();
        bad.reparse = Some(vec![1, 2, 3]);
        s.facts.insert(s.path("link"), bad);
        let (es, st, _, _) = walk(&mut s, &[], None, Changes::Unsupported, false);
        assert_eq!(st.errors.len(), 2, "{:?}", st.errors);
        assert!(!es
            .iter()
            .any(|e| e.path.ends_with(b"big.bin") || e.path.ends_with(b"/link")));
        assert!(es.iter().any(|e| e.path.ends_with(b"report.docx")));
    }
}
