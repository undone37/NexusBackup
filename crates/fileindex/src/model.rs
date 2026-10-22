//! The per-tenant search index: file-version documents in Tantivy.
//!
//! A document is one version of one file of one source: (path, size, mtime,
//! kind) with `first` (the first snapshot holding it) and `gone` (the first
//! later indexed snapshot without it; 0 = still in the newest). An unchanged
//! file costs one document for its whole history. Directories are versions
//! by path only (their mtime changes with every entry). The sealed
//! per-snapshot name indexes stay the source of truth; this index is a cache
//! that [`TenantIndex::sync_source`] keeps equal to them.

use crate::rules::Rules;
use chunkstore::names::kind_name;
use chunkstore::snapfile::MetaReader;
use chunkstore::NameIndex;
use index_proto::{source_kind, SourceRules};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use tantivy::collector::DocSetCollector;
use tantivy::query::{BooleanQuery, Occur, Query, TermQuery};
use tantivy::schema::{
    Field, IndexRecordOption, Schema, TextFieldIndexing, TextOptions, Value, FAST, INDEXED, STORED, STRING,
};
use tantivy::{doc, Index, IndexReader, IndexWriter, ReloadPolicy, TantivyDocument, Term};

/// Format of the documents and the payload; another value rebuilds (2: owner names, Phase 39 C2).
pub const VERSION: u32 = 2;
const WRITER_BYTES: usize = 64 << 20;
/// More new snapshots than this at once: rebuild the source instead of appending.
const MAX_APPEND: usize = 4;

#[derive(Clone, Copy)]
pub struct Fields {
    pub src: Field,
    pub skind: Field,
    pub path: Field,
    pub browse: Field,
    pub path_lc: Field,
    pub name_lc: Field,
    pub tok: Field,
    pub ext: Field,
    pub kind: Field,
    pub size: Field,
    pub mtime: Field,
    pub first: Field,
    pub gone: Field,
    pub fkey: Field,
    pub okey: Field,
    /// Phase 31c: the owner of the version (stored only)
    pub owner: Field,
    /// Phase 39 C2: the guest's name for that owner (stored only)
    pub owner_name: Field,
    /// the same, lowercased, for the owner filter by name (indexed only)
    pub owner_name_lc: Field,
}

pub fn schema() -> (Schema, Fields) {
    let mut b = Schema::builder();
    let tok = TextOptions::default().set_indexing_options(
        TextFieldIndexing::default()
            .set_tokenizer("default")
            .set_index_option(IndexRecordOption::Basic),
    );
    let f = Fields {
        src: b.add_text_field("src", STRING | STORED),
        skind: b.add_text_field("skind", STRING),
        path: b.add_text_field("path", STORED),
        browse: b.add_text_field("browse", STORED),
        path_lc: b.add_text_field("path_lc", STRING | FAST),
        name_lc: b.add_text_field("name_lc", STRING),
        tok: b.add_text_field("tok", tok),
        ext: b.add_text_field("ext", STRING),
        kind: b.add_u64_field("kind", INDEXED | STORED),
        size: b.add_u64_field("size", INDEXED | STORED | FAST),
        mtime: b.add_i64_field("mtime", INDEXED | STORED | FAST),
        first: b.add_u64_field("first", INDEXED | STORED | FAST),
        gone: b.add_u64_field("gone", INDEXED | STORED | FAST),
        fkey: b.add_u64_field("fkey", INDEXED | FAST),
        okey: b.add_u64_field("okey", INDEXED),
        owner: b.add_text_field("owner", STRING | STORED),
        owner_name: b.add_text_field("owner_name", STORED),
        owner_name_lc: b.add_text_field("owner_name_lc", STRING),
    };
    (b.build(), f)
}

/// What the index holds per source (commit payload, sealed with meta.json).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SrcState {
    /// snapshot times ingested, ascending
    pub ingested: Vec<u64>,
    /// hash of the rules the documents were made with
    pub rules: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct State {
    pub version: u32,
    pub sources: BTreeMap<String, SrcState>,
    /// the last rules the scheduler sent (kept across restarts)
    #[serde(default)]
    pub config: BTreeMap<String, SourceRules>,
}

/// FNV-1a over length-prefixed parts (stable across builds, unlike `Hash`).
pub fn hash(parts: &[&[u8]]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for p in parts {
        for b in (p.len() as u64).to_le_bytes().iter().chain(p.iter()) {
            h = (h ^ *b as u64).wrapping_mul(0x100_0000_01b3);
        }
    }
    h
}

/// The version identity of an entry: directories by path, the rest by
/// path, size, mtime and kind.
fn vkey(source: &str, browse: &str, size: u64, mtime: i64, kind: u8) -> u64 {
    if kind == chunkstore::names::KIND_DIR {
        return hash(&[source.as_bytes(), browse.as_bytes(), b"dir"]);
    }
    hash(&[
        source.as_bytes(),
        browse.as_bytes(),
        &size.to_le_bytes(),
        &mtime.to_le_bytes(),
        &[kind],
    ])
}

pub fn fkey(source: &str, browse: &str) -> u64 {
    hash(&[source.as_bytes(), browse.as_bytes()])
}

pub fn rules_hash(r: &SourceRules) -> u64 {
    hash(&[serde_json::to_string(r).unwrap_or_default().as_bytes()])
}

/// Turns name-index paths of one snapshot into guest paths.
pub enum Guest {
    /// VM snapshot with a volume report (crate fsindex mapping), and the guest's account names by owner
    /// id (uid, SID) from that report
    Vm(fsindex::mapping::Mapper, HashMap<String, String>),
    /// `/` + path; a Windows agent's `C/Users/…` becomes `C:/Users/…`
    Plain { windows: bool },
}

impl Guest {
    pub fn for_snapshot(r: &MetaReader, source: &str, time: u64, names: &NameIndex) -> Guest {
        if source_kind(source) == "vm" {
            if let Ok(Some(b)) = r.read_snap_file(source, time, fsindex::REPORT_FILE) {
                if let Ok(rep) = serde_json::from_slice::<fsindex::Report>(&b) {
                    let vols: Vec<fsindex::Volume> = rep.volumes.into_iter().map(|v| v.volume).collect();
                    let names = vols.iter().flat_map(|v| v.accounts.iter().cloned()).collect();
                    return Guest::Vm(fsindex::mapping::Mapper::new(&vols), names);
                }
            }
        }
        // a Windows agent's tree: top-level entries are drive letters
        let windows = source_kind(source) == "host" && !names.is_empty() && {
            let drive = |p: &str| {
                let top = p.split('/').next().unwrap_or_default();
                top.len() == 1 && top.as_bytes()[0].is_ascii_uppercase()
            };
            names.iter().take(256).all(|e| drive(e.0))
        };
        Guest::Plain { windows }
    }

    /// The guest's name for an owner (`S-1-5-21-…-1001`, or `uid:gid` by its uid), if it has one.
    pub fn owner_name(&self, owner: &str) -> Option<&str> {
        let Guest::Vm(_, names) = self else { return None };
        let id = if owner.starts_with("S-") {
            owner
        } else {
            owner.split(':').next()?
        };
        names.get(id).map(String::as_str)
    }

    pub fn path(&self, browse: &str) -> String {
        match self {
            Guest::Vm(m, _) => {
                let g = m.guest(browse);
                if g == browse {
                    format!("/{browse}")
                } else {
                    g
                }
            }
            Guest::Plain { windows: true } => match browse.split_once('/') {
                Some((d, rest)) if d.len() == 1 => format!("{d}:/{rest}"),
                None if browse.len() == 1 => format!("{browse}:"),
                _ => format!("/{browse}"),
            },
            Guest::Plain { windows: false } => format!("/{browse}"),
        }
    }
}

/// One open version while walking a source's snapshots.
struct Open {
    first: u64,
    path: String,
    browse: String,
    size: u64,
    mtime: i64,
    kind: u8,
    owner: Option<String>,
    owner_name: Option<String>,
}

pub struct TenantIndex {
    pub index: Index,
    pub reader: IndexReader,
    pub f: Fields,
    pub dir: crate::sealdir::SealedDir,
}

fn ext_of(name: &str) -> Option<String> {
    let (stem, e) = name.rsplit_once('.')?;
    (!stem.is_empty()
        && !e.is_empty()
        && e.len() <= 32
        && e.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-'))
    .then(|| e.to_lowercase())
}

impl TenantIndex {
    /// Opens (or creates) the index; an index that cannot be opened (damaged,
    /// another format) is wiped: it is rebuilt from the name indexes.
    pub fn open(dir: crate::sealdir::SealedDir) -> anyhow::Result<TenantIndex> {
        let (schema, f) = schema();
        let index = match Index::open_or_create(dir.clone(), schema.clone()) {
            Ok(i) if i.schema() == schema => i,
            other => {
                eprintln!(
                    "nexus-index: {dir:?}: {}; rebuilding",
                    other.err().map_or("schema changed".to_owned(), |e| e.to_string())
                );
                dir.wipe()?;
                Index::open_or_create(dir.clone(), schema)?
            }
        };
        let reader = index.reader_builder().reload_policy(ReloadPolicy::Manual).try_into()?;
        Ok(TenantIndex { index, reader, f, dir })
    }

    pub fn state(&self) -> State {
        let s = self
            .index
            .load_metas()
            .ok()
            .and_then(|m| m.payload)
            .and_then(|p| serde_json::from_str::<State>(&p).ok())
            .unwrap_or_default();
        if s.version == VERSION {
            s
        } else {
            State {
                version: VERSION,
                config: s.config,
                ..Default::default()
            }
        }
    }

    pub fn docs(&self) -> u64 {
        self.reader.searcher().num_docs()
    }

    pub fn writer(&self) -> anyhow::Result<IndexWriter> {
        Ok(self.index.writer_with_num_threads(1, WRITER_BYTES)?)
    }

    /// Commits with the state as payload and makes it visible to searches.
    pub fn commit(&self, w: &mut IndexWriter, st: &State) -> anyhow::Result<()> {
        let mut p = w.prepare_commit()?;
        p.set_payload(&serde_json::to_string(st)?);
        p.commit()?;
        self.reader.reload()?;
        Ok(())
    }

    fn doc(&self, source: &str, v: &Open, gone: u64) -> TantivyDocument {
        let f = &self.f;
        let lc = v.path.to_lowercase();
        let name = lc.rsplit('/').next().unwrap_or(&lc).to_owned();
        let mut d = doc!(
            f.src => source,
            f.skind => source_kind(source),
            f.path => v.path.as_str(),
            f.browse => v.browse.as_str(),
            f.tok => v.path.as_str(),
            f.name_lc => name.as_str(),
            f.path_lc => lc.as_str(),
            f.kind => v.kind as u64,
            f.size => v.size,
            f.mtime => v.mtime,
            f.first => v.first,
            f.gone => gone,
            f.fkey => fkey(source, &v.browse),
        );
        if v.kind != chunkstore::names::KIND_DIR {
            if let Some(e) = ext_of(&name) {
                d.add_text(f.ext, &e);
            }
        }
        if gone == 0 {
            d.add_u64(f.okey, vkey(source, &v.browse, v.size, v.mtime, v.kind));
        }
        if let Some(o) = &v.owner {
            d.add_text(f.owner, o);
        }
        if let Some(n) = &v.owner_name {
            d.add_text(f.owner_name, n);
            d.add_text(f.owner_name_lc, n.to_lowercase());
        }
        d
    }

    /// The entries of one snapshot the rules let in, by version key.
    fn entries(r: &MetaReader, source: &str, time: u64, rules: &Rules) -> anyhow::Result<Option<HashMap<u64, Open>>> {
        let Some(names) = r.load_names(source, time)? else {
            return Ok(None);
        };
        let g = Guest::for_snapshot(r, source, time, &names);
        let mut out = HashMap::with_capacity(names.len());
        for (i, (p, size, mtime, kind)) in names.iter().enumerate() {
            let path = g.path(p);
            if !rules.allows(&path) {
                continue;
            }
            let (size, mtime) = if kind == chunkstore::names::KIND_DIR {
                (0, mtime)
            } else {
                (size, mtime)
            };
            out.insert(
                vkey(source, p, size, mtime, kind),
                Open {
                    first: time,
                    path,
                    browse: p.to_owned(),
                    size,
                    mtime,
                    kind,
                    owner: names.owner(i).map(str::to_owned),
                    owner_name: names.owner(i).and_then(|o| g.owner_name(o)).map(str::to_owned),
                },
            );
        }
        Ok(Some(out))
    }

    /// Brings one source's documents in line with its snapshots (`times`:
    /// the snapshot times that have a name index, ascending). Appends new
    /// snapshots when only those changed, else rebuilds the source.
    /// Returns whether anything was written.
    pub fn sync_source(
        &self,
        w: &mut IndexWriter,
        st: &mut State,
        r: &MetaReader,
        source: &str,
        times: &[u64],
        rules: &SourceRules,
    ) -> anyhow::Result<bool> {
        let rh = rules_hash(rules);
        let cur = st.sources.get(source).cloned().unwrap_or_default();
        if cur.ingested == times && cur.rules == rh {
            return Ok(false);
        }
        let compiled = Rules::new(source, rules);
        let appendable = cur.rules == rh
            && !cur.ingested.is_empty()
            && times.starts_with(&cur.ingested)
            && times.len() - cur.ingested.len() <= MAX_APPEND;
        if appendable {
            let mut prev_t = *cur.ingested.last().unwrap();
            let mut ingested = cur.ingested.clone();
            for &t in &times[cur.ingested.len()..] {
                self.append(w, r, source, prev_t, t, &compiled)?;
                ingested.push(t);
                st.sources.insert(
                    source.to_owned(),
                    SrcState {
                        ingested: ingested.clone(),
                        rules: rh,
                    },
                );
                // the next append looks up the versions this one opened
                self.commit(w, st)?;
                prev_t = t;
            }
            return Ok(true);
        }
        self.rebuild_source(w, r, source, times, &compiled)?;
        if times.is_empty() {
            st.sources.remove(source);
        } else {
            st.sources.insert(
                source.to_owned(),
                SrcState {
                    ingested: times.to_vec(),
                    rules: rh,
                },
            );
        }
        Ok(true)
    }

    /// Removes a source's documents and walks all its snapshots again.
    fn rebuild_source(
        &self,
        w: &mut IndexWriter,
        r: &MetaReader,
        source: &str,
        times: &[u64],
        rules: &Rules,
    ) -> anyhow::Result<()> {
        w.delete_term(Term::from_field_text(self.f.src, source));
        if !rules.enabled() {
            return Ok(());
        }
        let mut open: HashMap<u64, Open> = HashMap::new();
        for &t in times {
            let Some(mut cur) = Self::entries(r, source, t, rules)? else {
                continue;
            };
            // closed: in the open set, not in this snapshot
            let gone: Vec<u64> = open.keys().filter(|k| !cur.contains_key(k)).copied().collect();
            for k in gone {
                let v = open.remove(&k).unwrap();
                w.add_document(self.doc(source, &v, t))?;
            }
            for (k, v) in cur.drain() {
                open.entry(k).or_insert(v);
            }
        }
        for v in open.values() {
            w.add_document(self.doc(source, v, 0))?;
        }
        Ok(())
    }

    /// Adds snapshot `t` after the ingested `prev`: new versions open, the
    /// versions that disappeared close (`gone = t`).
    fn append(
        &self,
        w: &mut IndexWriter,
        r: &MetaReader,
        source: &str,
        prev: u64,
        t: u64,
        rules: &Rules,
    ) -> anyhow::Result<()> {
        if !rules.enabled() {
            return Ok(());
        }
        let Some(cur) = Self::entries(r, source, t, rules)? else {
            return Ok(());
        };
        let old = Self::entries(r, source, prev, rules)?.unwrap_or_default();
        let searcher = self.reader.searcher();
        for (k, _) in old.iter().filter(|(k, _)| !cur.contains_key(k)) {
            let term = Term::from_field_u64(self.f.okey, *k);
            let hits = searcher.search(
                &TermQuery::new(term.clone(), IndexRecordOption::Basic),
                &DocSetCollector,
            )?;
            for a in hits {
                let d: TantivyDocument = searcher.doc(a)?;
                let v = self.open_of(&d);
                w.delete_term(term.clone());
                w.add_document(self.doc(source, &v, t))?;
            }
        }
        for (k, v) in cur {
            if !old.contains_key(&k) {
                w.add_document(self.doc(source, &v, 0))?;
            }
        }
        Ok(())
    }

    fn open_of(&self, d: &TantivyDocument) -> Open {
        let s = |f| d.get_first(f).and_then(|v| v.as_str()).unwrap_or_default().to_owned();
        let u = |f| d.get_first(f).and_then(|v| v.as_u64()).unwrap_or_default();
        Open {
            first: u(self.f.first),
            path: s(self.f.path),
            browse: s(self.f.browse),
            size: u(self.f.size),
            mtime: d.get_first(self.f.mtime).and_then(|v| v.as_i64()).unwrap_or_default(),
            kind: u(self.f.kind) as u8,
            owner: d.get_first(self.f.owner).and_then(|v| v.as_str()).map(str::to_owned),
            owner_name: d
                .get_first(self.f.owner_name)
                .and_then(|v| v.as_str())
                .map(str::to_owned),
        }
    }

    /// Every version of the files with these keys.
    pub fn versions(&self, keys: &[u64]) -> anyhow::Result<HashMap<u64, Vec<TantivyDocument>>> {
        let searcher = self.reader.searcher();
        let q: Vec<(Occur, Box<dyn Query>)> = keys
            .iter()
            .map(|k| {
                (
                    Occur::Should,
                    Box::new(TermQuery::new(
                        Term::from_field_u64(self.f.fkey, *k),
                        IndexRecordOption::Basic,
                    )) as Box<dyn Query>,
                )
            })
            .collect();
        let mut out: HashMap<u64, Vec<TantivyDocument>> = HashMap::new();
        if q.is_empty() {
            return Ok(out);
        }
        for a in searcher.search(&BooleanQuery::new(q), &DocSetCollector)? {
            let d: TantivyDocument = searcher.doc(a)?;
            let s = d.get_first(self.f.src).and_then(|v| v.as_str()).unwrap_or_default();
            let b = d.get_first(self.f.browse).and_then(|v| v.as_str()).unwrap_or_default();
            out.entry(fkey(s, b)).or_default().push(d);
        }
        Ok(out)
    }

    pub fn kind_name(k: u64) -> &'static str {
        kind_name(k as u8)
    }
}
