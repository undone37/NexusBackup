//! Search requests to Tantivy queries, grouping of versions per file, paging.
//!
//! Query text: `/` in it → a path glob on the guest path (`*` within one
//! component, `**` across; anchored at the start when it begins with `/` or a
//! drive, else at any component; without wildcards a path prefix); `*`/`?` or a
//! single term without `/` → a name glob (no wildcard: substring); several
//! words → each must start a word of the path. Matching
//! ignores case. Hits are files (source + path) ordered by path, each with all
//! its versions; the cursor is the number of version documents consumed.

use crate::model::{fkey, TenantIndex};
use index_proto::{Deleted, Hit, Mode, SearchReq, Version};
use std::collections::HashSet;
use std::ops::Bound;
use tantivy::collector::TopDocs;
use tantivy::query::{AllQuery, BooleanQuery, Occur, Query, RangeQuery, RegexQuery, TermQuery, TermSetQuery};
use tantivy::schema::{IndexRecordOption, Value};
use tantivy::{DocAddress, Order, TantivyDocument, Term};

/// Version documents looked at for one page at most.
const MAX_SCAN: usize = 200_000;

fn escape(c: char, out: &mut String) {
    if "\\.+*?()|[]{}^$".contains(c) {
        out.push('\\');
    }
    out.push(c);
}

/// A name glob (`*`, `?`) as a regex over the lowercase name.
pub fn name_regex(q: &str) -> String {
    let q = q.to_lowercase();
    if !q.contains(['*', '?']) {
        let mut s = String::from(".*");
        q.chars().for_each(|c| escape(c, &mut s));
        s.push_str(".*");
        return s;
    }
    let mut s = String::new();
    for c in q.chars() {
        match c {
            '*' => s.push_str(".*"),
            '?' => s.push('.'),
            c => escape(c, &mut s),
        }
    }
    s
}

/// A path glob as a regex over the lowercase guest path.
pub fn path_regex(q: &str) -> String {
    let q = q.to_lowercase();
    let anchored = q.starts_with('/') || q.split('/').next().is_some_and(|d| d.len() == 2 && d.ends_with(':'));
    let wild = q.contains(['*', '?']);
    let mut s = String::new();
    if !anchored {
        s.push_str("(.*/)?");
    }
    let cs: Vec<char> = q.chars().collect();
    let mut i = 0;
    while i < cs.len() {
        match cs[i] {
            '*' if cs.get(i + 1) == Some(&'*') => {
                s.push_str(".*");
                i += 1;
            }
            '*' => s.push_str("[^/]*"),
            '?' => s.push_str("[^/]"),
            c => escape(c, &mut s),
        }
        i += 1;
    }
    if !wild {
        s.push_str(".*");
    }
    s
}

fn words(q: &str) -> Vec<String> {
    q.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_owned)
        .collect()
}

fn regex(pattern: &str, f: tantivy::schema::Field) -> Result<Box<dyn Query>, String> {
    RegexQuery::from_pattern(pattern, f)
        .map(|q| Box::new(q) as Box<dyn Query>)
        .map_err(|e| format!("q: {e}"))
}

pub fn build(ix: &TenantIndex, r: &SearchReq) -> Result<Box<dyn Query>, String> {
    let f = &ix.f;
    let mut must: Vec<(Occur, Box<dyn Query>)> = Vec::new();
    let q = r.q.trim();
    if !q.is_empty() {
        let mode = match r.mode {
            Mode::Auto if q.contains('/') => Mode::Path,
            Mode::Auto if q.contains(['*', '?']) || !q.contains(char::is_whitespace) => Mode::Name,
            Mode::Auto => Mode::Words,
            m => m,
        };
        match mode {
            Mode::Path => must.push((Occur::Must, regex(&path_regex(q), f.path_lc)?)),
            Mode::Name => must.push((Occur::Must, regex(&name_regex(q), f.name_lc)?)),
            _ => {
                let ws = words(q);
                if ws.is_empty() {
                    must.push((Occur::Must, regex(&name_regex(q), f.name_lc)?));
                }
                // each word starts a word of the path (prefix automaton on the token
                // dictionary: fast; substrings are the name mode's job)
                for w in ws.iter().take(8) {
                    let mut esc = String::new();
                    w.chars().for_each(|c| escape(c, &mut esc));
                    must.push((Occur::Must, regex(&format!("{esc}.*"), f.tok)?));
                }
            }
        }
    }
    let set = |field, vals: &[String]| -> Box<dyn Query> {
        Box::new(TermSetQuery::new(vals.iter().map(|v| Term::from_field_text(field, v))))
    };
    if let Some(s) = &r.sources {
        must.push((Occur::Must, set(f.src, s)));
    }
    if let Some(k) = &r.kinds {
        must.push((Occur::Must, set(f.skind, k)));
    }
    if let Some(e) = r.ext.as_ref().filter(|e| !e.is_empty()) {
        let lc: Vec<String> = e.iter().map(|x| x.to_lowercase()).collect();
        must.push((Occur::Must, set(f.ext, &lc)));
    }
    if let Some(o) = r.owners.as_ref().filter(|o| !o.is_empty()) {
        // account names (Phase 39 C2): the guest's name, case-insensitive
        let (ids, names): (Vec<&String>, Vec<&String>) = o.iter().partition(|x| index_proto::owner_id(x));
        // a uid alone: any group (`uid:gid` is what the Linux walkers store)
        let (uids, exact): (Vec<&String>, Vec<&String>) =
            ids.into_iter().partition(|x| x.bytes().all(|b| b.is_ascii_digit()));
        let mut any: Vec<(Occur, Box<dyn Query>)> = Vec::new();
        if !names.is_empty() {
            let lc: Vec<String> = names.iter().map(|n| n.to_lowercase()).collect();
            any.push((Occur::Should, set(f.owner_name_lc, &lc)));
        }
        if !exact.is_empty() {
            let exact: Vec<String> = exact.into_iter().cloned().collect();
            any.push((Occur::Should, set(f.owner, &exact)));
        }
        for uid in uids {
            any.push((Occur::Should, regex(&format!("{uid}:[0-9]+"), f.owner)?));
        }
        must.push((Occur::Must, Box::new(BooleanQuery::new(any))));
    }
    let u = |v: Option<u64>, field| v.map_or(Bound::Unbounded, |v| Bound::Included(Term::from_field_u64(field, v)));
    let i = |v: Option<i64>, field| v.map_or(Bound::Unbounded, |v| Bound::Included(Term::from_field_i64(field, v)));
    if r.size_min.is_some() || r.size_max.is_some() {
        must.push((
            Occur::Must,
            Box::new(RangeQuery::new(u(r.size_min, f.size), u(r.size_max, f.size))),
        ));
    }
    if r.mtime_from.is_some() || r.mtime_to.is_some() {
        must.push((
            Occur::Must,
            Box::new(RangeQuery::new(i(r.mtime_from, f.mtime), i(r.mtime_to, f.mtime))),
        ));
    }
    if let Some(e) = &r.entry {
        let k = if e == "dir" { 1 } else { 0 };
        must.push((
            Occur::Must,
            Box::new(TermQuery::new(
                Term::from_field_u64(f.kind, k),
                IndexRecordOption::Basic,
            )),
        ));
    }
    match r.deleted {
        Deleted::Any => {}
        Deleted::Only => must.push((
            Occur::Must,
            Box::new(RangeQuery::new(
                Bound::Included(Term::from_field_u64(f.gone, 1)),
                Bound::Unbounded,
            )),
        )),
        Deleted::Exclude => must.push((
            Occur::Must,
            Box::new(TermQuery::new(
                Term::from_field_u64(f.gone, 0),
                IndexRecordOption::Basic,
            )),
        )),
    }
    Ok(if must.is_empty() {
        Box::new(AllQuery)
    } else {
        Box::new(BooleanQuery::new(must))
    })
}

/// (hits, next cursor) of one page.
pub fn run(ix: &TenantIndex, r: &SearchReq) -> Result<(Vec<Hit>, Option<String>), String> {
    let q = build(ix, r)?;
    let searcher = ix.reader.searcher();
    let mut off: usize = match &r.cursor {
        Some(c) => c.parse().map_err(|_| "cursor: invalid".to_owned())?,
        None => 0,
    };
    let batch = (r.limit * 4).clamp(64, 2000);
    let mut groups: Vec<u64> = Vec::new();
    let mut seen = HashSet::new();
    let mut last: Option<String> = None;
    let mut next = None;
    let mut scanned = 0;
    let fk = |a: DocAddress| -> Option<u64> {
        searcher
            .segment_reader(a.segment_ord)
            .fast_fields()
            .u64("fkey")
            .ok()?
            .first(a.doc_id)
    };
    'outer: loop {
        let page: Vec<(Option<String>, DocAddress)> = searcher
            .search(
                &q,
                &TopDocs::with_limit(batch)
                    .and_offset(off)
                    .order_by_string_fast_field("path_lc", Order::Asc),
            )
            .map_err(|e| e.to_string())?;
        for (i, (p, a)) in page.iter().enumerate() {
            // a page ends between two paths (all sources of one path stay together,
            // up to 4 x limit files)
            if groups.len() >= r.limit && (*p != last || groups.len() >= r.limit * 4) {
                next = Some((off + i).to_string());
                break 'outer;
            }
            if let Some(k) = fk(*a) {
                if seen.insert(k) {
                    groups.push(k);
                }
            }
            last = p.clone();
        }
        off += page.len();
        scanned += page.len();
        if page.len() < batch {
            break;
        }
        if scanned >= MAX_SCAN {
            next = Some(off.to_string());
            break;
        }
    }
    let mut versions = ix.versions(&groups).map_err(|e| e.to_string())?;
    let f = &ix.f;
    let mut hits = Vec::new();
    for k in groups {
        let Some(mut docs) = versions.remove(&k) else { continue };
        let u = |d: &TantivyDocument, field| d.get_first(field).and_then(|v| v.as_u64()).unwrap_or_default();
        docs.sort_by_key(|d| std::cmp::Reverse(u(d, f.first)));
        if r.deleted == Deleted::Only && docs.iter().any(|d| u(d, f.gone) == 0) {
            continue;
        }
        let s = |d: &TantivyDocument, field| {
            d.get_first(field)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned()
        };
        let newest = &docs[0];
        hits.push(Hit {
            source: s(newest, f.src),
            path: s(newest, f.path),
            browse: s(newest, f.browse),
            kind: TenantIndex::kind_name(u(newest, f.kind)).to_owned(),
            versions: docs
                .iter()
                .map(|d| Version {
                    size: u(d, f.size),
                    mtime: d.get_first(f.mtime).and_then(|v| v.as_i64()).unwrap_or_default(),
                    first: u(d, f.first),
                    gone: Some(u(d, f.gone)).filter(|g| *g != 0),
                    owner: d.get_first(f.owner).and_then(|v| v.as_str()).map(str::to_owned),
                    owner_name: d.get_first(f.owner_name).and_then(|v| v.as_str()).map(str::to_owned),
                })
                .collect(),
        });
    }
    debug_assert!(hits.iter().all(|h| fkey(&h.source, &h.browse) != 0));
    Ok((hits, next))
}

/// Sources of the hits (for the timeline marks).
pub fn hit_sources(hits: &[Hit]) -> Vec<String> {
    let mut v: Vec<String> = hits
        .iter()
        .map(|h| h.source.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    v.sort();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn re(p: &str, s: &str) -> bool {
        // tantivy anchors regexes; emulate with ^…$ in a tiny matcher via the fst regex crate
        let r = tantivy_fst::Regex::new(p).unwrap();
        use tantivy_fst::Automaton;
        let mut st = r.start();
        for b in s.bytes() {
            st = r.accept(&st, b);
        }
        r.is_match(&st)
    }

    #[test]
    fn globs() {
        assert!(re(&name_regex("*.PDF"), "report.pdf"));
        assert!(re(&name_regex("invoice"), "my-invoice-12.pdf"));
        assert!(!re(&name_regex("rep?rt"), "reprt"));
        assert!(re(&name_regex("a.b"), "xa.by") && !re(&name_regex("a.b"), "axb"));
        assert!(re(&path_regex("/etc/*.conf"), "/etc/resolv.conf"));
        assert!(!re(&path_regex("/etc/*.conf"), "/etc/x/resolv.conf"));
        assert!(re(&path_regex("/etc/**.conf"), "/etc/x/resolv.conf"));
        assert!(re(&path_regex("users/*/documents"), "c:/users/ann/documents"));
        assert!(
            re(&path_regex("C:/Users"), "c:/users/ann/x.docx"),
            "prefix without wildcard"
        );
        assert!(!re(&path_regex("C:/Users"), "d:/c:/users"));
        assert!(re(&path_regex("/var/lib/mysql"), "/var/lib/mysql/ibdata1"));
        assert_eq!(words("Angebot Müller-2026.docx"), ["angebot", "müller", "2026", "docx"]);
    }
}
