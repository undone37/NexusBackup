//! File search across a tenant's snapshots (Phase 15g, docs/file-index.md).
//! Every snapshot carries a sealed name index (chunkstore names.rs); the
//! `file_search` job opens the tenant's store with the tenant keyring, decodes
//! the name indexes (in parallel, newest snapshot first) and matches a glob.
//! Results collapse one file version (path, size, mtime) over the snapshots
//! that contain it. `file_index` writes missing name indexes: tenant-wide
//! backfill (in-process, daily with the maintenance jobs), or the VM/CT disks
//! of one snapshot through nexus-pve (opt-in per group, `groups.index_files`).

use crate::run::{Plan, Step, StoreOp};
use crate::{ident, num, Job, Scheduler};
use anyhow::{bail, Context, Result};
use catalog::rusqlite::{params, OptionalExtension};
use chunkstore::names::kind_name;
use chunkstore::{Manifest, NameIndex, Store};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::channel;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const DEFAULT_LIMIT: usize = 500;
pub const MAX_LIMIT: usize = 2000;
pub const MAX_QUERY: usize = 256;
/// a search stops picking up snapshots after this (`truncated`)
pub const BUDGET: Duration = Duration::from_secs(30);

// ------------------------------------------------------------------ glob

#[derive(Debug, PartialEq)]
enum Tok {
    Star,
    One,
    Lit(char),
    /// ranges (single chars are `(c, c)`), negated
    Class(Vec<(char, char)>, bool),
}

/// Shell-style pattern: `*`, `?`, `[abc]`, `[a-z]`, `[!x]` (or `[^x]`),
/// `\` escapes the next character. Optionally case-insensitive.
#[derive(Debug)]
pub struct Glob {
    toks: Vec<Tok>,
    fold: bool,
}

fn fold(c: char) -> char {
    if c.is_ascii() {
        c.to_ascii_lowercase()
    } else {
        c.to_lowercase().next().unwrap_or(c)
    }
}

impl Glob {
    pub fn new(pat: &str, case_insensitive: bool) -> Glob {
        let f = |c: char| if case_insensitive { fold(c) } else { c };
        let mut toks = Vec::new();
        let mut it = pat.chars().peekable();
        while let Some(c) = it.next() {
            toks.push(match c {
                '*' => {
                    if toks.last() == Some(&Tok::Star) {
                        continue;
                    }
                    Tok::Star
                }
                '?' => Tok::One,
                '\\' => Tok::Lit(f(it.next().unwrap_or('\\'))),
                '[' => {
                    // a class runs to the next `]` (a leading `]` is literal); no `]`: literal `[`
                    let rest: Vec<char> = it.clone().collect();
                    let neg = matches!(rest.first(), Some('!' | '^'));
                    let start = usize::from(neg);
                    let Some(end) = rest
                        .iter()
                        .enumerate()
                        .skip(start + 1)
                        .find(|(_, c)| **c == ']')
                        .map(|(i, _)| i)
                    else {
                        toks.push(Tok::Lit('['));
                        continue;
                    };
                    let body = &rest[start..end];
                    let mut ranges = Vec::new();
                    let mut i = 0;
                    while i < body.len() {
                        if i + 2 < body.len() && body[i + 1] == '-' {
                            ranges.push((f(body[i]), f(body[i + 2])));
                            i += 3;
                        } else {
                            ranges.push((f(body[i]), f(body[i])));
                            i += 1;
                        }
                    }
                    for _ in 0..=end {
                        it.next();
                    }
                    Tok::Class(ranges, neg)
                }
                c => Tok::Lit(f(c)),
            });
        }
        Glob {
            toks,
            fold: case_insensitive,
        }
    }

    fn one(&self, t: &Tok, c: char) -> bool {
        let c = if self.fold { fold(c) } else { c };
        match t {
            Tok::One => true,
            Tok::Lit(l) => *l == c,
            Tok::Class(r, neg) => r.iter().any(|(a, b)| (*a..=*b).contains(&c)) != *neg,
            Tok::Star => unreachable!(),
        }
    }

    /// Whole-string match; iterative with backtracking to the last `*`.
    pub fn matches(&self, s: &str) -> bool {
        let (mut p, mut i) = (0, 0); // token index, byte offset in s
        let mut back: Option<(usize, usize)> = None; // (token after the star, byte offset)
        loop {
            if let Some(t) = self.toks.get(p) {
                if *t == Tok::Star {
                    p += 1;
                    back = Some((p, i));
                    continue;
                }
                if let Some(c) = s[i..].chars().next() {
                    if self.one(t, c) {
                        p += 1;
                        i += c.len_utf8();
                        continue;
                    }
                }
            } else if i == s.len() {
                return true;
            }
            // mismatch: let the last star swallow one more character
            match back {
                Some((bp, bi)) => match s[bi..].chars().next() {
                    Some(c) => {
                        back = Some((bp, bi + c.len_utf8()));
                        (p, i) = (bp, bi + c.len_utf8());
                    }
                    None => return false,
                },
                None => return false,
            }
        }
    }
}

// ----------------------------------------------------------------- query

#[derive(Debug)]
pub struct Query {
    glob: Glob,
    /// match the whole path (the query has a `/`), else the last component
    full_path: bool,
    pub source: Option<String>,
    /// Phase 33 cases: every source starting with this (`plugin-m365-`)
    pub source_prefix: Option<String>,
    pub from: Option<u64>,
    pub to: Option<u64>,
    pub limit: usize,
    /// Phase 39 C4 (cases): the item metadata's sender / a To, Cc or Bcc address contains this (lowercase)
    pub sender: Option<String>,
    pub recipient: Option<String>,
}

impl Query {
    /// From `file_search` job params (validated by the web-api as well).
    pub fn from_params(p: &Value) -> Result<Query> {
        let q = p["query"].as_str().unwrap_or_default().trim();
        if q.is_empty() || q.len() > MAX_QUERY || q.contains('\0') {
            bail!("query: 1..={MAX_QUERY} characters");
        }
        let q = q.trim_start_matches('/');
        // no wildcard: a substring search
        let pat = if q.contains(['*', '?', '[']) {
            q.to_owned()
        } else {
            format!("*{q}*")
        };
        let source = match p["source"].as_str() {
            Some(s) => Some(ident(p, "source").map(|_| s.to_owned())?),
            None => None,
        };
        let source_prefix = match p["source_prefix"].as_str() {
            Some(s)
                if !s.is_empty()
                    && s.len() <= 128
                    && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) =>
            {
                Some(s.to_owned())
            }
            Some(s) => bail!("invalid source_prefix {s:?}"),
            None => None,
        };
        let addr = |k: &str| -> Result<Option<String>> {
            match p[k].as_str().map(|s| s.trim().to_lowercase()) {
                Some(s) if s.len() > 254 || s.chars().any(char::is_control) => bail!("{k}: at most 254 characters"),
                s => Ok(s.filter(|s| !s.is_empty())),
            }
        };
        let (sender, recipient) = (addr("sender")?, addr("recipient")?);
        let limit = p["limit"].as_u64().map_or(DEFAULT_LIMIT, |l| l as usize);
        if !(1..=MAX_LIMIT).contains(&limit) {
            bail!("limit: 1..={MAX_LIMIT}");
        }
        Ok(Query {
            glob: Glob::new(&pat, p["case_sensitive"].as_bool() != Some(true)),
            full_path: q.contains('/'),
            source,
            source_prefix,
            from: p["from"].as_u64(),
            to: p["to"].as_u64(),
            limit,
            sender,
            recipient,
        })
    }

    /// Whether the snapshots' item metadata is needed.
    fn by_meta(&self) -> bool {
        self.sender.is_some() || self.recipient.is_some()
    }

    /// Whether an item's metadata record matches the sender / recipient criteria.
    fn meta_hit(&self, rec: Option<&Value>) -> bool {
        if !self.by_meta() {
            return true;
        }
        let Some(r) = rec else { return false };
        let has = |v: &Value, want: &str| match v {
            Value::String(s) => s.to_lowercase().contains(want),
            Value::Array(a) => a
                .iter()
                .any(|x| x.as_str().is_some_and(|s| s.to_lowercase().contains(want))),
            _ => false,
        };
        self.sender.as_deref().is_none_or(|w| has(&r["from"], w))
            && self
                .recipient
                .as_deref()
                .is_none_or(|w| ["to", "cc", "bcc"].iter().any(|k| has(&r[*k], w)))
    }

    fn hit(&self, path: &str) -> bool {
        let s = if self.full_path {
            path
        } else {
            path.rsplit('/').next().unwrap_or(path)
        };
        self.glob.matches(s)
    }

    fn wants(&self, m: &Manifest) -> bool {
        self.source.as_ref().is_none_or(|s| *s == m.source)
            && self
                .source_prefix
                .as_ref()
                .is_none_or(|s| m.source.starts_with(s.as_str()))
            && self.from.is_none_or(|f| m.time >= f)
            && self.to.is_none_or(|t| m.time <= t)
    }
}

/// (path, kind, size, mtime) of one snapshot; `None` = no name index
type Hits = Option<Vec<(String, u8, u64, i64)>>;

/// Matches of one snapshot, at most `limit` (+1 to notice that there were more); `meta`: the snapshot's
/// item metadata when the query needs it.
fn scan(q: &Query, names: &NameIndex, meta: &BTreeMap<String, Value>) -> Vec<(String, u8, u64, i64)> {
    let mut out = Vec::new();
    for (p, size, mtime, kind) in names.iter() {
        if q.hit(p) && q.meta_hit(meta.get(p)) {
            out.push((p.to_owned(), kind, size, mtime));
            if out.len() > q.limit {
                break;
            }
        }
    }
    out
}

/// The item metadata of a snapshot (path → record, [`plugin_proto::ITEM_META_FILE`]); empty when it has
/// none or cannot be read (its items then match no sender / recipient criterion).
fn item_meta(store: &Store, m: &Manifest) -> BTreeMap<String, Value> {
    store
        .read_snap_file(&m.source, m.time, plugin_proto::ITEM_META_FILE)
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Runs a search; the JSON result of a `file_search` job (docs/control-plane.md).
pub fn search(store: &Store, q: &Query, budget: Duration) -> std::io::Result<Value> {
    let t0 = Instant::now();
    let mut snaps: Vec<Manifest> = store.list_snapshots()?.into_iter().filter(|m| q.wants(m)).collect();
    snaps.sort_by(|a, b| b.time.cmp(&a.time).then_with(|| a.source.cmp(&b.source)));
    let next = AtomicUsize::new(0);
    let failed = Mutex::new(None);
    let (tx, rx) = channel::<(usize, Hits)>();
    let workers = std::thread::available_parallelism().map_or(2, |n| n.get().min(8));
    let mut groups: Vec<(String, String, u8, u64, i64, Vec<u64>)> = Vec::new();
    let mut by_key: HashMap<(String, String, u64, i64), usize> = HashMap::new();
    let (mut scanned, mut unindexed, mut truncated) = (0usize, 0usize, false);
    std::thread::scope(|s| {
        for _ in 0..workers {
            let tx = tx.clone();
            let (snaps, next, failed) = (&snaps, &next, &failed);
            s.spawn(move || loop {
                let i = next.fetch_add(1, Ordering::SeqCst);
                if i >= snaps.len() || t0.elapsed() > budget {
                    break;
                }
                let meta = if q.by_meta() {
                    item_meta(store, &snaps[i])
                } else {
                    BTreeMap::new()
                };
                match store.names_or_build(&snaps[i]) {
                    Ok(n) => {
                        let _ = tx.send((i, n.map(|n| scan(q, &n, &meta))));
                    }
                    Err(e) => {
                        failed.lock().unwrap().get_or_insert(e);
                        next.store(snaps.len(), Ordering::SeqCst);
                    }
                }
            });
        }
        drop(tx);
        // merge in snapshot order (newest first): which versions make the limit
        // does not depend on thread timing
        let mut pending: HashMap<usize, Hits> = HashMap::new();
        let mut want = 0;
        let mut ready = VecDeque::new();
        for (i, h) in rx {
            pending.insert(i, h);
            while let Some(h) = pending.remove(&want) {
                ready.push_back((want, h));
                want += 1;
            }
            while let Some((i, h)) = ready.pop_front() {
                scanned += 1;
                let Some(hits) = h else {
                    unindexed += 1;
                    continue;
                };
                let m = &snaps[i];
                truncated |= hits.len() > q.limit;
                for (path, kind, size, mtime) in hits.into_iter().take(q.limit) {
                    let key = (m.source.clone(), path, size, mtime);
                    match by_key.get(&key) {
                        Some(&g) => groups[g].5.push(m.time),
                        None if groups.len() < q.limit => {
                            by_key.insert(key.clone(), groups.len());
                            groups.push((key.0, key.1, kind, size, mtime, vec![m.time]));
                        }
                        None => truncated = true,
                    }
                }
            }
        }
    });
    if let Some(e) = failed.into_inner().unwrap() {
        return Err(e);
    }
    truncated |= scanned < snaps.len();
    groups.sort_by(|a, b| (&a.1, &a.0, b.4).cmp(&(&b.1, &b.0, a.4)));
    let matches: Vec<Value> = groups
        .into_iter()
        .map(|(source, path, kind, size, mtime, times)| {
            json!({"source": source, "path": path, "kind": kind_name(kind), "size": size, "mtime": mtime, "times": times})
        })
        .collect();
    Ok(json!({
        "matches": matches,
        "scanned": scanned,
        "unindexed": unindexed,
        "truncated": truncated,
        "elapsed_ms": t0.elapsed().as_millis() as u64,
    }))
}

// ------------------------------------------------------------- scheduler

impl Scheduler {
    /// `file_search` and `file_index` jobs.
    pub(crate) fn plan_files_index(&self, job: &Job, mut plan: Plan) -> Result<Plan> {
        let p = &job.params;
        if job.kind == "file_search" {
            let q = Query::from_params(p)?;
            // read-only: never waits for (or blocks) the tenant's other jobs
            plan.key = format!("search:{}", job.id);
            plan.steps.push(Step::Store(StoreOp(Box::new(move |s| {
                search(s, &q, BUDGET)
                    .map(|v| v.to_string())
                    .map_err(|e| format!("search: {e}"))
            }))));
            return Ok(plan);
        }
        let Some(source) = p["source"].as_str() else {
            plan.key = format!("names:{}", job.tenant);
            plan.steps.push(Step::Store(StoreOp(Box::new(|s| {
                s.backfill_names()
                    .map(|(built, skipped)| json!({"built": built, "skipped": skipped}).to_string())
                    .map_err(|e| format!("name index backfill: {e}"))
            }))));
            return Ok(plan);
        };
        // the disks of one VM/CT snapshot (or a VMware VM's, #83): nexus-pve reads the store only
        ident(p, "source")?;
        let vmw = vmware::names::parse_source_name(source).is_some();
        let (ct, vmid) = if vmw { (false, 0) } else { crate::guest(source)? };
        let time = num(p, "time")?;
        plan.key = format!("guest:{}/{source}", job.tenant);
        let cfg = json!({"store": plan.store, "tenant": job.tenant, "keyd_socket": self.cfg.keyd_socket});
        plan.files = vec![("pve.json".into(), serde_json::to_vec_pretty(&cfg)?)];
        let mut args = vec![
            plan.dir.join("pve.json").to_string_lossy().into_owned(),
            if ct { "ct-files" } else { "files" }.to_owned(),
            if vmw { source.to_owned() } else { vmid.to_string() },
            time.to_string(),
            "index".into(),
        ];
        // Phase 28: containers with `file_hashes`; Phase 31c: VM disks too (nexus-fsindex)
        if p["hashes"] == true {
            args.push("hashes".into());
        }
        plan.steps.push(Step::Cli {
            bin: self.cfg.pve_bin.clone(),
            args,
            alert: None,
            capture: true,
        });
        Ok(plan)
    }

    /// After a group backup: `file_index` for the VM/CT snapshots it made, if
    /// the group indexes the files in its guests' disks (`groups.index_files`).
    pub(crate) fn queue_name_index(&self, job: &Job, result: Option<&Value>) -> Result<()> {
        let Some(g) = job.params["group_id"].as_i64() else {
            return Ok(());
        };
        let on: Option<(bool, bool)> = self
            .db
            .conn()
            .query_row(
                "SELECT index_files, file_hashes FROM groups WHERE id = ?1 AND tenant = ?2",
                params![g, job.tenant],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((true, hashes)) = on else {
            return Ok(());
        };
        let snaps = result
            .and_then(|r| r["snapshots"].as_array())
            .cloned()
            .unwrap_or_default();
        for s in snaps {
            let (Some(source), Some(time)) = (s["source"].as_str(), s["time"].as_i64()) else {
                continue;
            };
            if crate::guest_disks(source) {
                // after_job: shown with its backup (follow-up jobs)
                let mut p = json!({"source": source, "time": time, "after_job": job.id});
                if hashes {
                    p["hashes"] = json!(true);
                }
                let id = self
                    .insert_job("file_index", &job.tenant, &p)
                    .context("queue file_index")?;
                self.index_pending(&job.tenant, source, time, id)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chunkstore::{Index, Keyring, Options, TreeEntry, TreeKind};

    fn g(p: &str, s: &str) -> bool {
        Glob::new(p, true).matches(s)
    }

    #[test]
    fn glob_matching() {
        assert!(g("*.docx", "Report.DOCX"));
        assert!(!Glob::new("*.docx", false).matches("Report.DOCX"));
        assert!(g("rep?rt*", "report-2026.pdf"));
        assert!(!g("rep?rt", "reprt"));
        assert!(g("*", ""));
        assert!(g("a*b*c", "aXXbYYc") && !g("a*b*c", "aXXbYY"));
        assert!(g("[a-c]x", "Bx") && !g("[a-c]x", "dx"));
        assert!(g("[!a-c]x", "dx") && !g("[!a-c]x", "ax"));
        assert!(g("[^0-9]*", "x1") && !g("[^0-9]*", "1x"));
        assert!(g("[]x", "[]x"), "unterminated class is literal");
        assert!(g("\\*", "*") && !g("\\*", "a"));
        assert!(g("ÄRGER*", "ärger.txt"), "non-ASCII case folding");
        assert!(g("?pfel", "äpfel"), "? is one character, not one byte");
        assert!(g("**a", "a"));
        // pathological backtracking stays linear-ish
        assert!(!g("*a*a*a*a*a*b", &"a".repeat(2000)));
    }

    #[test]
    fn query_semantics() {
        let q = |v: Value| Query::from_params(&v).unwrap();
        let sub = q(json!({"query": "invoice"}));
        assert!(sub.hit("home/ann/Invoice-12.pdf") && !sub.hit("invoice/x.txt"));
        let path = q(json!({"query": "/etc/*.conf"}));
        assert!(path.hit("etc/resolv.conf") && !path.hit("x/etc/resolv.conf"));
        let any = q(json!({"query": "**/*.conf"}));
        assert!(any.hit("x/etc/resolv.conf"));
        assert!(Query::from_params(&json!({"query": ""})).is_err());
        assert!(Query::from_params(&json!({"query": "a", "limit": 0})).is_err());
        assert!(Query::from_params(&json!({"query": "a", "source": "../x"})).is_err());
    }

    fn entry(path: &str, size: u64, mtime: i64) -> TreeEntry {
        TreeEntry {
            path: path.as_bytes().to_vec(),
            kind: TreeKind::File,
            mode: 0o644,
            uid: 0,
            gid: 0,
            size,
            mtime_ns: mtime * 1_000_000_000,
            ctime_ns: 0,
            inode: 0,
            rdev: 0,
            link_target: None,
            xattrs: Vec::new(),
            chunks: Vec::new(),
            inconsistent: false,
        }
    }

    fn store(dir: &std::path::Path) -> Store {
        Store::open(dir, Keyring::new("acme", &[(1, [3; 32])]), Options::default()).unwrap()
    }

    #[test]
    fn versions_collapse_filters_and_truncation() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        let tree = |v: Vec<TreeEntry>| [("tree", Index::Tree { entries: v })];
        // report.txt unchanged in 1 and 2, changed in 3
        s.commit_snapshot(
            "host-a",
            1,
            &tree(vec![entry("doc/report.txt", 5, 10), entry("x.bin", 1, 1)]),
        )
        .unwrap();
        s.commit_snapshot("host-a", 2, &tree(vec![entry("doc/report.txt", 5, 10)]))
            .unwrap();
        s.commit_snapshot("host-a", 3, &tree(vec![entry("doc/report.txt", 6, 20)]))
            .unwrap();
        s.commit_snapshot("share-4", 2, &tree(vec![entry("Report.TXT", 5, 10)]))
            .unwrap();
        let disk = s.store_image(&[0u8; 100][..], 4096).unwrap();
        s.commit_snapshot("vm-100", 2, &[("drive-scsi0", disk)]).unwrap();

        let r = search(&s, &Query::from_params(&json!({"query": "report*"})).unwrap(), BUDGET).unwrap();
        assert_eq!(r["scanned"], 5);
        assert_eq!(r["unindexed"], 1);
        assert_eq!(r["truncated"], false);
        let m = r["matches"].as_array().unwrap();
        assert_eq!(m.len(), 3, "{r}");
        assert_eq!(
            m[0],
            json!({"source": "share-4", "path": "Report.TXT", "kind": "file", "size": 5, "mtime": 10, "times": [2]})
        );
        assert_eq!(m[1]["path"], "doc/report.txt");
        assert_eq!(m[1]["times"], json!([3]));
        assert_eq!(m[2]["times"], json!([2, 1]), "one version, two snapshots, newest first");

        let q = Query::from_params(&json!({"query": "report*", "source": "host-a", "from": 2, "to": 2})).unwrap();
        let r = search(&s, &q, BUDGET).unwrap();
        assert_eq!(
            (r["scanned"].as_u64(), r["matches"].as_array().unwrap().len()),
            (Some(1), 1)
        );

        let q = Query::from_params(&json!({"query": "*", "limit": 1})).unwrap();
        let r = search(&s, &q, BUDGET).unwrap();
        assert_eq!(r["truncated"], true);
        assert_eq!(r["matches"].as_array().unwrap().len(), 1);

        // time budget spent: nothing scanned, truncated
        let r = search(&s, &Query::from_params(&json!({"query": "x"})).unwrap(), Duration::ZERO).unwrap();
        assert_eq!((r["scanned"].as_u64(), r["truncated"].as_bool()), (Some(0), Some(true)));
    }

    /// `cargo test -p scheduler --release search_benchmark -- --ignored --nocapture`:
    /// 100 snapshots × 200k names (plan 15g target: < 10 s on the dev box).
    #[test]
    fn sender_and_recipient_from_item_metadata() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        let tree = |v: Vec<TreeEntry>| [("tree", Index::Tree { entries: v })];
        let src = "plugin-m365-1-u.alice";
        s.commit_snapshot(
            src,
            1,
            &tree(vec![
                entry("mail/Inbox/Offer.eml", 5, 10),
                entry("mail/Inbox/Lunch.eml", 5, 10),
                entry("mail/Inbox/Old.eml", 5, 10),
            ]),
        )
        .unwrap();
        let meta = json!({
            "mail/Inbox/Offer.eml": {"from": "eve@rival.test", "to": ["alice@contoso.test"], "cc": ["Bob@x.test"]},
            "mail/Inbox/Lunch.eml": {"from": "bob@contoso.test", "to": ["alice@contoso.test"], "bcc": ["carol@x.test"]},
        });
        s.write_snap_file(src, 1, plugin_proto::ITEM_META_FILE, meta.to_string().as_bytes())
            .unwrap();
        let find = |p: Value| {
            let r = search(&s, &Query::from_params(&p).unwrap(), BUDGET).unwrap();
            let mut v: Vec<String> = r["matches"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m["path"].as_str().unwrap().to_owned())
                .collect();
            v.sort();
            v
        };
        // substring, case-insensitive; Old.eml has no record (an older host) and matches no address criterion
        assert_eq!(find(json!({"query": "*", "sender": "RIVAL"})), ["mail/Inbox/Offer.eml"]);
        assert_eq!(
            find(json!({"query": "*", "recipient": "carol@"})),
            ["mail/Inbox/Lunch.eml"]
        );
        assert_eq!(
            find(json!({"query": "*", "recipient": "bob@x"})),
            ["mail/Inbox/Offer.eml"]
        );
        assert_eq!(
            find(json!({"query": "*", "recipient": "alice@contoso.test"})),
            ["mail/Inbox/Lunch.eml", "mail/Inbox/Offer.eml"]
        );
        assert!(find(json!({"query": "*", "sender": "eve", "recipient": "carol"})).is_empty());
        assert_eq!(
            find(json!({"query": "*.eml"})).len(),
            3,
            "without address criteria: by name only"
        );
        assert!(Query::from_params(&json!({"query": "a", "sender": "x\ny"})).is_err());
    }

    #[test]
    #[ignore]
    fn search_benchmark() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        let t = Instant::now();
        for snap in 0..100u64 {
            let mut n = NameIndex::default();
            for i in 0..200_000u64 {
                let p = format!("home/user{}/projects/p{}/src/module_{i}_{snap}.rs", i % 50, i % 997);
                n.push(&p, i * 7, 1_700_000_000 + i as i64, 0);
            }
            // name index only (the bench measures the search, not tree commits)
            s.commit_snapshot("host-bench", snap + 1, &[]).unwrap();
            s.write_names("host-bench", snap + 1, &n).unwrap();
        }
        let one = std::fs::metadata(d.path().join("snapshots/host-bench/1/names"))
            .unwrap()
            .len();
        println!("setup {:.1?}, one sealed index {} KiB", t.elapsed(), one / 1024);
        for query in ["module_4711_*", "*.rs", "nothing-matches-this"] {
            let q = Query::from_params(&json!({"query": query})).unwrap();
            let t = Instant::now();
            let r = search(&s, &q, Duration::from_secs(600)).unwrap();
            println!(
                "{query:?}: {:.2?}, scanned {}, matches {}, truncated {}",
                t.elapsed(),
                r["scanned"],
                r["matches"].as_array().unwrap().len(),
                r["truncated"]
            );
            assert_eq!(r["scanned"], 100);
        }
    }
}
