//! File-level change signals and the snapshot diff (Phase 21a,
//! docs/ransomware-signals.md). Both compare the sealed name indexes (15g) of
//! two snapshots of one source; the scheduler opens them with the tenant
//! keyring (`Step::Store`), so file names never reach the catalog.
//!
//! - `file_changes {source, time}` follows every indexed backup (tree
//!   snapshots at once, VM/CT after their `file_index`). It counts
//!   added/changed/deleted entries against the previous snapshot and looks for
//!   ransom notes and mass renames. The counts go into `backup_stats`; a signal
//!   raises the `anomaly` alert and flags the snapshot (`snapshots.anomaly`).
//! - `snapshot_diff {source, time, base?, change?, offset?, limit?}` (web-api
//!   `POST /snapshots/diff`) lists the changed paths, one page per job.
//!
//! Directories are left out: their mtime changes with every file inside.

use crate::run::{Plan, Step, StoreOp};
use crate::search::Glob;
use crate::{ident, num, Job, Scheduler};
use anyhow::{bail, Result};
use catalog::rusqlite::{params, OptionalExtension};
use chunkstore::names::{kind_name, KIND_DIR};
use chunkstore::{NameIndex, Store};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

/// Ransom-note file names (last path component, case-insensitive globs) of
/// common families; the `anomaly` setting's `ransom_notes` adds more.
pub const RANSOM_NOTES: &[&str] = &[
    "*how_to_decrypt*",
    "*how-to-decrypt*",
    "*decrypt_instructions*",
    "*decrypt-instructions*",
    "*readme_for_decrypt*",
    "*help_decrypt*",
    "*decrypt_my_files*",
    "*restore-my-files*",
    "*restore_my_files*",
    "*how_to_recover*",
    "*how_to_restore_files*",
    "readme-warning.txt",
    "*ryukreadme*",
    "!!!read_me!!!*",
];
/// a mass rename: at least this many deletions …
pub const RENAME_MIN: u64 = 50;
/// … and at least this share of the previous snapshot's files deleted …
pub const RENAME_SHARE: f64 = 0.1;
/// … with at least half as many additions with extensions the previous snapshot did not have
pub const RENAME_NEW_EXT: f64 = 0.5;
/// ransom-note paths kept in a result
const NOTES_KEPT: usize = 10;
pub const DIFF_DEFAULT_LIMIT: u64 = 200;
pub const DIFF_MAX_LIMIT: u64 = 1000;

/// One changed path: `added`, `changed` (size or mtime) or `deleted`.
#[derive(Debug, PartialEq)]
pub struct Change<'a> {
    pub path: &'a str,
    pub change: &'static str,
    pub kind: u8,
    pub size: u64,
    pub mtime: i64,
    /// before (changed and deleted)
    pub old: Option<(u64, i64)>,
}

fn entries(n: &NameIndex) -> HashMap<&str, (u64, i64, u8)> {
    n.iter()
        .filter(|e| e.3 != KIND_DIR)
        .map(|(p, size, mtime, kind)| (p, (size, mtime, kind)))
        .collect()
}

/// The changes from `base` to `cur`, sorted by path.
pub fn diff<'a>(base: &'a NameIndex, cur: &'a NameIndex) -> Vec<Change<'a>> {
    let (b, c) = (entries(base), entries(cur));
    let mut out = Vec::new();
    for (p, &(size, mtime, kind)) in &c {
        match b.get(p) {
            None => out.push(Change {
                path: p,
                change: "added",
                kind,
                size,
                mtime,
                old: None,
            }),
            Some(&(os, om, _)) if os != size || om != mtime => out.push(Change {
                path: p,
                change: "changed",
                kind,
                size,
                mtime,
                old: Some((os, om)),
            }),
            Some(_) => {}
        }
    }
    for (p, &(size, mtime, kind)) in &b {
        if !c.contains_key(p) {
            out.push(Change {
                path: p,
                change: "deleted",
                kind,
                size,
                mtime,
                old: Some((size, mtime)),
            });
        }
    }
    out.sort_by(|a, b| a.path.cmp(b.path));
    out
}

/// Lower-case extension of the last component (`report.docx.locked` →
/// `locked`); none for dot files and names without a dot.
pub(crate) fn ext(path: &str) -> Option<String> {
    let name = path.rsplit('/').next()?;
    let (stem, e) = name.rsplit_once('.')?;
    (!stem.is_empty() && !e.is_empty() && e.len() <= 16).then(|| e.to_lowercase())
}

/// Counts and signals of one snapshot against the previous one (the result of
/// a `file_changes` job).
pub fn signals(base: &NameIndex, cur: &NameIndex, notes: &[Glob]) -> Value {
    let ch = diff(base, cur);
    let count = |c: &str| ch.iter().filter(|x| x.change == c).count() as u64;
    let old_exts: HashSet<String> = base
        .iter()
        .filter(|e| e.3 != KIND_DIR)
        .filter_map(|e| ext(e.0))
        .collect();
    let added: Vec<&Change> = ch.iter().filter(|x| x.change == "added").collect();
    let mut new_exts: HashMap<String, u64> = HashMap::new();
    for c in &added {
        if let Some(e) = ext(c.path).filter(|e| !old_exts.contains(e)) {
            *new_exts.entry(e).or_default() += 1;
        }
    }
    let mut top: Vec<(String, u64)> = new_exts.iter().map(|(e, n)| (e.clone(), *n)).collect();
    top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    top.truncate(3);
    let found: Vec<&str> = added
        .iter()
        .filter(|c| {
            let name = c.path.rsplit('/').next().unwrap_or(c.path);
            notes.iter().any(|g| g.matches(name))
        })
        .map(|c| c.path)
        .collect();
    json!({
        "indexed": true,
        "files": base.iter().filter(|e| e.3 != KIND_DIR).count(),
        "added": count("added"),
        "changed": count("changed"),
        "deleted": count("deleted"),
        "new_ext": new_exts.values().sum::<u64>(),
        "new_exts": top.into_iter().map(|(e, _)| e).collect::<Vec<_>>(),
        "notes": found.iter().take(NOTES_KEPT).collect::<Vec<_>>(),
        "notes_total": found.len(),
    })
}

/// The file-level reason to flag a snapshot, from a `file_changes` result.
pub fn finding(r: &Value) -> Option<String> {
    let n = |k: &str| r[k].as_u64().unwrap_or(0);
    let mut why = Vec::new();
    if n("notes_total") > 0 {
        let first = r["notes"][0].as_str().unwrap_or_default();
        why.push(format!("{} ransom-note file name(s), e.g. {first}", n("notes_total")));
    }
    let (deleted, new_ext) = (n("deleted"), n("new_ext"));
    if deleted >= RENAME_MIN
        && deleted as f64 >= RENAME_SHARE * n("files") as f64
        && new_ext as f64 >= RENAME_NEW_EXT * deleted as f64
    {
        let exts: Vec<&str> = r["new_exts"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        why.push(format!(
            "mass rename: {deleted} of {} files deleted, {new_ext} added with new extensions (.{})",
            n("files"),
            exts.join(", .")
        ));
    }
    (!why.is_empty()).then(|| why.join("; "))
}

/// The previous snapshot of `source` before `time` in the store.
fn previous(store: &Store, source: &str, time: u64) -> std::io::Result<Option<u64>> {
    Ok(store
        .list_snapshots()?
        .into_iter()
        .filter(|m| m.source == source && m.time < time)
        .map(|m| m.time)
        .max())
}

/// Both name indexes, or `None` when one is missing (VM/CT disks not indexed).
fn pair(store: &Store, source: &str, base: u64, time: u64) -> std::io::Result<Option<(NameIndex, NameIndex)>> {
    let load = |t| -> std::io::Result<Option<NameIndex>> { store.names_or_build(&store.load_manifest(source, t)?) };
    Ok(match (load(base)?, load(time)?) {
        (Some(b), Some(c)) => Some((b, c)),
        _ => None,
    })
}

/// One page of a `snapshot_diff`.
pub fn diff_page(base: &NameIndex, cur: &NameIndex, filter: Option<&str>, offset: usize, limit: usize) -> Value {
    let ch = diff(base, cur);
    let count = |c: &str| ch.iter().filter(|x| x.change == c).count();
    let sel: Vec<&Change> = ch.iter().filter(|x| filter.is_none_or(|f| x.change == f)).collect();
    let entries: Vec<Value> = sel
        .iter()
        .skip(offset)
        .take(limit)
        .map(|c| {
            json!({"path": c.path, "change": c.change, "kind": kind_name(c.kind), "size": c.size, "mtime": c.mtime,
                   "old_size": c.old.map(|o| o.0), "old_mtime": c.old.map(|o| o.1)})
        })
        .collect();
    json!({
        "indexed": true,
        "added": count("added"),
        "changed": count("changed"),
        "deleted": count("deleted"),
        "total": sel.len(),
        "offset": offset,
        "limit": limit,
        "entries": entries,
    })
}

impl Scheduler {
    /// `file_changes` and `snapshot_diff` jobs: read-only, keyed by job id (never
    /// wait for the tenant's backups).
    pub(crate) fn plan_changes(&self, job: &Job, mut plan: Plan) -> Result<Plan> {
        let p = &job.params;
        let source = ident(p, "source")?.to_owned();
        let time = num(p, "time")?;
        plan.key = format!("changes:{}", job.id);
        if job.kind == "file_changes" {
            let cfg = crate::anomaly::Config::load(&self.db.conn());
            let notes: Vec<Glob> = RANSOM_NOTES
                .iter()
                .map(std::string::ToString::to_string)
                .chain(cfg.ransom_notes)
                .map(|g| Glob::new(&g, true))
                .collect();
            plan.steps.push(Step::Store(StoreOp(Box::new(move |s| {
                let r = (|| {
                    let Some(base) = previous(s, &source, time)? else {
                        return Ok(json!({"indexed": false, "base": null}));
                    };
                    let mut v = match pair(s, &source, base, time)? {
                        Some((b, c)) => signals(&b, &c, &notes),
                        None => json!({"indexed": false}),
                    };
                    v["base"] = json!(base);
                    Ok::<_, std::io::Error>(v)
                })();
                r.map(|v| v.to_string()).map_err(|e| format!("file changes: {e}"))
            }))));
            return Ok(plan);
        }
        let base = p
            .get("base")
            .filter(|b| !b.is_null())
            .map(|_| num(p, "base"))
            .transpose()?;
        if base.is_some_and(|b| b >= time) {
            bail!("base: an earlier snapshot than time");
        }
        let filter = match p["change"].as_str() {
            None => None,
            Some(c @ ("added" | "changed" | "deleted")) => Some(c.to_owned()),
            Some(c) => bail!("invalid change {c:?}"),
        };
        let offset = p["offset"].as_u64().unwrap_or(0) as usize;
        let limit = p["limit"].as_u64().unwrap_or(DIFF_DEFAULT_LIMIT);
        if !(1..=DIFF_MAX_LIMIT).contains(&limit) {
            bail!("limit: 1..={DIFF_MAX_LIMIT}");
        }
        plan.steps.push(Step::Store(StoreOp(Box::new(move |s| {
            let r = (|| {
                let Some(base) = base.map_or_else(|| previous(s, &source, time), |b| Ok(Some(b)))? else {
                    return Ok(json!({"indexed": false, "base": null, "time": time}));
                };
                let mut v = match pair(s, &source, base, time)? {
                    Some((b, c)) => diff_page(&b, &c, filter.as_deref(), offset, limit as usize),
                    None => json!({"indexed": false}),
                };
                v["base"] = json!(base);
                v["time"] = json!(time);
                Ok::<_, std::io::Error>(v)
            })();
            r.map(|v| v.to_string()).map_err(|e| format!("snapshot diff: {e}"))
        }))));
        Ok(plan)
    }

    /// `file_changes` for a new snapshot (tree snapshots after their backup,
    /// VM/CT after their `file_index`).
    pub(crate) fn queue_file_changes(&self, tenant: &str, source: &str, time: i64) -> Result<()> {
        self.insert_job("file_changes", tenant, &json!({"source": source, "time": time}))?;
        Ok(())
    }

    /// After a backup: `file_changes` for its tree snapshots (the name index is
    /// written at commit). VM/CT snapshots follow their `file_index` job.
    pub(crate) fn queue_changes_after_backup(&self, tenant: &str, log: &str) -> Result<()> {
        for s in crate::stats::parse(log) {
            if !crate::guest_disks(&s.source) {
                self.queue_file_changes(tenant, &s.source, s.time)?;
            }
        }
        Ok(())
    }

    /// A finished `file_changes`: counts into `backup_stats`, signals into the
    /// anomaly alert and the snapshot flag.
    pub(crate) fn changes_bookkeeping(&self, job: &Job, r: Option<&Value>) -> Result<()> {
        let Some(r) = r.filter(|r| r["indexed"] == true) else {
            return Ok(());
        };
        let (source, time) = (ident(&job.params, "source")?, num(&job.params, "time")? as i64);
        self.db.conn().execute(
            "UPDATE backup_stats SET files_added=?4, files_changed=?5, files_deleted=?6
             WHERE tenant=?1 AND source=?2 AND time=?3",
            params![
                job.tenant,
                source,
                time,
                r["added"].as_i64(),
                r["changed"].as_i64(),
                r["deleted"].as_i64()
            ],
        )?;
        if !crate::anomaly::Config::load(&self.db.conn()).enabled {
            return Ok(());
        }
        let Some(why) = finding(r) else {
            return Ok(());
        };
        self.flag_snapshot(&job.tenant, source, time, &why)?;
        let last = self.last_clean(&job.tenant, source, time)?;
        self.raise(
            "critical",
            "anomaly",
            &format!("anomaly:{}/{source}", job.tenant),
            &format!(
                "file-level anomaly on {}/{source}: snapshot {time}: {why} ({} added, {} changed, {} deleted); {last}",
                job.tenant, r["added"], r["changed"], r["deleted"]
            ),
            Some(&job.tenant),
        )
    }

    /// Marks a snapshot anomalous (the row may not exist yet: the refresh
    /// fills in the rest). A second reason is appended; a cleared flag is set again.
    pub(crate) fn flag_snapshot(&self, tenant: &str, source: &str, time: i64, why: &str) -> Result<()> {
        let c = self.db.conn();
        let old: Option<Option<String>> = c
            .query_row(
                "SELECT anomaly FROM snapshots WHERE tenant=?1 AND source=?2 AND time=?3",
                params![tenant, source, time],
                |r| r.get(0),
            )
            .optional()?;
        let reason = match old.flatten() {
            Some(o) if o.contains(why) => o,
            Some(o) => format!("{o}; {why}"),
            None => why.to_owned(),
        };
        c.execute(
            "INSERT INTO snapshots (tenant, source, time, local, offsite, anomaly, anomaly_at) VALUES (?1,?2,?3,1,0,?4,?5)
             ON CONFLICT (tenant, source, time) DO UPDATE SET anomaly=?4, anomaly_at=?5,
               anomaly_cleared_by=NULL, anomaly_cleared_at=NULL, anomaly_note=NULL",
            params![tenant, source, time, reason, catalog::now()],
        )?;
        drop(c);
        self.db.audit(
            crate::ACTOR,
            "snapshot.anomaly",
            &format!("snapshot/{tenant}/{source}/{time}"),
            &json!({"tenant": tenant, "reason": why}),
        )?;
        Ok(())
    }

    /// "last snapshot before: <source>/<time>" naming the newest clean snapshot
    /// before `time` (the alert's "hold last good snapshot" target); a snapshot
    /// a YARA scan found clean is preferred (Phase 28).
    pub(crate) fn last_clean(&self, tenant: &str, source: &str, time: i64) -> Result<String> {
        let scanned: Option<i64> = self.db.conn().query_row(
            "SELECT MAX(time) FROM snapshots WHERE tenant=?1 AND source=?2 AND time < ?3
               AND (anomaly IS NULL OR anomaly_cleared_at IS NOT NULL) AND scan_state = 'clean'",
            params![tenant, source, time],
            |r| r.get(0),
        )?;
        if let Some(t) = scanned {
            return Ok(format!("last scanned-clean snapshot before: {source}/{t}"));
        }
        let t: Option<i64> = self.db.conn().query_row(
            "SELECT MAX(time) FROM snapshots WHERE tenant=?1 AND source=?2 AND time < ?3
               AND (anomaly IS NULL OR anomaly_cleared_at IS NOT NULL)",
            params![tenant, source, time],
            |r| r.get(0),
        )?;
        Ok(match t {
            Some(t) => format!("last snapshot before: {source}/{t}"),
            None => "no earlier clean snapshot is kept".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idx(v: &[(&str, u64, i64)]) -> NameIndex {
        let mut n = NameIndex::default();
        n.push("docs", 0, 1, KIND_DIR);
        for (p, s, m) in v {
            n.push(p, *s, *m, 0);
        }
        n
    }

    #[test]
    fn diff_counts_and_order() {
        let a = idx(&[("docs/a.txt", 1, 1), ("docs/b.txt", 2, 2), ("x", 3, 3)]);
        let b = idx(&[("docs/a.txt", 1, 1), ("docs/b.txt", 5, 2), ("y", 1, 1)]);
        let d = diff(&a, &b);
        let v: Vec<(&str, &str)> = d.iter().map(|c| (c.path, c.change)).collect();
        assert_eq!(v, [("docs/b.txt", "changed"), ("x", "deleted"), ("y", "added")]);
        assert_eq!(d[0].old, Some((2, 2)));
        let p = diff_page(&a, &b, Some("deleted"), 0, 10);
        assert_eq!((p["total"].as_u64(), p["added"].as_u64()), (Some(1), Some(1)));
        assert_eq!(p["entries"][0]["path"], "x");
        let p = diff_page(&a, &b, None, 2, 1);
        assert_eq!(p["entries"].as_array().unwrap().len(), 1);
        assert_eq!(p["entries"][0]["path"], "y");
    }

    #[test]
    fn ransom_notes_and_mass_renames() {
        let notes: Vec<Glob> = RANSOM_NOTES.iter().map(|g| Glob::new(g, true)).collect();
        let before: Vec<(String, u64, i64)> = (0..200).map(|i| (format!("d/f{i}.docx"), 10, 1)).collect();
        let b: Vec<(&str, u64, i64)> = before.iter().map(|(p, s, m)| (p.as_str(), *s, *m)).collect();
        let base = idx(&b);
        // ordinary day: a few changes, nothing found
        let mut day = b.clone();
        day[0].1 = 11;
        day.push(("d/new.docx", 1, 2));
        let r = signals(&base, &idx(&day), &notes);
        assert_eq!(
            (r["added"].as_u64(), r["changed"].as_u64(), r["deleted"].as_u64()),
            (Some(1), Some(1), Some(0))
        );
        assert_eq!(finding(&r), None);
        // a note dropped into a folder
        day.push(("d/HOW_TO_DECRYPT.txt", 1, 2));
        let r = signals(&base, &idx(&day), &notes);
        assert!(finding(&r).unwrap().contains("d/HOW_TO_DECRYPT.txt"), "{r}");
        // 150 of 200 files renamed to .lockbit
        let enc: Vec<String> = (0..150).map(|i| format!("d/f{i}.docx.lockbit")).collect();
        let mut after: Vec<(&str, u64, i64)> = b[150..].to_vec();
        after.extend(enc.iter().map(|p| (p.as_str(), 10, 3)));
        let r = signals(&base, &idx(&after), &notes);
        let why = finding(&r).unwrap();
        assert!(
            why.contains("mass rename: 150 of 200 files deleted, 150 added") && why.contains(".lockbit"),
            "{why}"
        );
        // a clean-up (deletions without new extensions) is no rename
        let r = signals(&base, &idx(&b[150..]), &notes);
        assert_eq!(finding(&r), None);
        // an admin pattern
        let extra = [Glob::new("*.crypt-note", true)];
        let r = signals(&base, &idx(&[("d/x.crypt-note", 1, 1)]), &extra);
        assert_eq!(r["notes_total"], 1);
    }

    #[test]
    fn extensions() {
        assert_eq!(ext("a/b.DOCX").as_deref(), Some("docx"));
        assert_eq!(ext("a/.bashrc"), None);
        assert_eq!(ext("a.b/c"), None);
        assert_eq!(ext("x.tar.gz").as_deref(), Some("gz"));
    }
}
