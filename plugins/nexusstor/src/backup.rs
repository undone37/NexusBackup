//! One backup of one vStor (docs/nexusstor-design.md): NexusStor snapshot
//! `nexusbackup-<time>` (held), the file tree (`data/...`, `s3/...`: every
//! dataset dir of the inventory) into `files`, every LUN as the stream
//! `luns/<name>`, the vStor definition as the stream `vstor.json`.
//!
//! - Full (no usable base): the tree is walked with `list`, then every entry is
//!   read with `files` (content and metadata) in batches.
//! - Incremental: the base snapshot's entries (`BaseList`) and `zfs diff` of
//!   every dataset since the base's NexusStor snapshot (state blob). Removed
//!   paths and the old names of renamed ones leave the tree, added, modified and
//!   renamed paths are read again (a renamed directory is walked again: zfs diff
//!   does not list its content, and `Unchanged` only works for the same path),
//!   datasets created since the base are walked in full; everything else goes
//!   out as `Unchanged` (files: chunk ids of the base) or with the base's metadata.
//!   Datasets that disappeared since the base make it a full backup.
//! - LUNs are read in full every time (64 MiB per request) and deduplicated by
//!   the chunk store (`ponytail`: no block-level change tracking for zvols).
//!
//! The plugin does not see the host's commit: the previous base (`prev` in the
//! state blob) is released at the start of the next run, when its successor is
//! known to be committed. After a failure the new NexusStor snapshot is released.

use crate::proto::{Nst, Record, Type, VStor, MAX_ENTRIES, MAX_FILES, MAX_LUN_READ};
use anyhow::{bail, ensure, Result};
use plugin_sdk::{BackupResult, Ctx, Kind, Meta, Sink};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use truenas::diff::Change;

/// Request body bytes per `files` batch (paths as JSON; the contract allows 1 MiB).
const BATCH_BYTES: usize = 768 << 10;

/// The state blob kept with each snapshot.
#[derive(Debug, PartialEq)]
pub struct State {
    pub vstor: String,
    /// NexusStor snapshot this backup was read from (the next run's reference)
    pub snap: String,
    /// the reference of this backup (released by the next run)
    pub prev: Option<String>,
    /// dataset dirs at backup time
    pub dirs: Vec<String>,
}

impl State {
    pub fn to_bytes(&self) -> Vec<u8> {
        json!({"v": 1, "vstor": self.vstor, "snap": self.snap, "prev": self.prev, "dirs": self.dirs})
            .to_string()
            .into_bytes()
    }

    /// The base's state, if it is ours, of this vStor and well-formed.
    pub fn parse(b: Option<&[u8]>, vstor: &str) -> Option<State> {
        let v: Value = serde_json::from_slice(b?).ok()?;
        if v["v"] != 1 || v["vstor"] != vstor {
            return None;
        }
        let snap = v["snap"].as_str().filter(|s| crate::proto::valid_snap(s))?.to_owned();
        let prev = match &v["prev"] {
            Value::Null => None,
            p => Some(p.as_str().filter(|s| crate::proto::valid_snap(s))?.to_owned()),
        };
        let dirs = v["dirs"]
            .as_array()?
            .iter()
            .map(|d| {
                d.as_str()
                    .filter(|d| crate::proto::valid_tree_path(d))
                    .map(str::to_owned)
            })
            .collect::<Option<Vec<_>>>()?;
        Some(State {
            vstor: vstor.to_owned(),
            snap,
            prev,
            dirs,
        })
    }
}

/// What to send for a path of the new tree.
#[derive(Debug, Clone, PartialEq)]
enum Act {
    /// unchanged since the base: its metadata (files: `Unchanged`)
    Base(Meta),
    /// read with `files`
    Read,
}

#[derive(Default, Debug)]
pub struct Stats {
    pub entries: u64,
    pub read: u64,
    pub read_bytes: u64,
    pub unchanged: u64,
    pub unchanged_bytes: u64,
    pub failed: u64,
    pub changes: u64,
    pub lun_bytes: u64,
}

fn join(dir: &str, name: &str) -> String {
    format!("{dir}/{name}")
}

fn under(p: &str, dir: &str) -> bool {
    p == dir || (p.len() > dir.len() && p.starts_with(dir) && p.as_bytes()[dir.len()] == b'/')
}

/// Removes `p` and everything below it.
fn remove_tree(t: &mut BTreeMap<String, Act>, p: &str) {
    let below: Vec<String> = t
        .range(format!("{p}/")..)
        .take_while(|(k, _)| k.starts_with(&format!("{p}/")))
        .map(|(k, _)| k.clone())
        .collect();
    for k in below {
        t.remove(&k);
    }
    t.remove(p);
}

/// Walks `dir` (inclusive) with `list`; every path found is set to `Read`.
fn walk(ctx: &Ctx, nst: &Nst, v: &str, snap: &str, dir: &str, t: &mut BTreeMap<String, Act>) -> Result<()> {
    t.insert(dir.to_owned(), Act::Read);
    let mut todo = vec![dir.to_owned()];
    while let Some(d) = todo.pop() {
        let mut after: Option<String> = None;
        loop {
            let (entries, more) = nst.list(v, snap, &d, after.as_deref())?;
            for e in &entries {
                let p = join(&d, &e.name);
                ensure!(p.len() <= plugin_sdk::proto::MAX_PATH, "{p:?}: path too long");
                if e.kind == Type::Dir {
                    todo.push(p.clone());
                }
                t.insert(p, Act::Read);
            }
            ensure!(t.len() <= MAX_ENTRIES, "{v}: more than {MAX_ENTRIES} entries");
            if t.len() % 20_000 < entries.len() {
                ctx.progress(0, 0, format!("listing {v}: {} entries", t.len()));
            }
            if !more {
                break;
            }
            after = entries.last().map(|e| e.name.clone());
        }
    }
    Ok(())
}

/// Path bytes from `zfs diff` as a protocol path (JSON strings: UTF-8 only).
fn diff_path(sink: &mut Sink, p: &[u8]) -> Option<String> {
    match std::str::from_utf8(p) {
        Ok(s) => Some(s.to_owned()),
        Err(_) => {
            sink.item_failed(format!(
                "{}: the name is not UTF-8 and cannot be requested over the NexusStor protocol",
                String::from_utf8_lossy(p)
            ));
            None
        }
    }
}

/// The new tree from the base entries and the diff (see the module doc).
#[allow(clippy::too_many_arguments)]
fn incremental(
    ctx: &Ctx,
    sink: &mut Sink,
    nst: &Nst,
    vs: &VStor,
    base_snap: &str,
    snap: &str,
    base_dirs: &[String],
    st: &mut Stats,
) -> Result<BTreeMap<String, Act>> {
    let dirs = vs.dirs();
    let mut t: BTreeMap<String, Act> = BTreeMap::new();
    for e in sink.base_list()? {
        let Ok(p) = String::from_utf8(e.path) else { continue };
        t.insert(p, Act::Base(e.meta));
    }
    // entries outside every current dataset dir (cannot happen: base dirs ⊆ current)
    t.retain(|p, _| dirs.iter().any(|d| under(p, d)));
    let mut r = std::io::BufReader::new(nst.diff(&vs.name, base_snap, snap)?);
    let diff = crate::proto::parse_diff(&mut r, &dirs)?;
    let mut fresh: Vec<String> = dirs
        .iter()
        .filter(|d| !base_dirs.contains(d) || diff.iter().any(|x| &x.dir == *d && x.new))
        .cloned()
        .collect();
    for d in &dirs {
        if !fresh.contains(d) && !diff.iter().any(|x| &x.dir == d) {
            ctx.warn(format!(
                "{}: NexusStor listed no changes for {d:?}; reading it in full",
                vs.name
            ));
            fresh.push(d.clone());
        }
    }
    // 1. removals and old names (paths of the base snapshot)
    let mut renamed_dirs = Vec::new();
    let mut reads: BTreeSet<String> = BTreeSet::new();
    for l in diff.iter().flat_map(|d| &d.lines) {
        st.changes += 1;
        match &l.change {
            Change::Removed(p) => {
                if let Ok(p) = std::str::from_utf8(p) {
                    remove_tree(&mut t, p);
                }
            }
            Change::Renamed { from, to } => {
                if let Ok(f) = std::str::from_utf8(from) {
                    remove_tree(&mut t, f);
                }
                if let Some(to) = diff_path(sink, to) {
                    if l.ftype == b'/' {
                        renamed_dirs.push(to);
                    } else {
                        reads.insert(to);
                    }
                }
            }
            Change::Added(p) | Change::Modified(p) | Change::Links { path: p, .. } => {
                if let Some(p) = diff_path(sink, p) {
                    reads.insert(p);
                }
            }
        }
    }
    // 2. new names; renamed directories and new datasets walked in the new snapshot
    for d in renamed_dirs.iter().chain(&fresh) {
        remove_tree(&mut t, d);
        walk(ctx, nst, &vs.name, snap, d, &mut t)?;
    }
    for p in reads {
        t.insert(p, Act::Read);
    }
    Ok(t)
}

/// Reads the `Read` paths in batches and sends everything in path order.
fn emit(
    ctx: &Ctx,
    sink: &mut Sink,
    nst: &Nst,
    v: &str,
    snap: &str,
    t: BTreeMap<String, Act>,
    st: &mut Stats,
) -> Result<()> {
    let total = t.len() as u64;
    let mut batch: Vec<String> = Vec::new();
    let mut bytes = 0;
    let mut done = 0u64;
    let mut flush = |sink: &mut Sink, batch: &mut Vec<String>, st: &mut Stats| -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        read_batch(sink, nst, v, snap, batch, st)?;
        done += batch.len() as u64;
        ctx.progress(done, total, format!("{v}: {} files read", st.read));
        batch.clear();
        Ok(())
    };
    for (p, a) in t {
        st.entries += 1;
        match a {
            Act::Base(meta) => {
                if meta.kind.unwrap_or(Kind::File) == Kind::File {
                    st.unchanged += 1;
                    st.unchanged_bytes += meta.size;
                    sink.unchanged(p.as_bytes(), meta)?;
                } else {
                    sink.entry(p.as_bytes(), meta)?;
                }
            }
            Act::Read => {
                bytes += p.len() + 4;
                batch.push(p);
                if batch.len() >= MAX_FILES || bytes >= BATCH_BYTES {
                    flush(sink, &mut batch, st)?;
                    bytes = 0;
                }
            }
        }
    }
    flush(sink, &mut batch, st)
}

/// Counts what `sink.file` takes from the stream.
struct Counted<'a, R> {
    r: &'a mut R,
    n: u64,
}

impl<R: Read> Read for Counted<'_, R> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let n = self.r.read(b)?;
        self.n += n as u64;
        Ok(n)
    }
}

fn read_batch(sink: &mut Sink, nst: &Nst, v: &str, snap: &str, paths: &[String], st: &mut Stats) -> Result<()> {
    let mut f = nst.files(v, snap, paths)?;
    for p in paths {
        match f.next(p)? {
            Record::End => unreachable!("Files::next refuses End"),
            Record::Failed { path, reason, skip } => {
                if skip > 0 {
                    let n = std::io::copy(&mut (&mut f.r).take(skip), &mut std::io::sink())?;
                    ensure!(n == skip, "files: {path:?}: content truncated");
                }
                st.failed += 1;
                sink.item_failed(format!("{path}: {reason}"));
            }
            Record::Entry { path, meta } => {
                if meta.kind == Some(Kind::File) {
                    let size = meta.size;
                    let mut data = (&mut f.r).take(size);
                    let mut c = Counted { r: &mut data, n: 0 };
                    sink.file(path.as_bytes(), meta, &mut c)?;
                    ensure!(
                        c.n == size,
                        "files: {path:?}: content truncated ({} of {size} bytes)",
                        c.n
                    );
                    st.read += 1;
                    st.read_bytes += size;
                } else {
                    sink.entry(path.as_bytes(), meta)?;
                }
            }
        }
    }
    f.end()
}

/// Every LUN as the stream `luns/<name>`, read in full.
fn luns(ctx: &Ctx, sink: &mut Sink, nst: &Nst, vs: &VStor, snap: &str, st: &mut Stats) -> Result<()> {
    for l in &vs.luns {
        let mut w = sink.stream(&format!("luns/{}", l.name))?;
        let mut off = 0u64;
        while off < l.size {
            let len = (l.size - off).min(MAX_LUN_READ);
            let mut r = nst.lun(&vs.name, snap, &l.name, off, len)?;
            let n = std::io::copy(&mut (&mut r).take(len), &mut w)?;
            ensure!(
                n == len,
                "LUN {}: short read at offset {off} ({n} of {len} bytes)",
                l.name
            );
            let mut extra = [0u8; 1];
            ensure!(r.read(&mut extra)? == 0, "LUN {}: more data than requested", l.name);
            off += n;
            st.lun_bytes += n;
            ctx.progress(off, l.size, format!("LUN {}", l.name));
        }
        w.finish()?;
    }
    Ok(())
}

/// The whole run for vStor `vs` (see the module doc). Returns the result with the state blob.
pub fn run(ctx: &Ctx, sink: &mut Sink, nst: &Nst, nexusstor: &str, vs: &VStor) -> Result<BackupResult> {
    let v = vs.name.as_str();
    let state = if sink.has_base() {
        State::parse(ctx.state.as_deref(), v)
    } else {
        None
    };
    // the base is committed: its own reference is no longer needed
    if let Some(p) = state.as_ref().and_then(|s| s.prev.as_deref()) {
        if vs.has_snapshot(p) {
            match nst.release(v, p) {
                Ok(()) => ctx.info(format!("{v}: released the previous base {p}")),
                Err(e) => ctx.warn(format!("{v}: releasing {p} failed (retried next run): {e:#}")),
            }
        }
    }
    let reference = state.as_ref().map(|s| s.snap.clone()).filter(|s| vs.has_snapshot(s));
    if let (Some(s), None) = (&state, &reference) {
        ctx.info(format!(
            "{v}: the base's NexusStor snapshot {} is gone, reading everything",
            s.snap
        ));
    }
    let created = nst.snapshot(v)?;
    let snap = created.snapshot.clone();
    ensure!(
        Some(&snap) != reference.as_ref(),
        "NexusStor returned the base snapshot as the new one"
    );
    ctx.info(format!("{v}: NexusStor snapshot {snap} (held)"));
    let mut st = Stats::default();
    let r = (|| -> Result<bool> {
        let dirs = vs.dirs();
        let incr = match (&reference, &state) {
            (Some(_), Some(s)) if !s.dirs.iter().all(|d| dirs.contains(d)) => {
                ctx.info(format!("{v}: datasets were removed since the base, reading everything"));
                false
            }
            (Some(_), Some(_)) => true,
            _ => false,
        };
        let tree = if incr {
            incremental(
                ctx,
                sink,
                nst,
                vs,
                reference.as_deref().unwrap(),
                &snap,
                &state.as_ref().unwrap().dirs,
                &mut st,
            )?
        } else {
            let mut t = BTreeMap::new();
            for d in &dirs {
                if !t.contains_key(d) {
                    walk(ctx, nst, v, &snap, d, &mut t)?;
                }
            }
            t
        };
        emit(ctx, sink, nst, v, &snap, tree, &mut st)?;
        luns(ctx, sink, nst, vs, &snap, &mut st)?;
        let mut w = sink.stream("vstor.json")?;
        serde_json::to_writer_pretty(&mut w, &vs.definition)?;
        w.finish()?;
        Ok(incr)
    })();
    let incr = match r {
        Ok(i) => i,
        Err(e) => {
            if let Err(d) = nst.release(v, &snap) {
                ctx.warn(format!("{v}: releasing {snap} after the failure failed: {d:#}"));
            }
            return Err(e);
        }
    };
    sink.snapshot_meta(&json!({
        "nexusstor": nexusstor, "vstor": v, "snapshot": snap, "quota": vs.quota, "used": vs.used,
        "encrypted": vs.encrypted, "datasets": vs.dirs(),
        "exports": vs.exports.iter().map(|e| json!({"path": e.path, "dir": e.dir})).collect::<Vec<_>>(),
        "shares": vs.shares.iter().map(|s| json!({"name": s.name, "dir": s.dir})).collect::<Vec<_>>(),
        "s3_root": vs.s3_root, "luns": vs.luns.iter().map(|l| json!({"name": l.name, "size": l.size})).collect::<Vec<_>>(),
    }))?;
    let others: Vec<&str> = vs
        .snapshots
        .iter()
        .map(|s| s.name.as_str())
        .filter(|s| {
            Some(*s) != reference.as_deref() && *s != snap && Some(*s) != state.as_ref().and_then(|x| x.prev.as_deref())
        })
        .collect();
    if !others.is_empty() {
        ctx.warn(format!(
            "{v}: other nexusbackup snapshots on NexusStor are left alone (another pairing or an interrupted run may use them): {}",
            others.join(", ")
        ));
    }
    Ok(BackupResult {
        state: Some(
            State {
                vstor: v.to_owned(),
                snap: snap.clone(),
                prev: reference.clone(),
                dirs: vs.dirs(),
            }
            .to_bytes(),
        ),
        consistent: true,
        summary: format!(
            "{nexusstor}/{v}@{snap}: {} entries, {} files read ({} bytes), {} unchanged files ({} bytes), {} changes, {} LUN bytes, {} items failed{}",
            st.entries,
            st.read,
            st.read_bytes,
            st.unchanged,
            st.unchanged_bytes,
            st.changes,
            st.lun_bytes,
            st.failed,
            if incr { "" } else { ", full read" }
        ),
    })
}

/// Fails unless `s` is a vStor name this source may back up.
pub fn check_guest(s: &str) -> Result<()> {
    if !plugin_sdk::proto::valid_guest_id(s) {
        bail!("{s:?} is not a vStor name");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_roundtrip() {
        let s = State {
            vstor: "acme".into(),
            snap: "nexusbackup-2".into(),
            prev: Some("nexusbackup-1".into()),
            dirs: vec!["data".into(), "s3".into()],
        };
        let b = s.to_bytes();
        assert_eq!(State::parse(Some(&b), "acme"), Some(s));
        assert_eq!(State::parse(Some(&b), "other"), None);
        assert_eq!(State::parse(Some(b"junk"), "acme"), None);
        let bad = json!({"v": 1, "vstor": "acme", "snap": "auto-1", "prev": null, "dirs": []}).to_string();
        assert_eq!(State::parse(Some(bad.as_bytes()), "acme"), None);
        let bad = json!({"v": 1, "vstor": "acme", "snap": "nexusbackup-1", "prev": null, "dirs": ["../x"]}).to_string();
        assert_eq!(State::parse(Some(bad.as_bytes()), "acme"), None);
    }

    #[test]
    fn subtree_removal() {
        let mut t: BTreeMap<String, Act> = ["d", "d/a", "d/a/b", "d-x", "d0", "e"]
            .iter()
            .map(|p| ((*p).to_owned(), Act::Read))
            .collect();
        remove_tree(&mut t, "d");
        assert_eq!(t.keys().collect::<Vec<_>>(), ["d-x", "d0", "e"]);
        assert!(under("data/x", "data") && under("data", "data") && !under("database", "data"));
    }
}
