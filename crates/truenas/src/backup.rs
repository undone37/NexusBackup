//! One backup run of a TrueNAS source: snapshot every configured dataset
//! (recursively if configured) as `nexus-<source>-<time>`, then per dataset
//! diff against the reference snapshot, walk, read what changed, commit
//! `nas-<source>-<dataset>/<time>`, and rotate: after a successful commit the
//! new snapshot becomes the reference and every older `nexus-<source>-*`
//! snapshot of that dataset is deleted; after a failure the new snapshot is
//! deleted and the old reference stays.

use crate::api::{Dataset, Nas};
use crate::remote::{Remote, Transport};
use crate::stream;
use crate::tree::{changed_inodes, fill, plan};
use crate::{parse_snap_name, snap_name, source_name, under, valid_dataset, TREE_INDEX};
use anyhow::{bail, Context, Result};
use chunkstore::{Index, Store, TreeEntry};
use serde::Serialize;
use std::collections::HashMap;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub struct Spec {
    pub source_id: u64,
    /// configured roots
    pub datasets: Vec<String>,
    pub recursive: bool,
}

#[derive(Serialize, Debug, Clone, Default)]
pub struct DatasetReport {
    pub dataset: String,
    pub source: String,
    pub time: u64,
    /// read without a reference snapshot
    pub full: bool,
    pub entries: usize,
    pub files_read: usize,
    pub bytes_read: u64,
    pub reused_files: usize,
    pub reused_bytes: u64,
    pub new_chunks: usize,
    pub new_bytes: u64,
    /// bytes received over SSH (diff + walk + content)
    pub transferred_bytes: u64,
    pub changes: usize,
    pub secs: f64,
}

#[derive(Debug, Default)]
pub struct Report {
    pub time: u64,
    pub committed: Vec<DatasetReport>,
    /// (dataset, error)
    pub failed: Vec<(String, String)>,
    pub skipped: Vec<(String, String)>,
    pub deleted_snapshots: Vec<String>,
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

/// Latest committed time per store source.
fn latest_times(store: &Store) -> Result<HashMap<String, u64>> {
    let mut m: HashMap<String, u64> = HashMap::new();
    for s in store.list_snapshots()? {
        let e = m.entry(s.source).or_default();
        *e = (*e).max(s.time);
    }
    Ok(m)
}

fn load_tree(store: &Store, source: &str, time: u64) -> Result<Vec<TreeEntry>> {
    let m = store.load_manifest(source, time)?;
    match store.load_index(&m, TREE_INDEX)? {
        Index::Tree { entries } => Ok(entries),
        _ => bail!("{source}/{time} is not a file tree snapshot"),
    }
}

/// Datasets to back up: roots (must exist and be mounted file systems) and,
/// if recursive, mounted children (unmounted ones and zvols are skipped).
fn expand(nas: &mut dyn Nas, spec: &Spec, r: &mut Report, log: &mut dyn FnMut(&str)) -> Vec<(String, Dataset)> {
    let mut out: Vec<(String, Dataset)> = Vec::new();
    for root in &spec.datasets {
        let list = match nas.datasets(root, spec.recursive) {
            Ok(l) => l,
            Err(e) => {
                r.failed.push((root.clone(), format!("{e:#}")));
                continue;
            }
        };
        match list.iter().find(|d| &d.name == root) {
            Some(d) if d.mountpoint.is_some() => {}
            Some(_) => {
                r.failed.push((root.clone(), "not a mounted file system".into()));
                continue;
            }
            None => {
                r.failed.push((root.clone(), "dataset not found".into()));
                continue;
            }
        }
        for d in list {
            if !valid_dataset(&d.name) {
                // the connector's naming rules (docs): no `.`, `:` or spaces
                r.failed.push((
                    d.name.clone(),
                    "dataset name not supported (allowed: A-Z a-z 0-9 _ -)".into(),
                ));
                continue;
            }
            if d.mountpoint.is_none() {
                let why = if d.filesystem {
                    "not mounted"
                } else {
                    "not a file system (zvol)"
                };
                log(&format!("skipping {}: {why}", d.name));
                r.skipped.push((d.name.clone(), why.into()));
                continue;
            }
            if !out.iter().any(|(n, _)| n == &d.name) {
                out.push((root.clone(), d));
            }
        }
    }
    out
}

pub fn backup(
    store: &Store,
    nas: &mut dyn Nas,
    t: &dyn Transport,
    spec: &Spec,
    log: &mut dyn FnMut(&str),
) -> Result<Report> {
    if spec.datasets.is_empty() || !spec.datasets.iter().all(|d| valid_dataset(d)) {
        bail!("invalid dataset list");
    }
    for a in &spec.datasets {
        if spec.datasets.iter().filter(|b| under(a, b) || under(b, a)).count() > 1 {
            bail!("datasets overlap: {a}");
        }
    }
    let mut r = Report::default();
    let work = expand(nas, spec, &mut r, log);
    let latest = latest_times(store)?;
    let prev_of = |ds: &str| latest.get(&source_name(spec.source_id, ds)).copied();
    r.time = work
        .iter()
        .filter_map(|(_, d)| prev_of(&d.name))
        .map(|t| t + 1)
        .fold(now()?, u64::max);
    let snap = snap_name(spec.source_id, r.time);

    // one atomic (recursive) snapshot per root
    let mut roots_ok: Vec<&String> = Vec::new();
    for root in &spec.datasets {
        if !work.iter().any(|(rt, _)| rt == root) {
            continue;
        }
        match nas.create_snapshot(root, &snap, spec.recursive) {
            Ok(()) => roots_ok.push(root),
            Err(e) => r.failed.push((root.clone(), format!("snapshot: {e:#}"))),
        }
    }
    let mut remote = Remote::new(t);
    for (root, d) in &work {
        if !roots_ok.contains(&root) {
            continue;
        }
        let started = Instant::now();
        let before = remote.received;
        match one(
            store,
            nas,
            &mut remote,
            spec.source_id,
            d,
            r.time,
            prev_of(&d.name),
            log,
        ) {
            Ok(mut rep) => {
                rep.transferred_bytes = remote.received - before;
                rep.secs = started.elapsed().as_secs_f64();
                log(&format!(
                    "committed {}/{} in {:.1}s: {} entries, {} files read ({} bytes), {} unchanged files reused ({} bytes), {} new chunks ({} bytes), {} bytes transferred{}",
                    rep.source,
                    rep.time,
                    rep.secs,
                    rep.entries,
                    rep.files_read,
                    rep.bytes_read,
                    rep.reused_files,
                    rep.reused_bytes,
                    rep.new_chunks,
                    rep.new_bytes,
                    rep.transferred_bytes,
                    if rep.full { ", full read (no reference snapshot)" } else { "" }
                ));
                r.committed.push(rep);
            }
            Err(e) => {
                log(&format!("dataset {} failed: {e:#}", d.name));
                r.failed.push((d.name.clone(), format!("{e:#}")));
            }
        }
    }
    // rotation: per dataset, keep only the newest committed snapshot of this source
    let committed: Vec<&str> = r.committed.iter().map(|c| c.dataset.as_str()).collect();
    for (root, d) in &work {
        if !roots_ok.contains(&root) {
            continue;
        }
        let names = match nas.snapshots(&d.name) {
            Ok(n) => n,
            Err(e) => {
                log(&format!("listing snapshots of {} failed: {e:#}", d.name));
                continue;
            }
        };
        let ok = committed.contains(&d.name.as_str());
        for n in names {
            let Some(t) = parse_snap_name(spec.source_id, &n) else {
                continue; // not ours
            };
            // after success: everything but the new one; after failure: only the new one
            if (ok && t != r.time) || (!ok && t == r.time) {
                match nas.delete_snapshot(&d.name, &n) {
                    Ok(()) => r.deleted_snapshots.push(format!("{}@{n}", d.name)),
                    Err(e) => log(&format!("deleting {}@{n} failed (retried next run): {e:#}", d.name)),
                }
            }
        }
    }
    // a recursive snapshot also exists on skipped children: drop it
    for (ds, _) in &r.skipped {
        if spec
            .datasets
            .iter()
            .any(|root| under(ds, root) && roots_ok.contains(&root))
        {
            let _ = nas.delete_snapshot(ds, &snap);
        }
    }
    Ok(r)
}

#[allow(clippy::too_many_arguments)]
fn one(
    store: &Store,
    nas: &mut dyn Nas,
    remote: &mut Remote,
    source_id: u64,
    d: &Dataset,
    time: u64,
    prev: Option<u64>,
    log: &mut dyn FnMut(&str),
) -> Result<DatasetReport> {
    let mp = d.mountpoint.as_deref().context("not mounted")?;
    let source = source_name(source_id, &d.name);
    let snap = snap_name(source_id, time);
    let ours: Vec<u64> = nas
        .snapshots(&d.name)?
        .iter()
        .filter_map(|n| parse_snap_name(source_id, n))
        .collect();
    if !ours.contains(&time) {
        bail!("snapshot {}@{snap} missing", d.name);
    }
    // the reference: the last committed snapshot, if it still exists on TrueNAS
    let reference = prev.filter(|p| ours.contains(p));
    if let (Some(p), None) = (prev, reference) {
        log(&format!(
            "{}: reference snapshot {} is gone, reading everything",
            d.name,
            snap_name(source_id, p)
        ));
    }
    let diff = match reference {
        Some(p) => Some(remote.diff(&d.name, &snap_name(source_id, p), &snap, mp)?),
        None => None,
    };
    let walk = remote.walk(&d.name, &snap)?;
    let prev_tree = match reference {
        Some(p) => Some(load_tree(store, &source, p)?),
        None => None,
    };
    let changed = diff.as_ref().map(|l| changed_inodes(&walk, l));
    let mut p = plan(walk, prev_tree.as_deref(), changed.as_ref(), &|id| store.has_chunk(id));
    let mut rep = DatasetReport {
        dataset: d.name.clone(),
        source: source.clone(),
        time,
        full: reference.is_none(),
        entries: p.entries.len(),
        reused_files: p.reused_files,
        reused_bytes: p.reused_bytes,
        changes: diff.as_ref().map_or(0, Vec::len),
        ..Default::default()
    };
    if !p.need.is_empty() {
        let paths: Vec<Vec<u8>> = p.need.iter().map(|&i| p.entries[i].path.clone()).collect();
        rep.files_read = p
            .need
            .iter()
            .filter(|&&i| p.entries[i].kind == chunkstore::TreeKind::File)
            .count();
        let (bytes, nc, nb) = remote.read(&d.name, &snap, paths, |tar: &mut stream::Reader<_>| {
            fill(store, &mut p, tar)
        })?;
        rep.bytes_read = bytes;
        rep.new_chunks = nc;
        rep.new_bytes = nb;
    }
    store.commit_snapshot(&source, time, &[(TREE_INDEX, Index::Tree { entries: p.entries })])?;
    Ok(rep)
}
