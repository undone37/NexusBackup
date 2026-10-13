//! One backup run of a share: pick the scan root (the share root, or the
//! newest NAS snapshot below the configured snapshot directory), scan it
//! against the previous snapshot ([`crate::scan`]), commit
//! `share-<source>/<time>` (`Index::Tree`, index `tree`).
//!
//! Consistency: only a NAS snapshot gives a point in time. Without one (none
//! configured, or none found) the snapshot is committed with `consistent =
//! false`; files that changed while they were read are marked `inconsistent`
//! either way, entries that could not be read are reported (and also make the
//! snapshot not consistent).
//!
//! Scheduled full read (Phase 29, `Spec::full_read`): the scan runs without the
//! previous snapshot (no metadata cache: every file is read), and the result
//! is compared with it (`chunkstore::drift`): a file with the cache key of the
//! previous entry (size, mtime, ctime, inode) but other chunks is one the
//! cache would have kept stale. Logged as one `full-read <source>/<time> {json}`
//! line after the commit.

use crate::mount::{self, Order};
use crate::scan::{self, Prev, Report};
use crate::{source_name, TREE_INDEX};
use anyhow::{bail, Result};
use chunkstore::drift::{self, Drift};
use chunkstore::{Index, Store, TreeEntry};
use std::os::fd::OwnedFd;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Snap {
    /// below the share root, e.g. `.zfs/snapshot`, `.snapshot`, `~snapshot`
    pub dir: String,
    /// only names starting with this (e.g. `auto-`, `hourly.`)
    pub prefix: String,
    pub order: Order,
}

pub struct Spec {
    pub source_id: u64,
    pub scan: scan::Options,
    pub snapshot: Option<Snap>,
    /// Phase 29: ignore the metadata cache, compare with the previous snapshot
    pub full_read: bool,
}

#[derive(Debug)]
pub struct Outcome {
    pub source: String,
    pub time: u64,
    /// the NAS snapshot read (None: live share)
    pub snapshot: Option<String>,
    pub consistent: bool,
    /// a previous snapshot was used as metadata cache
    pub incremental: bool,
    pub report: Report,
    /// Phase 29: the comparison of a full read (`Spec::full_read`)
    pub full_read: Option<Drift>,
}

pub fn load_tree(store: &Store, source: &str, time: u64) -> Result<Vec<TreeEntry>> {
    let m = store.load_manifest(source, time)?;
    match store.load_index(&m, TREE_INDEX)? {
        Index::Tree { entries } => Ok(entries),
        _ => bail!("{source}/{time} is not a file tree snapshot"),
    }
}

/// Newest committed snapshot time of `source`.
pub fn latest(store: &Store, source: &str) -> Result<Option<u64>> {
    Ok(store
        .list_snapshots()?
        .into_iter()
        .filter(|m| m.source == source)
        .map(|m| m.time)
        .max())
}

pub fn backup(store: &Store, share_root: &OwnedFd, spec: &Spec, log: &(dyn Fn(&str) + Sync)) -> Result<Outcome> {
    let source = source_name(spec.source_id);
    let prev_time = latest(store, &source)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let time = prev_time.map_or(now, |p| now.max(p + 1));
    let prev_tree = match prev_time {
        Some(t) => match load_tree(store, &source, t) {
            Ok(tr) => Some(tr),
            Err(e) => {
                log(&format!(
                    "previous snapshot {source}/{t} unreadable ({e:#}): reading everything"
                ));
                None
            }
        },
        None => None,
    };
    if spec.full_read {
        log("full read (Phase 29): every file is read, the metadata cache is not used");
    }
    let prev = prev_tree.as_deref().filter(|_| !spec.full_read).map(Prev::new);

    let mut snapshot = None;
    let snap_fd;
    let root = match &spec.snapshot {
        Some(s) => match mount::newest_snapshot(share_root, &s.dir, &s.prefix, s.order)? {
            Some((name, fd)) => {
                log(&format!("reading NAS snapshot {}/{name}", s.dir));
                snapshot = Some(name);
                snap_fd = fd;
                &snap_fd
            }
            None => {
                log(&format!(
                    "no snapshot {}* in {}: reading the live share (not consistent)",
                    s.prefix, s.dir
                ));
                share_root
            }
        },
        None => share_root,
    };
    let (entries, report) = scan::scan(store, root, &spec.scan, prev.as_ref(), log)?;
    drop(prev);
    let full_read = spec.full_read.then(|| match (&prev_tree, prev_time) {
        (Some(old), Some(t)) => {
            let mut d = Drift::new("metadata-cache", Some(t));
            drift::tree(&mut d, old, &entries, drift::metadata_differs);
            d
        }
        _ => Drift::none(),
    });
    drop(prev_tree);
    store.commit_snapshot(&source, time, &[(TREE_INDEX, Index::Tree { entries })])?;
    if let Some(d) = &full_read {
        log(&d.line(&source, time));
    }
    let consistent = snapshot.is_some() && report.inconsistent == 0 && report.error_count == 0;
    Ok(Outcome {
        source,
        time,
        snapshot,
        consistent,
        incremental: prev_time.is_some() && !spec.full_read,
        report,
        full_read,
    })
}
