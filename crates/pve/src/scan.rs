//! Opt-in YARA scan of a snapshot (Phase 21e, docs/malware-scan.md):
//! `nexus-pve <cfg> scan <source> <time> <rules.json> [budget-secs] [--stop-on-match]`.
//!
//! The scanner (`yara`) runs only inside the restore micro-VM (no NIC,
//! read-only disks, `-sandbox on`):
//!
//! - VM snapshots: the disks are attached as for single-file restore and the
//!   agent scans every mounted guest file system;
//! - container snapshots: the root tar is streamed into the VM;
//! - file-tree snapshots (agents, NAS, shares, plugins): the appliance builds a
//!   tar of the regular files from the store and streams it into the VM.
//!
//! Prints the report: `{files, skipped, errors, matches: [{rule, path}],
//! matches_total, complete, stopped, seconds}`; `rule` is `<rule file>:<rule name>`.
//!
//! Scan back (Phase 29): the scheduler runs one `scan ... --stop-on-match` per
//! snapshot, newest first, until one is complete without a match (the last
//! clean restore point). `--stop-on-match` sends `stop_on_match` in the
//! limits: the VM agent ends at the first hit (`stopped: true`, `complete:
//! false`), so an infected snapshot costs seconds, not its budget. Only then
//! is the field sent, so an older VM image (unknown fields refused) still
//! serves plain scans.
//!
//! Manual CLI of the same walk: `nexus-pve <cfg> scan-back <source>
//! <from-time> <rules.json> [budget-secs-per-snapshot] [max-snapshots]`.
//! Progress on stderr, the result JSON on stdout: `{source, from, scanned:
//! [{time, files, skipped, errors, matches_total, matches (at most 20),
//! complete, stopped, seconds}], recommended, truncated}`.

use crate::restorevm::{self, Config};
use anyhow::{bail, Context, Result};
use chunkstore::{Index, Manifest, Store, TreeKind};
use std::ffi::OsStr;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::time::Duration;

/// files above this size are not scanned (counted as `skipped`)
pub const MAX_SIZE: u64 = 64 << 20;
/// seconds per file (`yara -a`)
pub const FILE_TIMEOUT: u32 = 60;
/// seconds for the whole scan unless the job says otherwise
pub const BUDGET: u64 = 4 * 3600;
/// rules sent into the VM at most (all files together)
pub const MAX_RULES_BYTES: usize = 1 << 20;
/// scan back: snapshots scanned at most unless the job says otherwise
pub const BACK_MAX: usize = 30;
/// scan back: matches listed per snapshot
const BACK_MATCHES: usize = 20;

/// Writes the regular files of a file-tree snapshot as a tar; returns the
/// number of files skipped (larger than `max_size`, or names a tar cannot hold).
pub fn tree_tar(store: &Store, m: &Manifest, max_size: u64, w: &mut dyn Write) -> Result<u64> {
    let mut b = tar::Builder::new(w);
    let mut skipped = 0;
    let mut add =
        |b: &mut tar::Builder<&mut dyn Write>, path: &[u8], size: u64, chunks: &[chunkstore::ChunkId]| -> Result<()> {
            if size > max_size {
                skipped += 1;
                return Ok(());
            }
            let mut h = tar::Header::new_gnu();
            h.set_size(size);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            let r = store.chunk_reader(chunks);
            match b.append_data(&mut h, OsStr::from_bytes(path.strip_prefix(b"/").unwrap_or(path)), r) {
                Ok(()) => Ok(()),
                // `..` or an empty name: never extracted anyway, but a tar cannot carry it
                Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
                    skipped += 1;
                    Ok(())
                }
                Err(e) => Err(e.into()),
            }
        };
    for name in &m.indexes {
        match store.load_index(m, name)? {
            Index::Tree { entries } => {
                for e in entries.iter().filter(|e| e.kind == TreeKind::File) {
                    add(&mut b, &e.path, e.size, &e.chunks)?;
                }
            }
            Index::Dynamic { entries } => {
                for e in &entries {
                    add(&mut b, format!("{name}/{}", e.path).as_bytes(), e.size, &e.chunks)?;
                }
            }
            Index::Fixed { .. } => {}
        }
    }
    b.finish()?;
    Ok(skipped)
}

/// The scan limits sent to the agent (`stop_on_match` only when set: older VM
/// images refuse unknown fields).
pub fn limits(budget: u64, threads: u32, stop_on_match: bool) -> serde_json::Value {
    let mut l =
        serde_json::json!({"max_size": MAX_SIZE, "file_timeout": FILE_TIMEOUT, "budget": budget, "threads": threads});
    if stop_on_match {
        l["stop_on_match"] = serde_json::json!(true);
    }
    l
}

fn read_rules(rules: &std::path::Path) -> Result<serde_json::Value> {
    let text = std::fs::read(rules).with_context(|| format!("rules {}", rules.display()))?;
    if text.len() > 2 * MAX_RULES_BYTES {
        bail!("rules: more than {MAX_RULES_BYTES} bytes");
    }
    let rules: serde_json::Value = serde_json::from_slice(&text).context("rules: [{name, text}]")?;
    if rules.as_array().is_none_or(|a| a.is_empty()) {
        bail!("no YARA rules");
    }
    Ok(rules)
}

pub fn cli(
    store: &Store,
    source: &str,
    time: u64,
    rules: &std::path::Path,
    budget: Option<u64>,
    stop_on_match: bool,
) -> Result<()> {
    let rules = read_rules(rules)?;
    let mut report = scan(store, source, time, &rules, budget, stop_on_match)?;

    report["source"] = serde_json::json!(source);
    report["time"] = serde_json::json!(time);
    println!("{report}");
    Ok(())
}

/// Scan back from `from` (module docs); prints the result JSON.
pub fn back_cli(
    store: &Store,
    source: &str,
    from: u64,
    rules: &std::path::Path,
    budget: Option<u64>,
    max: Option<usize>,
) -> Result<()> {
    let rules = read_rules(rules)?;
    let times: Vec<u64> = store
        .list_snapshots()?
        .into_iter()
        .filter(|m| m.source == source && m.time <= from)
        .map(|m| m.time)
        .collect();
    if times.is_empty() {
        bail!("no snapshot of {source} at or before {from}");
    }
    let out = back(source, from, times, max.unwrap_or(BACK_MAX).max(1), |t| {
        scan(store, source, t, &rules, budget, true)
    })?;
    println!("{out}");
    Ok(())
}

/// The scan-back loop over `times` (any order), `scan` = one snapshot's report.
fn back(
    source: &str,
    from: u64,
    mut times: Vec<u64>,
    max: usize,
    mut scan: impl FnMut(u64) -> Result<serde_json::Value>,
) -> Result<serde_json::Value> {
    times.sort_unstable_by(|a, b| b.cmp(a));
    let (mut scanned, mut recommended) = (Vec::new(), None);
    for &t in times.iter().take(max) {
        let r = scan(t).with_context(|| format!("scan of {source}/{t}"))?;
        let n = r["matches_total"].as_u64().unwrap_or(0);
        let complete = r["complete"].as_bool().unwrap_or(false);
        let state = match (n, complete) {
            (0, true) => "clean".to_owned(),
            (0, false) => "incomplete".to_owned(),
            (n, _) => format!("{n} matches"),
        };
        eprintln!("scan-back {source}/{t}: {state}");
        let matches: Vec<serde_json::Value> = r["matches"]
            .as_array()
            .map(|a| a.iter().take(BACK_MATCHES).cloned().collect())
            .unwrap_or_default();
        scanned.push(serde_json::json!({
            "time": t, "files": r["files"], "skipped": r["skipped"], "errors": r["errors"],
            "matches_total": n, "matches": matches, "complete": complete,
            "stopped": r["stopped"].as_bool().unwrap_or(false), "seconds": r["seconds"],
        }));
        if n == 0 && complete {
            recommended = Some(t);
            break;
        }
    }
    let truncated = recommended.is_none() && times.len() > scanned.len();
    Ok(serde_json::json!({
        "source": source, "from": from, "scanned": scanned, "recommended": recommended, "truncated": truncated,
    }))
}

/// One snapshot's scan in the restore micro-VM; returns the agent's report.
fn scan(
    store: &Store,
    source: &str,
    time: u64,
    rules: &serde_json::Value,
    budget: Option<u64>,
    stop_on_match: bool,
) -> Result<serde_json::Value> {
    let budget = budget.unwrap_or(BUDGET).clamp(60, 24 * 3600);
    let m = store.load_manifest(source, time)?;
    let cfg = Config::from_env();
    let limits = limits(budget, cfg.cpus, stop_on_match);
    // the agent stops at its budget; the margin covers boot, rule compilation and the last batch
    let wait = Duration::from_secs(budget + 600);
    let report = if source.starts_with("vm-") {
        let mut disks = Vec::new();
        for name in &m.indexes {
            let idx = store.load_index(&m, name)?;
            if matches!(idx, Index::Fixed { .. }) {
                disks.push((name.as_str(), idx));
            }
        }
        if disks.is_empty() {
            bail!("snapshot has no disk images");
        }
        let refs: Vec<(&str, &Index)> = disks.iter().map(|(n, i)| (*n, i)).collect();
        restorevm::with_vm(store, &refs, &cfg, |vm| {
            vm.rules(rules)?;
            vm.scan(&limits, wait)
        })?
    } else if source.starts_with("ct-") {
        let root = crate::ct::root_tar(store, &m)?;
        restorevm::with_vm(store, &[], &cfg, |vm| {
            vm.rules(rules)?;
            vm.scan_tar(&limits, wait, |w| {
                std::io::copy(&mut store.chunk_reader(&root.chunks), w)?;
                Ok(())
            })
        })?
    } else {
        let mut skipped = 0;
        let mut r = restorevm::with_vm(store, &[], &cfg, |vm| {
            vm.rules(rules)?;
            vm.scan_tar(&limits, wait, |w| {
                skipped = tree_tar(store, &m, MAX_SIZE, w)?;
                Ok(())
            })
        })?;
        r["skipped"] = serde_json::json!(r["skipped"].as_u64().unwrap_or(0) + skipped);
        r
    };
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chunkstore::{Keyring, Options, TreeEntry};

    fn entry(path: &str, kind: TreeKind, chunks: Vec<chunkstore::ChunkId>, size: u64) -> TreeEntry {
        TreeEntry {
            path: path.as_bytes().to_vec(),
            kind,
            mode: 0o644,
            uid: 0,
            gid: 0,
            size,
            mtime_ns: 0,
            ctime_ns: 0,
            inode: 0,
            rdev: 0,
            link_target: None,
            xattrs: vec![],
            chunks,
            inconsistent: false,
        }
    }

    /// Regular files of a tree become tar entries; large files and other kinds stay out.
    #[test]
    fn tree_to_tar() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path(), Keyring::new("t", &[(1, [3; 32])]), Options::default()).unwrap();
        let (small, n) = s.store_file(&b"X5O!P%@AP"[..]).unwrap();
        let (big, nb) = s.store_file(&vec![7u8; 100][..]).unwrap();
        let entries = vec![
            entry("docs", TreeKind::Dir, vec![], 0),
            entry("docs/eicar.com", TreeKind::File, small, n),
            entry("docs/big.bin", TreeKind::File, big, nb),
            entry("docs/link", TreeKind::Symlink, vec![], 0),
        ];
        let m = s
            .commit_snapshot("host-a", 1, &[("files", Index::Tree { entries })])
            .unwrap();
        let mut out = Vec::new();
        let skipped = tree_tar(&s, &m, 50, &mut out).unwrap();
        assert_eq!(skipped, 1);
        let mut a = tar::Archive::new(&out[..]);
        let got: Vec<(String, u64)> = a
            .entries()
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (e.path().unwrap().display().to_string(), e.header().size().unwrap())
            })
            .collect();
        assert_eq!(got, [("docs/eicar.com".to_owned(), 9)]);
    }

    #[test]
    fn stop_on_match_only_when_asked() {
        assert!(limits(60, 2, false).get("stop_on_match").is_none());
        assert_eq!(limits(60, 2, true)["stop_on_match"], true);
    }

    fn report(matches: u64, complete: bool) -> serde_json::Value {
        let m: Vec<_> = (0..matches.min(30))
            .map(|i| serde_json::json!({"rule": "r:X", "path": format!("/f{i}")}))
            .collect();
        serde_json::json!({"files": 3, "skipped": 0, "errors": 0, "matches": m, "matches_total": matches,
                           "complete": complete, "stopped": matches > 0, "seconds": 1})
    }

    /// Newest first, past infected and incomplete scans, to the first clean one.
    #[test]
    fn scan_back_stops_at_the_first_clean_snapshot() {
        let mut asked = Vec::new();
        let out = back("vm-101", 50, vec![10, 50, 40, 30, 20], 30, |t| {
            asked.push(t);
            Ok(match t {
                50 => report(40, false),
                40 => report(0, false),
                _ => report(0, true),
            })
        })
        .unwrap();
        assert_eq!(asked, [50, 40, 30]);
        assert_eq!(out["recommended"], 30);
        assert_eq!(out["truncated"], false);
        assert_eq!(out["scanned"][0]["matches"].as_array().unwrap().len(), BACK_MATCHES);
        assert_eq!(out["scanned"][0]["matches_total"], 40);
        assert_eq!(out["scanned"][0]["stopped"], true);
        assert_eq!(out["scanned"][1]["complete"], false);
        // all infected and the limit reached before a clean one
        let out = back("vm-101", 50, vec![50, 40, 30], 2, |_| Ok(report(1, false))).unwrap();
        assert_eq!(out["recommended"], serde_json::Value::Null);
        assert_eq!(out["truncated"], true);
        assert_eq!(out["scanned"].as_array().unwrap().len(), 2);
        // all infected, nothing older left: not truncated
        let out = back("vm-101", 50, vec![50], 2, |_| Ok(report(1, false))).unwrap();
        assert_eq!(out["truncated"], false);
    }
}
