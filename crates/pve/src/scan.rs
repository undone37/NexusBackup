//! Opt-in YARA scan of a snapshot (Phase 21e, docs/malware-scan.md):
//! `nexus-pve <cfg> scan <source> <time> <rules.json> [budget-secs]`.
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
//! matches_total, complete, seconds}`; `rule` is `<rule file>:<rule name>`.

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

/// The scan limits sent to the agent.
pub fn limits(budget: u64, threads: u32) -> serde_json::Value {
    serde_json::json!({"max_size": MAX_SIZE, "file_timeout": FILE_TIMEOUT, "budget": budget, "threads": threads})
}

pub fn cli(store: &Store, source: &str, time: u64, rules: &std::path::Path, budget: Option<u64>) -> Result<()> {
    let text = std::fs::read(rules).with_context(|| format!("rules {}", rules.display()))?;
    if text.len() > 2 * MAX_RULES_BYTES {
        bail!("rules: more than {MAX_RULES_BYTES} bytes");
    }
    let rules: serde_json::Value = serde_json::from_slice(&text).context("rules: [{name, text}]")?;
    if rules.as_array().is_none_or(|a| a.is_empty()) {
        bail!("no YARA rules");
    }
    let budget = budget.unwrap_or(BUDGET).clamp(60, 24 * 3600);
    let m = store.load_manifest(source, time)?;
    let cfg = Config::from_env();
    let limits = limits(budget, cfg.cpus);
    // the agent stops at its budget; the margin covers boot, rule compilation and the last batch
    let wait = Duration::from_secs(budget + 600);
    let mut report = if source.starts_with("vm-") {
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
            vm.rules(&rules)?;
            vm.scan(&limits, wait)
        })?
    } else if source.starts_with("ct-") {
        let root = crate::ct::root_tar(store, &m)?;
        restorevm::with_vm(store, &[], &cfg, |vm| {
            vm.rules(&rules)?;
            vm.scan_tar(&limits, wait, |w| {
                std::io::copy(&mut store.chunk_reader(&root.chunks), w)?;
                Ok(())
            })
        })?
    } else {
        let mut skipped = 0;
        let mut r = restorevm::with_vm(store, &[], &cfg, |vm| {
            vm.rules(&rules)?;
            vm.scan_tar(&limits, wait, |w| {
                skipped = tree_tar(store, &m, MAX_SIZE, w)?;
                Ok(())
            })
        })?;
        r["skipped"] = serde_json::json!(r["skipped"].as_u64().unwrap_or(0) + skipped);
        r
    };
    report["source"] = serde_json::json!(source);
    report["time"] = serde_json::json!(time);
    println!("{report}");
    Ok(())
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
}
