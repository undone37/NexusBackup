//! Synthetic (clean-file) restore of a file-tree snapshot (Phase 33,
//! docs/control-plane.md "Synthetic restore"): the scheduler decides per file
//! which snapshot's version is the newest clean one (from the sealed name
//! indexes, YARA results, IOC hash lists and the 21a ransom-note / mass-rename
//! signals) and writes a [`Plan`]; the connector composes the restored tree
//! from the chosen snapshot and the older versions it names ([`compose`]).
//! Every chunk belongs to the tenant's store, so versions of different
//! snapshots can be mixed freely.

use crate::names::normalise;
use crate::store::{TreeEntry, TreeKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io;

/// What the scheduler decided (`synthetic.json` in the job directory).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    /// file-tree source (`host-…`, `nas-…`, `share-…`)
    pub source: String,
    /// the chosen snapshot: every entry not named below comes from it
    pub time: u64,
    /// request paths inside the snapshot (`/` = everything)
    pub paths: Vec<String>,
    /// older snapshot time → paths (index form, [`key`]) taken from it instead:
    /// substituted files and files a mass rename deleted
    #[serde(default)]
    pub take: BTreeMap<u64, Vec<String>>,
    /// paths left out (no clean version within the examined snapshots)
    #[serde(default)]
    pub drop: Vec<String>,
    /// the scheduler's counts, passed through into the job result
    #[serde(default)]
    pub stats: serde_json::Value,
}

/// A path as the name index stores it (no leading `/`, lossy UTF-8).
pub fn key(path: &[u8]) -> String {
    normalise(&String::from_utf8_lossy(path)).into_owned()
}

/// The composed tree and what could not be composed.
#[derive(Debug, Default, PartialEq)]
pub struct Composed {
    /// in index path order (parents before children)
    pub entries: Vec<TreeEntry>,
    /// planned paths missing from their snapshot (it changed since the plan)
    pub missing: Vec<String>,
    /// hard links left out because the file they point to was left out
    pub dangling: Vec<String>,
}

fn dir(path: Vec<u8>) -> TreeEntry {
    TreeEntry {
        path,
        kind: TreeKind::Dir,
        mode: 0o40755,
        uid: 0,
        gid: 0,
        size: 0,
        mtime_ns: 0,
        ctime_ns: 0,
        inode: 0,
        rdev: 0,
        link_target: None,
        xattrs: Vec::new(),
        chunks: Vec::new(),
        inconsistent: false,
    }
}

/// The ancestors of an index path (`a/b/c` → `a`, `a/b`).
fn ancestors(k: &str) -> impl Iterator<Item = &str> {
    k.match_indices('/').map(move |(i, _)| &k[..i])
}

/// Composes the restored tree: `base` (the tree of `plan.time`) without the
/// dropped and substituted paths, plus the planned versions from older
/// snapshots (`load(time)` returns that snapshot's tree; its directories fill in
/// parents the base lacks, e.g. of files a mass rename deleted).
pub fn compose(
    plan: &Plan,
    base: Vec<TreeEntry>,
    load: &mut dyn FnMut(u64) -> io::Result<Vec<TreeEntry>>,
) -> io::Result<Composed> {
    let replaced: BTreeSet<&str> = plan
        .drop
        .iter()
        .chain(plan.take.values().flatten())
        .map(String::as_str)
        .collect();
    let mut out: BTreeMap<String, TreeEntry> = base
        .into_iter()
        .map(|e| (key(&e.path), e))
        .filter(|(k, _)| !replaced.contains(k.as_str()))
        .collect();
    let mut missing = Vec::new();
    for (time, paths) in plan.take.iter().rev() {
        if paths.is_empty() {
            continue;
        }
        let mut tree: BTreeMap<String, TreeEntry> = load(*time)?.into_iter().map(|e| (key(&e.path), e)).collect();
        for p in paths {
            let Some(e) = tree.remove(p) else {
                missing.push(p.clone());
                continue;
            };
            for a in ancestors(p) {
                if !out.contains_key(a) {
                    let d = match tree.get(a) {
                        Some(d) if d.kind == TreeKind::Dir => d.clone(),
                        // same form as the file's own path (with or without the leading /)
                        _ => {
                            let lead: &[u8] = if e.path.starts_with(b"/") { b"/" } else { b"" };
                            dir([lead, a.as_bytes()].concat())
                        }
                    };
                    out.insert(a.to_owned(), d);
                }
            }
            out.insert(p.clone(), e);
        }
    }
    // a hard link whose file was left out cannot be restored
    let files: BTreeSet<String> = out
        .iter()
        .filter(|(_, e)| e.kind == TreeKind::File)
        .map(|(k, _)| k.clone())
        .collect();
    let mut dangling = Vec::new();
    out.retain(|k, e| {
        let ok = e.kind != TreeKind::Hardlink || e.link_target.as_deref().is_some_and(|t| files.contains(&key(t)));
        if !ok {
            dangling.push(k.clone());
        }
        ok
    });
    Ok(Composed {
        entries: out.into_values().collect(),
        missing,
        dangling,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, size: u64, chunk: u8) -> TreeEntry {
        TreeEntry {
            kind: TreeKind::File,
            size,
            mode: 0o100644,
            chunks: vec![[chunk; 32]],
            ..dir(path.as_bytes().to_vec())
        }
    }

    fn paths(c: &Composed) -> Vec<String> {
        c.entries.iter().map(|e| key(&e.path)).collect()
    }

    #[test]
    fn composes_from_older_versions() {
        let base = vec![
            dir(b"/docs".to_vec()),
            file("/docs/a.txt", 5, 1),
            file("/docs/b.txt", 5, 2),
            file("/docs/b.txt.lockbit", 9, 3),
            file("/README-DECRYPT.txt", 1, 4),
        ];
        let older = vec![
            dir(b"/docs".to_vec()),
            dir(b"/docs/old".to_vec()),
            file("/docs/b.txt", 4, 20),
            file("/docs/old/c.txt", 3, 21),
            file("/docs/a.txt", 5, 1),
        ];
        let plan = Plan {
            source: "host-a".into(),
            time: 2,
            paths: vec!["/".into()],
            take: BTreeMap::from([(
                1,
                vec!["docs/b.txt".into(), "docs/old/c.txt".into(), "docs/gone".into()],
            )]),
            drop: vec!["docs/b.txt.lockbit".into(), "README-DECRYPT.txt".into()],
            stats: serde_json::Value::Null,
        };
        let mut asked = Vec::new();
        let c = compose(&plan, base, &mut |t| {
            asked.push(t);
            Ok(older.clone())
        })
        .unwrap();
        assert_eq!(asked, [1]);
        assert_eq!(
            paths(&c),
            ["docs", "docs/a.txt", "docs/b.txt", "docs/old", "docs/old/c.txt"]
        );
        let b = c.entries.iter().find(|e| key(&e.path) == "docs/b.txt").unwrap();
        assert_eq!((b.size, b.chunks[0]), (4, [20; 32]), "the older version");
        assert_eq!(c.missing, ["docs/gone"]);
    }

    #[test]
    fn parents_and_hard_links() {
        let mut link = dir(b"/x/link".to_vec());
        link.kind = TreeKind::Hardlink;
        link.link_target = Some(b"/x/bad".to_vec());
        let base = vec![dir(b"/x".to_vec()), file("/x/bad", 1, 1), link];
        let older = vec![file("/y/z/kept", 2, 2)];
        let plan = Plan {
            time: 2,
            take: BTreeMap::from([(1, vec!["y/z/kept".into()])]),
            drop: vec!["x/bad".into()],
            ..Plan::default()
        };
        let c = compose(&plan, base, &mut |_| Ok(older.clone())).unwrap();
        assert_eq!(
            paths(&c),
            ["x", "y", "y/z", "y/z/kept"],
            "parents made up when the old tree lacks them"
        );
        assert_eq!(c.dangling, ["x/link"]);
        let p: Plan = serde_json::from_str(&serde_json::to_string(&plan).unwrap()).unwrap();
        assert_eq!(p, plan);
    }
}
