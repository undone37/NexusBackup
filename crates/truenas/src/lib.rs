//! TrueNAS connector (docs/truenas-connector.md): ZFS snapshots through the
//! TrueNAS JSON-RPC 2.0 WebSocket API, change list (`zfs diff`), metadata walk
//! and changed-file contents streamed from `.zfs/snapshot/<snap>` over SSH to a
//! restricted user whose forced command ([`fc`]) only runs standard tools.
//! Every dataset becomes an `Index::Tree` snapshot `nas-<source>-<dataset>`;
//! unchanged files reuse the previous snapshot's keyed chunk IDs.
//! CLI: `nexus-truenas` (spawned by the scheduler like `nexus-pve`).
//!
//! Everything that comes from TrueNAS (API answers, `zfs diff`, the walk and
//! the tar stream) is treated as hostile input (threat model T12-like): strict
//! parsers with limits, validated paths, nothing from it reaches a shell or a
//! file system path on the appliance.

//!
//! Without the `connector` feature only names/validation and the forced
//! command generator are built (used by web-api and scheduler).

#[cfg(feature = "connector")]
pub mod api;
#[cfg(feature = "connector")]
pub mod backup;
#[cfg(feature = "connector")]
pub mod diff;
pub mod fc;
#[cfg(feature = "connector")]
pub mod remote;
#[cfg(feature = "connector")]
pub mod stream;
#[cfg(feature = "connector")]
pub mod tree;
#[cfg(feature = "connector")]
pub mod walk;

/// Index name inside a dataset snapshot (same as agent host snapshots).
pub const TREE_INDEX: &str = "tree";

/// Upper bound for paths and symlink targets from TrueNAS (Linux PATH_MAX).
pub const MAX_PATH: usize = 4096;

fn component_ok(c: &str) -> bool {
    !c.is_empty()
        && c.len() <= 200
        && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        && !c.starts_with('-')
}

/// Dataset names the connector accepts: `pool/a/b`, components of
/// `[A-Za-z0-9_-]` (no leading `-`). Stricter than ZFS (no `.`, `:` or space):
/// the name is part of the snapshot source (`/` → `.`) and of forced-command
/// arguments, so the mapping stays injective and shell-inert.
pub fn valid_dataset(s: &str) -> bool {
    s.len() <= 200 && s.split('/').all(component_ok)
}

/// Is `ds` the dataset `root` itself or below it?
pub fn under(ds: &str, root: &str) -> bool {
    ds == root || ds.strip_prefix(root).is_some_and(|r| r.starts_with('/'))
}

/// Store source of a dataset: `nas-<source-id>-<pool.a.b>`.
pub fn source_name(source_id: u64, dataset: &str) -> String {
    format!("nas-{source_id}-{}", dataset.replace('/', "."))
}

/// Inverse of [`source_name`]: (source id, dataset).
pub fn parse_source_name(s: &str) -> Option<(u64, String)> {
    let rest = s.strip_prefix("nas-")?;
    let (id, ds) = rest.split_once('-')?;
    if id.is_empty() || id.starts_with('0') || !id.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let ds = ds.replace('.', "/");
    valid_dataset(&ds).then(|| Some((id.parse().ok()?, ds)))?
}

/// ZFS snapshot name the connector creates: `nexus-<source-id>-<time>`.
pub fn snap_name(source_id: u64, time: u64) -> String {
    format!("nexus-{source_id}-{time}")
}

/// Time of one of *this source's* snapshots (`nexus-<source-id>-<time>`), else None.
/// Snapshots of other sources and all user snapshots are never touched.
pub fn parse_snap_name(source_id: u64, name: &str) -> Option<u64> {
    let t = name.strip_prefix(&format!("nexus-{source_id}-"))?;
    (!t.is_empty() && t.len() <= 20 && !t.starts_with('0') && t.bytes().all(|b| b.is_ascii_digit()))
        .then(|| t.parse().ok())?
}

/// Relative path from TrueNAS: raw bytes, `/`-separated, no empty, `.` or `..`
/// component, no NUL, at most [`MAX_PATH`] bytes.
pub fn valid_rel_path(p: &[u8]) -> bool {
    !p.is_empty()
        && p.len() <= MAX_PATH
        && !p.contains(&0)
        && p.split(|b| *b == b'/')
            .all(|c| !c.is_empty() && c != b"." && c != b"..")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for ok in ["tank", "tank/data", "tank/a_b/c-1", "p0/x"] {
            assert!(valid_dataset(ok), "{ok}");
        }
        for bad in [
            "", "tank/", "/tank", "tank//a", "tank/a.b", "tank/a b", "tank/-x", "tank/a:b", "tank/ä", "t\n",
        ] {
            assert!(!valid_dataset(bad), "{bad:?}");
        }
        assert!(under("tank/a", "tank/a") && under("tank/a/b", "tank/a"));
        assert!(!under("tank/ab", "tank/a") && !under("tank", "tank/a"));
        let s = source_name(3, "tank/data/projects");
        assert_eq!(s, "nas-3-tank.data.projects");
        assert_eq!(parse_source_name(&s), Some((3, "tank/data/projects".into())));
        for bad in [
            "nas-03-tank",
            "nas--tank",
            "nas-3-",
            "nas-3-tank..a",
            "vm-100",
            "nas-3-tank.a b",
        ] {
            assert_eq!(parse_source_name(bad), None, "{bad}");
        }
        assert_eq!(snap_name(3, 1700000000), "nexus-3-1700000000");
        assert_eq!(parse_snap_name(3, "nexus-3-1700000000"), Some(1700000000));
        for bad in [
            "nexus-4-1700000000",
            "nexus-3-",
            "nexus-3-0170",
            "nexus-3-17x",
            "auto-2026",
            "nexus-31-5",
        ] {
            assert_eq!(parse_snap_name(3, bad), None, "{bad}");
        }
    }
}
