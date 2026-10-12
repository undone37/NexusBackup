//! Disk and file selection (Phase 15e, docs/control-plane.md "Disk and file
//! selection"): what the connectors get from the group, its policy and the source.
//! - PVE: `exclude_disks` (`{"*": ["scsi1"], "<vmid>": ["virtio2"]}`) → nexus-pve
//!   `exclude_disks` per vmid as device names (`drive-scsi1`), the restore mode and
//!   `parallel`;
//! - agents: the source's globs + the policy's global globs as `excludes`, and
//!   `filters` (include roots, regexes of source and policy, cross_mounts,
//!   skip_fstypes) + the agent's `limits` for `PrepareEx`;
//! - NAS shares: the same include / regex / global excludes in nas.json.

use crate::{Files, GroupRow};
use anyhow::Result;
use serde_json::{json, Map, Value};

/// A disk key of a guest config (`scsi1`, `virtio2`, `efidisk0`, `tpmstate0`).
pub fn valid_disk_key(k: &str) -> bool {
    let digits = k.trim_start_matches(|c: char| c.is_ascii_lowercase());
    k.len() <= 16
        && digits.len() < k.len()
        && !digits.is_empty()
        && digits.len() <= 3
        && digits.bytes().all(|b| b.is_ascii_digit())
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s.as_str().map(str::to_owned))
        .collect()
}

/// nexus-pve `exclude_disks`: per backed-up vmid the device names of its excluded
/// disks (the `*` list plus its own); vmids without excludes are left out.
pub fn pve_excludes(exclude_disks: &Value, vmids: &[u32]) -> Value {
    let all = strings(&exclude_disks["*"]);
    let mut out = Map::new();
    for v in vmids {
        let mut keys: Vec<String> = all
            .iter()
            .cloned()
            .chain(strings(&exclude_disks[v.to_string()]))
            .collect();
        keys.retain(|k| valid_disk_key(k));
        keys.sort();
        keys.dedup();
        if !keys.is_empty() {
            out.insert(
                v.to_string(),
                keys.iter().map(|k| format!("drive-{k}")).collect::<Vec<_>>().into(),
            );
        }
    }
    Value::Object(out)
}

/// Group options for nexus-pve's config.
pub fn pve_options(g: &GroupRow, vmids: &[u32]) -> Value {
    json!({
        "parallel": g.parallel,
        "exclude_disks": pve_excludes(&g.exclude_disks, vmids),
        "exclude_disks_mode": g.exclude_disks_mode,
    })
}

/// (globs, Filters JSON) of an agent backup: source settings + the policy's
/// global excludes (`policy` = `{}` for a backup outside any group).
pub fn agent_filters(src: &Value, policy: &Value) -> (Vec<String>, Value) {
    let mut globs = strings(&src["excludes"]);
    globs.extend(strings(&policy["exclude"]));
    let mut regex = strings(&src["exclude_regex"]);
    regex.extend(strings(&policy["exclude_regex"]));
    (
        globs,
        json!({
            "include": strings(&src["include"]),
            "exclude_regex": regex,
            "cross_mounts": src["cross_mounts"].as_bool().unwrap_or(false),
            "skip_fstypes": strings(&src["skip_fstypes"]),
        }),
    )
}

/// Agent limits as the protocol takes them (`{bwlimit, nice}`), missing = none.
pub fn agent_limits(limits: &Value) -> Value {
    json!({
        "bwlimit": limits["bwlimit"].as_u64().unwrap_or(0),
        "nice": limits["nice"].as_u64().unwrap_or(0).min(19),
    })
}

/// Adds the include roots, regexes and the policy's global excludes to nas.json.
pub fn patch_share_config(files: &mut Files, src: &Value, policy: &Value) -> Result<()> {
    let Some((_, body)) = files.iter_mut().find(|(n, _)| n == "nas.json") else {
        return Ok(());
    };
    let mut cfg: Value = serde_json::from_slice(body)?;
    let (globs, f) = agent_filters(src, policy);
    cfg["excludes"] = json!(globs);
    cfg["include"] = f["include"].clone();
    cfg["exclude_regex"] = f["exclude_regex"].clone();
    *body = serde_json::to_vec_pretty(&cfg)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclude_disk_params() {
        assert!(valid_disk_key("scsi1") && valid_disk_key("efidisk0") && valid_disk_key("tpmstate0"));
        for bad in ["scsi", "1", "drive-scsi1", "Scsi1", "scsi1a", "scsi1234", ""] {
            assert!(!valid_disk_key(bad), "{bad}");
        }
        let ex = json!({"*": ["scsi1", "bad key"], "101": ["virtio2", "scsi1"], "999": ["sata0"]});
        assert_eq!(
            pve_excludes(&ex, &[100, 101]),
            json!({"100": ["drive-scsi1"], "101": ["drive-scsi1", "drive-virtio2"]})
        );
        assert_eq!(pve_excludes(&json!({}), &[100]), json!({}));
        assert_eq!(
            pve_excludes(&json!({"101": ["ide2"]}), &[100, 101]),
            json!({"101": ["drive-ide2"]})
        );
    }

    #[test]
    fn agent_and_share_filters_merge_source_and_policy() {
        let src = json!({"agent_id": "a", "paths": ["/"], "excludes": ["*.tmp"], "include": ["/home"],
                         "exclude_regex": ["\\.bak$"], "cross_mounts": true});
        let pol = json!({"exclude": ["/var/cache/**"], "exclude_regex": ["~$"]});
        let (globs, f) = agent_filters(&src, &pol);
        assert_eq!(globs, ["*.tmp", "/var/cache/**"]);
        assert_eq!(
            f,
            json!({"include": ["/home"], "exclude_regex": ["\\.bak$", "~$"], "cross_mounts": true, "skip_fstypes": []})
        );
        let (globs, f) = agent_filters(&json!({"paths": ["/"]}), &json!({}));
        assert!(globs.is_empty());
        assert_eq!(f["cross_mounts"], false);
        assert_eq!(
            agent_limits(&json!({"bwlimit": 1000, "nice": 40})),
            json!({"bwlimit": 1000, "nice": 19})
        );
        assert_eq!(agent_limits(&json!({})), json!({"bwlimit": 0, "nice": 0}));
        let mut files: Files = vec![("nas.json".into(), br#"{"excludes": ["a"], "threads": 4}"#.to_vec())];
        patch_share_config(&mut files, &json!({"excludes": ["a"], "include": ["/p"]}), &pol).unwrap();
        let cfg: Value = serde_json::from_slice(&files[0].1).unwrap();
        assert_eq!(cfg["excludes"], json!(["a", "/var/cache/**"]));
        assert_eq!(cfg["include"], json!(["/p"]));
        assert_eq!(cfg["exclude_regex"], json!(["~$"]));
        assert_eq!(cfg["threads"], 4);
    }
}
