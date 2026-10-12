//! Disk and file selection (Phase 15e) and agent limits (15f), docs/control-plane.md
//! "Disk and file selection": validation of the group / policy / source fields and
//! `PUT /agents/{id}/limits`.
//!
//! - `groups.exclude_disks`: `{"*": ["scsi1"], "<vmid>": ["virtio2"]}` (PVE groups only),
//!   `exclude_disks_mode` `placeholder` | `omit`, `parallel_guests` 1..=8;
//! - `policies.file_filters`: `{exclude: [globs], exclude_regex: [regexes]}`, applied to
//!   every agent and share source of the policy's groups;
//! - linux sources: `include`, `exclude_regex`, `cross_mounts`, `skip_fstypes`; share
//!   sources: `include`, `exclude_regex`.
//!
//! Excluding more (a disk added to `exclude_disks`, a global exclude added) backs up
//! less: like a weaker policy it needs an approval (`group.update` / `policy.update`).

use crate::auth::Ctx;
use crate::{validate, ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::Json;
use catalog::rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const MAX_PARALLEL: u32 = 8;
const MAX_PATTERNS: usize = 256;

/// A disk key of a guest config (`scsi1`, `virtio2`, `efidisk0`, `tpmstate0`).
pub fn valid_disk_key(k: &str) -> bool {
    let digits = k.trim_start_matches(|c: char| c.is_ascii_lowercase());
    k.len() <= 16
        && digits.len() < k.len()
        && !digits.is_empty()
        && digits.len() <= 3
        && digits.bytes().all(|b| b.is_ascii_digit())
}

/// `exclude_disks` of a group on a source of `kind`; normalised (sorted, deduplicated,
/// empty lists dropped).
pub fn check_exclude_disks(v: &mut Value, kind: &str) -> ApiResult<()> {
    let bad = |m: &str| ApiError::bad(format!("exclude_disks: {m}"));
    let Some(map) = v.as_object_mut() else {
        return Err(bad("an object {\"*\": [disks], \"<vmid>\": [disks]}"));
    };
    if !map.is_empty() && kind != "pve" {
        return Err(bad("only for groups of a pve source"));
    }
    if map.len() > 1000 {
        return Err(bad("at most 1000 entries"));
    }
    for (k, list) in map.iter_mut() {
        if k != "*" {
            let vmid: u32 = k.parse().map_err(|_| bad("keys are \"*\" or vmids"))?;
            validate::vmid(vmid)?;
        }
        let Some(a) = list.as_array_mut() else {
            return Err(bad("values are lists of disk keys"));
        };
        if a.len() > 32 || a.iter().any(|d| !d.as_str().is_some_and(valid_disk_key)) {
            return Err(bad("up to 32 disk keys like scsi1, virtio2, sata0, efidisk0"));
        }
        a.sort_by(|x, y| x.as_str().cmp(&y.as_str()));
        a.dedup();
    }
    map.retain(|_, l| l.as_array().is_some_and(|a| !a.is_empty()));
    Ok(())
}

pub fn check_mode(mode: &str) -> ApiResult<()> {
    if mode == "placeholder" || mode == "omit" {
        Ok(())
    } else {
        Err(ApiError::bad("exclude_disks_mode: placeholder or omit"))
    }
}

pub fn check_parallel(n: u32) -> ApiResult<()> {
    if (1..=MAX_PARALLEL).contains(&n) {
        Ok(())
    } else {
        Err(ApiError::bad(format!("parallel_guests: 1..={MAX_PARALLEL}")))
    }
}

/// The Phase 15e/f fields of a group request on source `source_id`.
pub fn check_group_fields(
    c: &catalog::rusqlite::Connection,
    source_id: i64,
    exclude_disks: &mut Value,
    mode: &str,
    parallel: u32,
) -> ApiResult<()> {
    let kind: String = c
        .query_row("SELECT kind FROM sources WHERE id = ?1", [source_id], |r| r.get(0))
        .map_err(|_| ApiError::bad("source_id: no such source"))?;
    check_exclude_disks(exclude_disks, &kind)?;
    check_mode(mode)?;
    check_parallel(parallel)
}

pub fn no_disks() -> Value {
    json!({})
}

pub fn placeholder() -> String {
    "placeholder".into()
}

pub fn one() -> u32 {
    1
}

/// Some disk excluded by `new` but not by `old`.
pub fn disks_added(old: &Value, new: &Value) -> bool {
    new.as_object().into_iter().flatten().any(|(k, l)| {
        l.as_array()
            .into_iter()
            .flatten()
            .any(|d| !old[k].as_array().is_some_and(|o| o.contains(d)))
    })
}

fn patterns(list: &[String], what: &str) -> ApiResult<()> {
    if list.len() > MAX_PATTERNS {
        return Err(ApiError::bad(format!("{what}: at most {MAX_PATTERNS} entries")));
    }
    for x in list {
        if x.trim().is_empty() || x.contains(['\n', '\r']) {
            return Err(ApiError::bad(format!("{what}: one non-empty pattern per entry")));
        }
        validate::text(x, what, 4096)?;
    }
    Ok(())
}

pub fn check_regex(list: &[String], what: &str) -> ApiResult<()> {
    patterns(list, what)?;
    agent_core::filter::check_regex(list).map_err(|e| ApiError::bad(format!("{what}: {e}")))
}

/// Include roots: absolute paths (Windows agents: `C:\Users\alice` too).
pub fn check_include(list: &[String], what: &str) -> ApiResult<()> {
    patterns(list, what)?;
    for p in list {
        let b = p.as_bytes();
        let windows = b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/');
        if !windows {
            validate::host_path(p, what)?;
        }
    }
    Ok(())
}

pub fn check_fstypes(list: &[String]) -> ApiResult<()> {
    if list.len() > 64
        || list.iter().any(|t| {
            t.is_empty() || t.len() > 32 || !t.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
    {
        return Err(ApiError::bad(
            "config.skip_fstypes: up to 64 file system type names (ext4, tmpfs, fuse.sshfs)",
        ));
    }
    Ok(())
}

/// `policies.file_filters`.
#[derive(Deserialize, Serialize, Clone, Default, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
pub struct FileFilters {
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub exclude_regex: Vec<String>,
}

impl FileFilters {
    pub fn check(&self) -> ApiResult<()> {
        patterns(&self.exclude, "file_filters.exclude")?;
        check_regex(&self.exclude_regex, "file_filters.exclude_regex")
    }

    /// Anything excluded that was not before (backs up less).
    pub fn widened_by(&self, new: &FileFilters) -> bool {
        new.exclude.iter().any(|x| !self.exclude.contains(x))
            || new.exclude_regex.iter().any(|x| !self.exclude_regex.contains(x))
    }
}

/// Appliance-side limits of an agent (agent_proto::Limits).
#[derive(Deserialize, Serialize, Clone, Copy, Default)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// bytes per second for the data sent to the appliance, 0 = unlimited
    #[serde(default)]
    pub bwlimit: u64,
    /// 0 = normal priority, 1..=19 = nicer
    #[serde(default)]
    pub nice: u8,
}

/// `PUT /agents/{id}/limits` (admin, tenant admin of the agent's tenant): stored
/// on the agent, sent with every backup.
pub async fn set_agent_limits(
    State(st): State<St>,
    ctx: Ctx,
    Path(id): Path<String>,
    J(l): J<Limits>,
) -> ApiResult<Json<Value>> {
    ctx.require(crate::auth::TENANT_WRITERS)?;
    if l.nice > 19 {
        return Err(ApiError::bad("nice: 0..=19"));
    }
    if l.bwlimit != 0 && l.bwlimit < 64 << 10 {
        return Err(ApiError::bad("bwlimit: 0 (unlimited) or at least 65536 bytes/s"));
    }
    let old: String = st
        .cat
        .conn()
        .query_row(
            "SELECT limits FROM agents WHERE id = ?1 AND (?2 IS NULL OR tenant = ?2)",
            params![id, ctx.scope()],
            |r| r.get(0),
        )
        .map_err(|_| ApiError::not_found())?;
    st.cat.conn().execute(
        "UPDATE agents SET limits = ?2 WHERE id = ?1",
        params![id, json!(l).to_string()],
    )?;
    let old: Value = serde_json::from_str(&old).unwrap_or_default();
    st.audit(
        ctx.name(),
        "agent.limits",
        &format!("agent/{id}"),
        json!({"new": l, "old": old}),
    )?;
    let a = crate::agents::agent_value(&st.cat.conn(), &id)?.ok_or_else(ApiError::not_found)?;
    Ok(Json(a))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclude_disks_validation_and_widening() {
        let mut v = json!({"*": ["scsi1", "scsi1"], "101": ["virtio2", "efidisk0"], "102": []});
        check_exclude_disks(&mut v, "pve").unwrap();
        assert_eq!(v, json!({"*": ["scsi1"], "101": ["efidisk0", "virtio2"]}));
        for bad in [
            json!([]),
            json!({"x": ["scsi1"]}),
            json!({"*": ["drive-scsi1"]}),
            json!({"*": "scsi1"}),
        ] {
            assert!(check_exclude_disks(&mut bad.clone(), "pve").is_err(), "{bad}");
        }
        assert!(check_exclude_disks(&mut json!({"*": ["scsi1"]}), "linux").is_err());
        check_exclude_disks(&mut json!({}), "linux").unwrap();
        assert!(disks_added(&json!({}), &json!({"*": ["scsi1"]})));
        assert!(disks_added(
            &json!({"*": ["scsi1"]}),
            &json!({"*": ["scsi1"], "5": ["sata0"]})
        ));
        assert!(!disks_added(
            &json!({"*": ["scsi1", "scsi2"]}),
            &json!({"*": ["scsi2"]})
        ));
        assert!(check_parallel(0).is_err() && check_parallel(9).is_err() && check_parallel(8).is_ok());
        assert!(check_mode("omit").is_ok() && check_mode("drop").is_err());
    }

    #[test]
    fn filter_validation() {
        assert!(check_regex(&["(".into()], "x").is_err());
        assert!(check_regex(&[r"\.bak$".into()], "x").is_ok());
        assert!(check_include(&["/home".into(), r"C:\Users\alice".into()], "x").is_ok());
        assert!(check_include(&["home".into()], "x").is_err());
        assert!(check_include(&["/a/../b".into()], "x").is_err());
        assert!(check_fstypes(&["fuse.sshfs".into(), "tmpfs".into()]).is_ok());
        assert!(check_fstypes(&["a b".into()]).is_err());
        let a = FileFilters {
            exclude: vec!["*.tmp".into()],
            exclude_regex: vec![],
        };
        let mut b = a.clone();
        assert!(!a.widened_by(&b));
        b.exclude_regex.push("~$".into());
        assert!(a.widened_by(&b) && !b.widened_by(&a));
    }
}
