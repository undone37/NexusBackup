//! Source limits and per-snapshot facts of Phase 22b (docs/control-plane.md
//! "Concurrency caps and read limits", docs/pve-connector.md "VM identity"):
//! - PVE: `max_parallel` (caps the group's parallel guests), `storage_caps`
//!   (`{storage: n}`: at most n guests at once with a disk there) and
//!   `read_limit` go into pve.json; TrueNAS and NFS/SMB sources get `read_limit`.
//!   One backup job per source runs at a time (plan key `source:<id>`), so the
//!   caps bound everything the appliance reads from that source.
//! - TrueNAS "use existing snapshots": the periodic snapshot each newest store
//!   snapshot was read from (`snapshots.meta.zfs_snapshot`) goes into
//!   truenas.json as the `zfs diff` reference of the next run.
//! - VM identity: nexus-pve prints `identity vm-<id>/<time> {json}`; it is kept
//!   in `snapshots.meta.identity`, a changed identity (VMID reused) raises
//!   `vmid_reused`.

use crate::{Job, Scheduler};
use anyhow::Result;
use catalog::rusqlite::params;
use serde_json::{json, Map, Value};

/// PVE source limits into a nexus-pve config.
pub(crate) fn pve_limits(src: &Value, cfg: &mut Value) {
    if let Some(m) = src["max_parallel"].as_u64() {
        cfg["max_parallel"] = json!(m.clamp(1, 8));
    }
    if src["storage_caps"].is_object() {
        cfg["storage_caps"] = src["storage_caps"].clone();
    }
    if src["read_limit"].is_object() {
        cfg["read_limit"] = src["read_limit"].clone();
    }
}

/// `identity <source>/<time> {json}` lines of nexus-pve.
fn identities(log: &str) -> impl Iterator<Item = (&str, i64, Value)> {
    log.lines().filter_map(|l| {
        let (id, js) = l.strip_prefix("identity ")?.split_once(' ')?;
        let (s, t) = id.rsplit_once('/')?;
        let v: Value = serde_json::from_str(js).ok()?;
        let t = t.parse().ok()?;
        v.is_object().then_some((s, t, v))
    })
}

/// Adds `meta.identity` to the backup result's snapshots (job detail).
pub(crate) fn attach_identity(log: &str, snaps: &mut [Value]) {
    for (s, t, id) in identities(log) {
        if let Some(x) = snaps.iter_mut().find(|x| x["source"] == s && x["time"] == t) {
            if !x["meta"].is_object() {
                x["meta"] = json!({});
            }
            x["meta"]["identity"] = id;
        }
    }
}

/// Per-snapshot metadata of a (possibly partly failed) backup log: the VM
/// identity and the TrueNAS snapshot a dataset was read from.
pub(crate) fn backup_meta(log: &str) -> Vec<(String, i64, Value)> {
    let mut out: Vec<(String, i64, Value)> = identities(log)
        .map(|(s, t, id)| (s.to_owned(), t, json!({ "identity": id })))
        .collect();
    let res = log
        .lines()
        .find_map(|l| serde_json::from_str::<Value>(l.strip_prefix("result ")?).ok());
    for s in res.iter().flat_map(|r| r["snapshots"].as_array().into_iter().flatten()) {
        let (Some(src), Some(t), Some(z)) = (
            s["source"].as_str().filter(|x| x.starts_with("nas-")),
            s["time"].as_i64(),
            s["meta"]["zfs_snapshot"].as_str(),
        ) else {
            continue;
        };
        out.push((src.to_owned(), t, json!({ "zfs_snapshot": z })));
    }
    out
}

impl Scheduler {
    /// After a backup (ok or failed): keeps the snapshots' facts in
    /// `snapshots.meta` (merged) and raises `vmid_reused` for a changed VM identity.
    pub(crate) fn backup_meta_bookkeeping(&self, job: &Job, log: &str) -> Result<()> {
        for (src, t, m) in backup_meta(log) {
            self.db.conn().execute(
                "INSERT INTO snapshots (tenant, source, time, local, offsite, meta) VALUES (?1,?2,?3,1,0,?4)
                 ON CONFLICT (tenant, source, time) DO UPDATE SET meta = json_patch(COALESCE(meta,'{}'), ?4)",
                params![job.tenant, src, t, m.to_string()],
            )?;
            let id = &m["identity"];
            if id["changed"] == true {
                let old = &id["previous"];
                self.raise(
                    "warning",
                    "vmid_reused",
                    &format!("vmid_reused:{}/{src}", job.tenant),
                    &format!(
                        "{src}: the VM identity changed in snapshot {t} (vmgenid {} → {}, SMBIOS UUID {} → {}): \
                         the VMID was reused or the VM replaced; older snapshots of {src} belong to the previous VM",
                        old["vmgenid"].as_str().unwrap_or("?"),
                        id["vmgenid"].as_str().unwrap_or("?"),
                        old["smbios_uuid"].as_str().unwrap_or("?"),
                        id["smbios_uuid"].as_str().unwrap_or("?"),
                    ),
                    Some(&job.tenant),
                )?;
            }
        }
        Ok(())
    }

    /// TrueNAS source limits and the "use existing snapshots" references.
    pub(crate) fn truenas_limits(&self, tenant: &str, source_id: i64, src: &Value, cfg: &mut Value) -> Result<()> {
        if src["read_limit"].is_object() {
            cfg["read_limit"] = src["read_limit"].clone();
        }
        let Some(prefix) = src["existing_snapshots"].as_str() else {
            return Ok(());
        };
        cfg["existing_snapshots"] = json!(prefix);
        let c = self.db.conn();
        let mut st = c.prepare(
            "SELECT source, MAX(time), json_extract(meta, '$.zfs_snapshot') FROM snapshots \
             WHERE tenant = ?1 AND source LIKE ?2 AND json_extract(meta, '$.zfs_snapshot') IS NOT NULL GROUP BY source",
        )?;
        let rows = st.query_map(params![tenant, format!("nas-{source_id}-%")], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?))
        })?;
        let mut refs = Map::new();
        for r in rows {
            let (s, t, z) = r?;
            refs.insert(s, json!({"time": t, "snapshot": z}));
        }
        cfg["references"] = Value::Object(refs);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_from_a_backup_log() {
        let log = "committed vm-100/1700000000\n\
                   identity vm-100/1700000000 {\"vmgenid\":\"b\",\"smbios_uuid\":\"u2\",\"changed\":true,\"previous\":{\"vmgenid\":\"a\",\"smbios_uuid\":\"u1\"}}\n\
                   identity broken\n\
                   result {\"snapshots\":[{\"source\":\"nas-3-tank.data\",\"time\":5,\"meta\":{\"zfs_snapshot\":\"auto-1\"}},{\"source\":\"plugin-x-1\",\"time\":6,\"meta\":{\"zfs_snapshot\":\"no\"}}]}\n";
        let m = backup_meta(log);
        assert_eq!(m.len(), 2, "{m:?}");
        assert_eq!(m[0].0, "vm-100");
        assert_eq!(m[0].2["identity"]["changed"], true);
        assert_eq!(
            m[1],
            ("nas-3-tank.data".to_string(), 5, json!({"zfs_snapshot": "auto-1"}))
        );
        let mut snaps = vec![json!({"source": "vm-100", "time": 1700000000})];
        attach_identity(log, &mut snaps);
        assert_eq!(snaps[0]["meta"]["identity"]["previous"]["vmgenid"], "a");
    }

    #[test]
    fn pve_limits_into_the_config() {
        let mut cfg = json!({"parallel": 4});
        pve_limits(
            &json!({"max_parallel": 20, "storage_caps": {"ceph": 2}, "read_limit": {"bwlimit": 5}}),
            &mut cfg,
        );
        assert_eq!(cfg["max_parallel"], 8);
        assert_eq!(cfg["storage_caps"]["ceph"], 2);
        assert_eq!(cfg["read_limit"]["bwlimit"], 5);
        let mut plain = json!({});
        pve_limits(&json!({}), &mut plain);
        assert_eq!(plain, json!({}));
    }
}
