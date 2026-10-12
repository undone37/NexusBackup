//! Guest inventory (Phase 13c, auto-protect): every VM and container of the
//! cluster from `/cluster/resources?type=vm`, with the tags groups select on:
//! `type:qemu|lxc`, `node:<node>`, `pool:<pool>`, `tag:<tag>` (PVE tags). Templates
//! are left out: they cannot be backed up (fleecing), an `all` group would fail on them.
//! Output of `nexus-pve <cfg> inventory`: `{"guests": [{id, title, kind, tags}]}`.

use crate::api::Api;
use anyhow::Result;
use serde_json::{json, Value};

/// Guests of a `/cluster/resources?type=vm` answer, ordered by vmid.
pub fn parse(resources: &Value) -> Vec<Value> {
    let mut out: Vec<(u64, Value)> = resources
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| {
            let vmid = r["vmid"].as_u64().filter(|v| (1..=999_999_999).contains(v))?;
            let kind = r["type"].as_str().filter(|t| *t == "qemu" || *t == "lxc")?;
            if r["template"].as_u64() == Some(1) {
                return None;
            }
            let mut tags = vec![format!("type:{kind}")];
            if let Some(n) = r["node"].as_str().filter(|n| !n.is_empty()) {
                tags.push(format!("node:{n}"));
            }
            if let Some(p) = r["pool"].as_str().filter(|p| !p.is_empty()) {
                tags.push(format!("pool:{p}"));
            }
            // PVE lists tags separated by `;` (older versions also `,` / spaces)
            for t in r["tags"]
                .as_str()
                .unwrap_or_default()
                .split([';', ',', ' '])
                .filter(|t| !t.is_empty())
            {
                tags.push(format!("tag:{t}"));
            }
            let title = r["name"].as_str().unwrap_or_default();
            Some((
                vmid,
                json!({"id": vmid.to_string(), "title": title, "kind": kind, "tags": tags}),
            ))
        })
        .collect();
    out.sort_by_key(|(v, _)| *v);
    out.into_iter().map(|(_, g)| g).collect()
}

pub fn list(api: &Api) -> Result<Value> {
    Ok(json!({ "guests": parse(&api.get("/cluster/resources?type=vm")?) }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cluster_resources() {
        let sample = json!([
            {"id": "lxc/200", "vmid": 200, "type": "lxc", "node": "pve2", "name": "dns", "status": "running",
             "tags": "infra;prod", "maxdisk": 8589934592u64},
            {"id": "qemu/100", "vmid": 100, "type": "qemu", "node": "pve1", "name": "web", "pool": "prod",
             "status": "running", "template": 0},
            {"id": "qemu/9000", "vmid": 9000, "type": "qemu", "node": "pve1", "name": "tpl", "template": 1},
            {"id": "storage/pve1/local", "type": "storage", "node": "pve1"},
            {"id": "qemu/0", "vmid": 0, "type": "qemu", "node": "pve1"}
        ]);
        let g = parse(&sample);
        assert_eq!(g.len(), 2, "no templates, storages or invalid vmids");
        assert_eq!(
            g[0],
            json!({"id": "100", "title": "web", "kind": "qemu", "tags": ["type:qemu", "node:pve1", "pool:prod"]})
        );
        assert_eq!(g[1]["tags"], json!(["type:lxc", "node:pve2", "tag:infra", "tag:prod"]));
        assert_eq!(parse(&json!({"unexpected": 1})), Vec::<Value>::new());
    }
}
