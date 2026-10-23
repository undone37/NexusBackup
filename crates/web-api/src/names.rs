//! Display names of snapshot sources (maintainer request 2026-10-22): the UI shows a PVE guest by its name
//! with `vm-100` muted next to it, which tells guests apart across clusters and tenants. Names come from the
//! source inventory (PVE: `lxc` = container, otherwise VM), from the agents and, for plugin sources, from the
//! source's name and its inventory (a database: `<source> / <database>`).

use crate::auth::Ctx;
use crate::{ApiError, ApiResult, St, Q};
use axum::extract::State;
use axum::Json;
use catalog::rusqlite::params;
use serde::Deserialize;
use serde_json::{Map, Value};

#[derive(Deserialize)]
pub struct NamesQ {
    /// one tenant (default: every tenant the caller sees)
    pub tenant: Option<String>,
}

/// `GET /names?tenant=` → `{"<tenant>": {"vm-100": "erp-app", "host-<id>": "fs02", ...}}`. A VMID with
/// different names in two clusters of one tenant (their snapshots share `vm-<vmid>`) gets both, joined by
/// ` / `.
pub async fn names(State(st): State<St>, ctx: Ctx, Q(q): Q<NamesQ>) -> ApiResult<Json<Value>> {
    if let Some(t) = &q.tenant {
        if !ctx.sees(t) {
            return Err(ApiError::forbidden());
        }
    }
    let c = st.cat.conn();
    let rows: Vec<(String, String, String)> = c
        .prepare(
            "SELECT so.tenant, CASE WHEN i.kind = 'lxc' THEN 'ct-' ELSE 'vm-' END || i.guest,
                    group_concat(DISTINCT i.name)
             FROM inventory i JOIN sources so ON so.id = i.source_id
             WHERE so.kind = 'pve' AND i.name != '' AND (?1 IS NULL OR so.tenant = ?1) AND (?2 IS NULL OR so.tenant = ?2)
             GROUP BY 1, 2
             UNION ALL
             SELECT tenant, 'host-' || id, name FROM agents
             WHERE (?1 IS NULL OR tenant = ?1) AND (?2 IS NULL OR tenant = ?2)
             UNION ALL
             -- plugin sources (plugin_proto::source_name): the source's name, a guest (database) after it
             SELECT tenant, 'plugin-' || substr(kind, 8) || '-' || id, replace(replace(name, ', ', ' '), ',', ' ') FROM sources
             WHERE kind LIKE 'plugin:%' AND (?1 IS NULL OR tenant = ?1) AND (?2 IS NULL OR tenant = ?2)
             UNION ALL
             SELECT so.tenant, 'plugin-' || substr(so.kind, 8) || '-' || so.id || '-' || i.guest,
                    replace(replace(so.name || ' / ' || CASE WHEN i.name != '' THEN i.name ELSE i.guest END, ', ', ' '), ',', ' ')
             FROM inventory i JOIN sources so ON so.id = i.source_id
             WHERE so.kind LIKE 'plugin:%' AND (?1 IS NULL OR so.tenant = ?1) AND (?2 IS NULL OR so.tenant = ?2)
             UNION ALL
             -- VMware VMs (vmware::names::source_name): the guest id is the VM UUID
             SELECT so.tenant, 'vmw-' || i.guest, replace(replace(i.name, ', ', ' '), ',', ' ')
             FROM inventory i JOIN sources so ON so.id = i.source_id
             WHERE so.kind = 'vmware' AND i.name != '' AND (?1 IS NULL OR so.tenant = ?1) AND (?2 IS NULL OR so.tenant = ?2)",
        )?
        .query_map(params![q.tenant, ctx.scope()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<_, _>>()?;
    let mut out = Map::new();
    for (tenant, source, name) in rows {
        let names: Vec<&str> = name.split(',').collect();
        let t = out.entry(tenant).or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(m) = t {
            m.insert(source, Value::String(names.join(" / ")));
        }
    }
    Ok(Json(Value::Object(out)))
}
