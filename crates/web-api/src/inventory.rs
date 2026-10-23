//! Guest inventory and auto-protect groups (Phase 13c, catalog v12).
//!
//! `GET /sources/{id}/inventory`: the guests the scheduler last listed for a
//! source, with tags and the groups that cover each one. A refresh is the job
//! `POST /jobs {kind: "inventory", params: {source_id}}` (operators). Group
//! `mode` / `selector` / `exclude` are checked here for `POST`/`PUT /groups`.

use crate::auth::Ctx;
use crate::{validate, ApiError, ApiResult, St};
use axum::extract::{Path, State};
use axum::Json;
use catalog::inventory::{auto, id_of, valid_tag, MODES};
use catalog::rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};

/// Selector tags per group.
const MAX_SELECTOR: usize = 50;

/// Whether sources of `kind` have an inventory (PVE, TrueNAS, VMware, plugin kinds that list guests).
pub fn has_inventory(c: &Connection, kind: &str) -> bool {
    match kind.strip_prefix("plugin:") {
        None => kind == "pve" || kind == "truenas" || kind == "vmware",
        Some(k) => plugin_manager::current_for_kind(c, k)
            .ok()
            .flatten()
            .and_then(|cur| cur.manifest.kinds.into_iter().find(|x| x.kind == k))
            .is_some_and(|s| s.guests.is_some_and(|g| g["list"] == true)),
    }
}

fn valid_guest(kind: &str, id: &str) -> bool {
    match kind {
        "pve" => id
            .parse::<u32>()
            .is_ok_and(|v| validate::vmid(v).is_ok() && v.to_string() == id),
        "truenas" => truenas::valid_dataset(id),
        "vmware" => vmware::names::valid_uuid(id),
        _ => plugin_proto::valid_guest_id(id),
    }
}

/// Checks and canonicalises a group's mode for a source of `kind`: `explicit`
/// keeps `guests` (checked by the caller); `all` / `tags` take the guests from the
/// inventory (no `guests`, `selector` = tags for `tags`, `exclude` = guest ids,
/// stored as strings). A TrueNAS group without datasets ("none = all") becomes
/// `all`, resolved at run time instead of frozen at save time. Returns whether the
/// group is an inventory group.
pub fn check_mode(
    c: &Connection,
    kind: &str,
    guests: &[Value],
    mode: &mut String,
    selector: &mut Vec<String>,
    exclude: &mut Vec<Value>,
) -> ApiResult<bool> {
    if !MODES.contains(&mode.as_str()) {
        return Err(ApiError::bad("mode: explicit, all or tags"));
    }
    if kind == "truenas" && mode == "explicit" && guests.is_empty() {
        *mode = "all".into();
    }
    if !auto(mode) {
        if !selector.is_empty() || !exclude.is_empty() {
            return Err(ApiError::bad("selector, exclude: only for groups of mode all or tags"));
        }
        return Ok(false);
    }
    if !has_inventory(c, kind) {
        return Err(ApiError::bad(
            "mode: this source has no guest inventory (linux, nfs, smb and plugin kinds without a guest list: explicit only)",
        ));
    }
    if !guests.is_empty() {
        return Err(ApiError::bad(
            "guests: a group of mode all or tags lists no guests (they come from the inventory)",
        ));
    }
    if mode == "all" && !selector.is_empty() {
        return Err(ApiError::bad("selector: only for mode tags"));
    }
    if mode == "tags" {
        if selector.is_empty() || selector.len() > MAX_SELECTOR {
            return Err(ApiError::bad(format!("selector: 1..={MAX_SELECTOR} tags")));
        }
        if let Some(t) = selector.iter().find(|t| !valid_tag(t)) {
            return Err(ApiError::bad(format!(
                "selector: invalid tag {t:?} (1..=128 characters, no control characters, no surrounding spaces)"
            )));
        }
        selector.sort();
        selector.dedup();
    }
    if exclude.len() > 1000 {
        return Err(ApiError::bad("exclude: at most 1000 guests"));
    }
    let mut ids = Vec::with_capacity(exclude.len());
    for g in exclude.iter() {
        let id = id_of(g)
            .filter(|id| valid_guest(kind, id))
            .ok_or_else(|| ApiError::bad(format!("exclude: {g} is not a guest id of this source")))?;
        ids.push(id);
    }
    ids.sort();
    ids.dedup();
    *exclude = ids.into_iter().map(Value::from).collect();
    Ok(true)
}

/// Per source: the groups (name) covering each guest id, and whether a group covers
/// the source as a whole (plugin group without guests). Groups resolve exactly like
/// the scheduler's (catalog::inventory::resolve).
pub type Cover = HashMap<i64, (Vec<String>, HashMap<String, Vec<String>>)>;

pub fn coverage(c: &Connection, scope: Option<&str>) -> ApiResult<Cover> {
    let rows: Vec<(i64, String, String, String, String, String, String)> = c
        .prepare(
            "SELECT g.source_id, s.kind, g.name, g.mode, g.guests, g.selector, g.exclude
             FROM groups g JOIN sources s ON s.id = g.source_id WHERE ?1 IS NULL OR g.tenant = ?1 ORDER BY g.name",
        )?
        .query_map([scope], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ))
        })?
        .collect::<Result<_, _>>()?;
    let mut out: Cover = HashMap::new();
    for (sid, kind, name, mode, guests, sel, ex) in rows {
        let resolved = catalog::inventory::resolve(c, sid, &kind, &mode, &guests, &sel, &ex)?;
        let e = out.entry(sid).or_default();
        if resolved.is_empty() && !auto(&mode) && kind.starts_with("plugin:") {
            e.0.push(name.clone());
        }
        for id in resolved.iter().filter_map(id_of) {
            e.1.entry(id).or_default().push(name.clone());
        }
    }
    Ok(out)
}

/// `GET /sources/{id}/inventory`: `{source_id, kind, refreshed, guests: [{guest, name,
/// kind, tags, seen, gone, groups}]}` (`refreshed` = last listing, null = never).
pub async fn list(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let c = st.cat.conn();
    let (tenant, kind): (String, String) = c
        .query_row("SELECT tenant, kind FROM sources WHERE id = ?1", [id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })
        .optional()?
        .filter(|(t, _)| ctx.sees(t))
        .ok_or_else(ApiError::not_found)?;
    let cover = coverage(&c, Some(&tenant))?.remove(&id).unwrap_or_default();
    let mut guests = catalog::inventory::list(&c, id)?;
    for g in guests.iter_mut() {
        let mut names: BTreeSet<String> = cover.0.iter().cloned().collect();
        if g["gone"].is_null() {
            names.extend(
                cover
                    .1
                    .get(g["guest"].as_str().unwrap_or_default())
                    .cloned()
                    .unwrap_or_default(),
            );
        }
        g["groups"] = json!(names);
    }
    let refreshed: Option<i64> = c.query_row(
        "SELECT MAX(finished) FROM jobs WHERE kind IN ('inventory','plugin_guests') AND state = 'ok'
         AND json_extract(params, '$.source_id') = ?1",
        params![id],
        |r| r.get(0),
    )?;
    Ok(Json(json!({
        "source_id": id, "kind": kind, "inventory": has_inventory(&c, &kind),
        "refreshed": refreshed, "guests": guests,
    })))
}
