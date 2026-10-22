//! Instant file search (Phase 31b, docs/file-index-v2-plan.md). The web-api
//! holds no tenant keys: `GET /files/search` asks nexus-index (Unix socket,
//! crate index-proto), which searches the tenant's sealed Tantivy index, and
//! adds what only the catalog knows: which local snapshots hold each version
//! and the index state of every snapshot of the hit sources (timeline marks).
//! Roles as for the job-based search (`search::SEARCHERS`, tenant users see
//! their tenant); every search is audited as `file.search` (queries reveal
//! names). `GET /files/index-status` (Storage page), per-group scope rules
//! `GET|PUT /groups/{id}/index-rules` (`group.index_rules`) and
//! `POST /files/index/rebuild` (admin, `file.index_rebuild`).
//! When nexus-index is down the search answers 503 and the UI falls back to
//! the `file_search` job (crate::search).

use crate::auth::{Ctx, TENANT_WRITERS};
use crate::search::SEARCHERS;
use crate::{validate, ApiError, ApiResult, St, J, Q};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use catalog::rusqlite::{params, OptionalExtension};
use index_proto::{Deleted, Mode, Request, SearchReq, SearchResp, SourceRules, DEFAULT_EXCLUDES};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(20);
/// rules per list
const MAX_RULES: usize = 64;

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SearchQuery {
    tenant: Option<String>,
    #[serde(default)]
    q: String,
    mode: Option<String>,
    source: Option<String>,
    group: Option<i64>,
    kind: Option<String>,
    ext: Option<String>,
    size_min: Option<u64>,
    size_max: Option<u64>,
    mtime_from: Option<i64>,
    mtime_to: Option<i64>,
    entry: Option<String>,
    /// C2: comma-separated SIDs, uid:gid, uids or well-known Windows group names
    owner: Option<String>,
    deleted: Option<String>,
    limit: Option<usize>,
    cursor: Option<String>,
}

/// Well-known Windows SIDs (the same on every Windows system) and their names. Local accounts and Linux
/// uids get their names from the guest itself (the index's `owner_name`, Phase 39 C2).
// ponytail: domain accounts stay as SIDs (their names are in AD, not on the member's disk)
const WELL_KNOWN: &[(&str, &str)] = &[
    ("S-1-1-0", "Everyone"),
    ("S-1-3-0", "CREATOR OWNER"),
    ("S-1-5-18", "SYSTEM"),
    ("S-1-5-19", "LOCAL SERVICE"),
    ("S-1-5-20", "NETWORK SERVICE"),
    ("S-1-5-32-544", "Administrators"),
    ("S-1-5-32-545", "Users"),
    ("S-1-5-32-546", "Guests"),
    ("S-1-5-32-551", "Backup Operators"),
    (
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
        "TrustedInstaller",
    ),
];

fn well_known_name(sid: &str) -> Option<&'static str> {
    WELL_KNOWN.iter().find(|(s, _)| *s == sid).map(|(_, n)| *n)
}

fn sid_of(name: &str) -> Option<&'static str> {
    WELL_KNOWN
        .iter()
        .find(|(_, n)| n.eq_ignore_ascii_case(name))
        .map(|(s, _)| *s)
}

fn unavailable(e: std::io::Error) -> ApiError {
    ApiError(
        StatusCode::SERVICE_UNAVAILABLE,
        format!("the file search index (nexus-index) is not available: {e}"),
    )
}

/// One request to nexus-index off the async runtime. Connection problems are
/// 503; errors the service reports (validation, unknown tenant) are 400.
async fn call(st: &St, req: Request) -> ApiResult<Value> {
    let sock = st.index_socket().to_owned();
    tokio::task::spawn_blocking(move || index_proto::call(&sock, &req, TIMEOUT))
        .await
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::Other => ApiError::bad(e.to_string()),
            _ => unavailable(e),
        })
}

fn list(s: &Option<String>) -> Option<Vec<String>> {
    s.as_ref().map(|s| {
        s.split(',')
            .map(|x| x.trim().to_owned())
            .filter(|x| !x.is_empty())
            .collect()
    })
}

/// The tenant a request is about: tenant users always their own.
fn tenant_of(ctx: &Ctx, t: Option<&str>) -> ApiResult<String> {
    let t = match (ctx.scope(), t) {
        (Some(own), Some(t)) if t != own => return Err(ApiError::forbidden()),
        (Some(own), _) => own.to_owned(),
        (None, Some(t)) => t.to_owned(),
        (None, None) => return Err(ApiError::bad("tenant: required")),
    };
    validate::name(&t, "tenant")?;
    Ok(t)
}

pub async fn search(State(st): State<St>, ctx: Ctx, Q(f): Q<SearchQuery>) -> ApiResult<Json<Value>> {
    ctx.require(SEARCHERS)?;
    let tenant = tenant_of(&ctx, f.tenant.as_deref())?;
    if let Some(s) = &f.source {
        validate::source_ref(s)?;
    }
    let mode = match f.mode.as_deref() {
        None | Some("auto") => Mode::Auto,
        Some("name") => Mode::Name,
        Some("path") => Mode::Path,
        Some("words") => Mode::Words,
        Some(_) => return Err(ApiError::bad("mode: auto, name, path or words")),
    };
    let deleted = match f.deleted.as_deref() {
        None | Some("any") => Deleted::Any,
        Some("only") => Deleted::Only,
        Some("exclude") => Deleted::Exclude,
        Some(_) => return Err(ApiError::bad("deleted: any, only or exclude")),
    };
    // source and group filters become one source list (the scheduler keeps group_sources)
    let mut sources: Option<Vec<String>> = f.source.clone().map(|s| vec![s]);
    {
        let c = st.cat.conn();
        c.query_row("SELECT 1 FROM tenants WHERE name = ?1", [&tenant], |_| Ok(()))
            .optional()?
            .ok_or_else(|| ApiError::bad("tenant: does not exist"))?;
        if let Some(g) = f.group {
            let gt: String = c
                .query_row("SELECT tenant FROM groups WHERE id = ?1", [g], |r| r.get(0))
                .optional()?
                .ok_or_else(|| ApiError::bad("group: does not exist"))?;
            if gt != tenant {
                return Err(ApiError::bad("group: not in this tenant"));
            }
            let in_group: BTreeSet<String> = c
                .prepare("SELECT source FROM group_sources WHERE group_id = ?1 AND tenant = ?2")?
                .query_map(params![g, tenant], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            sources = Some(match sources {
                Some(s) => s.into_iter().filter(|x| in_group.contains(x)).collect(),
                None => in_group.into_iter().collect(),
            });
        }
    }
    let req = SearchReq {
        tenant: tenant.clone(),
        q: f.q.trim().to_owned(),
        mode,
        sources: sources.clone(),
        kinds: list(&f.kind),
        ext: list(&f.ext).map(|v| {
            v.into_iter()
                .map(|e| e.trim_start_matches('.').to_lowercase())
                .collect()
        }),
        size_min: f.size_min,
        size_max: f.size_max,
        mtime_from: f.mtime_from,
        mtime_to: f.mtime_to,
        entry: f.entry.clone(),
        owners: list(&f.owner).map(|v| v.into_iter().map(|o| sid_of(&o).map_or(o, str::to_owned)).collect()),
        deleted,
        limit: f.limit.unwrap_or(index_proto::DEFAULT_LIMIT),
        cursor: f.cursor.clone(),
    };
    req.validate().map_err(ApiError::bad)?;
    let mut audit = serde_json::to_value(&req).unwrap_or(Value::Null);
    if let Some(o) = audit.as_object_mut() {
        o.remove("cursor");
        if let Some(g) = f.group {
            o.insert("group".into(), json!(g));
        }
    }
    st.audit(ctx.name(), "file.search", &format!("tenant/{tenant}"), audit)?;
    // a group without sources has no hits (no round trip)
    let resp: SearchResp = if sources.as_ref().is_some_and(std::vec::Vec::is_empty) {
        SearchResp::default()
    } else {
        serde_json::from_value(call(&st, Request::Search(Box::new(req))).await?)
            .map_err(|e| ApiError(StatusCode::BAD_GATEWAY, format!("nexus-index answer: {e}")))?
    };
    Ok(Json(enrich(&st, &tenant, resp)?))
}

/// Adds the local snapshots per version and the index state per snapshot.
fn enrich(st: &St, tenant: &str, resp: SearchResp) -> ApiResult<Value> {
    let c = st.cat.conn();
    let mut local: HashMap<String, Vec<i64>> = HashMap::new();
    let mut rows: HashMap<(String, i64), (String, Option<String>)> = HashMap::new();
    for s in resp.sources.keys() {
        let times: Vec<i64> = c
            .prepare("SELECT time FROM snapshots WHERE tenant = ?1 AND source = ?2 AND local = 1 ORDER BY time DESC")?
            .query_map(params![tenant, s], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        local.insert(s.clone(), times);
        let mut stmt = c.prepare("SELECT time, state, reason FROM snapshot_index WHERE tenant = ?1 AND source = ?2")?;
        for r in stmt.query_map(params![tenant, s], |r| Ok((r.get::<_, i64>(0)?, r.get(1)?, r.get(2)?)))? {
            let (t, state, reason) = r?;
            rows.insert((s.clone(), t), (state, reason));
        }
    }
    let indexed: HashMap<&str, BTreeSet<i64>> = resp
        .sources
        .iter()
        .map(|(s, v)| (s.as_str(), v.indexed.iter().map(|t| *t as i64).collect()))
        .collect();
    let hits: Vec<Value> = resp
        .hits
        .iter()
        .map(|h| {
            let times = local.get(&h.source).map(Vec::as_slice).unwrap_or_default();
            let idx = indexed.get(h.source.as_str());
            let versions: Vec<Value> = h
                .versions
                .iter()
                .map(|v| {
                    let held: Vec<i64> = times
                        .iter()
                        .copied()
                        .filter(|t| *t >= v.first as i64 && v.gone.is_none_or(|g| *t < g as i64))
                        .filter(|t| idx.is_some_and(|i| i.contains(t)))
                        .collect();
                    json!({"size": v.size, "mtime": v.mtime, "first": v.first, "gone": v.gone, "times": held, "owner": v.owner,
                           "owner_name": v.owner_name.as_deref().or_else(|| v.owner.as_deref().and_then(well_known_name))})
                })
                .collect();
            json!({"source": h.source, "path": h.path, "browse": h.browse, "kind": h.kind, "versions": versions})
        })
        .collect();
    let mut snapshots = BTreeMap::new();
    for (s, times) in &local {
        let idx = indexed.get(s.as_str());
        let marks: Vec<Value> = times
            .iter()
            .map(|t| {
                let row = rows.get(&(s.clone(), *t));
                let ingested = idx.is_some_and(|i| i.contains(t));
                let state = match row.map(|r| r.0.as_str()) {
                    Some(st @ ("partial" | "failed")) => st,
                    Some("pending") if !ingested => "pending",
                    _ if ingested => "indexed",
                    Some(st) => st,
                    None => "unindexed",
                };
                let mut m = json!({"time": t, "state": state});
                if let Some(r) = row.and_then(|r| r.1.clone()) {
                    m["reason"] = json!(r);
                }
                m
            })
            .collect();
        snapshots.insert(s.clone(), marks);
    }
    Ok(json!({
        "hits": hits, "next": resp.next, "elapsed_ms": resp.elapsed_ms, "pending": resp.pending,
        "snapshots": snapshots,
    }))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct StatusQuery {
    tenant: Option<String>,
}

pub async fn index_status(State(st): State<St>, ctx: Ctx, Q(f): Q<StatusQuery>) -> ApiResult<Json<Value>> {
    ctx.require(SEARCHERS)?;
    let tenant = match (ctx.scope(), f.tenant.as_deref()) {
        (None, None) => None,
        (_, t) => Some(tenant_of(&ctx, t)?),
    };
    match call(&st, Request::Status { tenant }).await {
        Ok(mut v) => {
            v["available"] = json!(true);
            Ok(Json(v))
        }
        Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, _)) => Ok(Json(json!({"available": false}))),
        Err(e) => Err(e),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RebuildReq {
    tenant: String,
}

/// Drops the tenant's search index and builds it again from the sealed name
/// indexes (admin; normally never needed: the service compares by itself).
pub async fn rebuild(State(st): State<St>, ctx: Ctx, J(r): J<RebuildReq>) -> ApiResult<Json<Value>> {
    ctx.require(&["admin"])?;
    validate::name(&r.tenant, "tenant")?;
    st.audit(
        ctx.name(),
        "file.index_rebuild",
        &format!("tenant/{}", r.tenant),
        json!({}),
    )?;
    Ok(Json(call(&st, Request::Rebuild { tenant: r.tenant }).await?))
}

fn rules_out(id: i64, raw: Option<String>) -> Value {
    let r: SourceRules = raw.and_then(|j| serde_json::from_str(&j).ok()).unwrap_or_default();
    json!({"id": id, "defaults": r.defaults, "include": r.include, "exclude": r.exclude,
           "default_excludes": DEFAULT_EXCLUDES})
}

fn group_tenant(st: &St, ctx: &Ctx, id: i64) -> ApiResult<Option<String>> {
    st.cat
        .conn()
        .query_row(
            "SELECT index_rules FROM groups WHERE id = ?1 AND (?2 IS NULL OR tenant = ?2)",
            params![id, ctx.scope()],
            |r| r.get::<_, Option<String>>(0),
        )
        .optional()?
        .ok_or_else(ApiError::not_found)
}

pub async fn get_rules(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let raw = group_tenant(&st, &ctx, id)?;
    Ok(Json(rules_out(id, raw)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesReq {
    #[serde(default = "yes")]
    defaults: bool,
    #[serde(default)]
    include: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
}

fn yes() -> bool {
    true
}

/// Which files of the group's sources go into the search index. Not a
/// weakening of protection (no approval): it only shapes the search.
pub async fn put_rules(
    State(st): State<St>,
    ctx: Ctx,
    Path(id): Path<i64>,
    J(r): J<RulesReq>,
) -> ApiResult<Json<Value>> {
    ctx.require(TENANT_WRITERS)?;
    group_tenant(&st, &ctx, id)?;
    let clean = |v: Vec<String>, what: &str| -> ApiResult<Vec<String>> {
        if v.len() > MAX_RULES {
            return Err(ApiError::bad(format!("{what}: at most {MAX_RULES} rules")));
        }
        let mut out: Vec<String> = Vec::new();
        for x in v {
            let x = x.trim().trim_end_matches('/').to_owned();
            let x = if x.is_empty() { "/".to_owned() } else { x };
            if !index_proto::valid_rule(&x) {
                return Err(ApiError::bad(format!(
                    "{what}: {x:?} is not an absolute path with / separators (use /C/... for one drive)"
                )));
            }
            if !out.contains(&x) {
                out.push(x);
            }
        }
        Ok(out)
    };
    let rules = SourceRules {
        enabled: true,
        defaults: r.defaults,
        include: clean(r.include, "include")?,
        exclude: clean(r.exclude, "exclude")?,
    };
    let raw = json!({"defaults": rules.defaults, "include": rules.include, "exclude": rules.exclude}).to_string();
    st.cat
        .conn()
        .execute("UPDATE groups SET index_rules = ?2 WHERE id = ?1", params![id, raw])?;
    let out = rules_out(id, Some(raw));
    st.audit(
        ctx.name(),
        "group.index_rules",
        &format!("group/{id}"),
        json!({"defaults": rules.defaults, "include": rules.include, "exclude": rules.exclude}),
    )?;
    Ok(Json(out))
}

/// Default socket path, `NEXUS_INDEX_SOCKET` overrides it.
pub fn default_socket() -> PathBuf {
    std::env::var_os("NEXUS_INDEX_SOCKET").map_or_else(|| index_proto::DEFAULT_SOCKET.into(), PathBuf::from)
}
