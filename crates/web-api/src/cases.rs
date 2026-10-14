//! Cases (Phase 33, docs/control-plane.md "Cases", Commvault Tier 2 "M365
//! compliance search and cases"): saved search criteria over a tenant's
//! sealed name indexes (Microsoft 365 snapshots by default: folder, subject and
//! date of every item, file names), the snapshots they match, legal holds on
//! them and an export of the matched items. The search is the existing
//! `file_search` job with `case_id` (the scheduler records the matched
//! snapshots); holds are ordinary legal holds (released one by one with
//! approval); the export queues one `files_get` per snapshot (Microsoft 365
//! mail as eml, mbox or PST through the plugin's download).
//!
//! Roles: administrators and security officers (appliance-wide) create, search
//! and close cases; security officers place the holds (as for any hold);
//! exports need the download privilege. Never through API tokens (not on the
//! allow-list). Case audit entries name `case/<id>` and `case_tenant`, so they
//! are not shown in the tenant's own audit view (an investigation is not
//! announced to the tenant's admins); the holds and export jobs are ordinary ones.

use crate::auth::Ctx;
use crate::{validate, ApiError, ApiResult, St, J, Q};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use catalog::rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const READERS: &[&str] = &["admin", "security_officer"];
const HOLDERS: &[&str] = &["security_officer"];
/// The matches a case search keeps (the file search's maximum).
const SEARCH_LIMIT: u64 = 2000;
/// Snapshots one export request covers at most.
pub const EXPORT_MAX: usize = 50;
/// Default criteria: every Microsoft 365 snapshot of the tenant.
pub const M365_PREFIX: &str = "plugin-m365-";

pub fn routes() -> Router<St> {
    Router::new()
        .route("/cases", get(list).post(create))
        .route("/cases/{id}", get(one))
        .route("/cases/{id}/search", post(search))
        .route("/cases/{id}/hold", post(hold))
        .route("/cases/{id}/export", post(export))
        .route("/cases/{id}/close", post(close))
}

/// What a case searches for (the `file_search` parameters).
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Criteria {
    /// name pattern (substring, or a glob with `*`, `?`, `[…]`; with a `/` the whole path)
    pub query: String,
    /// sources starting with this (default `plugin-m365-`; `""` = every source)
    #[serde(default = "m365", skip_serializing_if = "Option::is_none")]
    pub source_prefix: Option<String>,
    /// or exactly this source
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// snapshot time range (unix seconds)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<u64>,
    #[serde(default)]
    pub case_sensitive: bool,
}

fn m365() -> Option<String> {
    Some(M365_PREFIX.into())
}

impl Criteria {
    fn check(&mut self) -> ApiResult<()> {
        let q = self.query.trim();
        if q.is_empty() || q.len() > 256 || q.contains('\0') {
            return Err(ApiError::bad("criteria.query: 1..=256 characters"));
        }
        self.query = q.to_owned();
        if let Some(p) = &self.source_prefix {
            if p.is_empty() {
                self.source_prefix = None;
            } else if p.len() > 128 || !p.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) {
                return Err(ApiError::bad("criteria.source_prefix: letters, digits, . _ -"));
            }
        }
        if let Some(s) = &self.source {
            validate::source_ref(s)?;
        }
        if self.from.zip(self.to).is_some_and(|(f, t)| f > t) {
            return Err(ApiError::bad("criteria: from must not be after to"));
        }
        Ok(())
    }

    /// The `file_search` job parameters of the case.
    fn job_params(&self, case: i64) -> Value {
        let mut p = json!({"query": self.query, "case_sensitive": self.case_sensitive, "limit": SEARCH_LIMIT,
                           "case_id": case});
        for (k, v) in [
            ("source_prefix", self.source_prefix.as_ref().map(|s| json!(s))),
            ("source", self.source.as_ref().map(|s| json!(s))),
            ("from", self.from.map(|f| json!(f))),
            ("to", self.to.map(|t| json!(t))),
        ] {
            if let Some(v) = v {
                p[k] = v;
            }
        }
        p
    }
}

fn require(ctx: &Ctx, roles: &[&str]) -> ApiResult<()> {
    ctx.require(roles)?;
    if ctx.scope().is_some() || ctx.token.is_some() {
        return Err(ApiError::forbidden());
    }
    Ok(())
}

/// (tenant, name, criteria, state) of a case.
fn load(c: &Connection, id: i64) -> ApiResult<(String, String, Criteria, String)> {
    let (tenant, name, crit, state): (String, String, String, String) = c
        .query_row(
            "SELECT tenant, name, criteria, state FROM cases WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?
        .ok_or_else(ApiError::not_found)?;
    let crit: Criteria = serde_json::from_str(&crit).map_err(|e| anyhow::anyhow!("case {id}: {e}"))?;
    Ok((tenant, name, crit, state))
}

fn queue_search(c: &Connection, tenant: &str, crit: &Criteria, case: i64, by: &str) -> ApiResult<i64> {
    c.execute(
        "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES ('file_search', ?1, ?2, 'queued', ?3, ?4)",
        params![tenant, crit.job_params(case).to_string(), by, catalog::now()],
    )?;
    let job = c.last_insert_rowid();
    c.execute("UPDATE cases SET last_job = ?2 WHERE id = ?1", params![case, job])?;
    Ok(job)
}

fn summary(c: &Connection, id: i64) -> ApiResult<Value> {
    let row = c.query_row(
        "SELECT id, tenant, name, description, criteria, state, created_by, created_at, closed_by, closed_at, last_job,
           searched_at, truncated,
           (SELECT COUNT(*) FROM case_snapshots s WHERE s.case_id = cases.id AND s.items > 0),
           (SELECT COALESCE(SUM(items), 0) FROM case_snapshots s WHERE s.case_id = cases.id),
           (SELECT COUNT(*) FROM case_snapshots s JOIN legal_holds h ON h.id = s.hold_id
              WHERE s.case_id = cases.id AND h.state = 'active'),
           (SELECT state FROM jobs j WHERE j.id = cases.last_job)
         FROM cases WHERE id = ?1",
        [id],
        |r| {
            let crit: String = r.get(4)?;
            Ok(json!({
                "id": r.get::<_, i64>(0)?, "tenant": r.get::<_, String>(1)?, "name": r.get::<_, String>(2)?,
                "description": r.get::<_, String>(3)?,
                "criteria": serde_json::from_str::<Value>(&crit).unwrap_or(Value::Null),
                "state": r.get::<_, String>(5)?, "created_by": r.get::<_, String>(6)?, "created_at": r.get::<_, i64>(7)?,
                "closed_by": r.get::<_, Option<String>>(8)?, "closed_at": r.get::<_, Option<i64>>(9)?,
                "last_job": r.get::<_, Option<i64>>(10)?, "searched_at": r.get::<_, Option<i64>>(11)?,
                "truncated": r.get::<_, bool>(12)?, "snapshots": r.get::<_, i64>(13)?, "items": r.get::<_, i64>(14)?,
                "held": r.get::<_, i64>(15)?, "job_state": r.get::<_, Option<String>>(16)?,
            }))
        },
    );
    match row {
        Ok(v) => Ok(v),
        Err(catalog::rusqlite::Error::QueryReturnedNoRows) => Err(ApiError::not_found()),
        Err(e) => Err(e.into()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListQ {
    tenant: Option<String>,
}

pub async fn list(State(st): State<St>, ctx: Ctx, Q(q): Q<ListQ>) -> ApiResult<Json<Value>> {
    require(&ctx, READERS)?;
    let c = st.cat.conn();
    let ids: Vec<i64> = c
        .prepare("SELECT id FROM cases WHERE ?1 IS NULL OR tenant = ?1 ORDER BY state, id DESC")?
        .query_map([q.tenant], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    let out: Vec<Value> = ids.into_iter().map(|id| summary(&c, id)).collect::<ApiResult<_>>()?;
    Ok(Json(Value::Array(out)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateReq {
    tenant: String,
    name: String,
    #[serde(default)]
    description: String,
    criteria: Criteria,
}

/// 201 `{…case, job_id}`: the case and its first search.
pub async fn create(State(st): State<St>, ctx: Ctx, J(mut r): J<CreateReq>) -> ApiResult<(StatusCode, Json<Value>)> {
    require(&ctx, READERS)?;
    validate::name(&r.tenant, "tenant")?;
    validate::name(&r.name, "name")?;
    let description = r.description.trim().to_owned();
    if description.chars().count() > 2000 || description.chars().any(|c| c.is_control() && c != '\n') {
        return Err(ApiError::bad("description: up to 2000 characters"));
    }
    r.criteria.check()?;
    let (id, job) = {
        let mut c = st.cat.conn();
        let tx = c.transaction()?;
        tx.query_row("SELECT 1 FROM tenants WHERE name = ?1", [&r.tenant], |_| Ok(()))
            .optional()?
            .ok_or_else(|| ApiError::bad("tenant: does not exist"))?;
        let n = tx.execute(
            "INSERT OR IGNORE INTO cases (tenant, name, description, criteria, state, created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, 'open', ?5, ?6)",
            params![
                r.tenant,
                r.name,
                description,
                json!(r.criteria).to_string(),
                ctx.name(),
                catalog::now()
            ],
        )?;
        if n != 1 {
            return Err(ApiError::conflict("a case of this name exists in the tenant"));
        }
        let id = tx.last_insert_rowid();
        let job = queue_search(&tx, &r.tenant, &r.criteria, id, ctx.name())?;
        tx.commit()?;
        (id, job)
    };
    st.audit(
        ctx.name(),
        "case.create",
        &format!("case/{id}"),
        json!({"case_tenant": r.tenant, "case": id, "name": r.name, "criteria": r.criteria, "job": job}),
    )?;
    let mut v = summary(&st.cat.conn(), id)?;
    v["job_id"] = json!(job);
    Ok((StatusCode::CREATED, Json(v)))
}

/// The case, its snapshots (with their hold) and the matched items of the last search.
pub async fn one(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    require(&ctx, READERS)?;
    let c = st.cat.conn();
    let mut v = summary(&c, id)?;
    let tenant = v["tenant"].as_str().unwrap_or_default().to_owned();
    let snaps: Vec<Value> = c
        .prepare(
            "SELECT s.source, s.time, s.items, h.id, h.state, h.reason FROM case_snapshots s
             LEFT JOIN legal_holds h ON h.id = s.hold_id WHERE s.case_id = ?1 ORDER BY s.time DESC, s.source",
        )?
        .query_map([id], |r| {
            let hold = match r.get::<_, Option<i64>>(3)? {
                Some(h) => json!({"id": h, "state": r.get::<_, String>(4)?, "reason": r.get::<_, String>(5)?}),
                None => Value::Null,
            };
            Ok(
                json!({"source": r.get::<_, String>(0)?, "time": r.get::<_, i64>(1)?, "items": r.get::<_, i64>(2)?,
                      "hold": hold}),
            )
        })?
        .collect::<Result<_, _>>()?;
    let matches = match v["last_job"].as_i64() {
        Some(job) => c
            .query_row(
                "SELECT result FROM jobs WHERE id = ?1 AND tenant = ?2 AND kind = 'file_search'",
                params![job, tenant],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten()
            .and_then(|r| serde_json::from_str::<Value>(&r).ok())
            .map(|r| r["matches"].clone())
            .unwrap_or(Value::Null),
        None => Value::Null,
    };
    v["snapshot_list"] = Value::Array(snaps);
    v["matches"] = matches;
    drop(c);
    st.audit(
        ctx.name(),
        "case.view",
        &format!("case/{id}"),
        json!({"case_tenant": tenant, "case": id}),
    )?;
    Ok(Json(v))
}

/// `POST /cases/{id}/search`: searches again with the saved criteria.
pub async fn search(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<(StatusCode, Json<Value>)> {
    require(&ctx, READERS)?;
    let (tenant, job) = {
        let c = st.cat.conn();
        let (tenant, _, crit, state) = load(&c, id)?;
        if state != "open" {
            return Err(ApiError::conflict("the case is closed"));
        }
        let running: bool = c.query_row(
            "SELECT EXISTS (SELECT 1 FROM jobs WHERE id = (SELECT last_job FROM cases WHERE id = ?1)
               AND state IN ('queued', 'running'))",
            [id],
            |r| r.get(0),
        )?;
        if running {
            return Err(ApiError::conflict("the case's search is still running"));
        }
        let job = queue_search(&c, &tenant, &crit, id, ctx.name())?;
        (tenant, job)
    };
    st.audit(
        ctx.name(),
        "case.search",
        &format!("case/{id}"),
        json!({"case_tenant": tenant, "case": id, "job": job}),
    )?;
    Ok((StatusCode::ACCEPTED, Json(json!({"job_id": job}))))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoldReq {
    reason: String,
}

/// `POST /cases/{id}/hold {reason}`: legal holds on every matched snapshot that
/// has none yet (security officers, immediate; releasing them needs approval).
pub async fn hold(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>, J(r): J<HoldReq>) -> ApiResult<Json<Value>> {
    require(&ctx, HOLDERS)?;
    let reason = r.reason.trim();
    if reason.is_empty() || reason.chars().count() > 400 || reason.chars().any(char::is_control) {
        return Err(ApiError::bad("reason: 1 to 400 characters, one line"));
    }
    let (tenant, held) = {
        let mut c = st.cat.conn();
        let tx = c.transaction()?;
        let (tenant, name, _, state) = load(&tx, id)?;
        if state != "open" {
            return Err(ApiError::conflict("the case is closed"));
        }
        let snaps: Vec<(String, i64)> = tx
            .prepare(
                "SELECT s.source, s.time FROM case_snapshots s JOIN snapshots n
                   ON n.tenant = ?2 AND n.source = s.source AND n.time = s.time
                 WHERE s.case_id = ?1 AND s.items > 0 ORDER BY s.source, s.time",
            )?
            .query_map(params![id, tenant], |x| Ok((x.get(0)?, x.get(1)?)))?
            .collect::<Result<_, _>>()?;
        let why = format!("case {name}: {reason}");
        let mut held = Vec::new();
        for (source, time) in snaps {
            if crate::holds::hold_one(&tx, &tenant, &source, time, &why, ctx.name())?.is_some() {
                held.push(format!("{source}/{time}"));
            }
            // the snapshot's active hold (new, or one that was there already) belongs to the case's record
            if let Some(h) = catalog::holds::active(&tx, &tenant, &source, time)? {
                tx.execute(
                    "UPDATE case_snapshots SET hold_id = ?4 WHERE case_id = ?1 AND source = ?2 AND time = ?3",
                    params![id, source, time, h],
                )?;
            }
        }
        tx.commit()?;
        (tenant, held)
    };
    st.audit(
        ctx.name(),
        "case.hold",
        &format!("case/{id}"),
        json!({"case_tenant": tenant, "case": id, "reason": reason, "snapshots": held}),
    )?;
    Ok(Json(json!({"held": held.len(), "snapshots": held})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportReq {
    #[serde(default = "tar")]
    format: String,
    /// Microsoft 365 snapshots: `eml`, `mbox` or `pst` (the plugin's download parameter)
    #[serde(default)]
    mail_format: Option<String>,
}

fn tar() -> String {
    "tar".into()
}

/// `POST /cases/{id}/export {format?, mail_format?}`: one `files_get` per
/// matched snapshot (at most [`EXPORT_MAX`], newest first) with the matched
/// items of the last search; `{jobs: [{id, source, time, download_token}]}`.
pub async fn export(
    State(st): State<St>,
    ctx: Ctx,
    Path(id): Path<i64>,
    J(r): J<ExportReq>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    require(&ctx, READERS)?;
    if !ctx.user.can_download {
        return Err(ApiError::forbidden());
    }
    if r.mail_format
        .as_deref()
        .is_some_and(|m| !["eml", "mbox", "pst"].contains(&m))
    {
        return Err(ApiError::bad("mail_format: eml, mbox or pst"));
    }
    let (tenant, last_job) = {
        let c = st.cat.conn();
        // exports are restores of the tenant's data: in vault mode only through approved single restores
        crate::vault::refuse(&c, "case exports")?;
        let (tenant, ..) = load(&c, id)?;
        let last: Option<i64> = c.query_row("SELECT last_job FROM cases WHERE id = ?1", [id], |x| x.get(0))?;
        (tenant, last)
    };
    let result: Value = {
        let c = st.cat.conn();
        last_job
            .map(|j| {
                c.query_row(
                    "SELECT result FROM jobs WHERE id = ?1 AND kind = 'file_search' AND state = 'ok'",
                    [j],
                    |x| x.get::<_, Option<String>>(0),
                )
                .optional()
            })
            .transpose()?
            .flatten()
            .flatten()
            .and_then(|s| serde_json::from_str(&s).ok())
            .ok_or_else(|| ApiError::conflict("the case has no finished search yet"))?
    };
    // matched paths per snapshot, newest snapshots first
    let mut per: std::collections::BTreeMap<(std::cmp::Reverse<i64>, String), Vec<String>> = Default::default();
    for m in result["matches"].as_array().into_iter().flatten() {
        let (Some(source), Some(path)) = (m["source"].as_str(), m["path"].as_str()) else {
            continue;
        };
        for t in m["times"].as_array().into_iter().flatten().filter_map(Value::as_i64) {
            per.entry((std::cmp::Reverse(t), source.to_owned()))
                .or_default()
                .push(format!("/{}", path.trim_start_matches('/')));
        }
    }
    if per.is_empty() {
        return Err(ApiError::conflict("the case's last search matched nothing"));
    }
    let mut jobs = Vec::new();
    for ((std::cmp::Reverse(time), source), mut paths) in per.into_iter().take(EXPORT_MAX) {
        paths.sort();
        paths.dedup();
        paths.truncate(1000);
        let mut p = json!({"source": source, "time": time, "paths": paths, "format": r.format});
        if let (Some(m), true) = (&r.mail_format, source.starts_with(M365_PREFIX)) {
            p["params"] = json!({"mail_format": m});
        }
        let params = crate::jobs::check_params(&st, "files_get", &tenant, p)?;
        let job = {
            let c = st.cat.conn();
            c.execute(
                "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES ('files_get', ?1, ?2, 'queued', ?3, ?4)",
                params![tenant, params.to_string(), ctx.name(), catalog::now()],
            )?;
            c.last_insert_rowid()
        };
        st.audit(
            ctx.name(),
            "job.create",
            &format!("job/{job}"),
            json!({"kind": "files_get", "tenant": tenant, "params": params, "case": id}),
        )?;
        jobs.push(json!({"id": job, "source": source, "time": time, "download_token": params["download_token"]}));
    }
    st.audit(
        ctx.name(),
        "case.export",
        &format!("case/{id}"),
        json!({"case_tenant": tenant, "case": id, "jobs": jobs.iter().map(|j| j["id"].clone()).collect::<Vec<_>>(),
               "format": r.format, "mail_format": r.mail_format}),
    )?;
    Ok((StatusCode::ACCEPTED, Json(json!({"jobs": jobs}))))
}

/// `POST /cases/{id}/close`: no more searches, holds or exports; the holds stay
/// (each is released on its own, with approval).
pub async fn close(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    require(&ctx, READERS)?;
    let tenant = {
        let c = st.cat.conn();
        let (tenant, ..) = load(&c, id)?;
        let n = c.execute(
            "UPDATE cases SET state = 'closed', closed_by = ?2, closed_at = ?3 WHERE id = ?1 AND state = 'open'",
            params![id, ctx.name(), catalog::now()],
        )?;
        if n != 1 {
            return Err(ApiError::conflict("the case is closed already"));
        }
        tenant
    };
    st.audit(
        ctx.name(),
        "case.close",
        &format!("case/{id}"),
        json!({"case_tenant": tenant, "case": id}),
    )?;
    Ok(Json(summary(&st.cat.conn(), id)?))
}
