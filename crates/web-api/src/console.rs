//! Emergency console root access (Phase 14c, docs/control-plane.md "Console
//! root shell"). An admin requests `console.unlock` (1–8 h, with a reason); a
//! second person approves it while approvals are enabled (quorum, executed
//! nowhere: the row stays `approved`). The requester then fetches the one-time
//! code exactly once (`executed`); only its hash goes to the unlock dir, where
//! the console gate on tty2 (`nexus-console-gate`) looks it up. The code must
//! be used within 24 h of the approval. Issuing a code raises a critical alert;
//! the gate audits the shell (`console.root_shell`, `console.root_shell_end`)
//! and keeps the setting [`SHELL_SETTING`] for the UI banner while it runs.

use crate::auth::Ctx;
use crate::quorum::{accepted, request};
use crate::{ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::response::Response;
use axum::Json;
use catalog::console::{self, Unlock, ACTION, CODE_TTL_SECS, MAX_HOURS, SHELL_SETTING};
use catalog::rusqlite::{params, Connection};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;

const ADMIN: &[&str] = &["admin"];
const VIEW: &[&str] = &["admin", "security_officer"];

fn dir(st: &St) -> PathBuf {
    st.console_dir
        .get_or_init(|| {
            std::env::var_os("NEXUS_CONSOLE_UNLOCK_DIR")
                .map(Into::into)
                .unwrap_or_else(|| console::UNLOCK_DIR.into())
        })
        .clone()
}

/// Appliance-wide accounts only (a tenant-scoped admin manages its tenant).
fn require(ctx: &Ctx, roles: &[&str]) -> ApiResult<()> {
    ctx.require(roles)?;
    if ctx.scope().is_some() {
        return Err(ApiError::forbidden());
    }
    Ok(())
}

fn target(id: i64) -> String {
    format!("console-unlock/{id}")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnlockReq {
    hours: u32,
    reason: String,
}

pub async fn request_unlock(State(st): State<St>, ctx: Ctx, J(r): J<UnlockReq>) -> ApiResult<Response> {
    require(&ctx, ADMIN)?;
    if !(1..=MAX_HOURS).contains(&r.hours) {
        return Err(ApiError::bad(format!("hours: 1 to {MAX_HOURS}")));
    }
    let reason = r.reason.trim();
    if reason.is_empty() || reason.chars().count() > 500 {
        return Err(ApiError::bad("reason: 1 to 500 characters"));
    }
    let o = request(
        &st,
        &ctx,
        ACTION,
        "console",
        json!({"hours": r.hours, "reason": reason}),
    )?;
    Ok(accepted(o, json!({})))
}

struct Row {
    id: i64,
    p: Value,
    by: String,
    created: i64,
    decided_by: Option<String>,
    decided_at: Option<i64>,
    state: String,
}

fn rows(c: &Connection, id: Option<i64>) -> ApiResult<Vec<Row>> {
    let mut q = c.prepare(
        "SELECT id, params, requested_by, created, decided_by, decided_at, state FROM quorum
         WHERE action = ?1 AND (?2 IS NULL OR id = ?2) ORDER BY id DESC LIMIT 50",
    )?;
    let r = q.query_map(params![ACTION, id], |r| {
        Ok(Row {
            id: r.get(0)?,
            p: serde_json::from_str(&r.get::<_, String>(1)?).unwrap_or(Value::Null),
            by: r.get(2)?,
            created: r.get(3)?,
            decided_by: r.get(4)?,
            decided_at: r.get(5)?,
            state: r.get(6)?,
        })
    })?;
    Ok(r.collect::<Result<_, _>>()?)
}

/// What became of the codes: `console.root_shell` (used) or a revocation, by target.
fn outcomes(c: &Connection) -> ApiResult<HashMap<String, String>> {
    let mut q = c.prepare(
        "SELECT target, action FROM audit WHERE action IN ('console.root_shell', 'console.unlock_revoke') ORDER BY seq",
    )?;
    let r = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
    Ok(r.collect::<Result<_, _>>()?)
}

/// `pending | rejected | expired | approved` (code not fetched yet) `| issued | used | revoked`.
fn status(r: &Row, outcomes: &HashMap<String, String>, now: i64) -> &'static str {
    let fresh = r.decided_at.is_some_and(|t| t + CODE_TTL_SECS > now);
    match r.state.as_str() {
        "pending" => "pending",
        "rejected" => "rejected",
        "approved" if fresh => "approved",
        "executed" => match outcomes.get(&target(r.id)).map(String::as_str) {
            Some("console.root_shell") => "used",
            Some(_) => "revoked",
            None if fresh => "issued",
            None => "expired",
        },
        _ => "expired",
    }
}

fn view(r: &Row, outcomes: &HashMap<String, String>, now: i64) -> Value {
    json!({
        "id": r.id, "hours": r.p["hours"], "reason": r.p["reason"], "requested_by": r.by, "created": r.created,
        "decided_by": r.decided_by, "decided_at": r.decided_at,
        "code_expires": r.decided_at.map(|t| t + CODE_TTL_SECS),
        "status": status(r, outcomes, now),
    })
}

/// The last 50 requests with their status (admin, security officer).
pub async fn list(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    require(&ctx, VIEW)?;
    crate::quorum::expire(&st)?;
    let c = st.cat.conn();
    let (all, out, now) = (rows(&c, None)?, outcomes(&c)?, catalog::now());
    Ok(Json(Value::Array(all.iter().map(|r| view(r, &out, now)).collect())))
}

fn one(c: &Connection, id: i64) -> ApiResult<Row> {
    rows(c, Some(id))?.pop().ok_or_else(ApiError::not_found)
}

/// Shows the code once, to the requester only, while it is `approved`.
pub async fn fetch_code(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    require(&ctx, ADMIN)?;
    let now = catalog::now();
    let (row, out) = {
        let c = st.cat.conn();
        (one(&c, id)?, outcomes(&c)?)
    };
    if row.by != ctx.name() {
        return Err(ApiError::forbidden());
    }
    match status(&row, &out, now) {
        "approved" => {}
        "issued" | "used" | "revoked" => return Err(ApiError::conflict("the code of this request was already shown")),
        s => return Err(ApiError::conflict(format!("request is {s}"))),
    }
    let code = console::new_code();
    let approved_by = row.decided_by.clone().unwrap_or_default();
    let u = Unlock {
        id,
        hash: console::hash(&code).expect("generated codes are valid"),
        hours: row.p["hours"].as_u64().unwrap_or(1).clamp(1, MAX_HOURS.into()) as u32,
        requested_by: row.by.clone(),
        approved_by: approved_by.clone(),
        reason: row.p["reason"].as_str().unwrap_or_default().to_owned(),
        issued: now,
        expires: row.decided_at.unwrap_or(now) + CODE_TTL_SECS,
    };
    // tmp file first, then claim the row (exactly once), then publish it for the gate
    let d = dir(&st);
    let tmp = d.join(format!(".{id}.tmp"));
    let io = |e: std::io::Error| ApiError::from(anyhow::anyhow!("{}: {e}", d.display()));
    std::fs::write(&tmp, serde_json::to_vec(&u).expect("serializable")).map_err(io)?;
    let solo = row.decided_by.as_deref() == Some(row.by.as_str());
    let alert = {
        let mut c = st.cat.conn();
        let tx = c.transaction()?;
        if tx.execute(
            "UPDATE quorum SET state = 'executed' WHERE id = ?1 AND state = 'approved'",
            [id],
        )? != 1
        {
            drop(tx);
            let _ = std::fs::remove_file(&tmp);
            return Err(ApiError::conflict("the code of this request was already shown"));
        }
        let msg = format!(
            "console unlock code issued to {} for a root shell of up to {} h on the appliance console ({}; reason: {})",
            u.requested_by,
            u.hours,
            if solo {
                "approvals disabled".to_owned()
            } else {
                format!("approved by {approved_by}")
            },
            u.reason
        );
        tx.execute(
            "INSERT INTO alerts (ts, last_ts, severity, kind, key, message) VALUES (?1, ?1, 'critical', 'console_unlock', ?2, ?3)",
            params![now, format!("console_unlock:{id}"), msg],
        )?;
        let alert = tx.last_insert_rowid();
        tx.commit()?;
        alert
    };
    std::fs::rename(&tmp, console::path(&d, id)).map_err(io)?;
    st.audit(
        ctx.name(),
        "console.unlock_code",
        &target(id),
        json!({"hours": u.hours, "approved_by": approved_by, "approvals": if solo { "disabled" } else { "enabled" },
               "expires": u.expires, "alert": alert}),
    )?;
    Ok(Json(
        json!({"id": id, "code": code, "hours": u.hours, "expires": u.expires}),
    ))
}

/// Withdraws an approved or issued code (admin, security officer).
pub async fn revoke(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    require(&ctx, VIEW)?;
    let now = catalog::now();
    let (row, out) = {
        let c = st.cat.conn();
        (one(&c, id)?, outcomes(&c)?)
    };
    let s = status(&row, &out, now);
    if !matches!(s, "approved" | "issued") {
        return Err(ApiError::conflict(format!("request is {s}")));
    }
    st.cat.conn().execute(
        "UPDATE quorum SET state = 'executed' WHERE id = ?1 AND state = 'approved'",
        [id],
    )?;
    match std::fs::remove_file(console::path(&dir(&st), id)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(anyhow::anyhow!("{}: {e}", dir(&st).display()).into())
        }
        _ => {}
    }
    st.audit(ctx.name(), "console.unlock_revoke", &target(id), json!({"was": s}))?;
    Ok(Json(json!({"id": id, "status": "revoked"})))
}

/// The running console root shell (setting written by the gate) for the
/// banner; appliance-wide roles that see alerts only.
pub fn shell_banner(c: &Connection, ctx: &Ctx) -> ApiResult<Value> {
    if ctx.scope().is_some() || ctx.user.role == "tenant_user" {
        return Ok(Value::Null);
    }
    Ok(catalog::setting(c, SHELL_SETTING)?
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or(Value::Null))
}

/// Alerts of the console path are closed only by someone who could have approved.
pub fn officer_only(kind: &str) -> bool {
    matches!(kind, "console_unlock" | "console_root_shell")
}
