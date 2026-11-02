//! Reboot and shut down the appliance (issue #179; top bar > Power, `nexusctl system`; the design of
//! NexusStor's issue #86). The web-api writes intent only: the one-shot `request.json` for `nexus-power`
//! (root, started by `nexus-power.path`), which schedules the action through logind
//! (`systemctl reboot|poweroff --when=`), cancels it, and writes its `status.json` (the pending action with
//! the boot it belongs to, the last outcome) that is served here.
//!
//! - `GET /system/power` (admin, operator, security officer): the appliance's name, a pending action, the last
//!   outcome, what blocks a power action now, the jobs running now (a reboot ends them), a request waiting for
//!   approval and whether the actions wait for approval.
//! - `POST /system/power` (admin, a signed-in person: never an API token) `{action: reboot|poweroff, reason,
//!   delay_s (0-300), force?}`: quorum `system.reboot` / `system.poweroff` with the reason and the number of
//!   running jobs (so the approver sees what the action interrupts); written for nexus-power once approved.
//! - `DELETE /system/power` (admin, signed in): cancels a scheduled action (audited `system.power_cancel`).
//!
//! Four eyes (approvals on): both actions. NexusStor gates only the shutdown, because its update apply reboots
//! ungated; here `update.apply` is gated, and a reboot ends every running backup and restore (the scheduler
//! fails them as interrupted when it starts again; the retry policy applies), so a single admin account
//! must not be able to stop the backups with either.
//!
//! Refused (409) while an action is scheduled already, or an update request waits for nexus-update or an
//! update is being checked and staged, unless `force` (nexus-power refuses as well while nexus-update holds
//! its lock). Checked again when the request is approved (crate::quorum::approve), which can be hours later.

use crate::auth::Ctx;
use crate::{random_hex, ApiError, ApiResult, St, J};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const ADMIN: &[&str] = &["admin"];
const READ: &[&str] = &["admin", "operator", "security_officer"];
pub const DIR: &str = "/var/lib/nexus/power";
/// The quorum actions (crate::quorum::WEB_ACTIONS); also the audit actions once executed.
pub const REBOOT_ACTION: &str = "system.reboot";
pub const POWEROFF_ACTION: &str = "system.poweroff";
pub const ACTIONS: &[&str] = &[REBOOT_ACTION, POWEROFF_ACTION];
const TARGET: &str = "appliance/power";
pub const MAX_DELAY_S: u64 = 300;
/// A pending action whose time is this far gone without a reboot was cancelled outside the web UI
/// (`shutdown -c` on the console) or failed.
const OVERDUE_S: i64 = 120;
const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";

fn dir(st: &St) -> PathBuf {
    st.power_dir
        .get_or_init(|| {
            std::env::var_os("NEXUS_POWER_DIR")
                .map(Into::into)
                .unwrap_or_else(|| DIR.into())
        })
        .clone()
}

/// Appliance-wide accounts only.
fn require(ctx: &Ctx, roles: &[&str]) -> ApiResult<()> {
    ctx.require(roles)?;
    if ctx.scope().is_some() {
        return Err(ApiError::forbidden());
    }
    Ok(())
}

/// A person in their own session (the token allow-list refuses these routes as well).
fn person(ctx: &Ctx) -> ApiResult<()> {
    if ctx.token.is_some() {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "the appliance is rebooted or shut down by a person, not with an API token".into(),
        ));
    }
    Ok(())
}

fn boot_id() -> String {
    std::fs::read_to_string(BOOT_ID)
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

fn read_json(p: &Path) -> Option<Value> {
    let b = std::fs::read(p).ok()?;
    (b.len() <= 1 << 20).then(|| serde_json::from_slice(&b).ok())?
}

/// The pending action of `status.json`, if it belongs to this boot and is not overdue.
fn pending(status: &Value, boot: &str, now: i64) -> Option<Value> {
    let p = status.get("pending").filter(|p| p.is_object())?;
    (status["boot_id"] == boot && p["at"].as_i64().is_some_and(|at| at + OVERDUE_S > now)).then(|| p.clone())
}

fn status_file(d: &Path) -> Value {
    read_json(&d.join("status.json")).unwrap_or(Value::Null)
}

/// The request still waiting for `nexus-power` (normally a second).
fn waiting(d: &Path) -> Option<Value> {
    read_json(&d.join("request.json")).filter(Value::is_object)
}

/// What blocks a power action now: an update request waiting for nexus-update, an update being checked.
pub fn blockers(st: &St) -> Vec<String> {
    let u = crate::settings::update_status(&crate::settings::update_dir(st));
    if let Some(r) = u["pending_request"].as_str() {
        vec![format!(
            "an update request ({r}) waits for nexus-update (Settings > Updates)"
        )]
    } else if u["status"] == "checking" {
        vec!["an update is being checked and staged (Settings > Updates)".into()]
    } else {
        vec![]
    }
}

/// The jobs running now by kind (`[{kind, count}]`) and their total: what a reboot or shutdown ends.
fn running_jobs(st: &St) -> ApiResult<(i64, Value)> {
    let c = st.cat.conn();
    let mut q = c.prepare("SELECT kind, COUNT(*) FROM jobs WHERE state = 'running' GROUP BY kind ORDER BY kind")?;
    let rows: Vec<(String, i64)> = q
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    let total = rows.iter().map(|(_, n)| n).sum();
    Ok((
        total,
        rows.into_iter().map(|(k, n)| json!({"kind": k, "count": n})).collect(),
    ))
}

/// The newest power request waiting for approval: `{id, action, requested_by}`.
fn pending_request(st: &St) -> ApiResult<Option<Value>> {
    use catalog::rusqlite::OptionalExtension;
    Ok(st
        .cat
        .conn()
        .query_row(
            "SELECT id, action, requested_by FROM quorum WHERE action IN (?1, ?2) AND state = 'pending'
             ORDER BY id DESC LIMIT 1",
            [REBOOT_ACTION, POWEROFF_ACTION],
            |r| {
                Ok(json!({"id": r.get::<_, i64>(0)?, "action": r.get::<_, String>(1)?,
                          "requested_by": r.get::<_, String>(2)?}))
            },
        )
        .optional()?)
}

pub fn view(st: &St) -> ApiResult<Value> {
    let d = dir(st);
    let s = status_file(&d);
    let approvals = crate::quorum::enabled(st)?;
    let (total, by_kind) = running_jobs(st)?;
    let req = waiting(&d).filter(|r| r["action"] != "cancel");
    Ok(json!({
        "appliance": crate::nexusstor::hostname(),
        "pending": pending(&s, &boot_id(), catalog::now()),
        // written, not yet taken by nexus-power
        "requested": req,
        "last": s.get("last").filter(|l| l.is_object()),
        "blockers": blockers(st),
        "running_jobs": total,
        "running_by_kind": by_kind,
        "request_pending": pending_request(st)?,
        "approval_required": approvals,
        "max_delay_s": MAX_DELAY_S,
    }))
}

pub async fn get_power(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    require(&ctx, READ)?;
    Ok(Json(view(&st)?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PowerReq {
    action: String,
    reason: String,
    #[serde(default)]
    delay_s: u64,
    #[serde(default)]
    force: bool,
}

/// The request's checks without the appliance's state: `(quorum action, reason)` normalized.
pub fn validate(r: &PowerReq) -> Result<(&'static str, String), String> {
    let action = match r.action.as_str() {
        "reboot" => REBOOT_ACTION,
        "poweroff" => POWEROFF_ACTION,
        a => return Err(format!("action {a:?}: reboot or poweroff")),
    };
    let reason = r.reason.trim();
    let n = reason.chars().count();
    if !(3..=500).contains(&n) || reason.chars().any(char::is_control) {
        return Err("reason: 3-500 characters, one line (it goes to the audit log)".into());
    }
    if r.delay_s > MAX_DELAY_S {
        return Err(format!("delay_s: 0-{MAX_DELAY_S}"));
    }
    Ok((action, reason.to_owned()))
}

/// The appliance's state against the request (also when it is approved, hours later): 409 while an action
/// is scheduled or, unless forced, an update is in progress.
pub fn check(st: &St, p: &Value) -> ApiResult<()> {
    let d = dir(st);
    if pending(&status_file(&d), &boot_id(), catalog::now()).is_some()
        || waiting(&d).is_some_and(|r| r["action"] != "cancel")
    {
        return Err(ApiError::conflict(
            "a reboot or shutdown is scheduled already: cancel it first",
        ));
    }
    if p["force"] != true {
        let b = blockers(st);
        if !b.is_empty() {
            return Err(ApiError::conflict(format!(
                "not now: {} (wait, or force it)",
                b.join("; ")
            )));
        }
    }
    Ok(())
}

/// POST /system/power: quorum `system.reboot` / `system.poweroff` (202 `{quorum_id}`; with approvals off
/// 200 `{executed: true}` and the request is written at once).
pub async fn post_power(State(st): State<St>, ctx: Ctx, J(r): J<PowerReq>) -> ApiResult<Response> {
    require(&ctx, ADMIN)?;
    person(&ctx)?;
    let (action, reason) = validate(&r).map_err(ApiError::bad)?;
    let p = json!({"action": r.action, "reason": reason, "delay_s": r.delay_s, "force": r.force,
                   "running_jobs": running_jobs(&st)?.0});
    check(&st, &p)?;
    let o = crate::quorum::request(&st, &ctx, action, TARGET, p)?;
    Ok(crate::quorum::accepted(o, json!({"delay_s": r.delay_s})))
}

/// After an executed `system.reboot` / `system.poweroff` (approved, or direct with approvals off): the
/// request for nexus-power (tmp + rename, group-readable). Its outcome appears as `last` in the status.
pub fn after_approve(st: &St, action: &str, requested_by: &str, p: &Value, approved_by: Option<&str>) {
    if !ACTIONS.contains(&action) {
        return;
    }
    let req = json!({
        "id": &random_hex()[..32],
        "action": p["action"], "delay_s": p["delay_s"].as_u64().unwrap_or(0), "reason": p["reason"],
        "force": p["force"] == true, "running_jobs": p["running_jobs"],
        "requested_by": requested_by, "approved_by": approved_by, "time": catalog::now(),
    });
    match write_request(&dir(st), &req) {
        Ok(()) => eprintln!("web-api: {action} handed to nexus-power as {}", req["id"]),
        Err(e) => eprintln!("<3>web-api: after {action}: {}", e.1),
    }
}

fn write_request(d: &Path, req: &Value) -> ApiResult<()> {
    use std::os::unix::fs::PermissionsExt;
    let tmp = d.join(".request.json.tmp");
    let r = (|| -> std::io::Result<()> {
        std::fs::write(&tmp, req.to_string())?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o640))?;
        std::fs::rename(&tmp, d.join("request.json"))
    })();
    r.map_err(|e| anyhow::anyhow!("{}: {e}", d.display()).into())
}

/// DELETE /system/power: cancels a scheduled (or still waiting) action.
pub async fn cancel_power(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    require(&ctx, ADMIN)?;
    person(&ctx)?;
    let d = dir(&st);
    let pend = pending(&status_file(&d), &boot_id(), catalog::now())
        .or_else(|| waiting(&d).filter(|r| r["action"] != "cancel"))
        .ok_or_else(|| ApiError::conflict("no reboot or shutdown is scheduled"))?;
    // replaces a request nexus-power has not taken yet: then nothing was ever scheduled
    let req = json!({"id": &random_hex()[..32], "action": "cancel", "requested_by": ctx.name(),
                     "time": catalog::now()});
    write_request(&d, &req)?;
    st.audit(
        ctx.name(),
        "system.power_cancel",
        TARGET,
        json!({"action": pend["action"], "at": pend["at"], "requested_by": pend["requested_by"]}),
    )?;
    Ok(Json(json!({"status": "cancelled", "action": pend["action"]})))
}

pub fn routes() -> axum::Router<St> {
    use axum::routing::get;
    axum::Router::new().route("/system/power", get(get_power).post(post_power).delete(cancel_power))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(v: Value) -> PowerReq {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn validation() {
        let ok = req(json!({"action": "reboot", "reason": "  kernel update  ", "delay_s": 60}));
        assert_eq!(validate(&ok), Ok((REBOOT_ACTION, "kernel update".to_owned())));
        let off = req(json!({"action": "poweroff", "reason": "move rack"}));
        assert_eq!(validate(&off).unwrap().0, POWEROFF_ACTION);
        for (v, want) in [
            (json!({"action": "halt", "reason": "abc"}), "action"),
            (json!({"action": "reboot", "reason": "ab"}), "reason"),
            (json!({"action": "reboot", "reason": "a\nb c"}), "reason"),
            (json!({"action": "reboot", "reason": "x".repeat(501)}), "reason"),
            (json!({"action": "reboot", "reason": "abc", "delay_s": 301}), "delay_s"),
        ] {
            let e = validate(&req(v.clone())).unwrap_err();
            assert!(e.contains(want), "{v}: {e}");
        }
        assert!(serde_json::from_value::<PowerReq>(json!({"action": "reboot", "reason": "abc", "x": 1})).is_err());
    }

    #[test]
    fn pending_belongs_to_this_boot() {
        let s = json!({"boot_id": "b1", "pending": {"action": "reboot", "at": 1000}});
        assert!(pending(&s, "b1", 1000).is_some());
        assert!(pending(&s, "b1", 1000 + OVERDUE_S).is_none(), "overdue");
        assert!(pending(&s, "b2", 1000).is_none(), "after the reboot");
        assert!(pending(&json!({"boot_id": "b1", "pending": null}), "b1", 0).is_none());
    }
}
