//! Settings → Time (docs/control-plane.md "Time servers"): the chrony sources of the appliance. The
//! root helper `nexus-time` writes `status.json` into its control dir (default /var/lib/nexus/time);
//! the web-api serves it and writes intent only: `request.json` (nexus-time.path).
//!
//! - `GET /settings/time` (admin, security officer, operator, viewer): the configured servers,
//!   chrony's sources (state, reach, offset, NTS) and tracking, the last request's outcome, a
//!   request waiting for approval.
//! - `PUT /settings/time {servers: [{host, nts}], allow_ntp}` (admin): validated here and again by
//!   the helper; gated (`time.servers`): the clock drives retention locks, sign-in codes and
//!   certificate checks. Plain NTP servers (`nts: false`) only with `allow_ntp: true`, the
//!   administrator's explicit opt-in; chrony then prefers authenticated sources.

use crate::auth::Ctx;
use crate::{random_hex, ApiError, ApiResult, St, J};
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const READ: &[&str] = &["admin", "security_officer", "operator", "viewer"];
const ADMIN: &[&str] = &["admin"];
pub const ACTION: &str = "time.servers";
pub const DIR: &str = "/var/lib/nexus/time";
/// The same limit as nexus-time.
pub const MAX_SERVERS: usize = 8;
/// The timer runs every 2 minutes: older than this is shown as stale.
const STALE_SECS: i64 = 600;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Server {
    pub host: String,
    pub nts: bool,
}

fn dir(st: &St) -> PathBuf {
    st.time_dir
        .get_or_init(|| {
            std::env::var_os("NEXUS_TIME_DIR")
                .map(Into::into)
                .unwrap_or_else(|| DIR.into())
        })
        .clone()
}

/// Appliance-wide: never for tenant-scoped accounts.
fn require(ctx: &Ctx, roles: &[&str]) -> ApiResult<()> {
    ctx.require(roles)?;
    if ctx.scope().is_some() {
        return Err(ApiError::forbidden());
    }
    Ok(())
}

fn read_json(p: &Path) -> Option<Value> {
    let b = std::fs::read(p).ok()?;
    (b.len() <= 4 << 20).then(|| serde_json::from_slice(&b).ok())?
}

/// A DNS name (letters, digits, hyphens; dots between labels, an optional trailing dot) or an
/// IPv4/IPv6 address: the rule of nexus-time's `valid_host`.
pub fn valid_host(h: &str) -> bool {
    if h.is_empty() || h.len() > 253 {
        return false;
    }
    if h.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    let labels: Vec<&str> = h.strip_suffix('.').unwrap_or(h).split('.').collect();
    let label_ok = |l: &&str| {
        let b = l.as_bytes();
        (1..=63).contains(&b.len())
            && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
            && b[0] != b'-'
            && b[b.len() - 1] != b'-'
    };
    labels.iter().all(label_ok) && !labels.last().is_some_and(|l| l.bytes().all(|c| c.is_ascii_digit()))
}

/// The checks of nexus-time, so a refusal is shown at once instead of after the approval.
pub fn validate(servers: &[Server], allow_ntp: bool) -> Result<(), String> {
    if servers.is_empty() || servers.len() > MAX_SERVERS {
        return Err(format!("between 1 and {MAX_SERVERS} time servers"));
    }
    for (i, s) in servers.iter().enumerate() {
        if !valid_host(&s.host) {
            return Err(format!("not a host name or address: {:?}", s.host));
        }
        if servers[..i].iter().any(|o| o.host.eq_ignore_ascii_case(&s.host)) {
            return Err(format!("{} is listed twice", s.host));
        }
    }
    if !allow_ntp && servers.iter().any(|s| !s.nts) {
        return Err("plain NTP servers (without NTS) need allow_ntp: an explicit opt-in".into());
    }
    Ok(())
}

/// The newest pending `time.servers` request.
fn pending_request(st: &St) -> ApiResult<Option<i64>> {
    use catalog::rusqlite::OptionalExtension;
    Ok(st
        .cat
        .conn()
        .query_row(
            "SELECT id FROM quorum WHERE action = ?1 AND state = 'pending' ORDER BY id DESC LIMIT 1",
            [ACTION],
            |r| r.get(0),
        )
        .optional()?)
}

/// GET /settings/time
pub async fn get_time(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    require(&ctx, READ)?;
    let d = dir(&st);
    let s = read_json(&d.join("status.json")).filter(Value::is_object);
    let empty = json!({});
    let v = s.as_ref().unwrap_or(&empty);
    let scanned = v["scanned"].as_i64();
    Ok(Json(json!({
        "available": s.is_some(),
        "stale": scanned.is_some_and(|t| catalog::now() - t > STALE_SECS),
        "scanned": scanned,
        "servers": v.get("servers").cloned().unwrap_or_else(|| json!([])),
        "allow_ntp": v["allow_ntp"].as_bool().unwrap_or(false),
        "sources": v.get("sources").cloned().unwrap_or_else(|| json!([])),
        "tracking": v.get("tracking").cloned().unwrap_or(Value::Null),
        "chrony_error": v.get("chrony_error").cloned().unwrap_or(Value::Null),
        "last": v.get("last").cloned().unwrap_or(Value::Null),
        "queued": d.join("request.json").exists(),
        "request_pending": pending_request(&st)?,
        "max_servers": MAX_SERVERS,
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutTime {
    servers: Vec<Server>,
    #[serde(default)]
    allow_ntp: bool,
}

/// PUT /settings/time {servers, allow_ntp}: validated, then gated (`time.servers`).
pub async fn put_time(State(st): State<St>, ctx: Ctx, J(r): J<PutTime>) -> ApiResult<Response> {
    require(&ctx, ADMIN)?;
    validate(&r.servers, r.allow_ntp).map_err(ApiError::bad)?;
    let current: Vec<Server> = read_json(&dir(&st).join("status.json"))
        .and_then(|v| serde_json::from_value(v["servers"].clone()).ok())
        .unwrap_or_default();
    if current == r.servers {
        return Ok(Json(json!({"unchanged": true})).into_response());
    }
    // allow_ntp only matters with a plain NTP server; recorded as sent for the approver
    let params = json!({"servers": r.servers, "allow_ntp": r.allow_ntp,
                        "plain_ntp": r.servers.iter().filter(|s| !s.nts).map(|s| &s.host).collect::<Vec<_>>()});
    crate::quorum::gate(&st, &ctx, ACTION, "time", params)
}

/// After an approved (or, with approvals disabled, direct) `time.servers`: hand it to
/// nexus-time (request.json, tmp + rename, group-readable). Its outcome appears as `last` in
/// the status.
pub fn after_approve(st: &St, action: &str, requested_by: &str, p: &Value, quorum_id: Option<i64>) {
    if action != ACTION {
        return;
    }
    let id = random_hex()[..32].to_owned();
    let req = json!({"id": id, "by": requested_by, "quorum_id": quorum_id,
                     "servers": p["servers"], "allow_ntp": p["allow_ntp"]});
    let d = dir(st);
    let tmp = d.join(".request.json.tmp");
    let r = (|| -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(&tmp, req.to_string())?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o640))?;
        std::fs::rename(&tmp, d.join("request.json"))
    })();
    match r {
        Ok(()) => eprintln!("web-api: {action} handed to nexus-time as {id}"),
        Err(e) => eprintln!("<3>web-api: after {action}: {}: {e}", d.display()),
    }
}

pub fn routes() -> axum::Router<St> {
    use axum::routing::get;
    axum::Router::new().route("/settings/time", get(get_time).put(put_time))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(h: &str, nts: bool) -> Server {
        Server { host: h.into(), nts }
    }

    #[test]
    fn hosts_as_nexus_time_checks_them() {
        for h in [
            "time.cloudflare.com",
            "ntp1",
            "10.0.0.5",
            "2001:db8::1",
            "a-b.example.",
            &format!("{}.de", "x".repeat(63)),
        ] {
            assert!(valid_host(h), "{h}");
        }
        for h in [
            "",
            "-a.example",
            "a_b.example",
            "a..b",
            "1.2.3.400",
            &format!("{}.de", "x".repeat(64)),
            "a b",
            "host;rm",
            "a.123",
        ] {
            assert!(!valid_host(h), "{h}");
        }
    }

    #[test]
    fn plain_ntp_needs_the_opt_in() {
        assert!(validate(&[s("nts.example", true)], false).is_ok());
        assert!(validate(&[s("ntp.internal", false)], false)
            .unwrap_err()
            .contains("allow_ntp"));
        assert!(validate(&[s("ntp.internal", false)], true).is_ok());
        assert!(validate(&[], true).is_err());
        assert!(validate(&[s("a.example", true), s("A.example", true)], true).is_err());
        let many: Vec<Server> = (0..9).map(|i| s(&format!("s{i}.example"), true)).collect();
        assert!(validate(&many, true).is_err());
    }
}
