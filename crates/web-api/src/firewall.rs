//! Settings → Firewall (Phase 16c, docs/control-plane.md "Inbound firewall"):
//! per-service inbound source restrictions (catalog::firewall). Outbound stays
//! automatic (scheduler allow-list) and is only shown here.
//!
//! - `GET /firewall` (admin, security officer): per service the configured
//!   sources, what nftables holds now, pending requests; the outbound sets;
//!   recent blocked inbound attempts. The effective state comes from the status
//!   file nexus-nft-sync publishes (crate nftsync::status); the web-api never
//!   talks to nft itself.
//! - `PUT /firewall/inbound/{service}` (admin): every change needs approval
//!   (`firewall.inbound`). For services that can lock the administrators out
//!   (`web`), a list that does not contain the requester's address is refused
//!   unless `force` and `confirm` = that address. Console reset:
//!   `nexus-setup reset-firewall`.

use crate::auth::{ClientIp, Ctx};
use crate::quorum::gate;
use crate::{ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use catalog::access;
use catalog::firewall::{self, Rule};
use catalog::rusqlite::Connection;
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;

const ADMIN: &[&str] = &["admin"];
const READ: &[&str] = &["admin", "security_officer"];
pub const ACTION: &str = "firewall.inbound";
/// a status older than this is reported as stale (the timer runs every minute)
const STALE_SECS: i64 = 300;

pub fn routes() -> Router<St> {
    Router::new()
        .route("/firewall", get(get_firewall))
        .route("/firewall/inbound/{service}", put(put_inbound))
}

/// Appliance-wide: never for tenant-scoped accounts.
fn require(ctx: &Ctx, roles: &[&str]) -> ApiResult<()> {
    ctx.require(roles)?;
    if ctx.scope().is_some() {
        return Err(ApiError::forbidden());
    }
    Ok(())
}

fn status_file(st: &St) -> PathBuf {
    st.nft_status
        .get_or_init(|| {
            std::env::var_os("NEXUS_NFT_STATUS")
                .map(Into::into)
                .unwrap_or_else(|| "/run/nexus-nft-status/status.json".into())
        })
        .clone()
}

fn read_status(st: &St) -> Option<Value> {
    let b = std::fs::read(status_file(st)).ok()?;
    (b.len() <= 4 << 20).then(|| serde_json::from_slice(&b).ok())?
}

/// Pending `firewall.inbound` requests per service.
fn pending(c: &Connection) -> ApiResult<Vec<(String, i64)>> {
    let rows = c
        .prepare("SELECT id, params FROM quorum WHERE action = ?1 AND state = 'pending' ORDER BY id")?
        .query_map([ACTION], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, p)| {
            let p: Value = serde_json::from_str(&p).ok()?;
            Some((p["service"].as_str()?.to_owned(), id))
        })
        .collect())
}

/// The newest pending request for `service`, if any.
pub fn pending_for(c: &Connection, service: &str) -> ApiResult<Option<i64>> {
    Ok(newest(&pending(c)?, service))
}

fn newest(pend: &[(String, i64)], service: &str) -> Option<i64> {
    pend.iter().rev().find(|(s, _)| s == service).map(|(_, id)| *id)
}

pub async fn get_firewall(State(st): State<St>, ctx: Ctx, ClientIp(ip): ClientIp) -> ApiResult<Json<Value>> {
    require(&ctx, READ)?;
    let (inbound, pend) = {
        let c = st.cat.conn();
        (firewall::load(&c)?, pending(&c)?)
    };
    let status = read_status(&st);
    let sets = |name: &str| {
        status
            .as_ref()
            .map(|s| s["sets"][name].clone())
            .filter(serde_json::Value::is_array)
    };
    let services: Vec<Value> = firewall::SERVICES
        .iter()
        .map(|s| {
            let r = inbound.rule(s.id);
            let effective = match (
                s.available,
                sets(&format!("in_{}_v4", s.id)),
                sets(&format!("in_{}_v6", s.id)),
            ) {
                (true, Some(v4), Some(v6)) => json!({"v4": v4, "v6": v6}),
                _ => Value::Null,
            };
            json!({
                "id": s.id, "ports": s.ports, "lockout": s.lockout, "available": s.available,
                "can_disable": s.can_disable, "enabled": r.enabled, "allow": r.allow, "effective": effective,
                "pending": newest(&pend, s.id),
            })
        })
        .collect();
    let ts = status.as_ref().and_then(|s| s["ts"].as_i64());
    let join = |a: &str, b: &str| -> Value {
        let mut v: Vec<Value> = Vec::new();
        for n in [a, b] {
            v.extend(sets(n).and_then(|x| x.as_array().cloned()).unwrap_or_default());
        }
        Value::Array(v)
    };
    let outbound = status.as_ref().map(|_| {
        json!({
            "endpoints": join("allowed_out_v4", "allowed_out_v6"),
            "dns": join("dns_servers_v4", "dns_servers_v6"),
            "nts": join("nts_servers_v4", "nts_servers_v6"),
        })
    });
    Ok(Json(json!({
        "services": services,
        "client_ip": ip,
        "client_allowed": access::allows(&inbound.rule("web").allow, &ip),
        "status_ts": ts,
        "status_stale": ts.is_none_or(|t| catalog::now() - t > STALE_SECS),
        "outbound": outbound,
        "drops": status.as_ref().map_or(json!([]), |s| s["drops"].clone()),
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundReq {
    pub allow: Vec<String>,
    /// absent = unchanged
    #[serde(default)]
    pub enabled: Option<bool>,
    /// accept a list that does not contain the requesting client's address
    #[serde(default)]
    pub force: bool,
    /// with `force`: the client's address, typed
    #[serde(default)]
    pub confirm: String,
}

/// Validates a change of `service` and gates it (`firewall.inbound`); also
/// used by the 14d route `PUT /settings/mgmt-allow` (service `web`).
pub fn request(st: &St, ctx: &Ctx, ip: &str, service: &str, r: &InboundReq) -> ApiResult<Response> {
    require(ctx, ADMIN)?;
    let svc = firewall::service(service).ok_or_else(ApiError::not_found)?;
    if !svc.available {
        return Err(ApiError::conflict(format!(
            "{service}: nothing listens on {} on this appliance, so there is nothing to restrict",
            svc.ports
        )));
    }
    if r.enabled == Some(false) && !svc.can_disable {
        return Err(ApiError::bad(format!(
            "{service} cannot be switched off, only restricted to source addresses"
        )));
    }
    let list = firewall::normalize(&r.allow).map_err(ApiError::bad)?;
    let old = firewall::load(&st.cat.conn())?.rule(service);
    let new = Rule {
        allow: list,
        enabled: Some(r.enabled.unwrap_or(old.enabled == Some(true))),
    };
    if new == old {
        return Ok(Json(json!({"service": service, "rule": new})).into_response());
    }
    if service == "web" && new.allow.is_empty() {
        crate::vault::refuse(&st.cat.conn(), "an unrestricted web inbound rule")?;
    }
    let confirmed = r.force && r.confirm.trim() == ip;
    if svc.lockout && !access::allows(&new.allow, ip) && !confirmed {
        return Err(ApiError::conflict(format!(
            "the list for {service} does not contain your address {ip}: you would lose access to the web UI; \
             add it, or confirm with force and confirm = \"{ip}\""
        )));
    }
    let p = json!({"service": service, "rule": new, "old": old, "requested_from": ip});
    gate(st, ctx, ACTION, &format!("firewall/inbound/{service}"), p)
}

pub async fn put_inbound(
    State(st): State<St>,
    ctx: Ctx,
    ClientIp(ip): ClientIp,
    Path(service): Path<String>,
    J(r): J<InboundReq>,
) -> ApiResult<Response> {
    request(&st, &ctx, &ip, &service, &r)
}

/// Approved `firewall.inbound` (crate::quorum); refused if the service's rule
/// changed since the request.
pub fn execute(c: &Connection, p: &Value) -> ApiResult<()> {
    let service = p["service"].as_str().unwrap_or_default();
    if firewall::service(service).is_none_or(|s| !s.available) {
        return Err(ApiError::bad("unknown service"));
    }
    let mut inbound = firewall::load(c)?;
    if json!(inbound.rule(service)) != p["old"] {
        return Err(ApiError::conflict(
            "the rule changed since this request was made; reject it and request the change again",
        ));
    }
    let rule: Rule = serde_json::from_value(p["rule"].clone()).map_err(|_| ApiError::bad("quorum params: rule"))?;
    if service == "web" && rule.allow.is_empty() {
        crate::vault::refuse(c, "an unrestricted web inbound rule")?;
    }
    inbound.services.insert(service.to_owned(), rule);
    firewall::store(c, &inbound)?;
    Ok(())
}
