//! Storage accounting (Phase 13d/e, docs/storage-accounting.md):
//! `GET /storage` (per tenant and per group: logical, data in, stored, ratios,
//! growth; computed in `reports::storage`, shared with the `storage` report),
//! the soft tenant quota `PUT /tenants/{name}/quota` and the anomaly
//! thresholds `GET|PUT /settings/anomaly`.

use crate::auth::Ctx;
use crate::quorum::gate;
use crate::{ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const ADMIN: &[&str] = &["admin"];
const SETTINGS_READ: &[&str] = &["admin", "security_officer"];
pub const ANOMALY_SETTING: &str = "anomaly";

/// (dedup, compression) over the scope, for the dashboard's capacity tile.
pub fn ratios(c: &Connection, scope: Option<&str>) -> ApiResult<(Option<f64>, Option<f64>)> {
    Ok(reports::storage::ratios(c, scope)?)
}

pub fn compute(c: &Connection, scope: Option<&str>, now: i64) -> ApiResult<Value> {
    Ok(reports::storage::compute(c, scope, now)?)
}

pub async fn storage(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    Ok(Json(compute(&st.cat.conn(), ctx.scope(), catalog::now())?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaReq {
    quota_bytes: Option<i64>,
}

/// Sets or clears a tenant's soft quota. Applies directly: it only raises
/// alerts (80 % warning, 100 % critical), backups are never blocked.
pub async fn put_quota(
    State(st): State<St>,
    ctx: Ctx,
    Path(name): Path<String>,
    J(r): J<QuotaReq>,
) -> ApiResult<Json<Value>> {
    ctx.require(ADMIN)?;
    if r.quota_bytes.is_some_and(|q| q <= 0) {
        return Err(ApiError::bad("quota_bytes: a positive number of bytes, or null"));
    }
    let n = st.cat.conn().execute(
        "UPDATE tenants SET quota_bytes = ?2 WHERE name = ?1",
        params![name, r.quota_bytes],
    )?;
    if n == 0 {
        return Err(ApiError::not_found());
    }
    let v = json!({"name": name, "quota_bytes": r.quota_bytes});
    st.audit(ctx.name(), "tenant.quota", &format!("tenant/{name}"), v.clone())?;
    Ok(Json(v))
}

/// Setting `anomaly` (scheduler `anomaly.rs` reads the same fields).
#[derive(Deserialize, Serialize, Clone, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Anomaly {
    pub enabled: bool,
    pub factor: f64,
    pub history: u64,
    pub floor_bytes: u64,
}

impl Default for Anomaly {
    fn default() -> Self {
        Anomaly {
            enabled: true,
            factor: 3.0,
            history: 14,
            floor_bytes: 1 << 30,
        }
    }
}

impl Anomaly {
    fn check(&self) -> ApiResult<()> {
        if !(1.5..=100.0).contains(&self.factor) {
            return Err(ApiError::bad("factor: 1.5..=100"));
        }
        if !(5..=100).contains(&self.history) {
            return Err(ApiError::bad("history: 5..=100 runs"));
        }
        if !(1 << 20..=1 << 50).contains(&self.floor_bytes) {
            return Err(ApiError::bad("floor_bytes: 1 MiB..=1 PiB"));
        }
        Ok(())
    }

    /// Detection gets less sensitive (switched off, higher factor or floor, …).
    fn weaker_than(&self, old: &Anomaly) -> bool {
        (old.enabled && !self.enabled) || self.factor > old.factor || self.floor_bytes > old.floor_bytes
    }
}

pub fn load_anomaly(c: &Connection) -> ApiResult<Anomaly> {
    Ok(catalog::setting(c, ANOMALY_SETTING)?
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or_default())
}

pub async fn get_anomaly(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(SETTINGS_READ)?;
    Ok(Json(json!(load_anomaly(&st.cat.conn())?)))
}

/// Stricter thresholds apply at once; weakening the detection (a ransomware
/// signal) goes through approval (`settings.anomaly`).
pub async fn put_anomaly(State(st): State<St>, ctx: Ctx, J(new): J<Anomaly>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    new.check()?;
    let old = load_anomaly(&st.cat.conn())?;
    if new.weaker_than(&old) {
        let p = json!({"anomaly": new, "old": old});
        return gate(&st, &ctx, "settings.anomaly", "settings/anomaly", p);
    }
    catalog::set_setting(&st.cat.conn(), ANOMALY_SETTING, &json!(new).to_string())?;
    st.audit(ctx.name(), "settings.anomaly", "settings/anomaly", json!(new))?;
    Ok(Json(json!(new)).into_response())
}

/// Current value for the quorum's "unchanged since the request" check.
pub fn anomaly_value(c: &Connection) -> ApiResult<Option<Value>> {
    Ok(Some(json!(load_anomaly(c)?)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anomaly_weakening() {
        let d = Anomaly::default();
        let off = Anomaly {
            enabled: false,
            ..d.clone()
        };
        assert!(off.weaker_than(&d));
        assert!(!d.weaker_than(&off));
        let strict = Anomaly {
            factor: 2.0,
            ..d.clone()
        };
        assert!(!strict.weaker_than(&d));
        assert!(d.weaker_than(&strict));
    }
}
