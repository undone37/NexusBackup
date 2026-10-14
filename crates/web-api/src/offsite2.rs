//! Second offsite target with its own retention (Phase 30, docs/control-plane.md
//! "Second offsite target", docs/netbackup-comparison.md Tier 2).
//!
//! `PUT /tenants/{name}/offsite2 {target}` (admins): `target` has the shape of a
//! tenant offsite config (`remote` sftp or s3, `uploaders`, `bwlimit`,
//! `windows`, `timezone`) plus its own retention `gfs` (counts per class;
//! offsite retention is never shorter than local: the scheduler keeps the
//! larger of it and the policies' value); `null` removes it. It is stored as
//! `tenants.offsite.second`; the S3 secret is sealed to the scheduler at the
//! location `tenant/<t>/offsite/second/remote/secret_key` and, write-only like
//! the first target's, kept when omitted for the same endpoint. Needs a first
//! target. Setting it up applies at once; changing or removing an existing one
//! is the approval `tenant.update` (like the first target), except a pure
//! bandwidth tightening. Audited `tenant.offsite2`.

use crate::auth::Ctx;
use crate::quorum::gate;
use crate::resources::{check_offsite, public_offsite, tenant_value};
use crate::{ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::rusqlite::params;
use catalog::secret::tenant_owner;
use serde::Deserialize;
use serde_json::{json, Value};

/// Fields the stored S3 secret of the second target is bound to (as for the first).
const S3_BINDING: &[&str] = &["endpoint", "region", "bucket", "access_key", "path_style", "ca_pem"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecondReq {
    target: Option<Value>,
}

pub async fn put_second(
    State(st): State<St>,
    ctx: Ctx,
    Path(name): Path<String>,
    J(r): J<SecondReq>,
) -> ApiResult<Response> {
    ctx.require(&["admin"])?;
    crate::lockdown::refuse(&st.cat.conn(), &name, "tenant changes")?;
    let old = tenant_value(&st.cat.conn(), &name)?.ok_or_else(ApiError::not_found)?;
    let mut offsite = old["offsite"].clone();
    if !offsite.is_object() {
        offsite = json!({});
    }
    let before = offsite.get("second").cloned().filter(Value::is_object);
    match &r.target {
        None | Some(Value::Null) => {
            if let Some(o) = offsite.as_object_mut() {
                o.remove("second");
            }
        }
        Some(t) => {
            if !offsite["remote"].is_object() {
                return Err(ApiError::bad(
                    "target: the tenant has no offsite target yet: set up the first one",
                ));
            }
            let s3 = check_offsite(t)?;
            if t.get("remote").is_none_or(|r| !r.is_object()) {
                return Err(ApiError::bad("target.remote: required (sftp or s3)"));
            }
            let mut t = t.clone();
            if let Some(mut s) = s3 {
                if s.secret_key_missing() {
                    // the stored (sealed) secret only for the same S3 endpoint
                    let o = before.as_ref().map_or(&Value::Null, |b| &b["remote"]);
                    let n = serde_json::to_value(&s).map_err(anyhow::Error::from)?;
                    if o["type"] != "s3"
                        || !o["secret_key"].is_string()
                        || S3_BINDING.iter().any(|k| o.get(*k) != n.get(*k))
                    {
                        return Err(ApiError::bad(
                            "target.remote.secret_key: required when endpoint, region, bucket, access_key, path_style or ca_pem change",
                        ));
                    }
                    s.set_secret(o["secret_key"].as_str().map(str::to_owned));
                }
                t["remote"] = serde_json::to_value(&s).map_err(anyhow::Error::from)?;
            }
            offsite["second"] = t;
            // sealed in place: the location names the second target (`/second/remote/secret_key`)
            st.seal_key()?.seal_all(&tenant_owner(&name), &mut offsite)?;
        }
    }
    let after = offsite.get("second").cloned();
    let target = format!("tenant/{name}");
    if before.is_some() && before != after && !bandwidth_only(before.as_ref(), after.as_ref()) {
        let p = json!({"name": name, "offsite": offsite, "old": old});
        return gate(&st, &ctx, "tenant.update", &target, p);
    }
    let n = st.cat.conn().execute(
        "UPDATE tenants SET offsite = ?2 WHERE name = ?1",
        params![name, offsite.to_string()],
    )?;
    if n == 0 {
        return Err(ApiError::not_found());
    }
    let shown = public_offsite(&offsite);
    st.audit(
        ctx.name(),
        "tenant.offsite2",
        &target,
        json!({"second": shown.get("second")}),
    )?;
    Ok(Json(json!({"name": name, "offsite": shown})).into_response())
}

/// Only `bwlimit` / `windows` / `timezone` changed and nothing allows more
/// (the first target's rule, `resources::offsite_tightened`).
fn bandwidth_only(old: Option<&Value>, new: Option<&Value>) -> bool {
    match (old, new) {
        (Some(o), Some(n)) => crate::resources::offsite_tightened(o, n),
        _ => false,
    }
}
