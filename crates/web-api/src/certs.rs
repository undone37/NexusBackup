//! Settings → Certificate (docs/control-plane.md "Web certificate"): the served
//! chain, a CSR generated on the appliance, importing the signed chain and
//! reverting. The key and the files in /etc/nexus/tls belong to the root helper
//! nexus-tls (crate webtls); the web-api only writes its request file and reads
//! the answer. The new certificate is picked up by `tls::WebCert` on the next
//! handshake. Replication secondaries pin the self-signed identity certificate,
//! which replication connections keep getting: an import breaks no pin.

use crate::auth::Ctx;
use crate::{random_hex, ApiError, ApiResult, AppState, St, J};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// Catalog setting the scheduler reads for expiry alerts:
/// `{web: {not_after, sha256, subject, imported}, identity: {not_after, sha256}}`.
pub const STATUS_SETTING: &str = "tls_status";
const HELPER_TIMEOUT: Duration = Duration::from_secs(30);

pub fn paths(st: &AppState) -> webtls::Paths {
    st.tls
        .get_or_init(|| {
            let e = |k: &str, d: &str| std::env::var_os(k).map_or_else(|| d.into(), Into::into);
            webtls::Paths {
                tls: e("NEXUS_TLS_DIR", webtls::TLS_DIR),
                req: e("NEXUS_TLS_REQ_DIR", webtls::REQ_DIR),
            }
        })
        .clone()
}

/// Stores what the scheduler needs for the expiry alerts (on start, hourly and
/// after every change).
pub fn publish_status(st: &AppState) -> ApiResult<()> {
    let s = webtls::status(&paths(st))?;
    let pick = |c: &Value| json!({"not_after": c["not_after"], "sha256": c["sha256"], "subject": c["subject"]});
    let mut web = pick(&s["chain"][0]);
    web["imported"] = json!(s["active"] == "imported");
    let v = json!({"web": web, "identity": pick(&s["identity"])}).to_string();
    let c = st.cat.conn();
    if catalog::setting(&c, STATUS_SETTING)?.as_deref() != Some(v.as_str()) {
        catalog::set_setting(&c, STATUS_SETTING, &v)?;
    }
    Ok(())
}

/// Status for the UI: active certificate (`imported` / `self_signed`), its chain,
/// the identity certificate replication secondaries pin, the pending CSR.
pub async fn get_status(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(&["admin", "security_officer"])?;
    let mut s = webtls::status(&paths(&st))?;
    let peers: i64 = st.cat.conn().query_row(
        "SELECT COUNT(*) FROM replication_peers WHERE state = 'enrolled'",
        [],
        |r| r.get(0),
    )?;
    // who pins what: secondaries pin the identity certificate (unchanged by an
    // import); agents check the appliance's client certificate from the agent CA
    s["pins"] = json!({"replication_identity": s["identity"]["sha256"], "replication_peers": peers});
    Ok(Json(s))
}

static HELPER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// One request to nexus-tls (serialised); its answer or 400 with its error.
async fn helper(st: &AppState, mut req: Value) -> ApiResult<Value> {
    let _one = HELPER.lock().await;
    let p = paths(st);
    let id = random_hex()[..16].to_owned();
    req["id"] = json!(id);
    let _ = std::fs::remove_file(p.result());
    // 0640: nexus-tls runs as root with group nexus-webapi and no capabilities
    webtls::write_atomic(&p.request(), req.to_string().as_bytes(), 0o640)?;
    let end = Instant::now() + HELPER_TIMEOUT;
    while Instant::now() < end {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let Ok(Some(raw)) = webtls::read_small(&p.result(), webtls::MAX_CHAIN * 2) else {
            continue;
        };
        let Ok(v) = serde_json::from_slice::<Value>(&raw) else {
            continue;
        };
        if v["id"] != json!(id) {
            continue;
        }
        let _ = std::fs::remove_file(p.result());
        if v["ok"] != json!(true) {
            return Err(ApiError::bad(
                v["error"].as_str().unwrap_or("nexus-tls failed").to_owned(),
            ));
        }
        return Ok(v);
    }
    let _ = std::fs::remove_file(p.request());
    Err(ApiError(
        StatusCode::SERVICE_UNAVAILABLE,
        "the certificate helper (nexus-tls) did not answer; check nexus-tls.path".into(),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsrReq {
    cn: String,
    #[serde(default)]
    sans: Vec<String>,
}

/// New key (stays on the appliance) and CSR; replaces an earlier pending CSR.
pub async fn csr(State(st): State<St>, ctx: Ctx, J(r): J<CsrReq>) -> ApiResult<Json<Value>> {
    ctx.require(&["admin"])?;
    if r.cn.len() > 253 || r.sans.len() > webtls::MAX_SANS || r.sans.iter().any(|s| s.len() > 253) {
        return Err(ApiError::bad("cn / sans: too long or too many"));
    }
    let v = helper(&st, json!({"op": "csr", "cn": r.cn, "sans": r.sans})).await?;
    st.audit(ctx.name(), "tls.csr", "tls/web", json!({"pending": v["pending"]}))?;
    Ok(Json(json!({"csr_pem": v["csr_pem"], "pending": v["pending"]})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallReq {
    chain_pem: String,
}

/// Validated by nexus-tls (key, order, dates, names, usage), then served.
pub async fn install(State(st): State<St>, ctx: Ctx, J(r): J<InstallReq>) -> ApiResult<Json<Value>> {
    ctx.require(&["admin"])?;
    if r.chain_pem.len() > webtls::MAX_CHAIN {
        return Err(ApiError::bad("chain_pem: too large"));
    }
    let v = helper(&st, json!({"op": "install", "chain_pem": r.chain_pem})).await?;
    let leaf = &v["chain"][0];
    st.audit(
        ctx.name(),
        "tls.install",
        "tls/web",
        json!({"subject": leaf["subject"], "issuer": leaf["issuer"], "sha256": leaf["sha256"],
               "not_after": leaf["not_after"], "sans": leaf["sans"], "warnings": v["warnings"]}),
    )?;
    publish_status(&st)?;
    Ok(Json(json!({"chain": v["chain"], "warnings": v["warnings"]})))
}

/// Back to the previous imported certificate, or to the self-signed one.
pub async fn revert(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(&["admin"])?;
    let v = helper(&st, json!({"op": "revert"})).await?;
    publish_status(&st)?;
    let s = webtls::status(&paths(&st))?;
    st.audit(
        ctx.name(),
        "tls.revert",
        "tls/web",
        json!({"active": v["active"], "sha256": s["chain"][0]["sha256"]}),
    )?;
    Ok(Json(json!({"active": v["active"]})))
}
