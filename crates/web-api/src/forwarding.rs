//! Settings → Forwarding (Phase 14a, docs/control-plane.md "Forwarding"): the
//! syslog-over-TLS and HTTPS sinks of the setting `forwarding`
//! (`catalog::forwarding`), delivered by the scheduler's forwarder, and the
//! delivery status shown on the Audit page. Weakening what leaves the box
//! (a sink disabled or removed, its destination, trust or headers changed)
//! goes through approval (`settings.forwarding`).

use crate::auth::Ctx;
use crate::quorum::gate;
use crate::{ApiError, ApiResult, St, J};
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::forwarding::{self, Forwarding, Https, Syslog};
use catalog::rusqlite::Connection;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

const ADMIN: &[&str] = &["admin"];
const READ: &[&str] = &["admin", "security_officer"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyslogReq {
    #[serde(default = "yes")]
    enabled: bool,
    host: String,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    ca_pem: Option<String>,
    #[serde(default)]
    pin_sha256: Option<String>,
    #[serde(default)]
    app_name: Option<String>,
    #[serde(default)]
    facility: Option<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpsReq {
    #[serde(default = "yes")]
    enabled: bool,
    url: String,
    /// write-only values: null = keep the stored one (refused when the URL changes)
    #[serde(default)]
    headers: BTreeMap<String, Option<String>>,
    #[serde(default)]
    batch_max: Option<u32>,
    #[serde(default)]
    ca_pem: Option<String>,
    #[serde(default)]
    pin_sha256: Option<String>,
    /// `json_array` (default) or `splunk_hec`
    #[serde(default)]
    format: forwarding::Format,
    /// Splunk index (HEC only; empty = the token's default)
    #[serde(default)]
    index: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardingReq {
    #[serde(default)]
    syslog: Option<SyslogReq>,
    #[serde(default)]
    https: Option<HttpsReq>,
}

fn yes() -> bool {
    true
}

/// Header values are write-only: shown as null.
pub fn public(f: &Forwarding) -> Value {
    let mut v = json!(f);
    if let Some(h) = v.pointer_mut("/https/headers").and_then(Value::as_object_mut) {
        h.values_mut().for_each(|x| *x = Value::Null);
    }
    v
}

/// Current value for the quorum's "unchanged since the request" check.
pub fn value(c: &Connection) -> ApiResult<Option<Value>> {
    Ok(Some(json!(Forwarding::load(c)?)))
}

pub async fn get_settings(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(READ)?;
    Ok(Json(public(&Forwarding::load(&st.cat.conn())?)))
}

/// Empty / whitespace = none; else at least one PEM certificate (64 KiB max).
fn ca_pem(v: Option<String>, what: &str) -> ApiResult<Option<String>> {
    let Some(p) = v.filter(|p| !p.trim().is_empty()) else {
        return Ok(None);
    };
    let n = CertificateDer::pem_slice_iter(p.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map(|c| c.len())
        .unwrap_or(0);
    if p.len() > 64 << 10 || n == 0 {
        return Err(ApiError::bad(format!(
            "{what}.ca_pem: PEM certificate(s), at most 64 KiB"
        )));
    }
    Ok(Some(p))
}

/// SHA-256 of the server certificate, hex (colons allowed) → lowercase hex.
fn pin(v: Option<String>, what: &str) -> ApiResult<Option<String>> {
    let Some(p) = v.filter(|p| !p.trim().is_empty()) else {
        return Ok(None);
    };
    let hex: String = p.trim().chars().filter(|c| *c != ':').collect();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::bad(format!(
            "{what}.pin_sha256: 64 hex digits (SHA-256 of the certificate)"
        )));
    }
    Ok(Some(hex.to_ascii_lowercase()))
}

fn check_syslog(r: SyslogReq) -> ApiResult<Syslog> {
    let host = r.host.trim().trim_matches(['[', ']']).to_owned();
    crate::validate::host(&host).map_err(|_| ApiError::bad("syslog.host: host name or IP address"))?;
    let port = r.port.unwrap_or(6514);
    if port == 0 {
        return Err(ApiError::bad("syslog.port: 1..=65535"));
    }
    let app_name = r.app_name.unwrap_or_else(|| "nexus".into());
    if !(1..=48).contains(&app_name.len()) || !app_name.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(ApiError::bad(
            "syslog.app_name: 1..=48 printable ASCII characters, no spaces",
        ));
    }
    let facility = r.facility.unwrap_or(13);
    if facility > 23 {
        return Err(ApiError::bad("syslog.facility: 0..=23"));
    }
    Ok(Syslog {
        enabled: r.enabled,
        host,
        port,
        ca_pem: ca_pem(r.ca_pem, "syslog")?,
        pin_sha256: pin(r.pin_sha256, "syslog")?,
        app_name,
        facility,
    })
}

fn check_https(st: &St, r: HttpsReq, old: Option<&Https>) -> ApiResult<Https> {
    let ok = r.url.len() <= 2048
        && reqwest::Url::parse(&r.url)
            .is_ok_and(|u| u.scheme() == "https" && u.host_str().is_some() && u.username().is_empty());
    if !ok {
        return Err(ApiError::bad("https.url: https://host[:port]/path, without user info"));
    }
    let batch_max = r.batch_max.unwrap_or(100);
    if !(1..=1000).contains(&batch_max) {
        return Err(ApiError::bad("https.batch_max: 1..=1000"));
    }
    if r.headers.len() > 16 {
        return Err(ApiError::bad("https.headers: at most 16"));
    }
    let mut headers = BTreeMap::new();
    for (h, val) in r.headers {
        let token = (1..=64).contains(&h.len())
            && h.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
        let reserved = ["host", "content-type", "content-length"].contains(&h.to_ascii_lowercase().as_str());
        if !token || reserved {
            return Err(ApiError::bad(format!("https.headers: invalid header name {h:?}")));
        }
        let sealed = match val {
            Some(v) => {
                if v.is_empty() || v.len() > 4096 || v.chars().any(char::is_control) {
                    return Err(ApiError::bad("https.headers: values of 1..=4096 printable characters"));
                }
                st.seal_key()?.seal(&forwarding::header_location(&h, &r.url), &v)?
            }
            None => match old.filter(|o| o.url == r.url).and_then(|o| o.headers.get(&h)) {
                Some(v) => v.clone(),
                None => {
                    return Err(ApiError::bad(format!(
                        "https.headers: a value for {h} is required (new header or URL changed)"
                    )))
                }
            },
        };
        headers.insert(h, sealed);
    }
    let index = r.index.map(|i| i.trim().to_owned()).filter(|i| !i.is_empty());
    if let Some(i) = &index {
        let ok = i.len() <= 80
            && r.format == forwarding::Format::SplunkHec
            && i.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
        if !ok {
            return Err(ApiError::bad(
                "https.index: Splunk HEC only; lower-case letters, digits, _ and -, at most 80",
            ));
        }
    }
    Ok(Https {
        enabled: r.enabled,
        url: r.url,
        headers,
        batch_max,
        ca_pem: ca_pem(r.ca_pem, "https")?,
        pin_sha256: pin(r.pin_sha256, "https")?,
        format: r.format,
        index,
    })
}

/// Adding or enabling a sink applies at once; weakening it needs approval.
pub async fn put_settings(State(st): State<St>, ctx: Ctx, J(r): J<ForwardingReq>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let old = Forwarding::load(&st.cat.conn())?;
    let new = Forwarding {
        syslog: r.syslog.map(check_syslog).transpose()?,
        https: r.https.map(|h| check_https(&st, h, old.https.as_ref())).transpose()?,
    };
    if new.weaker_than(&old) {
        let p = json!({"forwarding": new, "old": old});
        return gate(&st, &ctx, "settings.forwarding", "settings/forwarding", p);
    }
    catalog::set_setting(&st.cat.conn(), forwarding::SETTING, &json!(new).to_string())?;
    let shown = public(&new);
    st.audit(ctx.name(), "settings.forwarding", "settings/forwarding", shown.clone())?;
    Ok(Json(shown).into_response())
}

/// One test message to every configured sink, sent by the scheduler (it holds
/// the header secrets): `{syslog?, https?}` = `"ok"` / `"error: …"`.
pub async fn test(State(st): State<St>, ctx: Ctx) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    crate::settings::run_test_job(&st, &ctx, "forward_test", json!({}), "forwarding test").await
}

/// Delivery status per configured sink (Audit page): the last delivered audit
/// seq against the chain head, the last success and the last error.
pub async fn status(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(READ)?;
    let c = st.cat.conn();
    let cfg = Forwarding::load(&c)?;
    let head: i64 = c.query_row("SELECT COALESCE(MAX(seq), 0) FROM audit", [], |r| r.get(0))?;
    let mut sinks = Vec::new();
    let configured = [
        cfg.syslog.as_ref().map(|s| ("syslog", s.enabled, s.dest())),
        cfg.https.as_ref().map(|h| ("https", h.enabled, h.dest())),
    ];
    for (sink, enabled, dest) in configured.into_iter().flatten() {
        let row = c
            .query_row(
                "SELECT audit_seq, event_seq, last_ok, last_error, last_error_ts, failing_since FROM forward_state
                 WHERE sink = ?1 AND dest = ?2",
                [sink, dest.as_str()],
                |r| {
                    Ok(json!({"audit_seq": r.get::<_, i64>(0)?, "event_seq": r.get::<_, i64>(1)?,
                              "last_ok": r.get::<_, Option<i64>>(2)?, "last_error": r.get::<_, Option<String>>(3)?,
                              "last_error_ts": r.get::<_, Option<i64>>(4)?, "failing_since": r.get::<_, Option<i64>>(5)?}))
                },
            )
            .ok()
            .unwrap_or_else(|| {
                json!({"audit_seq": 0, "event_seq": 0, "last_ok": null, "last_error": null, "last_error_ts": null,
                       "failing_since": null})
            });
        let mut v = json!({"sink": sink, "dest": dest, "enabled": enabled});
        if let (Some(o), Some(r)) = (v.as_object_mut(), row.as_object()) {
            o.extend(r.clone());
        }
        sinks.push(v);
    }
    Ok(Json(json!({"head_seq": head, "sinks": sinks})))
}
