//! New-device sign-in notice (Phase 28, docs/control-plane.md "New-device
//! sign-in"). Every new session (password + second factor, passkey, OIDC)
//! records the account's device: browser family + operating system from the
//! user agent, and the client network prefix (IPv4 /24, IPv6 /48). The first
//! sign-in from a combination the account has not used before raises
//! `login_new_device` (warning for admins and security officers, info for the
//! other roles; forwarded to SIEM sinks like every alert), which the scheduler
//! also mails to the account's own address when one is known (profile or OIDC
//! `email` claim). The very first sign-in of an account sets its baseline
//! without an alert.
//!
//! - `GET /auth/devices`: the caller's devices; `DELETE /auth/devices/{fp}`
//!   forgets one (the next sign-in from it raises the notice again).
//! - `PUT /auth/email {email}`: the caller's address (`null` removes it).
//!   Audited `user.email`.

use crate::auth::Ctx;
use crate::{sha256_hex, ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, put};
use axum::{Json, Router};
use catalog::rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::IpAddr;

pub const ALERT_KIND: &str = "login_new_device";
/// devices kept per account (the oldest seen are dropped)
const MAX_DEVICES: i64 = 50;

pub fn routes() -> Router<St> {
    Router::new()
        .route("/auth/devices", get(list))
        .route("/auth/devices/{fp}", axum::routing::delete(forget))
        .route("/auth/email", put(put_email))
}

/// "Firefox on Linux", "Edge on Windows", "curl", "other".
pub fn family(ua: &str) -> String {
    let browser = [
        ("Edg/", "Edge"),
        ("OPR/", "Opera"),
        ("Firefox/", "Firefox"),
        ("Chromium/", "Chromium"),
        ("Chrome/", "Chrome"),
        ("Safari/", "Safari"),
        ("curl/", "curl"),
        ("python-requests", "Python"),
        ("nexusctl", "nexusctl"),
    ]
    .iter()
    .find(|(k, _)| ua.contains(k))
    .map_or("other", |(_, v)| v);
    let os = [
        ("Windows", "Windows"),
        ("Android", "Android"),
        ("iPhone", "iOS"),
        ("iPad", "iOS"),
        ("Mac OS X", "macOS"),
        ("Macintosh", "macOS"),
        ("CrOS", "ChromeOS"),
        ("Linux", "Linux"),
    ]
    .iter()
    .find(|(k, _)| ua.contains(k))
    .map(|(_, v)| *v);
    match os {
        Some(os) => format!("{browser} on {os}"),
        None => browser.to_owned(),
    }
}

/// IPv4 /24 or IPv6 /48 of the client (`unknown` for anything else).
pub fn prefix(ip: &str) -> String {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => {
            let o = a.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        Ok(IpAddr::V6(a)) => match a.to_ipv4_mapped() {
            Some(v4) => prefix(&v4.to_string()),
            None => {
                let s = a.segments();
                format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
            }
        },
        Err(_) => "unknown".into(),
    }
}

/// Records the device of a new session; raises the notice for an unseen one
/// (inside the caller's connection, before the session row is written).
pub fn check(c: &Connection, user_id: i64, ip: &str, ua: &str) -> ApiResult<Option<i64>> {
    let (family, prefix) = (family(ua), prefix(ip));
    let fp = sha256_hex(format!("{family}\n{prefix}").as_bytes())[..16].to_owned();
    let now = catalog::now();
    let known: i64 = c.query_row(
        "SELECT COUNT(*) FROM login_devices WHERE user_id = ?1",
        [user_id],
        |r| r.get(0),
    )?;
    let seen = c.execute(
        "UPDATE login_devices SET last_seen = ?3 WHERE user_id = ?1 AND fingerprint = ?2",
        params![user_id, fp, now],
    )?;
    if seen > 0 {
        return Ok(None);
    }
    c.execute(
        "INSERT INTO login_devices (user_id, fingerprint, family, prefix, first_seen, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
        params![user_id, fp, family, prefix, now],
    )?;
    c.execute(
        "DELETE FROM login_devices WHERE user_id = ?1 AND fingerprint IN (SELECT fingerprint FROM login_devices
           WHERE user_id = ?1 ORDER BY last_seen DESC, first_seen DESC LIMIT -1 OFFSET ?2)",
        params![user_id, MAX_DEVICES],
    )?;
    if known == 0 {
        return Ok(None); // the account's first sign-in: baseline
    }
    let (name, role, tenant): (String, String, Option<String>) =
        c.query_row("SELECT name, role, tenant FROM users WHERE id = ?1", [user_id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?;
    let severity = if role == "admin" || role == "security_officer" {
        "warning"
    } else {
        "info"
    };
    c.execute(
        "INSERT INTO alerts (ts, last_ts, severity, kind, key, message, tenant) VALUES (?1, ?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            now,
            severity,
            ALERT_KIND,
            format!("{ALERT_KIND}:{user_id}:{fp}"),
            format!("account {name} ({role}) signed in from a new device: {family} from {prefix} (address {ip})"),
            tenant
        ],
    )?;
    Ok(Some(c.last_insert_rowid()))
}

pub async fn list(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    if ctx.token.is_some() {
        return Err(ApiError::forbidden());
    }
    let c = st.cat.conn();
    let rows = c
        .prepare(
            "SELECT fingerprint, family, prefix, first_seen, last_seen FROM login_devices WHERE user_id = ?1
             ORDER BY last_seen DESC",
        )?
        .query_map([ctx.user.id], |r| {
            Ok(
                json!({"fingerprint": r.get::<_, String>(0)?, "family": r.get::<_, String>(1)?,
                      "prefix": r.get::<_, String>(2)?, "first_seen": r.get::<_, i64>(3)?,
                      "last_seen": r.get::<_, i64>(4)?}),
            )
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let email: Option<String> = c
        .query_row("SELECT email FROM users WHERE id = ?1", [ctx.user.id], |r| r.get(0))
        .optional()?
        .flatten();
    Ok(Json(json!({"devices": rows, "email": email})))
}

pub async fn forget(State(st): State<St>, ctx: Ctx, Path(fp): Path<String>) -> ApiResult<StatusCode> {
    if ctx.token.is_some() {
        return Err(ApiError::forbidden());
    }
    if fp.len() != 16 || !fp.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::bad("fingerprint: 16 hex digits"));
    }
    let n = st.cat.conn().execute(
        "DELETE FROM login_devices WHERE user_id = ?1 AND fingerprint = ?2",
        params![ctx.user.id, fp],
    )?;
    if n == 0 {
        return Err(ApiError::not_found());
    }
    st.audit(
        ctx.name(),
        "user.device_forget",
        &format!("user/{}", ctx.name()),
        json!({"fingerprint": fp}),
    )?;
    Ok(StatusCode::NO_CONTENT)
}

/// A plausible mail address (`local@domain.tld`, no spaces or control characters, ≤ 254).
pub fn valid_email(s: &str) -> bool {
    let Some((local, domain)) = s.rsplit_once('@') else {
        return false;
    };
    s.len() <= 254
        && !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && s.chars()
            .all(|c| c.is_ascii_graphic() && c != '<' && c != '>' && c != ',' && c != ';')
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailReq {
    email: Option<String>,
}

pub async fn put_email(State(st): State<St>, ctx: Ctx, J(r): J<EmailReq>) -> ApiResult<Json<Value>> {
    if ctx.token.is_some() || ctx.impersonating.is_some() {
        return Err(ApiError::forbidden());
    }
    let email = r.email.map(|e| e.trim().to_owned()).filter(|e| !e.is_empty());
    if email.as_deref().is_some_and(|e| !valid_email(e)) {
        return Err(ApiError::bad("email: not a mail address"));
    }
    st.cat
        .conn()
        .execute("UPDATE users SET email = ?2 WHERE id = ?1", params![ctx.user.id, email])?;
    let out = json!({"email": email});
    st.audit(ctx.name(), "user.email", &format!("user/{}", ctx.name()), out.clone())?;
    Ok(Json(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families_and_prefixes() {
        let ff = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0";
        let edge = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36 Edg/141.0";
        let safari = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1";
        assert_eq!(family(ff), "Firefox on Linux");
        assert_eq!(family(edge), "Edge on Windows");
        assert_eq!(family(safari), "Safari on iOS");
        assert_eq!(family("curl/8.5.0"), "curl");
        assert_eq!(family(""), "other");
        assert_eq!(prefix("192.0.2.77"), "192.0.2.0/24");
        assert_eq!(prefix("::ffff:198.51.100.7"), "198.51.100.0/24");
        assert_eq!(prefix("2001:db8:abcd:12::1"), "2001:db8:abcd::/48");
        assert_eq!(prefix("unknown"), "unknown");
        assert!(valid_email("ann@example.com"));
        assert!(!valid_email("ann@localhost") && !valid_email("a b@example.com") && !valid_email("@example.com"));
    }
}
