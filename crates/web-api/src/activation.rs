//! Self-enrollment at first sign-in (plan §2 "User onboarding", user decision
//! 2026-10-10): an admin creates an account and receives a one-time activation
//! code; the person sets their own password and authenticator. The admin never
//! learns credentials of another account.
//!
//! Codes: 128 bit, base32 (26 characters), valid 72 h, stored as SHA-256 digest
//! (`users.activation_hash`). Privileged accounts (admin / security_officer)
//! created or reset while approvals are enabled get a **split** code: the
//! requesting admin receives part 1 when making the request, the approver part 2
//! when approving (digest `h1:h2`; `h1:?` until approval). Only the new user,
//! who receives both parts over two channels, can activate — neither of the two
//! admins alone can take the account over.
//!
//! `POST /auth/activate/begin {name, code}` checks the code and issues a fresh
//! TOTP seed (stored encrypted, shown only in this answer);
//! `POST /auth/activate/complete {name, code, password, totp}` sets the password
//! and, after the code from the new authenticator matched, clears the activation.
//! Failures count toward the login rate limiter (per user and per IP) and are
//! audited (`auth.activate_failed`); the TOTP step is consumed as at login.
//!
//! Passkeys (Phase 21c, crate::passkeys): `POST /auth/activate/passkey {name,
//! code}` answers creation options; `complete` takes the result as `passkey`
//! (optional, required for admins / security officers while the passkey policy
//! is on: `passkey_required` in the `begin` answer).

use crate::auth::{locked_out, record_failure, ClientIp};
use crate::{ct_eq, sha256_hex, validate, ApiError, ApiResult, St, J};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::Json;
use catalog::rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};

pub const ACTIVATION_SECS: i64 = 72 * 3600;
const PART_LEN: usize = 26;
/// Digest placeholder for a second part that is not issued yet.
const NOT_ISSUED: &str = "?";

/// A new code part: (code shown once, its digest).
pub fn new_part() -> (String, String) {
    let code = crate::agents::new_token();
    let digest = sha256_hex(code.as_bytes());
    (code, digest)
}

/// Uppercase letters and digits only: spaces, dashes and case do not matter.
fn normalize(s: &str) -> String {
    s.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

fn part_ok(entered: &str, digest: &str) -> bool {
    ct_eq(sha256_hex(entered.as_bytes()).as_bytes(), digest.as_bytes())
}

/// Checks an entered code against the stored digest (`h`, or `h1:h2` = both
/// parts one after the other).
pub fn code_matches(stored: &str, entered: &str) -> bool {
    let n = normalize(entered);
    match stored.split_once(':') {
        None => part_ok(&n, stored),
        Some((_, NOT_ISSUED)) => false,
        Some((a, b)) => n.len() == 2 * PART_LEN && part_ok(&n[..PART_LEN], a) & part_ok(&n[PART_LEN..], b),
    }
}

/// Digest stored for a pending privileged account until the approver gets part 2.
pub fn split_pending(part1_digest: &str) -> String {
    format!("{part1_digest}:{NOT_ISSUED}")
}

/// The SPA route where the person activates (the code never goes into a URL).
pub fn path(name: &str) -> String {
    format!("/#/activate?name={name}")
}

/// `{code, part, parts, expires, path}` as shown to the admin / approver.
pub fn shown(name: &str, code: &str, part: u8, parts: u8, expires: Option<i64>) -> Value {
    json!({"name": name, "code": code, "part": part, "parts": parts, "expires": expires, "path": path(name)})
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginReq {
    name: String,
    code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteReq {
    name: String,
    code: String,
    password: String,
    totp: String,
    #[serde(default)]
    passkey: Option<crate::passkeys::Registration>,
    #[serde(default)]
    passkey_name: String,
}

struct Pending {
    id: i64,
    /// TOTP is refused for this account later: a passkey must be registered
    passkey_required: bool,
    stored: String,
    seed: String,
    last_step: i64,
}

fn invalid() -> ApiError {
    ApiError(
        StatusCode::UNAUTHORIZED,
        "invalid name or activation code (or the code expired)".into(),
    )
}

fn limited() -> ApiError {
    ApiError(
        StatusCode::TOO_MANY_REQUESTS,
        "too many failed attempts, try again later".into(),
    )
}

/// Looks the account up and checks the code; failures are counted and audited.
fn check(st: &St, ip: &str, name: &str, code: &str) -> ApiResult<Pending> {
    let valid_name = validate::name(name, "name").is_ok();
    let ukey = format!("user:{}", if valid_name { name } else { "?" });
    let ikey = format!("ip:{ip}");
    let target = if valid_name {
        format!("user/{name}")
    } else {
        "user/?".into()
    };
    if locked_out(st, &ukey, &ikey) {
        st.failed_logins.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Err(limited());
    }
    let row = if valid_name && code.len() <= 256 {
        st.cat
            .conn()
            .query_row(
                "SELECT id, activation_hash, activation_expires, disabled, totp_secret, totp_last_step, role, auth
                 FROM users WHERE name = ?1",
                [name],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, Option<i64>>(2)?,
                        r.get::<_, i64>(3)? != 0,
                        r.get::<_, String>(4)?,
                        r.get::<_, i64>(5)?,
                        (r.get::<_, String>(6)?, r.get::<_, String>(7)?),
                    ))
                },
            )
            .optional()?
    } else {
        None
    };
    let verdict = match row {
        None => Err("unknown user or no pending activation"),
        Some((_, None, ..)) => Err("unknown user or no pending activation"),
        Some((_, Some(stored), ..)) if stored.ends_with(&format!(":{NOT_ISSUED}")) => Err("not approved yet"),
        Some((_, Some(stored), ..)) if !code_matches(&stored, code) => Err("code"),
        Some((_, _, exp, ..)) if exp.unwrap_or(0) <= catalog::now() => Err("expired"),
        Some((_, _, _, true, ..)) => Err("disabled"),
        Some((id, Some(stored), _, false, seed, last_step, (role, auth))) => Ok(Pending {
            id,
            passkey_required: crate::passkeys::required(&st.cat.conn(), &role, &auth)?,
            stored,
            seed,
            last_step,
        }),
    };
    verdict.or_else(|reason| {
        record_failure(
            st,
            ("anonymous", "auth.activate_failed", &target),
            (&ukey, &ikey, ip),
            json!({"ip": ip, "reason": reason}),
        )?;
        Err(invalid())
    })
}

/// Checks the code and issues a fresh TOTP seed (shown only here).
pub async fn begin(State(st): State<St>, ClientIp(ip): ClientIp, J(r): J<BeginReq>) -> ApiResult<Json<Value>> {
    let p = check(&st, &ip, &r.name, &r.code)?;
    let secret = catalog::auth::new_totp_secret();
    let uri = catalog::auth::totp_uri(&secret, &r.name)?;
    let enc = st.totp.encrypt(&r.name, &secret)?;
    let n = st.cat.conn().execute(
        "UPDATE users SET totp_secret = ?2 WHERE id = ?1 AND activation_hash = ?3",
        params![p.id, enc, p.stored],
    )?;
    if n != 1 {
        return Err(invalid());
    }
    st.audit(
        &r.name,
        "user.activation_begin",
        &format!("user/{}", r.name),
        json!({"ip": ip}),
    )?;
    Ok(Json(
        json!({"name": r.name, "totp_uri": uri, "totp_secret": secret, "passkey_required": p.passkey_required}),
    ))
}

/// Creation options for a passkey registered during activation.
pub async fn passkey_options(
    State(st): State<St>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    uri: Uri,
    J(r): J<BeginReq>,
) -> ApiResult<Json<Value>> {
    let p = check(&st, &ip, &r.name, &r.code)?;
    let c = st.cat.conn();
    let rp = crate::passkeys::rp_id(&c, &headers, &uri)?;
    Ok(Json(crate::passkeys::creation_options(&c, p.id, &r.name, &rp)?))
}

/// Sets the password, proves the authenticator and activates the account.
pub async fn complete(State(st): State<St>, ClientIp(ip): ClientIp, J(r): J<CompleteReq>) -> ApiResult<Json<Value>> {
    let p = check(&st, &ip, &r.name, &r.code)?;
    if r.password.len() > 1024 || r.password.chars().count() < 12 {
        return Err(ApiError::bad("password: at least 12 and at most 1024 characters"));
    }
    if p.passkey_required && r.passkey.is_none() {
        return Err(ApiError::bad(
            "a passkey is required for this role: register one in this step (TOTP alone is not accepted)",
        ));
    }
    let passkey_name = crate::passkeys::check_name(&r.passkey_name)?;
    let step = if p.seed.is_empty() {
        None
    } else {
        let seed = st.totp.decrypt(&r.name, &p.seed)?;
        catalog::auth::totp_step(&seed, &r.totp).map(|s| s as i64)
    };
    let (ukey, ikey, target) = (
        format!("user:{}", r.name),
        format!("ip:{ip}"),
        format!("user/{}", r.name),
    );
    let fail = |reason: &str| -> ApiResult<Json<Value>> {
        record_failure(
            &st,
            ("anonymous", "auth.activate_failed", &target),
            (&ukey, &ikey, &ip),
            json!({"ip": ip, "reason": reason}),
        )?;
        Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "the authenticator code is not valid (start the activation again if the QR code was replaced)".into(),
        ))
    };
    let Some(step) = step.filter(|s| *s > p.last_step) else {
        return fail("totp");
    };
    // after the TOTP check: a wrong code does not use up the passkey challenge
    let passkey = match &r.passkey {
        Some(reg) => match crate::passkeys::verify_registration(reg, p.id) {
            Ok(k) => Some(k),
            Err(reason) => {
                record_failure(
                    &st,
                    ("anonymous", "auth.activate_failed", &target),
                    (&ukey, &ikey, &ip),
                    json!({"ip": ip, "reason": format!("passkey: {reason}")}),
                )?;
                return Err(ApiError::bad(format!(
                    "passkey not accepted ({reason}): register it again"
                )));
            }
        },
        None => None,
    };
    let pw = r.password;
    let hash = tokio::task::spawn_blocking(move || catalog::auth::hash_password(&pw))
        .await
        .map_err(|e| anyhow::anyhow!("hash task: {e}"))?
        .map_err(|e| ApiError::bad(format!("password: {e}")))?;
    // atomic: the code is used once, the TOTP step is consumed, the seed is the checked one
    let n = st.cat.conn().execute(
        "UPDATE users SET password_hash = ?2, activation_hash = NULL, activation_expires = NULL, totp_last_step = ?3
         WHERE id = ?1 AND activation_hash = ?4 AND totp_secret = ?5 AND totp_last_step < ?3",
        params![p.id, hash, step, p.stored, p.seed],
    )?;
    if n != 1 {
        return fail("totp replay or concurrent activation");
    }
    st.limiter.lock().unwrap().clear(&ukey);
    if let Some(k) = &passkey {
        let id = crate::passkeys::store(&st.cat.conn(), p.id, &passkey_name, k)?;
        st.audit(
            &r.name,
            "passkey.register",
            &target,
            json!({"passkey": id, "name": passkey_name, "activation": true}),
        )?;
    }
    st.audit(
        &r.name,
        "user.activate",
        &target,
        json!({"ip": ip, "passkey": passkey.is_some()}),
    )?;
    Ok(Json(json!({"ok": true})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_and_split_codes() {
        let (a, ha) = new_part();
        let (b, hb) = new_part();
        assert_eq!(a.len(), PART_LEN);
        assert!(code_matches(&ha, &a));
        assert!(code_matches(&ha, &format!(" {}-{} ", &a[..13], a[13..].to_lowercase())));
        assert!(!code_matches(&ha, &b));
        let split = format!("{ha}:{hb}");
        assert!(code_matches(&split, &format!("{a} {b}")));
        assert!(!code_matches(&split, &a), "one part alone is not enough");
        assert!(!code_matches(&split, &format!("{b}{a}")));
        assert!(!code_matches(&split_pending(&ha), &a));
        assert!(!code_matches(&split_pending(&ha), &format!("{a}{b}")));
    }
}
