//! Passkeys (Phase 21c, docs/control-plane.md "Passkeys"): WebAuthn
//! credentials as a **second factor** next to TOTP. Password + passkey or
//! password + TOTP at login and re-authentication; no username-less sign-in.
//!
//! - Verification without a WebAuthn crate: a minimal CBOR reader, COSE keys
//!   ES256 (-7, P-256) and EdDSA (-8, Ed25519), signatures checked with `ring`.
//!   Attestation "none": the attestation statement is ignored (no vendor trust).
//! - Relying party ID: setting `passkeys.rp_id`, empty = the host name the UI is
//!   served on (Host header). The origin in clientDataJSON must be
//!   `https://<rp_id>[:port]`, the authenticator data must carry SHA-256(rp_id)
//!   and the user-presence flag. Challenges: 256 bit, single use, 3 min, bound
//!   to purpose and account (in memory: a restart only voids running ceremonies).
//! - Signature counter: when the authenticator counts (either value non-zero),
//!   the new value must be larger; a regression (cloned authenticator) fails.
//! - Policy `require_privileged`: local admins and security officers must use a
//!   passkey (TOTP is refused at login and re-authentication). Turning it on is
//!   immediate (a strengthening) but refused when the acting admin has no
//!   passkey for the current relying party ID; every other change of the setting
//!   needs approval (`security.passkeys`). New or reset privileged accounts then
//!   register a passkey during activation (crate::activation).
//! - Recovery: a lost passkey = admin reset (new activation code), which removes
//!   the account's passkeys. Every change is audited (`passkey.*`).

use crate::auth::{reauth, ClientIp, Ctx, User};
use crate::quorum::gate;
use crate::{validate, ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use catalog::rusqlite::{self, params, Connection, OptionalExtension};
use ring::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Setting key of [`Policy`].
pub const POLICY: &str = "passkeys";
/// Approval action for every change of [`Policy`] except turning the requirement on.
pub const ACTION: &str = "security.passkeys";
const ES256: i64 = -7;
const EDDSA: i64 = -8;
const CHALLENGE_SECS: i64 = 180;
const MAX_PENDING: usize = 10_000;
pub const MAX_PER_USER: i64 = 10;
const TIMEOUT_MS: i64 = 120_000;
const ADMIN: &[&str] = &["admin"];
const SETTINGS_READ: &[&str] = &["admin", "security_officer"];

pub fn routes() -> Router<St> {
    Router::new()
        .route("/auth/passkeys", get(list))
        .route("/auth/passkeys/register/begin", post(register_begin))
        .route("/auth/passkeys/register", post(register))
        .route("/auth/passkeys/challenge", post(reauth_challenge))
        .route("/auth/passkeys/{id}", put(rename).delete(remove))
        .route("/auth/login/passkey", post(login_options))
        .route("/settings/passkeys", get(get_settings).put(put_settings))
}

// ---------------------------------------------------------------- policy

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// admins and security officers (local accounts) sign in with a passkey only
    #[serde(default)]
    pub require_privileged: bool,
    /// relying party ID; empty = the host name of the request
    #[serde(default)]
    pub rp_id: String,
}

pub fn policy(c: &Connection) -> rusqlite::Result<Policy> {
    Ok(catalog::setting(c, POLICY)?
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or_default())
}

/// TOTP is refused for this account (local admin / security officer while
/// the policy is on).
pub fn required(c: &Connection, role: &str, auth: &str) -> rusqlite::Result<bool> {
    Ok(auth == "local" && validate::privileged(role) && policy(c)?.require_privileged)
}

/// A host name WebAuthn accepts as RP ID (no IP addresses, lowercase).
fn valid_rp(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && h.bytes().any(|b| b.is_ascii_lowercase())
        && !h.starts_with(['.', '-'])
        && !h.ends_with(['.', '-'])
        && !h.contains("..")
}

/// The request's host name (Host header or HTTP/2 authority), port stripped.
fn request_host(headers: &HeaderMap, uri: &Uri) -> String {
    let h = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .or_else(|| uri.authority().map(|a| a.as_str().to_owned()))
        .unwrap_or_default();
    if h.starts_with('[') {
        return String::new(); // IPv6 literal: never an RP ID
    }
    h.split(':').next().unwrap_or_default().to_ascii_lowercase()
}

/// The relying party ID for a ceremony started by this request.
pub fn rp_id(c: &Connection, headers: &HeaderMap, uri: &Uri) -> ApiResult<String> {
    let p = policy(c)?;
    let rp = if p.rp_id.is_empty() {
        request_host(headers, uri)
    } else {
        p.rp_id
    };
    if valid_rp(&rp) {
        Ok(rp)
    } else {
        Err(ApiError::bad(
            "passkeys need the appliance to be opened by its host name, not an IP address \
             (or set the relying party ID in Settings → Security)",
        ))
    }
}

// ---------------------------------------------------------------- challenges

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Purpose {
    Register,
    Login,
    Reauth,
}

struct Pending {
    purpose: Purpose,
    user: i64,
    rp_id: String,
    expires: i64,
}

fn pending() -> &'static Mutex<HashMap<String, Pending>> {
    static P: OnceLock<Mutex<HashMap<String, Pending>>> = OnceLock::new();
    P.get_or_init(Default::default)
}

/// A new single-use challenge for `user` (0 = unknown account: never verifies).
fn issue(purpose: Purpose, user: i64, rp_id: &str) -> ApiResult<String> {
    let now = catalog::now();
    let mut m = pending().lock().unwrap();
    m.retain(|_, p| p.expires > now);
    if m.len() >= MAX_PENDING {
        return Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "too many passkey ceremonies in progress, try again in a few minutes".into(),
        ));
    }
    let ch = B64.encode(rand::random::<[u8; 32]>());
    m.insert(
        ch.clone(),
        Pending {
            purpose,
            user,
            rp_id: rp_id.to_owned(),
            expires: now + CHALLENGE_SECS,
        },
    );
    Ok(ch)
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    typ: String,
    challenge: String,
    origin: String,
    #[serde(default, rename = "crossOrigin")]
    cross_origin: bool,
}

fn origin_ok(origin: &str, rp: &str) -> bool {
    origin
        .strip_prefix("https://")
        .map(|hp| {
            hp.split_once(':').map_or(hp, |(h, port)| {
                if port.bytes().all(|b| b.is_ascii_digit()) {
                    h
                } else {
                    ""
                }
            })
        })
        .is_some_and(|h| h == rp)
}

/// Checks clientDataJSON and consumes its challenge; the pending entry.
fn client_data(cdj: &[u8], typ: &str, purpose: Purpose, user: i64) -> Result<Pending, &'static str> {
    let cd: ClientData = serde_json::from_slice(cdj).map_err(|_| "client data")?;
    if cd.typ != typ {
        return Err("client data type");
    }
    let p = pending()
        .lock()
        .unwrap()
        .remove(&cd.challenge)
        .filter(|p| p.expires > catalog::now())
        .ok_or("challenge")?;
    if p.purpose != purpose || p.user != user || user == 0 {
        return Err("challenge");
    }
    if cd.cross_origin || !origin_ok(&cd.origin, &p.rp_id) {
        return Err("origin");
    }
    Ok(p)
}

// ---------------------------------------------------------------- CBOR / COSE

#[derive(Debug, PartialEq)]
enum Cbor {
    Int(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Simple(u8),
}

impl Cbor {
    fn get(&self, key: &Cbor) -> Option<&Cbor> {
        match self {
            Cbor::Map(kv) => kv.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    fn int(&self, k: i128) -> Option<i128> {
        match self.get(&Cbor::Int(k))? {
            Cbor::Int(i) => Some(*i),
            _ => None,
        }
    }
    fn bytes(&self, k: &Cbor) -> Option<&[u8]> {
        match self.get(k)? {
            Cbor::Bytes(b) => Some(b),
            _ => None,
        }
    }
}

/// One definite-length CBOR item (no floats, no tags): the item and its length.
fn cbor(b: &[u8], depth: u8) -> Result<(Cbor, usize), &'static str> {
    const E: &str = "cbor";
    if depth > 8 {
        return Err(E);
    }
    let first = *b.first().ok_or(E)?;
    let (major, info) = (first >> 5, first & 0x1f);
    let (arg, mut off) = match info {
        0..=23 => (info as u64, 1),
        24..=27 => {
            let n = 1usize << (info - 24);
            let bytes = b.get(1..1 + n).ok_or(E)?;
            (bytes.iter().fold(0u64, |a, x| (a << 8) | *x as u64), 1 + n)
        }
        _ => return Err(E),
    };
    let len = |a: u64| usize::try_from(a).ok().filter(|l| *l <= b.len()).ok_or(E);
    let item = match major {
        0 => Cbor::Int(arg as i128),
        1 => Cbor::Int(-1 - arg as i128),
        2 | 3 => {
            let n = len(arg)?;
            let s = b.get(off..off + n).ok_or(E)?.to_vec();
            off += n;
            if major == 2 {
                Cbor::Bytes(s)
            } else {
                Cbor::Text(String::from_utf8(s).map_err(|_| E)?)
            }
        }
        4 | 5 => {
            let n = len(arg)?;
            let mut items = Vec::with_capacity(n.min(64));
            for _ in 0..(if major == 5 { 2 * n } else { n }) {
                let (v, l) = cbor(&b[off..], depth + 1)?;
                off += l;
                items.push(v);
            }
            if major == 4 {
                Cbor::Array(items)
            } else {
                let mut kv = vec![];
                let mut it = items.into_iter();
                while let (Some(k), Some(v)) = (it.next(), it.next()) {
                    kv.push((k, v));
                }
                Cbor::Map(kv)
            }
        }
        7 if info < 24 => Cbor::Simple(info),
        _ => return Err(E),
    };
    Ok((item, off))
}

/// COSE_Key → (alg, raw public key: uncompressed P-256 point or Ed25519 key).
fn cose_key(k: &Cbor) -> Result<(i64, Vec<u8>), &'static str> {
    let coord = |i: i128| k.bytes(&Cbor::Int(i)).filter(|b| b.len() == 32);
    match (k.int(1), k.int(3), k.int(-1)) {
        (Some(2), Some(-7), Some(1)) => {
            let (x, y) = (coord(-2).ok_or("public key")?, coord(-3).ok_or("public key")?);
            Ok((ES256, [&[4u8][..], x, y].concat()))
        }
        (Some(1), Some(-8), Some(6)) => Ok((EDDSA, coord(-2).ok_or("public key")?.to_vec())),
        _ => Err("unsupported algorithm (ES256 or EdDSA only)"),
    }
}

struct AuthData {
    rp_hash: [u8; 32],
    flags: u8,
    count: u32,
    /// (credential id, alg, public key) when the AT flag is set
    attested: Option<(Vec<u8>, i64, Vec<u8>)>,
}

fn auth_data(b: &[u8]) -> Result<AuthData, &'static str> {
    const E: &str = "authenticator data";
    if b.len() < 37 {
        return Err(E);
    }
    let flags = b[32];
    let mut attested = None;
    if flags & 0x40 != 0 {
        let rest = b.get(37 + 16..).ok_or(E)?; // after the AAGUID
        let n = u16::from_be_bytes([*rest.first().ok_or(E)?, *rest.get(1).ok_or(E)?]) as usize;
        let id = rest.get(2..2 + n).ok_or(E)?.to_vec();
        let (key, _) = cbor(rest.get(2 + n..).ok_or(E)?, 0)?;
        let (alg, pk) = cose_key(&key)?;
        attested = Some((id, alg, pk));
    }
    Ok(AuthData {
        rp_hash: b[..32].try_into().unwrap(),
        flags,
        count: u32::from_be_bytes(b[33..37].try_into().unwrap()),
        attested,
    })
}

fn verify_sig(alg: i64, key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let algo: &dyn VerificationAlgorithm = match alg {
        ES256 => &signature::ECDSA_P256_SHA256_ASN1,
        EDDSA => &signature::ED25519,
        _ => return false,
    };
    UnparsedPublicKey::new(algo, key).verify(msg, sig).is_ok()
}

fn b64d(s: &str) -> Result<Vec<u8>, &'static str> {
    if s.len() > 64 * 1024 {
        return Err("too large");
    }
    B64.decode(s.trim_end_matches('=')).map_err(|_| "base64url")
}

// ---------------------------------------------------------------- ceremonies

/// `navigator.credentials.get()` result, fields base64url (as the SPA sends it).
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Assertion {
    pub id: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(default, rename = "userHandle")]
    pub user_handle: Option<String>,
}

/// `navigator.credentials.create()` result, fields base64url.
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub id: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

/// Verifies an assertion of `user` for `purpose` and advances the signature
/// counter; `Err(reason)` for the audit log.
pub fn verify_assertion(c: &Connection, a: &Assertion, purpose: Purpose, user: i64) -> Result<(), &'static str> {
    let cdj = b64d(&a.client_data_json)?;
    let p = client_data(&cdj, "webauthn.get", purpose, user)?;
    let ad_raw = b64d(&a.authenticator_data)?;
    let sig = b64d(&a.signature)?;
    let row: Option<(i64, i64, Vec<u8>, String, i64)> = c
        .query_row(
            "SELECT id, alg, public_key, rp_id, sign_count FROM passkeys WHERE cred_id = ?1 AND user_id = ?2",
            params![a.id, user],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()
        .map_err(|_| "catalog")?;
    let (id, alg, key, rp, stored) = row.ok_or("unknown passkey")?;
    let ad = auth_data(&ad_raw)?;
    if rp != p.rp_id || ad.rp_hash[..] != Sha256::digest(rp.as_bytes())[..] {
        return Err("relying party");
    }
    if ad.flags & 0x01 == 0 {
        return Err("user presence");
    }
    let msg = [&ad_raw[..], &Sha256::digest(&cdj)[..]].concat();
    if !verify_sig(alg, &key, &msg, &sig) {
        return Err("signature");
    }
    let count = ad.count as i64;
    if (count != 0 || stored != 0) && count <= stored {
        return Err("signature counter did not increase (cloned authenticator?)");
    }
    let n = c
        .execute(
            "UPDATE passkeys SET sign_count = ?2, last_used = ?3 WHERE id = ?1 AND sign_count = ?4",
            params![id, count, catalog::now(), stored],
        )
        .map_err(|_| "catalog")?;
    if n != 1 {
        return Err("signature counter did not increase (cloned authenticator?)");
    }
    Ok(())
}

/// A verified registration, ready to store.
pub struct NewPasskey {
    cred_id: String,
    alg: i64,
    key: Vec<u8>,
    rp_id: String,
    count: i64,
}

pub fn verify_registration(r: &Registration, user: i64) -> Result<NewPasskey, &'static str> {
    let cdj = b64d(&r.client_data_json)?;
    let p = client_data(&cdj, "webauthn.create", Purpose::Register, user)?;
    let (att, _) = cbor(&b64d(&r.attestation_object)?, 0)?;
    // attestation "none": fmt and attStmt are not evaluated
    let ad = auth_data(att.bytes(&Cbor::Text("authData".into())).ok_or("attestation object")?)?;
    if ad.rp_hash[..] != Sha256::digest(p.rp_id.as_bytes())[..] {
        return Err("relying party");
    }
    if ad.flags & 0x01 == 0 {
        return Err("user presence");
    }
    let (id, alg, key) = ad.attested.ok_or("no attested credential")?;
    if id.is_empty() || id.len() > 1023 || B64.encode(&id) != r.id.trim_end_matches('=') {
        return Err("credential id");
    }
    Ok(NewPasskey {
        cred_id: B64.encode(&id),
        alg,
        key,
        rp_id: p.rp_id,
        count: ad.count as i64,
    })
}

/// Stores a verified passkey; the row id.
pub fn store(c: &Connection, user: i64, name: &str, k: &NewPasskey) -> ApiResult<i64> {
    let n: i64 = c.query_row("SELECT COUNT(*) FROM passkeys WHERE user_id = ?1", [user], |r| r.get(0))?;
    if n >= MAX_PER_USER {
        return Err(ApiError::conflict(format!(
            "at most {MAX_PER_USER} passkeys per account"
        )));
    }
    let taken: bool = c.query_row("SELECT COUNT(*) FROM passkeys WHERE cred_id = ?1", [&k.cred_id], |r| {
        r.get(0)
    })?;
    if taken {
        return Err(ApiError::conflict("this passkey is registered already"));
    }
    c.execute(
        "INSERT INTO passkeys (user_id, cred_id, name, alg, public_key, rp_id, sign_count, created)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![user, k.cred_id, name, k.alg, k.key, k.rp_id, k.count, catalog::now()],
    )?;
    Ok(c.last_insert_rowid())
}

/// Passkey names: 1..=64 printable characters (default "Passkey").
pub fn check_name(name: &str) -> ApiResult<String> {
    let n = name.trim();
    if n.is_empty() {
        return Ok("Passkey".into());
    }
    if n.chars().count() > 64 || n.chars().any(char::is_control) {
        return Err(ApiError::bad("name: up to 64 characters, no control characters"));
    }
    Ok(n.to_owned())
}

fn cred_list(c: &Connection, user: i64, rp: &str) -> ApiResult<Vec<Value>> {
    Ok(
        c.prepare("SELECT cred_id FROM passkeys WHERE user_id = ?1 AND rp_id = ?2 ORDER BY id")?
            .query_map(params![user, rp], |r| r.get::<_, String>(0))?
            .map(|id| id.map(|id| json!({"type": "public-key", "id": id})))
            .collect::<Result<_, _>>()?,
    )
}

/// Options for `navigator.credentials.create()` (base64url fields).
pub fn creation_options(c: &Connection, user: i64, name: &str, rp: &str) -> ApiResult<Value> {
    Ok(json!({
        "challenge": issue(Purpose::Register, user, rp)?,
        "rp": {"id": rp, "name": "NexusBackup"},
        "user": {"id": B64.encode(user.to_be_bytes()), "name": name, "displayName": name},
        "pubKeyCredParams": [{"type": "public-key", "alg": ES256}, {"type": "public-key", "alg": EDDSA}],
        "timeout": TIMEOUT_MS,
        "attestation": "none",
        "authenticatorSelection": {"residentKey": "discouraged", "userVerification": "preferred"},
        "excludeCredentials": cred_list(c, user, rp)?,
    }))
}

fn request_options(challenge: String, rp: &str, allow: Vec<Value>) -> Value {
    json!({"challenge": challenge, "rpId": rp, "allowCredentials": allow, "timeout": TIMEOUT_MS,
           "userVerification": "preferred"})
}

// ---------------------------------------------------------------- handlers

fn row(r: &rusqlite::Row) -> rusqlite::Result<Value> {
    Ok(json!({
        "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?,
        "alg": if r.get::<_, i64>(2)? == ES256 { "ES256" } else { "EdDSA" },
        "rp_id": r.get::<_, String>(3)?, "created": r.get::<_, i64>(4)?, "last_used": r.get::<_, Option<i64>>(5)?,
    }))
}

/// The caller's passkeys and whether the policy requires them.
pub async fn list(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    let c = st.cat.conn();
    let keys = c
        .prepare("SELECT id, name, alg, rp_id, created, last_used FROM passkeys WHERE user_id = ?1 ORDER BY id")?
        .query_map([ctx.user.id], row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(json!({
        "passkeys": keys,
        "required": required(&c, &ctx.user.role, &ctx.user.auth)?,
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReauthReq {
    current_password: Option<String>,
    current_totp: Option<String>,
}

fn session_only(ctx: &Ctx) -> ApiResult<()> {
    if ctx.token.is_some() || ctx.impersonating.is_some() || ctx.user.auth != "local" {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "passkeys belong to local accounts and are managed in their own session".into(),
        ));
    }
    Ok(())
}

/// Starts registering a passkey: re-authentication, then creation options.
pub async fn register_begin(
    State(st): State<St>,
    ctx: Ctx,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    uri: Uri,
    J(r): J<ReauthReq>,
) -> ApiResult<Json<Value>> {
    session_only(&ctx)?;
    let rp = rp_id(&st.cat.conn(), &headers, &uri)?;
    reauth(&st, &ctx, &ip, r.current_password, r.current_totp, "passkey.register").await?;
    Ok(Json(creation_options(&st.cat.conn(), ctx.user.id, ctx.name(), &rp)?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterReq {
    #[serde(default)]
    name: String,
    credential: Registration,
}

pub async fn register(State(st): State<St>, ctx: Ctx, J(r): J<RegisterReq>) -> ApiResult<Json<Value>> {
    session_only(&ctx)?;
    let name = check_name(&r.name)?;
    let k = verify_registration(&r.credential, ctx.user.id).map_err(|reason| {
        let _ = st.audit(
            ctx.name(),
            "passkey.register_failed",
            &format!("user/{}", ctx.name()),
            json!({"reason": reason}),
        );
        ApiError::bad(format!("passkey not accepted: {reason}"))
    })?;
    let id = store(&st.cat.conn(), ctx.user.id, &name, &k)?;
    st.audit(
        ctx.name(),
        "passkey.register",
        &format!("user/{}", ctx.name()),
        json!({"passkey": id, "name": name, "alg": k.alg, "rp_id": k.rp_id}),
    )?;
    Ok(Json(json!({"id": id, "name": name})))
}

/// Options for a re-authentication with a passkey (the assertion then goes
/// into `current_totp` as JSON, see `crate::auth::reauth`).
pub async fn reauth_challenge(State(st): State<St>, ctx: Ctx, headers: HeaderMap, uri: Uri) -> ApiResult<Json<Value>> {
    session_only(&ctx)?;
    let c = st.cat.conn();
    let rp = rp_id(&c, &headers, &uri)?;
    let allow = cred_list(&c, ctx.user.id, &rp)?;
    if allow.is_empty() {
        return Err(ApiError::bad("no passkey registered for this host name"));
    }
    Ok(Json(request_options(
        issue(Purpose::Reauth, ctx.user.id, &rp)?,
        &rp,
        allow,
    )))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenameReq {
    name: String,
}

fn own_name(c: &Connection, ctx: &Ctx, id: i64) -> ApiResult<String> {
    c.query_row(
        "SELECT name FROM passkeys WHERE id = ?1 AND user_id = ?2",
        params![id, ctx.user.id],
        |r| r.get(0),
    )
    .optional()?
    .ok_or_else(ApiError::not_found)
}

pub async fn rename(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>, J(r): J<RenameReq>) -> ApiResult<Json<Value>> {
    session_only(&ctx)?;
    let name = check_name(&r.name)?;
    let old = {
        let c = st.cat.conn();
        let old = own_name(&c, &ctx, id)?;
        c.execute("UPDATE passkeys SET name = ?2 WHERE id = ?1", params![id, name])?;
        old
    };
    st.audit(
        ctx.name(),
        "passkey.rename",
        &format!("user/{}", ctx.name()),
        json!({"passkey": id, "name": name, "old": old}),
    )?;
    Ok(Json(json!({"id": id, "name": name})))
}

/// Removes one of the caller's passkeys; the last one stays while the policy
/// requires it for the caller's role.
pub async fn remove(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    session_only(&ctx)?;
    let name = {
        let c = st.cat.conn();
        let name = own_name(&c, &ctx, id)?;
        let n: i64 = c.query_row("SELECT COUNT(*) FROM passkeys WHERE user_id = ?1", [ctx.user.id], |r| {
            r.get(0)
        })?;
        if n == 1 && required(&c, &ctx.user.role, &ctx.user.auth)? {
            return Err(ApiError::conflict(
                "passkeys are required for your role: register another passkey before removing the last one",
            ));
        }
        c.execute("DELETE FROM passkeys WHERE id = ?1", [id])?;
        name
    };
    st.audit(
        ctx.name(),
        "passkey.remove",
        &format!("user/{}", ctx.name()),
        json!({"passkey": id, "name": name}),
    )?;
    Ok(Json(json!({"ok": true})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginOptionsReq {
    name: String,
}

/// Stable stand-in credential id for names without passkeys (no account
/// enumeration through `allowCredentials`); keyed by a random per-appliance salt.
fn decoy(c: &Connection, name: &str) -> ApiResult<String> {
    const KEY: &str = "passkey_decoy_salt";
    let salt = match catalog::setting(c, KEY)? {
        Some(s) => s,
        None => {
            let s = crate::random_hex();
            catalog::set_setting(c, KEY, &s)?;
            s
        }
    };
    Ok(B64.encode(&Sha256::digest(format!("{salt}:{name}").as_bytes())[..16]))
}

/// Public (login page): assertion options for `name`. Unknown names and
/// accounts without passkeys get the same answer with a decoy credential.
pub async fn login_options(
    State(st): State<St>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    uri: Uri,
    J(r): J<LoginOptionsReq>,
) -> ApiResult<Json<Value>> {
    let valid = validate::name(&r.name, "name").is_ok();
    let (ukey, ikey) = (
        format!("user:{}", if valid { r.name.as_str() } else { "?" }),
        format!("ip:{ip}"),
    );
    if crate::auth::locked_out(&st, &ukey, &ikey) {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed logins, try again later".into(),
        ));
    }
    let c = st.cat.conn();
    let rp = rp_id(&c, &headers, &uri)?;
    let user: Option<i64> = if valid {
        c.query_row(
            "SELECT id FROM users WHERE name = ?1 AND auth = 'local' AND activation_hash IS NULL",
            [&r.name],
            |r| r.get(0),
        )
        .optional()?
    } else {
        None
    };
    let mut allow = match user {
        Some(u) => cred_list(&c, u, &rp)?,
        None => vec![],
    };
    if allow.is_empty() {
        allow.push(json!({"type": "public-key", "id": decoy(&c, &r.name)?}));
    }
    Ok(Json(request_options(
        issue(Purpose::Login, user.unwrap_or(0), &rp)?,
        &rp,
        allow,
    )))
}

/// Local admins / security officers (enabled, activated) without a passkey for `rp`.
fn without_passkey(c: &Connection, rp: &str) -> ApiResult<Vec<String>> {
    Ok(c.prepare(
        "SELECT name FROM users u WHERE role IN ('admin','security_officer') AND auth = 'local' AND disabled = 0
           AND activation_hash IS NULL
           AND NOT EXISTS (SELECT 1 FROM passkeys p WHERE p.user_id = u.id AND p.rp_id = ?1) ORDER BY name",
    )?
    .query_map([rp], |r| r.get(0))?
    .collect::<Result<_, _>>()?)
}

/// `{policy, rp_id (effective, null if the host name is not usable),
/// without_passkey, pending}`.
pub async fn get_settings(State(st): State<St>, ctx: Ctx, headers: HeaderMap, uri: Uri) -> ApiResult<Json<Value>> {
    ctx.require(SETTINGS_READ)?;
    let c = st.cat.conn();
    let rp = rp_id(&c, &headers, &uri).ok();
    let missing = match &rp {
        Some(rp) => without_passkey(&c, rp)?,
        None => vec![],
    };
    let pending: Option<i64> = c
        .query_row(
            "SELECT id FROM quorum WHERE action = ?1 AND state = 'pending' ORDER BY id DESC LIMIT 1",
            [ACTION],
            |r| r.get(0),
        )
        .optional()?;
    Ok(Json(json!({
        "policy": policy(&c)?, "rp_id": rp, "without_passkey": missing, "pending": pending,
    })))
}

/// Turning the requirement on (relying party unchanged) applies at once; it is
/// refused when the acting admin has no passkey for the relying party.
/// Everything else (turning it off, another relying party ID) needs approval.
pub async fn put_settings(
    State(st): State<St>,
    ctx: Ctx,
    headers: HeaderMap,
    uri: Uri,
    J(mut new): J<Policy>,
) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    new.rp_id = new.rp_id.trim().to_ascii_lowercase();
    if !new.rp_id.is_empty() && !valid_rp(&new.rp_id) {
        return Err(ApiError::bad(
            "rp_id: a host name (lowercase, no IP address, no port), or empty",
        ));
    }
    let (old, missing) = {
        let c = st.cat.conn();
        let old = policy(&c)?;
        if new == old {
            return Ok(Json(json!({"policy": new})).into_response());
        }
        if old.require_privileged && new.require_privileged && new.rp_id != old.rp_id {
            return Err(ApiError::conflict(
                "turn the passkey requirement off before changing the relying party ID (existing passkeys stop working)",
            ));
        }
        let mut missing = vec![];
        if new.require_privileged {
            let rp = if new.rp_id.is_empty() {
                request_host(&headers, &uri)
            } else {
                new.rp_id.clone()
            };
            if !valid_rp(&rp) {
                return Err(ApiError::bad(
                    "open the appliance by its host name (or set rp_id) first",
                ));
            }
            missing = without_passkey(&c, &rp)?;
            if session_only(&ctx).is_err() || missing.contains(&ctx.user.name) {
                return Err(ApiError::conflict(format!(
                    "register a passkey for your own account (host name {rp}) first: the requirement would lock you out"
                )));
            }
            let admins: i64 = c.query_row(
                "SELECT COUNT(*) FROM users u WHERE role = 'admin' AND auth = 'local' AND disabled = 0
                   AND EXISTS (SELECT 1 FROM passkeys p WHERE p.user_id = u.id AND p.rp_id = ?1)",
                [&rp],
                |r| r.get(0),
            )?;
            if admins == 0 {
                return Err(ApiError::conflict("no admin has a passkey for this host name"));
            }
        }
        (old, missing)
    };
    if new.require_privileged && !old.require_privileged && new.rp_id == old.rp_id {
        catalog::set_setting(&st.cat.conn(), POLICY, &json!(new).to_string())?;
        st.audit(
            ctx.name(),
            ACTION,
            "settings/passkeys",
            json!({"passkeys": new, "old": old, "without_passkey": missing}),
        )?;
        return Ok(Json(json!({"policy": new, "without_passkey": missing})).into_response());
    }
    gate(
        &st,
        &ctx,
        ACTION,
        "settings/passkeys",
        json!({"passkeys": new, "old": old}),
    )
}

/// For crate::access::execute (approved `security.passkeys`).
pub fn current(c: &Connection) -> ApiResult<Value> {
    Ok(json!(policy(c)?))
}

/// Accounts losing their passkeys with a credential reset (crate::resources).
pub fn delete_for(c: &Connection, user: i64) -> rusqlite::Result<usize> {
    c.execute("DELETE FROM passkeys WHERE user_id = ?1", [user])
}

/// Whether `u` has any passkey (role grants under the policy, crate::resources).
pub fn has_any(c: &Connection, u: &User) -> rusqlite::Result<bool> {
    c.query_row("SELECT COUNT(*) > 0 FROM passkeys WHERE user_id = ?1", [u.id], |r| {
        r.get(0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rp_and_origin() {
        assert!(valid_rp("backup.example.com"));
        assert!(valid_rp("localhost"));
        assert!(!valid_rp("192.0.2.1"));
        assert!(!valid_rp("Backup.example.com"));
        assert!(!valid_rp("a..b"));
        assert!(!valid_rp(""));
        assert!(origin_ok("https://backup.example.com", "backup.example.com"));
        assert!(origin_ok("https://backup.example.com:8443", "backup.example.com"));
        assert!(!origin_ok("http://backup.example.com", "backup.example.com"));
        assert!(!origin_ok("https://evil.example.com", "backup.example.com"));
        assert!(!origin_ok("https://backup.example.com.evil.net", "backup.example.com"));
        assert!(!origin_ok(
            "https://backup.example.com:x@evil.net",
            "backup.example.com"
        ));
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "Backup.Example.com:8443".parse().unwrap());
        assert_eq!(request_host(&h, &Uri::from_static("/")), "backup.example.com");
        h.insert(header::HOST, "[2001:db8::1]:8443".parse().unwrap());
        assert_eq!(request_host(&h, &Uri::from_static("/")), "");
    }

    #[test]
    fn cbor_items() {
        // {1: 2, 3: -7, -2: h'0102', "a": [true]}
        let b = [0xa4, 0x01, 0x02, 0x03, 0x26, 0x21, 0x42, 1, 2, 0x61, b'a', 0x81, 0xf5];
        let (v, n) = cbor(&b, 0).unwrap();
        assert_eq!(n, b.len());
        assert_eq!(v.int(1), Some(2));
        assert_eq!(v.int(3), Some(-7));
        assert_eq!(v.bytes(&Cbor::Int(-2)), Some(&[1u8, 2][..]));
        assert!(cbor(&[0x5a, 0xff, 0xff, 0xff, 0xff], 0).is_err(), "length beyond input");
        assert!(cbor(&[0x9f], 0).is_err(), "indefinite length");
        assert!(cbor(&[0x81; 20], 0).is_err(), "nesting depth");
    }
}
