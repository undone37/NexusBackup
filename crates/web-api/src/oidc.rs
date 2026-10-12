//! OIDC sign-in (docs/phase12-contract.md §2; plan §2 "OIDC", "OIDC user
//! provisioning"): authorization code flow with PKCE (S256), `state` + `nonce`,
//! against any OIDC provider (Keycloak, Entra ID, Okta, Authentik, …).
//!
//! - Discovery: `<issuer>/.well-known/openid-configuration` (its `issuer` must equal
//!   the configured one); JWKS from `jwks_uri`, cached, fetched again (at most every
//!   [`JWKS_MIN_REFRESH`]) when a token names an unknown `kid`.
//! - The pending login (state → nonce, PKCE verifier, `next`) lives in memory for
//!   at most 10 min, bound to the browser by the HttpOnly cookie `nx_oidc`
//!   (SameSite=Lax: the IdP's redirect back is a cross-site navigation). Each
//!   state is usable once.
//! - ID token: signature against the JWKS with RS256 / ES256 / PS256 only (never
//!   `none` or HMAC), `iss` = issuer, `aud` contains the client id (`azp` = client id
//!   when several audiences), `exp` / `iat` / `nbf` with [`SKEW`] seconds of clock
//!   skew, `nonce` = the pending login's.
//! - Claims → account (just in time, refreshed at every login): the highest
//!   privileged matching mapping wins; no match → the account is disabled and the
//!   login refused. OIDC accounts have no password / TOTP (MFA is the IdP's job)
//!   and cannot use local login; sessions are the normal ones.
//! - The client secret is encrypted with the web-api's own key (it is needed here,
//!   for the token request), not sealed to the scheduler like source secrets.
//!
//! Egress: the scheduler adds the issuer host and the hosts of the token and JWKS
//! endpoints (`settings.oidc_endpoints`, recorded after a successful discovery)
//! to the firewall allow-list. `http://` issuers are accepted for loopback hosts
//! only (tests, a local proxy).

use crate::auth::{locked_out, new_session, record_failure, ClientIp, Ctx, User, USER_COLS};
use crate::quorum::{accepted, request};
use crate::{ct_eq, random_hex, sha256_hex, validate, ApiError, ApiResult, St, J, Q};
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use catalog::rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Settings key (catalog `settings`).
pub const SETTING: &str = "oidc";
/// Non-secret endpoints of the last successful discovery (firewall allow-list).
pub const ENDPOINTS_SETTING: &str = "oidc_endpoints";
pub const COOKIE: &str = "nx_oidc";
const COOKIE_PATH: &str = "/api/v1/auth/oidc";
/// pending logins expire after this
pub const PENDING_SECS: i64 = 600;
const MAX_PENDING: usize = 10_000;
/// clock skew accepted for `exp` / `iat` / `nbf`
pub const SKEW: i64 = 60;
pub const ALGS: &[&str] = &["RS256", "ES256", "PS256"];
const DISCOVERY_TTL: Duration = Duration::from_secs(3600);
pub const JWKS_MIN_REFRESH: Duration = Duration::from_secs(10);
const MAX_BODY: usize = 1 << 20;
const MAX_TOKEN: usize = 16 << 10;
const SECRET_LABEL: &str = "oidc/client_secret";
const ROLES_BY_RANK: [&str; 5] = ["viewer", "tenant_user", "operator", "security_officer", "admin"];

// ---------------------------------------------------------------- settings

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Mapping {
    pub group: String,
    pub role: String,
    #[serde(default)]
    pub tenants: Vec<String>,
}

/// Stored form (`settings.oidc`); `client_secret` is `enc:v1:` (web-api key).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Settings {
    pub enabled: bool,
    pub issuer: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    pub username_claim: String,
    pub groups_claim: String,
    pub label: String,
    pub mappings: Vec<Mapping>,
    /// additive: PEM CA certificate(s) of an IdP with a private CA
    #[serde(default)]
    pub ca_pem: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            enabled: false,
            issuer: String::new(),
            client_id: String::new(),
            client_secret: None,
            scopes: ["openid", "profile", "email"].map(String::from).to_vec(),
            username_claim: "preferred_username".into(),
            groups_claim: "groups".into(),
            label: "Sign in with SSO".into(),
            mappings: vec![],
            ca_pem: None,
        }
    }
}

pub fn load(c: &Connection) -> ApiResult<Option<Settings>> {
    Ok(catalog::setting(c, SETTING)?.and_then(|v| serde_json::from_str(&v).ok()))
}

/// What `GET /settings/oidc` shows (secret write-only).
fn public(s: &Settings, redirect_uri: &str) -> Value {
    let mut v = serde_json::to_value(s).unwrap_or(Value::Null);
    v["client_secret"] = Value::Null;
    if let Some(o) = v.as_object_mut() {
        o.remove("client_secret");
    }
    v["client_secret_set"] = json!(s.client_secret.is_some());
    v["redirect_uri"] = json!(redirect_uri);
    v
}

fn printable(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len()) && !s.chars().any(char::is_control)
}

fn token_chars(s: &str, max: usize) -> bool {
    (1..=max).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"_:./-".contains(&b))
}

/// `(scheme, host, port)` of an http(s) URL without userinfo, query or fragment.
pub fn url_parts(u: &str) -> Option<(String, String, u16)> {
    let url = reqwest::Url::parse(u).ok()?;
    if !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
        return None;
    }
    let scheme = url.scheme().to_owned();
    if scheme != "https" && scheme != "http" {
        return None;
    }
    let host = url.host_str()?.trim_matches(['[', ']']).to_owned();
    let port = url.port_or_known_default()?;
    Some((scheme, host, port))
}

fn loopback(host: &str) -> bool {
    host == "localhost" || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// https, or http on a loopback host only.
fn url_ok(u: &str) -> bool {
    url_parts(u).is_some_and(|(s, h, _)| s == "https" || loopback(&h))
}

fn validate_settings(c: &Connection, s: &Settings) -> ApiResult<()> {
    let bad = |m: &str| Err(ApiError::bad(m.to_owned()));
    if !s.issuer.is_empty() && (s.issuer.len() > 512 || !url_ok(&s.issuer)) {
        return bad("issuer: https://host[:port][/path] (http only for loopback), no query or fragment");
    }
    if !s.client_id.is_empty() && (!printable(&s.client_id, 1, 255) || s.client_id.contains(' ')) {
        return bad("client_id: 1..=255 printable characters without spaces");
    }
    if s.scopes.is_empty() || s.scopes.len() > 16 || !s.scopes.iter().all(|x| token_chars(x, 64)) {
        return bad("scopes: 1..=16 scope names");
    }
    if !s.scopes.iter().any(|x| x == "openid") {
        return bad("scopes: must contain openid");
    }
    if !token_chars(&s.username_claim, 64) || !token_chars(&s.groups_claim, 64) {
        return bad("username_claim / groups_claim: claim names [A-Za-z0-9_:./-]{1,64}");
    }
    if !printable(&s.label, 1, 64) {
        return bad("label: 1..=64 printable characters");
    }
    if s.mappings.len() > 64 {
        return bad("mappings: at most 64");
    }
    for m in &s.mappings {
        if !printable(&m.group, 1, 256) {
            return bad("mappings: group 1..=256 printable characters");
        }
        validate::role(&m.role)?;
        // an account has exactly one tenant (tenant_user), at most one (viewer)
        // or none (all other roles)
        if m.role == "tenant_user" && m.tenants.len() != 1 {
            return bad("mappings: tenant_user needs exactly one tenant");
        }
        if m.role == "viewer" && m.tenants.len() > 1 {
            return bad("mappings: a viewer mapping names at most one tenant (none = all tenants)");
        }
        if !matches!(m.role.as_str(), "tenant_user" | "viewer") && !m.tenants.is_empty() {
            return bad("mappings: only tenant_user and viewer mappings name a tenant (other roles see all tenants)");
        }
        for t in &m.tenants {
            validate::name(t, "tenant")?;
            if c.query_row("SELECT 1 FROM tenants WHERE name = ?1", [t], |_| Ok(()))
                .optional()?
                .is_none()
            {
                return Err(ApiError::bad(format!("mappings: tenant {t} does not exist")));
            }
        }
    }
    if let Some(pem) = &s.ca_pem {
        if pem.len() > 65536 || reqwest::Certificate::from_pem_bundle(pem.as_bytes()).map_or(true, |v| v.is_empty()) {
            return bad("ca_pem: PEM certificate(s)");
        }
    }
    if s.enabled && (s.issuer.is_empty() || s.client_id.is_empty() || s.mappings.is_empty()) {
        return bad("enabled: needs issuer, client_id and at least one mapping");
    }
    Ok(())
}

/// The redirect URI registered at the IdP: this appliance's callback, from the
/// address the browser used (the IdP compares it with its registration). HTTP/2
/// carries it as `:authority` (the request URI), HTTP/1.1 as the Host header.
fn redirect_uri(uri: &Uri, h: &HeaderMap) -> String {
    let host = uri
        .authority()
        .map(|a| a.as_str())
        .or_else(|| h.get(header::HOST).and_then(|v| v.to_str().ok()))
        .filter(|s| {
            (1..=255).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
        })
        .unwrap_or("localhost");
    format!("https://{host}{COOKIE_PATH}/callback")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsReq {
    enabled: bool,
    issuer: String,
    client_id: String,
    /// write-only: omitted / null = keep, "" = remove (public client, PKCE only)
    #[serde(default)]
    client_secret: Option<String>,
    /// echoed by a client that sends back what it read: ignored
    #[serde(default, rename = "client_secret_set")]
    _client_secret_set: Option<bool>,
    #[serde(default, rename = "redirect_uri")]
    _redirect_uri: Option<String>,
    #[serde(default = "default_scopes")]
    scopes: Vec<String>,
    #[serde(default = "default_username_claim")]
    username_claim: String,
    #[serde(default = "default_groups_claim")]
    groups_claim: String,
    label: String,
    #[serde(default)]
    mappings: Vec<Mapping>,
    #[serde(default)]
    ca_pem: Option<String>,
}

fn default_scopes() -> Vec<String> {
    Settings::default().scopes
}
fn default_username_claim() -> String {
    Settings::default().username_claim
}
fn default_groups_claim() -> String {
    Settings::default().groups_claim
}

pub async fn get_settings(State(st): State<St>, ctx: Ctx, uri: Uri, headers: HeaderMap) -> ApiResult<Json<Value>> {
    ctx.require(&["admin", "security_officer"])?;
    let s = load(&st.cat.conn())?.unwrap_or_default();
    Ok(Json(public(&s, &redirect_uri(&uri, &headers))))
}

/// Changes who can sign in: quorum `oidc.update` while approvals are enabled.
pub async fn put_settings(State(st): State<St>, ctx: Ctx, J(r): J<SettingsReq>) -> ApiResult<Response> {
    ctx.require(&["admin"])?;
    let old = load(&st.cat.conn())?;
    let client_secret = match r.client_secret {
        None => old.as_ref().and_then(|o| o.client_secret.clone()),
        Some(s) if s.is_empty() => None,
        Some(s) => {
            if !printable(&s, 1, 1024) {
                return Err(ApiError::bad("client_secret: 1..=1024 printable characters"));
            }
            Some(st.totp.encrypt_labeled(SECRET_LABEL, &s)?)
        }
    };
    let new = Settings {
        enabled: r.enabled,
        issuer: r.issuer.trim().to_owned(),
        client_id: r.client_id.trim().to_owned(),
        client_secret,
        scopes: r.scopes,
        username_claim: r.username_claim,
        groups_claim: r.groups_claim,
        label: r.label,
        mappings: r.mappings,
        ca_pem: r.ca_pem.filter(|p| !p.trim().is_empty()),
    };
    validate_settings(&st.cat.conn(), &new)?;
    let p = json!({"settings": new, "old": old});
    let o = request(&st, &ctx, "oidc.update", "settings/oidc", p)?;
    Ok(accepted(o, json!({})))
}

/// Audit entry `settings.oidc` once a change is in effect (direct or approved).
pub fn audit_applied(st: &St, actor: &str, s: &Settings) -> ApiResult<()> {
    st.oidc.cache.lock().unwrap().take();
    st.audit(
        actor,
        "settings.oidc",
        "settings/oidc",
        json!({"enabled": s.enabled, "issuer": s.issuer, "client_id": s.client_id,
               "client_secret_set": s.client_secret.is_some(), "mappings": s.mappings}),
    )
}

/// Quorum execution of `oidc.update` (inside the approver's transaction):
/// refused when the settings changed since the request.
pub fn execute(c: &Connection, p: &Value) -> ApiResult<()> {
    let current = serde_json::to_value(load(c)?)?;
    if current != p["old"] {
        return Err(ApiError::conflict(
            "the OIDC settings changed since this request was made; reject it and request the change again",
        ));
    }
    let s: Settings =
        serde_json::from_value(p["settings"].clone()).map_err(|_| ApiError::bad("quorum params: settings"))?;
    catalog::set_setting(c, SETTING, &serde_json::to_string(&s)?)?;
    Ok(())
}

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        ApiError::from(anyhow::Error::from(e))
    }
}

// ---------------------------------------------------------------- IdP client

#[derive(Deserialize, Clone, Debug)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct Jwk {
    pub kty: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default, rename = "use")]
    pub use_: Option<String>,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
}

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Value>,
}

struct Cached {
    /// issuer + CA the entry belongs to
    key: String,
    disc: Discovery,
    at: Instant,
    keys: Vec<Jwk>,
    /// last fetch forced by an unknown `kid` (rate limit)
    refreshed: Option<Instant>,
}

struct Pending {
    nonce: String,
    verifier: String,
    binder: String,
    next: String,
    redirect_uri: String,
    created: i64,
}

#[derive(Default)]
pub struct OidcState {
    cache: Mutex<Option<Cached>>,
    pending: Mutex<HashMap<String, Pending>>,
}

fn client(s: &Settings) -> anyhow::Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("NexusBackup");
    if let Some(pem) = &s.ca_pem {
        for c in reqwest::Certificate::from_pem_bundle(pem.as_bytes())? {
            b = b.add_root_certificate(c);
        }
    }
    Ok(b.build()?)
}

async fn body_limited(r: reqwest::Response) -> anyhow::Result<Vec<u8>> {
    let mut r = r;
    let mut out = Vec::new();
    while let Some(chunk) = r.chunk().await? {
        if out.len() + chunk.len() > MAX_BODY {
            anyhow::bail!("answer larger than {MAX_BODY} bytes");
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

async fn get_json(cl: &reqwest::Client, url: &str) -> anyhow::Result<Value> {
    let r = cl.get(url).header(header::ACCEPT, "application/json").send().await?;
    let status = r.status();
    let body = body_limited(r).await?;
    if !status.is_success() {
        anyhow::bail!("GET {url}: HTTP {status}");
    }
    Ok(serde_json::from_slice(&body)?)
}

async fn discover(s: &Settings) -> anyhow::Result<Discovery> {
    let url = format!("{}/.well-known/openid-configuration", s.issuer.trim_end_matches('/'));
    let d: Discovery = serde_json::from_value(get_json(&client(s)?, &url).await?)?;
    if d.issuer != s.issuer {
        anyhow::bail!("discovery names issuer {:?}, configured is {:?}", d.issuer, s.issuer);
    }
    for (what, u) in [
        ("authorization_endpoint", &d.authorization_endpoint),
        ("token_endpoint", &d.token_endpoint),
        ("jwks_uri", &d.jwks_uri),
    ] {
        if !url_ok(u) {
            anyhow::bail!("{what} {u:?}: not an https URL");
        }
    }
    if d.code_challenge_methods_supported
        .as_ref()
        .is_some_and(|m| !m.iter().any(|x| x == "S256"))
    {
        anyhow::bail!("the IdP does not offer PKCE S256");
    }
    Ok(d)
}

async fn fetch_jwks(s: &Settings, d: &Discovery) -> anyhow::Result<Vec<Jwk>> {
    let set: JwkSet = serde_json::from_value(get_json(&client(s)?, &d.jwks_uri).await?)?;
    // keys of other types (enc keys, unsupported curves) are skipped, not fatal
    Ok(set
        .keys
        .into_iter()
        .filter_map(|k| serde_json::from_value::<Jwk>(k).ok())
        .filter(|k| k.use_.as_deref().is_none_or(|u| u == "sig"))
        .collect())
}

fn cache_key(s: &Settings) -> String {
    format!(
        "{}\0{}",
        s.issuer,
        sha256_hex(s.ca_pem.as_deref().unwrap_or("").as_bytes())
    )
}

/// Discovery + JWKS, from the cache when fresh. Records the endpoints for the
/// firewall allow-list when they changed.
async fn provider(st: &St, s: &Settings) -> anyhow::Result<(Discovery, Vec<Jwk>)> {
    let key = cache_key(s);
    if let Some(c) = st.oidc.cache.lock().unwrap().as_ref() {
        if c.key == key && c.at.elapsed() < DISCOVERY_TTL {
            return Ok((c.disc.clone(), c.keys.clone()));
        }
    }
    let disc = discover(s).await?;
    let keys = fetch_jwks(s, &disc).await?;
    record_endpoints(st, &disc)?;
    *st.oidc.cache.lock().unwrap() = Some(Cached {
        key,
        disc: disc.clone(),
        at: Instant::now(),
        keys: keys.clone(),
        refreshed: None,
    });
    Ok((disc, keys))
}

/// A token named a key we do not know: fetch the JWKS again (key rotation at
/// the IdP); such forced fetches at most every [`JWKS_MIN_REFRESH`].
async fn refresh_keys(st: &St, s: &Settings, d: &Discovery) -> anyhow::Result<Option<Vec<Jwk>>> {
    let key = cache_key(s);
    let due = st
        .oidc
        .cache
        .lock()
        .unwrap()
        .as_ref()
        .is_none_or(|c| c.key != key || c.refreshed.is_none_or(|t| t.elapsed() >= JWKS_MIN_REFRESH));
    if !due {
        return Ok(None);
    }
    let keys = fetch_jwks(s, d).await?;
    if let Some(c) = st.oidc.cache.lock().unwrap().as_mut().filter(|c| c.key == key) {
        c.keys = keys.clone();
        c.refreshed = Some(Instant::now());
    }
    Ok(Some(keys))
}

fn record_endpoints(st: &St, d: &Discovery) -> anyhow::Result<()> {
    let v = json!({"token_endpoint": d.token_endpoint, "jwks_uri": d.jwks_uri}).to_string();
    let c = st.cat.conn();
    if catalog::setting(&c, ENDPOINTS_SETTING)?.as_deref() != Some(v.as_str()) {
        catalog::set_setting(&c, ENDPOINTS_SETTING, &v)?;
    }
    Ok(())
}

/// `POST /settings/oidc/test`: discovery + JWKS of the saved settings.
pub async fn test_settings(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(&["admin"])?;
    let s = load(&st.cat.conn())?.unwrap_or_default();
    if s.issuer.is_empty() {
        return Err(ApiError::bad("no issuer configured"));
    }
    st.oidc.cache.lock().unwrap().take();
    // flat `{check: "ok" | "ok: detail" | "error: message"}` (contract clarification)
    let out = match discover(&s).await {
        Err(e) => json!({"discovery": format!("error: {e:#}")}),
        Ok(d) => {
            record_endpoints(&st, &d)?;
            let jwks = match fetch_jwks(&s, &d).await {
                Ok(keys) => match keys.iter().filter(|k| key_alg_ok(k)).count() {
                    0 => "error: the JWKS has no RS256/ES256/PS256 signing key".to_owned(),
                    n => format!("ok: {n} keys"),
                },
                Err(e) => format!("error: {e:#}"),
            };
            json!({"discovery": "ok", "jwks": jwks})
        }
    };
    st.audit(ctx.name(), "settings.oidc_test", "settings/oidc", out.clone())?;
    Ok(Json(out))
}

// ---------------------------------------------------------------- ID token

fn b64url(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

/// A JWK we can verify with: RSA (n, e) or EC P-256 (x, y), `alg` (if given) allowed.
fn key_alg_ok(k: &Jwk) -> bool {
    let alg_ok = k.alg.as_deref().is_none_or(|a| ALGS.contains(&a));
    alg_ok
        && match k.kty.as_str() {
            "RSA" => k.n.is_some() && k.e.is_some(),
            "EC" => k.crv.as_deref() == Some("P-256") && k.x.is_some() && k.y.is_some(),
            _ => false,
        }
}

fn verify_sig(alg: &str, k: &Jwk, msg: &[u8], sig: &[u8]) -> bool {
    use ring::signature as sg;
    if k.alg.as_deref().is_some_and(|a| a != alg) {
        return false;
    }
    match (alg, k.kty.as_str()) {
        ("RS256" | "PS256", "RSA") => {
            let (Some(n), Some(e)) = (k.n.as_deref().and_then(b64url), k.e.as_deref().and_then(b64url)) else {
                return false;
            };
            let params: &sg::RsaParameters = if alg == "RS256" {
                &sg::RSA_PKCS1_2048_8192_SHA256
            } else {
                &sg::RSA_PSS_2048_8192_SHA256
            };
            sg::RsaPublicKeyComponents { n: &n, e: &e }
                .verify(params, msg, sig)
                .is_ok()
        }
        ("ES256", "EC") if k.crv.as_deref() == Some("P-256") => {
            let (Some(x), Some(y)) = (k.x.as_deref().and_then(b64url), k.y.as_deref().and_then(b64url)) else {
                return false;
            };
            if x.len() != 32 || y.len() != 32 {
                return false;
            }
            let point = [&[4u8][..], &x, &y].concat();
            sg::UnparsedPublicKey::new(&sg::ECDSA_P256_SHA256_FIXED, point)
                .verify(msg, sig)
                .is_ok()
        }
        _ => false,
    }
}

/// Why an ID token was refused (audited; the browser only sees `token`).
#[derive(Debug, PartialEq)]
pub enum TokenError {
    Malformed,
    Alg(String),
    /// no key with this `kid` (the caller refreshes the JWKS once)
    UnknownKey,
    Signature,
    Claim(&'static str),
}

/// Checks an ID token (compact JWS) and returns its claims.
pub fn validate_id_token(
    token: &str,
    keys: &[Jwk],
    issuer: &str,
    client_id: &str,
    nonce: &str,
    now: i64,
) -> Result<Value, TokenError> {
    if token.len() > MAX_TOKEN {
        return Err(TokenError::Malformed);
    }
    let parts: Vec<&str> = token.split('.').collect();
    let [h, p, s] = parts[..] else {
        return Err(TokenError::Malformed);
    };
    let header: Value = b64url(h)
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or(TokenError::Malformed)?;
    let alg = header["alg"].as_str().unwrap_or_default();
    // allow-list before anything else: never `none`, never HMAC with a public key
    if !ALGS.contains(&alg) {
        return Err(TokenError::Alg(alg.chars().take(16).collect()));
    }
    if header.get("crit").is_some() {
        return Err(TokenError::Malformed);
    }
    let sig = b64url(s).ok_or(TokenError::Malformed)?;
    let kid = header["kid"].as_str();
    let candidates: Vec<&Jwk> = keys
        .iter()
        .filter(|k| key_alg_ok(k))
        .filter(|k| match kid {
            Some(kid) => k.kid.as_deref() == Some(kid),
            None => true,
        })
        .collect();
    if candidates.is_empty() {
        return Err(TokenError::UnknownKey);
    }
    let msg = format!("{h}.{p}");
    if !candidates.iter().any(|k| verify_sig(alg, k, msg.as_bytes(), &sig)) {
        return Err(TokenError::Signature);
    }
    let c: Value = b64url(p)
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or(TokenError::Malformed)?;
    if c["iss"].as_str() != Some(issuer) {
        return Err(TokenError::Claim("iss"));
    }
    let aud_ok = match &c["aud"] {
        Value::String(a) => a == client_id,
        Value::Array(a) => {
            a.iter().any(|x| x.as_str() == Some(client_id)) && (a.len() == 1 || c["azp"].as_str() == Some(client_id))
        }
        _ => false,
    };
    if !aud_ok {
        return Err(TokenError::Claim("aud"));
    }
    if c.get("azp").is_some_and(|a| a.as_str() != Some(client_id)) {
        return Err(TokenError::Claim("azp"));
    }
    let num = |k: &str| c[k].as_i64().or_else(|| c[k].as_f64().map(|f| f as i64));
    match num("exp") {
        Some(exp) if exp + SKEW > now => {}
        _ => return Err(TokenError::Claim("exp")),
    }
    match num("iat") {
        Some(iat) if iat <= now + SKEW => {}
        _ => return Err(TokenError::Claim("iat")),
    }
    if c.get("nbf").is_some() && num("nbf").is_none_or(|nbf| nbf > now + SKEW) {
        return Err(TokenError::Claim("nbf"));
    }
    if !c["nonce"]
        .as_str()
        .is_some_and(|n| ct_eq(n.as_bytes(), nonce.as_bytes()))
    {
        return Err(TokenError::Claim("nonce"));
    }
    if !c["sub"].as_str().is_some_and(|s| printable(s, 1, 255)) {
        return Err(TokenError::Claim("sub"));
    }
    Ok(c)
}

// ---------------------------------------------------------------- claims → account

/// The winning mapping for the groups: highest privileged role; among equal
/// roles an unscoped mapping, then the first in configured order. Tenants that
/// no longer exist do not match.
pub fn pick_mapping<'a>(c: &Connection, s: &'a Settings, groups: &[String]) -> ApiResult<Option<&'a Mapping>> {
    let norm = |g: &str| g.trim_start_matches('/').to_owned();
    let have: Vec<String> = groups.iter().map(|g| norm(g)).collect();
    let mut best: Option<(usize, bool, &Mapping)> = None;
    for m in &s.mappings {
        if !have.contains(&norm(&m.group)) {
            continue;
        }
        if let Some(t) = m.tenants.first() {
            if c.query_row("SELECT 1 FROM tenants WHERE name = ?1", [t], |_| Ok(()))
                .optional()?
                .is_none()
            {
                continue;
            }
        }
        let rank = ROLES_BY_RANK.iter().position(|r| *r == m.role).unwrap_or(0);
        let unscoped = m.tenants.is_empty();
        if best.is_none_or(|(br, bu, _)| (rank, unscoped) > (br, bu)) {
            best = Some((rank, unscoped, m));
        }
    }
    Ok(best.map(|b| b.2))
}

fn claim_groups(c: &Value, claim: &str) -> Vec<String> {
    match &c[claim] {
        Value::Array(a) => a
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .take(1000)
            .collect(),
        Value::String(s) => vec![s.clone()],
        _ => vec![],
    }
}

/// SSO account names come from the IdP as they are (Entra UPNs contain `@`):
/// 1..=128 characters, printable, no whitespace.
pub fn sso_name_ok(s: &str) -> bool {
    (1..=128).contains(&s.chars().count()) && !s.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// Why a login was refused: (code for the browser, reason for the audit log).
type Denied = (&'static str, String);
/// The account and the audit entries (action, details) its provisioning produced.
type Provisioned = (User, Vec<(String, Value)>);

/// Creates or refreshes the account of the token's subject. Inside one
/// transaction; audit entries are returned for the caller to write.
fn provision(st: &St, s: &Settings, claims: &Value) -> ApiResult<Result<Provisioned, Denied>> {
    let sub = format!("{}|{}", s.issuer, claims["sub"].as_str().unwrap_or_default());
    let name = claims[&s.username_claim].as_str().unwrap_or_default().to_owned();
    let groups = claim_groups(claims, &s.groups_claim);
    let mut c = st.cat.conn();
    let tx = c.transaction()?;
    let existing: Option<User> = tx
        .query_row(
            &format!("SELECT {USER_COLS} FROM users WHERE oidc_sub = ?1"),
            [&sub],
            |r| User::from_row(r, 0),
        )
        .optional()?;
    let mapping = pick_mapping(&tx, s, &groups)?.cloned();
    let mut audits = vec![];
    let Some(m) = mapping else {
        if let Some(u) = &existing {
            tx.execute("UPDATE users SET disabled = 1 WHERE id = ?1", [u.id])?;
            tx.execute("DELETE FROM sessions WHERE user_id = ?1", [u.id])?;
            tx.commit()?;
        }
        return Ok(Err(("denied", format!("no mapping matches the groups {groups:?}"))));
    };
    let tenant = m.tenants.first().cloned();
    let user = match existing {
        Some(u) if u.disabled => {
            return Ok(Err((
                "account_disabled",
                "the account was disabled (by an admin or because no mapping matched); an admin re-enables it".into(),
            )))
        }
        Some(u) if u.expired(catalog::now()) => {
            tx.execute("DELETE FROM sessions WHERE user_id = ?1", [u.id])?;
            tx.commit()?;
            return Ok(Err((
                "account_disabled",
                "the account expired; an admin extends or clears its expiry date".into(),
            )));
        }
        Some(u) => {
            if u.role != m.role || u.tenant != tenant {
                tx.execute(
                    "UPDATE users SET role = ?2, tenant = ?3 WHERE id = ?1",
                    params![u.id, m.role, tenant],
                )?;
                audits.push((
                    "user.oidc_updated".to_owned(),
                    json!({"role": m.role, "tenant": tenant, "previous_role": u.role,
                           "previous_tenant": u.tenant, "group": m.group}),
                ));
            }
            User::load(&tx, u.id)?
        }
        None => {
            if !sso_name_ok(&name) {
                return Ok(Err((
                    "denied",
                    format!("claim {} is not a usable account name: {name:?}", s.username_claim),
                )));
            }
            // matched by (issuer, sub) only: a name that exists (a local account, or
            // another subject) is never merged or taken over
            let taken: Option<String> = tx
                .query_row("SELECT auth FROM users WHERE name = ?1", [&name], |r| r.get(0))
                .optional()?;
            if let Some(auth) = taken {
                return Ok(Err((
                    "denied",
                    format!("name_conflict: an account named {name} exists already ({auth})"),
                )));
            }
            tx.execute(
                "INSERT INTO users (name, password_hash, totp_secret, role, tenant, disabled, created, auth, oidc_sub)
                 VALUES (?1, ?2, '', ?3, ?4, 0, ?5, 'oidc', ?6)",
                params![name, catalog::OIDC_PASSWORD, m.role, tenant, catalog::now(), sub],
            )?;
            let u = User::load(&tx, tx.last_insert_rowid())?;
            audits.push((
                "user.oidc_created".to_owned(),
                json!({"role": m.role, "tenant": tenant, "group": m.group, "subject": sub}),
            ));
            u
        }
    };
    tx.commit()?;
    Ok(Ok((user, audits)))
}

// ---------------------------------------------------------------- login flow

/// `GET /auth/oidc` (no session): what the login page shows.
pub async fn info(State(st): State<St>) -> ApiResult<Json<Value>> {
    let s = load(&st.cat.conn())?.unwrap_or_default();
    Ok(Json(json!({"enabled": s.enabled, "label": s.label})))
}

/// Same-origin path only: `/…`, not `//…` or `/\…`, printable ASCII, no
/// whitespace (a header value). Anything else → `/`.
pub fn safe_next(next: Option<&str>) -> String {
    match next {
        Some(n)
            if n.starts_with('/')
                && !n.starts_with("//")
                && !n.starts_with("/\\")
                && n.len() <= 512
                && n.bytes().all(|b| b.is_ascii_graphic() && b != b'\\') =>
        {
            n.to_owned()
        }
        _ => "/".into(),
    }
}

fn redirect(to: &str, cookie: Option<String>) -> Response {
    let mut res = StatusCode::FOUND.into_response();
    let h = res.headers_mut();
    h.insert(
        header::LOCATION,
        HeaderValue::from_str(to).unwrap_or(HeaderValue::from_static("/")),
    );
    if let Some(c) = cookie {
        if let Ok(v) = HeaderValue::from_str(&c) {
            h.append(header::SET_COOKIE, v);
        }
    }
    res
}

fn fail(code: &str) -> Response {
    redirect(
        &format!("/#/login?oidc_error={code}"),
        Some(format!(
            "{COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path={COOKIE_PATH}; Max-Age=0"
        )),
    )
}

#[derive(Deserialize)]
pub struct StartQuery {
    next: Option<String>,
}

/// `GET /auth/oidc/start?next=/path` → 302 to the IdP.
pub async fn start(State(st): State<St>, uri: Uri, headers: HeaderMap, Q(q): Q<StartQuery>) -> ApiResult<Response> {
    let s = load(&st.cat.conn())?.unwrap_or_default();
    if !s.enabled {
        return Ok(fail("disabled"));
    }
    let disc = match provider(&st, &s).await {
        Ok((d, _)) => d,
        Err(e) => {
            eprintln!("<4>web-api: oidc discovery: {e:#}");
            return Ok(fail("idp"));
        }
    };
    let (state, nonce, binder) = (random_hex(), random_hex(), random_hex());
    let verifier = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let challenge = URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier.as_bytes()));
    let redirect_uri = redirect_uri(&uri, &headers);
    let now = catalog::now();
    {
        let mut p = st.oidc.pending.lock().unwrap();
        // expired logins are kept a while longer to tell `expired` from `state`
        p.retain(|_, v| now - v.created < 2 * PENDING_SECS);
        if p.len() >= MAX_PENDING {
            return Ok(fail("idp"));
        }
        p.insert(
            state.clone(),
            Pending {
                nonce: nonce.clone(),
                verifier,
                binder: sha256_hex(binder.as_bytes()),
                next: safe_next(q.next.as_deref()),
                redirect_uri: redirect_uri.clone(),
                created: now,
            },
        );
    }
    let mut url = reqwest::Url::parse(&disc.authorization_endpoint).map_err(|e| anyhow::anyhow!("{e}"))?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &s.client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("scope", &s.scopes.join(" "))
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    Ok(redirect(
        url.as_str(),
        Some(format!(
            "{COOKIE}={binder}; HttpOnly; Secure; SameSite=Lax; Path={COOKIE_PATH}; Max-Age={PENDING_SECS}"
        )),
    ))
}

use sha2::Digest;

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

fn binder_cookie(h: &HeaderMap) -> Option<String> {
    h.get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|kv| kv.trim().strip_prefix(COOKIE)?.strip_prefix('=').map(str::to_owned))
}

/// Token request (code + PKCE verifier); client_secret_basic when a secret is set.
async fn exchange(st: &St, s: &Settings, d: &Discovery, code: &str, p: &Pending) -> anyhow::Result<String> {
    let mut form = vec![
        ("grant_type", "authorization_code".to_owned()),
        ("code", code.to_owned()),
        ("redirect_uri", p.redirect_uri.clone()),
        ("code_verifier", p.verifier.clone()),
    ];
    let mut req = client(s)?
        .post(&d.token_endpoint)
        .header(header::ACCEPT, "application/json");
    match &s.client_secret {
        Some(enc) => {
            let secret = st.totp.decrypt_labeled(SECRET_LABEL, enc)?;
            // RFC 6749 §2.3.1: both parts form-urlencoded before Basic
            let enc = |v: &str| form_urlencode(v);
            let basic = STANDARD.encode(format!("{}:{}", enc(&s.client_id), enc(&secret)));
            req = req.header(header::AUTHORIZATION, format!("Basic {basic}"));
        }
        None => form.push(("client_id", s.client_id.clone())),
    }
    let body: String = form
        .iter()
        .map(|(k, v)| format!("{k}={}", form_urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let r = req
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await?;
    let status = r.status();
    let b = body_limited(r).await?;
    if !status.is_success() {
        let v: Value = serde_json::from_slice(&b).unwrap_or(Value::Null);
        anyhow::bail!(
            "token endpoint: HTTP {status} {}",
            v["error"]
                .as_str()
                .unwrap_or_default()
                .chars()
                .take(64)
                .collect::<String>()
        );
    }
    let v: Value = serde_json::from_slice(&b)?;
    v["id_token"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("token endpoint: no id_token"))
}

fn form_urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'*' => (b as char).to_string(),
            b' ' => "+".into(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// `GET /auth/oidc/callback?code&state` → session cookie + 302 to `next`, or
/// 302 `/#/login?oidc_error=<code>`.
pub async fn callback(
    State(st): State<St>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Q(q): Q<CallbackQuery>,
) -> ApiResult<Response> {
    let ikey = format!("ip:{ip}");
    let ukey = format!("oidc-ip:{ip}");
    if locked_out(&st, &ukey, &ikey) {
        return Ok(fail("denied"));
    }
    let deny = |code: &'static str, reason: String| -> ApiResult<Response> {
        record_failure(
            &st,
            ("anonymous", "auth.oidc_denied", "settings/oidc"),
            (&ukey, &ikey, &ip),
            json!({"ip": ip, "code": code, "reason": reason}),
        )?;
        Ok(fail(code))
    };
    // one use per state, whatever happens next
    let pending = q
        .state
        .as_deref()
        .and_then(|s| st.oidc.pending.lock().unwrap().remove(s));
    let Some(p) = pending else {
        return deny("state", "unknown, used or expired state".into());
    };
    let bound =
        binder_cookie(&headers).is_some_and(|b| ct_eq(sha256_hex(b.as_bytes()).as_bytes(), p.binder.as_bytes()));
    if !bound {
        return deny("state", "login not started in this browser".into());
    }
    if catalog::now() - p.created >= PENDING_SECS {
        return deny("expired", "the pending login expired".into());
    }
    if let Some(e) = &q.error {
        return deny(
            "idp",
            format!("IdP answered error {:?}", e.chars().take(64).collect::<String>()),
        );
    }
    let Some(code) = q.code.as_deref().filter(|c| printable(c, 1, 4096)) else {
        return deny("idp", "no code".into());
    };
    let s = load(&st.cat.conn())?.unwrap_or_default();
    if !s.enabled {
        return Ok(fail("disabled"));
    }
    let (disc, mut keys) = match provider(&st, &s).await {
        Ok(x) => x,
        Err(e) => return deny("idp", format!("discovery: {e:#}")),
    };
    let token = match exchange(&st, &s, &disc, code, &p).await {
        Ok(t) => t,
        Err(e) => return deny("token", format!("{e:#}")),
    };
    let now = catalog::now();
    let mut claims = validate_id_token(&token, &keys, &s.issuer, &s.client_id, &p.nonce, now);
    if claims == Err(TokenError::UnknownKey) {
        if let Ok(Some(k)) = refresh_keys(&st, &s, &disc).await {
            keys = k;
            claims = validate_id_token(&token, &keys, &s.issuer, &s.client_id, &p.nonce, now);
        }
    }
    let claims = match claims {
        Ok(c) => c,
        Err(e) => return deny("token", format!("id token refused: {e:?}")),
    };
    let (user, audits) = match provision(&st, &s, &claims)? {
        Ok(x) => x,
        Err((code, reason)) => return deny(code, reason),
    };
    let target = format!("user/{}", user.name);
    for (action, details) in audits {
        st.audit("web-api", &action, &target, details)?;
    }
    let (cookie, _csrf) = new_session(&st, user.id, &ip, &headers)?;
    st.audit(
        &user.name,
        "auth.oidc_login",
        &target,
        json!({"ip": ip, "role": user.role, "tenant": user.tenant}),
    )?;
    let mut res = redirect(
        &p.next,
        Some(format!(
            "{COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path={COOKIE_PATH}; Max-Age=0"
        )),
    );
    res.headers_mut().append(header::SET_COOKIE, cookie);
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HTTP/2 has no Host header (the browser's address is the URI authority);
    /// HTTP/1.1 sends a path-only URI plus Host; hostile values fall back.
    #[test]
    fn redirect_uri_from_authority_or_host() {
        let h2: Uri = "https://nexus-m5:28481/api/v1/auth/oidc/start".parse().unwrap();
        assert_eq!(
            redirect_uri(&h2, &HeaderMap::new()),
            "https://nexus-m5:28481/api/v1/auth/oidc/callback"
        );
        let mut h = HeaderMap::new();
        h.insert(header::HOST, HeaderValue::from_static("backup.example.com"));
        let h1: Uri = "/api/v1/auth/oidc/start".parse().unwrap();
        assert_eq!(
            redirect_uri(&h1, &h),
            "https://backup.example.com/api/v1/auth/oidc/callback"
        );
        h.insert(header::HOST, HeaderValue::from_static("evil.example/x?"));
        assert_eq!(redirect_uri(&h1, &h), "https://localhost/api/v1/auth/oidc/callback");
    }

    #[test]
    fn next_is_same_origin_only() {
        assert_eq!(safe_next(Some("/#/jobs")), "/#/jobs");
        assert_eq!(safe_next(Some("/a?b=c")), "/a?b=c");
        for bad in [
            "//evil.example/",
            "/\\evil.example",
            "https://evil.example/",
            "evil",
            "/a b",
            "/a\r\nSet-Cookie: x",
            "",
        ] {
            assert_eq!(safe_next(Some(bad)), "/", "{bad:?}");
        }
        assert_eq!(safe_next(None), "/");
    }

    #[test]
    fn urls() {
        assert!(url_ok("https://idp.example.com/realms/nexus"));
        assert!(url_ok("http://127.0.0.1:8080/realms/nexus"));
        assert!(url_ok("http://localhost/x"));
        assert!(!url_ok("http://idp.example.com/realms/nexus"));
        assert!(!url_ok("https://user:pw@idp.example.com/"));
        assert!(!url_ok("https://idp.example.com/?x=1"));
        assert!(!url_ok("ftp://idp.example.com/"));
        assert_eq!(
            url_parts("https://idp.example.com/realms/x"),
            Some(("https".into(), "idp.example.com".into(), 443))
        );
    }

    #[test]
    fn form_encoding() {
        assert_eq!(form_urlencode("a b&c=d/é"), "a+b%26c%3Dd%2F%C3%A9");
    }

    // ---- ID token validation against locally generated keys (no IdP)

    use ring::rand::SystemRandom;
    use ring::signature::{self as sg, KeyPair};

    const ISS: &str = "https://idp.example.com/realms/nexus";
    const CID: &str = "nexusbackup";
    const NOW: i64 = 1_791_750_000;

    struct Keys {
        ec: sg::EcdsaKeyPair,
        rsa: sg::RsaKeyPair,
    }

    fn keys() -> Keys {
        let rng = SystemRandom::new();
        let pk8 = sg::EcdsaKeyPair::generate_pkcs8(&sg::ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let ec = sg::EcdsaKeyPair::from_pkcs8(&sg::ECDSA_P256_SHA256_FIXED_SIGNING, pk8.as_ref(), &rng).unwrap();
        let pem = include_str!("../../../plugins/m365/tests/data/test-app.key");
        let der = STANDARD
            .decode(pem.lines().filter(|l| !l.starts_with("-----")).collect::<String>())
            .unwrap();
        let rsa = sg::RsaKeyPair::from_pkcs8(&der).unwrap();
        Keys { ec, rsa }
    }

    fn jwks(k: &Keys) -> Vec<Jwk> {
        let p = k.ec.public_key().as_ref();
        let r: ring::rsa::PublicKeyComponents<Vec<u8>> = k.rsa.public().into();
        let (n, e) = (r.n, r.e);
        serde_json::from_value(json!([
            {"kty": "EC", "crv": "P-256", "kid": "ec1", "use": "sig",
             "x": URL_SAFE_NO_PAD.encode(&p[1..33]), "y": URL_SAFE_NO_PAD.encode(&p[33..])},
            {"kty": "RSA", "kid": "rsa1", "n": URL_SAFE_NO_PAD.encode(n), "e": URL_SAFE_NO_PAD.encode(e)},
            {"kty": "oct", "kid": "hmac", "k": URL_SAFE_NO_PAD.encode(b"secret")}
        ]))
        .unwrap()
    }

    fn claims() -> Value {
        json!({"iss": ISS, "aud": CID, "sub": "u-1", "exp": NOW + 300, "iat": NOW, "nonce": "n0nce",
               "preferred_username": "kc-alice", "groups": ["/nexus-admins"]})
    }

    fn sign(k: &Keys, alg: &str, kid: &str, c: &Value) -> String {
        let h = URL_SAFE_NO_PAD.encode(json!({"alg": alg, "kid": kid, "typ": "JWT"}).to_string());
        let p = URL_SAFE_NO_PAD.encode(c.to_string());
        let msg = format!("{h}.{p}");
        let rng = SystemRandom::new();
        let sig = match alg {
            "ES256" => k.ec.sign(&rng, msg.as_bytes()).unwrap().as_ref().to_vec(),
            "RS256" | "PS256" => {
                let mut s = vec![0; k.rsa.public().modulus_len()];
                let enc: &dyn sg::RsaEncoding = if alg == "RS256" {
                    &sg::RSA_PKCS1_SHA256
                } else {
                    &sg::RSA_PSS_SHA256
                };
                k.rsa.sign(enc, &rng, msg.as_bytes(), &mut s).unwrap();
                s
            }
            "HS256" => ring::hmac::sign(
                &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"secret"),
                msg.as_bytes(),
            )
            .as_ref()
            .to_vec(),
            _ => vec![],
        };
        format!("{msg}.{}", URL_SAFE_NO_PAD.encode(sig))
    }

    fn check(k: &Keys, t: &str) -> Result<Value, TokenError> {
        validate_id_token(t, &jwks(k), ISS, CID, "n0nce", NOW)
    }

    #[test]
    fn id_token_accepts_es256_rs256_ps256() {
        let k = keys();
        for (alg, kid) in [("ES256", "ec1"), ("RS256", "rsa1"), ("PS256", "rsa1")] {
            let c = check(&k, &sign(&k, alg, kid, &claims())).unwrap();
            assert_eq!(c["sub"], "u-1", "{alg}");
        }
        // aud as an array with azp
        let mut c = claims();
        c["aud"] = json!([CID, "account"]);
        c["azp"] = json!(CID);
        assert!(check(&k, &sign(&k, "ES256", "ec1", &c)).is_ok());
        // small clock skew tolerated
        let mut c = claims();
        c["exp"] = json!(NOW - 30);
        c["iat"] = json!(NOW + 30);
        assert!(check(&k, &sign(&k, "ES256", "ec1", &c)).is_ok());
    }

    #[test]
    fn id_token_refusals() {
        let k = keys();
        let with = |f: &dyn Fn(&mut Value)| {
            let mut c = claims();
            f(&mut c);
            check(&k, &sign(&k, "ES256", "ec1", &c))
        };
        assert_eq!(with(&|c| c["aud"] = json!("other")), Err(TokenError::Claim("aud")));
        assert_eq!(
            with(&|c| c["aud"] = json!([CID, "other"])),
            Err(TokenError::Claim("aud")),
            "several audiences need azp"
        );
        assert_eq!(
            with(&|c| {
                c["aud"] = json!([CID]);
                c["azp"] = json!("other")
            }),
            Err(TokenError::Claim("azp"))
        );
        assert_eq!(
            with(&|c| c["iss"] = json!("https://evil.example")),
            Err(TokenError::Claim("iss"))
        );
        assert_eq!(
            with(&|c| c["iss"] = json!(format!("{ISS}/"))),
            Err(TokenError::Claim("iss"))
        );
        assert_eq!(with(&|c| c["nonce"] = json!("other")), Err(TokenError::Claim("nonce")));
        assert_eq!(
            with(&|c| {
                c.as_object_mut().unwrap().remove("nonce");
            }),
            Err(TokenError::Claim("nonce"))
        );
        assert_eq!(
            with(&|c| c["exp"] = json!(NOW - SKEW - 1)),
            Err(TokenError::Claim("exp"))
        );
        assert_eq!(
            with(&|c| c["iat"] = json!(NOW + SKEW + 1)),
            Err(TokenError::Claim("iat"))
        );
        assert_eq!(with(&|c| c["nbf"] = json!(NOW + 3600)), Err(TokenError::Claim("nbf")));
        assert_eq!(with(&|c| c["sub"] = json!("")), Err(TokenError::Claim("sub")));
        // alg none: unsigned token with an empty signature
        let none = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(json!({"alg": "none"}).to_string()),
            URL_SAFE_NO_PAD.encode(claims().to_string())
        );
        assert_eq!(check(&k, &none), Err(TokenError::Alg("none".into())));
        // HMAC with a key the attacker knows, even if the JWKS publishes it
        assert_eq!(
            check(&k, &sign(&k, "HS256", "hmac", &claims())),
            Err(TokenError::Alg("HS256".into()))
        );
        // unknown kid: the caller fetches the JWKS once more
        assert_eq!(
            check(&k, &sign(&k, "ES256", "rotated", &claims())),
            Err(TokenError::UnknownKey)
        );
        // key confusion: RSA signature presented under the EC key id, and vice versa
        assert_eq!(
            check(&k, &sign(&k, "RS256", "ec1", &claims())),
            Err(TokenError::Signature)
        );
        assert_eq!(
            check(&k, &sign(&k, "ES256", "rsa1", &claims())),
            Err(TokenError::Signature)
        );
        // tampered payload
        let t = sign(&k, "ES256", "ec1", &claims());
        let mut parts: Vec<String> = t.split('.').map(str::to_owned).collect();
        let mut c = claims();
        c["groups"] = json!(["nexus-admins", "/god"]);
        parts[1] = URL_SAFE_NO_PAD.encode(c.to_string());
        assert_eq!(check(&k, &parts.join(".")), Err(TokenError::Signature));
        // a token signed by another key with the same kid
        let other = keys();
        assert_eq!(
            check(&k, &sign(&other, "ES256", "ec1", &claims())),
            Err(TokenError::Signature)
        );
        assert_eq!(check(&k, "a.b"), Err(TokenError::Malformed));
        assert_eq!(check(&k, &"x".repeat(MAX_TOKEN + 1)), Err(TokenError::Malformed));
        // a JWK pinned to another algorithm is not used
        let mut ks = jwks(&k);
        ks[0].alg = Some("ES384".into());
        assert!(validate_id_token(&sign(&k, "ES256", "ec1", &claims()), &ks, ISS, CID, "n0nce", NOW).is_err());
    }

    #[test]
    fn mapping_highest_privilege_wins() {
        let cat = catalog::Catalog::open_memory().unwrap();
        let c = cat.conn();
        c.execute("INSERT INTO tenants (name) VALUES ('acme')", []).unwrap();
        let m = |g: &str, r: &str, t: &[&str]| Mapping {
            group: g.into(),
            role: r.into(),
            tenants: t.iter().map(|x| x.to_string()).collect(),
        };
        let s = Settings {
            mappings: vec![
                m("acme-users", "tenant_user", &["acme"]),
                m("support-acme", "tenant_user", &["acme"]),
                m("ops", "operator", &[]),
                m("nexus-admins", "admin", &[]),
                m("gone", "tenant_user", &["deleted"]),
            ],
            ..Settings::default()
        };
        let pick = |g: &[&str]| {
            pick_mapping(&c, &s, &g.iter().map(|x| x.to_string()).collect::<Vec<_>>())
                .unwrap()
                .map(|m| m.group.clone())
        };
        assert_eq!(pick(&["acme-users", "/nexus-admins"]).as_deref(), Some("nexus-admins"));
        assert_eq!(pick(&["support-acme", "ops", "acme-users"]).as_deref(), Some("ops"));
        assert_eq!(
            pick(&["support-acme", "acme-users"]).as_deref(),
            Some("acme-users"),
            "configured order"
        );
        assert_eq!(pick(&["gone"]), None, "tenant no longer exists");
        assert_eq!(pick(&["other"]), None);
        assert_eq!(pick(&[]), None);
    }

    #[test]
    fn settings_validation() {
        let cat = catalog::Catalog::open_memory().unwrap();
        let c = cat.conn();
        c.execute("INSERT INTO tenants (name) VALUES ('acme')", []).unwrap();
        let ok = Settings {
            enabled: true,
            issuer: ISS.into(),
            client_id: CID.into(),
            mappings: vec![Mapping {
                group: "g".into(),
                role: "admin".into(),
                tenants: vec![],
            }],
            ..Settings::default()
        };
        assert!(validate_settings(&c, &ok).is_ok());
        let bad = |f: &dyn Fn(&mut Settings)| {
            let mut s = ok.clone();
            f(&mut s);
            validate_settings(&c, &s).is_err()
        };
        assert!(bad(&|s| s.issuer = "http://idp.example.com".into()));
        assert!(bad(&|s| s.mappings.clear()), "enabled without mappings");
        assert!(bad(&|s| s.scopes = vec!["profile".into()]), "openid required");
        assert!(bad(&|s| s.mappings[0].tenants = vec!["acme".into()]), "admin scoped");
        assert!(
            bad(&|s| s.mappings[0].role = "tenant_user".into()),
            "tenant_user unscoped"
        );
        assert!(bad(&|s| {
            s.mappings[0].role = "tenant_user".into();
            s.mappings[0].tenants = vec!["nope".into()]
        }));
        assert!(
            bad(&|s| {
                s.mappings[0].role = "operator".into();
                s.mappings[0].tenants = vec!["acme".into()]
            }),
            "operators see all tenants"
        );
        assert!(!bad(&|s| {
            s.mappings[0].role = "tenant_user".into();
            s.mappings[0].tenants = vec!["acme".into()]
        }));
        // viewers: appliance-wide or one tenant
        assert!(!bad(&|s| s.mappings[0].role = "viewer".into()));
        assert!(!bad(&|s| {
            s.mappings[0].role = "viewer".into();
            s.mappings[0].tenants = vec!["acme".into()]
        }));
        assert!(bad(&|s| {
            s.mappings[0].role = "viewer".into();
            s.mappings[0].tenants = vec!["acme".into(), "acme".into()]
        }));
        assert!(bad(&|s| s.mappings[0].role = "tenant_admin".into()), "reserved");
        assert!(sso_name_ok("alice@contoso.onmicrosoft.com") && sso_name_ok("kc.alice"));
        assert!(!sso_name_ok("a b") && !sso_name_ok("") && !sso_name_ok(&"x".repeat(129)) && !sso_name_ok("a\tb"));
        assert!(bad(&|s| s.username_claim = "a b".into()));
        assert!(bad(&|s| s.ca_pem = Some("not a cert".into())));
        assert!(bad(&|s| s.client_id = "a b".into()));
        assert!(!bad(&|s| {
            s.enabled = false;
            s.mappings.clear()
        }));
    }
}
