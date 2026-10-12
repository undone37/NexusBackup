//! Appliance replication (docs/replication.md).
//!
//! **Peer API** (`/replication/v1/*`, primary): only on TLS connections that
//! negotiated a replication ALPN ([`ReplConn`]). The client certificate's
//! fingerprint is looked up in `replication_peers` on every request (revocation
//! takes effect immediately), the tenant scope is enforced, and data requests
//! are forwarded to nexus-replicad over its Unix socket and streamed back: the
//! web-api never opens store files and never talks to keyd.
//!
//! **Management API** (`/api/v1/replication/*`, session auth): peers on the
//! primary (quorum-gated creation, key export and deletion) and replication
//! sources on the secondary (the scheduler enrolls and syncs).

use crate::auth::Ctx;
use crate::quorum::{accepted, request, request_as};
use crate::tls::ReplConn;
use crate::{validate, ApiError, ApiResult, St, J};
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, FromRequestParts, Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::rusqlite::{params, Connection, OptionalExtension};
use catalog::schedule::{self, Bandwidth, RateWindow, Span};
use catalog::secret::{replication_peer_token_location, replication_source_token_location, SealKey};
use repl_proto::{
    hex, key_fingerprint, parse_ids, split_code, token_digest, unhex, valid_hex64, valid_peer_id, EnrollOutcome,
    EnrollRequest, EnrollResponse, Header, KeyExport, Request, SessionEnd, MAX_BODY, MAX_CONCURRENT,
    MAX_ENROLL_FAILURES, TOKEN_TTL_SECS,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader, ReadBuf};

const ADMIN: &[&str] = &["admin"];
const READ: &[&str] = &["admin", "security_officer", "operator"];

/// Paths of the replicad interface (None = replication serving disabled).
#[derive(Clone, Debug, Default)]
pub struct ReplPaths {
    /// `/run/nexus-replicad/replicad.sock`
    pub socket: Option<PathBuf>,
    /// `/run/nexus-replicad/seal.pub`: enrollment token digests are sealed to it
    pub seal_pub: Option<PathBuf>,
    /// this appliance's TLS certificate: its SHA-256 is shown when a peer is
    /// created (the secondary pins it during enrollment)
    pub tls_cert: Option<PathBuf>,
}

/// SHA-256 (hex) of the first certificate in a PEM file — the value a secondary pins.
pub fn cert_fingerprint(path: &std::path::Path) -> anyhow::Result<String> {
    use rustls::pki_types::{pem::PemObject, CertificateDer};
    let cert = CertificateDer::pem_file_iter(path)?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no certificate in {}", path.display()))??;
    Ok(repl_proto::sha256_hex(&cert))
}

struct Session {
    peer: String,
    tenant: String,
    start: i64,
    served_at_start: u64,
}

/// In-memory replication state of the web-api.
#[derive(Default)]
pub struct ReplState {
    pub paths: ReplPaths,
    /// running requests per peer
    active: Mutex<HashMap<String, usize>>,
    /// bytes served per peer since start
    served: Mutex<HashMap<String, Arc<AtomicU64>>>,
    sessions: Mutex<HashMap<String, Session>>,
    /// last `replication.denied` audit per fingerprint (throttle)
    denied: Mutex<HashMap<String, i64>>,
}

impl ReplState {
    pub fn new(paths: ReplPaths) -> Self {
        ReplState {
            paths,
            ..Default::default()
        }
    }

    fn counter(&self, peer: &str) -> Arc<AtomicU64> {
        self.served.lock().unwrap().entry(peer.to_owned()).or_default().clone()
    }
}

/// Is `tenant` replicated into this appliance (secondary)? Such tenants take no
/// backups: no groups, no agents, no backup jobs (docs/replication.md §7). A
/// source may exist (restore target, e.g. the DR site's PVE cluster).
pub fn replicated_tenant(c: &Connection, tenant: &str) -> ApiResult<bool> {
    Ok(c.query_row(
        "SELECT 1 FROM replication_sources, json_each(replication_sources.tenants) j WHERE j.value = ?1",
        [tenant],
        |_| Ok(()),
    )
    .optional()?
    .is_some())
}

/// 409 if `tenant` is a replicated tenant.
pub fn refuse_replicated(c: &Connection, tenant: &str) -> ApiResult<()> {
    if replicated_tenant(c, tenant)? {
        return Err(ApiError::conflict(
            "tenant is replicated from another appliance: it takes no local backups (groups, agents, backup jobs)",
        ));
    }
    Ok(())
}

// ================================================================ peer API (primary)

#[derive(Clone, Debug)]
pub struct Peer {
    pub id: String,
    pub name: String,
    pub tenants: Vec<String>,
}

/// Optional JSON body: empty = defaults, otherwise strict like `J`.
fn optional_json<T: serde::de::DeserializeOwned + Default>(b: &[u8]) -> ApiResult<T> {
    if b.iter().all(u8::is_ascii_whitespace) {
        return Ok(T::default());
    }
    serde_json::from_slice(b).map_err(|e| ApiError::bad(format!("invalid JSON body: {e}")))
}

fn tenants_of(s: &str) -> Vec<String> {
    serde_json::from_str(s).unwrap_or_default()
}

/// The TLS connection kind and remote address of a request.
pub struct PeerConn {
    pub conn: Option<ReplConn>,
    pub ip: Option<SocketAddr>,
}

impl<S: Send + Sync> FromRequestParts<S> for PeerConn {
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(parts: &mut axum::http::request::Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(PeerConn {
            conn: parts.extensions.get::<ReplConn>().cloned(),
            ip: parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|c| c.0),
        })
    }
}

/// The enrolled, non-revoked peer of this connection's client certificate.
fn peer_auth(st: &St, pc: &PeerConn) -> ApiResult<Peer> {
    let ip = pc.ip;
    let Some(ReplConn::Peer { fp }) = pc.conn.as_ref() else {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "replication requests need a replication client certificate".into(),
        ));
    };
    let row = st
        .cat
        .conn()
        .query_row(
            "SELECT id, name, tenants FROM replication_peers WHERE cert_sha256 = ?1 AND state = 'enrolled'",
            [fp],
            |r| {
                Ok(Peer {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    tenants: tenants_of(&r.get::<_, String>(2)?),
                })
            },
        )
        .optional()?;
    match row {
        Some(p) => Ok(p),
        None => {
            let now = catalog::now();
            let log = {
                let mut d = st.repl.denied.lock().unwrap();
                let last = d.insert(fp.clone(), now);
                d.retain(|_, t| now - *t < 3600);
                last.is_none_or(|t| now - t >= 60)
            };
            if log {
                st.audit(
                    "replication",
                    "replication.denied",
                    &format!("cert/{fp}"),
                    json!({"reason": "unknown or revoked peer certificate", "remote": ip.map(|a| a.ip().to_string())}),
                )?;
            }
            Err(ApiError(
                StatusCode::FORBIDDEN,
                "unknown or revoked replication peer".into(),
            ))
        }
    }
}

fn in_scope(p: &Peer, tenant: &str) -> ApiResult<()> {
    if p.tenants.iter().any(|t| t == tenant) {
        Ok(())
    } else {
        Err(ApiError(
            StatusCode::FORBIDDEN,
            format!("tenant {tenant} is not replicated to this peer"),
        ))
    }
}

/// A concurrency slot of a peer, released on drop (also when a stream ends).
struct Slot {
    st: St,
    peer: String,
}

impl Slot {
    fn take(st: &St, peer: &str) -> ApiResult<Slot> {
        let mut a = st.repl.active.lock().unwrap();
        let n = a.entry(peer.to_owned()).or_default();
        if *n >= MAX_CONCURRENT {
            return Err(ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                format!("at most {MAX_CONCURRENT} concurrent requests per peer"),
            ));
        }
        *n += 1;
        Ok(Slot {
            st: st.clone(),
            peer: peer.to_owned(),
        })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        if let Some(n) = self.st.repl.active.lock().unwrap().get_mut(&self.peer) {
            *n = n.saturating_sub(1);
        }
    }
}

/// Counts streamed bytes for the peer and holds its slot until the body ends.
struct Counting<R> {
    inner: R,
    served: Arc<AtomicU64>,
    _slot: Option<Slot>,
}

impl<R: AsyncRead + Unpin> AsyncRead for Counting<R> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = buf.filled().len() - before;
        self.served.fetch_add(n as u64, Ordering::Relaxed);
        r
    }
}

fn unavailable() -> ApiError {
    ApiError(
        StatusCode::SERVICE_UNAVAILABLE,
        "replication service (nexus-replicad) unavailable".into(),
    )
}

/// Sends one request to replicad; returns its header and the body reader.
async fn replicad(st: &St, req: &Request) -> ApiResult<(Header, BufReader<tokio::net::UnixStream>)> {
    let sock = st.repl.paths.socket.as_ref().ok_or_else(unavailable)?;
    let mut s = tokio::net::UnixStream::connect(sock).await.map_err(|e| {
        eprintln!("<4>web-api: replicad socket {}: {e}", sock.display());
        unavailable()
    })?;
    let mut line = serde_json::to_vec(req).map_err(|e| ApiError::from(anyhow::Error::from(e)))?;
    line.push(b'\n');
    s.write_all(&line).await.map_err(|_| unavailable())?;
    let mut r = BufReader::new(s);
    let mut head = String::new();
    (&mut r)
        .take(64 << 10)
        .read_line(&mut head)
        .await
        .map_err(|_| unavailable())?;
    let h: Header = serde_json::from_str(&head).map_err(|_| unavailable())?;
    Ok((h, r))
}

fn status_error(h: Header) -> ApiError {
    ApiError(
        StatusCode::from_u16(h.status).unwrap_or(StatusCode::BAD_GATEWAY),
        h.error.unwrap_or_else(|| "replication request failed".into()),
    )
}

/// Forwards a data request and streams replicad's answer (sealed bytes / JSON).
async fn forward(st: &St, peer: &Peer, req: Request, ctype: &'static str) -> ApiResult<Response> {
    let slot = Slot::take(st, &peer.id)?;
    let (h, r) = replicad(st, &req).await?;
    if h.status != 200 {
        return Err(status_error(h));
    }
    let body = Counting {
        inner: r,
        served: st.repl.counter(&peer.id),
        _slot: Some(slot),
    };
    let mut res = Body::from_stream(tokio_util::io::ReaderStream::with_capacity(body, 256 << 10)).into_response();
    res.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(ctype));
    Ok(res)
}

pub async fn peer_info(State(st): State<St>, pc: PeerConn) -> ApiResult<Json<Value>> {
    let p = peer_auth(&st, &pc)?;
    let exports: Value = st.cat.conn().query_row(
        "SELECT key_exports FROM replication_peers WHERE id = ?1",
        [&p.id],
        |r| Ok(serde_json::from_str(&r.get::<_, String>(0)?).unwrap_or(Value::Null)),
    )?;
    let keys: serde_json::Map<String, Value> = exports
        .as_object()
        .map(|o| o.iter().map(|(t, e)| (t.clone(), e["versions"].clone())).collect())
        .unwrap_or_default();
    Ok(Json(
        json!({"peer_id": p.id, "name": p.name, "tenants": p.tenants, "keys": keys}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionReq {
    tenant: String,
}

pub async fn session_start(State(st): State<St>, pc: PeerConn, J(r): J<SessionReq>) -> ApiResult<Json<Value>> {
    let remote = pc.ip;
    let p = peer_auth(&st, &pc)?;
    in_scope(&p, &r.tenant)?;
    let id = crate::random_hex()[..32].to_owned();
    let now = catalog::now();
    {
        let mut s = st.repl.sessions.lock().unwrap();
        s.retain(|_, x| now - x.start < 7 * 86400);
        if s.len() > 1000 {
            return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "too many open sessions".into()));
        }
        s.insert(
            id.clone(),
            Session {
                peer: p.id.clone(),
                tenant: r.tenant.clone(),
                start: now,
                served_at_start: st.repl.counter(&p.id).load(Ordering::Relaxed),
            },
        );
    }
    st.cat.conn().execute(
        "UPDATE replication_peers SET last_seen = ?2 WHERE id = ?1",
        params![p.id, now],
    )?;
    st.audit(
        &format!("peer:{}", p.name),
        "replication.session_start",
        &format!("replication-peer/{}", p.id),
        json!({"tenant": r.tenant, "session": id, "remote": remote.map(|a| a.ip().to_string())}),
    )?;
    Ok(Json(json!({"session": id})))
}

pub async fn session_end(
    State(st): State<St>,
    pc: PeerConn,
    Path(id): Path<String>,
    J(r): J<SessionEnd>,
) -> ApiResult<Json<Value>> {
    let p = peer_auth(&st, &pc)?;
    let s = {
        let mut m = st.repl.sessions.lock().unwrap();
        match m.get(&id) {
            Some(s) if s.peer == p.id => m.remove(&id).unwrap(),
            _ => return Err(ApiError::not_found()),
        }
    };
    let served = st.repl.counter(&p.id).load(Ordering::Relaxed) - s.served_at_start;
    let now = catalog::now();
    st.cat.conn().execute(
        "UPDATE replication_peers SET last_seen = ?2 WHERE id = ?1",
        params![p.id, now],
    )?;
    let error = r.error.map(|e| e.chars().take(500).collect::<String>());
    st.audit(
        &format!("peer:{}", p.name),
        "replication.session_end",
        &format!("replication-peer/{}", p.id),
        json!({"tenant": s.tenant, "session": id, "secs": now - s.start, "bytes_served": served,
               "reported": {"snapshots": r.snapshots, "chunks": r.chunks, "bytes": r.bytes, "error": error}}),
    )?;
    Ok(Json(json!({"ok": true})))
}

pub async fn tenant_keys(State(st): State<St>, pc: PeerConn, Path(tenant): Path<String>) -> ApiResult<Json<KeyExport>> {
    let p = peer_auth(&st, &pc)?;
    in_scope(&p, &tenant)?;
    let exports: Value = st.cat.conn().query_row(
        "SELECT key_exports FROM replication_peers WHERE id = ?1",
        [&p.id],
        |r| Ok(serde_json::from_str(&r.get::<_, String>(0)?).unwrap_or(Value::Null)),
    )?;
    let e = &exports[&tenant];
    let (Some(blob), Some(versions)) = (e["blob"].as_str(), e["versions"].as_array()) else {
        return Err(ApiError(
            StatusCode::NOT_FOUND,
            format!("no key export for tenant {tenant}: approve the key export request on the primary"),
        ));
    };
    Ok(Json(KeyExport {
        tenant,
        versions: versions.iter().filter_map(|v| v.as_u64().map(|v| v as u32)).collect(),
        blob: blob.to_owned(),
    }))
}

pub async fn list_remote_snapshots(
    State(st): State<St>,
    pc: PeerConn,
    Path(tenant): Path<String>,
) -> ApiResult<Response> {
    let p = peer_auth(&st, &pc)?;
    in_scope(&p, &tenant)?;
    let scope = p.tenants.clone();
    forward(&st, &p, Request::List { scope, tenant }, "application/json").await
}

/// The tenant's active legal holds (Phase 15c): advisory for the secondary.
pub async fn remote_holds(
    State(st): State<St>,
    pc: PeerConn,
    Path(tenant): Path<String>,
) -> ApiResult<Json<Vec<repl_proto::HoldInfo>>> {
    let p = peer_auth(&st, &pc)?;
    in_scope(&p, &tenant)?;
    Ok(Json(crate::holds::active_infos(&st.cat.conn(), &tenant)?))
}

pub async fn snapshot_file(
    State(st): State<St>,
    pc: PeerConn,
    Path((tenant, source, time, file)): Path<(String, String, u64, String)>,
) -> ApiResult<Response> {
    let p = peer_auth(&st, &pc)?;
    in_scope(&p, &tenant)?;
    let req = Request::File {
        scope: p.tenants.clone(),
        tenant,
        source,
        time,
        file,
    };
    req.check().map_err(ApiError::bad)?;
    forward(&st, &p, req, "application/octet-stream").await
}

pub async fn chunks(
    State(st): State<St>,
    pc: PeerConn,
    Path(tenant): Path<String>,
    body: Bytes,
) -> ApiResult<Response> {
    let p = peer_auth(&st, &pc)?;
    in_scope(&p, &tenant)?;
    if body.len() > MAX_BODY {
        return Err(ApiError(StatusCode::PAYLOAD_TOO_LARGE, "request too large".into()));
    }
    let ids = parse_ids(&body).map_err(ApiError::bad)?;
    let scope = p.tenants.clone();
    forward(
        &st,
        &p,
        Request::Chunks { scope, tenant, ids },
        "application/octet-stream",
    )
    .await
}

/// `POST /replication/v1/enroll` (enrollment ALPN only, docs §4).
pub async fn enroll(State(st): State<St>, pc: PeerConn, J(r): J<EnrollRequest>) -> ApiResult<Json<EnrollResponse>> {
    let Some(ReplConn::Enroll { exporter }) = pc.conn.as_ref() else {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "enrollment needs the replication enrollment protocol (ALPN)".into(),
        ));
    };
    let remote = pc.ip.map(|a| a.ip().to_string());
    let refused = || ApiError(StatusCode::FORBIDDEN, "enrollment refused".into());
    if !valid_peer_id(&r.peer_id) || !valid_hex64(&r.keyd_pub) || !valid_hex64(&r.proof) || r.csr_pem.len() > 16 << 10 {
        return Err(ApiError::bad("invalid enrollment request"));
    }
    type Row = (String, String, String, Option<String>, Option<i64>, String);
    let row: Option<Row> = st
        .cat
        .conn()
        .query_row(
            "SELECT name, tenants, state, token_hash, token_expires, created_by FROM replication_peers WHERE id = ?1",
            [&r.peer_id],
            |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?, x.get(3)?, x.get(4)?, x.get(5)?)),
        )
        .optional()?;
    let Some((name, tenants, state, Some(token), Some(expires), created_by)) = row else {
        return Err(refused());
    };
    if state != "approved" || expires <= catalog::now() {
        return Err(refused());
    }
    let req = Request::Enroll {
        peer_id: r.peer_id.clone(),
        token_sealed: token,
        exporter: hex(exporter),
        proof: r.proof.clone(),
        csr_pem: r.csr_pem.clone(),
    };
    let (h, mut body) = replicad(&st, &req).await?;
    if h.status == 403 {
        let voided = {
            let c = st.cat.conn();
            c.execute(
                "UPDATE replication_peers SET enroll_failures = enroll_failures + 1 WHERE id = ?1",
                [&r.peer_id],
            )?;
            c.execute(
                "UPDATE replication_peers SET token_hash = NULL, token_expires = NULL WHERE id = ?1 AND enroll_failures >= ?2",
                params![r.peer_id, MAX_ENROLL_FAILURES],
            )? > 0
        };
        st.audit(
            "replication",
            "replication_peer.enroll_failed",
            &format!("replication-peer/{}", r.peer_id),
            json!({"reason": h.error, "remote": remote, "token_voided": voided}),
        )?;
        return Err(refused());
    }
    if h.status != 200 {
        return Err(status_error(h));
    }
    let mut b = Vec::new();
    (&mut body)
        .take(256 << 10)
        .read_to_end(&mut b)
        .await
        .map_err(|_| unavailable())?;
    let out: EnrollOutcome = serde_json::from_slice(&b).map_err(|_| unavailable())?;
    if !valid_hex64(&out.proof) || !valid_hex64(&out.cert_sha256) {
        return Err(unavailable());
    }
    let now = catalog::now();
    let n = st.cat.conn().execute(
        "UPDATE replication_peers SET state = 'enrolled', cert_sha256 = ?2, keyd_pub = ?3, token_hash = NULL,
         token_expires = NULL, enrolled_at = ?4, last_seen = ?4 WHERE id = ?1 AND state = 'approved' AND token_hash IS NOT NULL",
        params![r.peer_id, out.cert_sha256, r.keyd_pub, now],
    )?;
    if n != 1 {
        return Err(refused());
    }
    let keyd_pub = unhex(&r.keyd_pub).unwrap_or_default();
    st.audit(
        "replication",
        "replication_peer.enrolled",
        &format!("replication-peer/{}", r.peer_id),
        json!({"name": name, "secondary": r.name.chars().take(64).collect::<String>(), "cert_sha256": out.cert_sha256,
               "keyd_fingerprint": key_fingerprint(&keyd_pub), "remote": remote}),
    )?;
    let tenants = tenants_of(&tenants);
    // the DEKs follow only after a second approval that names the keyd key (docs §5)
    request_as(
        &st,
        &created_by,
        "replication.key_export",
        &format!("replication-peer/{}", r.peer_id),
        json!({"peer_id": r.peer_id, "name": name, "tenants": tenants, "keyd_pub": r.keyd_pub,
               "keyd_fingerprint": key_fingerprint(&keyd_pub)}),
    )?;
    Ok(Json(EnrollResponse {
        proof: out.proof,
        cert_pem: out.cert_pem,
        ca_pem: out.ca_pem,
        tenants,
    }))
}

// ================================================================ management: peers (primary)

const PEER_COLS: &str = "id, name, tenants, state, cert_sha256, keyd_pub, token_expires, enrolled_at, last_seen, \
                         revoked, created, created_by, key_exports, enroll_failures";

fn peer_row(r: &catalog::rusqlite::Row) -> catalog::rusqlite::Result<Value> {
    let keyd: Option<String> = r.get(5)?;
    let exports: Value = serde_json::from_str(&r.get::<_, String>(12)?).unwrap_or(Value::Null);
    let keys: serde_json::Map<String, Value> = exports
        .as_object()
        .map(|o| {
            o.iter()
                .map(|(t, e)| (t.clone(), json!({"versions": e["versions"], "created": e["created"]})))
                .collect()
        })
        .unwrap_or_default();
    Ok(json!({
        "id": r.get::<_, String>(0)?, "name": r.get::<_, String>(1)?,
        "tenants": tenants_of(&r.get::<_, String>(2)?), "state": r.get::<_, String>(3)?,
        "cert_sha256": r.get::<_, Option<String>>(4)?,
        "keyd_fingerprint": keyd.as_deref().and_then(unhex).map(|k| key_fingerprint(&k)),
        "token_expires": r.get::<_, Option<i64>>(6)?, "enrolled_at": r.get::<_, Option<i64>>(7)?,
        "last_seen": r.get::<_, Option<i64>>(8)?, "revoked": r.get::<_, Option<i64>>(9)?,
        "created": r.get::<_, i64>(10)?, "created_by": r.get::<_, String>(11)?, "keys": keys,
        "enroll_failures": r.get::<_, i64>(13)?,
    }))
}

fn peer_value(c: &Connection, id: &str) -> ApiResult<Option<Value>> {
    Ok(c.query_row(
        &format!("SELECT {PEER_COLS} FROM replication_peers WHERE id = ?1"),
        [id],
        peer_row,
    )
    .optional()?)
}

pub async fn list_peers(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(READ)?;
    if ctx.scope().is_some() {
        return Ok(Json(json!([])));
    }
    let c = st.cat.conn();
    let rows = c
        .prepare(&format!("SELECT {PEER_COLS} FROM replication_peers ORDER BY name"))?
        .query_map([], peer_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Value::Array(rows)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerReq {
    name: String,
    tenants: Vec<String>,
}

fn check_tenants(c: &Connection, tenants: &[String]) -> ApiResult<()> {
    if tenants.is_empty() || tenants.len() > 64 {
        return Err(ApiError::bad("tenants: 1..=64 tenant names"));
    }
    let mut seen = std::collections::HashSet::new();
    for t in tenants {
        validate::name(t, "tenants")?;
        if !seen.insert(t) {
            return Err(ApiError::bad("tenants: duplicate"));
        }
        if c.query_row("SELECT 1 FROM tenants WHERE name = ?1", [t], |_| Ok(()))
            .optional()?
            .is_none()
        {
            return Err(ApiError::bad(format!("tenants: {t} does not exist")));
        }
    }
    Ok(())
}

fn replicad_seal_key(st: &St) -> ApiResult<SealKey> {
    let p = st.repl.paths.seal_pub.as_ref().ok_or_else(unavailable)?;
    SealKey::load(p).map_err(|e| {
        eprintln!("<4>web-api: {e:#}");
        unavailable()
    })
}

/// Creates a pending peer with a one-time code (shown once) and requests the
/// quorum approval that makes the code usable.
pub async fn create_peer(State(st): State<St>, ctx: Ctx, J(r): J<PeerReq>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    crate::vault::refuse(&st.cat.conn(), "replication peers (serving as a primary)")?;
    validate::name(&r.name, "name")?;
    check_tenants(&st.cat.conn(), &r.tenants)?;
    let pk = replicad_seal_key(&st)?;
    let id = hex(&rand::random::<[u8; 8]>());
    let token = crate::agents::new_token();
    let sealed = pk.seal(&replication_peer_token_location(&id), &token_digest(&token))?;
    let peer = {
        let c = st.cat.conn();
        c.execute(
            "INSERT INTO replication_peers (id, name, tenants, state, token_hash, created, created_by)
             VALUES (?1, ?2, ?3, 'pending', ?4, ?5, ?6)",
            params![
                id,
                r.name,
                json!(r.tenants).to_string(),
                sealed,
                catalog::now(),
                ctx.name()
            ],
        )?;
        peer_value(&c, &id)?.ok_or_else(ApiError::not_found)?
    };
    st.audit(
        ctx.name(),
        "replication_peer.create",
        &format!("replication-peer/{id}"),
        json!({"name": r.name, "tenants": r.tenants}),
    )?;
    let q = request(
        &st,
        &ctx,
        "replication_peer.create",
        &format!("replication-peer/{id}"),
        json!({"id": id, "name": r.name, "tenants": r.tenants}),
    )?;
    // approvals disabled: already approved
    let peer = peer_value(&st.cat.conn(), &id)?.unwrap_or(peer);
    let primary_cert_sha256 = st.repl.paths.tls_cert.as_deref().and_then(|p| cert_fingerprint(p).ok());
    Ok(accepted(
        q,
        json!({"peer": peer, "code": format!("{id}.{token}"), "primary_cert_sha256": primary_cert_sha256}),
    ))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ExportReq {
    tenants: Option<Vec<String>>,
}

/// Requests a (re-)export of the peer's tenant DEKs (quorum; the scheduler executes it).
pub async fn export_keys(State(st): State<St>, ctx: Ctx, Path(id): Path<String>, body: Bytes) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let r: ExportReq = optional_json(&body)?;
    let (name, scope, state, keyd) = st
        .cat
        .conn()
        .query_row(
            "SELECT name, tenants, state, keyd_pub FROM replication_peers WHERE id = ?1",
            [&id],
            |x| {
                Ok((
                    x.get::<_, String>(0)?,
                    x.get::<_, String>(1)?,
                    x.get::<_, String>(2)?,
                    x.get::<_, Option<String>>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(ApiError::not_found)?;
    let (Some(keyd), "enrolled") = (keyd, state.as_str()) else {
        return Err(ApiError::conflict("the peer is not enrolled"));
    };
    let scope = tenants_of(&scope);
    let tenants = r.tenants.unwrap_or_else(|| scope.clone());
    if tenants.is_empty() || tenants.iter().any(|t| !scope.contains(t)) {
        return Err(ApiError::bad("tenants: must be tenants of the peer"));
    }
    let q = request(
        &st,
        &ctx,
        "replication.key_export",
        &format!("replication-peer/{id}"),
        json!({"peer_id": id, "name": name, "tenants": tenants, "keyd_pub": keyd,
               "keyd_fingerprint": unhex(&keyd).map(|k| key_fingerprint(&k))}),
    )?;
    Ok(accepted(q, json!({})))
}

/// Revocation (quorum); a peer that was never approved is removed directly.
pub async fn delete_peer(State(st): State<St>, ctx: Ctx, Path(id): Path<String>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let p = peer_value(&st.cat.conn(), &id)?.ok_or_else(ApiError::not_found)?;
    match p["state"].as_str() {
        Some("revoked") => Err(ApiError::conflict("the peer is already revoked")),
        Some("pending") => {
            st.cat.conn().execute(
                "UPDATE replication_peers SET state = 'revoked', revoked = ?2, token_hash = NULL, token_expires = NULL
                 WHERE id = ?1 AND state = 'pending'",
                params![id, catalog::now()],
            )?;
            st.audit(
                ctx.name(),
                "replication_peer.delete",
                &format!("replication-peer/{id}"),
                json!({"name": p["name"], "state": "pending"}),
            )?;
            Ok((StatusCode::OK, Json(json!({"id": id, "state": "revoked"}))).into_response())
        }
        _ => {
            let q = request(
                &st,
                &ctx,
                "replication_peer.delete",
                &format!("replication-peer/{id}"),
                json!({"id": id, "name": p["name"], "tenants": p["tenants"], "cert_sha256": p["cert_sha256"]}),
            )?;
            Ok(accepted(q, json!({})))
        }
    }
}

/// Quorum execution (inside the approval transaction).
pub fn execute(c: &Connection, action: &str, p: &Value) -> ApiResult<bool> {
    let changed = |n: usize| {
        if n == 1 {
            Ok(())
        } else {
            Err(ApiError::conflict("the object no longer exists or changed state"))
        }
    };
    match action {
        "replication_peer.create" => changed(c.execute(
            "UPDATE replication_peers SET state = 'approved', token_expires = ?2 WHERE id = ?1 AND state = 'pending'",
            params![p["id"].as_str(), catalog::now() + TOKEN_TTL_SECS],
        )?)?,
        "replication_peer.delete" => changed(c.execute(
            "UPDATE replication_peers SET state = 'revoked', revoked = ?2, token_hash = NULL, token_expires = NULL,
             key_exports = '{}' WHERE id = ?1 AND state != 'revoked'",
            params![p["id"].as_str(), catalog::now()],
        )?)?,
        "replication_source.delete" => {
            changed(c.execute("DELETE FROM replication_sources WHERE id = ?1", [p["id"].as_i64()])?)?
        }
        "replication_source.update" => {
            let cur = source_value(c, p["id"].as_i64().unwrap_or_default())?;
            if cur.as_ref().map(settings) != Some(settings(&p["old"])) {
                return Err(ApiError::conflict(
                    "the replication source changed since this request was made; reject it and request again",
                ));
            }
            let s = settings(p); // requests made before Phase 17a carry no windows: defaults
            changed(c.execute(
                "UPDATE replication_sources SET schedule = ?2, gfs = ?3, bwlimit = ?4, windows = ?5, sync_window = ?6, \
                 timezone = ?7 WHERE id = ?1",
                params![
                    p["id"].as_i64(),
                    p["schedule"].as_str(),
                    p["gfs"].to_string(),
                    p["bwlimit"].as_u64(),
                    s["windows"].to_string(),
                    s["sync_window"].to_string(),
                    s["timezone"].as_str()
                ],
            )?)?
        }
        REOPEN => changed(c.execute(
            "UPDATE replication_sources SET closed_until = NULL, closed_by = NULL, closed_at = NULL \
             WHERE id = ?1 AND closed_until IS NOT NULL",
            [p["id"].as_i64()],
        )?)?,
        _ => return Ok(false),
    }
    Ok(true)
}

fn settings(v: &Value) -> Value {
    let or = |k: &str, d: Value| v.get(k).filter(|x| !x.is_null()).cloned().unwrap_or(d);
    json!({"schedule": v["schedule"], "gfs": v["gfs"], "bwlimit": v["bwlimit"], "windows": or("windows", json!([])),
           "sync_window": or("sync_window", json!([])), "timezone": or("timezone", json!("UTC"))})
}

/// Quorum action: reopening a closed replication source (Phase 17b).
pub const REOPEN: &str = "replication.reopen";

// ================================================================ management: sources (secondary)

const SOURCE_COLS: &str =
    "id, name, url, peer_id, cert_pin, tenants, schedule, gfs, bwlimit, state, cert_sha256, keyd_pub, created, last_sync, status, \
     windows, sync_window, timezone, closed_until, closed_by, closed_at";

fn source_row(r: &catalog::rusqlite::Row) -> catalog::rusqlite::Result<Value> {
    let keyd: Option<String> = r.get(11)?;
    Ok(json!({
        "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?, "url": r.get::<_, String>(2)?,
        "peer_id": r.get::<_, String>(3)?, "cert_pin": r.get::<_, String>(4)?,
        "tenants": tenants_of(&r.get::<_, String>(5)?), "schedule": r.get::<_, String>(6)?,
        "gfs": serde_json::from_str::<Value>(&r.get::<_, String>(7)?).unwrap_or(Value::Null),
        "bwlimit": r.get::<_, Option<i64>>(8)?, "state": r.get::<_, String>(9)?,
        "cert_sha256": r.get::<_, Option<String>>(10)?,
        "keyd_fingerprint": keyd.as_deref().and_then(unhex).map(|k| key_fingerprint(&k)),
        "created": r.get::<_, i64>(12)?, "last_sync": r.get::<_, Option<i64>>(13)?,
        "status": serde_json::from_str::<Value>(&r.get::<_, String>(14)?).unwrap_or(Value::Null),
        "windows": serde_json::from_str::<Value>(&r.get::<_, String>(15)?).unwrap_or(json!([])),
        "sync_window": serde_json::from_str::<Value>(&r.get::<_, String>(16)?).unwrap_or(json!([])),
        "timezone": r.get::<_, String>(17)?, "closed_until": r.get::<_, Option<i64>>(18)?,
        "closed_by": r.get::<_, Option<String>>(19)?, "closed_at": r.get::<_, Option<i64>>(20)?,
    }))
}

/// Closed by "close vault now" right now (`closed_until` -1 = until reopened).
fn is_closed(s: &Value) -> bool {
    schedule::paused(s["closed_until"].as_i64(), catalog::now())
}

/// Stored windows of a source row (as validated when they were set).
fn bandwidth_of(s: &Value) -> Bandwidth {
    Bandwidth {
        base: s["bwlimit"].as_u64(),
        windows: serde_json::from_value(s["windows"].clone()).unwrap_or_default(),
        tz: schedule::tz(s["timezone"].as_str().unwrap_or("UTC")).unwrap_or(schedule::Tz::UTC),
    }
}

fn sync_window_of(s: &Value) -> Vec<Span> {
    serde_json::from_value(s["sync_window"].clone()).unwrap_or_default()
}

pub fn source_value(c: &Connection, id: i64) -> ApiResult<Option<Value>> {
    Ok(c.query_row(
        &format!("SELECT {SOURCE_COLS} FROM replication_sources WHERE id = ?1"),
        [id],
        source_row,
    )
    .optional()?)
}

pub async fn list_sources(State(st): State<St>, ctx: Ctx) -> ApiResult<Json<Value>> {
    ctx.require(READ)?;
    if ctx.scope().is_some() {
        return Ok(Json(json!([])));
    }
    let c = st.cat.conn();
    let rows = c
        .prepare(&format!("SELECT {SOURCE_COLS} FROM replication_sources ORDER BY name"))?
        .query_map([], source_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Value::Array(rows)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceReq {
    name: String,
    /// primary `host[:port]` (8443 by default)
    url: String,
    /// enrollment code from the primary (`<peer-id>.<token>`)
    code: String,
    /// SHA-256 of the primary's TLS certificate (hex, colons allowed)
    fingerprint: String,
    tenants: Vec<String>,
    schedule: String,
    gfs: Option<validate::Gfs>,
    bwlimit: Option<u64>,
    #[serde(default)]
    windows: Vec<RateWindow>,
    #[serde(default)]
    sync_window: Vec<Span>,
    timezone: Option<String>,
}

/// `host:port` with the port defaulting to 8443.
pub fn normalize_url(u: &str) -> ApiResult<String> {
    let u = u.trim().trim_start_matches("https://").trim_end_matches('/');
    let (host, port) = if let Some(rest) = u.strip_prefix('[') {
        let (h, p) = rest
            .split_once(']')
            .ok_or_else(|| ApiError::bad("url: invalid IPv6 address"))?;
        (h, p.strip_prefix(':'))
    } else {
        match u.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (h, Some(p)),
            Some(_) => return Err(ApiError::bad("url: put IPv6 addresses in brackets")),
            None => (u, None),
        }
    };
    validate::host(host).map_err(|_| ApiError::bad("url: invalid host"))?;
    let port: u16 = match port {
        Some(p) => p
            .parse()
            .ok()
            .filter(|p| *p > 0)
            .ok_or_else(|| ApiError::bad("url: invalid port"))?,
        None => 8443,
    };
    Ok(if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    })
}

pub fn normalize_fingerprint(f: &str) -> ApiResult<String> {
    let f: String = f
        .chars()
        .filter(|c| !matches!(c, ':' | ' '))
        .collect::<String>()
        .to_ascii_lowercase();
    if valid_hex64(&f) {
        Ok(f)
    } else {
        Err(ApiError::bad(
            "fingerprint: SHA-256 of the primary's certificate (64 hex characters)",
        ))
    }
}

fn queue_job(c: &Connection, kind: &str, tenant: &str, p: &Value, by: &str) -> ApiResult<i64> {
    c.execute(
        "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES (?1, ?2, ?3, 'queued', ?4, ?5)",
        params![kind, tenant, p.to_string(), by, catalog::now()],
    )?;
    Ok(c.last_insert_rowid())
}

/// Seals the code's token digest to the scheduler, bound to source + primary.
fn seal_token(st: &St, id: i64, url: &str, peer: &str, pin: &str, token: &str) -> ApiResult<String> {
    Ok(st.seal_key()?.seal(
        &replication_source_token_location(id, url, peer, pin),
        &token_digest(token),
    )?)
}

pub async fn create_source(State(st): State<St>, ctx: Ctx, J(r): J<SourceReq>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    validate::name(&r.name, "name")?;
    let url = normalize_url(&r.url)?;
    let pin = normalize_fingerprint(&r.fingerprint)?;
    let (peer_id, token) = split_code(&r.code).ok_or_else(|| ApiError::bad("code: expected <peer-id>.<token>"))?;
    validate::schedule(&r.schedule)?;
    let gfs = r.gfs.unwrap_or(validate::Gfs {
        recent: 0,
        daily: 14,
        weekly: 4,
        monthly: 6,
        yearly: 2,
    });
    gfs.check()?;
    if r.tenants.is_empty() || r.tenants.len() > 64 {
        return Err(ApiError::bad("tenants: 1..=64 tenant names"));
    }
    validate::windows(&r.windows)?;
    validate::sync_window(&r.sync_window)?;
    let tz = r.timezone.clone().unwrap_or_else(|| "UTC".into());
    validate::timezone(&tz)?;
    st.seal_key()?; // 503 before anything is written
    let (id, job, created) = {
        let mut c = st.cat.conn();
        let tx = c.transaction()?;
        let mut created = Vec::new();
        for t in &r.tenants {
            validate::name(t, "tenants")?;
            if replicated_tenant(&tx, t)? {
                return Err(ApiError::conflict(format!(
                    "tenant {t} is already replicated from another source"
                )));
            }
            for (table, what) in [("groups", "backup groups"), ("agents", "agents")] {
                if tx
                    .query_row(&format!("SELECT 1 FROM {table} WHERE tenant = ?1"), [t], |_| Ok(()))
                    .optional()?
                    .is_some()
                {
                    return Err(ApiError::conflict(format!(
                        "tenant {t} has local {what}: replicated tenants must be exclusive"
                    )));
                }
            }
            if tx.execute("INSERT OR IGNORE INTO tenants (name) VALUES (?1)", [t])? == 1 {
                created.push(t.clone());
            }
        }
        tx.execute(
            "INSERT INTO replication_sources (name, url, peer_id, cert_pin, tenants, schedule, gfs, bwlimit, state, created,
               windows, sync_window, timezone)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'enrolling', ?9, ?10, ?11, ?12)",
            params![r.name, url, peer_id, pin, json!(r.tenants).to_string(), r.schedule, json!(gfs).to_string(),
                    r.bwlimit, catalog::now(), json!(r.windows).to_string(), json!(r.sync_window).to_string(), tz],
        )?;
        let id = tx.last_insert_rowid();
        let sealed = seal_token(&st, id, &url, peer_id, &pin, token)?;
        tx.execute(
            "UPDATE replication_sources SET token_hash = ?2 WHERE id = ?1",
            params![id, sealed],
        )?;
        let job = queue_job(
            &tx,
            "replica_enroll",
            &r.tenants[0],
            &json!({"replication_source_id": id}),
            ctx.name(),
        )?;
        tx.commit()?;
        (id, job, created)
    };
    for t in &created {
        st.audit(
            ctx.name(),
            "tenant.create",
            &format!("tenant/{t}"),
            json!({"replicated": true}),
        )?;
    }
    let out = source_value(&st.cat.conn(), id)?.ok_or_else(ApiError::not_found)?;
    st.audit(
        ctx.name(),
        "replication_source.create",
        &format!("replication-source/{id}"),
        json!({"name": r.name, "url": url, "peer_id": peer_id, "cert_pin": pin, "tenants": r.tenants,
               "schedule": r.schedule, "gfs": gfs, "bwlimit": r.bwlimit, "windows": r.windows,
               "sync_window": r.sync_window, "timezone": tz}),
    )?;
    st.audit(
        ctx.name(),
        "job.create",
        &format!("job/{job}"),
        json!({"kind": "replica_enroll", "params": {"replication_source_id": id}}),
    )?;
    Ok((StatusCode::CREATED, Json(json!({"source": out, "job": job}))).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceUpdate {
    schedule: Option<String>,
    gfs: Option<validate::Gfs>,
    bwlimit: Option<Option<u64>>,
    /// Phase 17a: bandwidth windows, sync window, their time zone
    windows: Option<Vec<RateWindow>>,
    sync_window: Option<Vec<Span>>,
    timezone: Option<String>,
}

pub async fn update_source(
    State(st): State<St>,
    ctx: Ctx,
    Path(id): Path<i64>,
    J(r): J<SourceUpdate>,
) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let old = source_value(&st.cat.conn(), id)?.ok_or_else(ApiError::not_found)?;
    let schedule = r
        .schedule
        .unwrap_or_else(|| old["schedule"].as_str().unwrap_or_default().to_owned());
    validate::schedule(&schedule)?;
    let old_gfs: validate::Gfs = serde_json::from_value(old["gfs"].clone()).unwrap_or(validate::Gfs {
        recent: 0,
        daily: 14,
        weekly: 4,
        monthly: 6,
        yearly: 2,
    });
    let gfs = r.gfs.unwrap_or(old_gfs);
    gfs.check()?;
    let bwlimit = match r.bwlimit {
        Some(b) => b,
        None => old["bwlimit"].as_u64(),
    };
    let windows = r.windows.map_or_else(|| old["windows"].clone(), |w| json!(w));
    let sync_window = r.sync_window.map_or_else(|| old["sync_window"].clone(), |s| json!(s));
    let timezone = r
        .timezone
        .unwrap_or_else(|| old["timezone"].as_str().unwrap_or("UTC").to_owned());
    validate::timezone(&timezone)?;
    let p = json!({"id": id, "schedule": schedule, "gfs": gfs, "bwlimit": bwlimit, "windows": windows,
                   "sync_window": sync_window, "timezone": timezone, "old": settings(&old)});
    let new_windows: Vec<RateWindow> =
        serde_json::from_value(windows.clone()).map_err(|e| ApiError::bad(format!("windows: {e}")))?;
    let new_sync: Vec<Span> =
        serde_json::from_value(sync_window.clone()).map_err(|e| ApiError::bad(format!("sync_window: {e}")))?;
    validate::windows(&new_windows)?;
    validate::sync_window(&new_sync)?;
    // weakening needs approval: lower GFS, more bandwidth (a pause removed or
    // shortened, a higher rate), a wider sync window; tightening applies directly
    let (old_bw, new_tz) = (bandwidth_of(&old), schedule::tz(&timezone).unwrap_or(schedule::Tz::UTC));
    let new_bw = Bandwidth {
        base: bwlimit,
        windows: new_windows,
        tz: new_tz,
    };
    let now = catalog::now();
    let weaker =
        old_bw.weaker(&new_bw, now) || schedule::sync_widened(&sync_window_of(&old), old_bw.tz, &new_sync, new_tz, now);
    if old_gfs.lowered_by(&gfs) || weaker {
        let q = request(
            &st,
            &ctx,
            "replication_source.update",
            &format!("replication-source/{id}"),
            p,
        )?;
        return Ok(accepted(q, json!({})));
    }
    execute(&st.cat.conn(), "replication_source.update", &p)?;
    st.audit(
        ctx.name(),
        "replication_source.update",
        &format!("replication-source/{id}"),
        json!({"schedule": schedule, "gfs": gfs, "bwlimit": bwlimit, "windows": windows,
               "sync_window": sync_window, "timezone": timezone}),
    )?;
    let out = source_value(&st.cat.conn(), id)?.ok_or_else(ApiError::not_found)?;
    Ok(Json(out).into_response())
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EnrollAgain {
    code: Option<String>,
}

/// Retries the enrollment (a consumed code needs a new one from the primary).
pub async fn enroll_source(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>, body: Bytes) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let r: EnrollAgain = optional_json(&body)?;
    let s = source_value(&st.cat.conn(), id)?.ok_or_else(ApiError::not_found)?;
    let (url, pin) = (
        s["url"].as_str().unwrap_or_default(),
        s["cert_pin"].as_str().unwrap_or_default(),
    );
    let tenants: Vec<String> = serde_json::from_value(s["tenants"].clone()).unwrap_or_default();
    let job = {
        let mut c = st.cat.conn();
        let tx = c.transaction()?;
        if let Some(code) = &r.code {
            let (peer_id, token) = split_code(code).ok_or_else(|| ApiError::bad("code: expected <peer-id>.<token>"))?;
            let sealed = seal_token(&st, id, url, peer_id, pin, token)?;
            tx.execute(
                "UPDATE replication_sources SET peer_id = ?2, token_hash = ?3, state = 'enrolling' WHERE id = ?1",
                params![id, peer_id, sealed],
            )?;
        } else if tx.query_row(
            "SELECT token_hash IS NULL FROM replication_sources WHERE id = ?1",
            [id],
            |x| x.get::<_, bool>(0),
        )? {
            return Err(ApiError::conflict(
                "the enrollment code was used: ask the primary for a new one and pass it as `code`",
            ));
        }
        let job = queue_job(
            &tx,
            "replica_enroll",
            tenants.first().map(String::as_str).unwrap_or("-"),
            &json!({"replication_source_id": id}),
            ctx.name(),
        )?;
        tx.commit()?;
        job
    };
    st.audit(
        ctx.name(),
        "job.create",
        &format!("job/{job}"),
        json!({"kind": "replica_enroll", "params": {"replication_source_id": id}, "new_code": r.code.is_some()}),
    )?;
    Ok((StatusCode::ACCEPTED, Json(json!({"id": job}))).into_response())
}

/// Queues a `replica_sync` per tenant (unless one is queued/running).
pub async fn sync_source(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Response> {
    ctx.require(&["admin", "operator"])?;
    if ctx.scope().is_some() {
        return Err(ApiError::forbidden());
    }
    let s = source_value(&st.cat.conn(), id)?.ok_or_else(ApiError::not_found)?;
    if s["state"] != "enrolled" {
        return Err(ApiError::conflict("the replication source is not enrolled yet"));
    }
    if is_closed(&s) {
        return Err(ApiError::conflict(
            "the replication source is closed (pulling paused): request reopening first",
        ));
    }
    if !schedule::sync_open(&sync_window_of(&s), bandwidth_of(&s).tz, catalog::now()) {
        return Err(ApiError::conflict(
            "outside the sync window: the primary is not reachable now",
        ));
    }
    let tenants: Vec<String> = serde_json::from_value(s["tenants"].clone()).unwrap_or_default();
    let mut jobs = Vec::new();
    for t in &tenants {
        let p = json!({"replication_source_id": id, "tenant": t});
        let busy: i64 = st.cat.conn().query_row(
            "SELECT COUNT(*) FROM jobs WHERE kind = 'replica_sync' AND tenant = ?1 AND state IN ('queued','running')
             AND json_extract(params, '$.replication_source_id') = ?2",
            params![t, id],
            |x| x.get(0),
        )?;
        // a deactivated tenant syncs no more (Phase 17f)
        if busy > 0 || catalog::tenants::disabled(&st.cat.conn(), t)? {
            continue;
        }
        let j = queue_job(&st.cat.conn(), "replica_sync", t, &p, ctx.name())?;
        st.audit(
            ctx.name(),
            "job.create",
            &format!("job/{j}"),
            json!({"kind": "replica_sync", "tenant": t, "params": p}),
        )?;
        jobs.push(j);
    }
    Ok((StatusCode::ACCEPTED, Json(json!({"jobs": jobs}))).into_response())
}

pub async fn delete_source(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Response> {
    ctx.require(ADMIN)?;
    let s = source_value(&st.cat.conn(), id)?.ok_or_else(ApiError::not_found)?;
    if s["state"] != "enrolled" {
        st.cat
            .conn()
            .execute("DELETE FROM replication_sources WHERE id = ?1", [id])?;
        st.audit(
            ctx.name(),
            "replication_source.delete",
            &format!("replication-source/{id}"),
            json!({"name": s["name"], "state": s["state"]}),
        )?;
        return Ok((StatusCode::OK, Json(json!({"id": id}))).into_response());
    }
    let q = request(
        &st,
        &ctx,
        "replication_source.delete",
        &format!("replication-source/{id}"),
        json!({"id": id, "name": s["name"], "url": s["url"], "tenants": s["tenants"]}),
    )?;
    Ok(accepted(q, json!({})))
}

// ================================================================ close vault (Phase 17b)

/// Who may close a vault and request reopening it (approved by another approver).
const CLOSERS: &[&str] = &["admin", "security_officer"];

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CloseReq {
    /// unix time; absent = until reopened
    until: Option<i64>,
}

/// "Close vault now": no syncs and no firewall target from the next scheduler
/// tick; queued syncs are cancelled and running ones get a cancel request here
/// already. Never needs approval (it only adds protection) but can never
/// shorten an existing closure.
pub async fn close_source(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>, body: Bytes) -> ApiResult<Response> {
    ctx.require(CLOSERS)?;
    if ctx.scope().is_some() {
        return Err(ApiError::forbidden());
    }
    let r: CloseReq = optional_json(&body)?;
    let now = catalog::now();
    let until = match r.until {
        None => -1,
        Some(u) if u > now => u,
        Some(_) => return Err(ApiError::bad("until: must be in the future")),
    };
    let s = source_value(&st.cat.conn(), id)?.ok_or_else(ApiError::not_found)?;
    if let Some(cur) = s["closed_until"].as_i64().filter(|_| is_closed(&s)) {
        if cur == -1 || (until != -1 && until <= cur) {
            return Err(ApiError::conflict(
                "the vault is already closed at least that long; reopening needs approval",
            ));
        }
    }
    let cancelled = {
        let mut c = st.cat.conn();
        let tx = c.transaction()?;
        tx.execute(
            "UPDATE replication_sources SET closed_until = ?2, closed_by = ?3, closed_at = ?4 WHERE id = ?1",
            params![id, until, ctx.name(), now],
        )?;
        let q = tx.execute(
            "UPDATE jobs SET state = 'cancelled', finished = ?2, log = log || '[web-api] cancelled: vault closed\n' \
             WHERE kind = 'replica_sync' AND state = 'queued' AND json_extract(params, '$.replication_source_id') = ?1",
            params![id, now],
        )?;
        let r = tx.execute(
            "UPDATE jobs SET cancel_by = 'vault_closed' WHERE kind = 'replica_sync' AND state = 'running' \
             AND cancel_by IS NULL AND json_extract(params, '$.replication_source_id') = ?1",
            [id],
        )?;
        tx.commit()?;
        q + r
    };
    st.audit(
        ctx.name(),
        "replication_source.close",
        &format!("replication-source/{id}"),
        json!({"name": s["name"], "closed_until": until, "syncs_cancelled": cancelled}),
    )?;
    let out = source_value(&st.cat.conn(), id)?.ok_or_else(ApiError::not_found)?;
    Ok(Json(out).into_response())
}

/// Reopening a closed vault needs approval (quorum `replication.reopen`).
pub async fn reopen_source(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Response> {
    ctx.require(CLOSERS)?;
    if ctx.scope().is_some() {
        return Err(ApiError::forbidden());
    }
    let s = source_value(&st.cat.conn(), id)?.ok_or_else(ApiError::not_found)?;
    if s["closed_until"].is_null() {
        return Err(ApiError::conflict("the replication source is not closed"));
    }
    let q = request(
        &st,
        &ctx,
        REOPEN,
        &format!("replication-source/{id}"),
        json!({"id": id, "name": s["name"], "url": s["url"], "closed_until": s["closed_until"],
               "closed_by": s["closed_by"], "closed_at": s["closed_at"]}),
    )?;
    Ok(accepted(q, json!({})))
}
