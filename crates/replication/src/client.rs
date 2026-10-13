//! Secondary side (docs/replication.md §4, §7): enrollment with the primary and
//! the pull sync of one tenant. Everything received is verified with the
//! tenant keyring before it is written; a snapshot is committed (manifest last)
//! only after all its indexes and chunks were verified and stored.

use crate::ca::{common_name, new_key_and_csr, pem_to_der, write_private};
use crate::http::{client_config, Conn, Target};
use crate::{
    hex, proof, proof_eq, sha256_hex, unhex, EnrollRequest, EnrollResponse, HoldInfo, KeyExport, SessionEnd,
    SnapshotInfo, ALPN_ENROLL, ALPN_PEER, CN_PREFIX, EXPORTER_LABEL, MAX_CHUNK, MAX_FILE, MISSING, PREFIX,
};
use anyhow::{anyhow, bail, Context, Result};
use catalog::schedule::{Bandwidth, Throttle};
use chunkstore::retention::{keep, Gfs};
use chunkstore::{ChunkId, Options, Store};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ClientConfig;
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Ids per chunk request (≤ MAX_IDS); small enough to spread over the workers.
const BATCH: usize = 128;

/// A sealed object from the primary failed verification (nothing of that
/// snapshot was imported). The CLI reports it as `verify-failed`.
#[derive(Debug)]
pub struct VerifyFailed(pub String);
impl std::fmt::Display for VerifyFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "verification failed: {}", self.0)
    }
}
impl std::error::Error for VerifyFailed {}

/// The primary has no (usable) DEK export for the tenant. Reported as `key-mismatch`.
#[derive(Debug)]
pub struct KeysMissing(pub String);
impl std::fmt::Display for KeysMissing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for KeysMissing {}

// ---------------------------------------------------------------- enrollment

pub struct EnrollParams<'a> {
    pub target: &'a Target,
    pub peer_id: &'a str,
    /// `token_digest(token)` of the code's token part
    pub token_digest: &'a str,
    /// this appliance's host name (display on the primary)
    pub name: &'a str,
    /// where client.key / client.pem / ca.pem go (0600)
    pub cred_dir: &'a Path,
    pub keyd_pub: [u8; 32],
}

#[derive(Serialize, Debug)]
pub struct Enrolled {
    pub cert_sha256: String,
    pub tenants: Vec<String>,
    pub keyd_pub: String,
}

pub fn enroll(p: &EnrollParams) -> Result<Enrolled> {
    let mut c = Conn::connect(p.target, client_config(&p.target.pin, ALPN_ENROLL, None)?)?;
    let ex = c.exporter(EXPORTER_LABEL)?;
    let (key_pem, csr_pem) = new_key_and_csr(&format!("{CN_PREFIX}{}", p.peer_id))?;
    let req = EnrollRequest {
        peer_id: p.peer_id.to_owned(),
        name: p.name.to_owned(),
        csr_pem,
        keyd_pub: hex(&p.keyd_pub),
        proof: hex(&proof(p.token_digest, "secondary", &ex)),
    };
    let r: EnrollResponse = c
        .request(
            "POST",
            &format!("{PREFIX}/enroll"),
            Some("application/json"),
            &serde_json::to_vec(&req)?,
        )?
        .json(256 << 10)?;
    let theirs: [u8; 32] = unhex(&r.proof)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("malformed proof from the primary"))?;
    if !proof_eq(&theirs, &proof(p.token_digest, "primary", &ex)) {
        bail!("the primary's enrollment proof is invalid (wrong code, or a man in the middle): not enrolled");
    }
    let der = pem_to_der(&r.cert_pem).context("certificate from the primary")?;
    if common_name(&der).as_deref() != Some(&format!("{CN_PREFIX}{}", p.peer_id)) {
        bail!("the primary issued a certificate for another peer");
    }
    // the certificate must carry our public key
    let (_, cert) = x509_parser::parse_x509_certificate(&der).map_err(|e| anyhow!("certificate: {e}"))?;
    let key = rcgen::KeyPair::from_pem(&key_pem)?;
    if cert.public_key().subject_public_key.data.as_ref() != key.public_key_raw() {
        bail!("the primary's certificate does not match our key");
    }
    fs::create_dir_all(p.cred_dir)?;
    fs::set_permissions(p.cred_dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    write_private(&p.cred_dir.join("client.key"), key_pem.as_bytes())?;
    write_private(&p.cred_dir.join("ca.pem"), r.ca_pem.as_bytes())?;
    write_private(&p.cred_dir.join("client.pem"), r.cert_pem.as_bytes())?;
    Ok(Enrolled {
        cert_sha256: sha256_hex(&der),
        tenants: r.tenants,
        keyd_pub: hex(&p.keyd_pub),
    })
}

/// Client certificate + key written by `enroll`.
pub fn load_creds(dir: &Path) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert = dir.join("client.pem");
    let chain = CertificateDer::pem_file_iter(&cert)
        .with_context(|| format!("{} (not enrolled?)", cert.display()))?
        .collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(dir.join("client.key")).context("client.key")?;
    Ok((chain, key))
}

// ---------------------------------------------------------------- sync

pub struct SyncParams {
    pub target: Target,
    pub cred_dir: PathBuf,
    pub tenant: String,
    /// the tenant's store (`<store_base>/<tenant>`)
    pub store: PathBuf,
    pub keyd_socket: PathBuf,
    pub gfs: Gfs,
    /// parallel connections for chunk downloads
    pub parallel: usize,
    /// bytes per second (`base`, None = unlimited) and the bandwidth windows
    /// (pause / limit, Phase 17a), re-evaluated while fetching
    pub bandwidth: Bandwidth,
    /// `(source, time)` under a legal hold applied on this appliance: kept by
    /// the local retention
    pub held: BTreeSet<(String, u64)>,
    /// the primary tenant's uid seen before (Phase 19b): a primary that
    /// reports another uid for the name serves a different tenant (deleted and
    /// re-created) and is refused. `None`: first sync or a legacy primary.
    pub tenant_uid: Option<String>,
}

#[derive(Serialize, Debug, Default)]
pub struct SyncReport {
    pub tenant: String,
    /// committed snapshots on the primary (in scope)
    pub remote: usize,
    /// `source/time` imported in this run
    pub imported: Vec<String>,
    /// remote snapshots not fetched because local GFS would not keep them
    pub skipped_by_retention: usize,
    /// `source/time` whose key version is unknown here
    pub key_mismatch: Vec<String>,
    pub chunks_fetched: u64,
    pub bytes_fetched: u64,
    /// chunks referenced by imported snapshots that were already present
    pub chunks_present: u64,
    /// `source: kept, deleted, still locked`
    pub retention: Vec<String>,
    pub key_versions: Vec<u32>,
    /// the primary's legal holds (advisory; empty from primaries before 15c)
    pub holds: Vec<HoldInfo>,
    /// the primary tenant's immutable uid (None from primaries before 19b)
    pub tenant_uid: Option<String>,
    pub secs: f64,
}

struct Peer {
    target: Target,
    cfg: Arc<ClientConfig>,
    conn: Option<Conn>,
}

impl Peer {
    fn conn(&mut self) -> Result<&mut Conn> {
        if self.conn.is_none() {
            self.conn = Some(Conn::connect(&self.target, self.cfg.clone())?);
        }
        Ok(self.conn.as_mut().unwrap())
    }

    /// One request with a bounded body; a dropped keep-alive connection is
    /// re-established once.
    fn call(&mut self, method: &str, path: &str, body: Option<&serde_json::Value>, max: u64) -> Result<(u16, Vec<u8>)> {
        let b = body.map(|v| v.to_string().into_bytes()).unwrap_or_default();
        let ct = body.map(|_| "application/json");
        for attempt in 0..2 {
            let r = self.conn().and_then(|c| c.request(method, path, ct, &b)).and_then(|r| {
                let s = r.status;
                Ok((s, r.bytes(max)?))
            });
            match r {
                Ok(x) => return Ok(x),
                Err(e) if attempt == 0 && e.downcast_ref::<std::io::Error>().is_some() => {
                    self.conn = None;
                }
                Err(e) => {
                    self.conn = None;
                    return Err(e);
                }
            }
        }
        unreachable!()
    }

    fn json<T: serde::de::DeserializeOwned>(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&serde_json::Value>,
        max: u64,
    ) -> Result<T> {
        let (s, b) = self.call(method, path, body, max)?;
        if !(200..300).contains(&s) {
            bail!("{path}: {}", crate::http::error_text(s, &b));
        }
        serde_json::from_slice(&b).with_context(|| format!("{path}: malformed JSON"))
    }

    fn file(&mut self, path: &str) -> Result<Vec<u8>> {
        let (s, b) = self.call("GET", path, None, MAX_FILE)?;
        if s != 200 {
            bail!("{path}: {}", crate::http::error_text(s, &b));
        }
        Ok(b)
    }
}

fn verify(what: String) -> impl FnOnce(std::io::Error) -> anyhow::Error {
    move |e| anyhow::Error::new(VerifyFailed(format!("{what}: {e}")))
}

/// Pulls the missing, retention-kept snapshots of one tenant (docs §7).
pub fn sync(p: &SyncParams, log: &mut dyn FnMut(&str)) -> Result<SyncReport> {
    let t0 = Instant::now();
    let cfg = client_config(&p.target.pin, ALPN_PEER, Some(load_creds(&p.cred_dir)?))?;
    let mut peer = Peer {
        target: p.target.clone(),
        cfg: cfg.clone(),
        conn: None,
    };
    let sess: serde_json::Value = peer.json(
        "POST",
        &format!("{PREFIX}/session"),
        Some(&json!({"tenant": p.tenant})),
        4096,
    )?;
    let session = sess["session"].as_str().unwrap_or_default().to_owned();
    let mut report = SyncReport {
        tenant: p.tenant.clone(),
        tenant_uid: sess["tenant_uid"].as_str().map(str::to_owned),
        ..Default::default()
    };
    let r = match (&p.tenant_uid, &report.tenant_uid) {
        (Some(want), Some(got)) if want != got => Err(anyhow::Error::new(VerifyFailed(format!(
            "tenant {} on the primary has uid {got}, this secondary replicates uid {want}: \
             a different tenant with the same name (deleted and re-created?); nothing fetched",
            p.tenant
        )))),
        _ => sync_inner(p, &mut peer, cfg, &mut report, log),
    };
    report.secs = t0.elapsed().as_secs_f64();
    let end = SessionEnd {
        snapshots: report.imported.len() as u64,
        chunks: report.chunks_fetched,
        bytes: report.bytes_fetched,
        error: r.as_ref().err().map(|e| format!("{e:#}")),
    };
    if !session.is_empty() {
        let path = format!("{PREFIX}/session/{session}/end");
        if let Err(e) = peer.json::<serde_json::Value>("POST", &path, Some(&serde_json::to_value(&end)?), 4096) {
            log(&format!("session end not recorded on the primary: {e:#}"));
        }
    }
    r.map(|()| report)
}

fn sync_inner(
    p: &SyncParams,
    peer: &mut Peer,
    cfg: Arc<ClientConfig>,
    report: &mut SyncReport,
    log: &mut dyn FnMut(&str),
) -> Result<()> {
    let t = &p.tenant;
    // 1. keys: import versions we do not have yet
    let (s, b) = peer.call("GET", &format!("{PREFIX}/tenants/{t}/keys"), None, 1 << 20)?;
    if s == 404 {
        return Err(anyhow::Error::new(KeysMissing(format!(
            "the primary has no key export for tenant {t} yet: approve the key export request on the primary"
        ))));
    }
    if s != 200 {
        bail!("keys: {}", crate::http::error_text(s, &b));
    }
    let export: KeyExport = serde_json::from_slice(&b).context("key export")?;
    let have = keyd::fetch_keyring(&p.keyd_socket, t)
        .map(|k| k.versions())
        .unwrap_or_default();
    if export.versions.iter().any(|v| !have.contains(v)) {
        let blob = unhex(&export.blob).ok_or_else(|| anyhow!("malformed key export"))?;
        let vs = keyd::request_import(&p.keyd_socket, t, &p.target.pin, &blob)
            .with_context(|| format!("importing the DEKs of tenant {t} into keyd"))?;
        log(&format!("imported DEKs of tenant {t}: versions {vs:?}"));
    }
    let keys = keyd::fetch_keyring(&p.keyd_socket, t).context("keyd")?;
    report.key_versions = keys.versions();
    let store = Store::open(&p.store, keys, Options::default())?;

    // 2. what to fetch: missing locally and kept by local GFS over local ∪ remote
    let remote: Vec<SnapshotInfo> = peer.json("GET", &format!("{PREFIX}/tenants/{t}/snapshots"), None, 64 << 20)?;
    report.remote = remote.len();
    let local: HashSet<(String, u64)> = store
        .list_snapshots()?
        .into_iter()
        .map(|m| (m.source, m.time))
        .collect();
    let mut by_source: BTreeMap<&str, Vec<&SnapshotInfo>> = BTreeMap::new();
    for s in &remote {
        if crate::valid_name(&s.source) {
            by_source.entry(&s.source).or_default().push(s);
        }
    }
    let mut wanted = Vec::new();
    for (source, snaps) in &by_source {
        let mut times: Vec<u64> = snaps.iter().map(|s| s.time).collect();
        times.extend(local.iter().filter(|(s, _)| s == source).map(|(_, t)| *t));
        let kept = keep(&times, &p.gfs);
        for s in snaps {
            if local.contains(&(s.source.clone(), s.time)) {
                continue;
            }
            if !kept.contains_key(&s.time) {
                report.skipped_by_retention += 1;
                continue;
            }
            if !report.key_versions.contains(&s.key_version) {
                report.key_mismatch.push(format!("{}/{}", s.source, s.time));
                log(&format!(
                    "key-mismatch {}",
                    json!({"tenant": t, "source": s.source, "time": s.time, "version": s.key_version, "have": report.key_versions})
                ));
                continue;
            }
            wanted.push(*s);
        }
    }
    wanted.sort_by_key(|s| (s.time, s.source.clone()));
    log(&format!(
        "tenant {t}: {} snapshots on the primary, {} to fetch, {} skipped by retention",
        remote.len(),
        wanted.len(),
        report.skipped_by_retention
    ));

    let limiter = (p.bandwidth != Bandwidth::default()).then(|| Throttle::new(p.bandwidth.clone()));
    // 3. per snapshot: manifest + indexes (verified), missing chunks (verified), commit
    for s in wanted {
        let id = format!("{}/{}", s.source, s.time);
        let base = format!("{PREFIX}/tenants/{t}/snapshots/{}/{}", s.source, s.time);
        let mbytes = peer.file(&format!("{base}/manifest"))?;
        let m = store
            .decode_manifest(&s.source, s.time, &mbytes)
            .map_err(verify(format!("manifest of {id}")))?;
        if m.tenant != *t || m.source != s.source || m.time != s.time {
            return Err(anyhow::Error::new(VerifyFailed(format!(
                "manifest of {id} names another snapshot"
            ))));
        }
        let mut files = Vec::new();
        let mut ids: BTreeSet<ChunkId> = BTreeSet::new();
        for name in &m.indexes {
            if !crate::valid_name(name) {
                return Err(anyhow::Error::new(VerifyFailed(format!(
                    "{id}: invalid index name {name:?}"
                ))));
            }
            let f = format!("{name}.idx");
            let b = peer.file(&format!("{base}/{f}"))?;
            let idx = store
                .decode_index(&s.source, s.time, name, &b)
                .map_err(verify(format!("index {name} of {id}")))?;
            ids.extend(idx.chunk_ids().into_iter().copied());
            files.push((f, b));
        }
        let mut missing = Vec::new();
        for c in ids {
            // touched under the chunk lock: a concurrent GC keeps it until the commit
            if store.touch_chunk(&c)? {
                report.chunks_present += 1;
            } else {
                missing.push(c);
            }
        }
        let (n, bytes) = fetch_chunks(p, &cfg, &store, missing, limiter.as_ref())?;
        report.chunks_fetched += n;
        report.bytes_fetched += bytes;
        files.push(("manifest".into(), mbytes));
        store
            .import_snapshot_raw(&s.source, s.time, &files)
            .map_err(verify(format!("snapshot {id}")))?;
        log(&format!("imported {id}: {n} chunks fetched ({bytes} bytes)"));
        report.imported.push(id);
    }

    // 4. the primary's legal holds: reported, never applied here (advisory)
    let (s, b) = peer.call("GET", &format!("{PREFIX}/tenants/{t}/holds"), None, 16 << 20)?;
    match s {
        200 => {
            report.holds = serde_json::from_slice::<Vec<HoldInfo>>(&b)
                .context("holds")?
                .into_iter()
                .filter(|h| crate::valid_name(&h.source))
                .collect();
        }
        404 => {} // primary before Phase 15c
        _ => log(&format!("holds: {}", crate::http::error_text(s, &b))),
    }

    // 5. independent retention (never because the primary deleted something),
    // skipping the holds applied here
    let sources: BTreeSet<String> = store.list_snapshots()?.into_iter().map(|m| m.source).collect();
    for src in sources {
        let held: BTreeSet<u64> = p.held.iter().filter(|(s, _)| *s == src).map(|(_, t)| *t).collect();
        let (k, d, l) = store.apply_retention_held(&src, &p.gfs, &held)?;
        report
            .retention
            .push(format!("{src}: kept {k}, deleted {d}, still locked {l}"));
    }
    if !report.key_mismatch.is_empty() {
        return Err(anyhow::Error::new(KeysMissing(format!(
            "{} snapshot(s) of tenant {t} use a key version this appliance does not have (have {:?}): re-export the keys on the primary",
            report.key_mismatch.len(),
            report.key_versions
        ))));
    }
    Ok(())
}

/// One frame of a `POST …/chunks` answer: `id(32) ‖ u32 BE len ‖ sealed bytes`.
/// The id must be the one requested next; lengths are bounded before allocating.
/// (The sealed bytes are verified by the caller's `insert_chunk_raw`.)
pub fn read_chunk_frame(r: &mut impl Read, want: &ChunkId) -> Result<Vec<u8>> {
    let mut head = [0u8; 36];
    r.read_exact(&mut head).context("chunk stream truncated")?;
    if head[..32] != want[..] {
        bail!("the primary answered chunks out of order");
    }
    let len = u32::from_be_bytes(head[32..].try_into().unwrap());
    if len == MISSING {
        bail!(
            "chunk {} is missing on the primary (removed by its GC since the listing?): retry the sync",
            hex(want)
        );
    }
    if u64::from(len) > MAX_CHUNK {
        return Err(anyhow::Error::new(VerifyFailed(format!(
            "chunk {} exceeds the size limit",
            hex(want)
        ))));
    }
    let mut data = vec![0u8; len as usize];
    r.read_exact(&mut data).context("chunk stream truncated")?;
    Ok(data)
}

/// Downloads `ids` over `p.parallel` connections; every chunk is verified
/// (AEAD + keyed hash) by `insert_chunk_raw` before it is stored.
fn fetch_chunks(
    p: &SyncParams,
    cfg: &Arc<ClientConfig>,
    store: &Store,
    ids: Vec<ChunkId>,
    limiter: Option<&Throttle>,
) -> Result<(u64, u64)> {
    if ids.is_empty() {
        return Ok((0, 0));
    }
    let queue: Mutex<VecDeque<Vec<ChunkId>>> = Mutex::new(ids.chunks(BATCH).map(<[ChunkId]>::to_vec).collect());
    let workers = p.parallel.clamp(1, 16).min(queue.lock().unwrap().len());
    let (count, bytes) = (AtomicU64::new(0), AtomicU64::new(0));
    let stop = AtomicBool::new(false);
    let first_err: Mutex<Option<anyhow::Error>> = Mutex::new(None);
    let path = format!("{PREFIX}/tenants/{}/chunks", p.tenant);
    std::thread::scope(|sc| {
        for _ in 0..workers {
            sc.spawn(|| {
                let r = (|| -> Result<()> {
                    let mut conn = Conn::connect(&p.target, cfg.clone())?;
                    loop {
                        if stop.load(Ordering::Relaxed) {
                            return Ok(());
                        }
                        // a pause window: wait, then start over on a fresh connection
                        if limiter.is_some_and(Throttle::wait_open) {
                            conn = Conn::connect(&p.target, cfg.clone())?;
                        }
                        let Some(batch) = queue.lock().unwrap().pop_front() else {
                            return Ok(());
                        };
                        let body: Vec<u8> = batch.iter().flat_map(|c| c.iter().copied()).collect();
                        let mut r = conn
                            .request("POST", &path, Some("application/octet-stream"), &body)?
                            .ok()?;
                        for want in &batch {
                            let data = read_chunk_frame(&mut r, want)?;
                            store
                                .insert_chunk_raw(want, &data)
                                .map_err(verify(format!("chunk {}", hex(want))))?;
                            count.fetch_add(1, Ordering::Relaxed);
                            bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                            if let Some(l) = limiter {
                                l.account(data.len() as u64);
                            }
                        }
                        let mut extra = [0u8; 1];
                        if r.read(&mut extra)? != 0 {
                            bail!("the primary sent more chunks than requested");
                        }
                    }
                })();
                if let Err(e) = r {
                    stop.store(true, Ordering::Relaxed);
                    first_err.lock().unwrap().get_or_insert(e);
                }
            });
        }
    });
    if let Some(e) = first_err.into_inner().unwrap() {
        return Err(e);
    }
    Ok((count.into_inner(), bytes.into_inner()))
}
