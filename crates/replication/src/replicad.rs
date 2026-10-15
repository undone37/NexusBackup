//! nexus-replicad (primary, docs/replication.md §2): serves sealed snapshot
//! files and chunks of the tenant stores **read-only** to the web-api over a
//! Unix socket, and signs enrolled secondaries' certificates. It has no keys:
//! nothing is decrypted here. Only the web-api uid may connect (SO_PEERCRED).
//!
//! State (`/var/lib/nexus/replicad`, 0700): `ca.key`/`ca.pem` (replication CA),
//! `seal.key` (opens the enrollment token digests the web-api sealed to it).
//! Published for the web-api (runtime dir): `ca.pem`, `seal.pub`.

use crate::ca::Ca;
use crate::{
    hex, proof, proof_eq, unhex, EnrollOutcome, Header, Request, SnapshotInfo, MAX_CHUNK, MAX_FILE, MAX_IDS, MISSING,
};
use anyhow::{Context, Result};
use catalog::secret::{replication_peer_token_location, SchedulerKey};
use chunkstore::Keyring;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Connections served at once (each streams one answer).
const MAX_CONNECTIONS: usize = 64;
/// One request line: ≤ 1024 ids of 64 hex plus JSON overhead.
const MAX_LINE: u64 = (MAX_IDS as u64) * 70 + (16 << 10);

pub struct Replicad {
    pub store_base: PathBuf,
    pub ca: Ca,
    seal: SchedulerKey,
    active: AtomicUsize,
}

fn open_nofollow(p: &Path) -> io::Result<File> {
    fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(p)
}

pub fn peer_uid(s: &UnixStream) -> io::Result<u32> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            std::os::fd::AsRawFd::as_raw_fd(s),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid)
}

fn header(w: &mut impl Write, status: u16, error: Option<String>) -> io::Result<()> {
    let mut l = serde_json::to_vec(&Header { status, error }).map_err(io::Error::other)?;
    l.push(b'\n');
    w.write_all(&l)
}

impl Replicad {
    /// CA and sealing key in `state_dir` (created on first start).
    pub fn open(state_dir: &Path, store_base: &Path) -> Result<Self> {
        let ca = Ca::load_or_create(state_dir).context("replication CA")?;
        let (seal, _) = SchedulerKey::load_or_create(&state_dir.join("seal.key")).context("seal.key")?;
        Ok(Replicad {
            store_base: store_base.to_owned(),
            ca,
            seal,
            active: AtomicUsize::new(0),
        })
    }

    /// Writes `ca.pem` and `seal.pub` (0640, group `gid`) for the web-api.
    pub fn publish(&self, dir: &Path, gid: Option<u32>) -> Result<()> {
        self.seal.write_public(&dir.join("seal.pub"), gid)?;
        let p = dir.join("ca.pem");
        let tmp = dir.join(".ca.pem.tmp");
        let _ = fs::remove_file(&tmp);
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .open(&tmp)?
            .write_all(self.ca.ca_pem.as_bytes())?;
        if gid.is_some() {
            std::os::unix::fs::chown(&tmp, None, gid)?;
        }
        fs::rename(&tmp, &p)?;
        Ok(())
    }

    /// Accept loop: one thread per connection, at most `MAX_CONNECTIONS`.
    pub fn serve(self: Arc<Self>, listener: UnixListener, allow_uid: u32) -> io::Result<()> {
        for conn in listener.incoming() {
            let s = match conn {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("<4>replicad: accept: {e}");
                    continue;
                }
            };
            if self.active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                self.active.fetch_sub(1, Ordering::SeqCst);
                eprintln!("<4>replicad: too many connections, refused");
                continue;
            }
            let me = self.clone();
            std::thread::spawn(move || {
                if let Err(e) = me.handle(s, allow_uid) {
                    eprintln!("<4>replicad: request failed: {e}");
                }
                me.active.fetch_sub(1, Ordering::SeqCst);
            });
        }
        Ok(())
    }

    fn handle(&self, s: UnixStream, allow_uid: u32) -> io::Result<()> {
        let uid = peer_uid(&s)?;
        if uid != allow_uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("peer uid {uid} not allowed"),
            ));
        }
        s.set_read_timeout(Some(Duration::from_secs(30)))?;
        s.set_write_timeout(Some(Duration::from_secs(300)))?;
        let mut line = String::new();
        BufReader::new(&s).take(MAX_LINE).read_line(&mut line)?;
        let mut w = io::BufWriter::with_capacity(256 << 10, &s);
        match serde_json::from_str::<Request>(&line) {
            Ok(req) => self.answer(&req, &mut w)?,
            Err(e) => header(&mut w, 400, Some(format!("malformed request: {e}")))?,
        }
        w.flush()
    }

    /// Writes header + body of the answer to `req`.
    pub fn answer(&self, req: &Request, w: &mut impl Write) -> io::Result<()> {
        if let Err(e) = req.check() {
            return header(w, 403, Some(e));
        }
        match req {
            Request::List { tenant, .. } => match self.list(tenant) {
                Ok(l) => {
                    header(w, 200, None)?;
                    w.write_all(&serde_json::to_vec(&l).map_err(io::Error::other)?)
                }
                Err(e) => header(w, 500, Some(format!("listing failed: {e}"))),
            },
            Request::File {
                tenant,
                source,
                time,
                file,
                ..
            } => {
                let p = self
                    .tenant_root(tenant)
                    .join("snapshots")
                    .join(source)
                    .join(time.to_string())
                    .join(file);
                let mut f = match open_nofollow(&p) {
                    Ok(f) => f,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        return header(w, 404, Some("no such file".into()))
                    }
                    Err(e) => return header(w, 500, Some(e.to_string())),
                };
                let m = f.metadata()?;
                if !m.is_file() || m.len() > MAX_FILE {
                    return header(w, 500, Some("not a regular file within limits".into()));
                }
                header(w, 200, None)?;
                io::copy(&mut (&mut f).take(MAX_FILE), w).map(drop)
            }
            Request::Chunks { tenant, ids, .. } => {
                let root = self.tenant_root(tenant).join("chunks");
                header(w, 200, None)?;
                for id in ids {
                    let raw = unhex(id).expect("checked");
                    w.write_all(&raw)?;
                    match open_nofollow(&root.join(&id[..4]).join(id)) {
                        Ok(f) => {
                            let m = f.metadata()?;
                            if !m.is_file() || m.len() > MAX_CHUNK {
                                return Err(io::Error::other(format!(
                                    "chunk {id}: not a regular file within limits"
                                )));
                            }
                            w.write_all(&(m.len() as u32).to_be_bytes())?;
                            let n = io::copy(&mut f.take(m.len()), w)?;
                            if n != m.len() {
                                // truncated while reading: the stream cannot be kept consistent
                                return Err(io::Error::other(format!("chunk {id} changed while read")));
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::NotFound => w.write_all(&MISSING.to_be_bytes())?,
                        Err(e) => return Err(e),
                    }
                }
                Ok(())
            }
            Request::Enroll {
                peer_id,
                token_sealed,
                exporter,
                proof: given,
                csr_pem,
            } => {
                let digest = match self.seal.open(&replication_peer_token_location(peer_id), token_sealed) {
                    Ok(d) => d,
                    Err(e) => return header(w, 403, Some(format!("enrollment token unusable: {e:#}"))),
                };
                let ex: [u8; 32] = unhex(exporter).and_then(|b| b.try_into().ok()).expect("checked");
                let given: [u8; 32] = unhex(given).and_then(|b| b.try_into().ok()).expect("checked");
                if !proof_eq(&given, &proof(&digest, "secondary", &ex)) {
                    return header(
                        w,
                        403,
                        Some("enrollment proof invalid (wrong code, or a man in the middle)".into()),
                    );
                }
                let (cert_pem, cert_sha256) = match self.ca.sign_peer(csr_pem, peer_id) {
                    Ok(c) => c,
                    Err(e) => return header(w, 400, Some(format!("{e:#}"))),
                };
                let out = EnrollOutcome {
                    proof: hex(&proof(&digest, "primary", &ex)),
                    cert_pem,
                    ca_pem: self.ca.ca_pem.clone(),
                    cert_sha256,
                };
                header(w, 200, None)?;
                w.write_all(&serde_json::to_vec(&out).map_err(io::Error::other)?)
            }
        }
    }

    fn tenant_root(&self, tenant: &str) -> PathBuf {
        self.store_base.join(tenant)
    }

    /// Committed snapshots (manifest present) of a tenant store, without decrypting.
    pub fn list(&self, tenant: &str) -> io::Result<Vec<SnapshotInfo>> {
        let root = self.tenant_root(tenant).join("snapshots");
        let mut out = Vec::new();
        let sources = match fs::read_dir(&root) {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e),
        };
        for src in sources {
            let src = src?;
            let Some(source) = src
                .file_name()
                .to_str()
                .filter(|s| crate::valid_name(s))
                .map(str::to_owned)
            else {
                continue;
            };
            if !src.file_type()?.is_dir() {
                continue;
            }
            for t in fs::read_dir(src.path())? {
                let t = t?;
                let Some(time) = t.file_name().to_str().and_then(|s| s.parse::<u64>().ok()) else {
                    continue;
                };
                if !t.file_type()?.is_dir() {
                    continue;
                }
                let mut head = [0u8; 64];
                let n = match open_nofollow(&t.path().join("manifest")) {
                    Ok(mut f) => f.read(&mut head)?,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue, // aborted / in progress
                    Err(e) => return Err(e),
                };
                let Some(key_version) = Keyring::blob_version(&head[..n]) else {
                    continue;
                };
                let (mut files, mut size) = (Vec::new(), 0u64);
                for f in fs::read_dir(t.path())? {
                    let f = f?;
                    let name = f.file_name().to_string_lossy().into_owned();
                    let m = f.metadata()?;
                    if crate::valid_file(&name) && m.is_file() {
                        size += m.len();
                        files.push(name);
                    }
                }
                files.sort();
                out.push(SnapshotInfo {
                    source: source.clone(),
                    time,
                    key_version,
                    files,
                    size,
                });
            }
        }
        out.sort_by(|a, b| (&a.source, a.time).cmp(&(&b.source, b.time)));
        Ok(out)
    }
}
