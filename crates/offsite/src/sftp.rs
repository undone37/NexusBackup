//! `Remote` over SFTP (Hetzner Storage Box, plan §9), pure Rust (russh + russh-sftp).
//!
//! Hetzner facts this is built for (docs.hetzner.com, storage-box/access and
//! backup-space-ssh-keys, checked 2026-10):
//! - SFTP is offered on port 22 *and* port 23. Port 23 is the "extended SSH
//!   service" and takes the public key in normal one-line OpenSSH format; port 22
//!   needs the key converted to RFC4716. We default to **23**.
//! - Max. 10 simultaneous connections per account. We use one SFTP channel per
//!   SSH connection and default to 4 connections (rest is reserved for
//!   restore/verify/humans); more than 10 is rejected at construction.
//! - No server-side processes: everything is plain SFTP v3 requests.
//!
//! Design: the trait is synchronous, so the remote owns a small private tokio
//! runtime and each call `block_on`s it (must not be called from inside another
//! tokio runtime). A pool holds up to `max_connections` (SSH session + SFTP
//! channel) pairs, opened lazily. A call takes a connection (or waits), runs, and
//! returns it. Transport-level failures (timeouts, closed channel, connect
//! errors) drop the connection and retry the whole operation on a fresh one with
//! exponential backoff; protocol answers (no such file, exists, …) are returned
//! as is. The host key is pinned (no TOFU): a different key fails the connect
//! and is not retried.

use futures_util::stream::{self, StreamExt, TryStreamExt};
use russh::client;
use russh::keys::{self, Algorithm, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use russh_sftp::client::error::Error as SftpError;
use russh_sftp::client::RawSftpSession;
use russh_sftp::protocol::{FileAttributes, OpenFlags, StatusCode};
use std::borrow::Cow;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::remote::Remote;

/// Hetzner's per-account connection limit.
pub const MAX_BOX_CONNECTIONS: usize = 10;
/// Requests in flight per connection during get/put (pipelining).
const WINDOW: usize = 16;
/// Read/write request size when the server does not announce `limits@openssh.com`
/// (32 KiB is what every SFTP v3 server must accept).
const DEFAULT_CHUNK: u32 = 32 * 1024;
/// Upper bound on request size; replies must fit into russh-sftp's 256 KiB packets.
const MAX_CHUNK: u32 = 255 * 1024;

#[derive(Clone, Debug)]
pub struct SftpConfig {
    pub host: String,
    /// Storage Box: 23 (OpenSSH-format keys). See module docs.
    pub port: u16,
    pub user: String,
    /// Unencrypted OpenSSH ed25519 private key file.
    pub key_file: PathBuf,
    /// Pinned server key: a known_hosts line (`[host]:port ssh-ed25519 AAAA…`)
    /// or a public key (`ssh-ed25519 AAAA…`). A server presenting any other key
    /// is refused.
    pub host_key: String,
    /// Directory on the box all paths are relative to ("" = login directory).
    pub base_dir: String,
    /// Pool size, 1..=10 (default 4).
    pub max_connections: usize,
    /// TCP connect + key exchange + auth + SFTP init (default 20 s).
    pub connect_timeout: Duration,
    /// Per SFTP request (one read/write/open/…; default 60 s). A stalled
    /// connection is detected after this and replaced.
    pub request_timeout: Duration,
    /// Retries after transport failures (default 4; total attempts = retries + 1).
    pub retries: u32,
    /// First retry delay, doubled per retry, capped at 30 s (default 500 ms).
    pub backoff: Duration,
}

impl SftpConfig {
    pub fn new(host: &str, user: &str, key_file: impl Into<PathBuf>, host_key: &str) -> Self {
        SftpConfig {
            host: host.into(),
            port: 23,
            user: user.into(),
            key_file: key_file.into(),
            host_key: host_key.into(),
            base_dir: String::new(),
            max_connections: 4,
            connect_timeout: Duration::from_secs(20),
            request_timeout: Duration::from_secs(60),
            retries: 4,
            backoff: Duration::from_millis(500),
        }
    }
}

/// Parses a known_hosts line or an OpenSSH public key line.
pub fn parse_host_key(s: &str) -> io::Result<PublicKey> {
    s.split_whitespace()
        .find_map(|t| keys::parse_public_key_base64(t).ok())
        .ok_or_else(|| invalid(format!("no SSH public key in pinned host key {s:?}")))
}

struct Conn {
    ssh: client::Handle<Pinned>,
    sftp: RawSftpSession,
    chunk: u32,
    fsync: bool,
    statvfs: bool,
}

#[derive(Default)]
struct Pool {
    idle: Vec<Conn>,
    open: usize,
}

pub struct SftpRemote {
    // field order = drop order: connections go before the runtime
    pool: Mutex<Pool>,
    freed: Condvar,
    cfg: SftpConfig,
    base: String,
    key: Arc<PrivateKey>,
    pinned: PublicKey,
    rt: tokio::runtime::Runtime,
}

/// Operation error: `Op` = the server answered (connection is fine),
/// `Conn` = transport trouble (drop the connection, retry).
enum E {
    Op(io::Error),
    Conn(io::Error),
}

type R<T> = Result<T, E>;

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

fn classify(e: SftpError) -> E {
    use io::ErrorKind as K;
    match e {
        SftpError::Status(s) => {
            let kind = match s.status_code {
                StatusCode::NoSuchFile => K::NotFound,
                StatusCode::PermissionDenied => K::PermissionDenied,
                StatusCode::Eof => K::UnexpectedEof,
                StatusCode::OpUnsupported => K::Unsupported,
                StatusCode::NoConnection | StatusCode::ConnectionLost => {
                    return E::Conn(io::Error::new(K::ConnectionAborted, s.error_message))
                }
                _ => K::Other,
            };
            E::Op(io::Error::new(kind, format!("{}: {}", s.status_code, s.error_message)))
        }
        SftpError::Limited(m) => E::Op(io::Error::other(m)),
        SftpError::Timeout => E::Conn(io::Error::new(K::TimedOut, "SFTP request timed out")),
        other => E::Conn(io::Error::new(K::ConnectionAborted, other.to_string())),
    }
}

fn is_not_found(e: &E) -> bool {
    matches!(e, E::Op(e) if e.kind() == io::ErrorKind::NotFound)
}

fn check(path: &str) -> io::Result<()> {
    // same rules as remote::LocalDir
    let ok =
        !path.is_empty() && !path.starts_with('/') && path.split('/').all(|c| !c.is_empty() && c != "." && c != "..");
    if ok {
        Ok(())
    } else {
        Err(invalid(format!("invalid remote path {path:?}")))
    }
}

fn unique() -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    format!("{:x}{:x}{:x}", std::process::id(), t, N.fetch_add(1, Ordering::Relaxed))
}

struct Pinned(PublicKey);

impl client::Handler for Pinned {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(matches!(key, PublicKeyOrCertificate::PublicKey { key, .. } if key.key_data() == self.0.key_data()))
    }
}

impl SftpRemote {
    /// Validates the config and loads the keys; connects lazily on first use.
    pub fn new(cfg: SftpConfig) -> io::Result<Self> {
        if cfg.max_connections == 0 || cfg.max_connections > MAX_BOX_CONNECTIONS {
            return Err(invalid(format!(
                "max_connections must be 1..={MAX_BOX_CONNECTIONS} (Storage Box limit), got {}",
                cfg.max_connections
            )));
        }
        let pinned = parse_host_key(&cfg.host_key)?;
        let key = keys::load_secret_key(&cfg.key_file, None)
            .map_err(|e| invalid(format!("client key {}: {e}", cfg.key_file.display())))?;
        if key.algorithm() != Algorithm::Ed25519 {
            return Err(invalid(format!("client key must be ed25519, is {}", key.algorithm())));
        }
        let base = cfg.base_dir.trim_end_matches('/').to_owned();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("sftp-remote")
            .enable_all()
            .build()?;
        Ok(SftpRemote {
            pool: Mutex::default(),
            freed: Condvar::new(),
            cfg,
            base,
            key: Arc::new(key),
            pinned,
            rt,
        })
    }

    /// Opens one connection right away (fails fast on wrong host key, auth, …).
    pub fn connect(&self) -> io::Result<()> {
        self.run(|_, _| Ok(()))
    }

    /// `(total, available)` bytes of the box via `statvfs@openssh.com`.
    pub fn usage(&self) -> io::Result<(u64, u64)> {
        let dir = if self.base.is_empty() {
            ".".to_owned()
        } else {
            self.base.clone()
        };
        self.run(|c, _| {
            if !c.statvfs {
                return Err(E::Op(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "no statvfs@openssh.com",
                )));
            }
            let s = self.rt.block_on(c.sftp.statvfs(dir.clone())).map_err(classify)?;
            Ok((s.blocks * s.fragment_size, s.blocks_avail * s.fragment_size))
        })
    }

    fn full(&self, path: &str) -> String {
        if self.base.is_empty() {
            path.to_owned()
        } else {
            format!("{}/{path}", self.base)
        }
    }

    async fn open_conn(&self) -> R<Conn> {
        let mut preferred = russh::Preferred::default();
        let algs = match self.pinned.algorithm() {
            Algorithm::Rsa { .. } => vec![
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha512),
                },
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha256),
                },
            ],
            a => vec![a],
        };
        preferred.key = Cow::Owned(algs);
        let config = Arc::new(client::Config {
            preferred,
            window_size: 8 << 20,
            keepalive_interval: Some(Duration::from_secs(30)),
            keepalive_max: 3,
            nodelay: true,
            ..Default::default()
        });
        let conn_err = |what: &str, e: russh::Error| match e {
            russh::Error::UnknownKey => E::Op(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "host key of {}:{} does not match the pinned key",
                    self.cfg.host, self.cfg.port
                ),
            )),
            e => E::Conn(io::Error::new(io::ErrorKind::ConnectionRefused, format!("{what}: {e}"))),
        };
        let mut ssh = client::connect(
            config,
            (self.cfg.host.as_str(), self.cfg.port),
            Pinned(self.pinned.clone()),
        )
        .await
        .map_err(|e| conn_err("connect", e))?;
        let auth = ssh
            .authenticate_publickey(&self.cfg.user, PrivateKeyWithHashAlg::new(self.key.clone(), None))
            .await
            .map_err(|e| conn_err("auth", e))?;
        if !auth.success() {
            // Also what an 11th connection to a Storage Box looks like: retry.
            return Err(E::Conn(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("public key auth as {} refused", self.cfg.user),
            )));
        }
        let ch = ssh.channel_open_session().await.map_err(|e| conn_err("channel", e))?;
        ch.request_subsystem(true, "sftp")
            .await
            .map_err(|e| conn_err("subsystem", e))?;
        let cfg = russh_sftp::client::Config {
            request_timeout_secs: self.cfg.request_timeout.as_secs().max(1),
            ..Default::default()
        };
        let mut sftp = RawSftpSession::new_with_config(ch.into_stream(), cfg);
        let version = sftp.init().await.map_err(classify)?;
        let ext = |n: &str| version.extensions.contains_key(n);
        let mut chunk = DEFAULT_CHUNK;
        if ext("limits@openssh.com") {
            let l = russh_sftp::client::rawsession::Limits::from(sftp.limits().await.map_err(classify)?);
            let lim = l.read_len.unwrap_or(0).min(l.write_len.unwrap_or(0));
            if lim > 0 {
                chunk = lim.min(MAX_CHUNK as u64) as u32;
            }
            sftp.set_limits(l);
        }
        Ok(Conn {
            ssh,
            sftp,
            chunk,
            fsync: ext("fsync@openssh.com"),
            statvfs: ext("statvfs@openssh.com"),
        })
    }

    fn checkout(&self) -> R<Conn> {
        let mut p = self.pool.lock().unwrap();
        loop {
            while let Some(c) = p.idle.pop() {
                if !c.ssh.is_closed() {
                    return Ok(c);
                }
                p.open -= 1; // died while idle (server timeout, box restart, …)
            }
            if p.open < self.cfg.max_connections {
                p.open += 1;
                drop(p);
                let r = self
                    .rt
                    .block_on(async { tokio::time::timeout(self.cfg.connect_timeout, self.open_conn()).await })
                    .unwrap_or_else(|_| Err(E::Conn(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))));
                if r.is_err() {
                    self.checkin(None);
                }
                return r;
            }
            p = self.freed.wait(p).unwrap();
        }
    }

    fn checkin(&self, c: Option<Conn>) {
        let mut p = self.pool.lock().unwrap();
        match c {
            Some(c) => p.idle.push(c),
            None => p.open -= 1,
        }
        drop(p);
        self.freed.notify_one();
    }

    /// Runs `op` (which gets the attempt number) on a pooled connection,
    /// retrying on transport errors.
    fn run<T>(&self, mut op: impl FnMut(&Conn, u32) -> R<T>) -> io::Result<T> {
        let mut attempt = 0;
        loop {
            let err = match self.checkout() {
                Err(E::Op(e)) => return Err(e),
                Err(E::Conn(e)) => e,
                Ok(c) => match op(&c, attempt) {
                    Ok(v) => {
                        self.checkin(Some(c));
                        return Ok(v);
                    }
                    Err(E::Op(e)) => {
                        self.checkin(Some(c));
                        return Err(e);
                    }
                    Err(E::Conn(e)) => {
                        drop(c);
                        self.checkin(None);
                        e
                    }
                },
            };
            if attempt >= self.cfg.retries {
                return Err(io::Error::new(err.kind(), format!("sftp {}: {err}", self.cfg.host)));
            }
            std::thread::sleep((self.cfg.backoff * 2u32.saturating_pow(attempt)).min(Duration::from_secs(30)));
            attempt += 1;
        }
    }
}

async fn stat(c: &Conn, path: &str) -> R<Option<FileAttributes>> {
    match c.sftp.stat(path).await.map_err(classify) {
        Ok(a) => Ok(Some(a.attrs)),
        Err(e) if is_not_found(&e) => Ok(None),
        Err(e) => Err(e),
    }
}

/// mkdir -p for the parent of `path`; tolerates directories created concurrently.
async fn mkdir_parents(c: &Conn, path: &str) -> R<()> {
    let Some((parent, _)) = path.rsplit_once('/') else {
        return Ok(());
    };
    let mut cur = String::new();
    for comp in parent.split('/') {
        if !cur.is_empty() || parent.starts_with('/') {
            cur.push('/');
        }
        cur.push_str(comp);
        if comp.is_empty() {
            continue;
        }
        if let Err(e) = c
            .sftp
            .mkdir(cur.clone(), FileAttributes::empty())
            .await
            .map_err(classify)
        {
            match (&e, stat(c, &cur).await?) {
                (E::Op(_), Some(a)) if a.is_dir() => {}
                _ => return Err(e),
            }
        }
    }
    Ok(())
}

async fn close(c: &Conn, handle: String) -> R<()> {
    c.sftp.close(handle).await.map(|_| ()).map_err(classify)
}

/// Reads exactly `len` bytes at `off` (servers may return short reads).
async fn read_exact(c: &Conn, h: &str, mut off: u64, len: u32) -> R<Vec<u8>> {
    let mut out = Vec::with_capacity(len as usize);
    while out.len() < len as usize {
        let want = len - out.len() as u32;
        let d = c.sftp.read(h, off, want).await.map_err(classify)?;
        if d.data.is_empty() {
            return Err(E::Op(io::ErrorKind::UnexpectedEof.into()));
        }
        off += d.data.len() as u64;
        out.extend_from_slice(&d.data);
    }
    Ok(out)
}

impl SftpRemote {
    async fn put_once(&self, c: &Conn, path: &str, data: &[u8], retry: bool) -> R<()> {
        let exists = |a: Option<FileAttributes>| match a {
            // a previous attempt's rename may have landed before the connection broke
            Some(a) if retry && a.size == Some(data.len() as u64) => Ok(()),
            Some(_) => Err(E::Op(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{path} exists (append-only)"),
            ))),
            None => Err(E::Op(io::ErrorKind::NotFound.into())),
        };
        // cheap pre-check: no 64 MiB upload just to fail the rename
        if let Some(a) = stat(c, path).await? {
            return exists(Some(a));
        }
        let tmp = format!("{path}.tmp-{}", unique());
        let flags = OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE | OpenFlags::TRUNCATE;
        let h = match c
            .sftp
            .open(tmp.clone(), flags, FileAttributes::empty())
            .await
            .map_err(classify)
        {
            Err(e) if is_not_found(&e) => {
                mkdir_parents(c, path).await?;
                c.sftp
                    .open(tmp.clone(), flags, FileAttributes::empty())
                    .await
                    .map_err(classify)?
            }
            r => r?,
        }
        .handle;
        let hr = h.as_str();
        let written = async {
            stream::iter(data.chunks(c.chunk as usize).enumerate())
                .map(|(i, part)| {
                    let off = i as u64 * c.chunk as u64;
                    async move { c.sftp.write(hr, off, part.to_vec()).await.map_err(classify) }
                })
                .buffer_unordered(WINDOW)
                .try_for_each(|_| async { Ok(()) })
                .await?;
            if c.fsync {
                c.sftp.fsync(hr).await.map_err(classify)?;
            }
            Ok(())
        }
        .await;
        let closed = close(c, h).await;
        if let Err(e) = written.and(closed) {
            if let E::Op(_) = e {
                let _ = c.sftp.remove(tmp).await;
            }
            return Err(e);
        }
        // Plain SSH_FXP_RENAME (not posix-rename@openssh.com) must not replace an
        // existing target: OpenSSH does link()+unlink(), so exactly one racer wins.
        match c.sftp.rename(tmp.clone(), path).await.map_err(classify) {
            Ok(_) => Ok(()),
            Err(E::Conn(e)) => Err(E::Conn(e)),
            Err(e) => {
                let _ = c.sftp.remove(tmp).await;
                match stat(c, path).await? {
                    Some(a) => exists(Some(a)),
                    None => Err(e),
                }
            }
        }
    }

    async fn get_once(&self, c: &Conn, path: &str, offset: u64, len: Option<u64>) -> R<Vec<u8>> {
        let h = c
            .sftp
            .open(path, OpenFlags::READ, FileAttributes::empty())
            .await
            .map_err(classify)?
            .handle;
        let r = async {
            let end = match len {
                Some(n) => offset
                    .checked_add(n)
                    .ok_or_else(|| E::Op(io::Error::new(io::ErrorKind::InvalidInput, "range overflows")))?,
                None => c
                    .sftp
                    .fstat(h.as_str())
                    .await
                    .map_err(classify)?
                    .attrs
                    .size
                    .unwrap_or(0),
            };
            if end < offset {
                return Err(E::Op(io::ErrorKind::UnexpectedEof.into()));
            }
            let chunk = c.chunk as u64;
            let parts: Vec<Vec<u8>> = stream::iter((offset..end).step_by(chunk as usize))
                .map(|off| read_exact(c, &h, off, (end - off).min(chunk) as u32))
                .buffered(WINDOW)
                .try_collect()
                .await?;
            Ok(parts.concat())
        }
        .await;
        let closed = close(c, h).await;
        let out = r?;
        closed?;
        Ok(out)
    }

    async fn list_once(&self, c: &Conn, dir: &str) -> R<Vec<(String, u64, bool)>> {
        let h = match c.sftp.opendir(dir).await.map_err(classify) {
            Ok(h) => h.handle,
            Err(e) if is_not_found(&e) => return Ok(vec![]),
            Err(e) => return Err(e),
        };
        let mut out = Vec::new();
        let r = loop {
            match c.sftp.readdir(h.as_str()).await {
                Ok(names) => out.extend(
                    names
                        .files
                        .into_iter()
                        .filter(|f| f.filename != "." && f.filename != "..")
                        .map(|f| (f.filename, f.attrs.size.unwrap_or(0), f.attrs.is_dir())),
                ),
                Err(SftpError::Status(s)) if s.status_code == StatusCode::Eof => break Ok(()),
                Err(e) => break Err(classify(e)),
            }
        };
        let closed = close(c, h).await;
        r?;
        closed?;
        out.sort();
        Ok(out)
    }
}

impl Remote for SftpRemote {
    fn put(&self, path: &str, data: &[u8]) -> io::Result<()> {
        check(path)?;
        let full = self.full(path);
        self.run(|c, attempt| self.rt.block_on(self.put_once(c, &full, data, attempt > 0)))
    }

    fn get(&self, path: &str, offset: u64, len: Option<u64>) -> io::Result<Vec<u8>> {
        check(path)?;
        let full = self.full(path);
        self.run(|c, _| self.rt.block_on(self.get_once(c, &full, offset, len)))
    }

    fn list(&self, dir: &str) -> io::Result<Vec<(String, u64, bool)>> {
        let full = if dir.is_empty() {
            if self.base.is_empty() {
                ".".to_owned()
            } else {
                self.base.clone()
            }
        } else {
            check(dir)?;
            self.full(dir)
        };
        self.run(|c, _| self.rt.block_on(self.list_once(c, &full)))
    }

    fn delete(&self, path: &str) -> io::Result<()> {
        check(path)?;
        let full = self.full(path);
        self.run(|c, _| {
            self.rt
                .block_on(c.sftp.remove(full.as_str()))
                .map(|_| ())
                .map_err(classify)
        })
    }

    /// SFTP rmdir: fails on a non-empty directory, never recursive.
    fn remove_dir(&self, dir: &str) -> io::Result<()> {
        check(dir)?;
        let full = self.full(dir);
        self.run(|c, _| {
            self.rt
                .block_on(c.sftp.rmdir(full.as_str()))
                .map(|_| ())
                .map_err(classify)
        })
    }
}
