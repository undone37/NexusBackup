//! Listener, enrollment and the protocol session state machine, shared by all agents.
//! The agent never initiates connections. Everything that touches the host (volumes,
//! snapshots, the file system walk, restore writes, installing updates) is behind the
//! [`Platform`] trait.

use crate::cache::Cache;
use crate::chunk::Locator;
use crate::config::{write_atomic, Paths, Settings};
use crate::tls;
use agent_proto::{
    enroll_proof, proof_eq, read_msg, write_msg, Entry, Hash, Message, Overwrite, ScanStats, SnapshotInfo, Volume,
    VssWriter, ALPN, EXPORTER_LABEL, MAX_BATCH, VERSION,
};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

pub const E_BAD_REQUEST: u32 = 400;
pub const E_AUTH: u32 = 401;
pub const E_REFUSED: u32 = 403;
pub const E_UNKNOWN_JOB: u32 = 404;
pub const E_BUSY: u32 = 409;
/// some requested chunks could not be served (fallback file changed after the scan)
pub const E_CHUNKS_GONE: u32 = 410;
pub const E_LOCKED: u32 = 423;
pub const E_VERSION: u32 = 426;
pub const E_INTERNAL: u32 = 500;

pub const MAX_FAILED_PROOFS: u32 = 5;
const BATCH_BYTES: usize = 4 << 20;
/// at most this many paths per `Prepare`
pub const MAX_PATHS: usize = 1000;

pub type Stream = StreamOwned<ServerConnection, TcpStream>;

/// What `HelloReply` reports about the host.
#[derive(Clone, Debug, Default)]
pub struct HostInfo {
    pub os: String,
    pub kernel: String,
    pub hostname: String,
    pub caps: Vec<String>,
    /// the agent binary's version (`CARGO_PKG_VERSION` of the agent crate)
    pub agent_version: String,
}

/// Paths and settings handed to platform calls.
#[derive(Clone, Copy)]
pub struct Ctx<'a> {
    pub paths: &'a Paths,
    pub settings: &'a Settings,
}

/// A request the platform refuses: answered with `Error { code, message }`.
#[derive(Debug)]
pub struct Refused(pub u32, pub String);

/// Result of a successful `Prepare`.
pub struct PreparedJob<J> {
    pub job: J,
    pub snapshots: Vec<SnapshotInfo>,
    pub consistent: bool,
    pub hook_log: String,
    /// structured VSS writer report (Windows), served by `Writers`
    pub writers: Vec<VssWriter>,
}

/// Output of a scan: chunk locations for `Want` and the cache to commit on success.
pub struct ScanOutput {
    pub stats: ScanStats,
    pub locator: Locator,
    pub cache: Cache,
}

pub enum ScanError {
    /// connection broken (abort the session)
    Conn(io::Error),
    /// answer with an error, keep the session
    Refused(Refused),
}

impl From<io::Error> for ScanError {
    fn from(e: io::Error) -> Self {
        ScanError::Conn(e)
    }
}

/// A restore in progress (see [`crate::restore::Stream`]).
pub trait RestoreJob {
    fn entries(&mut self, batch: Vec<Entry>);
    fn chunk(&mut self, hash: Hash, data: &[u8]);
    fn end(self) -> ScanStats;
    fn target(&self) -> String;
}

/// Host-specific half of an agent.
pub trait Platform: Send + Sync + 'static {
    type Job: Send;
    type Restore: RestoreJob + Send;

    fn host_info(&self) -> HostInfo;
    fn list_volumes(&self) -> Vec<Volume>;
    /// Validate paths, run pre hooks / VSS writers, create snapshots.
    fn prepare(
        &self,
        ctx: Ctx,
        job: u64,
        paths: &[String],
        excludes: &[String],
        hooks: bool,
    ) -> Result<PreparedJob<Self::Job>, Refused>;
    /// Walk the prepared roots, emitting entries; `cache` = committed metadata cache
    /// (only when the appliance sent a base).
    fn scan(
        &self,
        ctx: Ctx,
        job: &mut Self::Job,
        id: u64,
        base: Option<u64>,
        cache: Option<&Cache>,
        emit: &mut dyn FnMut(Entry) -> io::Result<()>,
    ) -> Result<ScanOutput, ScanError>;
    /// Drop snapshots (before the cache is committed). Returns log text.
    fn release_snapshots(&self, ctx: Ctx, job: &mut Self::Job, id: u64, success: bool) -> String;
    /// After the cache commit: post hooks etc. Returns log text.
    fn finish_job(&self, ctx: Ctx, job: Self::Job, id: u64, success: bool) -> String;
    fn restore_begin(
        &self,
        ctx: Ctx,
        job: u64,
        target: &str,
        overwrite: Overwrite,
        confirm: &str,
    ) -> io::Result<Self::Restore>;
    /// Verify and install a signed update. Returns a summary.
    fn update(&self, ctx: Ctx, version: &str, binary: &[u8], signature: &[u8]) -> Result<String, String>;
    /// Called after `UpdateDone` was sent (if `exit_on_update`): restart into the new binary.
    fn restart_after_update(&self) -> !;
}

#[derive(Clone)]
pub enum Mode {
    Uninitialized,
    Enroll(Arc<ServerConfig>),
    Locked(Arc<ServerConfig>),
    Mtls {
        config: Arc<ServerConfig>,
        agent_id: String,
    },
}

pub struct Agent<P: Platform> {
    pub platform: P,
    pub paths: Paths,
    pub settings: Settings,
    mode: RwLock<Mode>,
    enroll_lock: Mutex<()>,
    connections: AtomicUsize,
    active_jobs: AtomicUsize,
    /// restart after a successful self-update (off in tests)
    pub exit_on_update: bool,
}

static LOG_TIMESTAMPS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Prefix log lines with a UTC timestamp (log files; journald adds its own).
pub fn log_timestamps(on: bool) {
    LOG_TIMESTAMPS.store(on, Ordering::Relaxed);
}

/// `YYYY-MM-DDTHH:MM:SSZ` for a Unix time.
pub fn utc(secs: u64) -> String {
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    // civil from days (H. Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

pub fn log(msg: impl AsRef<str>) {
    if LOG_TIMESTAMPS.load(Ordering::Relaxed) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        eprintln!("{} nexus-agent: {}", utc(now), msg.as_ref());
    } else {
        eprintln!("nexus-agent: {}", msg.as_ref());
    }
}

pub fn failures(paths: &Paths) -> u32 {
    fs::read_to_string(paths.failures())
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Current mode from the files in the config dir.
pub fn load_mode(paths: &Paths, settings: &Settings) -> Result<Mode, String> {
    let read = |p: PathBuf| fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()));
    if paths.cert().exists() && paths.ca().exists() && paths.agent_id().exists() {
        let config = tls::mtls_config(
            &read(paths.key())?,
            &read(paths.cert())?,
            &read(paths.ca())?,
            settings.appliance_id.clone(),
        )?;
        return Ok(Mode::Mtls {
            config,
            agent_id: read(paths.agent_id())?.trim().to_string(),
        });
    }
    if !paths.token().exists() {
        return Ok(Mode::Uninitialized);
    }
    let cfg = tls::enroll_config(&read(paths.key())?, &read(paths.enroll_cert())?)?;
    Ok(if failures(paths) >= MAX_FAILED_PROOFS {
        Mode::Locked(cfg)
    } else {
        Mode::Enroll(cfg)
    })
}

/// One-line description of a mode (`status` commands).
pub fn describe_mode(paths: &Paths, mode: Result<Mode, String>) -> String {
    match mode {
        Ok(Mode::Uninitialized) => "not initialised (run nexus-agent init --token <T>)".to_string(),
        Ok(Mode::Enroll(_)) => format!("enrollment pending ({} failed proofs)", failures(paths)),
        Ok(Mode::Locked(_)) => "LOCKED after failed enrollment proofs; run nexus-agent init again".to_string(),
        Ok(Mode::Mtls { agent_id, .. }) => format!("enrolled as {agent_id}"),
        Err(e) => format!("error: {e}"),
    }
}

pub fn error(s: &mut impl Write, code: u32, message: impl Into<String>) -> io::Result<()> {
    write_msg(
        s,
        &Message::Error {
            code,
            message: message.into(),
        },
    )
}

impl<P: Platform + Default> Agent<P> {
    pub fn new(paths: Paths, settings: Settings) -> Result<Agent<P>, String> {
        Agent::with_platform(P::default(), paths, settings)
    }
}

impl<P: Platform> Agent<P> {
    pub fn with_platform(platform: P, paths: Paths, settings: Settings) -> Result<Agent<P>, String> {
        let mode = load_mode(&paths, &settings)?;
        Ok(Agent {
            platform,
            paths,
            settings,
            mode: RwLock::new(mode),
            enroll_lock: Mutex::new(()),
            connections: AtomicUsize::new(0),
            active_jobs: AtomicUsize::new(0),
            exit_on_update: true,
        })
    }

    fn ctx(&self) -> Ctx<'_> {
        Ctx {
            paths: &self.paths,
            settings: &self.settings,
        }
    }

    pub fn mode(&self) -> Mode {
        self.mode.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn set_mode(&self, m: Mode) {
        *self.mode.write().unwrap_or_else(|e| e.into_inner()) = m;
    }

    /// Accept loop: one thread per connection, at most `max_connections`.
    pub fn serve(self: Arc<Self>, listener: TcpListener) -> io::Result<()> {
        for conn in listener.incoming() {
            let tcp = match conn {
                Ok(t) => t,
                Err(e) => {
                    log(format!("accept: {e}"));
                    continue;
                }
            };
            if self.connections.fetch_add(1, Ordering::SeqCst) >= self.settings.max_connections {
                self.connections.fetch_sub(1, Ordering::SeqCst);
                drop(tcp);
                continue;
            }
            let me = self.clone();
            std::thread::spawn(move || {
                let peer = tcp.peer_addr().map(|a| a.to_string()).unwrap_or_default();
                if let Err(e) = me.handle(tcp) {
                    if e.kind() != io::ErrorKind::UnexpectedEof {
                        log(format!("connection from {peer}: {e}"));
                    }
                }
                me.connections.fetch_sub(1, Ordering::SeqCst);
            });
        }
        Ok(())
    }

    pub fn handle(&self, tcp: TcpStream) -> io::Result<()> {
        tcp.set_read_timeout(Some(Duration::from_secs(3600)))?;
        tcp.set_write_timeout(Some(Duration::from_secs(600)))?;
        tcp.set_nodelay(true)?;
        let mode = self.mode();
        let cfg = match &mode {
            Mode::Uninitialized => return Ok(()),
            Mode::Enroll(c) | Mode::Locked(c) => c.clone(),
            Mode::Mtls { config, .. } => config.clone(),
        };
        let conn = ServerConnection::new(cfg).map_err(io::Error::other)?;
        let mut s = StreamOwned::new(conn, tcp);
        while s.conn.is_handshaking() {
            s.conn.complete_io(&mut s.sock)?;
        }
        if s.conn.alpn_protocol() != Some(ALPN) {
            return Err(io::Error::other("client did not negotiate ALPN nexus-agent/1"));
        }
        let r = match mode {
            Mode::Uninitialized => Ok(()),
            Mode::Locked(_) => error(
                &mut s,
                E_LOCKED,
                "enrollment locked after too many failed proofs; run nexus-agent init again",
            ),
            Mode::Enroll(_) => self.enroll(&mut s),
            Mode::Mtls { agent_id, .. } => {
                let id = s
                    .conn
                    .peer_certificates()
                    .and_then(|c| c.first())
                    .map(|c| tls::appliance_id(c, self.settings.appliance_id.as_deref()))
                    .transpose()
                    .map_err(io::Error::other)?
                    .ok_or_else(|| io::Error::other("no client certificate"))?;
                let mut sess = Session {
                    agent: self,
                    agent_id,
                    appliance: id,
                    jobs: HashMap::new(),
                    restore: None,
                };
                let r = sess.run(&mut s);
                sess.abort_all();
                r
            }
        };
        s.conn.send_close_notify();
        let _ = s.flush();
        r
    }

    fn enroll(&self, s: &mut Stream) -> io::Result<()> {
        let _g = self.enroll_lock.lock().unwrap_or_else(|e| e.into_inner());
        if !matches!(self.mode(), Mode::Enroll(_)) {
            return error(s, E_LOCKED, "not in enrollment mode");
        }
        let token = fs::read_to_string(self.paths.token())?.trim().to_string();
        let mut ex = [0u8; 32];
        s.conn
            .export_keying_material(&mut ex, EXPORTER_LABEL, None)
            .map_err(io::Error::other)?;
        let Message::Enroll { proof } = read_msg(s)? else {
            return error(s, E_BAD_REQUEST, "expected Enroll");
        };
        if !proof_eq(&proof, &enroll_proof(&token, "appliance", &ex)) {
            let n = failures(&self.paths) + 1;
            write_atomic(&self.paths.failures(), n.to_string().as_bytes(), 0o600)?;
            log(format!("enrollment proof rejected ({n}/{MAX_FAILED_PROOFS})"));
            if n >= MAX_FAILED_PROOFS {
                log("enrollment locked; run `nexus-agent init --token <T>` again");
                if let Ok(m) = load_mode(&self.paths, &self.settings) {
                    self.set_mode(m);
                }
            }
            return error(s, E_AUTH, "enrollment proof rejected");
        }
        let key = fs::read_to_string(self.paths.key())?;
        let csr_pem = tls::csr(&key).map_err(io::Error::other)?;
        write_msg(
            s,
            &Message::EnrollReply {
                proof: enroll_proof(&token, "agent", &ex),
                csr_pem,
            },
        )?;
        let Message::EnrollDone {
            cert_pem,
            ca_pem,
            agent_id,
        } = read_msg(s)?
        else {
            return error(s, E_BAD_REQUEST, "expected EnrollDone");
        };
        if let Err(e) = tls::check_issued(&key, &cert_pem, &ca_pem, &agent_id) {
            log(format!("enrollment: issued certificate rejected: {e}"));
            return error(s, E_BAD_REQUEST, e);
        }
        write_atomic(&self.paths.cert(), cert_pem.as_bytes(), 0o644)?;
        write_atomic(&self.paths.ca(), ca_pem.as_bytes(), 0o644)?;
        write_atomic(&self.paths.agent_id(), agent_id.as_bytes(), 0o644)?;
        fs::remove_file(self.paths.token())?;
        let _ = fs::remove_file(self.paths.failures());
        let m = load_mode(&self.paths, &self.settings).map_err(io::Error::other)?;
        self.set_mode(m);
        log(format!("enrolled as agent {agent_id}; token deleted, mTLS mode active"));
        Ok(())
    }
}

struct Job<J> {
    inner: J,
    writers: Vec<VssWriter>,
    scan: Option<(Locator, Cache)>,
}

struct Session<'a, P: Platform> {
    agent: &'a Agent<P>,
    agent_id: String,
    appliance: String,
    jobs: HashMap<u64, Job<P::Job>>,
    restore: Option<P::Restore>,
}

impl<P: Platform> Session<'_, P> {
    fn run(&mut self, s: &mut Stream) -> io::Result<()> {
        match read_msg(s)? {
            Message::Hello { version } if version == VERSION => {}
            Message::Hello { version } => {
                return error(
                    s,
                    E_VERSION,
                    format!("protocol version {version} not supported (agent speaks {VERSION})"),
                )
            }
            _ => return error(s, E_BAD_REQUEST, "expected Hello"),
        }
        let info = self.agent.platform.host_info();
        write_msg(
            s,
            &Message::HelloReply {
                version: VERSION,
                agent_id: self.agent_id.clone(),
                os: info.os,
                kernel: info.kernel,
                hostname: info.hostname,
                agent_version: info.agent_version,
                caps: {
                    let mut c = info.caps;
                    if !c.iter().any(|x| x == agent_proto::CAP_LZ4) {
                        c.push(agent_proto::CAP_LZ4.into()); // wire compression lives in the shared core
                    }
                    c
                },
            },
        )?;
        log(format!("session with appliance {}", self.appliance));
        loop {
            let m = match read_msg(s) {
                Ok(m) => m,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
            };
            match m {
                Message::ListVolumes => write_msg(
                    s,
                    &Message::Volumes {
                        list: self.agent.platform.list_volumes(),
                    },
                )?,
                Message::Prepare {
                    job,
                    paths,
                    excludes,
                    hooks,
                } => self.prepare(s, job, paths, excludes, hooks)?,
                Message::Writers { job } => match self.jobs.get(&job) {
                    Some(j) => write_msg(
                        s,
                        &Message::WritersReport {
                            job,
                            writers: j.writers.clone(),
                        },
                    )?,
                    None => error(s, E_UNKNOWN_JOB, format!("unknown job {job}"))?,
                },
                Message::Scan { job, base } => self.scan(s, job, base.map(|b| b.time))?,
                Message::Want { job, hashes } => self.want(s, job, &hashes, false)?,
                Message::WantLz4 { job, hashes } => self.want(s, job, &hashes, true)?,
                Message::Release { job, success } => match self.release(job, success) {
                    Some(hook_log) => write_msg(s, &Message::Released { job, hook_log })?,
                    None => error(s, E_UNKNOWN_JOB, format!("unknown job {job}"))?,
                },
                Message::RestoreBegin {
                    job,
                    target,
                    overwrite,
                    confirm,
                } => {
                    if self.restore.is_some() {
                        error(s, E_BUSY, "a restore is already running on this connection")?;
                        continue;
                    }
                    match self
                        .agent
                        .platform
                        .restore_begin(self.agent.ctx(), job, &target, overwrite, &confirm)
                    {
                        Ok(r) => {
                            self.restore = Some(r);
                            write_msg(s, &Message::RestoreReady)?
                        }
                        Err(e) => error(s, E_REFUSED, e.to_string())?,
                    }
                }
                Message::RestoreEntries { batch } => match self.restore.as_mut() {
                    Some(r) => r.entries(batch),
                    None => return error(s, E_BAD_REQUEST, "RestoreEntries without RestoreBegin"),
                },
                Message::RestoreChunk { hash, data } => match self.restore.as_mut() {
                    Some(r) => r.chunk(hash, &data),
                    None => return error(s, E_BAD_REQUEST, "RestoreChunk without RestoreBegin"),
                },
                Message::RestoreChunkLz4 { hash, raw_len, data } => match self.restore.as_mut() {
                    Some(r) => match agent_proto::lz4_unpack(&data, raw_len) {
                        Ok(raw) => r.chunk(hash, &raw), // the restore verifies the hash
                        Err(e) => return error(s, E_BAD_REQUEST, e.to_string()),
                    },
                    None => return error(s, E_BAD_REQUEST, "RestoreChunkLz4 without RestoreBegin"),
                },
                Message::RestoreEnd => match self.restore.take() {
                    Some(r) => {
                        let target = r.target();
                        let stats = r.end();
                        log(format!(
                            "restore to {target}: {} files, {} dirs, {} bytes, {} errors",
                            stats.files,
                            stats.dirs,
                            stats.bytes,
                            stats.errors.len()
                        ));
                        write_msg(s, &Message::RestoreDone { stats })?
                    }
                    None => return error(s, E_BAD_REQUEST, "RestoreEnd without RestoreBegin"),
                },
                Message::Update {
                    version,
                    binary,
                    signature,
                } => self.update(s, &version, &binary, &signature)?,
                other => return error(s, E_BAD_REQUEST, format!("unexpected message {}", msg_name(&other))),
            }
        }
    }

    fn prepare(
        &mut self,
        s: &mut Stream,
        job: u64,
        paths: Vec<String>,
        excludes: Vec<String>,
        hooks: bool,
    ) -> io::Result<()> {
        if self.jobs.contains_key(&job) {
            return error(s, E_BUSY, format!("job {job} already prepared"));
        }
        if paths.is_empty() || paths.len() > MAX_PATHS {
            return error(s, E_BAD_REQUEST, "1 to 1000 paths required");
        }
        let p = match self
            .agent
            .platform
            .prepare(self.agent.ctx(), job, &paths, &excludes, hooks)
        {
            Ok(p) => p,
            Err(Refused(code, msg)) => return error(s, code, msg),
        };
        self.agent.active_jobs.fetch_add(1, Ordering::SeqCst);
        self.jobs.insert(
            job,
            Job {
                inner: p.job,
                writers: p.writers,
                scan: None,
            },
        );
        log(format!(
            "job {job} prepared ({}consistent)",
            if p.consistent { "" } else { "NOT " }
        ));
        write_msg(
            s,
            &Message::Prepared {
                job,
                snapshots: p.snapshots,
                consistent: p.consistent,
                hook_log: p.hook_log,
            },
        )
    }

    fn scan(&mut self, s: &mut Stream, job: u64, base: Option<u64>) -> io::Result<()> {
        let agent = self.agent;
        let Some(j) = self.jobs.get_mut(&job) else {
            return error(s, E_UNKNOWN_JOB, format!("unknown job {job}"));
        };
        j.scan = None;
        let cache = base.and_then(|_| Cache::load(&agent.paths));
        let mut batch: Vec<Entry> = vec![];
        let mut bytes = 0usize;
        let mut emit = |e: Entry| -> io::Result<()> {
            bytes += 96
                + e.path.len()
                + e.link_target.as_ref().map_or(0, Vec::len)
                + e.chunks.len() * 40
                + e.xattrs.iter().map(|(k, v)| k.len() + v.len() + 8).sum::<usize>();
            batch.push(e);
            if batch.len() >= MAX_BATCH / 10 || bytes >= BATCH_BYTES {
                write_msg(
                    s,
                    &Message::Entries {
                        batch: std::mem::take(&mut batch),
                    },
                )?;
                bytes = 0;
            }
            Ok(())
        };
        let out = agent
            .platform
            .scan(agent.ctx(), &mut j.inner, job, base, cache.as_ref(), &mut emit);
        let out = match out {
            Ok(o) => o,
            Err(ScanError::Conn(e)) => return Err(e),
            Err(ScanError::Refused(Refused(code, msg))) => return error(s, code, msg),
        };
        if !batch.is_empty() {
            write_msg(s, &Message::Entries { batch })?;
        }
        let ScanOutput { stats, locator, cache } = out;
        log(format!(
            "job {job} scanned: {} files, {} dirs, {} bytes, {} read, {} unchanged, {} inconsistent, {} errors, {} chunks, {} spooled",
            stats.files,
            stats.dirs,
            stats.bytes,
            stats.read_bytes,
            stats.unchanged,
            stats.inconsistent,
            stats.errors.len(),
            locator.chunks(),
            locator.spooled_bytes()
        ));
        j.scan = Some((locator, cache));
        write_msg(s, &Message::ScanDone { stats })
    }

    /// `lz4`: the appliance asked via `WantLz4`; compressible chunks go as `ChunkLz4`
    /// (one fast attempt per chunk, a single extra buffer at a time).
    fn want(&mut self, s: &mut Stream, job: u64, hashes: &[Hash], lz4: bool) -> io::Result<()> {
        let Some((loc, _)) = self.jobs.get_mut(&job).and_then(|j| j.scan.as_mut()) else {
            return error(s, E_UNKNOWN_JOB, format!("job {job} has no scan"));
        };
        let mut missing = vec![];
        for h in hashes {
            match loc.get(h) {
                Some(data) => match lz4.then(|| agent_proto::lz4_pack(&data)).flatten() {
                    Some(c) => write_msg(
                        s,
                        &Message::ChunkLz4 {
                            hash: *h,
                            raw_len: data.len() as u32,
                            data: c,
                        },
                    )?,
                    None => write_msg(s, &Message::Chunk { hash: *h, data })?,
                },
                None => missing.push(hex::encode(h)),
            }
        }
        if missing.is_empty() {
            write_msg(s, &Message::WantDone)
        } else {
            let n = missing.len();
            missing.truncate(16);
            error(
                s,
                E_CHUNKS_GONE,
                format!(
                    "{n} chunk(s) unavailable (file changed or unknown): {}",
                    missing.join(",")
                ),
            )
        }
    }

    /// Drop snapshots, commit the cache on success, run post hooks.
    fn release(&mut self, job: u64, success: bool) -> Option<String> {
        let mut j = self.jobs.remove(&job)?;
        let (agent, ctx) = (self.agent, self.agent.ctx());
        // the locator keeps the last read file open: close it before the snapshots go,
        // or the snapshot stays busy (Linux: lazy umount, then lvremove fails with
        // "contains a filesystem in use"; found in the lab on Debian 13)
        let cache = j.scan.take().map(|(locator, cache)| {
            drop(locator);
            cache
        });
        let mut text = agent.platform.release_snapshots(ctx, &mut j.inner, job, success);
        if success {
            if let Some(cache) = &cache {
                if let Err(e) = cache.commit(&agent.paths) {
                    text.push_str(&format!("metadata cache not saved: {e}\n"));
                }
            }
        }
        text.push_str(&agent.platform.finish_job(ctx, j.inner, job, success));
        agent.active_jobs.fetch_sub(1, Ordering::SeqCst);
        log(format!("job {job} released (success={success})"));
        Some(text)
    }

    /// Connection gone: never leave snapshots behind.
    fn abort_all(&mut self) {
        let jobs: Vec<u64> = self.jobs.keys().copied().collect();
        for j in jobs {
            log(format!(
                "job {j}: connection closed without Release, releasing as failed"
            ));
            self.release(j, false);
        }
        if let Some(r) = self.restore.take() {
            log("restore aborted by disconnect");
            r.end();
        }
    }

    fn update(&mut self, s: &mut Stream, version: &str, binary: &[u8], signature: &[u8]) -> io::Result<()> {
        if self.agent.active_jobs.load(Ordering::SeqCst) > 0 || self.restore.is_some() {
            return error(s, E_BUSY, "jobs are running; update refused");
        }
        match self.agent.platform.update(self.agent.ctx(), version, binary, signature) {
            Ok(msg) => {
                log(&msg);
                write_msg(s, &Message::UpdateDone)?;
                if self.agent.exit_on_update {
                    s.conn.send_close_notify();
                    let _ = s.flush();
                    log("restarting into the new version");
                    self.agent.platform.restart_after_update();
                }
                Ok(())
            }
            Err(e) => {
                log(format!("update refused: {e}"));
                error(s, E_REFUSED, e)
            }
        }
    }
}

fn msg_name(m: &Message) -> &'static str {
    match m {
        Message::Enroll { .. } | Message::EnrollReply { .. } | Message::EnrollDone { .. } => "Enroll*",
        Message::Hello { .. } => "Hello",
        Message::Error { .. } => "Error",
        _ => "(agent-to-appliance message)",
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn utc_format() {
        assert_eq!(super::utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(super::utc(1_609_459_200), "2021-01-01T00:00:00Z");
        assert_eq!(super::utc(951_782_400 + 3_723), "2000-02-29T01:02:03Z");
    }
}
