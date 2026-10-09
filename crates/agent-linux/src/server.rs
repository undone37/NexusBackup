//! Listener, enrollment and the request loop. The agent never initiates connections.

use crate::cache::Cache;
use crate::config::{write_atomic, Paths, Settings};
use crate::glob::Excludes;
use crate::restore::Restore;
use crate::scan::{Locator, Root, Scanner};
use crate::snapshot::{self, Snap};
use crate::{hooks, tls, update, volumes};
use agent_proto::{
    enroll_proof, proof_eq, read_msg, write_msg, Entry, Message, ALPN, EXPORTER_LABEL, MAX_BATCH, VERSION,
};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::collections::{HashMap, HashSet};
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
const MAX_PATHS: usize = 1000;

pub type Stream = StreamOwned<ServerConnection, TcpStream>;

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

pub struct Agent {
    pub paths: Paths,
    pub settings: Settings,
    mode: RwLock<Mode>,
    enroll_lock: Mutex<()>,
    connections: AtomicUsize,
    active_jobs: AtomicUsize,
    /// exit with `RESTART_EXIT_CODE` after a successful self-update (off in tests)
    pub exit_on_update: bool,
}

fn log(msg: impl AsRef<str>) {
    eprintln!("nexus-agent: {}", msg.as_ref());
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

fn error(s: &mut impl Write, code: u32, message: impl Into<String>) -> io::Result<()> {
    write_msg(
        s,
        &Message::Error {
            code,
            message: message.into(),
        },
    )
}

impl Agent {
    pub fn new(paths: Paths, settings: Settings) -> Result<Agent, String> {
        let mode = load_mode(&paths, &settings)?;
        Ok(Agent {
            paths,
            settings,
            mode: RwLock::new(mode),
            enroll_lock: Mutex::new(()),
            connections: AtomicUsize::new(0),
            active_jobs: AtomicUsize::new(0),
            exit_on_update: true,
        })
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

struct Job {
    snaps: Vec<Snap>,
    roots: Vec<Root>,
    excludes: Excludes,
    hooks: bool,
    scan: Option<(Locator, Cache)>,
}

struct Session<'a> {
    agent: &'a Agent,
    agent_id: String,
    appliance: String,
    jobs: HashMap<u64, Job>,
    restore: Option<Restore>,
}

impl Session<'_> {
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
        let (kernel, hostname) = crate::sys::uname();
        write_msg(
            s,
            &Message::HelloReply {
                version: VERSION,
                agent_id: self.agent_id.clone(),
                os: os_name(),
                kernel,
                hostname,
                agent_version: env!("CARGO_PKG_VERSION").into(),
                caps: caps(),
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
                        list: volumes::list_volumes(),
                    },
                )?,
                Message::Prepare {
                    job,
                    paths,
                    excludes,
                    hooks,
                } => self.prepare(s, job, paths, excludes, hooks)?,
                Message::Scan { job, base } => self.scan(s, job, base.map(|b| b.time))?,
                Message::Want { job, hashes } => self.want(s, job, &hashes)?,
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
                    match Restore::begin(job, &target, overwrite, &confirm) {
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
                Message::RestoreEnd => match self.restore.take() {
                    Some(r) => {
                        let target = r.target.clone();
                        let stats = r.end();
                        log(format!(
                            "restore to {}: {} files, {} dirs, {} bytes, {} errors",
                            target.display(),
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
        let mut norm = vec![];
        for p in &paths {
            match volumes::normalize(p) {
                Ok(n) => norm.push(n),
                Err(e) => return error(s, E_BAD_REQUEST, e),
            }
        }
        let mounts = volumes::mounts();
        let mut by_mount: Vec<(volumes::Mount, Vec<PathBuf>)> = vec![];
        for p in norm {
            let Some(m) = volumes::containing(&mounts, &p) else {
                return error(
                    s,
                    E_BAD_REQUEST,
                    format!("{} is not on a mounted file system", p.display()),
                );
            };
            if !volumes::is_data_fs(m) {
                return error(
                    s,
                    E_BAD_REQUEST,
                    format!(
                        "{} is on {} ({}), not a data file system",
                        p.display(),
                        m.mountpoint.display(),
                        m.fstype
                    ),
                );
            }
            match by_mount.iter_mut().find(|(x, _)| x.mountpoint == m.mountpoint) {
                Some((_, v)) => v.push(p),
                None => by_mount.push((m.clone(), vec![p])),
            }
        }
        let mut log_text = String::new();
        let env = [("NEXUS_JOB", job.to_string())];
        if hooks {
            let (ok, l) = self.run_hooks("pre", &env);
            log_text.push_str(&l);
            if !ok {
                let (_, l) = self.run_hooks("post", &[("NEXUS_JOB", job.to_string()), ("NEXUS_SUCCESS", "0".into())]);
                log_text.push_str(&l);
                return error(
                    s,
                    E_REFUSED,
                    format!("pre hook failed, nothing snapshotted:\n{log_text}"),
                );
            }
        }
        let mut snaps = vec![];
        let mut roots = vec![];
        for (idx, (m, mut ps)) in by_mount.into_iter().enumerate() {
            let (snap, note) = snapshot::prepare(&self.agent.paths, &self.agent.settings, job, idx, &m);
            if let Some(n) = note {
                log(&n);
                log_text.push_str(&n);
                log_text.push('\n');
            }
            ps.sort();
            ps.dedup();
            let mut kept: Vec<PathBuf> = vec![];
            for p in ps {
                if !kept.iter().any(|k| p.starts_with(k)) {
                    kept.push(p);
                }
            }
            for p in kept {
                roots.push(Root {
                    src: snapshot::source_path(&snap, &p),
                    host: p,
                    live: !snap.consistent(),
                });
            }
            snaps.push(snap);
        }
        let consistent = snaps.iter().all(Snap::consistent);
        let snapshots = snaps.iter().filter_map(|s| s.info.clone()).collect();
        self.agent.active_jobs.fetch_add(1, Ordering::SeqCst);
        self.jobs.insert(
            job,
            Job {
                snaps,
                roots,
                excludes: Excludes::new(&excludes),
                hooks,
                scan: None,
            },
        );
        log(format!(
            "job {job} prepared ({}consistent)",
            if consistent { "" } else { "NOT " }
        ));
        write_msg(
            s,
            &Message::Prepared {
                job,
                snapshots,
                consistent,
                hook_log: log_text,
            },
        )
    }

    fn run_hooks(&self, phase: &str, env: &[(&str, String)]) -> (bool, String) {
        let a = self.agent;
        hooks::run(
            &a.paths.hooks(),
            phase,
            a.settings.hook_owner,
            Duration::from_secs(a.settings.hook_timeout_secs),
            env,
        )
    }

    fn scan(&mut self, s: &mut Stream, job: u64, base: Option<u64>) -> io::Result<()> {
        let paths = self.agent.paths.clone();
        let spool_max = self.agent.settings.spool_max_bytes;
        let Some(j) = self.jobs.get_mut(&job) else {
            return error(s, E_UNKNOWN_JOB, format!("unknown job {job}"));
        };
        j.scan = None;
        let cache = base.and_then(|_| Cache::load(&paths));
        let live = j.roots.iter().any(|r| r.live);
        let locator = match Locator::new(live.then(|| paths.spool_dir()).as_deref(), spool_max) {
            Ok(l) => l,
            Err(e) => return error(s, E_INTERNAL, format!("spool: {e}")),
        };
        let mut scanner = Scanner::new(&j.excludes, cache.as_ref(), locator, Cache::new(job, base));
        scanner.mountpoints = volumes::mounts()
            .into_iter()
            .map(|m| m.mountpoint)
            .collect::<HashSet<_>>();
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
        scanner.run(&j.roots, &mut emit)?;
        if !batch.is_empty() {
            write_msg(s, &Message::Entries { batch })?;
        }
        let stats = std::mem::take(&mut scanner.stats);
        log(format!(
            "job {job} scanned: {} files, {} dirs, {} bytes, {} read, {} unchanged, {} inconsistent, {} errors, {} chunks, {} spooled",
            stats.files,
            stats.dirs,
            stats.bytes,
            stats.read_bytes,
            stats.unchanged,
            stats.inconsistent,
            stats.errors.len(),
            scanner.locator.chunks(),
            scanner.locator.spooled_bytes()
        ));
        let Scanner { locator, new_cache, .. } = scanner;
        j.scan = Some((locator, new_cache));
        write_msg(s, &Message::ScanDone { stats })
    }

    fn want(&mut self, s: &mut Stream, job: u64, hashes: &[agent_proto::Hash]) -> io::Result<()> {
        let Some((loc, _)) = self.jobs.get_mut(&job).and_then(|j| j.scan.as_mut()) else {
            return error(s, E_UNKNOWN_JOB, format!("job {job} has no scan"));
        };
        let mut missing = vec![];
        for h in hashes {
            match loc.get(h) {
                Some(data) => write_msg(s, &Message::Chunk { hash: *h, data })?,
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

    /// Drop snapshots, run post hooks, commit the cache on success.
    fn release(&mut self, job: u64, success: bool) -> Option<String> {
        let mut j = self.jobs.remove(&job)?;
        let mut text = String::new();
        for snap in &mut j.snaps {
            for e in snap.release(&self.agent.paths) {
                log(&e);
                text.push_str(&format!("snapshot cleanup: {e}\n"));
            }
        }
        if success {
            if let Some((_, cache)) = &j.scan {
                if let Err(e) = cache.commit(&self.agent.paths) {
                    text.push_str(&format!("metadata cache not saved: {e}\n"));
                }
            }
        }
        if j.hooks {
            let (_, l) = self.run_hooks(
                "post",
                &[
                    ("NEXUS_JOB", job.to_string()),
                    ("NEXUS_SUCCESS", if success { "1" } else { "0" }.into()),
                ],
            );
            text.push_str(&l);
        }
        self.agent.active_jobs.fetch_sub(1, Ordering::SeqCst);
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
        let exe = match std::env::current_exe().and_then(fs::canonicalize) {
            Ok(e) => e,
            Err(e) => return error(s, E_INTERNAL, format!("current executable: {e}")),
        };
        let keys = update::load_keys(&self.agent.paths.release_keys());
        match update::apply(version, binary, signature, &keys, env!("CARGO_PKG_VERSION"), &exe) {
            Ok(msg) => {
                log(&msg);
                write_msg(s, &Message::UpdateDone)?;
                if self.agent.exit_on_update {
                    s.conn.send_close_notify();
                    let _ = s.flush();
                    log("restarting into the new version");
                    std::process::exit(update::RESTART_EXIT_CODE);
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

pub fn os_name() -> String {
    let t = fs::read_to_string("/etc/os-release").unwrap_or_default();
    t.lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim_matches('"').to_string())
        .unwrap_or_else(|| "Linux".into())
}

pub fn caps() -> Vec<String> {
    let mut c: Vec<String> = ["fallback", "xattrs", "acl", "hardlinks", "hooks", "restore", "update"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    for (tool, cap) in [("lvcreate", "lvm"), ("zfs", "zfs"), ("btrfs", "btrfs")] {
        if volumes::tool(tool).is_some() {
            c.push(cap.into());
        }
    }
    c
}
