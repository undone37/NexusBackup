//! Starting a plugin process (docs/plugin-system.md "Sandbox", docs/plugin-sdk.md).
//!
//! The host verifies the installed binary (SHA-256 of the opened file = catalog
//! record, `manifest.json` = catalog manifest), prepares everything that needs
//! memory (Landlock ruleset, seccomp programs, argv/envp) and forks. The child
//! only makes system calls, in this order:
//!
//! 1. `PR_SET_PDEATHSIG(SIGKILL)` (dies with the host), own process group;
//! 2. nice 10; rlimits: `RLIMIT_DATA` = memory, `RLIMIT_AS` = 4 × memory,
//!    `RLIMIT_FSIZE` = tmp size, `RLIMIT_CPU` = op time limit, `RLIMIT_NOFILE`, no core;
//! 3. best effort: new user + IPC namespace with the own uid mapped (not on the
//!    appliance: the scheduler unit has `RestrictNamespaces=yes`; the plugin then
//!    simply runs as the job uid);
//! 4. `PR_SET_NO_NEW_PRIVS`; Landlock (read/exec: install dir, /usr, /lib*, /bin,
//!    /sbin; read: a few files under /etc + the CA stores; rw: /dev/null|zero|urandom
//!    and the private tmp dir; TCP connect only to the manifest's endpoint ports and
//!    53; no TCP bind; signals and abstract Unix sockets scoped to the sandbox);
//! 5. seccomp allowlist ([`crate::seccomp`]);
//! 6. `execveat(fd, "", AT_EMPTY_PATH)` of the verified binary (no path race), with a
//!    cleared environment (`PATH`, `HOME`=`TMPDIR`=tmp dir, `LANG=C.UTF-8`). On the
//!    appliance the exec type `nexus_plugin_exec_t` moves it into `nexus_plugin_t`.
//!
//! The private tmp dir (0700) is watched: more than `tmp_mb` in it kills the plugin.

use crate::landlock::{self, Ruleset};
use crate::{escape, seccomp};
use anyhow::{bail, Context, Result};
use plugin_proto::{read_msg, write_msg, Message};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Resource limits of one plugin process.
#[derive(Clone, Debug)]
pub struct Limits {
    pub memory_mb: u64,
    pub tmp_mb: u64,
    /// RLIMIT_CPU (seconds of CPU time)
    pub cpu_secs: u64,
    pub nofile: u64,
}

impl Limits {
    /// From the manifest's `sandbox` object (defaults: 1 GiB memory, 1 GiB tmp), clamped.
    pub fn from_manifest(sandbox: Option<&serde_json::Value>, cpu_secs: u64) -> Limits {
        let get = |k: &str, def: u64, max: u64| sandbox.and_then(|s| s[k].as_u64()).unwrap_or(def).clamp(16, max);
        Limits {
            memory_mb: get("memory_mb", 1024, 64 << 10),
            tmp_mb: get("tmp_mb", 1024, 1 << 20),
            cpu_secs: cpu_secs.max(1),
            nofile: 1024,
        }
    }
}

/// How to sandbox (host-side settings, not from the plugin).
#[derive(Clone, Debug)]
pub struct Options {
    /// parent of the private tmp dirs (the scheduler's private /tmp on the appliance)
    pub tmp_base: PathBuf,
    /// refuse to run without Landlock (default; tests on old kernels may turn it off)
    pub require_landlock: bool,
    /// try a user + IPC namespace
    pub userns: bool,
    /// extra read-only paths (tests / lab only: the example plugin reads a local dir)
    pub read_paths: Vec<PathBuf>,
    /// extra writable paths (tests only: restore targets)
    pub write_paths: Vec<PathBuf>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            tmp_base: std::env::temp_dir(),
            require_landlock: true,
            userns: true,
            read_paths: Vec::new(),
            write_paths: Vec::new(),
        }
    }
}

/// What to start.
#[derive(Clone, Debug)]
pub struct Spec {
    /// `/var/lib/nexus/plugins/<id>/<version>`
    pub dir: PathBuf,
    /// expected SHA-256 (hex) of `bin/plugin` (catalog `plugins.bin_sha256`)
    pub bin_sha256: String,
    /// expected `manifest.json` (catalog `plugins.manifest`); None = not checked (tests)
    pub manifest: Option<String>,
    /// TCP ports the plugin may connect to; None = no network restriction by Landlock
    pub tcp_ports: Option<Vec<u16>>,
    pub limits: Limits,
    pub job: u64,
}

/// Read (system) paths every plugin gets; missing ones are skipped.
const SYSTEM_RX: &[&str] = &["/usr", "/lib", "/lib64", "/bin", "/sbin"];
const SYSTEM_R: &[&str] = &[
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/host.conf",
    "/etc/nsswitch.conf",
    "/etc/gai.conf",
    "/etc/services",
    "/etc/protocols",
    "/etc/localtime",
    "/etc/passwd",
    "/etc/group",
    "/etc/ssl",
    "/etc/pki/tls",
    "/etc/pki/ca-trust",
    "/etc/crypto-policies",
    "/etc/alternatives",
    "/sys/devices/system/cpu",
];
const SYSTEM_RW: &[&str] = &["/dev/null", "/dev/zero", "/dev/urandom", "/dev/random", "/dev/full"];

/// Summary of the applied sandbox (logged into the job log).
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub landlock_abi: u32,
    pub tcp_restricted: bool,
    pub scoped: bool,
    pub tmp: PathBuf,
    pub limits: String,
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "sandbox: landlock ABI {}{}{}, seccomp allowlist, no_new_privs, {}, tmp {}",
            self.landlock_abi,
            if self.tcp_restricted {
                " (tcp ports)"
            } else {
                " (no tcp port rules)"
            },
            if self.scoped {
                " (scoped signals/abstract sockets)"
            } else {
                ""
            },
            self.limits,
            self.tmp.display()
        )
    }
}

/// Opens `bin/plugin` without following symlinks and checks its SHA-256 on the open file.
fn open_verified(dir: &Path, want: &str) -> Result<File> {
    let p = dir.join("bin/plugin");
    let mut f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&p)
        .with_context(|| format!("{}", p.display()))?;
    let m = f.metadata()?;
    if !m.is_file() {
        bail!("{} is not a regular file", p.display());
    }
    if m.mode() & 0o022 != 0 {
        bail!("{} is group/world writable", p.display());
    }
    let mut h = Sha256::new();
    io::copy(&mut f, &mut h)?;
    let got: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    if !want.eq_ignore_ascii_case(&got) {
        bail!(
            "installed plugin binary {} does not match the catalog (sha256 {got}, expected {want})",
            p.display()
        );
    }
    Ok(f)
}

struct Prepared {
    ruleset: Option<Ruleset>,
    seccomp: Vec<seccompiler::BpfProgram>,
    argv: Vec<CString>,
    envp: Vec<CString>,
    uid_map: CString,
    gid_map: CString,
    rlimits: Vec<(libc::__rlimit_resource_t, u64)>,
}

fn prepare(spec: &Spec, opts: &Options, tmp: &Path) -> Result<(Prepared, Report)> {
    let mut report = Report {
        tmp: tmp.to_owned(),
        limits: format!(
            "memory {} MiB, tmp {} MiB, cpu {} s",
            spec.limits.memory_mb, spec.limits.tmp_mb, spec.limits.cpu_secs
        ),
        ..Default::default()
    };
    let ruleset = match Ruleset::new(spec.tcp_ports.is_some()) {
        Ok(mut r) => {
            let rx = landlock::READ_EXEC;
            let rw = (1u64 << 16) - 1; // everything the ABI knows (masked per ABI)
            r.allow_path(&spec.dir, rx)?;
            for p in SYSTEM_RX {
                r.allow_path(Path::new(p), rx)?;
            }
            for p in SYSTEM_R {
                r.allow_path(Path::new(p), landlock::READ)?;
            }
            for p in SYSTEM_RW {
                r.allow_path(Path::new(p), landlock::FS_READ_FILE | landlock::FS_WRITE_FILE)?;
            }
            for p in &opts.read_paths {
                r.allow_path(p, landlock::READ)?;
            }
            for p in &opts.write_paths {
                r.allow_path(p, rw)?;
            }
            r.allow_path(tmp, rw)?;
            if let Some(ports) = &spec.tcp_ports {
                for p in ports.iter().chain(&[53]) {
                    r.allow_connect(*p)?;
                }
            }
            report.landlock_abi = r.abi;
            report.tcp_restricted = r.net;
            report.scoped = r.scoped;
            Some(r)
        }
        Err(e) if opts.require_landlock => {
            return Err(e).context("sandbox: Landlock is required (sandbox.require_landlock)");
        }
        Err(_) => None,
    };
    let seccomp = seccomp::programs().map_err(anyhow::Error::msg)?;
    let tmp_s = tmp.to_string_lossy();
    let envp = [
        "PATH=/usr/local/bin:/usr/bin:/bin".to_owned(),
        format!("HOME={tmp_s}"),
        format!("TMPDIR={tmp_s}"),
        "LANG=C.UTF-8".to_owned(),
        format!("NEXUS_PLUGIN_JOB={}", spec.job),
    ]
    .into_iter()
    .map(CString::new)
    .collect::<Result<Vec<_>, _>>()?;
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let m = &spec.limits;
    Ok((
        Prepared {
            ruleset,
            seccomp,
            argv: vec![CString::new("plugin")?],
            envp,
            uid_map: CString::new(format!("{uid} {uid} 1"))?,
            gid_map: CString::new(format!("{gid} {gid} 1"))?,
            rlimits: vec![
                (libc::RLIMIT_DATA, m.memory_mb << 20),
                (libc::RLIMIT_AS, (m.memory_mb << 22).max(4 << 30)),
                (libc::RLIMIT_FSIZE, m.tmp_mb << 20),
                (libc::RLIMIT_CPU, m.cpu_secs),
                (libc::RLIMIT_NOFILE, m.nofile),
                (libc::RLIMIT_CORE, 0),
            ],
        },
        report,
    ))
}

/// Async-signal-safe write of a whole buffer to a path (uid_map etc.).
unsafe fn write_file(path: &[u8], data: &[u8]) -> bool {
    let fd = libc::open(path.as_ptr().cast(), libc::O_WRONLY | libc::O_CLOEXEC);
    if fd < 0 {
        return false;
    }
    let ok = libc::write(fd, data.as_ptr().cast(), data.len()) == data.len() as isize;
    libc::close(fd);
    ok
}

/// Messages and errors from the plugin's stdout.
type Inbox = Receiver<Result<Message, String>>;

/// Reader thread: frames from `r` (validated by `plugin_proto::read_msg`).
pub(crate) fn reader_thread(r: impl Read + Send + 'static) -> Inbox {
    let (tx, rx) = mpsc::sync_channel(4);
    std::thread::spawn(move || {
        let mut r = io::BufReader::with_capacity(1 << 16, r);
        loop {
            let m = read_msg(&mut r);
            let end = m.is_err();
            if tx
                .send(m.map_err(|e| match e.kind() {
                    io::ErrorKind::UnexpectedEof => "EOF".to_owned(),
                    _ => e.to_string(),
                }))
                .is_err()
                || end
            {
                break;
            }
        }
    });
    rx
}

/// The host's side of a plugin connection.
pub trait Peer {
    fn send(&mut self, m: &Message) -> Result<()>;
    /// Next message; fails (and stops the plugin) on EOF, invalid frames and timeouts.
    fn recv(&mut self) -> Result<Message>;
    /// Next message within `wait` (None after `wait`; the plugin keeps running);
    /// EOF, invalid frames and the op deadline fail as in [`Peer::recv`].
    fn poll(&mut self, wait: Duration) -> Result<Option<Message>>;
    /// Idle limit between two messages (None: only the op deadline, e.g. while mounted).
    fn set_idle(&mut self, idle: Option<Duration>);
    /// Protocol violation: stop the plugin, return the error to propagate.
    fn violation(&mut self, why: &str) -> anyhow::Error;
    /// Plugin finished (Done sent): let it exit, kill it after a short grace period.
    fn finish(&mut self);
}

/// Common timeouts + inbox handling for [`PluginProc`] and the in-process peer.
pub(crate) struct Conn {
    pub inbox: Inbox,
    pub out: Box<dyn Write + Send>,
    pub deadline: Instant,
    pub idle: Option<Duration>,
}

impl Conn {
    pub(crate) fn recv(&mut self) -> Result<Message, String> {
        let now = Instant::now();
        if now >= self.deadline {
            return Err("time limit of the operation exceeded".into());
        }
        let left = self.deadline - now;
        let wait = self.idle.map_or(left, |i| i.min(left));
        match self.inbox.recv_timeout(wait) {
            Ok(Ok(m)) => Ok(m),
            Ok(Err(e)) if e == "EOF" => Err("plugin closed its output (exited) before finishing".into()),
            Ok(Err(e)) => Err(format!("invalid message: {e}")),
            Err(RecvTimeoutError::Timeout) if Instant::now() >= self.deadline => {
                Err("time limit of the operation exceeded".into())
            }
            Err(RecvTimeoutError::Timeout) => Err(format!(
                "no message for {} s (idle limit)",
                self.idle.unwrap_or_default().as_secs()
            )),
            Err(RecvTimeoutError::Disconnected) => Err("plugin connection lost".into()),
        }
    }
    pub(crate) fn poll(&mut self, wait: Duration) -> Result<Option<Message>, String> {
        let now = Instant::now();
        if now >= self.deadline {
            return Err("time limit of the operation exceeded".into());
        }
        match self.inbox.recv_timeout(wait.min(self.deadline - now)) {
            Ok(Ok(m)) => Ok(Some(m)),
            Ok(Err(e)) if e == "EOF" => Err("plugin closed its output (exited) before finishing".into()),
            Ok(Err(e)) => Err(format!("invalid message: {e}")),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err("plugin connection lost".into()),
        }
    }
    pub(crate) fn send(&mut self, m: &Message) -> io::Result<()> {
        write_msg(&mut self.out, m)
    }
}

/// A sandboxed plugin process.
pub struct PluginProc {
    child: Child,
    conn: Conn,
    tmp: PathBuf,
    over_quota: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    pub report: Report,
}

/// Escaped, bounded copy of the plugin's stderr into the host's stdout (job log).
fn stderr_thread(r: impl Read + Send + 'static) {
    std::thread::spawn(move || {
        let mut left: usize = 1 << 20;
        let mut r = BufReader::new(r.take(64 << 20));
        let mut line = Vec::new();
        loop {
            line.clear();
            match r.read_until(b'\n', &mut line) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if left == 0 {
                        continue;
                    }
                    left = left.saturating_sub(n);
                    let s = String::from_utf8_lossy(&line);
                    crate::log_line(&format!("plugin stderr: {}", escape(s.trim_end_matches('\n'), 2000)));
                    if left == 0 {
                        crate::log_line("plugin stderr: [… further output dropped …]");
                    }
                }
            }
        }
    });
}

fn dir_usage(p: &Path, budget: &mut u32) -> u64 {
    let Ok(rd) = fs::read_dir(p) else { return 0 };
    let mut n = 0;
    for e in rd.flatten() {
        if *budget == 0 {
            break;
        }
        *budget -= 1;
        if let Ok(m) = e.metadata() {
            n += m.blocks() * 512;
            if m.is_dir() {
                n += dir_usage(&e.path(), budget);
            }
        }
    }
    n
}

impl PluginProc {
    /// Verifies and starts the plugin in its sandbox.
    pub fn spawn(spec: &Spec, opts: &Options, op_timeout: Duration, idle: Option<Duration>) -> Result<PluginProc> {
        if let Some(want) = &spec.manifest {
            let p = spec.dir.join("manifest.json");
            let got = fs::read(&p).with_context(|| format!("{}", p.display()))?;
            if got != want.as_bytes() {
                bail!("installed {} does not match the catalog", p.display());
            }
        }
        let bin = open_verified(&spec.dir, &spec.bin_sha256)?;
        let tmp = opts
            .tmp_base
            .join(format!("nexus-plugin-{}-{:08x}", spec.job, rand::random::<u32>()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        let r = Self::start(spec, opts, op_timeout, idle, &bin, &tmp);
        if r.is_err() {
            let _ = fs::remove_dir_all(&tmp);
        }
        r
    }

    fn start(
        spec: &Spec,
        opts: &Options,
        op_timeout: Duration,
        idle: Option<Duration>,
        bin: &File,
        tmp: &Path,
    ) -> Result<PluginProc> {
        let (p, report) = prepare(spec, opts, tmp)?;
        let bin_fd = bin.as_raw_fd();
        let parent = unsafe { libc::getpid() };
        let userns = opts.userns;
        let argv: Vec<*const libc::c_char> = p
            .argv
            .iter()
            .map(|a| a.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let envp: Vec<*const libc::c_char> = p
            .envp
            .iter()
            .map(|a| a.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let ruleset_fd = p.ruleset.as_ref().map(|r| r.raw_fd());
        let mut cmd = Command::new("/proc/self/exe"); // never executed: pre_exec execs the plugin
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .current_dir(tmp)
            .env_clear();
        let (argv_p, envp_p) = (argv.as_ptr() as usize, envp.as_ptr() as usize);
        let (uid_map, gid_map) = (p.uid_map.as_bytes().to_vec(), p.gid_map.as_bytes().to_vec());
        let rlimits = p.rlimits.clone();
        let seccomp = p.seccomp.clone();
        unsafe {
            cmd.pre_exec(move || {
                // only system calls from here on (the parent may be multithreaded)
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 || libc::getppid() != parent {
                    return Err(io::Error::from_raw_os_error(libc::ESRCH));
                }
                libc::setpriority(libc::PRIO_PROCESS, 0, 10);
                for (res, v) in &rlimits {
                    let l = libc::rlimit {
                        rlim_cur: *v,
                        rlim_max: *v,
                    };
                    if libc::setrlimit(*res, &l) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                if userns && libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWIPC) == 0 {
                    let _ = write_file(b"/proc/self/setgroups\0", b"deny");
                    if !write_file(b"/proc/self/uid_map\0", &uid_map) || !write_file(b"/proc/self/gid_map\0", &gid_map)
                    {
                        return Err(io::Error::from_raw_os_error(libc::EPERM));
                    }
                }
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if let Some(fd) = ruleset_fd {
                    landlock::restrict_self(fd)?;
                }
                // descriptors the host inherited without O_CLOEXEC must not reach the plugin
                libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, libc::CLOSE_RANGE_CLOEXEC);
                seccomp::apply(&seccomp)?;
                libc::syscall(
                    libc::SYS_execveat,
                    bin_fd,
                    c"".as_ptr(),
                    argv_p as *const *const libc::c_char,
                    envp_p as *const *const libc::c_char,
                    libc::AT_EMPTY_PATH,
                );
                Err(io::Error::last_os_error())
            });
        }
        let mut child = cmd.spawn().context("starting the plugin")?;
        drop(p); // ruleset fd: the child has its copy (closed at exec)
        let out = child.stdout.take().unwrap();
        let err = child.stderr.take().unwrap();
        let stdin: ChildStdin = child.stdin.take().unwrap();
        stderr_thread(err);
        let over_quota = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        {
            // tmp size accounting: the plugin's process group dies above tmp_mb
            let (tmp, over, stop) = (tmp.to_owned(), over_quota.clone(), stop.clone());
            let max = spec.limits.tmp_mb << 20;
            let pgid = child.id() as i32;
            let used = Arc::new(AtomicU64::new(0));
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let mut budget = 200_000;
                    let n = dir_usage(&tmp, &mut budget);
                    used.store(n, Ordering::Relaxed);
                    if n > max {
                        over.store(true, Ordering::SeqCst);
                        unsafe { libc::kill(-pgid, libc::SIGKILL) };
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(500));
                }
            });
        }
        Ok(PluginProc {
            child,
            conn: Conn {
                inbox: reader_thread(out),
                out: Box::new(BufWriter::new(stdin)),
                deadline: Instant::now() + op_timeout,
                idle,
            },
            tmp: tmp.to_owned(),
            over_quota,
            stop,
            report,
        })
    }

    fn kill(&mut self) {
        let pgid = self.child.id() as i32;
        unsafe { libc::kill(-pgid, libc::SIGKILL) };
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn err(&mut self, e: String) -> anyhow::Error {
        self.kill();
        if self.over_quota.load(Ordering::SeqCst) {
            return anyhow::anyhow!("plugin killed: its tmp dir exceeded the limit of the manifest (sandbox.tmp_mb)");
        }
        anyhow::anyhow!("plugin stopped: {e}")
    }
}

impl Peer for PluginProc {
    fn send(&mut self, m: &Message) -> Result<()> {
        match self.conn.send(m) {
            Ok(()) => Ok(()),
            Err(e) => Err(self.err(format!("cannot write to the plugin: {e}"))),
        }
    }
    fn recv(&mut self) -> Result<Message> {
        match self.conn.recv() {
            Ok(m) => Ok(m),
            Err(e) => Err(self.err(e)),
        }
    }
    fn poll(&mut self, wait: Duration) -> Result<Option<Message>> {
        match self.conn.poll(wait) {
            Ok(m) => Ok(m),
            Err(e) => Err(self.err(e)),
        }
    }
    fn set_idle(&mut self, idle: Option<Duration>) {
        self.conn.idle = idle;
    }
    fn violation(&mut self, why: &str) -> anyhow::Error {
        self.err(format!("protocol violation: {why}"))
    }
    fn finish(&mut self) {
        self.conn.out = Box::new(io::sink()); // EOF on the plugin's stdin
        let end = Instant::now() + Duration::from_secs(10);
        while Instant::now() < end {
            if let Ok(Some(_)) = self.child.try_wait() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        self.kill();
    }
}

impl Drop for PluginProc {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.kill();
        let _ = fs::remove_dir_all(&self.tmp);
    }
}
