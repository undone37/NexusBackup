//! Single-file restore from VM disk images via the restore micro-VM (plan §8).
//!
//! The disks of a snapshot are served read-only from the chunk store over
//! private Unix-socket NBD servers; QEMU attaches them read-only as virtio-blk
//! to a micro-VM (Debian kernel + initramfs from `restore-vm/build.sh`, no NIC,
//! `-sandbox on`) whose agent mounts the guest file systems read-only and
//! answers over virtio-serial. Foreign file systems never touch the host kernel.
//! Protocol: see `restore-vm/agent/src/main.rs`.

use anyhow::{bail, Context, Result};
use chunkstore::{Index, Store};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub const AGENT_PORT: &str = "org.nexusbackup.agent";
const MAX_RESPONSE: u64 = 256 << 20;
const MAX_FRAME: u32 = 16 << 20;

#[derive(Clone, Debug)]
pub struct Config {
    /// directory with `vmlinuz` and `initrd.img` (target/restore-vm, or the appliance's copy)
    pub image_dir: PathBuf,
    /// QEMU binary (`qemu-system-x86_64`; `/usr/libexec/qemu-kvm` on EL)
    pub qemu: PathBuf,
    pub mem_mb: u32,
    pub cpus: u32,
    /// boot until the agent reports ready (TCG is much slower than KVM)
    pub boot_timeout: Duration,
    /// longest silence of the agent within one request
    pub io_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            image_dir: "/usr/lib/nexus/restore-vm".into(),
            qemu: "qemu-system-x86_64".into(),
            mem_mb: 1024,
            cpus: 2,
            boot_timeout: Duration::from_secs(120),
            io_timeout: Duration::from_secs(300),
        }
    }
}

/// A file system the agent found (mounted when `mountpoint` is set).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Mount {
    pub device: String,
    /// index name of the disk (virtio-blk serial), for partitions of attached disks
    pub disk: Option<String>,
    pub fstype: String,
    pub label: Option<String>,
    pub uuid: Option<String>,
    pub size: Option<u64>,
    pub mountpoint: Option<String>,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Entry {
    pub name: String,
    pub kind: String,
    pub size: u64,
    pub mode: u32,
    pub mtime: i64,
    pub uid: u32,
    pub gid: u32,
    pub link: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct TarSummary {
    pub entries: u64,
    /// unreadable files (zero-filled in the archive) and skipped entries
    pub errors: Vec<String>,
}

/// A virtual disk of the micro-VM.
pub enum Disk<'a> {
    /// NBD export on a Unix socket, always attached read-only
    Nbd { name: &'a str, socket: &'a Path },
    /// local image file (test fixtures only)
    File {
        name: &'a str,
        path: &'a Path,
        writable: bool,
    },
}

pub fn kvm_usable() -> bool {
    fs::OpenOptions::new().read(true).write(true).open("/dev/kvm").is_ok()
}

/// The QEMU command line: no NIC, no default devices, seccomp sandbox, virtio
/// disks (read-only for NBD), agent port on `agent` (QEMU connects to it).
pub fn qemu_command(cfg: &Config, initrd: &Path, disks: &[Disk], agent: &Path, log: &Path, append: &str) -> Command {
    let mut c = Command::new(&cfg.qemu);
    let kvm = kvm_usable();
    c.args(["-name", "nexus-restore", "-nodefaults", "-no-user-config", "-no-reboot"])
        .args(["-machine", if kvm { "q35,accel=kvm" } else { "q35,accel=tcg" }])
        .args(["-cpu", if kvm { "host" } else { "max" }])
        .args(["-m", &cfg.mem_mb.to_string(), "-smp", &cfg.cpus.to_string()])
        .args(["-display", "none", "-nic", "none", "-vga", "none"])
        .args([
            "-sandbox",
            "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
        ])
        .arg("-kernel")
        .arg(cfg.image_dir.join("vmlinuz"))
        .arg("-initrd")
        .arg(initrd)
        .args(["-append", &format!("console=ttyS0 panic=-1 quiet {append}")])
        .arg("-serial")
        .arg(format!("file:{}", log.display()))
        .args(["-device", "virtio-serial-pci,id=vs"])
        .arg("-chardev")
        .arg(format!("socket,id=agent,path={}", agent.display()))
        .args([
            "-device",
            &format!("virtserialport,bus=vs.0,chardev=agent,name={AGENT_PORT}"),
        ]);
    for (i, d) in disks.iter().enumerate() {
        let (name, drive) = match d {
            Disk::Nbd { name, socket } => (
                name,
                format!(
                    "driver=nbd,server.type=unix,server.path={},export=disk,read-only=on",
                    socket.display()
                ),
            ),
            Disk::File { name, path, writable } => (
                name,
                format!(
                    "driver=raw,file.filename={},read-only={}",
                    path.display(),
                    if *writable { "off" } else { "on" }
                ),
            ),
        };
        // virtio-blk serials are at most 20 bytes; commas would break the option parser
        let serial: String = name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || "-_.".contains(*c))
            .take(20)
            .collect();
        c.args(["-drive", &format!("{drive},if=none,id=d{i}")])
            .args(["-device", &format!("virtio-blk-pci,drive=d{i},serial={serial}")]);
    }
    c.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
    unsafe {
        c.pre_exec(|| {
            // QEMU dies with us; no core dumps of guest memory
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            let zero = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            libc::setrlimit(libc::RLIMIT_CORE, &zero);
            Ok(())
        });
    }
    c
}

/// Private 0700 directory for the sockets and the console log, removed on drop.
pub struct WorkDir(pub PathBuf);
impl WorkDir {
    pub fn new() -> io::Result<Self> {
        let base = std::env::var_os("XDG_RUNTIME_DIR").map_or_else(std::env::temp_dir, PathBuf::from);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let p = base.join(format!("nexus-restorevm-{}-{}", std::process::id(), nonce.as_nanos()));
        fs::DirBuilder::new().mode(0o700).create(&p)?;
        Ok(WorkDir(p))
    }
}
impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn console_tail(log: &Path) -> String {
    let s = fs::read(log).unwrap_or_default();
    let s = String::from_utf8_lossy(&s);
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(15)..].join("\n")
}

/// A running micro-VM with a connected agent.
pub struct Vm {
    child: Child,
    r: BufReader<UnixStream>,
    w: UnixStream,
    log: PathBuf,
    /// a tar stream was started but not finished: the protocol is out of sync
    desync: bool,
    /// boot until the agent was ready
    pub boot_time: Duration,
}

impl Vm {
    /// Last lines of the VM console (kernel + agent log).
    pub fn console(&self) -> String {
        console_tail(&self.log)
    }

    fn context(&self, e: anyhow::Error) -> anyhow::Error {
        e.context(format!("restore VM console:\n{}", console_tail(&self.log)))
    }

    fn request(&mut self, req: serde_json::Value) -> Result<serde_json::Value> {
        if self.desync {
            bail!("previous tar stream not finished");
        }
        let mut line = serde_json::to_vec(&req)?;
        line.push(b'\n');
        self.w.write_all(&line).context("agent write")?;
        self.response()
    }

    fn response(&mut self) -> Result<serde_json::Value> {
        let mut line = Vec::new();
        (&mut self.r)
            .take(MAX_RESPONSE)
            .read_until(b'\n', &mut line)
            .context("agent read")?;
        if line.last() != Some(&b'\n') {
            bail!("agent closed the connection or sent an over-long line");
        }
        parse_response(&line)
    }

    pub fn mounts(&mut self) -> Result<Vec<Mount>> {
        let v = self.request(serde_json::json!({"cmd": "mounts"}))?;
        Ok(serde_json::from_value(v)?)
    }

    /// Entries of the directory `path` (`/` lists the mountpoints).
    pub fn ls(&mut self, path: &str) -> Result<Vec<Entry>> {
        let v = self.request(serde_json::json!({"cmd": "ls", "path": path}))?;
        Ok(serde_json::from_value(v)?)
    }

    /// Starts a tar stream of `paths` (archive names without the leading `/`).
    /// Read it to the end, then call `TarStream::finish`.
    pub fn tar(&mut self, paths: &[String]) -> Result<TarStream<'_>> {
        let v = self.request(serde_json::json!({"cmd": "tar", "paths": paths}))?;
        if v != "tar" {
            bail!("unexpected tar response {v}");
        }
        self.desync = true;
        Ok(TarStream {
            vm: self,
            left: 0,
            done: false,
        })
    }

    /// Writes `paths` as tar or zip into `out`; returns entries written + agent summary.
    pub fn extract(&mut self, paths: &[String], fmt: crate::files::Format, out: File) -> Result<(usize, TarSummary)> {
        let mut t = self.tar(paths)?;
        let n = crate::files::extract(&mut t, &[String::new()], fmt, out)?;
        Ok((n, t.finish()?))
    }

    /// Asks the agent to power off; kills QEMU after `timeout`.
    pub fn shutdown(&mut self, timeout: Duration) {
        // out of sync (unfinished tar stream): the agent cannot take commands, kill
        let wait = if self.desync { Duration::ZERO } else { timeout };
        if !self.desync {
            let _ = self.w.write_all(b"{\"cmd\":\"quit\"}\n");
        }
        let t = Instant::now();
        while t.elapsed() < wait {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One agent response line: `{"ok": …}` → the value, `{"err": "…"}` → error.
/// Anything else (the agent is untrusted once a guest file system got to it) is an error.
pub fn parse_response(line: &[u8]) -> Result<serde_json::Value> {
    let v: serde_json::Value = serde_json::from_slice(line).context("agent response")?;
    let serde_json::Value::Object(mut o) = v else {
        bail!("agent response is not an object");
    };
    if let Some(e) = o.get("err") {
        bail!("agent: {}", e.as_str().unwrap_or("?"));
    }
    Ok(o.remove("ok").unwrap_or_default())
}

/// Tar stream from the agent (decoded frames).
pub struct TarStream<'a> {
    vm: &'a mut Vm,
    left: u32,
    done: bool,
}

impl Read for TarStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        read_frame(&mut self.vm.r, &mut self.left, &mut self.done, buf)
    }
}

/// Decodes the agent's `[u32 BE len][len bytes]` frames (zero length = end);
/// `left` / `done` carry the state between calls.
pub fn read_frame(r: &mut impl Read, left: &mut u32, done: &mut bool, buf: &mut [u8]) -> io::Result<usize> {
    if *done || buf.is_empty() {
        return Ok(0);
    }
    if *left == 0 {
        let mut len = [0u8; 4];
        r.read_exact(&mut len)?;
        *left = u32::from_be_bytes(len);
        if *left == 0 {
            *done = true;
            return Ok(0);
        }
        if *left > MAX_FRAME {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "agent frame too large"));
        }
    }
    let n = buf.len().min(*left as usize);
    let n = r.read(&mut buf[..n])?;
    if n == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    *left -= n as u32;
    Ok(n)
}

impl TarStream<'_> {
    /// Drains the rest of the stream and returns the agent's summary.
    pub fn finish(mut self) -> Result<TarSummary> {
        io::copy(&mut self, &mut io::sink())?;
        self.vm.desync = false;
        Ok(serde_json::from_value(self.vm.response()?)?)
    }
}

/// Boots the micro-VM with the given fixed indexes (name, index) of one
/// snapshot attached read-only, runs `f` and shuts the VM down.
pub fn with_vm<T>(
    store: &Store,
    disks: &[(&str, &Index)],
    cfg: &Config,
    f: impl FnOnce(&mut Vm) -> Result<T>,
) -> Result<T> {
    let work = WorkDir::new()?;
    let stop = AtomicBool::new(false);
    let mut socks = Vec::new();
    let mut listeners = Vec::new();
    for (i, (name, idx)) in disks.iter().enumerate() {
        store.image_reader(idx).with_context(|| format!("disk {name}"))?;
        let p = work.0.join(format!("disk{i}.sock"));
        listeners.push((UnixListener::bind(&p)?, *idx));
        socks.push(p);
    }
    std::thread::scope(|s| {
        for (l, idx) in &listeners {
            let stop = &stop;
            s.spawn(move || {
                for conn in l.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(c) = conn else { continue };
                    // one thread per connection, each with its own chunk cache
                    s.spawn(move || {
                        let Ok(mut rd) = store.image_reader(idx) else { return };
                        let size = rd.size();
                        let Ok(r) = c.try_clone() else { return };
                        if let Err(e) = nbd::server::serve(r, c, "disk", size, |off, buf| rd.read_at(off, buf)) {
                            eprintln!("restore VM nbd: {e}");
                        }
                    });
                }
            });
        }
        // stops the NBD accept loops on every exit path (including panics in `f`)
        struct Stop<'a>(&'a AtomicBool, &'a [PathBuf]);
        impl Drop for Stop<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
                for p in self.1 {
                    let _ = UnixStream::connect(p);
                }
            }
        }
        let _stop = Stop(&stop, &socks);
        let nbd: Vec<Disk> = disks
            .iter()
            .zip(&socks)
            .map(|((name, _), socket)| Disk::Nbd { name, socket })
            .collect();
        let mut vm = boot(cfg, &work.0, &cfg.image_dir.join("initrd.img"), &nbd, "")?;
        let res = f(&mut vm);
        vm.shutdown(Duration::from_secs(10));
        res
    })
}

/// Starts QEMU and waits for the agent's ready line.
pub fn boot(cfg: &Config, work: &Path, initrd: &Path, disks: &[Disk], append: &str) -> Result<Vm> {
    for f in [cfg.image_dir.join("vmlinuz"), initrd.to_owned()] {
        if !f.is_file() {
            bail!("restore VM image {} missing (run restore-vm/build.sh)", f.display());
        }
    }
    let t = Instant::now();
    let agent_sock = work.join("agent.sock");
    let log = work.join("console.log");
    let listener = UnixListener::bind(&agent_sock)?;
    listener.set_nonblocking(true)?;
    let mut child = qemu_command(cfg, initrd, disks, &agent_sock, &log, append)
        .spawn()
        .with_context(|| format!("starting {}", cfg.qemu.display()))?;
    let stream = loop {
        match listener.accept() {
            Ok((s, _)) => break s,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
        if let Some(st) = child.try_wait()? {
            let mut err = String::new();
            child.stderr.take().map(|mut e| e.read_to_string(&mut err));
            bail!("qemu exited ({st}) before connecting: {}", err.trim());
        }
        if t.elapsed() > Duration::from_secs(30) {
            let _ = child.kill();
            bail!("qemu did not connect the agent port");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(cfg.boot_timeout))?;
    let mut vm = Vm {
        child,
        r: BufReader::new(stream.try_clone()?),
        w: stream,
        log,
        desync: false,
        boot_time: Duration::ZERO,
    };
    let mut line = Vec::new();
    let ready = (&mut vm.r)
        .take(64 << 10)
        .read_until(b'\n', &mut line)
        .map_err(anyhow::Error::from)
        .and_then(|_| Ok(serde_json::from_slice::<serde_json::Value>(&line)?));
    match ready {
        Ok(v) if v["ready"] == true => {}
        Ok(v) => return Err(vm.context(anyhow::anyhow!("unexpected agent greeting {v}"))),
        Err(e) => return Err(vm.context(e.context("restore VM did not become ready"))),
    }
    vm.w.set_read_timeout(Some(cfg.io_timeout))?;
    vm.boot_time = t.elapsed();
    Ok(vm)
}

/// `nexus-pve … files <vmid> <time> mounts | ls <path> | get <out.tar|out.zip> <path>…`:
/// all fixed indexes (disks) of the VM snapshot attached. Image directory from
/// `NEXUS_RESTORE_VM_DIR` (default `/usr/lib/nexus/restore-vm`), QEMU from `NEXUS_QEMU`.
pub fn cli(store: &Store, vmid: u32, time: u64, args: &[String]) -> Result<()> {
    let usage = "files <vmid> <time> mounts | ls <path> | get <out.tar|out.zip> <path>...";
    let m = store.load_manifest(&crate::backup::source_name(vmid), time)?;
    let mut disks = Vec::new();
    for name in &m.indexes {
        let idx = store.load_index(&m, name)?;
        if matches!(idx, Index::Fixed { .. }) {
            disks.push((name.as_str(), idx));
        }
    }
    if disks.is_empty() {
        bail!("snapshot has no disk images");
    }
    let refs: Vec<(&str, &Index)> = disks.iter().map(|(n, i)| (*n, i)).collect();
    let mut cfg = Config::default();
    if let Some(d) = std::env::var_os("NEXUS_RESTORE_VM_DIR") {
        cfg.image_dir = d.into();
    }
    if let Some(q) = std::env::var_os("NEXUS_QEMU") {
        cfg.qemu = q.into();
    }
    with_vm(store, &refs, &cfg, |vm| {
        match args {
            [c] if c == "mounts" => println!("{}", serde_json::to_string_pretty(&vm.mounts()?)?),
            [c, path] if c == "ls" => println!("{}", serde_json::to_string_pretty(&vm.ls(path)?)?),
            [c, out, paths @ ..] if c == "get" && !paths.is_empty() => {
                let out = Path::new(out);
                let fmt = crate::files::Format::from_path(out)?;
                let t = Instant::now();
                let (n, sum) = vm.extract(paths, fmt, File::create_new(out)?)?;
                for e in &sum.errors {
                    eprintln!("warning: {e}");
                }
                println!("{n} entries written to {} in {:.1?}", out.display(), t.elapsed());
            }
            _ => bail!("usage: {usage}"),
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression (fuzzing, agent_frames): `{"ok"}` lookup on a non-object
    /// response (`5`, `[]`) panicked in serde_json's IndexMut.
    #[test]
    fn agent_responses() {
        assert_eq!(parse_response(b"{\"ok\":[1]}\n").unwrap(), serde_json::json!([1]));
        assert_eq!(parse_response(b"{}").unwrap(), serde_json::Value::Null);
        assert!(parse_response(b"{\"err\":\"no such mount\"}").is_err());
        for bad in [&b"5\n"[..], b"[]", b"\"ok\"", b"null", b"{"] {
            assert!(parse_response(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn frames_decode() {
        let wire = [
            &3u32.to_be_bytes()[..],
            b"abc",
            &1u32.to_be_bytes(),
            b"d",
            &0u32.to_be_bytes(),
            b"rest",
        ]
        .concat();
        let (mut r, mut left, mut done, mut out, mut buf) = (&wire[..], 0, false, Vec::new(), [0u8; 2]);
        loop {
            let n = read_frame(&mut r, &mut left, &mut done, &mut buf).unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        assert_eq!((out.as_slice(), r), (&b"abcd"[..], &b"rest"[..]));
        let huge = (MAX_FRAME + 1).to_be_bytes();
        assert!(read_frame(&mut &huge[..], &mut 0, &mut false, &mut buf).is_err());
    }
}
