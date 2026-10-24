//! Restore micro-VM agent (PID 1, static musl binary). Mounts every recognizable
//! file system of the attached (read-only) disks read-only under /mnt and serves
//! them over the virtio-serial port `org.nexusbackup.agent`. No network.
//!
//! Protocol: one JSON request per line, one JSON response line
//! (`{"ok":…}` or `{"err":"…"}`):
//! - `{"cmd":"mounts"}` → list of detected file systems
//! - `{"cmd":"ls","path":"/vda1/etc"}` → entries of one directory
//! - `{"cmd":"tar","paths":["/vda1/etc", …]}` → `{"ok":"tar"}`, then frames
//!   `[u32 BE len][len bytes]` of a tar stream, a zero-length frame, then
//!   `{"ok":{"entries":N,"errors":[…]}}`
//! - `{"cmd":"rules","rules":[{"name","text"}…]}` → compiles YARA rules (`scan.rs`)
//! - `{"cmd":"scan","limits":{…}}` → YARA scan of every mounted file system
//! - `{"cmd":"scantar","limits":{…}}` → `{"ok":"send"}`, then the appliance sends
//!   frames of a tar stream (zero-length frame = end), then the scan report
//! - `{"cmd":"quit"}` → `{"ok":"bye"}`, power off
//!
//! Paths are `/<mountpoint>/<path inside the file system>`. `.`/`..`/NUL are
//! rejected, and the path inside a file system is resolved with
//! `openat2(RESOLVE_IN_ROOT)`, so symlinks in the guest data cannot leave it.
//!
//! Kernel command line `nexus.fixture=1` (tests only): run `/fixture.sh` from
//! the fixture overlay with writable disks instead of serving, then power off.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

mod scan;

const MNT: &str = "/mnt";
const PORT_NAME: &str = "org.nexusbackup.agent";
/// requests from the appliance; `rules` carries up to 1 MiB of YARA rules (escaped)
const MAX_LINE: u64 = 8 << 20;
const MAX_PATH: usize = 4096;
const FRAME: usize = 1 << 20;
const MODULES: &[&str] = &[
    "virtio_pci",
    "virtio_blk",
    "virtio_console",
    "ext4",
    "xfs",
    "btrfs",
    "ntfs3",
    "vfat",
    "exfat",
    "isofs",
    "nls_cp437",
    "nls_utf8",
    "dm_mod",
    "dm_snapshot",
    "dm_thin_pool",
    "dm_mirror",
    "raid1",
    "raid10",
    "raid456",
    "zfs",
];
/// No udev in the VM: LVM creates its device nodes itself; never write metadata.
const LVM_CFG: &str = "activation{udev_sync=0 udev_rules=0 monitoring=0} devices{obtain_device_list_from_udev=0 write_cache_state=0} global{use_lvmpolld=0 thin_check_executable=\"\" cache_check_executable=\"\"} backup{backup=0 archive=0}";

macro_rules! log {
    ($($t:tt)*) => { eprintln!("agent: {}", format!($($t)*)) };
}

#[derive(Serialize, Clone, Debug, Default)]
struct Mount {
    device: String,
    /// virtio-blk serial of the disk (= index name on the appliance), if any
    disk: Option<String>,
    fstype: String,
    label: Option<String>,
    uuid: Option<String>,
    /// file system size in bytes (statvfs), when mounted
    size: Option<u64>,
    /// `/vda1`, `/lvm/vg0-root`, `/zfs/tank+data`; None when not mountable
    mountpoint: Option<String>,
    error: Option<String>,
}

#[derive(Serialize, Debug)]
struct Entry {
    name: String,
    kind: &'static str,
    size: u64,
    mode: u32,
    mtime: i64,
    uid: u32,
    gid: u32,
    link: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "cmd", rename_all = "lowercase")]
pub(crate) enum Req {
    Mounts,
    Ls { path: String },
    Tar { paths: Vec<String> },
    Rules { rules: Vec<scan::Rule> },
    Scan { limits: scan::Limits },
    Scantar { limits: scan::Limits },
    Quit,
}

fn main() {
    if std::process::id() != 1 {
        eprintln!("nexus-restore-agent runs as PID 1 inside the restore micro-VM");
        std::process::exit(2);
    }
    if let Err(e) = run() {
        log!("fatal: {e}");
    }
    poweroff();
}

fn poweroff() -> ! {
    // SAFETY: sync and reboot take no pointers; the agent is PID 1 of the restore VM and powers it off.
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_POWER_OFF);
    }
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn run() -> io::Result<()> {
    std::env::set_var("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    for (src, dst, ty) in [
        ("proc", "/proc", "proc"),
        ("sysfs", "/sys", "sysfs"),
        ("devtmpfs", "/dev", "devtmpfs"),
        ("tmpfs", "/run", "tmpfs"),
        ("tmpfs", "/tmp", "tmpfs"),
    ] {
        fs::create_dir_all(dst)?;
        mount(src, dst, ty, libc::MS_NOSUID, "")?;
    }
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let fixture = cmdline.split_whitespace().any(|a| a == "nexus.fixture=1");
    let st = Command::new("modprobe").arg("-a").args(MODULES).status();
    log!("modules loaded: {st:?}");
    if fixture {
        let st = Command::new("busybox").args(["sh", "/fixture.sh"]).status();
        log!("fixture script: {st:?}");
        return Ok(());
    }
    let port = find_port()?;
    let t = std::time::Instant::now();
    let mounts = mount_all();
    log!("mounted {} file systems in {:.1?}", mounts.len(), t.elapsed());
    // virtio ports can be opened once only
    let w = fs::OpenOptions::new().read(true).write(true).open(&port)?;
    let r = BufReader::new(w.try_clone()?);
    serve(r, w, &mounts)
}

fn mount(src: &str, dst: &str, ty: &str, flags: libc::c_ulong, data: &str) -> io::Result<()> {
    let c = |s: &str| CString::new(s).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput));
    let (s, d, t, o) = (c(src)?, c(dst)?, c(ty)?, c(data)?);
    // SAFETY: all four are NUL-terminated CStrings alive across the call; mount does not keep the pointers.
    let r = unsafe { libc::mount(s.as_ptr(), d.as_ptr(), t.as_ptr(), flags, o.as_ptr().cast()) };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn find_port() -> io::Result<PathBuf> {
    for _ in 0..100 {
        for e in fs::read_dir("/sys/class/virtio-ports").into_iter().flatten().flatten() {
            if fs::read_to_string(e.path().join("name")).is_ok_and(|n| n.trim() == PORT_NAME) {
                return Ok(Path::new("/dev").join(e.file_name()));
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "agent virtio-serial port missing",
    ))
}

/// stdout of a helper; failures are logged and yield None.
fn cmd(prog: &str, args: &[&str]) -> Option<String> {
    let t = std::time::Instant::now();
    let res = Command::new(prog).args(args).output();
    if t.elapsed() > Duration::from_millis(500) {
        log!("{prog} {} took {:.1?}", args.first().unwrap_or(&""), t.elapsed());
    }
    match res {
        Ok(o) if o.status.success() => Some(String::from_utf8_lossy(&o.stdout).into_owned()),
        Ok(o) => {
            log!("{prog} {args:?}: {}", String::from_utf8_lossy(&o.stderr).trim());
            None
        }
        Err(e) => {
            log!("{prog}: {e}");
            None
        }
    }
}

/// `blkid -p -o export` of one device: (TYPE, LABEL, UUID).
fn probe(dev: &str) -> Option<(String, Option<String>, Option<String>)> {
    let out = cmd("blkid", &["-p", "-o", "export", dev])?;
    let get = |k: &str| {
        out.lines()
            .find_map(|l| l.strip_prefix(k)?.strip_prefix('=').map(str::to_owned))
    };
    Some((get("TYPE")?, get("LABEL"), get("UUID")))
}

/// Block devices without holders (holders = PV/md member/thin pool internals).
fn leaf_devices() -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir("/sys/class/block")
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| fs::read_dir(e.path().join("holders")).is_ok_and(|mut h| h.next().is_none()))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !n.starts_with("loop") && !n.starts_with("ram") && !n.starts_with("zd"))
        .collect();
    v.sort();
    v
}

/// GPT partition types of Windows dynamic disks (lowercase, as blkid prints them).
const LDM_META: &str = "5808c8aa-7e8f-42e0-85d2-e1e90434cfb3";
const LDM_DATA: &str = "af9b60a0-1431-4f62-bc68-3311714a69ad";

/// Whole disks read for the LDM parser (`/dev/<name>`, read-only).
struct BlockDisks(Vec<(String, File, u64)>);

impl ldm::Disks for BlockDisks {
    fn size(&self, disk: usize) -> u64 {
        self.0[disk].2
    }
    fn read(&mut self, disk: usize, off: u64, buf: &mut [u8]) -> io::Result<()> {
        std::os::unix::fs::FileExt::read_exact_at(&self.0[disk].1, buf, off)
    }
}

/// A dm-linear table (512-byte sectors) of a dynamic volume's extents on `/dev/<disk>`.
fn dm_table(ext: &[ldm::Extent], disks: &[String]) -> String {
    ext.iter()
        .map(|e| {
            format!(
                "{} {} linear /dev/{} {}\n",
                e.start / 512,
                e.len / 512,
                disks[e.disk],
                e.offset / 512
            )
        })
        .collect()
}

/// A device-mapper name for a dynamic volume: `ldm-` + its name in safe characters (else its index).
fn dm_volume_name(name: &str, i: usize) -> String {
    let n: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .take(64)
        .collect();
    if n.is_empty() {
        format!("ldm-{i}")
    } else {
        format!("ldm-{n}")
    }
}

/// The private header of a GPT dynamic disk: the last sector of its LDM metadata partition (blkid's
/// PART_ENTRY_OFFSET and PART_ENTRY_SIZE, in sectors).
fn ldm_privhead(offset: u64, size: u64) -> Option<u64> {
    offset.checked_add(size)?.checked_sub(1)?.checked_mul(512)
}

/// Windows dynamic disks with GPT (#53): the kernel reads LDM only from MBR disks, so the group's database is
/// parsed here (crate `ldm`) and every simple or spanned volume becomes a read-only dm-linear device
/// `ldm-<name>`, mounted below `/ldm`. Returns the LDM data partitions not to mount on their own (when the
/// group was mapped) and entries for volumes that cannot be read (striped, RAID-5, a missing disk).
fn ldm_map() -> (BTreeSet<String>, Vec<Mount>) {
    let mut members: Vec<(String, u64)> = Vec::new();
    let mut data_parts = BTreeSet::new();
    for e in fs::read_dir("/sys/class/block").into_iter().flatten().flatten() {
        if !e.path().join("partition").exists() {
            continue;
        }
        let part = e.file_name().to_string_lossy().into_owned();
        let Some(out) = cmd("blkid", &["-p", "-o", "export", &format!("/dev/{part}")]) else {
            continue;
        };
        let get = |k: &str| {
            out.lines()
                .find_map(|l| l.strip_prefix(k)?.strip_prefix('=').map(str::to_owned))
        };
        let disk = fs::canonicalize(e.path()).ok().and_then(|p| {
            p.parent()
                .and_then(|d| d.file_name())
                .map(|n| n.to_string_lossy().into_owned())
        });
        match (get("PART_ENTRY_TYPE").as_deref(), disk) {
            (Some(LDM_META), Some(disk)) => {
                let num = |k: &str| get(k).and_then(|v| v.parse::<u64>().ok());
                if let Some(at) = num("PART_ENTRY_OFFSET")
                    .zip(num("PART_ENTRY_SIZE"))
                    .and_then(|(o, s)| ldm_privhead(o, s))
                {
                    if members.iter().all(|(d, _)| *d != disk) {
                        members.push((disk, at));
                    }
                }
            }
            (Some(LDM_DATA), _) => {
                data_parts.insert(part);
            }
            _ => {}
        }
    }
    if members.is_empty() {
        return (BTreeSet::new(), Vec::new());
    }
    let mut disks = BlockDisks(Vec::new());
    let mut ms = Vec::new();
    for (d, at) in &members {
        let size = fs::read_to_string(format!("/sys/class/block/{d}/size"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map_or(0, |s| s * 512);
        match File::open(format!("/dev/{d}")) {
            Ok(f) => disks.0.push((d.clone(), f, size)),
            Err(e) => {
                log!("ldm: /dev/{d}: {e}");
                continue;
            }
        }
        ms.push(ldm::Member {
            disk: disks.0.len() - 1,
            privhead: *at,
        });
    }
    let names: Vec<String> = disks.0.iter().map(|d| d.0.clone()).collect();
    let vols = match ldm::volumes(&mut disks, &ms) {
        Ok(v) => v,
        Err(e) => {
            log!("ldm: {e}");
            return (BTreeSet::new(), Vec::new());
        }
    };
    let (mut failed, mut mapped) = (Vec::new(), 0);
    for (i, v) in vols.iter().enumerate() {
        let dm = dm_volume_name(&v.name, i);
        let err = match &v.map {
            Ok(ext) => {
                let table = dm_table(ext, &names);
                cmd("dmsetup", &["create", &dm, "--readonly", "--table", &table])
                    .map(|_| ())
                    .ok_or_else(|| "dmsetup create failed".to_owned())
            }
            Err(why) => Err(why.clone()),
        };
        if err.is_ok() {
            mapped += 1;
        }
        if let Err(why) = err {
            failed.push(Mount {
                device: format!("ldm/{}", v.name),
                fstype: "ldm".into(),
                error: Some(why),
                ..Default::default()
            });
        }
    }
    log!(
        "ldm: {mapped} of {} dynamic volume(s) mapped on {} disk(s)",
        vols.len(),
        names.len()
    );
    // nothing mapped (no dmsetup?): the data partitions are probed as before (a simple volume at their start)
    (if mapped > 0 { data_parts } else { BTreeSet::new() }, failed)
}

/// Mount type and data for a blkid TYPE; journals are never replayed.
fn fs_options(ty: &str) -> Option<(&'static str, &'static str)> {
    Some(match ty {
        "ext2" | "ext3" | "ext4" => ("ext4", "noload"),
        "xfs" => ("xfs", "norecovery"),
        "btrfs" => ("btrfs", "rescue=nologreplay"),
        "ntfs" => ("ntfs3", ""),
        "vfat" => ("vfat", "iocharset=utf8,shortname=mixed"),
        "exfat" => ("exfat", ""),
        "iso9660" => ("iso9660", ""),
        _ => return None,
    })
}

const RO: libc::c_ulong = libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_NOATIME;

fn finish(m: &mut Mount, mp: String, res: io::Result<()>) {
    match res {
        Ok(()) => {
            m.size = statvfs_size(&format!("{MNT}{mp}"));
            m.mountpoint = Some(mp);
        }
        Err(e) => m.error = Some(e.to_string()),
    }
}

fn mount_all() -> Vec<Mount> {
    let t = std::time::Instant::now();
    if Path::new("/usr/sbin/mdadm").exists() {
        cmd("mdadm", &["--assemble", "--scan", "--readonly"]);
    }
    // LVM: read-only activation of every VG found (list built from a scan, `*` is not accepted).
    if let Some(vgs) = cmd("lvm", &["vgs", "--noheadings", "-o", "vg_name", "--config", LVM_CFG]) {
        let names: Vec<String> = vgs.split_whitespace().map(|v| format!("\"{v}\"")).collect();
        if !names.is_empty() {
            let cfg = format!("{LVM_CFG} activation{{read_only_volume_list=[{}]}}", names.join(","));
            cmd("lvm", &["vgchange", "-ay", "--config", &cfg]);
        }
    }
    log!("md + lvm: {:.1?}", t.elapsed());
    let (ldm_data, mut out) = ldm_map();
    // ZFS: blkid reports the pool name as LABEL of each member.
    let mut pools = std::collections::BTreeMap::<String, Vec<String>>::new();
    for dev in leaf_devices() {
        if let Some((ty, Some(label), _)) = probe(&format!("/dev/{dev}")) {
            if ty == "zfs_member" {
                pools.entry(label).or_default().push(format!("/dev/{dev}"));
            }
        }
    }
    for (pool, devs) in pools {
        let alt = format!("/run/zfs-altroot/{pool}");
        // only the member devices are scanned (`-d /dev` probes everything and is slow)
        let mut imp = vec![
            "import",
            "-N",
            "-f",
            "-o",
            "readonly=on",
            "-o",
            "cachefile=none",
            "-R",
            &alt,
        ];
        devs.iter().for_each(|d| imp.extend(["-d", d.as_str()]));
        imp.push(&pool);
        if cmd("zpool", &imp).is_none() {
            out.push(Mount {
                device: pool.clone(),
                fstype: "zfs".into(),
                error: Some("zpool import failed".into()),
                ..Default::default()
            });
            continue;
        }
        let list = cmd("zfs", &["list", "-H", "-o", "name", "-t", "filesystem", "-r", &pool]).unwrap_or_default();
        for ds in list.lines().filter(|l| !l.is_empty()) {
            let mp = format!("/zfs/{}", ds.replace('/', "+"));
            let mut m = Mount {
                device: ds.into(),
                fstype: "zfs".into(),
                ..Default::default()
            };
            let res =
                fs::create_dir_all(format!("{MNT}{mp}")).and_then(|_| mount(ds, &format!("{MNT}{mp}"), "zfs", RO, ""));
            finish(&mut m, mp, res);
            out.push(m);
        }
    }
    log!("zfs: {:.1?}", t.elapsed());
    for dev in leaf_devices() {
        // a GPT dynamic disk's data partition: its volumes are mounted through their ldm-* devices
        if ldm_data.contains(&dev) {
            continue;
        }
        let path = format!("/dev/{dev}");
        let Some((ty, label, uuid)) = probe(&path) else {
            continue;
        };
        let serial = [
            format!("/sys/class/block/{dev}/serial"),
            format!("/sys/class/block/{dev}/../serial"),
        ]
        .iter()
        .find_map(|p| fs::read_to_string(p).ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());
        let mut m = Mount {
            device: path.clone(),
            disk: serial,
            fstype: ty.clone(),
            label,
            uuid,
            ..Default::default()
        };
        match ty.as_str() {
            "zfs_member" | "LVM2_member" | "linux_raid_member" | "swap" => continue,
            _ => {}
        }
        let Some((fstype, data)) = fs_options(&ty) else {
            m.error = Some(format!("unsupported file system {ty}"));
            out.push(m);
            continue;
        };
        let mp = match fs::read_to_string(format!("/sys/class/block/{dev}/dm/name")) {
            Ok(n) => {
                m.device = format!("/dev/mapper/{}", n.trim());
                match n.trim().strip_prefix("ldm-") {
                    Some(v) => format!("/ldm/{v}"),
                    None => format!("/lvm/{}", n.trim()),
                }
            }
            Err(_) => format!("/{dev}"),
        };
        let res = fs::create_dir_all(format!("{MNT}{mp}"))
            .and_then(|_| mount(&path, &format!("{MNT}{mp}"), fstype, RO, data));
        finish(&mut m, mp, res);
        out.push(m);
    }
    out
}

fn statvfs_size(p: &str) -> Option<u64> {
    let c = CString::new(p).ok()?;
    // SAFETY: libc::statvfs is plain C data (integers only); all-zero is a valid value for the out buffer.
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a NUL-terminated CString alive across the call and `s` a valid, exclusive out buffer.
    (unsafe { libc::statvfs(c.as_ptr(), &mut s) } == 0).then(|| s.f_blocks as u64 * s.f_frsize as u64)
}

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

/// Where a request path points.
#[derive(Debug, PartialEq)]
pub(crate) enum Target {
    /// inside a mounted file system: (mountpoint, components below it)
    Fs(String, Vec<String>),
    /// a directory of the virtual tree above the mountpoints (`/`, `/lvm`)
    Virtual(Vec<String>),
}

/// Validates a request path and maps it to a mountpoint. Rejects relative
/// paths, `.`/`..`, NUL and over-long paths; `//` and a trailing `/` are fine.
pub(crate) fn resolve(path: &str, mountpoints: &[String]) -> io::Result<Target> {
    if !path.starts_with('/') || path.len() > MAX_PATH || path.contains('\0') {
        return Err(err(format!("invalid path {path:?}")));
    }
    let comps: Vec<String> = path.split('/').filter(|c| !c.is_empty()).map(str::to_owned).collect();
    if comps.iter().any(|c| c == "." || c == "..") {
        return Err(err(format!("invalid path {path:?}")));
    }
    let best = mountpoints
        .iter()
        .map(|m| (m, m.split('/').filter(|c| !c.is_empty()).collect::<Vec<_>>()))
        .filter(|(_, mc)| comps.len() >= mc.len() && comps.iter().zip(mc).all(|(a, b)| a == b))
        .max_by_key(|(_, mc)| mc.len());
    if let Some((m, mc)) = best {
        return Ok(Target::Fs(m.clone(), comps[mc.len()..].to_vec()));
    }
    let above = mountpoints.iter().any(|m| {
        let mc: Vec<_> = m.split('/').filter(|c| !c.is_empty()).collect();
        mc.len() > comps.len() && comps.iter().zip(&mc).all(|(a, b)| a == b)
    });
    if above {
        Ok(Target::Virtual(comps))
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no such mount for {path:?}"),
        ))
    }
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_IN_ROOT: u64 = 0x10;

/// Opens `rel` below the mountpoint with the mountpoint as `/` for symlinks.
fn open_in(mp: &str, rel: &[String], flags: i32) -> io::Result<OwnedFd> {
    let root = File::open(format!("{MNT}{mp}"))?;
    let p = CString::new(if rel.is_empty() { ".".into() } else { rel.join("/") }).map_err(|_| err("NUL"))?;
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: `root` stays open across the call, `p` is a live C string, and `how` is a live #[repr(C)]
    // open_how whose exact size is passed.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            p.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor (checked >= 0) that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

fn fd_path(fd: &OwnedFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

fn kind(ft: fs::FileType) -> &'static str {
    if ft.is_dir() {
        "dir"
    } else if ft.is_file() {
        "file"
    } else if ft.is_symlink() {
        "symlink"
    } else if ft.is_block_device() {
        "block"
    } else if ft.is_char_device() {
        "char"
    } else if ft.is_fifo() {
        "fifo"
    } else {
        "socket"
    }
}

fn entry(name: String, p: &Path) -> io::Result<Entry> {
    let md = fs::symlink_metadata(p)?;
    Ok(Entry {
        name,
        kind: kind(md.file_type()),
        size: md.len(),
        mode: md.mode(),
        mtime: md.mtime(),
        uid: md.uid(),
        gid: md.gid(),
        link: md
            .file_type()
            .is_symlink()
            .then(|| fs::read_link(p).map(|l| l.to_string_lossy().into_owned()))
            .transpose()?,
    })
}

fn ls(path: &str, mountpoints: &[String]) -> io::Result<Vec<Entry>> {
    let mut v = Vec::new();
    match resolve(path, mountpoints)? {
        Target::Virtual(comps) => {
            let names: BTreeSet<&str> = mountpoints
                .iter()
                .filter_map(|m| {
                    let mc: Vec<_> = m.split('/').filter(|c| !c.is_empty()).collect();
                    (mc.len() > comps.len() && comps.iter().zip(&mc).all(|(a, b)| a == b)).then(|| mc[comps.len()])
                })
                .collect();
            for n in names {
                let mut p = PathBuf::from(MNT);
                p.extend(&comps);
                v.push(entry(n.to_owned(), &p.join(n))?);
            }
        }
        Target::Fs(mp, rel) => {
            let dir = open_in(&mp, &rel, libc::O_RDONLY | libc::O_DIRECTORY)?;
            let base = fd_path(&dir);
            for e in fs::read_dir(&base)? {
                let e = e?;
                // ponytail: non-UTF-8 names are shown lossily (tar of the parent keeps the bytes)
                let name = e.file_name().to_string_lossy().into_owned();
                v.push(entry(name, &base.join(e.file_name()))?);
            }
        }
    }
    v.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(v)
}

/// Splits a byte stream into `[u32 BE len][data]` frames; `finish` writes the empty end frame.
pub(crate) struct Frames<W: Write> {
    pub(crate) w: W,
    pub(crate) buf: Vec<u8>,
}

impl<W: Write> Frames<W> {
    fn flush_frame(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            self.w.write_all(&(self.buf.len() as u32).to_be_bytes())?;
            self.w.write_all(&self.buf)?;
            self.buf.clear();
        }
        Ok(())
    }
    pub(crate) fn finish(mut self) -> io::Result<W> {
        self.flush_frame()?;
        self.w.write_all(&0u32.to_be_bytes())?;
        self.w.flush()?;
        Ok(self.w)
    }
}

impl<W: Write> Write for Frames<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let n = data.len().min(FRAME - self.buf.len());
        self.buf.extend_from_slice(&data[..n]);
        if self.buf.len() == FRAME {
            self.flush_frame()?;
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Reads exactly `left` bytes; after a read error (bad block, I/O error from
/// the backing store) or a short file it pads with zeros so the tar stays
/// valid, and remembers the error.
struct Padded<R> {
    r: R,
    left: u64,
    err: Option<String>,
}

impl<R: Read> Read for Padded<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = (buf.len() as u64).min(self.left) as usize;
        if n == 0 {
            return Ok(0);
        }
        if self.err.is_none() {
            match self.r.read(&mut buf[..n]) {
                Ok(0) => self.err = Some("file shorter than its size".into()),
                Ok(k) => {
                    self.left -= k as u64;
                    return Ok(k);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => return self.read(buf),
                Err(e) => self.err = Some(e.to_string()),
            }
        }
        buf[..n].fill(0);
        self.left -= n as u64;
        Ok(n)
    }
}

struct TarJob<W: Write> {
    b: tar::Builder<W>,
    entries: u64,
    errors: Vec<String>,
}

impl<W: Write> TarJob<W> {
    /// Archives `p` (not following a final symlink) as `arc`, recursing into directories.
    fn walk(&mut self, p: &Path, arc: &Path) -> io::Result<()> {
        let md = match fs::symlink_metadata(p) {
            Ok(m) => m,
            Err(e) => {
                self.errors.push(format!("{}: {e}", arc.display()));
                return Ok(());
            }
        };
        let mut h = tar::Header::new_gnu();
        h.set_metadata_in_mode(&md, tar::HeaderMode::Complete);
        let ft = md.file_type();
        if ft.is_dir() {
            h.set_size(0);
            self.b.append_data(&mut h, arc, io::empty())?;
            self.entries += 1;
            let mut names: Vec<_> = match fs::read_dir(p) {
                Ok(rd) => rd.filter_map(|e| e.ok().map(|e| e.file_name())).collect(),
                Err(e) => {
                    self.errors.push(format!("{}: {e}", arc.display()));
                    return Ok(());
                }
            };
            names.sort();
            for n in names {
                self.walk(&p.join(&n), &arc.join(&n))?;
            }
            return Ok(());
        }
        if ft.is_symlink() {
            let target = match fs::read_link(p) {
                Ok(t) => t,
                Err(e) => {
                    self.errors.push(format!("{}: {e}", arc.display()));
                    return Ok(());
                }
            };
            h.set_size(0);
            self.b.append_link(&mut h, arc, target)?;
        } else if ft.is_file() {
            let f = match fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(p) {
                Ok(f) => f,
                Err(e) => {
                    self.errors.push(format!("{}: {e}", arc.display()));
                    return Ok(());
                }
            };
            let mut r = Padded {
                r: f,
                left: md.len(),
                err: None,
            };
            self.b.append_data(&mut h, arc, &mut r)?;
            if let Some(e) = r.err {
                self.errors.push(format!("{}: {e} (zero-filled)", arc.display()));
            }
        } else {
            h.set_size(0); // device, fifo, socket: header only
            self.b.append_data(&mut h, arc, io::empty())?;
        }
        self.entries += 1;
        Ok(())
    }
}

#[derive(Serialize)]
struct TarSummary {
    entries: u64,
    errors: Vec<String>,
}

fn tar_paths<W: Write>(paths: &[String], mountpoints: &[String], w: &mut W) -> io::Result<TarSummary> {
    // validate and open everything before the first byte goes out
    let mut todo = Vec::new();
    for p in paths {
        let Target::Fs(mp, rel) = resolve(p, mountpoints)? else {
            return Err(err(format!("{p:?} is not inside a mounted file system")));
        };
        let (parent, name) = match rel.split_last() {
            Some((n, parent)) => (open_in(&mp, parent, libc::O_PATH | libc::O_DIRECTORY)?, Some(n.clone())),
            None => (open_in(&mp, &[], libc::O_PATH | libc::O_DIRECTORY)?, None),
        };
        let fsp = name
            .as_ref()
            .map_or_else(|| fd_path(&parent).join("."), |n| fd_path(&parent).join(n));
        fs::symlink_metadata(&fsp)?;
        let arc: PathBuf = p.split('/').filter(|c| !c.is_empty()).collect();
        todo.push((parent, fsp, arc));
    }
    send_line(w, &serde_json::json!({"ok": "tar"}))?;
    let mut job = TarJob {
        b: tar::Builder::new(Frames {
            w: &mut *w,
            buf: Vec::with_capacity(FRAME),
        }),
        entries: 0,
        errors: Vec::new(),
    };
    for (_fd, fsp, arc) in &todo {
        job.walk(fsp, arc)?;
    }
    let (entries, errors) = (job.entries, std::mem::take(&mut job.errors));
    job.b.into_inner()?.finish()?;
    Ok(TarSummary { entries, errors })
}

fn send_line(w: &mut impl Write, v: &serde_json::Value) -> io::Result<()> {
    let mut s = serde_json::to_vec(v)?;
    s.push(b'\n');
    w.write_all(&s)?;
    w.flush()
}

fn serve(mut r: impl BufRead, mut w: impl Write, mounts: &[Mount]) -> io::Result<()> {
    let mountpoints: Vec<String> = mounts.iter().filter_map(|m| m.mountpoint.clone()).collect();
    send_line(&mut w, &serde_json::json!({"ready": true, "mounts": mountpoints.len()}))?;
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = (&mut r).take(MAX_LINE).read_until(b'\n', &mut line)?;
        if n == 0 {
            std::thread::sleep(Duration::from_millis(100)); // host not connected
            continue;
        }
        if line.last() != Some(&b'\n') {
            send_line(&mut w, &serde_json::json!({"err": "request line too long"}))?;
            // skip the rest of the oversized line
            while !line.is_empty() && line.last() != Some(&b'\n') {
                line.clear();
                (&mut r).take(MAX_LINE).read_until(b'\n', &mut line)?;
            }
            continue;
        }
        let req: Req = match serde_json::from_slice(&line) {
            Ok(r) => r,
            Err(e) => {
                send_line(&mut w, &serde_json::json!({"err": format!("bad request: {e}")}))?;
                continue;
            }
        };
        let res = match req {
            Req::Mounts => serde_json::to_value(mounts).map_err(io::Error::from),
            Req::Ls { path } => ls(&path, &mountpoints).and_then(|v| Ok(serde_json::to_value(v)?)),
            Req::Tar { paths } => match tar_paths(&paths, &mountpoints, &mut w) {
                Ok(s) => {
                    send_line(&mut w, &serde_json::json!({"ok": s}))?;
                    continue;
                }
                Err(e) => Err(e),
            },
            Req::Rules { rules } => scan::compile(&rules).map(|n| serde_json::json!({ "rules": n })),
            Req::Scan { limits } => {
                let mut s = scan::Scan::new(limits);
                s.mounts(&mountpoints)
                    .and_then(|_| Ok(serde_json::to_value(s.finish())?))
            }
            Req::Scantar { limits } => scan::serve_tar(&mut r, &mut w, limits),
            Req::Quit => {
                send_line(&mut w, &serde_json::json!({"ok": "bye"}))?;
                return Ok(());
            }
        };
        match res {
            Ok(v) => send_line(&mut w, &serde_json::json!({ "ok": v }))?,
            Err(e) => send_line(&mut w, &serde_json::json!({ "err": e.to_string() }))?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_volume_tables() {
        let ext = [
            ldm::Extent {
                start: 0,
                len: 1 << 20,
                disk: 0,
                offset: 1 << 20,
            },
            ldm::Extent {
                start: 1 << 20,
                len: 2 << 20,
                disk: 1,
                offset: 17408,
            },
        ];
        assert_eq!(
            dm_table(&ext, &["vda".into(), "vdb".into()]),
            "0 2048 linear /dev/vda 2048\n2048 4096 linear /dev/vdb 34\n"
        );
        assert_eq!(dm_volume_name("Volume1", 0), "ldm-Volume1");
        assert_eq!(dm_volume_name("a b/../c", 0), "ldm-abc");
        assert_eq!(dm_volume_name("///", 3), "ldm-3");
        // the last sector of the metadata partition
        assert_eq!(ldm_privhead(34, 2014), Some(2047 * 512));
        assert_eq!(ldm_privhead(0, 0), None);
    }

    fn mps() -> Vec<String> {
        ["/vda1", "/lvm/vg0-root", "/zfs/tank", "/zfs/tank+data"]
            .map(String::from)
            .to_vec()
    }

    #[test]
    fn resolves_paths_to_mounts() {
        let fs = |m: &str, r: &[&str]| Target::Fs(m.into(), r.iter().map(std::string::ToString::to_string).collect());
        assert_eq!(resolve("/vda1", &mps()).unwrap(), fs("/vda1", &[]));
        assert_eq!(
            resolve("/vda1//etc/über x/", &mps()).unwrap(),
            fs("/vda1", &["etc", "über x"])
        );
        assert_eq!(resolve("/lvm/vg0-root/a", &mps()).unwrap(), fs("/lvm/vg0-root", &["a"]));
        assert_eq!(
            resolve("/zfs/tank+data/x", &mps()).unwrap(),
            fs("/zfs/tank+data", &["x"])
        );
        assert_eq!(resolve("/", &mps()).unwrap(), Target::Virtual(vec![]));
        assert_eq!(resolve("/lvm", &mps()).unwrap(), Target::Virtual(vec!["lvm".into()]));
    }

    #[test]
    fn rejects_escapes_and_junk() {
        for p in [
            "vda1/etc",
            "/vda1/../etc",
            "/vda1/etc/..",
            "/vda1/./etc",
            "/..",
            "/vda1/a\0b",
            "",
            "/vda2",
            "/vda10",
            "/lvmx",
        ] {
            assert!(resolve(p, &mps()).is_err(), "{p:?} accepted");
        }
        assert!(resolve(&format!("/vda1/{}", "a".repeat(MAX_PATH)), &mps()).is_err());
    }

    #[test]
    fn frames_and_padding() {
        let mut out = Vec::new();
        let mut f = Frames {
            w: &mut out,
            buf: Vec::new(),
        };
        f.write_all(&vec![1u8; FRAME + 10]).unwrap();
        f.finish().unwrap();
        assert_eq!(&out[..4], &(FRAME as u32).to_be_bytes());
        assert_eq!(&out[4 + FRAME..8 + FRAME], &10u32.to_be_bytes());
        assert_eq!(&out[out.len() - 4..], &[0, 0, 0, 0]);

        let mut p = Padded {
            r: &b"abc"[..],
            left: 6,
            err: None,
        };
        let mut v = Vec::new();
        p.read_to_end(&mut v).unwrap();
        assert_eq!(v, b"abc\0\0\0");
        assert!(p.err.is_some());
    }
}
