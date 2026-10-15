//! Rescue mode (`nexus-agent rescue`, docs/bmr.md): the agent on the rescue ISO.
//!
//! The console sets up the network, takes the appliance address and the one-time
//! recovery token, and has the operator pick and confirm the target disks (or
//! reads all of that from a config disk labelled `NEXUSCFG`, for unattended P2V).
//! It then starts the usual listener in enrollment mode with the token and checks
//! in with the appliance over HTTPS (a hint: "a rescue agent for session X is
//! waiting at address:port"). The appliance enrolls it like an agent (token proofs
//! bound to the TLS session, so a forged check-in gets nowhere) and drives the
//! recovery over mTLS: `RescueApply` (recreate + mount), the ordinary restore
//! stream into [`TARGET`], `RescueFinish` (boot loader, initramfs, reboot).
//!
//! The rescue agent takes no backups; restores go only into [`TARGET`], and only
//! after `RescueApply` mounted the recreated file systems there.

pub mod checkin;
pub mod exec;
pub mod plan;

use crate::restore::Restore;
use agent_core::cache::Cache;
use agent_core::config::{Paths, Settings};
use agent_core::server::{
    Agent, Ctx, HostInfo, Mode, Platform, PreparedJob, Refused, ScanError, ScanOutput, E_BAD_REQUEST, E_REFUSED,
};
use agent_proto::layout::Layout;
use agent_proto::{Entry, Filters, Overwrite, Volume};
use plan::{Plan, TargetDisk};
use serde::Deserialize;
use std::io::{self, BufRead, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Where the recreated file systems are mounted (the restore target).
pub const TARGET: &str = "/mnt/nexus-target";
/// Rescue agent state (tmpfs).
pub const RUN: &str = "/run/nexus-rescue";
/// Volume label of the config disk (P2V).
pub const CONFIG_LABEL: &str = "NEXUSCFG";
pub const CONFIG_FILE: &str = "rescue.json";

/// The agent platform of the rescue system.
pub struct Rescue {
    targets: Vec<TargetDisk>,
    applied: Mutex<Option<(Layout, Plan)>>,
}

impl Rescue {
    pub fn new(targets: Vec<TargetDisk>) -> Rescue {
        Rescue {
            targets,
            applied: Mutex::new(None),
        }
    }
}

fn refused(msg: &str) -> Refused {
    Refused(E_REFUSED, msg.into())
}

impl Platform for Rescue {
    type Job = ();
    type Restore = Restore;

    fn host_info(&self) -> HostInfo {
        let (kernel, _) = crate::sys::uname();
        HostInfo {
            os: "NexusBackup rescue".into(),
            kernel,
            hostname: "nexus-rescue".into(),
            caps: ["restore", "xattrs", "acl", "hardlinks", agent_proto::CAP_RESCUE]
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            agent_version: env!("CARGO_PKG_VERSION").into(),
        }
    }

    fn list_volumes(&self) -> Vec<Volume> {
        vec![]
    }

    fn prepare(
        &self,
        _: Ctx,
        _: u64,
        _: &[String],
        _: &[String],
        _: &Filters,
        _: bool,
    ) -> Result<PreparedJob<()>, Refused> {
        Err(refused("a rescue agent takes no backups"))
    }

    fn scan(
        &self,
        _: Ctx,
        _: &mut (),
        _: u64,
        _: Option<u64>,
        _: Option<&Cache>,
        _: &mut dyn FnMut(Entry) -> io::Result<()>,
    ) -> Result<ScanOutput, ScanError> {
        Err(ScanError::Refused(refused("a rescue agent takes no backups")))
    }

    fn release_snapshots(&self, _: Ctx, _: &mut (), _: u64, _: bool) -> String {
        String::new()
    }

    fn finish_job(&self, _: Ctx, _: (), _: u64, _: bool) -> String {
        String::new()
    }

    fn restore_begin(
        &self,
        _: Ctx,
        job: u64,
        target: &str,
        overwrite: Overwrite,
        confirm: &str,
    ) -> io::Result<Restore> {
        if self
            .applied
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_none()
        {
            return Err(io::Error::other("restore before RescueApply: nothing is mounted yet"));
        }
        if Path::new(target) != Path::new(TARGET) {
            return Err(io::Error::other(format!("a rescue agent restores only into {TARGET}")));
        }
        Restore::begin(job, target, overwrite, confirm)
    }

    fn update(&self, _: Ctx, _: &str, _: &[u8], _: &[u8]) -> Result<String, String> {
        Err("a rescue agent is not updated (use the matching rescue ISO)".into())
    }

    fn restart_after_update(&self) -> ! {
        std::process::exit(0)
    }

    fn rescue_apply(&self, _: Ctx, _job: u64, layout: &str) -> Result<(String, String), Refused> {
        let l: Layout = serde_json::from_str(layout).map_err(|e| Refused(E_BAD_REQUEST, format!("layout: {e}")))?;
        let mut applied = self.applied.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut log = exec::Log::default();
        match exec::apply(&l, &self.targets, &mut log) {
            Ok(plan) => {
                log.line(format!("file systems mounted below {TARGET}: restoring files"));
                *applied = Some((l, plan));
                Ok((TARGET.into(), log.0))
            }
            Err(e) => {
                log.line(format!("error: {e}"));
                Err(refused(&log.0))
            }
        }
    }

    fn rescue_finish(&self, _: Ctx, _job: u64) -> Result<(String, String), Refused> {
        let applied = self.applied.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some((l, plan)) = applied.as_ref() else {
            return Err(refused("RescueFinish before RescueApply"));
        };
        let mut log = exec::Log::default();
        match exec::finish(l, plan, &mut log) {
            Ok(()) => {
                log.line("recovery finished");
                Ok((TARGET.into(), log.0))
            }
            Err(e) => {
                log.line(format!("error: {e}"));
                Err(refused(&log.0))
            }
        }
    }

    fn reboot(&self) {
        // SAFETY: plain syscalls; the file systems are unmounted and synced.
        unsafe {
            libc::sync();
            libc::reboot(libc::RB_AUTOBOOT);
        }
    }
}

/// Settings of the rescue console (interactive answers or the config disk).
#[derive(Deserialize, Default, Debug, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct RescueConfig {
    /// appliance web address, `host` or `host:port` (HTTPS, default 443)
    pub appliance: String,
    pub token: String,
    /// optional pin of the appliance's web certificate (sha256 hex)
    pub appliance_sha256: String,
    pub network: Net,
    /// target disks in the order of the original disks, or `["auto"]` = every disk
    /// (sorted by name; unattended P2V only)
    pub disks: Vec<String>,
    /// the disks above may be erased without asking (config disk only)
    pub confirm: bool,
    /// `host:port` the appliance should connect to (NAT, port forwarding); default:
    /// this machine's address towards the appliance and `port`
    pub advertise: String,
    pub port: u16,
}

#[derive(Deserialize, Default, Debug, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct Net {
    /// "dhcp" (default), "static" or "none" (already configured)
    pub mode: String,
    /// static: interface (default: the first with a link)
    pub interface: String,
    /// static: "192.0.2.10/24"
    pub address: String,
    pub gateway: String,
    pub dns: Vec<String>,
}

fn prompt(q: &str, default: &str) -> String {
    if default.is_empty() {
        print!("{q}: ");
    } else {
        print!("{q} [{default}]: ");
    }
    let _ = io::stdout().flush();
    let mut s = String::new();
    let _ = io::stdin().lock().read_line(&mut s);
    let s = s.trim().to_string();
    if s.is_empty() {
        default.to_string()
    } else {
        s
    }
}

fn sh(argv: &[&str]) -> Result<String, String> {
    exec::run(
        &plan::Cmd {
            argv: argv.iter().map(std::string::ToString::to_string).collect(),
            stdin: None,
        },
        &mut exec::Log::default(),
    )
}

/// Network interfaces except `lo` (name, MAC).
fn interfaces() -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = std::fs::read_dir("/sys/class/net")
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != "lo")
        .map(|n| {
            let mac = std::fs::read_to_string(format!("/sys/class/net/{n}/address")).unwrap_or_default();
            (n, mac.trim().to_string())
        })
        .collect();
    v.sort();
    v
}

fn network(n: &Net) -> Result<(), String> {
    let ifs = interfaces();
    match n.mode.as_str() {
        "none" => Ok(()),
        "static" => {
            let dev = if n.interface.is_empty() {
                ifs.first().map(|i| i.0.clone()).ok_or("no network interface")?
            } else {
                n.interface.clone()
            };
            sh(&["ip", "link", "set", "dev", &dev, "up"])?;
            sh(&["ip", "addr", "add", &n.address, "dev", &dev])?;
            if !n.gateway.is_empty() {
                sh(&["ip", "route", "add", "default", "via", &n.gateway])?;
            }
            let dns: String = n.dns.iter().map(|d| format!("nameserver {d}\n")).collect();
            std::fs::write("/etc/resolv.conf", dns).map_err(|e| format!("resolv.conf: {e}"))
        }
        _ => {
            let mut last = String::from("no network interface");
            for (dev, _) in ifs.iter().filter(|i| n.interface.is_empty() || i.0 == n.interface) {
                let _ = sh(&["ip", "link", "set", "dev", dev, "up"]);
                match sh(&[
                    "udhcpc",
                    "-i",
                    dev,
                    "-n",
                    "-q",
                    "-t",
                    "6",
                    "-T",
                    "3",
                    "-s",
                    "/usr/share/nexus-rescue/udhcpc.script",
                ]) {
                    Ok(_) => {
                        println!("DHCP lease on {dev}");
                        return Ok(());
                    }
                    Err(e) => last = e,
                }
            }
            Err(format!("DHCP failed: {last}"))
        }
    }
}

/// The config disk (P2V): `nexus-rescue.json` on the file system labelled NEXUSCFG.
fn config_disk() -> Option<RescueConfig> {
    let dev = sh(&["blkid", "-L", CONFIG_LABEL]).ok()?;
    let dev = dev.trim();
    let mnt = format!("{RUN}/cfg");
    let _ = std::fs::create_dir_all(&mnt);
    sh(&["mount", "-o", "ro", dev, &mnt]).ok()?;
    let text = std::fs::read_to_string(Path::new(&mnt).join(CONFIG_FILE));
    let _ = sh(&["umount", &mnt]);
    match serde_json::from_str(&text.ok()?) {
        Ok(c) => Some(c),
        Err(e) => {
            println!("config disk {dev}: {CONFIG_FILE}: {e}");
            None
        }
    }
}

fn gib(b: u64) -> String {
    format!("{:.1} GiB", b as f64 / (1u64 << 30) as f64)
}

/// Resolve the configured / typed target disks.
pub fn pick_disks(want: &[String], avail: &[(TargetDisk, String)]) -> Result<Vec<TargetDisk>, String> {
    if want.len() == 1 && want[0] == "auto" {
        let v: Vec<TargetDisk> = avail
            .iter()
            .filter(|(_, m)| !m.ends_with("(removable)"))
            .map(|(d, _)| d.clone())
            .collect();
        return if v.is_empty() {
            Err("no disks found".into())
        } else {
            Ok(v)
        };
    }
    let mut out = vec![];
    for w in want {
        let path = if w.starts_with("/dev/") {
            w.clone()
        } else {
            format!("/dev/{w}")
        };
        let d = avail
            .iter()
            .find(|(d, _)| d.path == path)
            .ok_or_else(|| format!("no disk {w}"))?;
        if out.iter().any(|x: &TargetDisk| x.path == path) {
            return Err(format!("{w} named twice"));
        }
        out.push(d.0.clone());
    }
    if out.is_empty() {
        return Err("no target disk".into());
    }
    Ok(out)
}

fn interactive(cfg: &mut RescueConfig) -> Result<Vec<TargetDisk>, String> {
    println!("\nNexusBackup bare-metal recovery\n");
    for (n, mac) in interfaces() {
        println!("  network interface {n} {mac}");
    }
    let mode = prompt("Network: dhcp, static or none", "dhcp");
    cfg.network.mode = mode.clone();
    if mode == "static" {
        cfg.network.interface = prompt(
            "Interface",
            &interfaces().first().map(|i| i.0.clone()).unwrap_or_default(),
        );
        cfg.network.address = prompt("Address with prefix (e.g. 192.0.2.10/24)", "");
        cfg.network.gateway = prompt("Default gateway", "");
        let dns = prompt("DNS server", "");
        cfg.network.dns = if dns.is_empty() { vec![] } else { vec![dns] };
    }
    if let Err(e) = network(&cfg.network) {
        println!("network: {e}");
    }
    for l in sh(&["ip", "-o", "-4", "addr", "show"]).unwrap_or_default().lines() {
        println!("  {}", l.split_whitespace().take(4).collect::<Vec<_>>().join(" "));
    }
    cfg.appliance = prompt("Appliance address (host or host:port)", &cfg.appliance);
    cfg.token = prompt("Recovery token (Agents > Bare-metal recovery)", "");
    println!("\nDisks of this machine:");
    let avail = exec::list_disks();
    for (d, m) in &avail {
        println!("  {:<14} {:>10}  {m}", d.path.trim_start_matches("/dev/"), gib(d.size));
    }
    println!("Give one disk per disk of the original machine, in its order (the web UI shows them).");
    loop {
        let want = prompt(
            "Target disk(s), comma-separated",
            avail
                .first()
                .map(|d| d.0.path.trim_start_matches("/dev/"))
                .unwrap_or(""),
        );
        let want: Vec<String> = want
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        match pick_disks(&want, &avail) {
            Ok(d) => {
                let names = want.join(",");
                println!("ALL DATA on {names} will be ERASED when the recovery starts.");
                if prompt("Type the disk name(s) again to confirm", "") == names {
                    cfg.disks = want;
                    return Ok(d);
                }
                println!("not confirmed");
            }
            Err(e) => println!("{e}"),
        }
    }
}

/// `nexus-agent rescue [--config FILE]`
pub fn main(config: Option<PathBuf>) -> Result<(), String> {
    // SAFETY: trivial syscall
    unsafe { libc::umask(0o077) };
    let file = match &config {
        Some(p) => Some(
            serde_json::from_slice::<RescueConfig>(&std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?)
                .map_err(|e| format!("{}: {e}", p.display()))?,
        ),
        None => config_disk(),
    };
    let (mut cfg, targets) = match file {
        Some(c) if c.confirm && !c.disks.is_empty() && !c.token.is_empty() => {
            println!("unattended recovery (config disk)");
            network(&c.network)?;
            let t = pick_disks(&c.disks, &exec::list_disks())?;
            (c, t)
        }
        other => {
            let mut c = other.unwrap_or_default();
            let t = interactive(&mut c)?;
            (c, t)
        }
    };
    if cfg.port == 0 {
        cfg.port = agent_proto::DEFAULT_PORT;
    }
    println!(
        "target disks: {}",
        targets
            .iter()
            .map(|t| format!("{} ({})", t.path, gib(t.size)))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let paths = Paths {
        config: Path::new(RUN).join("config"),
        state: Path::new(RUN).join("state"),
        run: Path::new(RUN).join("run"),
    };
    agent_core::init(&paths, &cfg.token, Some(cfg.port), "nexus-rescue")?;
    let settings = Settings::load(&paths)?;
    let agent = Arc::new(Agent::with_platform(
        Rescue::new(targets.clone()),
        paths,
        settings.clone(),
    )?);
    let listener = TcpListener::bind(("0.0.0.0", cfg.port)).map_err(|e| format!("listen :{}: {e}", cfg.port))?;
    let a = agent.clone();
    let server = std::thread::spawn(move || a.serve(listener));
    let disks: Vec<checkin::DiskInfo> = targets
        .iter()
        .map(|t| checkin::DiskInfo {
            path: t.path.clone(),
            size: t.size,
        })
        .collect();
    let mut announced = false;
    while !matches!(agent.mode(), Mode::Mtls { .. }) {
        match checkin::checkin(&cfg, &disks) {
            Ok(r) if !announced => {
                println!("checked in: {r}");
                println!("Waiting for the appliance. Start the recovery in the web UI (Agents > Bare-metal recovery).");
                announced = true;
            }
            Ok(_) => {}
            Err(e) => println!("check-in with {} failed: {e} (retrying)", cfg.appliance),
        }
        for _ in 0..15 {
            if matches!(agent.mode(), Mode::Mtls { .. }) {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    println!("enrolled by the appliance; the recovery runs from there (progress below and in the web UI)");
    server
        .join()
        .map_err(|_| "listener thread panicked".to_string())?
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_picking() {
        let d = |p: &str, m: &str| {
            (
                TargetDisk {
                    path: p.into(),
                    size: 1,
                    sector_size: 512,
                },
                m.to_string(),
            )
        };
        let avail = [d("/dev/sda", ""), d("/dev/sdb", "x"), d("/dev/sdc", "USB (removable)")];
        let auto = pick_disks(&["auto".into()], &avail).unwrap();
        assert_eq!(auto.len(), 2, "auto skips removable disks");
        let p = pick_disks(&["sdb".into(), "/dev/sda".into()], &avail).unwrap();
        assert_eq!(p[0].path, "/dev/sdb");
        assert!(pick_disks(&["sda".into(), "sda".into()], &avail).is_err());
        assert!(pick_disks(&["sdz".into()], &avail).is_err());
        let c: RescueConfig = serde_json::from_str(
            r#"{"appliance":"10.0.0.1","token":"T","disks":["auto"],"confirm":true,"network":{"mode":"dhcp"}}"#,
        )
        .unwrap();
        assert!(c.confirm && c.advertise.is_empty());
        assert!(serde_json::from_str::<RescueConfig>(r#"{"bogus":1}"#).is_err());
    }
}
