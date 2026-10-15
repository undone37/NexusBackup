//! Running a recreation plan on the rescue machine (`RescueApply`) and fixing up
//! the restored system afterwards (`RescueFinish`), docs/bmr.md "Recovery steps".
//! Every command is logged (to the console and into the answer for the job log).

use super::plan::{Cmd, Plan, TargetDisk};
use agent_proto::layout::Layout;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// Collects the step log (console + answer).
#[derive(Default)]
pub struct Log(pub String);

impl Log {
    pub fn line(&mut self, l: impl AsRef<str>) {
        agent_core::server::log(l.as_ref());
        self.0.push_str(l.as_ref());
        self.0.push('\n');
    }
}

/// Run one command; Err with its stderr on failure.
pub fn run(c: &Cmd, log: &mut Log) -> Result<String, String> {
    log.line(format!("$ {}", c.argv.join(" ")));
    let mut child = Command::new(&c.argv[0])
        .args(&c.argv[1..])
        .env_clear()
        .env("PATH", PATH)
        .env("LC_ALL", "C")
        .env("LVM_SUPPRESS_FD_WARNINGS", "1")
        .stdin(if c.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{}: {e}", c.argv[0]))?;
    if let (Some(input), Some(mut stdin)) = (&c.stdin, child.stdin.take()) {
        stdin
            .write_all(input.as_bytes())
            .map_err(|e| format!("{}: stdin: {e}", c.argv[0]))?;
    }
    let out = child.wait_with_output().map_err(|e| format!("{}: {e}", c.argv[0]))?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() {
        Ok(stdout)
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        Err(format!(
            "{} failed ({}): {}",
            c.argv.join(" "),
            out.status,
            err.trim().chars().take(2000).collect::<String>()
        ))
    }
}

fn c(argv: &[&str]) -> Cmd {
    Cmd {
        argv: argv.iter().map(std::string::ToString::to_string).collect(),
        stdin: None,
    }
}

/// Best effort: release everything that might hold the target disks (an earlier
/// failed attempt, VGs found on them), then wipe their signatures.
fn release_targets(targets: &[String], log: &mut Log) {
    let _ = run(&c(&["umount", "-R", "-l", super::TARGET]), log);
    let _ = run(&c(&["lvm", "vgchange", "-an"]), log);
    for t in targets {
        // partitions first, then the disk
        if let Ok(o) = run(&c(&["lsblk", "-n", "-l", "-p", "-o", "NAME", t]), log) {
            for p in o.lines().skip(1) {
                let _ = run(&c(&["wipefs", "-a", "-f", p.trim()]), log);
            }
        }
        let _ = run(&c(&["wipefs", "-a", "-f", t]), log);
    }
}

/// `RescueApply`: recreate and mount below [`super::TARGET`].
pub fn apply(l: &Layout, targets: &[TargetDisk], log: &mut Log) -> Result<Plan, String> {
    let plan = super::plan::plan(l, targets)?;
    for w in &plan.warnings {
        log.line(format!("warning: {w}"));
    }
    for w in &l.warnings {
        log.line(format!("note from the backup: {w}"));
    }
    let used: Vec<String> = plan.disks.iter().map(|(_, t)| t.clone()).collect();
    log.line(format!(
        "recreating the layout of {} on {}",
        if l.hostname.is_empty() { "the host" } else { &l.hostname },
        plan.disks
            .iter()
            .map(|(s, t)| format!("{s} -> {t}"))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    release_targets(&used, log);
    for cmd in &plan.cmds {
        run(cmd, log)?;
        if cmd.argv[0] == "sfdisk" {
            // devtmpfs creates the partition nodes; give the kernel a moment
            let _ = run(&c(&["partx", "-u", cmd.argv.last().unwrap()]), log);
            wait_nodes(cmd.stdin.as_deref().unwrap_or_default());
        }
    }
    mount_all(&plan, log)?;
    Ok(plan)
}

fn wait_nodes(script: &str) {
    for _ in 0..50 {
        if script
            .lines()
            .filter_map(|l| l.split_once(" : ").map(|x| x.0))
            .all(|n| Path::new(n).exists())
        {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn target_path(mp: &str) -> PathBuf {
    Path::new(super::TARGET).join(mp.trim_start_matches('/'))
}

pub fn mount_all(plan: &Plan, log: &mut Log) -> Result<(), String> {
    for m in &plan.mounts {
        let at = target_path(&m.mountpoint);
        fs::create_dir_all(&at).map_err(|e| format!("{}: {e}", at.display()))?;
        let at = at.to_string_lossy().into_owned();
        let mut a = vec!["mount", "-t", &m.fstype];
        if !m.options.is_empty() {
            a.extend(["-o", &m.options]);
        }
        a.extend([m.device.as_str(), at.as_str()]);
        run(&c(&a), log)?;
    }
    Ok(())
}

fn exists(root: &Path, rel: &str) -> bool {
    root.join(rel.trim_start_matches('/')).exists()
}

fn first_existing<'a>(root: &Path, cands: &[&'a str]) -> Option<&'a str> {
    cands.iter().copied().find(|p| exists(root, p))
}

fn chroot(root: &Path, argv: &[&str], log: &mut Log) -> Result<String, String> {
    let mut a = vec!["chroot", root.to_str().unwrap_or("/")];
    a.extend(argv);
    run(&c(&a), log)
}

/// Replace `old` UUIDs by `new` ones in a text file of the restored system.
fn replace_in(file: &Path, pairs: &[(String, String)], log: &mut Log) {
    let Ok(text) = fs::read_to_string(file) else {
        return;
    };
    let mut t = text.clone();
    for (old, new) in pairs {
        t = t.replace(old.as_str(), new);
    }
    if t != text && fs::write(file, t).is_ok() {
        log.line(format!("{}: file system UUIDs updated", file.display()));
    }
}

/// `RescueFinish`: fix-ups in the restored system, then unmount everything.
pub fn finish(l: &Layout, plan: &Plan, log: &mut Log) -> Result<(), String> {
    let root = Path::new(super::TARGET);
    let _ = fs::remove_dir_all(root.join(".nexus-system"));
    for d in ["dev", "proc", "sys", "run", "tmp"] {
        let _ = fs::create_dir_all(root.join(d));
    }
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(root.join("tmp"), fs::Permissions::from_mode(0o1777));
    }
    // UUIDs the mkfs tools could not keep
    let mut changed = vec![];
    for (dev, want) in &plan.uuids {
        if let Ok(got) = run(&c(&["blkid", "-s", "UUID", "-o", "value", dev]), log) {
            let got = got.trim().to_string();
            if !got.is_empty() && !got.eq_ignore_ascii_case(want) {
                log.line(format!("{dev}: new UUID {got} (was {want})"));
                changed.push((want.clone(), got));
            }
        }
    }
    if !changed.is_empty() {
        for f in ["etc/fstab", "etc/crypttab", "etc/default/grub"] {
            replace_in(&root.join(f), &changed, log);
        }
    }
    if let Ok(fstab) = fs::read_to_string(root.join("etc/fstab")) {
        for line in fstab
            .lines()
            .filter(|l| l.contains("/dev/disk/by-id/") || l.contains("/dev/disk/by-path/"))
        {
            log.line(format!(
                "warning: /etc/fstab names a device by hardware id, which differs on new hardware: {line}"
            ));
        }
    }
    let mut errors = vec![];
    let r = fixups(l, plan, root, log);
    if let Err(e) = r {
        log.line(format!("error: {e}"));
        errors.push(e);
    }
    let _ = run(&c(&["sync"]), log);
    if let Err(e) = run(&c(&["umount", "-R", super::TARGET]), log) {
        log.line(format!("warning: {e}; lazy unmount"));
        let _ = run(&c(&["umount", "-R", "-l", super::TARGET]), log);
    }
    let _ = run(&c(&["lvm", "vgchange", "-an"]), log);
    let _ = run(&c(&["sync"]), log);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// Boot loader and initramfs, in a chroot of the restored system.
fn fixups(l: &Layout, plan: &Plan, root: &Path, log: &mut Log) -> Result<(), String> {
    let r = root.to_string_lossy().into_owned();
    let efi = l.firmware == "uefi";
    if efi && Path::new("/sys/firmware/efi").exists() {
        let _ = run(
            &c(&["mount", "-t", "efivarfs", "efivarfs", "/sys/firmware/efi/efivars"]),
            log,
        );
    }
    for (what, args) in [
        ("dev", vec!["mount", "--rbind", "/dev", "dev"]),
        ("proc", vec!["mount", "-t", "proc", "proc", "proc"]),
        ("sys", vec!["mount", "--rbind", "/sys", "sys"]),
        ("run", vec!["mount", "-t", "tmpfs", "tmpfs", "run"]),
    ] {
        let mut a: Vec<String> = args.iter().map(std::string::ToString::to_string).collect();
        let last = a.len() - 1;
        a[last] = format!("{r}/{what}");
        run(&Cmd { argv: a, stdin: None }, log)?;
    }
    let boot_disk = l
        .boot_disk()
        .and_then(|d| plan.disks.iter().find(|(s, _)| *s == d.path))
        .map(|(_, t)| t.clone())
        .ok_or("no boot disk in the plan")?;
    // the LVM devices file names the PVs by hardware id (serial, WWID): on new disks
    // LVM (and the initramfs, which copies it) would ignore every PV. Re-create it for
    // the new disks; without it LVM uses all devices, which is fine as well.
    let devices = root.join("etc/lvm/devices/system.devices");
    if devices.exists() {
        let _ = fs::remove_file(&devices);
        match chroot(root, &["vgimportdevices", "-a"], log) {
            Ok(_) => log.line("LVM devices file re-created for the new disks"),
            Err(e) => log.line(format!("LVM devices file removed (LVM uses all devices): {e}")),
        }
    }
    // initramfs first: grub-mkconfig lists the kernels with their initramfs
    // Generic images, never "host only": inside the chroot the tools would detect the
    // rescue system's (tmpfs) root and leave out the disk and device-mapper drivers. The
    // next kernel update on the restored system builds a host-only one again.
    if exists(root, "usr/sbin/update-initramfs") {
        let conf = root.join("etc/initramfs-tools/conf.d/zz-nexus-rescue");
        let _ = fs::write(&conf, "MODULES=most\n");
        let r = chroot(root, &["update-initramfs", "-u", "-k", "all"], log);
        let _ = fs::remove_file(&conf);
        r?;
    } else if first_existing(root, &["usr/bin/dracut", "usr/sbin/dracut"]).is_some() {
        chroot(root, &["dracut", "-f", "--regenerate-all", "--no-hostonly"], log)?;
    } else if exists(root, "usr/bin/mkinitcpio") {
        chroot(root, &["mkinitcpio", "-P", "-S", "autodetect"], log)?;
    } else {
        log.line("warning: no initramfs tool found (update-initramfs, dracut, mkinitcpio): initramfs kept as restored");
    }
    let esp_mp = l
        .esp()
        .and_then(|f| f.mounts.first())
        .map(|m| m.mountpoint.clone())
        .unwrap_or_else(|| "/boot/efi".into());
    match l.bootloader.as_str() {
        "systemd-boot" => {
            chroot(root, &["bootctl", "install"], log)?;
        }
        _ => {
            let install = first_existing(root, &["usr/sbin/grub-install", "usr/sbin/grub2-install"])
                .map(|p| p.rsplit('/').next().unwrap_or(p));
            if efi {
                let id = efi_id(root, &esp_mp, l);
                match install {
                    Some("grub-install") => {
                        let dir = format!("--efi-directory={esp_mp}");
                        let bid = format!("--bootloader-id={id}");
                        let mut a = vec!["grub-install", "--target=x86_64-efi", &dir, &bid, "--recheck"];
                        if !Path::new("/sys/firmware/efi").exists() {
                            log.line("warning: the rescue system did not boot in UEFI mode: no NVRAM boot entry (the fallback loader boots)");
                            a.push("--no-nvram");
                        }
                        chroot(root, &a, log)?;
                        // fallback path EFI/BOOT/BOOTX64.EFI: boots on firmware without our NVRAM entry
                        chroot(
                            root,
                            &["grub-install", "--target=x86_64-efi", &dir, "--removable", "--no-nvram"],
                            log,
                        )?;
                    }
                    _ => efi_entry(root, l, plan, &esp_mp, &id, log)?,
                }
            } else {
                let tool = install.ok_or("no grub-install / grub2-install in the restored system")?;
                chroot(root, &[tool, "--target=i386-pc", &boot_disk], log)?;
            }
            if exists(root, "usr/sbin/update-grub") {
                chroot(root, &["update-grub"], log)?;
            } else if exists(root, "usr/sbin/grub2-mkconfig") {
                chroot(root, &["grub2-mkconfig", "-o", "/boot/grub2/grub.cfg"], log)?;
            } else if exists(root, "usr/sbin/grub-mkconfig") {
                chroot(root, &["grub-mkconfig", "-o", "/boot/grub/grub.cfg"], log)?;
            }
        }
    }
    if let Ok(t) = fs::read_to_string(root.join("etc/selinux/config")) {
        if t.lines()
            .any(|x| matches!(x.trim(), "SELINUX=enforcing" | "SELINUX=permissive"))
        {
            let _ = fs::write(root.join(".autorelabel"), b"");
            log.line("SELinux: /.autorelabel created (labels are checked at the first boot, which then reboots once)");
        }
    }
    Ok(())
}

/// Directory name below `<esp>/EFI` of the distribution's boot loader.
fn efi_id(root: &Path, esp_mp: &str, l: &Layout) -> String {
    let dir = root.join(esp_mp.trim_start_matches('/')).join("EFI");
    let found = fs::read_dir(&dir).ok().and_then(|rd| {
        rd.flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .find(|n| !n.eq_ignore_ascii_case("BOOT") && !n.eq_ignore_ascii_case("Linux"))
    });
    found.unwrap_or_else(|| l.os_id.split_whitespace().next().unwrap_or("linux").to_string())
}

/// UEFI without a Debian-style grub-install (RHEL family: signed shim + grub from the
/// restored ESP): an NVRAM entry and the fallback path.
fn efi_entry(root: &Path, l: &Layout, plan: &Plan, esp_mp: &str, id: &str, log: &mut Log) -> Result<(), String> {
    let esp = root.join(esp_mp.trim_start_matches('/')).join("EFI");
    let loader = ["shimx64.efi", "grubx64.efi"]
        .iter()
        .find(|f| esp.join(id).join(f).exists())
        .ok_or_else(|| {
            format!(
                "no shimx64.efi / grubx64.efi in {esp_mp}/EFI/{id}: was the EFI system partition included in the backup?"
            )
        })?;
    let boot = esp.join("BOOT");
    if !boot.join("BOOTX64.EFI").exists() {
        let _ = fs::create_dir_all(&boot);
        fs::copy(esp.join(id).join(loader), boot.join("BOOTX64.EFI")).map_err(|e| format!("fallback loader: {e}"))?;
        log.line(format!("{esp_mp}/EFI/BOOT/BOOTX64.EFI = {id}/{loader}"));
    }
    let Some(f) = l.esp() else {
        return Ok(());
    };
    let (disk, num) = l
        .disks
        .iter()
        .find_map(|d| {
            let p = d.partitions.iter().find(|p| p.path == f.device)?;
            let t = plan.disks.iter().find(|(s, _)| *s == d.path)?;
            Some((t.1.clone(), p.number.to_string()))
        })
        .ok_or("the EFI system partition is not on a recreated disk")?;
    let label = if l.os.is_empty() { id.to_string() } else { l.os.clone() };
    let path = format!("\\EFI\\{id}\\{loader}");
    if let Err(e) = chroot(
        root,
        &["efibootmgr", "-c", "-d", &disk, "-p", &num, "-L", &label, "-l", &path],
        log,
    ) {
        log.line(format!("warning: {e} (the fallback loader still boots)"));
    }
    Ok(())
}

/// Target disks of the rescue machine (`lsblk -d`), for the console and the check-in.
pub fn list_disks() -> Vec<(TargetDisk, String)> {
    let Ok(o) = run(
        &c(&[
            "lsblk",
            "-J",
            "-b",
            "-d",
            "-o",
            "NAME,PATH,TYPE,SIZE,RM,RO,MODEL,LOG-SEC",
        ]),
        &mut Log::default(),
    ) else {
        return vec![];
    };
    parse_disks(&o)
}

pub fn parse_disks(json: &str) -> Vec<(TargetDisk, String)> {
    let v: serde_json::Value = serde_json::from_str(json).unwrap_or_default();
    let n = |x: &serde_json::Value| {
        x.as_u64()
            .or_else(|| x.as_str().and_then(|s| s.parse().ok()))
            .unwrap_or(0)
    };
    let b = |x: &serde_json::Value| x.as_bool().unwrap_or_else(|| x.as_str() == Some("1"));
    let mut out: Vec<(TargetDisk, String)> = v["blockdevices"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|d| d["type"] == "disk" && !b(&d["ro"]) && n(&d["size"]) > 0)
        .map(|d| {
            let name = d["name"].as_str().unwrap_or_default();
            (
                TargetDisk {
                    path: d["path"]
                        .as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("/dev/{name}")),
                    size: n(&d["size"]),
                    sector_size: n(&d["log-sec"]) as u32,
                },
                format!(
                    "{}{}",
                    d["model"].as_str().unwrap_or("").trim(),
                    if b(&d["rm"]) { " (removable)" } else { "" }
                ),
            )
        })
        .collect();
    out.sort_by(|a, b| a.0.path.cmp(&b.0.path));
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn rescue_disks() {
        let d = super::parse_disks(
            r#"{"blockdevices":[{"name":"sr0","path":"/dev/sr0","type":"rom","size":1,"rm":true,"ro":false},
            {"name":"sdb","path":"/dev/sdb","type":"disk","size":8589934592,"rm":false,"ro":false,"model":"QEMU HARDDISK  ","log-sec":512},
            {"name":"sda","type":"disk","size":"21474836480","rm":"0","ro":"0","log-sec":"512"},
            {"name":"loop0","type":"loop","size":5,"ro":false}]}"#,
        );
        let paths: Vec<&str> = d.iter().map(|x| x.0.path.as_str()).collect();
        assert_eq!(paths, ["/dev/sda", "/dev/sdb"]);
        assert_eq!(d[0].0.size, 20 << 30);
        assert_eq!(d[1].1, "QEMU HARDDISK");
    }
}
