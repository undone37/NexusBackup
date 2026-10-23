//! Restore of a VMware VM snapshot (`vmw-<uuid>`, crates/vmware) as a Proxmox VE VM (plan.md Phase 41, #34): the
//! snapshot's `.vmx` becomes a `qemu-server.conf`, its disk indexes (`scsi0-0`, `sata0-1`, ...) become PVE drives.
//! The restore then runs like a PVE one (a temporary archive in the nodes' index.json, `restore-serve` per drive).
//!
//! Drivers: Linux guests get VirtIO (SCSI and network), their kernels carry the drivers. Windows and other guests
//! get SATA disks and e1000e NICs, which Windows drives with its built-in drivers; the restore log says to install
//! the VirtIO drivers and switch over afterwards.

use anyhow::{bail, Result};
use std::collections::BTreeMap;

/// Config index entries of a VMware snapshot (crates/vmware backup.rs).
pub const VMX_FILE: &str = "vm.vmx";
pub const STATE_FILE: &str = "vmware.json";

/// One disk of the snapshot: its index name and size in bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmDisk {
    pub index: String,
    pub size: u64,
}

/// The converted VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Converted {
    /// `qemu-server.conf` for the archive entry
    pub conf: String,
    /// the VM name (from `displayName`)
    pub name: String,
    /// (PVE device `drive-<key>`, snapshot index, size) in drive order
    pub devices: Vec<(String, String, u64)>,
    /// what the operator should know (drivers, firmware), for the restore log
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Linux,
    Windows,
    Other,
}

/// `key = "value"` lines of a `.vmx`; keys are case-insensitive, so they are lower-cased.
pub fn parse_vmx(vmx: &str) -> BTreeMap<String, String> {
    vmx.lines()
        .filter_map(|l| {
            let (k, v) = l.split_once('=')?;
            let k = k.trim();
            if k.is_empty() || k.starts_with('#') {
                return None;
            }
            Some((k.to_ascii_lowercase(), v.trim().trim_matches('"').to_owned()))
        })
        .collect()
}

fn family(guest_os: &str) -> Family {
    let g = guest_os.to_ascii_lowercase();
    if g.starts_with("win") {
        return Family::Windows;
    }
    const LINUX: &[&str] = &[
        "linux",
        "debian",
        "ubuntu",
        "centos",
        "rhel",
        "sles",
        "oracle",
        "fedora",
        "almalinux",
        "rocky",
        "photon",
        "coreos",
        "asianux",
        "mandrake",
        "mandriva",
        "opensuse",
        "suse",
        "turbolinux",
        "redhat",
        "amazonlinux",
    ];
    if LINUX.iter().any(|x| g.contains(x)) {
        Family::Linux
    } else {
        Family::Other
    }
}

/// A PVE VM name (DNS characters) from the VMware display name.
fn pve_name(display: &str) -> String {
    let n: String = display
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-")
        .chars()
        .take(55)
        .collect::<String>()
        .trim_end_matches('-')
        .to_owned();
    if n.is_empty() {
        "vmware-vm".into()
    } else {
        n
    }
}

/// `size=` value of a drive: whole units where they fit.
fn size_str(bytes: u64) -> String {
    for (u, s) in [(1u64 << 40, "T"), (1 << 30, "G"), (1 << 20, "M"), (1 << 10, "K")] {
        if bytes >= u && bytes.is_multiple_of(u) {
            return format!("{}{s}", bytes / u);
        }
    }
    bytes.to_string()
}

/// Order of the snapshot's disks: controller kind (SCSI, SATA, NVMe, IDE, other), then bus and unit.
fn disk_key(index: &str) -> (usize, u32, u32, String) {
    const KINDS: [&str; 4] = ["scsi", "sata", "nvme", "ide"];
    let kind = KINDS.iter().position(|k| index.starts_with(k)).unwrap_or(KINDS.len());
    let digits = index.trim_start_matches(|c: char| c.is_ascii_alphabetic());
    let (bus, unit) = digits.split_once('-').unwrap_or((digits, "0"));
    (
        kind,
        bus.parse().unwrap_or(u32::MAX),
        unit.parse().unwrap_or(u32::MAX),
        index.to_owned(),
    )
}

/// The MAC of `ethernet<n>` (static `address` or `generatedAddress`), upper-case as PVE writes it.
fn mac(v: &BTreeMap<String, String>, n: u32) -> Option<String> {
    let m = v
        .get(&format!("ethernet{n}.address"))
        .or_else(|| v.get(&format!("ethernet{n}.generatedaddress")))?;
    let ok = m.len() == 17
        && m.split(':')
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()));
    ok.then(|| m.to_ascii_uppercase())
}

/// Converts the `.vmx` and the snapshot's disks into a PVE configuration for VM `target` with its disks on
/// `storage` and its NICs on `bridge`.
pub fn convert(vmx: &str, disks: &[VmDisk], target: u32, storage: &str, bridge: &str) -> Result<Converted> {
    if disks.is_empty() {
        bail!("the snapshot has no disks");
    }
    let v = parse_vmx(vmx);
    let get = |k: &str| v.get(k).map(String::as_str);
    let fam = family(get("guestos").unwrap_or(""));
    let name = pve_name(get("displayname").unwrap_or(""));
    let mut notes = Vec::new();

    let memory: u64 = get("memsize")
        .and_then(|m| m.parse().ok())
        .filter(|m| *m >= 16)
        .unwrap_or(1024);
    let vcpus: u32 = get("numvcpus")
        .and_then(|n| n.parse().ok())
        .filter(|n| *n >= 1)
        .unwrap_or(1);
    let per_socket: u32 = get("cpuid.corespersocket")
        .and_then(|n| n.parse().ok())
        .filter(|c| *c >= 1 && vcpus.is_multiple_of(*c))
        .unwrap_or(vcpus);
    let sockets = vcpus / per_socket;
    let guest_os = get("guestos").unwrap_or("other").to_ascii_lowercase();
    let ostype = match fam {
        Family::Linux => "l26",
        // VMware ids: windows11-64, windows2019srvNext-64 (Server 2022), windows2022srvNext-64 (Server 2025)
        Family::Windows if ["11", "srvnext", "2022", "2025"].iter().any(|x| guest_os.contains(x)) => "win11",
        Family::Windows => "win10",
        Family::Other => "other",
    };
    let efi = get("firmware").is_some_and(|f| f.eq_ignore_ascii_case("efi"));

    let mut sorted: Vec<&VmDisk> = disks.iter().collect();
    sorted.sort_by_key(|d| disk_key(&d.index));
    // Linux: VirtIO SCSI; Windows and others: SATA (drivers built in), up to the six ports of the AHCI controller
    let (bus, max) = if fam == Family::Linux {
        ("scsi", 30)
    } else {
        ("sata", 6)
    };
    if sorted.len() > max {
        bail!(
            "{} disks: more than the {max} {bus} ports a PVE VM has for this guest type",
            sorted.len()
        );
    }
    let mut lines = vec![
        format!("name: {name}"),
        format!("memory: {memory}"),
        format!("cores: {per_socket}"),
        format!("sockets: {sockets}"),
        format!("ostype: {ostype}"),
    ];
    if efi {
        lines.push("bios: ovmf".into());
        lines.push("machine: q35".into());
        notes.push(
            "UEFI: the VM boots without an EFI disk (default variables); add one under Hardware if the guest \
             needs persistent boot entries"
                .into(),
        );
        if get("uefi.secureboot.enabled").is_some_and(|s| s.eq_ignore_ascii_case("true")) {
            notes.push("Secure Boot was on in VMware; it is off in the restored VM".into());
        }
    }
    if fam == Family::Linux {
        lines.push("scsihw: virtio-scsi-single".into());
    }
    let mut devices = Vec::new();
    for (i, d) in sorted.iter().enumerate() {
        let key = format!("{bus}{i}");
        lines.push(format!(
            "{key}: {storage}:vm-{target}-disk-{i},size={}",
            size_str(d.size)
        ));
        devices.push((format!("drive-{key}"), d.index.clone(), d.size));
    }
    lines.push(format!("boot: order={bus}0"));
    let model = if fam == Family::Linux { "virtio" } else { "e1000e" };
    let mut nics = 0;
    for n in 0..10 {
        if !get(&format!("ethernet{n}.present")).is_some_and(|p| p.eq_ignore_ascii_case("true")) {
            continue;
        }
        let m = mac(&v, n).map(|m| format!("={m}")).unwrap_or_default();
        lines.push(format!("net{nics}: {model}{m},bridge={bridge}"));
        nics += 1;
    }
    if fam != Family::Linux {
        notes.push(format!(
            "{}: disks on SATA and NICs as e1000e (built-in drivers); install the VirtIO drivers, then switch to \
             VirtIO SCSI and network for speed",
            if fam == Family::Windows {
                "Windows guest"
            } else {
                "guest without known VirtIO support"
            }
        ));
    }
    let mut conf = lines.join("\n");
    conf.push('\n');
    Ok(Converted {
        conf,
        name,
        devices,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINUX_VMX: &str = r#".encoding = "UTF-8"
displayName = "nx-cbt (Debian 12)"
guestOS = "debian12-64"
memSize = "2048"
numvcpus = "4"
cpuid.coresPerSocket = "2"
scsi0.virtualDev = "pvscsi"
scsi0:0.fileName = "nx-cbt.vmdk"
ethernet0.present = "TRUE"
ethernet0.virtualDev = "vmxnet3"
ethernet0.addressType = "generated"
ethernet0.generatedAddress = "00:0c:29:ab:cd:ef"
ethernet1.present = "FALSE"
ctkEnabled = "TRUE"
"#;

    fn disks(list: &[(&str, u64)]) -> Vec<VmDisk> {
        list.iter()
            .map(|(i, s)| VmDisk {
                index: (*i).into(),
                size: *s,
            })
            .collect()
    }

    #[test]
    fn linux_guest_gets_virtio() {
        let c = convert(
            LINUX_VMX,
            &disks(&[("scsi0-1", 4 << 30), ("scsi0-0", 16 << 30)]),
            220,
            "local-lvm",
            "vmbr0",
        )
        .unwrap();
        assert_eq!(c.name, "nx-cbt-debian-12");
        assert_eq!(
            c.conf,
            "name: nx-cbt-debian-12\nmemory: 2048\ncores: 2\nsockets: 2\nostype: l26\nscsihw: virtio-scsi-single\n\
             scsi0: local-lvm:vm-220-disk-0,size=16G\nscsi1: local-lvm:vm-220-disk-1,size=4G\nboot: order=scsi0\n\
             net0: virtio=00:0C:29:AB:CD:EF,bridge=vmbr0\n"
        );
        assert_eq!(
            c.devices,
            vec![
                ("drive-scsi0".into(), "scsi0-0".into(), 16 << 30),
                ("drive-scsi1".into(), "scsi0-1".into(), 4 << 30)
            ]
        );
        assert!(c.notes.is_empty());
    }

    #[test]
    fn windows_uefi_guest_gets_sata_and_e1000e() {
        let vmx =
            "displayName = \"SQL 01\"\nguestOS = \"windows2019srvNext-64\"\nmemSize = \"8192\"\nnumvcpus = \"2\"\n\
                   firmware = \"efi\"\nuefi.secureBoot.enabled = \"TRUE\"\nethernet0.present = \"TRUE\"\n\
                   ethernet0.address = \"00:50:56:01:02:03\"\nethernet1.present = \"TRUE\"\n";
        let c = convert(
            vmx,
            &disks(&[("nvme0-0", 1 << 30), ("sata0-0", 64 << 30)]),
            230,
            "ceph",
            "vmbr1",
        )
        .unwrap();
        assert!(c.conf.contains("ostype: win11\n"), "{}", c.conf);
        assert!(c.conf.contains("bios: ovmf\nmachine: q35\n"));
        assert!(!c.conf.contains("scsihw"));
        // SATA before NVMe in the order, so the old boot disk stays first
        assert!(c
            .conf
            .contains("sata0: ceph:vm-230-disk-0,size=64G\nsata1: ceph:vm-230-disk-1,size=1G\nboot: order=sata0\n"));
        assert!(c
            .conf
            .contains("net0: e1000e=00:50:56:01:02:03,bridge=vmbr1\nnet1: e1000e,bridge=vmbr1\n"));
        assert_eq!(c.notes.len(), 3, "{:?}", c.notes);
        assert_eq!(c.devices[0], ("drive-sata0".into(), "sata0-0".into(), 64 << 30));
    }

    #[test]
    fn edge_cases() {
        // no disks, too many SATA disks for a Windows guest
        assert!(convert(LINUX_VMX, &[], 220, "s", "vmbr0").is_err());
        let seven: Vec<(String, u64)> = (0..7).map(|i| (format!("sata0-{i}"), 1 << 30)).collect();
        let seven: Vec<(&str, u64)> = seven.iter().map(|(n, s)| (n.as_str(), *s)).collect();
        assert!(convert("guestOS = \"windows9-64\"\n", &disks(&seven), 220, "s", "vmbr0").is_err());
        // defaults when the .vmx says little; odd sizes and names
        let c = convert(
            "displayName = \"--\"\n",
            &disks(&[("scsi0-0", 1_000_000)]),
            221,
            "s",
            "vmbr0",
        )
        .unwrap();
        assert!(
            c.conf
                .starts_with("name: vmware-vm\nmemory: 1024\ncores: 1\nsockets: 1\nostype: other\n"),
            "{}",
            c.conf
        );
        assert!(c.conf.contains("sata0: s:vm-221-disk-0,size=1000000\n"));
        // cores per socket that do not divide the vCPUs fall back to one socket
        let c = convert(
            "numvcpus = \"6\"\ncpuid.coresPerSocket = \"4\"\nguestOS = \"ubuntu-64\"\n",
            &disks(&[("scsi0-0", 1 << 30)]),
            222,
            "s",
            "b",
        )
        .unwrap();
        assert!(c.conf.contains("cores: 6\nsockets: 1\n"));
        assert_eq!(size_str(3 << 20), "3M");
        assert_eq!(size_str(1 << 40), "1T");
        assert_eq!(parse_vmx("A.B = \"x\"\n# c = \"d\"\n")["a.b"], "x");
    }
}
