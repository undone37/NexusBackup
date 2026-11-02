//! #19 (docs/bmr.md "Windows"): the machine layout of a Windows host for bare-metal recovery, from the facts
//! `win/layout.ps1` collects (Get-Disk, Get-Partition, Get-Volume), as the protocol's [`Layout`]. Platform
//! independent (unit-tested on Linux); the Win32 side adds the MBR boot code and opens the partitions.
//!
//! Every partition of the recorded disks gets an image (`disk<N>-p<M>`): Windows needs its NTFS volumes block for
//! block (security descriptors, reparse points, short names, the boot files), and the system partitions (ESP,
//! MSR, recovery) have nothing a file restore could recreate. Disks are the ones holding the boot or system
//! partition or a volume with a drive letter.

use agent_proto::layout::{Disk, FileSystem, Layout, Mount, Partition};
use serde::Deserialize;

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
pub struct Facts {
    pub hostname: String,
    pub firmware: String,
    pub os: String,
    pub version: String,
    pub disks: Vec<DiskFacts>,
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
pub struct DiskFacts {
    pub number: u32,
    pub size: u64,
    pub sector: u32,
    pub model: String,
    /// MBR, GPT or RAW
    pub style: String,
    pub signature: Option<u64>,
    pub guid: Option<String>,
    pub boot: bool,
    pub system: bool,
    pub bus: String,
    pub partitions: Vec<PartFacts>,
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
pub struct PartFacts {
    pub number: u32,
    pub offset: u64,
    pub size: u64,
    pub mbr_type: Option<u32>,
    pub gpt_type: Option<String>,
    pub guid: Option<String>,
    pub active: bool,
    pub letter: String,
    /// Get-Partition `Type`: Basic, System, Reserved, Recovery, IFS, ... (dynamic disks show other values)
    #[serde(rename = "type")]
    pub kind: String,
    pub fs: Option<String>,
    pub label: Option<String>,
    /// `\\?\Volume{...}\` when the partition holds a volume
    pub volume: Option<String>,
}

fn guid(s: &str) -> String {
    s.trim_matches(|c| c == '{' || c == '}').to_ascii_lowercase()
}

/// The image name of partition `p` of disk `d`.
pub fn image_name(d: u32, p: u32) -> String {
    format!("disk{d}-p{p}")
}

/// The device path of partition `p` of disk `d` (readable raw, also without a file system).
pub fn partition_device(d: u32, p: u32) -> String {
    format!("\\\\?\\GLOBALROOT\\Device\\Harddisk{d}\\Partition{p}")
}

/// The disks to record: holding the boot or system partition, or a lettered volume; not USB.
fn wanted(d: &DiskFacts) -> bool {
    !d.bus.eq_ignore_ascii_case("usb")
        && (d.boot
            || d.system
            || d.partitions
                .iter()
                .any(|p| !p.letter.trim().is_empty() && p.letter != "\0"))
}

/// `Facts` -> `Layout`; `boot_code(disk)` reads the first 440 bytes of a disk (Win32 side).
pub fn build(f: &Facts, mut boot_code: impl FnMut(u32) -> Option<Vec<u8>>) -> Layout {
    let mut l = Layout {
        version: 1,
        hostname: f.hostname.clone(),
        os: format!("{} {}", f.os, f.version).trim().to_owned(),
        os_id: "windows".into(),
        firmware: if f.firmware == "uefi" {
            "uefi".into()
        } else {
            "bios".into()
        },
        bootloader: "windows".into(),
        ..Default::default()
    };
    for d in f.disks.iter().filter(|d| wanted(d)) {
        let sector = u64::from(d.sector.max(512));
        let table = match d.style.to_ascii_uppercase().as_str() {
            "GPT" => "gpt",
            "MBR" => "dos",
            _ => {
                l.warnings.push(format!(
                    "disk {}: no partition table ({}): not recorded",
                    d.number, d.style
                ));
                continue;
            }
        };
        if d.bus.eq_ignore_ascii_case("spaces") {
            l.warnings.push(format!(
                "disk {}: a Storage Spaces disk: not restorable this way",
                d.number
            ));
        }
        let id = match table {
            "gpt" => d.guid.as_deref().map(guid).unwrap_or_default(),
            _ => d.signature.map(|s| format!("0x{s:08x}")).unwrap_or_default(),
        };
        let mut parts = Vec::new();
        for p in &d.partitions {
            if !matches!(
                p.kind.as_str(),
                "Basic" | "System" | "Reserved" | "Recovery" | "IFS" | "FAT32" | "Unknown" | ""
            ) {
                l.warnings.push(format!(
                    "disk {} partition {}: type {} (a dynamic disk?): the restored machine may not boot",
                    d.number, p.number, p.kind
                ));
            }
            let ptype = match table {
                "gpt" => p.gpt_type.as_deref().map(guid).unwrap_or_default(),
                _ => format!("{:x}", p.mbr_type.unwrap_or(7)),
            };
            parts.push(Partition {
                path: partition_device(d.number, p.number),
                number: p.number,
                start: p.offset / sector,
                size: p.size / sector,
                ptype,
                uuid: if table == "gpt" {
                    p.guid.as_deref().map(guid).unwrap_or_default()
                } else {
                    String::new()
                },
                name: String::new(),
                bootable: p.active,
                attrs: String::new(),
                image: image_name(d.number, p.number),
                image_size: p.size,
            });
            if let Some(fs) = p.fs.as_deref().filter(|x| !x.is_empty()) {
                let fstype = match fs.to_ascii_uppercase().as_str() {
                    "NTFS" => "ntfs",
                    "REFS" => "refs",
                    "FAT32" | "FAT" => "vfat",
                    "EXFAT" => "exfat",
                    _ => "other",
                };
                let letter = p.letter.trim().trim_matches('\0');
                l.filesystems.push(FileSystem {
                    device: partition_device(d.number, p.number),
                    fstype: fstype.into(),
                    label: p.label.clone().unwrap_or_default(),
                    mounts: if letter.is_empty() {
                        vec![]
                    } else {
                        vec![Mount {
                            mountpoint: format!("{letter}:\\"),
                            options: String::new(),
                        }]
                    },
                    ..Default::default()
                });
            }
        }
        let code = boot_code(d.number).map(|c| c.iter().map(|b| format!("{b:02x}")).collect::<String>());
        l.disks.push(Disk {
            name: format!("disk{}", d.number),
            path: format!("\\\\.\\PhysicalDrive{}", d.number),
            size: d.size,
            sector_size: sector as u32,
            model: d.model.clone(),
            table: table.into(),
            id,
            partitions: parts,
            boot_code: code.unwrap_or_default(),
        });
    }
    if l.disks.is_empty() {
        l.warnings
            .push("no disk with the boot or system partition found".into());
    }
    l
}

/// The partitions to image with what to read them from: (image name, partition device, volume path when VSS can
/// snapshot it (NTFS / ReFS), bytes).
pub fn images(f: &Facts) -> Vec<(String, String, Option<String>, u64)> {
    let mut out = Vec::new();
    for d in f
        .disks
        .iter()
        .filter(|d| wanted(d) && matches!(d.style.to_ascii_uppercase().as_str(), "GPT" | "MBR"))
    {
        for p in &d.partitions {
            let vss =
                p.fs.as_deref()
                    .filter(|fs| fs.eq_ignore_ascii_case("ntfs") || fs.eq_ignore_ascii_case("refs"))
                    .and(p.volume.clone());
            out.push((
                image_name(d.number, p.number),
                partition_device(d.number, p.number),
                vss,
                p.size,
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Get-Disk / Get-Partition as on the spike's VM (SeaBIOS, MBR, System Reserved + C:) plus a data disk with no
    /// letter and a USB stick.
    fn facts() -> Facts {
        serde_json::from_value(serde_json::json!({
            "hostname": "WINSRV", "firmware": "bios", "os": "Microsoft Windows Server 2022 Standard", "version": "10.0.20348",
            "disks": [
                {"number": 0, "size": 42949672960u64, "sector": 512, "model": "QEMU HARDDISK", "style": "MBR",
                 "signature": 3735928559u64, "boot": true, "system": true, "bus": "SATA", "partitions": [
                    {"number": 1, "offset": 1048576, "size": 104857600, "mbr_type": 7, "active": true, "letter": "",
                     "type": "IFS", "fs": "NTFS", "label": "System Reserved", "volume": "\\\\?\\Volume{a}\\"},
                    {"number": 2, "offset": 105906176, "size": 42842718208u64, "mbr_type": 7, "letter": "C",
                     "type": "IFS", "fs": "NTFS", "label": "", "volume": "\\\\?\\Volume{b}\\"}]},
                {"number": 1, "size": 100, "style": "GPT", "bus": "SATA", "partitions": []},
                {"number": 2, "size": 8000000000u64, "style": "MBR", "bus": "USB", "boot": false,
                 "partitions": [{"number": 1, "letter": "E", "fs": "FAT32"}]}
            ]
        }))
        .unwrap()
    }

    #[test]
    fn mbr_layout() {
        let l = build(&facts(), |d| (d == 0).then(|| vec![0xeb, 0x63]));
        assert_eq!((l.os_id.as_str(), l.firmware.as_str()), ("windows", "bios"));
        assert_eq!(
            l.disks.len(),
            1,
            "the boot disk only: disk 1 has no letter, disk 2 is USB"
        );
        let d = &l.disks[0];
        assert_eq!(
            (d.table.as_str(), d.id.as_str(), d.boot_code.as_str()),
            ("dos", "0xdeadbeef", "eb63")
        );
        assert_eq!(d.path, "\\\\.\\PhysicalDrive0");
        let p = &d.partitions[0];
        assert_eq!(
            (p.start, p.size, p.ptype.as_str(), p.bootable),
            (2048, 204800, "7", true)
        );
        assert_eq!((p.image.as_str(), p.image_size), ("disk0-p1", 104_857_600));
        assert_eq!(p.path, "\\\\?\\GLOBALROOT\\Device\\Harddisk0\\Partition1");
        assert_eq!(l.filesystems.len(), 2);
        assert_eq!(l.filesystems[1].mounts[0].mountpoint, "C:\\");
        let im = images(&facts());
        assert_eq!(im.len(), 2);
        assert_eq!(im[1].2.as_deref(), Some("\\\\?\\Volume{b}\\"), "NTFS through VSS");
    }

    #[test]
    fn gpt_layout() {
        let f: Facts = serde_json::from_value(serde_json::json!({
            "firmware": "uefi", "disks": [{"number": 0, "size": 1000, "sector": 512, "style": "GPT", "boot": true,
              "guid": "{ABCD-1}", "bus": "NVMe", "partitions": [
                {"number": 1, "offset": 1048576, "size": 104857600, "gpt_type": "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}",
                 "guid": "{E1}", "type": "System", "fs": "FAT32", "volume": "\\\\?\\Volume{e}\\"},
                {"number": 2, "offset": 105906176, "size": 16777216, "gpt_type": "{e3c9e316-0b5c-4db8-817d-f92df00215ae}",
                 "guid": "{E2}", "type": "Reserved"}]}]
        }))
        .unwrap();
        let l = build(&f, |_| None);
        let d = &l.disks[0];
        assert_eq!(
            (d.table.as_str(), d.id.as_str(), l.firmware.as_str()),
            ("gpt", "abcd-1", "uefi")
        );
        assert_eq!(d.partitions[0].ptype, "c12a7328-f81f-11d2-ba4b-00a0c93ec93b");
        assert_eq!(d.partitions[1].uuid, "e2");
        let im = images(&f);
        assert!(im.iter().all(|i| i.2.is_none()), "FAT32 ESP and the MSR are read raw");
        assert!(l.warnings.is_empty(), "{:?}", l.warnings);
    }
}
