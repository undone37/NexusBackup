//! Machine layout recorded with every Linux backup (docs/bmr.md "Layout"): disks
//! and partition tables, LVM, md RAID / LUKS (detected only), file systems with
//! UUIDs and labels, swap, firmware and boot loader, kernel command line, network.
//! The agent sends it as JSON (`Layout { json }`, CAP_LAYOUT); the appliance keeps
//! it in the host snapshot as `.nexus-system/layout.json`, and the rescue agent
//! recreates the disks from it (`RescueApply`). Every field has a default, so
//! layouts of older or newer agents still parse.

use serde::{Deserialize, Serialize};

/// Format version of [`Layout`].
pub const LAYOUT_VERSION: u32 = 1;
/// Path of the layout file inside a host snapshot (relative to `/`).
pub const LAYOUT_PATH: &str = ".nexus-system/layout.json";

/// The whole machine layout (JSON object, every field optional).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct Layout {
    /// [`LAYOUT_VERSION`] of the writer (0 when absent)
    pub version: u32,
    /// host name at backup time
    pub hostname: String,
    /// `PRETTY_NAME` of /etc/os-release
    pub os: String,
    /// `ID` and `ID_LIKE` of /etc/os-release (picks the boot loader / initramfs tools)
    pub os_id: String,
    /// running kernel release (`uname -r`)
    pub kernel: String,
    /// /proc/cmdline
    pub cmdline: String,
    /// "uefi" or "bios"
    pub firmware: String,
    /// "grub2", "systemd-boot" or "" (unknown)
    pub bootloader: String,
    /// whole disks holding the system's file systems
    pub disks: Vec<Disk>,
    /// LVM volume groups
    pub vgs: Vec<Vg>,
    /// software RAID arrays (detected; not recreated)
    pub md: Vec<Md>,
    /// LUKS containers (detected; not recreated)
    pub luks: Vec<Luks>,
    /// mounted on-disk file systems
    pub filesystems: Vec<FileSystem>,
    /// swap partitions and LVs (swap files are restored as files)
    pub swaps: Vec<Swap>,
    /// /etc/fstab as it was (reference; the restored copy is the one used)
    pub fstab: String,
    /// network interfaces except `lo` (reference for the operator)
    pub network: Vec<NetIf>,
    /// what could not be recorded
    pub warnings: Vec<String>,
}

/// One whole disk.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct Disk {
    /// kernel name, e.g. `sda`, `nvme0n1`, `vda`
    pub name: String,
    /// device path, e.g. `/dev/sda`
    pub path: String,
    /// bytes
    pub size: u64,
    /// logical sector size in bytes
    pub sector_size: u32,
    /// model string as the kernel reports it ("" if none)
    pub model: String,
    /// "gpt", "dos" or "" (no partition table: whole-disk PV / file system)
    pub table: String,
    /// disk GUID (gpt) or disk identifier (dos)
    pub id: String,
    /// partitions in table order
    pub partitions: Vec<Partition>,
}

/// One partition of a [`Disk`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct Partition {
    /// device path, e.g. `/dev/sda1`
    pub path: String,
    /// partition number in the table (1-based)
    pub number: u32,
    /// sectors
    pub start: u64,
    /// sectors
    pub size: u64,
    /// GPT type GUID or MBR type (hex, e.g. "83")
    pub ptype: String,
    /// GPT partition GUID (PARTUUID)
    pub uuid: String,
    /// GPT partition name
    pub name: String,
    /// MBR boot flag
    pub bootable: bool,
    /// GPT attribute bits as sfdisk prints them
    pub attrs: String,
}

/// One LVM volume group.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct Vg {
    /// VG name
    pub name: String,
    /// LVM UUID of the VG
    pub uuid: String,
    /// bytes
    pub extent_size: u64,
    /// its physical volumes
    pub pvs: Vec<Pv>,
    /// its logical volumes
    pub lvs: Vec<Lv>,
}

/// One LVM physical volume of a [`Vg`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct Pv {
    /// device path (a partition or a whole disk)
    pub device: String,
    /// LVM UUID of the PV
    pub uuid: String,
    /// bytes
    pub size: u64,
}

/// One LVM logical volume of a [`Vg`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct Lv {
    /// LV name
    pub name: String,
    /// LVM UUID of the LV
    pub uuid: String,
    /// bytes (virtual size for thin volumes)
    pub size: u64,
    /// "linear", "striped", "thin-pool", "thin", …
    pub segtype: String,
    /// thin volumes: their pool
    pub pool: String,
    /// thin pools: metadata size in bytes
    pub metadata_size: u64,
    /// `/dev/mapper/<vg>-<lv>`
    pub dm_path: String,
}

/// A software RAID array (recorded for the operator, not recreated).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct Md {
    /// array device, e.g. `/dev/md0`
    pub path: String,
    /// RAID level as lsblk names it, e.g. `raid1`
    pub level: String,
    /// member device paths
    pub devices: Vec<String>,
}

/// A LUKS container (recorded for the operator, not recreated).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct Luks {
    /// the encrypted device (partition / LV)
    pub device: String,
    /// UUID of the LUKS header
    pub uuid: String,
    /// the opened mapping, e.g. `/dev/mapper/luks-…`
    pub mapping: String,
}

/// A mounted file system on a disk, partition or LV.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct FileSystem {
    /// block device: a partition, `/dev/mapper/<vg>-<lv>`, …
    pub device: String,
    /// file system type as the kernel names it (`ext4`, `xfs`, `btrfs`, `vfat`, ...)
    pub fstype: String,
    /// e.g. "FAT32", "1.0"
    pub version: String,
    /// file system UUID (recreated with the same value, `/etc/fstab` refers to it)
    pub uuid: String,
    /// file system label ("" if none)
    pub label: String,
    /// where it was mounted (a btrfs file system once per subvolume)
    pub mounts: Vec<Mount>,
}

/// One mount of a [`FileSystem`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct Mount {
    /// absolute mount point
    pub mountpoint: String,
    /// mount options, comma-separated as `findmnt` prints them
    pub options: String,
}

impl Mount {
    /// btrfs `subvol=` of the mount options ("" = top level / default).
    pub fn subvol(&self) -> &str {
        self.options
            .split(',')
            .find_map(|o| o.strip_prefix("subvol="))
            .map(|s| s.trim_start_matches('/'))
            .unwrap_or("")
    }
}

/// A swap partition or LV.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct Swap {
    /// device path
    pub device: String,
    /// swap UUID (recreated with the same value)
    pub uuid: String,
    /// swap label ("" if none)
    pub label: String,
}

/// A network interface.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct NetIf {
    /// interface name, e.g. `eth0`
    pub name: String,
    /// MAC address, `aa:bb:cc:dd:ee:ff`
    pub mac: String,
    /// "address/prefix"
    pub addrs: Vec<String>,
}

impl Layout {
    /// The boot loader target: the disk with the EFI system partition (UEFI) or a
    /// BIOS boot partition / bootable MBR partition (BIOS), else the disk holding
    /// `/boot` or `/` (or the first disk).
    pub fn boot_disk(&self) -> Option<&Disk> {
        let marker = |d: &&Disk| {
            d.partitions.iter().any(|p| {
                let t = p.ptype.to_ascii_uppercase();
                if self.firmware == "uefi" {
                    t == "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" || t == "EF"
                } else {
                    t == "21686148-6449-6E6F-744E-656564454649" || p.bootable
                }
            })
        };
        if let Some(d) = self.disks.iter().find(marker) {
            return Some(d);
        }
        let root = self
            .filesystems
            .iter()
            .find(|f| f.mounts.iter().any(|m| m.mountpoint == "/boot"))
            .or_else(|| {
                self.filesystems
                    .iter()
                    .find(|f| f.mounts.iter().any(|m| m.mountpoint == "/"))
            });
        let on = |d: &&Disk| {
            root.is_some_and(|f| {
                d.path == f.device
                    || d.partitions.iter().any(|p| p.path == f.device)
                    || self.vgs.iter().any(|vg| {
                        vg.lvs.iter().any(|l| l.dm_path == f.device)
                            && vg
                                .pvs
                                .iter()
                                .any(|pv| pv.device == d.path || d.partitions.iter().any(|p| p.path == pv.device))
                    })
            })
        };
        self.disks.iter().find(on).or(self.disks.first())
    }

    /// The EFI system partition's file system (mounted at /boot/efi, /efi or /boot, vfat).
    pub fn esp(&self) -> Option<&FileSystem> {
        ["/boot/efi", "/efi", "/boot"].iter().find_map(|mp| {
            self.filesystems
                .iter()
                .find(|f| f.fstype == "vfat" && f.mounts.iter().any(|m| m.mountpoint == *mp))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fs(device: &str, fstype: &str, mp: &str) -> FileSystem {
        FileSystem {
            device: device.into(),
            fstype: fstype.into(),
            mounts: vec![Mount {
                mountpoint: mp.into(),
                options: "rw".into(),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn subvol_boot_disk_and_esp() {
        let m = Mount {
            mountpoint: "/home".into(),
            options: "rw,relatime,subvol=/home,compress=zstd".into(),
        };
        assert_eq!(m.subvol(), "home");
        let disk = |name: &str, parts: &[u32]| Disk {
            name: name.into(),
            path: format!("/dev/{name}"),
            partitions: parts
                .iter()
                .map(|n| Partition {
                    path: format!("/dev/{name}{n}"),
                    number: *n,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        let l = Layout {
            disks: vec![disk("vdb", &[]), disk("vda", &[1, 2])],
            vgs: vec![Vg {
                name: "vg0".into(),
                pvs: vec![Pv {
                    device: "/dev/vda2".into(),
                    ..Default::default()
                }],
                lvs: vec![Lv {
                    name: "root".into(),
                    dm_path: "/dev/mapper/vg0-root".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            filesystems: vec![
                fs("/dev/vdb", "xfs", "/srv"),
                fs("/dev/mapper/vg0-root", "ext4", "/"),
                fs("/dev/vda1", "vfat", "/boot/efi"),
            ],
            ..Default::default()
        };
        assert_eq!(l.boot_disk().unwrap().name, "vda", "root LV on a PV of vda");
        assert_eq!(l.esp().unwrap().device, "/dev/vda1");
        // BIOS: the disk with the BIOS boot partition wins over the disk holding `/`
        let mut b = l.clone();
        b.firmware = "bios".into();
        b.disks[1].partitions[0].ptype = "21686148-6449-6E6F-744E-656564454649".into();
        b.vgs[0].pvs[0].device = "/dev/vdb".into();
        assert_eq!(b.boot_disk().unwrap().name, "vda");
    }
}
