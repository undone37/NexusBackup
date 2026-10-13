//! Guest file index without the restore micro-VM (Phase 31a, docs/file-index-v2-plan.md).
//!
//! `nexus-fsindex` lists the files of a VM snapshot's disk images read-only:
//! partition tables (GPT, MBR with logical partitions), LVM2 (linear, striped,
//! mirror / raid1 by reading the first leg), ext2/3/4 (crate `ext4-view`), NTFS
//! (crate `ntfs`), FAT12/16/32 (crate `fatfs`) and exFAT (own parser). Other
//! file systems and containers (XFS, btrfs, ReFS, BitLocker, LUKS, Windows LDM,
//! Storage Spaces, ZFS, md RAID, LVM thin) are reported per volume as "not
//! indexed: <reason>"; the micro-VM stays the fallback for them.
//!
//! Guest file systems are untrusted input. The parsers run in the helper
//! process (`src/main.rs`): no keys, no files, no network (SELinux domain
//! `nexus_fsindex_t`, seccomp allowlist, rlimits). The helper asks the parent
//! for disk bytes over stdin/stdout ([`proto`]); the parent ([`parent`], used by
//! nexus-pve) reads the snapshot from the chunk store, answers, records which
//! chunks each volume's parse read, and writes the sealed name index.

pub mod disk;
pub mod exfat;
pub mod fat;
pub mod fs_ext;
pub mod fs_ntfs;
pub mod lvm;
pub mod mapping;
pub mod parent;
pub mod part;
pub mod probe;
pub mod proto;
pub mod sandbox;
pub mod walk;

use serde::{Deserialize, Serialize};

/// Entry kinds (the values of `chunkstore::names::KIND_*`).
pub const KIND_FILE: u8 = 0;
pub const KIND_DIR: u8 = 1;
pub const KIND_SYMLINK: u8 = 2;
pub const KIND_OTHER: u8 = 3;

/// Deepest directory nesting a walker follows (loops in corrupted file systems).
pub const MAX_DEPTH: usize = 256;
/// Longest path (bytes) an entry may have; longer ones are skipped and counted.
pub const MAX_PATH: usize = 4096;

/// What the helper found on one volume (a partition, a whole disk or an LVM
/// logical volume). Sent to the parent at the start (`state` empty) and at the
/// end of the volume.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Volume {
    /// stable identity for the per-volume cache: disk, location, fs, uuid
    pub key: String,
    /// path of the volume in the file browser / restore micro-VM
    /// (`vda1`, `vdb`, `lvm/vg-root`), without leading `/`
    pub browse: String,
    /// `drive-scsi0` (partitions, whole disks) or `vg/lv` (LVM)
    pub device: String,
    /// `ext4`, `ntfs`, `vfat`, `exfat`, `xfs`, `swap`, … (`` = nothing recognized)
    pub fs: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// file system UUID / serial as `/etc/fstab` writes it
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// GPT partition GUID (`PARTUUID=`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partuuid: Option<String>,
    /// `indexed` | `skipped` (swap, empty, boot loader areas: not a problem) |
    /// `unsupported` | `failed` | `partial` (limit hit)
    #[serde(default)]
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default)]
    pub entries: u64,
    /// `/etc/fstab` of a Linux root file system (at most 64 KiB)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fstab: Option<String>,
    /// holds `Windows/System32` (the guest's `C:`)
    #[serde(default)]
    pub windows: bool,
    /// the journal / log was not replayed (crash-consistent snapshot of a
    /// mounted file system): changes of the last seconds may be missing
    #[serde(default)]
    pub dirty: bool,
    /// NTFS files with the Windows deduplication reparse tag (listed with their
    /// logical size; restore them through the Windows agent)
    #[serde(default)]
    pub dedup_files: u64,
    /// entries skipped (path too long, names that do not decode, …)
    #[serde(default)]
    pub skipped_entries: u64,
    /// where the guest mounts it (set by the parent, [`mapping`]): `/`, `/home`,
    /// `C:`; `None`: shown as its label or `vol<N>`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount: Option<String>,
}

impl Volume {
    /// A volume that needs no parse and has no problem (swap, empty space).
    pub fn quiet(&self) -> bool {
        self.state == "skipped"
    }

    pub fn problem(&self) -> bool {
        matches!(self.state.as_str(), "unsupported" | "failed" | "partial")
    }
}

/// One listed entry; `path` relative to the volume root, `/`-separated.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub path: String,
    pub size: u64,
    /// seconds since the epoch
    pub mtime: i64,
    pub kind: u8,
}

/// Limits of one listing (all volumes of a snapshot together).
#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct Limits {
    pub max_entries: u64,
    /// seconds
    pub budget_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_entries: 5_000_000,
            budget_secs: 3600,
        }
    }
}

/// NT time (100 ns since 1601) to unix seconds.
pub fn nt_to_unix(nt: u64) -> i64 {
    (nt / 10_000_000) as i64 - 11_644_473_600
}

/// Lowercase hex.
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The browse name of disk `i` in the restore micro-VM (virtio-blk in the
/// order of the snapshot's disk indexes): vda … vdz, vdaa, vdab, …
pub fn disk_name(i: usize) -> String {
    let mut n = i;
    let mut s = Vec::new();
    loop {
        s.push(b'a' + (n % 26) as u8);
        if n < 26 {
            break;
        }
        n = n / 26 - 1;
    }
    s.reverse();
    format!("vd{}", String::from_utf8(s).unwrap())
}

/// The device-mapper name of an LV (`-` doubled in both parts), as the
/// micro-VM mounts it below `/lvm/`.
pub fn dm_name(vg: &str, lv: &str) -> String {
    format!("{}-{}", vg.replace('-', "--"), lv.replace('-', "--"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(disk_name(0), "vda");
        assert_eq!(disk_name(25), "vdz");
        assert_eq!(disk_name(26), "vdaa");
        assert_eq!(disk_name(27), "vdab");
        assert_eq!(dm_name("vg-data", "root"), "vg--data-root");
        assert_eq!(nt_to_unix(116_444_736_000_000_000), 0);
    }
}
