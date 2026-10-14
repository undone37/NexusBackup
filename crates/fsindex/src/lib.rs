//! Guest file index without the restore micro-VM (Phase 31a, docs/file-index-v2-plan.md).
//!
//! `nexus-fsindex` lists the files of a VM snapshot's disk images read-only:
//! partition tables (GPT, MBR with logical partitions), LVM2 (linear, striped,
//! mirror / raid1 by reading the first leg, thin), ext2/3/4 (crate `ext4-view`), NTFS
//! (crate `ntfs`), FAT12/16/32 (crate `fatfs`), exFAT and XFS (own parsers).
//! Other file systems and containers (btrfs, ReFS, BitLocker, LUKS, Windows LDM,
//! Storage Spaces, ZFS, md RAID, LVM cache/VDO) are reported per volume as "not
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
pub mod regf;
pub mod sandbox;
pub mod walk;
pub mod xfs;

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
    /// how the SYSTEM hive's `MountedDevices` names this volume: `guid:<GPT partition
    /// or dynamic volume GUID>`, `mbr:<disk signature>:<byte offset>`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub win_id: Option<String>,
    /// Windows system volume: the drive letters of its SYSTEM hive (`D:`, `win_id`)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub drives: Vec<(String, String)>,
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

/// One directory of a parsed volume (Phase 31c): what its listing depended on,
/// so the next snapshot can take its entries over unread when none of that changed.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct DirRec {
    /// path below the volume root (`""` = the root)
    pub rel: String,
    /// (disk, chunk index) its listing read: the directory's index and its
    /// children's records / inodes
    pub deps: Vec<(u32, u64)>,
    /// its subdirectories: (NTFS file record number, 0 elsewhere; name)
    pub subdirs: Vec<(u64, String)>,
    /// its entries' share of the volume's `dedup_files` / `skipped_entries`
    #[serde(default)]
    pub dedup: u64,
    #[serde(default)]
    pub skipped: u64,
}

/// The sealed per-snapshot volume report (`fsindex` side file, crate
/// chunkstore `snapfile.rs`): what was found on each volume and, for the next
/// snapshot, which chunks each volume's parse read.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Report {
    pub version: u32,
    pub volumes: Vec<VolumeRec>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct VolumeRec {
    pub volume: Volume,
    /// (disk index name, chunk index, chunk id hex) the parse read
    #[serde(default)]
    pub reads: Vec<(String, u64, String)>,
}

/// Side file name of the report.
pub const REPORT_FILE: &str = "fsindex";

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
    /// which share of the directory trees this helper walks (Phase 32)
    #[serde(default)]
    pub part: Part,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_entries: 5_000_000,
            budget_secs: 3600,
            part: Part::default(),
        }
    }
}

/// Helper `index` of `count` walking one volume together (Phase 32). Every
/// directory belongs to one helper, which emits its entries: the root to helper
/// 0, any other by a hash of its path, below [`PART_DEPTH`] by a hash of its first
/// [`PART_DEPTH`] components (a subtree stays together). Directories above that
/// depth are walked by all helpers to find the ones below (cheaply where they are
/// not theirs: subdirectories only); deeper ones only by their owner. Every entry
/// comes from exactly one helper.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub struct Part {
    pub index: u32,
    pub count: u32,
}

impl Default for Part {
    fn default() -> Self {
        Part { index: 0, count: 1 }
    }
}

/// Depth from which whole subtrees go to one helper (root = 0): with 3 the
/// subdirectories of `Windows/WinSxS` (tens of thousands) spread over all helpers.
pub const PART_DEPTH: usize = 3;

impl Part {
    /// The helper that owns directory `rel` at `depth` (its entries, below
    /// [`PART_DEPTH`] also its walk).
    fn owner(&self, rel: &str, depth: usize) -> u32 {
        if self.count <= 1 || depth == 0 {
            return 0;
        }
        // FNV-1a of the first PART_DEPTH components: stable across processes
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in rel.split('/').take(PART_DEPTH).collect::<Vec<_>>().join("/").bytes() {
            h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
        (h % u64::from(self.count)) as u32
    }

    /// Whether this helper reads directory `rel` at `depth`.
    pub fn walks(&self, rel: &str, depth: usize) -> bool {
        depth < PART_DEPTH || self.owner(rel, depth) == self.index
    }

    /// Whether this helper emits the entries of directory `rel` at `depth`.
    pub fn owns(&self, rel: &str, depth: usize) -> bool {
        self.owner(rel, depth) == self.index
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
    fn parts_own_every_directory_once() {
        let parts: Vec<Part> = (0..4).map(|index| Part { index, count: 4 }).collect();
        let mut used = [0u32; 4];
        for i in 0..400 {
            for (rel, depth) in [
                (String::new(), 0),
                (format!("d{i}"), 1),
                (format!("d{}/s{i}", i % 7), 2),
                (format!("d{}/s{}/t{i}", i % 7, i % 5), 3),
                (format!("d{}/s{}/t{i}/x/y", i % 7, i % 5), 5),
            ] {
                let owners: Vec<u32> = parts.iter().filter(|p| p.owns(&rel, depth)).map(|p| p.index).collect();
                assert_eq!(owners.len(), 1, "{rel}");
                let walkers: Vec<u32> = parts.iter().filter(|p| p.walks(&rel, depth)).map(|p| p.index).collect();
                match depth {
                    0 => assert_eq!(owners, [0], "the root belongs to helper 0"),
                    d if d < PART_DEPTH => assert_eq!(walkers.len(), 4, "{rel}: everyone walks the top levels"),
                    _ => assert_eq!(walkers, owners, "{rel}: only its owner walks it"),
                }
                if depth > 0 {
                    used[owners[0] as usize] += 1;
                }
            }
        }
        // a subtree below PART_DEPTH stays with its owner; WinSxS' subdirectories spread
        let o = |rel: &str, d| parts.iter().find(|p| p.owns(rel, d)).unwrap().index;
        assert_eq!(o("Windows/WinSxS/amd64_x", 3), o("Windows/WinSxS/amd64_x/y/z", 5));
        let sxs: std::collections::BTreeSet<u32> =
            (0..64).map(|i| o(&format!("Windows/WinSxS/amd64_{i}"), 3)).collect();
        assert_eq!(sxs.len(), 4, "the subdirectories of one big directory use every helper");
        assert!(used.iter().all(|&n| n > 200), "spread over all helpers: {used:?}");
        assert!(Part::default().walks("a/b/c", 3) && Part::default().owns("a/b/c", 3));
    }

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
