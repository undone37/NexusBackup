//! File system / container detection by signature.

use crate::disk::{le16, le32, Vol};

#[derive(Clone, Debug, PartialEq)]
pub enum Kind {
    Ext,
    Ntfs,
    Fat,
    Exfat,
    Xfs,
    LvmPv,
    Swap,
    /// recognized, not indexed: (fs name, reason)
    Unsupported(&'static str, &'static str),
    /// nothing recognized (empty, zeroed, unknown)
    Unknown,
}

/// Boot sector of a FAT / NTFS / exFAT file system (sector 0 of a volume).
pub fn is_boot_sector_fs(s: &[u8]) -> bool {
    fat_boot(s) || s.get(3..11) == Some(b"NTFS    ") || s.get(3..11) == Some(b"EXFAT   ")
}

/// A FAT boot sector: jump, sane BPB (bytes per sector, sectors per cluster,
/// reserved sectors, FAT count), signature.
pub fn fat_boot(s: &[u8]) -> bool {
    if s.len() < 512 || s[510] != 0x55 || s[511] != 0xaa || !matches!(s[0], 0xeb | 0xe9) {
        return false;
    }
    let bps = le16(s, 11);
    let spc = s[13];
    let fats = s[16];
    matches!(bps, 512 | 1024 | 2048 | 4096)
        && spc.is_power_of_two()
        && le16(s, 14) > 0
        && (1..=4).contains(&fats)
        && (s.get(0x36..0x39) == Some(b"FAT") || s.get(0x52..0x57) == Some(b"FAT32") || le16(s, 22) > 0)
        && s.get(3..11) != Some(b"NTFS    ")
        && s.get(3..11) != Some(b"EXFAT   ")
}

/// Detects what a volume holds from its first 68 KiB.
pub fn probe(v: &Vol) -> Kind {
    let head = match v.read_vec(0, 0x11000) {
        Ok(h) => h,
        Err(_) => return Kind::Unknown,
    };
    let at = |o: usize, m: &[u8]| head.get(o..o + m.len()) == Some(m);
    if at(3, b"NTFS    ") {
        return Kind::Ntfs;
    }
    if at(3, b"EXFAT   ") {
        return Kind::Exfat;
    }
    if at(3, b"-FVE-FS-") {
        return Kind::Unsupported("bitlocker", "BitLocker-encrypted volume");
    }
    if at(3, b"ReFS\0\0\0\0") {
        return Kind::Unsupported("refs", "ReFS is not indexed");
    }
    if at(0, b"LUKS\xba\xbe") {
        return Kind::Unsupported("luks", "LUKS-encrypted volume");
    }
    if at(0, b"XFSB") {
        return Kind::Xfs;
    }
    if le16(&head, 1024 + 56) == 0xEF53 && le32(&head, 1024 + 24) <= 6 {
        return Kind::Ext;
    }
    if at(0x10040, b"_BHRfS_M") {
        return Kind::Unsupported("btrfs", "btrfs is not indexed yet");
    }
    for s in 0..4 {
        if at(s * 512, b"LABELONE") && at(s * 512 + 24, b"LVM2 001") {
            return Kind::LvmPv;
        }
    }
    if at(4086, b"SWAPSPACE2") || at(4086, b"SWAP-SPACE") {
        return Kind::Swap;
    }
    if fat_boot(&head) {
        return Kind::Fat;
    }
    // md RAID superblock 1.1 (offset 0) / 1.2 (offset 4096); 0.90/1.0 sit at the end
    if le32(&head, 0) == 0xa92b_4efc || le32(&head, 4096) == 0xa92b_4efc {
        return Kind::Unsupported("linux_raid_member", "Linux software RAID (md) is not indexed yet");
    }
    if at(0x8001, b"CD001") {
        return Kind::Unsupported("iso9660", "ISO 9660 is not indexed");
    }
    // ZFS vdev label: uberblock magic in the uberblock array (label 0 at 128 KiB)
    // (1 KiB slots; only the slots of written transaction groups carry the magic)
    if let Ok(l) = v.read_vec(128 << 10, 128 << 10) {
        let magic = |s: &[u8]| {
            le32(s, 0) == 0x00ba_b10c || (s.len() >= 8 && u32::from_be_bytes([s[4], s[5], s[6], s[7]]) == 0x00ba_b10c)
        };
        if l.chunks(1024).any(magic) {
            return Kind::Unsupported("zfs_member", "ZFS inside the guest is not indexed");
        }
    }
    Kind::Unknown
}
