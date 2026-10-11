//! Windows metadata ↔ `Entry` mapping (pure, tested on Linux). See docs/agent-windows.md.
//!
//! | Windows | `Entry` |
//! |---|---|
//! | LastWriteTime / ChangeTime (FILETIME) | `mtime_ns` / `ctime_ns` (Unix ns) |
//! | CreationTime | xattr `win.created` (FILETIME, i64 LE) |
//! | FILE_ATTRIBUTE_* | xattr `win.attrs` (u32 LE); `mode` = synthesised POSIX bits |
//! | owner, group, DACL, SACL | xattr `win.sd` (self-relative SECURITY_DESCRIPTOR) |
//! | symlink / junction | `Kind::Symlink`, `link_target` = print name, xattr `win.reparse` (raw REPARSE_DATA_BUFFER) |
//! | 128-bit file id | `inode` (low 64 bits; folded if the high half is used, ReFS) |
//! | named `$DATA` stream | own entry `<path>:<stream>`, `Kind::File`, xattr `win.ads` (empty) |
//! | hard link (link count > 1, same file id) | `Kind::Hardlink` to the first path |

use std::fmt::Write as _;

pub const X_SD: &[u8] = b"win.sd";
pub const X_ATTRS: &[u8] = b"win.attrs";
pub const X_CREATED: &[u8] = b"win.created";
pub const X_REPARSE: &[u8] = b"win.reparse";
pub const X_ADS: &[u8] = b"win.ads";

pub const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
pub const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
pub const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x100;
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
pub const FILE_ATTRIBUTE_COMPRESSED: u32 = 0x800;
pub const FILE_ATTRIBUTE_OFFLINE: u32 = 0x1000;
pub const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED: u32 = 0x2000;
pub const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x4000;
pub const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x40_0000;

/// Attributes a restore sets with `SetFileInformationByHandle(FileBasicInfo)`;
/// compression, encryption, sparse and reparse need their own APIs (not restored).
pub const RESTORABLE_ATTRS: u32 = FILE_ATTRIBUTE_READONLY
    | FILE_ATTRIBUTE_HIDDEN
    | FILE_ATTRIBUTE_SYSTEM
    | FILE_ATTRIBUTE_ARCHIVE
    | FILE_ATTRIBUTE_TEMPORARY
    | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;

pub const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
pub const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
const SYMLINK_FLAG_RELATIVE: u32 = 1;

/// 100 ns intervals between 1601-01-01 and 1970-01-01
const EPOCH_DIFF: i64 = 116_444_736_000_000_000;

pub fn filetime_to_unix_ns(ft: i64) -> i64 {
    (ft - EPOCH_DIFF).saturating_mul(100)
}

pub fn unix_ns_to_filetime(ns: i64) -> i64 {
    ns.div_euclid(100) + EPOCH_DIFF
}

/// POSIX-looking mode for appliance-side tools (tar export): directories 0755, files
/// 0644, read-only files 0444.
pub fn synth_mode(attrs: u32) -> u32 {
    if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
        0o755
    } else if attrs & FILE_ATTRIBUTE_READONLY != 0 {
        0o444
    } else {
        0o644
    }
}

/// 128-bit file id → `Entry.inode`.
pub fn inode_of(id: u128) -> u64 {
    let (lo, hi) = (id as u64, (id >> 64) as u64);
    if hi == 0 {
        lo
    } else {
        let h = blake3::hash(&id.to_le_bytes());
        u64::from_le_bytes(h.as_bytes()[..8].try_into().expect("8 bytes"))
    }
}

pub fn xattr<'a>(x: &'a [(Vec<u8>, Vec<u8>)], name: &[u8]) -> Option<&'a [u8]> {
    x.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_slice())
}

pub fn attrs_of(x: &[(Vec<u8>, Vec<u8>)]) -> Option<u32> {
    xattr(x, X_ATTRS).and_then(|v| Some(u32::from_le_bytes(v.try_into().ok()?)))
}

pub fn created_of(x: &[(Vec<u8>, Vec<u8>)]) -> Option<i64> {
    xattr(x, X_CREATED).and_then(|v| Some(i64::from_le_bytes(v.try_into().ok()?)))
}

pub fn is_ads(x: &[(Vec<u8>, Vec<u8>)]) -> bool {
    xattr(x, X_ADS).is_some()
}

// ---------------------------------------------------------------- security descriptors

pub const OWNER_SECURITY_INFORMATION: u32 = 0x1;
pub const GROUP_SECURITY_INFORMATION: u32 = 0x2;
pub const DACL_SECURITY_INFORMATION: u32 = 0x4;
pub const SACL_SECURITY_INFORMATION: u32 = 0x8;
pub const UNPROTECTED_SACL_SECURITY_INFORMATION: u32 = 0x1000_0000;
pub const UNPROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x2000_0000;
pub const PROTECTED_SACL_SECURITY_INFORMATION: u32 = 0x4000_0000;
pub const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;

const SE_DACL_PRESENT: u16 = 0x0004;
const SE_SACL_PRESENT: u16 = 0x0010;
const SE_DACL_PROTECTED: u16 = 0x1000;
const SE_SACL_PROTECTED: u16 = 0x2000;
const SE_SELF_RELATIVE: u16 = 0x8000;

/// What a stored self-relative security descriptor contains.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SdInfo {
    pub owner: Option<String>,
    pub group: Option<String>,
    pub dacl: bool,
    pub sacl: bool,
    pub dacl_protected: bool,
    pub sacl_protected: bool,
}

impl SdInfo {
    /// Validate a self-relative SECURITY_DESCRIPTOR (bounds of every part, SID and ACL
    /// headers) before it is handed to `SetKernelObjectSecurity`.
    pub fn parse(b: &[u8]) -> Result<SdInfo, String> {
        if b.len() < 20 || b[0] != 1 {
            return Err("security descriptor: bad header".into());
        }
        let control = u16::from_le_bytes([b[2], b[3]]);
        if control & SE_SELF_RELATIVE == 0 {
            return Err("security descriptor is not self-relative".into());
        }
        let off = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().expect("4")) as usize;
        let (o_owner, o_group, o_sacl, o_dacl) = (off(4), off(8), off(12), off(16));
        let sid = |o: usize| -> Result<Option<String>, String> {
            if o == 0 {
                return Ok(None);
            }
            parse_sid(b.get(o..).ok_or("SID offset out of range")?).map(|(s, _)| Some(s))
        };
        let acl = |present: bool, o: usize| -> Result<bool, String> {
            if !present || o == 0 {
                return Ok(false); // absent or NULL ACL
            }
            check_acl(b.get(o..).ok_or("ACL offset out of range")?)?;
            Ok(true)
        };
        Ok(SdInfo {
            owner: sid(o_owner)?,
            group: sid(o_group)?,
            dacl: acl(control & SE_DACL_PRESENT != 0, o_dacl)?,
            sacl: acl(control & SE_SACL_PRESENT != 0, o_sacl)?,
            dacl_protected: control & SE_DACL_PROTECTED != 0,
            sacl_protected: control & SE_SACL_PROTECTED != 0,
        })
    }

    /// `SECURITY_INFORMATION` flags to apply this descriptor; `sacl_ok` = the process
    /// holds SeSecurityPrivilege (otherwise the SACL is skipped).
    pub fn apply_flags(&self, sacl_ok: bool) -> u32 {
        let mut f = 0;
        if self.owner.is_some() {
            f |= OWNER_SECURITY_INFORMATION;
        }
        if self.group.is_some() {
            f |= GROUP_SECURITY_INFORMATION;
        }
        if self.dacl {
            f |= DACL_SECURITY_INFORMATION
                | if self.dacl_protected {
                    PROTECTED_DACL_SECURITY_INFORMATION
                } else {
                    UNPROTECTED_DACL_SECURITY_INFORMATION
                };
        }
        if self.sacl && sacl_ok {
            f |= SACL_SECURITY_INFORMATION
                | if self.sacl_protected {
                    PROTECTED_SACL_SECURITY_INFORMATION
                } else {
                    UNPROTECTED_SACL_SECURITY_INFORMATION
                };
        }
        f
    }
}

/// Parse a SID; returns its string form (`S-1-5-32-544`) and length.
pub fn parse_sid(b: &[u8]) -> Result<(String, usize), String> {
    if b.len() < 8 || b[0] != 1 || b[1] > 15 {
        return Err("bad SID".into());
    }
    let n = b[1] as usize;
    let len = 8 + 4 * n;
    if b.len() < len {
        return Err("SID truncated".into());
    }
    let auth = b[2..8].iter().fold(0u64, |a, x| (a << 8) | *x as u64);
    let mut s = format!("S-1-{auth}");
    for i in 0..n {
        let sub = u32::from_le_bytes(b[8 + 4 * i..12 + 4 * i].try_into().expect("4"));
        let _ = write!(s, "-{sub}");
    }
    Ok((s, len))
}

fn check_acl(b: &[u8]) -> Result<(), String> {
    if b.len() < 8 || !(2..=4).contains(&b[0]) {
        return Err("bad ACL header".into());
    }
    let size = u16::from_le_bytes([b[2], b[3]]) as usize;
    let count = u16::from_le_bytes([b[4], b[5]]) as usize;
    if size < 8 || size > b.len() {
        return Err("ACL size out of range".into());
    }
    let mut o = 8;
    for _ in 0..count {
        let h = b.get(o..o + 4).ok_or("ACE header out of range")?;
        let ace_size = u16::from_le_bytes([h[2], h[3]]) as usize;
        if ace_size < 4 || o + ace_size > size {
            return Err("ACE size out of range".into());
        }
        o += ace_size;
    }
    Ok(())
}

// ---------------------------------------------------------------- reparse points

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reparse {
    /// IO_REPARSE_TAG_SYMLINK
    Symlink {
        substitute: Vec<u16>,
        print: Vec<u16>,
        relative: bool,
    },
    /// IO_REPARSE_TAG_MOUNT_POINT (junction or volume mount point)
    MountPoint { substitute: Vec<u16>, print: Vec<u16> },
}

/// Name-surrogate reparse points are links (recorded, never followed); every other
/// tag (dedup, WOF compression, cloud files, HSM) is a data reparse point whose
/// content is read normally.
pub fn is_link_tag(tag: u32) -> bool {
    tag == IO_REPARSE_TAG_SYMLINK || tag == IO_REPARSE_TAG_MOUNT_POINT
}

fn u16s(b: &[u8]) -> Vec<u16> {
    b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect()
}

impl Reparse {
    /// Parse a REPARSE_DATA_BUFFER (as returned by FSCTL_GET_REPARSE_POINT).
    pub fn parse(b: &[u8]) -> Result<Reparse, String> {
        if b.len() < 8 {
            return Err("reparse buffer too short".into());
        }
        let tag = u32::from_le_bytes(b[0..4].try_into().expect("4"));
        let data_len = u16::from_le_bytes([b[4], b[5]]) as usize;
        let data = b.get(8..8 + data_len).ok_or("reparse data length out of range")?;
        let hdr = match tag {
            IO_REPARSE_TAG_SYMLINK => 12,
            IO_REPARSE_TAG_MOUNT_POINT => 8,
            _ => return Err(format!("reparse tag {tag:#x} is not a link")),
        };
        if data.len() < hdr {
            return Err("reparse data too short".into());
        }
        let f = |i: usize| u16::from_le_bytes([data[i], data[i + 1]]) as usize;
        let (so, sl, po, pl) = (f(0), f(2), f(4), f(6));
        let path = &data[hdr..];
        let get = |o: usize, l: usize| -> Result<Vec<u16>, String> {
            if !o.is_multiple_of(2) || !l.is_multiple_of(2) {
                return Err("odd name offset".into());
            }
            Ok(u16s(path.get(o..o + l).ok_or("reparse name out of range")?))
        };
        let (substitute, print) = (get(so, sl)?, get(po, pl)?);
        if substitute.is_empty() {
            return Err("reparse point without target".into());
        }
        Ok(if tag == IO_REPARSE_TAG_SYMLINK {
            let flags = u32::from_le_bytes(data[8..12].try_into().expect("4"));
            Reparse::Symlink {
                substitute,
                print,
                relative: flags & SYMLINK_FLAG_RELATIVE != 0,
            }
        } else {
            Reparse::MountPoint { substitute, print }
        })
    }

    /// Build the REPARSE_DATA_BUFFER (FSCTL_SET_REPARSE_POINT input).
    pub fn build(&self) -> Vec<u8> {
        let (tag, sub, print, flags) = match self {
            Reparse::Symlink {
                substitute,
                print,
                relative,
            } => (IO_REPARSE_TAG_SYMLINK, substitute, print, Some(u32::from(*relative))),
            Reparse::MountPoint { substitute, print } => (IO_REPARSE_TAG_MOUNT_POINT, substitute, print, None),
        };
        let bytes = |w: &[u16]| w.iter().flat_map(|c| c.to_le_bytes()).collect::<Vec<u8>>();
        let (sb, pb) = (bytes(sub), bytes(print));
        let mut data = vec![];
        let so = 0u16;
        // mount points need NUL terminators after both names
        let term = if flags.is_none() { 2 } else { 0 };
        let po = (sb.len() + term) as u16;
        data.extend(so.to_le_bytes());
        data.extend((sb.len() as u16).to_le_bytes());
        data.extend(po.to_le_bytes());
        data.extend((pb.len() as u16).to_le_bytes());
        if let Some(fl) = flags {
            data.extend(fl.to_le_bytes());
        }
        data.extend(&sb);
        data.extend(vec![0; term]);
        data.extend(&pb);
        data.extend(vec![0; term]);
        let mut out = tag.to_le_bytes().to_vec();
        out.extend((data.len() as u16).to_le_bytes());
        out.extend([0, 0]);
        out.extend(data);
        out
    }

    /// What `Entry.link_target` shows (print name, else the substitute name).
    pub fn display_target(&self) -> Vec<u16> {
        let (s, p) = match self {
            Reparse::Symlink { substitute, print, .. } | Reparse::MountPoint { substitute, print } => {
                (substitute, print)
            }
        };
        if p.is_empty() {
            s.clone()
        } else {
            p.clone()
        }
    }

    /// A symlink for a link target that came without `win.reparse` (e.g. a Linux
    /// backup restored on Windows): `/` → `\`, absolute targets become `\??\` paths
    /// only if they name a drive (`C:\...`), everything else stays relative.
    pub fn symlink_for(target: &[u8]) -> Option<Reparse> {
        let t = String::from_utf8_lossy(target).replace('/', "\\");
        if t.is_empty() {
            return None;
        }
        let b = t.as_bytes();
        let absolute = b.len() >= 3 && b[1] == b':' && b[2] == b'\\' && b[0].is_ascii_alphabetic();
        let print: Vec<u16> = t.encode_utf16().collect();
        Some(Reparse::Symlink {
            substitute: if absolute {
                format!(r"\??\{t}").encode_utf16().collect()
            } else {
                print.clone()
            },
            print,
            relative: !absolute,
        })
    }
}

// ---------------------------------------------------------------- streams

/// Name of a named data stream from `FILE_STREAM_INFO.StreamName` (`:name:$DATA`);
/// `None` for the unnamed main stream (`::$DATA`) and non-`$DATA` streams.
pub fn stream_name(raw: &[u16]) -> Option<Vec<u16>> {
    let s: &[u16] = raw.strip_prefix(&[b':' as u16])?;
    let suffix: Vec<u16> = ":$DATA".encode_utf16().collect();
    let name = s.strip_suffix(&suffix[..])?;
    (!name.is_empty()).then(|| name.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)` as Windows stores it
    /// (self-relative; layout per MS-DTYP 2.4.6), owner + group + protected DACL.
    pub fn sample_sd() -> Vec<u8> {
        let sid_ba = [1u8, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0]; // S-1-5-32-544
        let sid_sy = [1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]; // S-1-5-18
        let ace = |sid: &[u8]| {
            let mut a = vec![0u8, 0x03]; // ACCESS_ALLOWED, OI|CI
            a.extend(((8 + sid.len()) as u16).to_le_bytes());
            a.extend(0x001F_01FFu32.to_le_bytes()); // FILE_ALL_ACCESS
            a.extend(sid);
            a
        };
        let aces = [ace(&sid_sy), ace(&sid_ba)].concat();
        let mut acl = vec![2u8, 0];
        acl.extend(((8 + aces.len()) as u16).to_le_bytes());
        acl.extend(2u16.to_le_bytes());
        acl.extend([0, 0]);
        acl.extend(aces);
        let control: u16 = 0x8000 | 0x1000 | 0x0004; // self-relative, DACL protected + present
        let mut sd = vec![1u8, 0];
        sd.extend(control.to_le_bytes());
        let o_owner = 20u32;
        let o_group = o_owner + sid_ba.len() as u32;
        let o_dacl = o_group + sid_sy.len() as u32;
        for o in [o_owner, o_group, 0, o_dacl] {
            sd.extend(o.to_le_bytes());
        }
        sd.extend(sid_ba);
        sd.extend(sid_sy);
        sd.extend(acl);
        sd
    }

    #[test]
    fn time_and_mode_mapping() {
        assert_eq!(filetime_to_unix_ns(EPOCH_DIFF), 0);
        assert_eq!(filetime_to_unix_ns(EPOCH_DIFF + 1), 100);
        // 2021-01-01T00:00:00Z
        let ft = 132_539_328_000_000_000i64;
        assert_eq!(filetime_to_unix_ns(ft), 1_609_459_200_000_000_000);
        assert_eq!(unix_ns_to_filetime(filetime_to_unix_ns(ft + 7)), ft + 7);
        assert_eq!(unix_ns_to_filetime(-50), EPOCH_DIFF - 1, "pre-1970 rounds down");
        assert_eq!(synth_mode(FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY), 0o755);
        assert_eq!(synth_mode(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE), 0o444);
        assert_eq!(synth_mode(FILE_ATTRIBUTE_ARCHIVE), 0o644);
        assert_eq!(
            inode_of(0x0005_0000_0000_1234),
            0x0005_0000_0000_1234,
            "NTFS ids unchanged"
        );
        assert_ne!(inode_of(1u128 << 64 | 7), 7, "ReFS ids folded");
        let x = vec![
            (X_ATTRS.to_vec(), 0x21u32.to_le_bytes().to_vec()),
            (X_CREATED.to_vec(), 5i64.to_le_bytes().to_vec()),
            (X_ADS.to_vec(), vec![]),
        ];
        assert_eq!(attrs_of(&x), Some(0x21));
        assert_eq!(created_of(&x), Some(5));
        assert!(is_ads(&x));
        assert!(!is_ads(&x[..2]));
        assert_eq!(attrs_of(&[(X_ATTRS.to_vec(), vec![1])]), None, "wrong length");
    }

    #[test]
    fn security_descriptor_parsing_and_flags() {
        let sd = sample_sd();
        let i = SdInfo::parse(&sd).unwrap();
        assert_eq!(i.owner.as_deref(), Some("S-1-5-32-544"));
        assert_eq!(i.group.as_deref(), Some("S-1-5-18"));
        assert!(i.dacl && i.dacl_protected && !i.sacl);
        assert_eq!(
            i.apply_flags(true),
            OWNER_SECURITY_INFORMATION
                | GROUP_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION
        );
        // corruptions are refused, never passed to the OS
        for cut in [0, 10, 19, 30, sd.len() - 1] {
            assert!(SdInfo::parse(&sd[..cut]).is_err(), "truncated at {cut}");
        }
        let mut abs = sd.clone();
        abs[3] &= 0x7F; // not self-relative
        assert!(SdInfo::parse(&abs).is_err());
        let mut far = sd.clone();
        far[16..20].copy_from_slice(&9999u32.to_le_bytes()); // DACL offset out of range
        assert!(SdInfo::parse(&far).is_err());
        let mut acl_big = sd.clone();
        let o = 20 + 16 + 12;
        acl_big[o + 2..o + 4].copy_from_slice(&0x7FFFu16.to_le_bytes());
        assert!(SdInfo::parse(&acl_big).is_err());
        // SACL present but no privilege: SACL skipped
        let mut with_sacl = sd.clone();
        let c = u16::from_le_bytes([sd[2], sd[3]]) | 0x0010;
        with_sacl[2..4].copy_from_slice(&c.to_le_bytes());
        with_sacl[12..16].copy_from_slice(&(o as u32).to_le_bytes()); // reuse the DACL bytes as SACL
        let i = SdInfo::parse(&with_sacl).unwrap();
        assert!(i.sacl);
        assert_eq!(i.apply_flags(false) & SACL_SECURITY_INFORMATION, 0);
        assert_ne!(i.apply_flags(true) & UNPROTECTED_SACL_SECURITY_INFORMATION, 0);
    }

    #[test]
    fn reparse_points_roundtrip() {
        let w = |s: &str| s.encode_utf16().collect::<Vec<u16>>();
        let sym = Reparse::Symlink {
            substitute: w(r"\??\C:\Data\target"),
            print: w(r"C:\Data\target"),
            relative: false,
        };
        let buf = sym.build();
        assert_eq!(&buf[0..4], &IO_REPARSE_TAG_SYMLINK.to_le_bytes());
        assert_eq!(Reparse::parse(&buf).unwrap(), sym);
        assert_eq!(sym.display_target(), w(r"C:\Data\target"));
        let junction = Reparse::MountPoint {
            substitute: w(r"\??\Volume{12345678-1234-1234-1234-123456789abc}\"),
            print: vec![],
        };
        let b = junction.build();
        assert_eq!(Reparse::parse(&b).unwrap(), junction);
        assert_eq!(
            junction.display_target(),
            w(r"\??\Volume{12345678-1234-1234-1234-123456789abc}\")
        );
        // other tags are data, not links
        let mut dedup = buf.clone();
        dedup[0..4].copy_from_slice(&0x8000_0013u32.to_le_bytes());
        assert!(Reparse::parse(&dedup).is_err());
        assert!(!is_link_tag(0x8000_0013));
        // malformed lengths
        let mut bad = buf.clone();
        bad[4..6].copy_from_slice(&5000u16.to_le_bytes());
        assert!(Reparse::parse(&bad).is_err());
        let mut bad = buf.clone();
        bad[10..12].copy_from_slice(&4000u16.to_le_bytes()); // substitute length
        assert!(Reparse::parse(&bad).is_err());
        // Linux link targets
        assert_eq!(
            Reparse::symlink_for(b"../x/y").unwrap(),
            Reparse::Symlink {
                substitute: w(r"..\x\y"),
                print: w(r"..\x\y"),
                relative: true
            }
        );
        match Reparse::symlink_for(b"D:/data").unwrap() {
            Reparse::Symlink {
                substitute, relative, ..
            } => {
                assert_eq!(substitute, w(r"\??\D:\data"));
                assert!(!relative);
            }
            _ => panic!(),
        }
        assert!(Reparse::symlink_for(b"").is_none());
    }

    #[test]
    fn stream_names() {
        let w = |s: &str| s.encode_utf16().collect::<Vec<u16>>();
        assert_eq!(stream_name(&w("::$DATA")), None);
        assert_eq!(stream_name(&w(":Zone.Identifier:$DATA")), Some(w("Zone.Identifier")));
        assert_eq!(stream_name(&w(":x:$INDEX_ALLOCATION")), None);
        assert_eq!(stream_name(&w("garbage")), None);
    }
}
