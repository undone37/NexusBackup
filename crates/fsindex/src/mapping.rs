//! Guest paths instead of partitions (docs/file-index-v2-plan.md, "31a: mount
//! point mapping"): Linux volumes from the root file system's `/etc/fstab`
//! (`UUID=`, `LABEL=`, `PARTUUID=`, `/dev/mapper/…`, `/dev/<vg>/<lv>`,
//! `/dev/disk/by-*/…`); Windows `C:` is the NTFS volume holding
//! `Windows/System32`, the other Windows volumes get their letters from its
//! SYSTEM hive (`MountedDevices`, Phase 31c, [`crate::regf`]); every other
//! volume shows as its label or `vol<N>`.

use crate::Volume;

fn listed(v: &Volume) -> bool {
    matches!(v.state.as_str(), "indexed" | "partial") || v.state.is_empty()
}

/// (spec, mount point) of the fstab lines that mount a file system.
pub fn fstab(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let l = l.split('#').next()?.trim();
            let mut f = l.split_whitespace();
            let (spec, mp, ty) = (f.next()?, f.next()?, f.next().unwrap_or(""));
            if !mp.starts_with('/') || matches!(ty, "swap" | "proc" | "sysfs" | "tmpfs" | "devpts" | "none") {
                return None;
            }
            Some((unescape(spec), unescape(mp)))
        })
        .collect()
}

/// fstab octal escapes (`\040` for a space).
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 4 <= b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            let n = (b[i + 1] - b'0') as u32 * 64 + (b[i + 2] - b'0') as u32 * 8 + (b[i + 3] - b'0') as u32;
            out.push(n as u8);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether an fstab device spec names volume `v`.
fn names(spec: &str, v: &Volume) -> bool {
    let eq = |a: &Option<String>, b: &str| a.as_deref().is_some_and(|a| a.eq_ignore_ascii_case(b));
    let tail = |p: &str| spec.strip_prefix(p);
    if let Some(u) = tail("UUID=").or_else(|| tail("/dev/disk/by-uuid/")) {
        return eq(&v.uuid, u.trim_matches('"'));
    }
    if let Some(l) = tail("LABEL=").or_else(|| tail("/dev/disk/by-label/")) {
        return v.label.as_deref() == Some(l.trim_matches('"'));
    }
    if let Some(p) = tail("PARTUUID=").or_else(|| tail("/dev/disk/by-partuuid/")) {
        return eq(&v.partuuid, p.trim_matches('"'));
    }
    let Some((vg, lv)) = v.device.split_once('/').filter(|_| v.browse.starts_with("lvm/")) else {
        return false;
    };
    if let Some(dm) = tail("/dev/mapper/") {
        return dm == crate::dm_name(vg, lv);
    }
    spec == format!("/dev/{vg}/{lv}")
}

/// Sets `mount` of the volumes.
pub fn assign(vols: &mut [Volume]) {
    for v in vols.iter_mut() {
        v.mount = None;
    }
    // Linux: the root file system is the one whose own fstab mounts it at `/`
    let with_fstab: Vec<usize> = (0..vols.len())
        .filter(|&i| vols[i].fstab.is_some() && listed(&vols[i]))
        .collect();
    let root = with_fstab
        .iter()
        .copied()
        .find(|&i| {
            fstab(vols[i].fstab.as_deref().unwrap_or_default())
                .iter()
                .any(|(spec, mp)| mp == "/" && names(spec, &vols[i]))
        })
        .or_else(|| with_fstab.first().copied());
    if let Some(r) = root {
        let tab = fstab(vols[r].fstab.as_deref().unwrap_or_default());
        vols[r].mount = Some("/".into());
        for (spec, mp) in tab {
            if mp == "/" {
                continue;
            }
            if let Some(v) = vols
                .iter_mut()
                .find(|v| v.mount.is_none() && listed(v) && names(&spec, v))
            {
                v.mount = Some(mp);
            }
        }
    }
    // Windows: the drive letters of the system volume's SYSTEM hive (`MountedDevices`,
    // matched by GPT partition / dynamic volume GUID or MBR signature + offset); the
    // system volume is C: when the hive does not name it
    let Some(sys) = vols.iter().position(|v| v.windows && v.mount.is_none() && listed(v)) else {
        return;
    };
    let letters: Vec<(String, String)> = vols[sys]
        .drives
        .iter()
        .filter(|(l, id)| {
            let b = l.as_bytes();
            b.len() == 2 && b[0].is_ascii_uppercase() && b[1] == b':' && !id.is_empty() && id.len() <= 64
        })
        .take(26)
        .cloned()
        .collect();
    for (letter, id) in letters {
        if vols.iter().any(|v| v.mount.as_deref() == Some(letter.as_str())) {
            continue;
        }
        if let Some(v) = vols.iter_mut().find(|v| {
            v.mount.is_none() && listed(v) && v.win_id.as_deref().is_some_and(|w| w.eq_ignore_ascii_case(&id))
        }) {
            v.mount = Some(letter);
        }
    }
    if vols[sys].mount.is_none() && !vols.iter().any(|v| v.mount.as_deref() == Some("C:")) {
        vols[sys].mount = Some("C:".into());
    }
}

/// How a listed volume appears in guest paths: its mount point, else its
/// label (unique among the volumes), else `vol<N>` (1-based position).
pub fn prefixes(vols: &[Volume]) -> Vec<String> {
    let mut out = Vec::new();
    for (i, v) in vols.iter().enumerate() {
        let p = match (&v.mount, &v.label) {
            (Some(m), _) => m.clone(),
            (None, Some(l))
                if !l.is_empty()
                    && !l.contains('/')
                    && vols.iter().filter(|o| o.label.as_deref() == Some(l)).count() == 1 =>
            {
                l.clone()
            }
            _ => format!("vol{}", i + 1),
        };
        out.push(p);
    }
    out
}

/// Maps name-index paths (`vda1/etc/hosts`, browse paths) to guest paths
/// (`/etc/hosts`, `C:/Users/…`, `Data/x`, `vol3/x`).
pub struct Mapper {
    /// (browse prefix, guest prefix), longest browse prefix first
    map: Vec<(String, String)>,
}

impl Mapper {
    pub fn new(vols: &[Volume]) -> Mapper {
        let pre = prefixes(vols);
        let mut map: Vec<(String, String)> = vols.iter().zip(pre).map(|(v, p)| (v.browse.clone(), p)).collect();
        map.sort_by_key(|a| std::cmp::Reverse(a.0.len()));
        Mapper { map }
    }

    pub fn guest(&self, browse_path: &str) -> String {
        for (b, g) in &self.map {
            let rest = match browse_path.strip_prefix(b.as_str()) {
                Some("") => "",
                Some(r) if r.starts_with('/') => &r[1..],
                _ => continue,
            };
            return match (g.as_str(), rest) {
                ("/", r) => format!("/{r}"),
                (g, "") => g.to_owned(),
                (g, r) if g.ends_with('/') => format!("{g}{r}"),
                (g, r) => format!("{g}/{r}"),
            };
        }
        browse_path.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vol(browse: &str, device: &str, uuid: Option<&str>, label: Option<&str>) -> Volume {
        Volume {
            browse: browse.into(),
            device: device.into(),
            uuid: uuid.map(Into::into),
            label: label.map(Into::into),
            state: "indexed".into(),
            ..Default::default()
        }
    }

    #[test]
    fn linux_fstab_and_windows() {
        let mut root = vol("lvm/vg--sys-root", "vg-sys/root", Some("aaaa-1"), None);
        root.fstab = Some(
            "# /etc/fstab\n/dev/mapper/vg--sys-root / ext4 defaults 0 1\nUUID=BBBB-2 /boot ext4 defaults 0 2\n\
             UUID=7A3B-1C2D /boot/efi vfat umask=0077 0 1\n/dev/vg-sys/home /home ext4 defaults 0 2\n\
             /dev/vg-sys/swap none swap sw 0 0\nLABEL=my\\040data /srv/my\\040data ext4 defaults 0 0\n"
                .into(),
        );
        let mut vols = vec![
            vol("vda1", "drive-scsi0", Some("7a3b-1c2d"), None),
            vol("vda2", "drive-scsi0", Some("bbbb-2"), None),
            root,
            vol("lvm/vg--sys-home", "vg-sys/home", Some("cccc"), None),
            vol("vdb1", "drive-scsi1", Some("dd"), Some("my data")),
            vol("vdc1", "drive-scsi2", Some("0123456789ABCDEF"), Some("Backup")),
            vol("vdc2", "drive-scsi2", Some("x"), None),
        ];
        let mut win = vol("vdd2", "drive-scsi3", Some("EE"), None);
        win.windows = true;
        vols.push(win);
        assign(&mut vols);
        let m: Vec<_> = vols.iter().map(|v| v.mount.clone()).collect();
        assert_eq!(
            m,
            [
                Some("/boot/efi".into()),
                Some("/boot".into()),
                Some("/".into()),
                Some("/home".into()),
                Some("/srv/my data".into()),
                None,
                None,
                Some("C:".into())
            ]
        );
        let map = Mapper::new(&vols);
        assert_eq!(map.guest("lvm/vg--sys-root/etc/hosts"), "/etc/hosts");
        assert_eq!(map.guest("vda1/EFI/boot.efi"), "/boot/efi/EFI/boot.efi");
        assert_eq!(map.guest("vdc1/x.txt"), "Backup/x.txt");
        assert_eq!(map.guest("vdc2/y"), "vol7/y");
        assert_eq!(map.guest("vdd2/Users/ann"), "C:/Users/ann");
        assert_eq!(map.guest("vdd2"), "C:");
        assert_eq!(map.guest("vdc"), "vdc", "no volume: unchanged");
        assert_eq!(map.guest("vda10/x"), "vda10/x", "prefix must end at a component");
    }

    #[test]
    fn windows_drive_letters_from_the_hive() {
        let with = |browse: &str, id: &str| Volume {
            win_id: Some(id.into()),
            ..vol(browse, "drive-scsi0", None, None)
        };
        let mut sys = with("vda3", "guid:aaaa");
        sys.windows = true;
        sys.drives = vec![
            ("C:".into(), "GUID:AAAA".into()),
            ("D:".into(), "mbr:12345678:1048576".into()),
            ("E:".into(), "guid:nowhere".into()),
            ("../x".into(), "guid:bbbb".into()),
            ("F:".into(), "guid:bbbb".into()),
        ];
        let mut failed = with("vdc1", "guid:cccc");
        failed.state = "failed".into();
        let mut vols = vec![
            with("vda1", "guid:efi"),
            sys,
            with("vdb1", "mbr:12345678:1048576"),
            with("lvm/x", "guid:bbbb"),
            failed,
        ];
        assign(&mut vols);
        let m: Vec<_> = vols.iter().map(|v| v.mount.as_deref()).collect();
        assert_eq!(m, [None, Some("C:"), Some("D:"), Some("F:"), None]);
        // a hive that does not name the system volume: it is still C:
        vols[1].drives.retain(|d| d.0 != "C:");
        assign(&mut vols);
        assert_eq!(vols[1].mount.as_deref(), Some("C:"));
        // a hive that gives C: to another volume: the system volume shows as its label / vol<N>
        vols[1].drives = vec![("C:".into(), "mbr:12345678:1048576".into())];
        assign(&mut vols);
        assert_eq!((vols[1].mount.as_deref(), vols[2].mount.as_deref()), (None, Some("C:")));
    }
}
