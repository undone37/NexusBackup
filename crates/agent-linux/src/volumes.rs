//! Mounted file systems (`/proc/self/mountinfo`) and their snapshot capability.

use agent_proto::{SnapshotKind, Volume};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

#[derive(Clone, Debug, PartialEq)]
pub struct Mount {
    pub mountpoint: PathBuf,
    /// path inside the file system that is mounted (btrfs subvolume, bind mounts)
    pub root: String,
    pub fstype: String,
    pub source: String,
}

/// File systems that hold host data and can be backed up.
const DATA_FS: &[&str] = &[
    "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "jfs", "reiserfs", "vfat", "exfat", "ntfs3", "bcachefs",
];

fn unescape(s: &str) -> String {
    // mountinfo escapes space, tab, newline and backslash as \ooo
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            out.push((b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_mountinfo(text: &str) -> Vec<Mount> {
    let mut out: Vec<Mount> = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let Some(sep) = f.iter().position(|x| *x == "-") else {
            continue;
        };
        if f.len() < sep + 3 || sep < 6 {
            continue;
        }
        let m = Mount {
            mountpoint: PathBuf::from(unescape(f[4])),
            root: unescape(f[3]),
            fstype: f[sep + 1].to_string(),
            source: unescape(f[sep + 2]),
        };
        // a later mount on the same mount point hides the earlier one
        out.retain(|o| o.mountpoint != m.mountpoint);
        out.push(m);
    }
    out
}

pub fn mounts() -> Vec<Mount> {
    std::fs::read_to_string("/proc/self/mountinfo")
        .map(|t| parse_mountinfo(&t))
        .unwrap_or_default()
}

pub fn is_data_fs(m: &Mount) -> bool {
    DATA_FS.contains(&m.fstype.as_str())
}

/// The mount containing `path` (longest mount point prefix, component-wise).
pub fn containing<'a>(mounts: &'a [Mount], path: &Path) -> Option<&'a Mount> {
    mounts
        .iter()
        .filter(|m| path.starts_with(&m.mountpoint))
        .max_by_key(|m| m.mountpoint.components().count())
}

/// `Filters::cross_mounts`: the mounts strictly below one of `roots` that become
/// roots of their own (each read from its own snapshot): local data file systems
/// not in the skip list (`skip` empty = `agent_core::filter::DEFAULT_SKIP_FSTYPES`),
/// whose mount point and the directories leading to it are not excluded, and not
/// below a skipped mount. Returns (mount points to add, notes about skipped ones
/// worth telling: network and data file systems).
pub fn nested_roots(
    mounts: &[Mount],
    roots: &[PathBuf],
    skip: &[String],
    filter: &agent_core::filter::Filter,
) -> (Vec<PathBuf>, Vec<String>) {
    use agent_core::filter::{skip_fstype, Visit};
    use std::os::unix::ffi::OsStrExt;
    let mut sorted: Vec<&Mount> = mounts.iter().collect();
    sorted.sort_by(|a, b| a.mountpoint.cmp(&b.mountpoint));
    let (mut add, mut notes, mut skipped) = (vec![], vec![], Vec::<&Path>::new());
    for m in sorted {
        let mp = m.mountpoint.as_path();
        let Some(root) = roots.iter().find(|r| mp.starts_with(r) && mp != r.as_path()) else {
            continue;
        };
        if roots.iter().any(|r| r == mp) || skipped.iter().any(|s| mp.starts_with(s)) {
            continue;
        }
        let excluded = mp
            .ancestors()
            .take_while(|a| a.starts_with(root) && *a != root.as_path())
            .any(|a| filter.visit(a.as_os_str().as_bytes()) == Visit::Skip);
        if excluded {
            skipped.push(mp);
            continue;
        }
        if skip_fstype(skip, &m.fstype) || !is_data_fs(m) {
            if is_data_fs(m) || m.fstype.starts_with("nfs") || m.fstype == "cifs" || m.fstype == "smb3" {
                notes.push(format!(
                    "nested mount {} ({}) skipped by file system type",
                    mp.display(),
                    m.fstype
                ));
            }
            skipped.push(mp);
            continue;
        }
        add.push(mp.to_path_buf());
    }
    (add, notes)
}

/// Normalised absolute path: must start with `/`, no `..`, `.` removed.
pub fn normalize(p: &str) -> Result<PathBuf, String> {
    let path = Path::new(p);
    if !path.is_absolute() {
        return Err(format!("path {p} is not absolute"));
    }
    let mut out = PathBuf::from("/");
    for c in path.components() {
        match c {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(n) => out.push(n),
            Component::ParentDir | Component::Prefix(_) => return Err(format!("path {p} contains ..")),
        }
    }
    Ok(out)
}

pub fn tool(name: &str) -> Option<PathBuf> {
    ["/usr/sbin", "/sbin", "/usr/bin", "/bin", "/usr/local/sbin"]
        .iter()
        .map(|d| Path::new(d).join(name))
        .find(|p| p.is_file())
}

/// Run a host tool, returning stdout or a message with stderr.
pub fn run_tool(name: &str, args: &[&str]) -> Result<String, String> {
    let bin = tool(name).ok_or_else(|| format!("{name} not found"))?;
    let out = Command::new(&bin)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .env("LVM_SUPPRESS_FD_WARNINGS", "1")
        .output()
        .map_err(|e| format!("{name}: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!(
            "{name} {}: {} {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LvInfo {
    pub vg: String,
    pub lv: String,
    pub attr: String,
    pub size: u64,
}

impl LvInfo {
    pub fn thin(&self) -> bool {
        self.attr.starts_with('V')
    }
}

pub fn parse_lvs(out: &str) -> Option<LvInfo> {
    let line = out.lines().map(str::trim).find(|l| !l.is_empty())?;
    let f: Vec<&str> = line.split('|').map(str::trim).collect();
    if f.len() < 4 {
        return None;
    }
    Some(LvInfo {
        vg: f[0].into(),
        lv: f[1].into(),
        attr: f[2].into(),
        size: f[3].parse().ok()?,
    })
}

pub fn lv_info(device: &str) -> Option<LvInfo> {
    if !device.starts_with("/dev/") {
        return None;
    }
    let out = run_tool(
        "lvs",
        &[
            "--noheadings",
            "--nosuffix",
            "--units",
            "b",
            "--separator",
            "|",
            "-o",
            "vg_name,lv_name,lv_attr,lv_size",
            device,
        ],
    )
    .ok()?;
    let info = parse_lvs(&out)?;
    can_snapshot(&info.attr).then_some(info)
}

/// The origin must be a plain/thin/raid/mirror/cache LV, or one that already has
/// (thick) snapshots (`o`: e.g. a leftover or the admin's own), not itself a
/// snapshot, a pool or an origin whose snapshot is being merged (`O`).
fn can_snapshot(lv_attr: &str) -> bool {
    matches!(
        lv_attr.chars().next(),
        Some('-' | 'o' | 'V' | 'r' | 'R' | 'm' | 'M' | 'C')
    )
}

/// btrfs: a read-only snapshot needs the mount point to be a subvolume root (inode 256).
fn btrfs_subvolume_root(mp: &Path) -> bool {
    std::fs::metadata(mp).map(|m| m.ino() == 256).unwrap_or(false)
}

/// Subvolume paths from `btrfs subvolume list -o <dir>` (paths from the file system's
/// top level), mapped below the mount whose subvolume is `mount_root` (mountinfo root,
/// e.g. `/root`). Subvolumes outside that mount and our own snapshots are dropped.
pub fn parse_subvolume_list(out: &str, mount_root: &str) -> Vec<PathBuf> {
    let prefix = mount_root.trim_matches('/');
    out.lines()
        .filter_map(|l| l.split_once(" path ").map(|(_, p)| p.trim()))
        .filter_map(|p| {
            let rel = if prefix.is_empty() {
                p
            } else {
                p.strip_prefix(prefix)?.strip_prefix('/')?
            };
            let rel = Path::new(rel);
            let ok = !rel.as_os_str().is_empty()
                && rel
                    .components()
                    .all(|c| matches!(c, Component::Normal(n) if n != crate::snapshot::BTRFS_DIR));
            ok.then(|| rel.to_path_buf())
        })
        .collect()
}

/// Nested btrfs subvolumes below a mounted btrfs subvolume, recursively, as synthetic
/// mounts (a btrfs snapshot does not contain nested subvolumes: they show up as empty
/// directories). Real mount points are left out (they are mounts of their own).
pub fn btrfs_nested(m: &Mount, real: &[Mount]) -> Vec<Mount> {
    let mut out: Vec<Mount> = vec![];
    if m.fstype != "btrfs" || tool("btrfs").is_none() {
        return out;
    }
    let mut todo = vec![m.mountpoint.clone()];
    while let Some(dir) = todo.pop() {
        let Ok(list) = run_tool("btrfs", &["subvolume", "list", "-o", &dir.to_string_lossy()]) else {
            continue;
        };
        for rel in parse_subvolume_list(&list, &m.root) {
            let mp = m.mountpoint.join(&rel);
            if out.iter().any(|o| o.mountpoint == mp)
                || real.iter().any(|r| r.mountpoint == mp)
                || !btrfs_subvolume_root(&mp)
            {
                continue;
            }
            todo.push(mp.clone());
            out.push(Mount {
                root: format!("{}/{}", m.root.trim_end_matches('/'), rel.display()),
                mountpoint: mp,
                fstype: m.fstype.clone(),
                source: m.source.clone(),
            });
        }
    }
    out
}

pub fn snapshot_kind(m: &Mount) -> SnapshotKind {
    match m.fstype.as_str() {
        "zfs" if tool("zfs").is_some() => SnapshotKind::Zfs,
        "btrfs" if tool("btrfs").is_some() && btrfs_subvolume_root(&m.mountpoint) => SnapshotKind::Btrfs,
        _ if lv_info(&m.source).is_some() => SnapshotKind::Lvm,
        _ => SnapshotKind::None,
    }
}

pub fn list_volumes() -> Vec<Volume> {
    mounts()
        .into_iter()
        .filter(is_data_fs)
        .map(|m| Volume {
            snapshot: snapshot_kind(&m),
            mountpoint: m.mountpoint.to_string_lossy().into_owned(),
            device: m.source,
            fstype: m.fstype,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_subvolumes_below_a_mount() {
        // Fedora: / is subvolume `root`; `btrfs subvolume list -o /` (lab)
        let out = "ID 260 gen 41 top level 256 path root/srv/btrfs\n\
                   ID 261 gen 41 top level 256 path root/srv/with space\n\
                   ID 267 gen 42 top level 256 path root/.nexus-snapshots/nexus-snap-7\n\
                   ID 258 gen 29 top level 5 path home\n";
        assert_eq!(
            parse_subvolume_list(out, "/root"),
            vec![PathBuf::from("srv/btrfs"), PathBuf::from("srv/with space")]
        );
        // top-level mount (subvolid=5): paths as listed
        assert_eq!(
            parse_subvolume_list("ID 300 gen 1 top level 5 path data/sub\n", "/"),
            vec![PathBuf::from("data/sub")]
        );
        assert!(parse_subvolume_list("", "/root").is_empty());
    }

    #[test]
    fn lv_attrs_that_can_be_snapshotted() {
        // lab: once a thick snapshot existed, the origin (`owi-aos---`) was read live
        for a in ["-wi-ao----", "owi-aos---", "Vwi-aotz--", "rwi-aor---", "Cwi-aoC---"] {
            assert!(can_snapshot(a), "{a}");
        }
        for a in ["swi-a-s---", "twi-aotz--", "Owi-a-s---", ""] {
            assert!(!can_snapshot(a), "{a}");
        }
    }

    const MI: &str = "\
22 1 253:1 / / rw,relatime shared:1 - xfs /dev/mapper/rl-root rw,attr2
23 22 0:5 / /proc rw - proc proc rw
24 22 253:2 / /home\\040dir rw shared:2 - ext4 /dev/mapper/vg-home rw
25 22 0:40 /@data /data rw - btrfs /dev/sdb1 rw,subvol=/@data
26 22 0:41 / /tank rw - zfs tank/ds rw,xattr
27 22 0:42 / /run rw - tmpfs tmpfs rw
28 22 253:3 / /data rw - ext4 /dev/sdc1 rw
";

    #[test]
    fn mountinfo_parsing_and_lookup() {
        let m = parse_mountinfo(MI);
        assert_eq!(m.len(), 6, "overmounted /data replaced");
        let home = m
            .iter()
            .find(|x| x.fstype == "ext4" && x.source == "/dev/mapper/vg-home")
            .unwrap();
        assert_eq!(home.mountpoint, PathBuf::from("/home dir"));
        let data = m.iter().find(|x| x.mountpoint == Path::new("/data")).unwrap();
        assert_eq!(data.source, "/dev/sdc1");
        assert_eq!(
            containing(&m, Path::new("/home dir/a")).unwrap().source,
            "/dev/mapper/vg-home"
        );
        assert_eq!(
            containing(&m, Path::new("/home")).unwrap().source,
            "/dev/mapper/rl-root"
        );
        assert_eq!(containing(&m, Path::new("/tank/x")).unwrap().source, "tank/ds");
        let data_fs: Vec<_> = m.iter().filter(|x| is_data_fs(x)).map(|x| x.fstype.as_str()).collect();
        assert_eq!(data_fs, ["xfs", "ext4", "zfs", "ext4"]);
    }

    #[test]
    fn nested_mounts_by_fstype_and_filter() {
        use agent_core::filter::Filter;
        use agent_core::glob::Excludes;
        let mi = "\
1 0 253:1 / / rw - xfs /dev/root rw
2 1 0:5 / /proc rw - proc proc rw
3 1 253:2 / /srv rw - ext4 /dev/sdb1 rw
4 3 253:3 / /srv/cache rw - ext4 /dev/sdc1 rw
5 3 0:50 / /srv/nfs rw - nfs4 nas:/x rw
6 5 253:4 / /srv/nfs/inner rw - ext4 /dev/sdd1 rw
7 1 253:5 / /boot/efi rw - vfat /dev/sda1 rw
8 1 0:42 / /run rw - tmpfs tmpfs rw
9 1 253:6 / /home rw - ext4 /dev/sde1 rw
";
        let m = parse_mountinfo(mi);
        let f = Filter::new(Excludes::new(&["/srv/cache".into()]), &[], &[], false).unwrap();
        let (add, notes) = nested_roots(&m, &[PathBuf::from("/")], &[], &f);
        assert_eq!(add, [PathBuf::from("/boot/efi"), "/home".into(), "/srv".into()]);
        assert_eq!(notes, ["nested mount /srv/nfs (nfs4) skipped by file system type"]);
        // an explicit list replaces the default; a requested root is not added twice
        let (add, _) = nested_roots(
            &m,
            &[PathBuf::from("/"), "/home".into()],
            &["vfat".into()],
            &Filter::default(),
        );
        assert_eq!(add, [PathBuf::from("/srv"), "/srv/cache".into()]);
        // only below the requested paths
        let (add, _) = nested_roots(&m, &[PathBuf::from("/srv")], &[], &Filter::default());
        assert_eq!(add, [PathBuf::from("/srv/cache")]);
    }

    #[test]
    fn lvs_and_normalize() {
        let i = parse_lvs("  vg|home|Vwi-aotz--|10737418240\n").unwrap();
        assert!(i.thin());
        assert_eq!(i.size, 10 << 30);
        assert!(!parse_lvs("  vg|root|-wi-ao----|1073741824").unwrap().thin());
        assert_eq!(normalize("/a/./b/").unwrap(), PathBuf::from("/a/b"));
        assert!(normalize("/a/../b").is_err());
        assert!(normalize("a/b").is_err());
    }
}
