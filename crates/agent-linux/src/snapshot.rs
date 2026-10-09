//! Consistent snapshots (LVM thin/thick, ZFS, btrfs) with crash-safe cleanup.
//!
//! Every object we create is first recorded in `snapshots.journal`; `release` removes
//! it again. On startup `cleanup_leftovers` removes everything still in the journal
//! plus any LVM LV / ZFS snapshot carrying our prefix (crash, kill -9, power loss).
//! LVM snapshots are mounted read-only below `/run/nexus-agent/<job>/` inside the
//! agent's private mount namespace, so they are invisible to the rest of the host and
//! disappear with the process.

use crate::config::{ensure_dir, Paths, Settings};
use crate::sys;
use crate::volumes::{lv_info, run_tool, snapshot_kind, Mount};
use agent_proto::{SnapshotInfo, SnapshotKind};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const PREFIX: &str = "nexus-snap-";
/// btrfs snapshots must live inside the snapshotted file system
pub const BTRFS_DIR: &str = ".nexus-snapshots";

static JOURNAL: Mutex<()> = Mutex::new(());

#[derive(Clone, Debug, PartialEq)]
pub enum Item {
    Mount(PathBuf),
    Lvm(String),
    Zfs(String),
    Btrfs(PathBuf),
}

impl Item {
    fn line(&self) -> String {
        match self {
            Item::Mount(p) => format!("mount\t{}", p.display()),
            Item::Lvm(n) => format!("lvm\t{n}"),
            Item::Zfs(n) => format!("zfs\t{n}"),
            Item::Btrfs(p) => format!("btrfs\t{}", p.display()),
        }
    }

    fn parse(l: &str) -> Option<Item> {
        let (k, v) = l.split_once('\t')?;
        Some(match k {
            "mount" => Item::Mount(v.into()),
            "lvm" => Item::Lvm(v.into()),
            "zfs" => Item::Zfs(v.into()),
            "btrfs" => Item::Btrfs(v.into()),
            _ => return None,
        })
    }

    /// Only ever touch objects that carry our prefix, whatever the journal says.
    fn ours(&self, paths: &Paths) -> bool {
        match self {
            Item::Mount(p) => p.starts_with(&paths.run),
            Item::Lvm(n) => n.split('/').nth(1).is_some_and(|lv| lv.starts_with(PREFIX)),
            Item::Zfs(n) => n.split_once('@').is_some_and(|(_, s)| s.starts_with(PREFIX)),
            Item::Btrfs(p) => {
                p.file_name().is_some_and(|n| n.to_string_lossy().starts_with(PREFIX))
                    && p.parent().and_then(|d| d.file_name()).is_some_and(|d| d == BTRFS_DIR)
            }
        }
    }

    fn remove(&self) -> Result<(), String> {
        match self {
            Item::Mount(p) => {
                let r = sys::umount(p);
                let _ = fs::remove_dir(p);
                match r {
                    Err(e) if e.raw_os_error() != Some(libc::EINVAL) && e.raw_os_error() != Some(libc::ENOENT) => {
                        Err(format!("umount {}: {e}", p.display()))
                    }
                    _ => Ok(()),
                }
            }
            Item::Lvm(n) => {
                // udev may still probe the device right after the umount: retry briefly
                let mut r = run_tool("lvremove", &["-f", "-y", n]).map(drop);
                for _ in 0..5 {
                    match &r {
                        Err(e) if e.contains("in use") => {
                            std::thread::sleep(std::time::Duration::from_millis(400));
                            r = run_tool("lvremove", &["-f", "-y", n]).map(drop);
                        }
                        _ => break,
                    }
                }
                r
            }
            Item::Zfs(n) => run_tool("zfs", &["destroy", n]).map(drop),
            Item::Btrfs(p) => run_tool("btrfs", &["subvolume", "delete", &p.to_string_lossy()]).map(drop),
        }
    }
}

fn journal_read(paths: &Paths) -> Vec<Item> {
    fs::read_to_string(paths.journal())
        .unwrap_or_default()
        .lines()
        .filter_map(Item::parse)
        .collect()
}

fn journal_add(paths: &Paths, item: &Item) -> Result<(), String> {
    let _g = JOURNAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(paths.journal())
        .map_err(|e| format!("snapshot journal: {e}"))?;
    writeln!(f, "{}", item.line())
        .and_then(|_| f.sync_all())
        .map_err(|e| format!("snapshot journal: {e}"))
}

fn journal_remove(paths: &Paths, item: &Item) {
    let _g = JOURNAL.lock().unwrap_or_else(|e| e.into_inner());
    let rest: String = journal_read(paths)
        .iter()
        .filter(|i| *i != item)
        .map(|i| i.line() + "\n")
        .collect();
    let _ = crate::config::write_atomic(&paths.journal(), rest.as_bytes(), 0o600);
}

/// A prepared volume: where to read its content from.
#[derive(Debug)]
pub struct Snap {
    pub mount: Mount,
    /// directory that shows the volume's mount root (snapshot or live)
    pub root: PathBuf,
    pub info: Option<SnapshotInfo>,
    items: Vec<Item>,
}

impl Snap {
    pub fn live(mount: Mount) -> Snap {
        Snap {
            root: mount.mountpoint.clone(),
            mount,
            info: None,
            items: vec![],
        }
    }

    pub fn consistent(&self) -> bool {
        self.info.is_some()
    }

    /// Remove everything this snapshot created (reverse order). Errors are returned
    /// for the hook log; the journal keeps failed items for the next startup cleanup.
    pub fn release(&mut self, paths: &Paths) -> Vec<String> {
        let mut errs = vec![];
        while let Some(it) = self.items.pop() {
            match it.remove() {
                Ok(()) => journal_remove(paths, &it),
                Err(e) => errs.push(e),
            }
        }
        errs
    }
}

impl Drop for Snap {
    fn drop(&mut self) {
        if !self.items.is_empty() {
            eprintln!(
                "nexus-agent: snapshot of {} dropped without release",
                self.mount.mountpoint.display()
            );
        }
    }
}

/// Create a snapshot of `mount` for `job`; `idx` makes names unique within the job.
/// Returns a live (inconsistent) view plus a note if the volume cannot be snapshotted.
pub fn prepare(paths: &Paths, settings: &Settings, job: u64, idx: usize, mount: &Mount) -> (Snap, Option<String>) {
    let kind = snapshot_kind(mount);
    let mut snap = Snap {
        root: mount.mountpoint.clone(),
        mount: mount.clone(),
        info: None,
        items: vec![],
    };
    let res = match kind {
        SnapshotKind::None => {
            let note = format!(
                "no snapshot support for {} ({} on {}), reading live",
                mount.mountpoint.display(),
                mount.fstype,
                mount.source
            );
            return (snap, Some(note));
        }
        SnapshotKind::Lvm => lvm(paths, settings, job, idx, &mut snap),
        SnapshotKind::Zfs => zfs(paths, job, &mut snap),
        SnapshotKind::Btrfs => btrfs(paths, job, &mut snap),
    };
    match res {
        Ok(name) => {
            snap.info = Some(SnapshotInfo {
                mountpoint: mount.mountpoint.to_string_lossy().into_owned(),
                kind,
                name,
            });
            (snap, None)
        }
        Err(e) => {
            let errs = snap.release(paths);
            let note = format!(
                "snapshot of {} ({kind:?}) failed, reading live: {e}{}",
                mount.mountpoint.display(),
                if errs.is_empty() {
                    String::new()
                } else {
                    format!(" (cleanup: {})", errs.join("; "))
                }
            );
            (Snap::live(mount.clone()), Some(note))
        }
    }
}

fn record(paths: &Paths, snap: &mut Snap, item: Item) -> Result<(), String> {
    journal_add(paths, &item)?;
    snap.items.push(item);
    Ok(())
}

fn lvm(paths: &Paths, settings: &Settings, job: u64, idx: usize, snap: &mut Snap) -> Result<String, String> {
    let lv = lv_info(&snap.mount.source).ok_or("not an LVM logical volume")?;
    let name = format!("{PREFIX}{job}-{idx}");
    let full = format!("{}/{}", lv.vg, name);
    let origin = format!("{}/{}", lv.vg, lv.lv);
    record(paths, snap, Item::Lvm(full.clone()))?;
    if lv.thin() {
        // thin snapshots carry the activation-skip flag by default: -kn clears it
        run_tool("lvcreate", &["-q", "-s", "-kn", "-n", &name, &origin])?;
        run_tool("lvchange", &["-q", "-ay", "-K", &full])?;
    } else {
        let size = thick_snapshot_size(lv.size, settings.lvm_snapshot_percent);
        run_tool("lvcreate", &["-q", "-s", "-L", &size, "-n", &name, &origin])?;
    }
    let dir = paths.run.join(job.to_string()).join(idx.to_string());
    ensure_dir(&dir, 0o700).map_err(|e| format!("{}: {e}", dir.display()))?;
    record(paths, snap, Item::Mount(dir.clone()))?;
    let dev = PathBuf::from("/dev").join(&lv.vg).join(&name);
    let fstype = snap.mount.fstype.as_str();
    // The snapshot is a writable block device, so a plain read-only mount replays the
    // journal into the snapshot (consistent view). XFS refuses the duplicate UUID
    // without `nouuid`; if replay is impossible we retry without it.
    let (first, retry) = match fstype {
        "xfs" => ("nouuid", Some("nouuid,norecovery")),
        "ext3" | "ext4" => ("", Some("noload")),
        _ => ("", None),
    };
    if let Err(e) = sys::mount_ro(&dev, &dir, fstype, first) {
        let Some(r) = retry else {
            return Err(format!("mount {}: {e}", dev.display()));
        };
        sys::mount_ro(&dev, &dir, fstype, r).map_err(|e2| format!("mount {}: {e}; with {r}: {e2}", dev.display()))?;
    }
    snap.root = dir.join(snap.mount.root.trim_start_matches('/'));
    Ok(full)
}

/// `lvcreate -L` argument for a thick snapshot: `percent` of the origin, at least
/// 64 MiB, in whole MiB (lvcreate rejects byte sizes that are not a multiple of 512
/// and rounds up to the extent size itself).
fn thick_snapshot_size(origin_bytes: u64, percent: u32) -> String {
    let bytes = (origin_bytes / 100 * percent as u64).max(64 << 20);
    format!("{}m", bytes.div_ceil(1 << 20))
}

fn zfs(paths: &Paths, job: u64, snap: &mut Snap) -> Result<String, String> {
    let name = format!("{}@{PREFIX}{job}", snap.mount.source);
    record(paths, snap, Item::Zfs(name.clone()))?;
    run_tool("zfs", &["snapshot", &name])?;
    // read through the automounted .zfs/snapshot directory (works with snapdir=hidden)
    let root = snap
        .mount
        .mountpoint
        .join(".zfs/snapshot")
        .join(format!("{PREFIX}{job}"));
    fs::read_dir(&root).map_err(|e| format!("{}: {e}", root.display()))?;
    snap.root = root;
    Ok(name)
}

fn btrfs(paths: &Paths, job: u64, snap: &mut Snap) -> Result<String, String> {
    let dir = snap.mount.mountpoint.join(BTRFS_DIR);
    ensure_dir(&dir, 0o700).map_err(|e| format!("{}: {e}", dir.display()))?;
    let path = dir.join(format!("{PREFIX}{job}"));
    record(paths, snap, Item::Btrfs(path.clone()))?;
    run_tool(
        "btrfs",
        &[
            "-q",
            "subvolume",
            "snapshot",
            "-r",
            &snap.mount.mountpoint.to_string_lossy(),
            &path.to_string_lossy(),
        ],
    )?;
    snap.root = path.clone();
    Ok(path.to_string_lossy().into_owned())
}

/// Startup: remove leftovers of a crashed run. Returns messages for the journal.
pub fn cleanup_leftovers(paths: &Paths) -> Vec<String> {
    let mut msgs = vec![];
    let mut items = journal_read(paths);
    if let Ok(out) = run_tool("lvs", &["--noheadings", "-o", "vg_name,lv_name", "--separator", "/"]) {
        items.extend(
            out.lines()
                .map(str::trim)
                .filter(|l| l.contains(&format!("/{PREFIX}")))
                .map(|l| Item::Lvm(l.into())),
        );
    }
    if let Ok(out) = run_tool("zfs", &["list", "-H", "-t", "snapshot", "-o", "name"]) {
        items.extend(
            out.lines()
                .map(str::trim)
                .filter(|l| l.contains(&format!("@{PREFIX}")))
                .map(|l| Item::Zfs(l.into())),
        );
    }
    // mounts first (reverse journal order), then the block devices / snapshots
    items.sort_by_key(|i| !matches!(i, Item::Mount(_)));
    items.dedup();
    let mut failed = vec![];
    for it in items {
        if !it.ours(paths) {
            msgs.push(format!("journal entry {:?} ignored: not ours", it));
            continue;
        }
        match it.remove() {
            Ok(()) => msgs.push(format!("removed leftover {}", it.line().replace('\t', " "))),
            Err(e) => {
                msgs.push(format!("leftover {}: {e}", it.line().replace('\t', " ")));
                failed.push(it);
            }
        }
    }
    let rest: String = failed.iter().map(|i| i.line() + "\n").collect();
    let _ = crate::config::write_atomic(&paths.journal(), rest.as_bytes(), 0o600);
    msgs
}

pub fn leftover_count(paths: &Paths) -> usize {
    journal_read(paths).len()
}

/// Map an absolute host path to where it can be read in `snap`.
pub fn source_path(snap: &Snap, host: &Path) -> PathBuf {
    let rel = host.strip_prefix(&snap.mount.mountpoint).unwrap_or(Path::new(""));
    if rel.as_os_str().is_empty() {
        snap.root.clone()
    } else {
        snap.root.join(rel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(t: &Path) -> Paths {
        Paths {
            config: t.join("etc"),
            state: t.join("state"),
            run: t.join("run"),
        }
    }

    #[test]
    fn journal_roundtrip_and_ownership_guard() {
        let t = tempfile::tempdir().unwrap();
        let p = paths(t.path());
        ensure_dir(&p.state, 0o700).unwrap();
        let a = Item::Lvm(format!("vg/{PREFIX}1-0"));
        let b = Item::Mount(p.run.join("1/0"));
        journal_add(&p, &a).unwrap();
        journal_add(&p, &b).unwrap();
        assert_eq!(journal_read(&p), vec![a.clone(), b.clone()]);
        journal_remove(&p, &a);
        assert_eq!(journal_read(&p), vec![b.clone()]);
        assert!(a.ours(&p) && b.ours(&p));
        assert!(!Item::Lvm("vg/root".into()).ours(&p));
        assert!(!Item::Zfs("tank/ds@daily".into()).ours(&p));
        assert!(!Item::Mount("/home".into()).ours(&p));
        assert!(!Item::Btrfs("/data/nexus-snap-1".into()).ours(&p));
        assert!(Item::Btrfs(format!("/data/{BTRFS_DIR}/{PREFIX}1").into()).ours(&p));
    }

    #[test]
    fn startup_cleanup_unmounts_missing_dirs_without_error() {
        let t = tempfile::tempdir().unwrap();
        let p = paths(t.path());
        ensure_dir(&p.state, 0o700).unwrap();
        journal_add(&p, &Item::Mount(p.run.join("9/0"))).unwrap();
        journal_add(&p, &Item::Lvm("vg/root".into())).unwrap();
        let msgs = cleanup_leftovers(&p);
        assert!(msgs.iter().any(|m| m.contains("not ours")), "{msgs:?}");
        assert_eq!(leftover_count(&p), 0);
    }

    #[test]
    fn thick_snapshot_size_is_whole_mib() {
        // 10 % of a 3 GiB LV is not a multiple of 512 bytes (lab: Debian root on LVM)
        assert_eq!(thick_snapshot_size(3 << 30, 10), "308m");
        assert_eq!(thick_snapshot_size(100 << 20, 10), "64m");
        assert_eq!(thick_snapshot_size(10 << 30, 100), "10240m");
    }

    // Root-only snapshot provider tests: run in a VM as root with the matching
    // storage, e.g. `NEXUS_TEST_LVM=/mnt/lvtest cargo test -p agent-linux -- --ignored`.
    fn provider_roundtrip(env: &str, want: SnapshotKind) {
        let Ok(mp) = std::env::var(env) else {
            panic!("set {env} to a mount point of that type")
        };
        let t = tempfile::tempdir().unwrap();
        let p = paths(t.path());
        ensure_dir(&p.state, 0o700).unwrap();
        crate::sys::private_mount_namespace().unwrap();
        let mounts = crate::volumes::mounts();
        let m = crate::volumes::containing(&mounts, Path::new(&mp)).unwrap().clone();
        assert_eq!(snapshot_kind(&m), want);
        fs::write(Path::new(&mp).join("nexus-snap-test"), b"before").unwrap();
        let (mut s, note) = prepare(&p, &Settings::default(), 4242, 0, &m);
        assert!(note.is_none(), "{note:?}");
        assert!(s.consistent());
        fs::write(Path::new(&mp).join("nexus-snap-test"), b"after!").unwrap();
        assert_eq!(
            fs::read(source_path(&s, &Path::new(&mp).join("nexus-snap-test"))).unwrap(),
            b"before"
        );
        assert!(s.release(&p).is_empty());
        assert_eq!(leftover_count(&p), 0);
        fs::remove_file(Path::new(&mp).join("nexus-snap-test")).unwrap();
    }

    #[test]
    #[ignore = "root + LVM volume: NEXUS_TEST_LVM=<mountpoint on an LV>"]
    fn lvm_snapshot() {
        provider_roundtrip("NEXUS_TEST_LVM", SnapshotKind::Lvm);
    }

    #[test]
    #[ignore = "root + ZFS dataset: NEXUS_TEST_ZFS=<dataset mountpoint>"]
    fn zfs_snapshot() {
        provider_roundtrip("NEXUS_TEST_ZFS", SnapshotKind::Zfs);
    }

    #[test]
    #[ignore = "root + btrfs subvolume: NEXUS_TEST_BTRFS=<subvolume mountpoint>"]
    fn btrfs_snapshot() {
        provider_roundtrip("NEXUS_TEST_BTRFS", SnapshotKind::Btrfs);
    }
}
