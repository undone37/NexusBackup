//! The VMware proxy role (agent protocol v1.9, docs/vmware-design.md): the disk the appliance
//! hot-added at SCSI target `0:N`, found through sysfs. Only a disk nothing uses is handed out:
//! not mounted (also no partition of it), no swap, nothing stacked on it (LVM, device mapper,
//! md). The agent opens it read-only.

use std::fs;
use std::path::{Path, PathBuf};

/// `/dev/<name>` of the one SCSI disk at `<host>:0:<target>:0` below `sys` (`/sys`), checked
/// against `mounts` (`/proc/mounts`) and `swaps` (`/proc/swaps`).
pub fn find(sys: &Path, mounts: &str, swaps: &str, target: u32) -> Result<PathBuf, String> {
    let dir = sys.join("class/scsi_disk");
    let mut found = Vec::new();
    for e in fs::read_dir(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .flatten()
    {
        let n = e.file_name().to_string_lossy().into_owned();
        let p: Vec<&str> = n.split(':').collect();
        if p.len() == 4 && p[1] == "0" && p[2] == target.to_string() && p[3] == "0" {
            let blk = e.path().join("device/block");
            if let Some(b) = fs::read_dir(&blk).ok().and_then(|mut d| d.next()).and_then(Result::ok) {
                found.push(b.file_name().to_string_lossy().into_owned());
            }
        }
    }
    let name = match found.as_slice() {
        [one] => one.clone(),
        [] => return Err(format!("no disk at SCSI target 0:{target} (hot-added?)")),
        _ => {
            return Err(format!(
                "more than one disk at SCSI target 0:{target}: {}",
                found.join(", ")
            ))
        }
    };
    // the disk and its partitions
    let mut names = vec![name.clone()];
    if let Ok(d) = fs::read_dir(sys.join("block").join(&name)) {
        names.extend(
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|p| p.starts_with(&name)),
        );
    }
    for n in &names {
        let dev = format!("/dev/{n}");
        if mounts
            .lines()
            .any(|l| l.split_whitespace().next() == Some(dev.as_str()))
        {
            return Err(format!("{dev} is mounted: not a hot-added snapshot disk"));
        }
        if swaps.lines().any(|l| l.split_whitespace().next() == Some(dev.as_str())) {
            return Err(format!("{dev} is swap: not a hot-added snapshot disk"));
        }
        let holders = sys
            .join("block")
            .join(&name)
            .join(if n == &name { String::new() } else { n.clone() })
            .join("holders");
        if fs::read_dir(&holders).is_ok_and(|mut d| d.next().is_some()) {
            return Err(format!("{dev} is in use (LVM, device mapper or md on top of it)"));
        }
    }
    Ok(PathBuf::from(format!("/dev/{name}")))
}

#[cfg(test)]
mod tests {
    use super::find;
    use std::fs;
    use std::path::Path;

    fn disk(sys: &Path, hctl: &str, name: &str, parts: &[&str]) {
        fs::create_dir_all(sys.join("class/scsi_disk").join(hctl).join("device/block").join(name)).unwrap();
        fs::create_dir_all(sys.join("block").join(name).join("holders")).unwrap();
        for p in parts {
            fs::create_dir_all(sys.join("block").join(name).join(p).join("holders")).unwrap();
        }
    }

    #[test]
    fn hot_added_disks_only() {
        let d = tempfile::tempdir().unwrap();
        let sys = d.path();
        disk(sys, "2:0:0:0", "sda", &["sda1", "sda2"]); // the proxy's own disk
        disk(sys, "2:0:1:0", "sdb", &[]); // a hot-added snapshot disk
        disk(sys, "2:0:2:0", "sdc", &["sdc1"]); // one someone mounted
        disk(sys, "0:0:0:0", "sr0", &[]); // the CD-ROM
        let mounts = "/dev/sda1 / ext4 rw 0 0\n/dev/sdc1 /mnt ext4 rw 0 0\n";
        assert_eq!(find(sys, mounts, "", 1).unwrap(), Path::new("/dev/sdb"));
        assert!(find(sys, mounts, "", 2).unwrap_err().contains("mounted"));
        assert!(find(sys, mounts, "", 3).unwrap_err().contains("no disk"));
        // something stacked on it
        fs::create_dir_all(sys.join("block/sdb/holders/dm-0")).unwrap();
        assert!(find(sys, mounts, "", 1).unwrap_err().contains("in use"));
        fs::remove_dir(sys.join("block/sdb/holders/dm-0")).unwrap();
        assert!(find(sys, "", "/dev/sdb partition 1024 0 -2\n", 1)
            .unwrap_err()
            .contains("swap"));
    }
}
