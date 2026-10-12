//! Layout → recreation plan (pure; docs/bmr.md "What is recreated"). The source
//! disks of the layout map in order onto the target disks confirmed at the rescue
//! console; every target must be at least as large and use the same logical
//! sector size. Partitions keep their start, size, type, GUID and name (the extra
//! space of a larger disk stays unallocated); LVM PVs keep their UUID, VGs and LVs
//! their names and sizes (thin pools and thin volumes included); file systems and
//! swap are made with their original UUID and label, so `/etc/fstab`, the boot
//! loader and the initramfs of the restored system keep working.
//!
//! Not recreated (the plan is refused): file systems or PVs on LUKS or md RAID,
//! ZFS, and file system types without a known mkfs.

use agent_proto::layout::{Disk, FileSystem, Layout};
use std::collections::HashSet;

/// A disk of the rescue machine.
#[derive(Clone, Debug, PartialEq)]
pub struct TargetDisk {
    pub path: String,
    pub size: u64,
    pub sector_size: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Cmd {
    pub argv: Vec<String>,
    pub stdin: Option<String>,
}

fn cmd(argv: &[&str]) -> Cmd {
    Cmd {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        stdin: None,
    }
}

/// A file system mount below the restore target, in mount order.
#[derive(Clone, Debug, PartialEq)]
pub struct PlannedMount {
    pub device: String,
    /// absolute path inside the restored system
    pub mountpoint: String,
    pub fstype: String,
    /// "subvol=…" for btrfs subvolumes, else ""
    pub options: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Plan {
    /// (source disk, target disk)
    pub disks: Vec<(String, String)>,
    pub cmds: Vec<Cmd>,
    pub mounts: Vec<PlannedMount>,
    /// (file system device on the target, UUID it must have)
    pub uuids: Vec<(String, String)>,
    pub warnings: Vec<String>,
}

/// `/dev/sda` + 2 → `/dev/sda2`; `/dev/nvme0n1` + 2 → `/dev/nvme0n1p2`.
pub fn part_node(disk: &str, n: u32) -> String {
    if disk.ends_with(|c: char| c.is_ascii_digit()) {
        format!("{disk}p{n}")
    } else {
        format!("{disk}{n}")
    }
}

fn gib(b: u64) -> String {
    format!("{:.1} GiB", b as f64 / (1u64 << 30) as f64)
}

/// sfdisk script recreating `d`'s partition table on `target`.
pub fn sfdisk_script(d: &Disk, target: &str) -> String {
    let mut s = format!("label: {}\n", d.table);
    if !d.id.is_empty() {
        s.push_str(&format!("label-id: {}\n", d.id));
    }
    s.push_str("unit: sectors\n\n");
    let mut parts = d.partitions.clone();
    parts.sort_by_key(|p| p.number);
    for p in parts {
        let mut f = vec![format!("start={}", p.start), format!("size={}", p.size)];
        if !p.ptype.is_empty() {
            f.push(format!("type={}", p.ptype));
        }
        if d.table == "gpt" {
            if !p.uuid.is_empty() {
                f.push(format!("uuid={}", p.uuid));
            }
            if !p.name.is_empty() {
                f.push(format!("name=\"{}\"", p.name.replace(['"', '\\', '\n'], "_")));
            }
            if !p.attrs.is_empty() {
                f.push(format!("attrs=\"{}\"", p.attrs.replace(['"', '\\', '\n'], "_")));
            }
        } else if p.bootable {
            f.push("bootable".into());
        }
        s.push_str(&format!("{} : {}\n", part_node(target, p.number), f.join(", ")));
    }
    s
}

/// mkfs / mkswap command for a file system on `dev` with its UUID and label.
pub fn mkfs(f: &FileSystem, dev: &str) -> Result<Cmd, String> {
    let mut a: Vec<String> = vec![];
    let push = |a: &mut Vec<String>, x: &[&str]| a.extend(x.iter().map(|s| s.to_string()));
    match f.fstype.as_str() {
        t @ ("ext2" | "ext3" | "ext4") => {
            push(&mut a, &[&format!("mkfs.{t}"), "-F", "-q"]);
            if !f.uuid.is_empty() {
                push(&mut a, &["-U", &f.uuid]);
            }
            if !f.label.is_empty() {
                push(&mut a, &["-L", &f.label]);
            }
        }
        "xfs" => {
            push(&mut a, &["mkfs.xfs", "-f", "-q"]);
            if !f.uuid.is_empty() {
                push(&mut a, &["-m", &format!("uuid={}", f.uuid)]);
            }
            if !f.label.is_empty() {
                push(&mut a, &["-L", &f.label]);
            }
        }
        "btrfs" => {
            push(&mut a, &["mkfs.btrfs", "-f", "-q"]);
            if !f.uuid.is_empty() {
                push(&mut a, &["-U", &f.uuid]);
            }
            if !f.label.is_empty() {
                push(&mut a, &["-L", &f.label]);
            }
        }
        "vfat" => {
            push(&mut a, &["mkfs.vfat"]);
            match f.version.as_str() {
                "FAT12" => push(&mut a, &["-F", "12"]),
                "FAT16" => push(&mut a, &["-F", "16"]),
                "FAT32" => push(&mut a, &["-F", "32"]),
                _ => {}
            }
            let id = f.uuid.replace('-', "");
            if id.len() == 8 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
                push(&mut a, &["-i", &id]);
            }
            if !f.label.is_empty() {
                push(&mut a, &["-n", &f.label]);
            }
        }
        "swap" => {
            push(&mut a, &["mkswap"]);
            if !f.uuid.is_empty() {
                push(&mut a, &["-U", &f.uuid]);
            }
            if !f.label.is_empty() {
                push(&mut a, &["-L", &f.label]);
            }
        }
        t => return Err(format!("{}: file system type {t:?} cannot be recreated", f.device)),
    }
    a.push(dev.to_string());
    Ok(Cmd { argv: a, stdin: None })
}

fn depth(mp: &str) -> usize {
    mp.split('/').filter(|c| !c.is_empty()).count()
}

/// The recreation plan of `l` on `targets` (in the order of the layout's disks).
pub fn plan(l: &Layout, targets: &[TargetDisk]) -> Result<Plan, String> {
    let mut p = Plan::default();
    if l.disks.is_empty() {
        return Err("the layout records no disks (was the snapshot taken by an agent older than 0.2?)".into());
    }
    if targets.len() < l.disks.len() {
        return Err(format!(
            "the snapshot's machine had {} disk(s) ({}), but only {} target disk(s) were confirmed",
            l.disks.len(),
            l.disks.iter().map(|d| d.name.as_str()).collect::<Vec<_>>().join(", "),
            targets.len()
        ));
    }
    for (d, t) in l.disks.iter().zip(targets) {
        if t.size < d.size {
            return Err(format!(
                "target disk {} ({}) is smaller than the original disk {} ({}): same or larger disks only",
                t.path,
                gib(t.size),
                d.name,
                gib(d.size)
            ));
        }
        if d.sector_size != 0 && t.sector_size != 0 && d.sector_size != t.sector_size {
            return Err(format!(
                "target disk {} has {}-byte sectors, the original disk {} had {}",
                t.path, t.sector_size, d.name, d.sector_size
            ));
        }
        p.disks.push((d.path.clone(), t.path.clone()));
    }
    if targets.len() > l.disks.len() {
        p.warnings.push(format!(
            "{} confirmed target disk(s) are not needed and stay untouched",
            targets.len() - l.disks.len()
        ));
    }
    // source device → target device: whole disks, partitions, LVs (same /dev/mapper name)
    let lv_paths: HashSet<&str> = l
        .vgs
        .iter()
        .flat_map(|v| v.lvs.iter().map(|x| x.dm_path.as_str()))
        .collect();
    let map = |dev: &str| -> Option<String> {
        for (d, (_, t)) in l.disks.iter().zip(&p.disks) {
            if d.path == dev {
                return Some(t.clone());
            }
            if let Some(part) = d.partitions.iter().find(|x| x.path == dev) {
                return Some(part_node(t, part.number));
            }
        }
        lv_paths.contains(dev).then(|| dev.to_string())
    };
    let unsupported = |dev: &str, what: &str| {
        let why = if l.luks.iter().any(|x| x.mapping == dev) {
            "on LUKS (encrypted volumes are not recreated)"
        } else if l.md.iter().any(|x| x.path == dev) {
            "on md RAID (software RAID is not recreated)"
        } else {
            "not on a recorded partition, disk or LVM volume"
        };
        format!("{what} {dev} is {why}; see docs/bmr.md \"Limitations\"")
    };
    let mut cmds = vec![];
    for (d, t) in l.disks.iter().zip(targets) {
        if !d.table.is_empty() {
            cmds.push(Cmd {
                argv: [
                    "sfdisk",
                    "-q",
                    "--wipe",
                    "always",
                    "--wipe-partitions",
                    "always",
                    &t.path,
                ]
                .iter()
                .map(|s| s.to_string())
                .collect(),
                stdin: Some(sfdisk_script(d, &t.path)),
            });
        }
    }
    for vg in &l.vgs {
        let mut devs = vec![];
        for pv in &vg.pvs {
            let dev = map(&pv.device).ok_or_else(|| unsupported(&pv.device, &format!("LVM PV of {}", vg.name)))?;
            let mut c = vec!["lvm", "pvcreate", "-ff", "-y"];
            if !pv.uuid.is_empty() {
                c.extend(["--uuid", &pv.uuid, "--norestorefile"]);
            }
            c.push(&dev);
            cmds.push(cmd(&c));
            devs.push(dev);
        }
        let ext = vg.extent_size.max(1 << 20);
        let mut c: Vec<String> = ["lvm", "vgcreate", "-y", "-s"].iter().map(|s| s.to_string()).collect();
        c.push(format!("{}k", ext / 1024));
        c.push(vg.name.clone());
        c.extend(devs);
        cmds.push(Cmd { argv: c, stdin: None });
        let extents = |b: u64| b.div_ceil(ext).to_string();
        let mut lvs = vg.lvs.clone();
        // pools before their thin volumes
        lvs.sort_by_key(|x| match x.segtype.as_str() {
            "thin-pool" => 0,
            "thin" => 2,
            _ => 1,
        });
        for lv in &lvs {
            let full = format!("{}/{}", vg.name, lv.name);
            let c: Vec<String> = match lv.segtype.as_str() {
                "thin-pool" => {
                    let mut c: Vec<String> = ["lvm", "lvcreate", "-y", "-Wy", "-Zy", "--type", "thin-pool", "-l"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect();
                    c.push(extents(lv.size));
                    if lv.metadata_size > 0 {
                        c.push("--poolmetadatasize".into());
                        c.push(format!("{}b", lv.metadata_size));
                    }
                    c.extend(["-n".into(), lv.name.clone(), vg.name.clone()]);
                    c
                }
                "thin" => {
                    let mut c: Vec<String> = ["lvm", "lvcreate", "-y", "--type", "thin", "-V"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect();
                    c.push(format!("{}b", lv.size));
                    c.extend([
                        "--thinpool".into(),
                        lv.pool.clone(),
                        "-n".into(),
                        lv.name.clone(),
                        vg.name.clone(),
                    ]);
                    c
                }
                "snapshot" => {
                    p.warnings.push(format!("LVM snapshot {full} is not recreated"));
                    continue;
                }
                t => {
                    if t != "linear" && !t.is_empty() {
                        p.warnings.push(format!("{full} ({t}) is recreated as a linear volume"));
                    }
                    let mut c: Vec<String> = ["lvm", "lvcreate", "-y", "-Wy", "-Zy", "-l"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect();
                    c.push(extents(lv.size));
                    c.extend(["-n".into(), lv.name.clone(), vg.name.clone()]);
                    c
                }
            };
            cmds.push(Cmd { argv: c, stdin: None });
        }
    }
    let mut mounts: Vec<PlannedMount> = vec![];
    let mut btrfs_n = 0;
    for f in &l.filesystems {
        let dev = map(&f.device).ok_or_else(|| unsupported(&f.device, "file system"))?;
        cmds.push(mkfs(f, &dev)?);
        if !f.uuid.is_empty() {
            p.uuids.push((dev.clone(), f.uuid.clone()));
        }
        let mut ms = f.mounts.clone();
        ms.sort_by(|a, b| {
            depth(&a.mountpoint)
                .cmp(&depth(&b.mountpoint))
                .then(a.mountpoint.cmp(&b.mountpoint))
        });
        if f.fstype == "btrfs" {
            let subs: Vec<&str> = {
                let mut v: Vec<&str> = ms.iter().map(|m| m.subvol()).filter(|s| !s.is_empty()).collect();
                v.sort();
                v.dedup();
                v
            };
            if !subs.is_empty() {
                let tmp = format!("/run/nexus-rescue/btrfs-{btrfs_n}");
                btrfs_n += 1;
                cmds.push(cmd(&["mkdir", "-p", &tmp]));
                cmds.push(cmd(&["mount", "-t", "btrfs", "-o", "subvolid=5", &dev, &tmp]));
                for s in &subs {
                    let path = format!("{tmp}/{s}");
                    if let Some((parent, _)) = path.rsplit_once('/') {
                        cmds.push(cmd(&["mkdir", "-p", parent]));
                    }
                    cmds.push(cmd(&["btrfs", "subvolume", "create", &path]));
                }
                cmds.push(cmd(&["umount", &tmp]));
            }
            let mut seen = HashSet::new();
            for m in ms {
                if seen.insert(m.subvol().to_string()) {
                    let sv = m.subvol();
                    mounts.push(PlannedMount {
                        device: dev.clone(),
                        mountpoint: m.mountpoint.clone(),
                        fstype: f.fstype.clone(),
                        options: if sv.is_empty() {
                            String::new()
                        } else {
                            format!("subvol={sv}")
                        },
                    });
                }
            }
        } else if let Some(m) = ms.first() {
            // further mounts of the same file system are bind mounts: the content is there once
            mounts.push(PlannedMount {
                device: dev.clone(),
                mountpoint: m.mountpoint.clone(),
                fstype: f.fstype.clone(),
                options: String::new(),
            });
        }
    }
    for s in &l.swaps {
        let dev = map(&s.device).ok_or_else(|| unsupported(&s.device, "swap"))?;
        let f = FileSystem {
            device: s.device.clone(),
            fstype: "swap".into(),
            uuid: s.uuid.clone(),
            label: s.label.clone(),
            ..Default::default()
        };
        cmds.push(mkfs(&f, &dev)?);
    }
    if !mounts.iter().any(|m| m.mountpoint == "/") {
        return Err("the layout has no recreatable root file system (ZFS, LUKS or md RAID root?)".into());
    }
    mounts.sort_by(|a, b| {
        depth(&a.mountpoint)
            .cmp(&depth(&b.mountpoint))
            .then(a.mountpoint.cmp(&b.mountpoint))
    });
    if !l.md.is_empty() {
        p.warnings
            .push("md RAID arrays of the original machine are not recreated (see docs/bmr.md)".into());
    }
    p.cmds = cmds;
    p.mounts = mounts;
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_proto::layout::*;

    fn deb() -> Layout {
        crate::layout::build(&crate::layout::tests::sources("deb-lvm"))
    }

    fn t(path: &str, gib: u64) -> TargetDisk {
        TargetDisk {
            path: path.into(),
            size: gib << 30,
            sector_size: 512,
        }
    }

    fn line(p: &Plan, first: &str) -> Vec<String> {
        p.cmds
            .iter()
            .filter(|c| c.argv.join(" ").starts_with(first))
            .map(|c| c.argv.join(" "))
            .collect()
    }

    #[test]
    fn debian_lvm_onto_larger_scsi_disks() {
        let p = plan(&deb(), &[t("/dev/sda", 20), t("/dev/sdb", 8)]).unwrap();
        assert_eq!(
            p.disks,
            [
                ("/dev/vda".into(), "/dev/sda".into()),
                ("/dev/vdb".into(), "/dev/sdb".into())
            ]
        );
        let sf = &p.cmds[0];
        assert_eq!(sf.argv.last().unwrap(), "/dev/sda");
        let script = sf.stdin.as_deref().unwrap();
        assert!(script.starts_with("label: gpt\nlabel-id: 5D1E3A27-9C1B-4E3A-8F55-0B1C2D3E4F50\nunit: sectors\n"));
        assert!(script.contains(
            "/dev/sda15 : start=8192, size=253952, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, uuid=A1B2C3D4-0000-4000-8000-000000000015, name=\"EFI System\"\n"
        ));
        assert!(script.find("/dev/sda1 :").unwrap() < script.find("/dev/sda14 :").unwrap());
        assert_eq!(line(&p, "sfdisk").len(), 1, "vdb is a whole-disk PV: no table");
        assert_eq!(
            line(&p, "lvm pvcreate"),
            [
                "lvm pvcreate -ff -y --uuid Pv0aaa-1111 --norestorefile /dev/sda1",
                "lvm pvcreate -ff -y --uuid Pv1bbb-2222 --norestorefile /dev/sdb"
            ]
        );
        assert_eq!(
            line(&p, "lvm vgcreate"),
            [
                "lvm vgcreate -y -s 4096k vg0 /dev/sda1",
                "lvm vgcreate -y -s 4096k vgdata /dev/sdb"
            ]
        );
        let lvs = line(&p, "lvm lvcreate");
        assert_eq!(lvs[0], "lvm lvcreate -y -Wy -Zy -l 2304 -n root vg0");
        let pool = lvs.iter().position(|l| l.contains("thin-pool")).unwrap();
        let thin = lvs.iter().position(|l| l.contains("--thinpool")).unwrap();
        assert!(pool < thin);
        assert_eq!(
            lvs[pool],
            "lvm lvcreate -y -Wy -Zy --type thin-pool -l 1024 --poolmetadatasize 4194304b -n pool vgdata"
        );
        assert_eq!(
            lvs[thin],
            "lvm lvcreate -y --type thin -V 3221225472b --thinpool pool -n xfs vgdata"
        );
        assert_eq!(
            line(&p, "mkfs.ext4"),
            [
                "mkfs.ext4 -F -q -U 6f1c2a5e-8f0b-4b1e-9d1c-0c8a3b2f4e11 /dev/mapper/vg0-root",
                "mkfs.ext4 -F -q -U 1d0e8f61-5a54-4c1b-8f63-2b8a6b9c7d22 /dev/mapper/vgdata-data"
            ]
        );
        assert_eq!(
            line(&p, "mkfs.vfat"),
            ["mkfs.vfat -F 16 -i 7C2E1A0B -n UEFI /dev/sda15"]
        );
        assert_eq!(
            line(&p, "mkfs.xfs"),
            ["mkfs.xfs -f -q -m uuid=9a7c3e1d-44b2-4d7e-a9b3-5c6d7e8f9a33 -L srvxfs /dev/mapper/vgdata-xfs"]
        );
        assert_eq!(
            line(&p, "mkswap"),
            ["mkswap -U 0b6f6c55-2f0a-4d8e-bd1c-7a1e3b6c9d01 /dev/mapper/vg0-swap"]
        );
        let mps: Vec<&str> = p.mounts.iter().map(|m| m.mountpoint.as_str()).collect();
        assert_eq!(mps, ["/", "/boot/efi", "/srv/xfs", "/var/lib/postgresql"]);
        assert!(p.uuids.contains(&("/dev/sda15".into(), "7C2E-1A0B".into())));
    }

    #[test]
    fn refusals() {
        let l = deb();
        let e = plan(&l, &[t("/dev/sda", 20)]).unwrap_err();
        assert!(e.contains("only 1 target disk"), "{e}");
        let e = plan(&l, &[t("/dev/sda", 11), t("/dev/sdb", 8)]).unwrap_err();
        assert!(e.contains("smaller than the original disk vda"), "{e}");
        let mut big = t("/dev/sdb", 8);
        big.sector_size = 4096;
        assert!(plan(&l, &[t("/dev/sda", 12), big]).unwrap_err().contains("4096-byte"));
        let mut luks = l.clone();
        luks.luks.push(Luks {
            device: "/dev/vda1".into(),
            uuid: "x".into(),
            mapping: "/dev/mapper/luks-x".into(),
        });
        luks.filesystems[0].device = "/dev/mapper/luks-x".into();
        let e = plan(&luks, &[t("/dev/sda", 12), t("/dev/sdb", 8)]).unwrap_err();
        assert!(e.contains("on LUKS"), "{e}");
        let mut zfs = l.clone();
        zfs.filesystems
            .retain(|f| !f.mounts.iter().any(|m| m.mountpoint == "/"));
        assert!(plan(&zfs, &[t("/dev/sda", 12), t("/dev/sdb", 8)])
            .unwrap_err()
            .contains("no recreatable root"));
    }

    #[test]
    fn btrfs_subvolumes_and_nvme_names() {
        let l = Layout {
            disks: vec![Disk {
                name: "vda".into(),
                path: "/dev/vda".into(),
                size: 10 << 30,
                sector_size: 512,
                table: "dos".into(),
                id: "0x1234".into(),
                partitions: vec![
                    Partition {
                        path: "/dev/vda1".into(),
                        number: 1,
                        start: 2048,
                        size: 2048,
                        ptype: "83".into(),
                        bootable: true,
                        ..Default::default()
                    },
                    Partition {
                        path: "/dev/vda2".into(),
                        number: 2,
                        start: 4096,
                        size: 9999,
                        ptype: "83".into(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            filesystems: vec![FileSystem {
                device: "/dev/vda2".into(),
                fstype: "btrfs".into(),
                uuid: "u".into(),
                label: "fedora".into(),
                mounts: ["/@root:/", "/@home:/home", "/@root:/var/alias"]
                    .iter()
                    .map(|x| {
                        let (sv, mp) = x.split_once(':').unwrap();
                        Mount {
                            mountpoint: mp.into(),
                            options: format!("rw,subvol={sv}"),
                        }
                    })
                    .collect(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let p = plan(&l, &[t("/dev/nvme0n1", 10)]).unwrap();
        let s = p.cmds[0].stdin.as_deref().unwrap();
        assert!(
            s.contains("/dev/nvme0n1p1 : start=2048, size=2048, type=83, bootable\n"),
            "{s}"
        );
        assert!(!s.contains("uuid="));
        assert_eq!(
            line(&p, "mkfs.btrfs"),
            ["mkfs.btrfs -f -q -U u -L fedora /dev/nvme0n1p2"]
        );
        assert_eq!(
            line(&p, "btrfs subvolume"),
            [
                "btrfs subvolume create /run/nexus-rescue/btrfs-0/@home",
                "btrfs subvolume create /run/nexus-rescue/btrfs-0/@root"
            ]
        );
        let m: Vec<(&str, &str)> = p
            .mounts
            .iter()
            .map(|m| (m.mountpoint.as_str(), m.options.as_str()))
            .collect();
        assert_eq!(
            m,
            [("/", "subvol=@root"), ("/home", "subvol=@home")],
            "the second @root mount is a bind mount"
        );
    }
}
