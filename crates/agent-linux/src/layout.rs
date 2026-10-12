//! Machine layout capture (`GetLayout`, docs/bmr.md "Layout"): the output of
//! `lsblk -J`, `sfdisk -J`, `pvs`/`vgs`/`lvs --reportformat json`, `findmnt -J`,
//! `blkid -o export`, `/proc/swaps`, `ip -j addr` and a few files, parsed into
//! [`agent_proto::layout::Layout`]. Collecting runs the tools; [`build`] is pure
//! (tested with fixtures from real machines in `tests/fixtures/layout/`).
//!
//! Recorded: the disks below every mounted block-device file system and swap
//! area (removable, loop, zram and optical devices are skipped), their partition
//! tables, the LVM volume groups on them, md RAID and LUKS (detected only), file
//! systems with UUID / label / mounts, swap, firmware, boot loader, kernel command
//! line, hostname, network addresses. Anything missing becomes a warning.

use crate::volumes::{run_tool, tool};
use agent_proto::layout::*;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;

/// Raw tool outputs ("" = tool missing or failed; the reason is in `warnings`).
#[derive(Default, Debug)]
pub struct Sources {
    pub lsblk: String,
    /// (disk path, `sfdisk -J <disk>` output)
    pub sfdisk: Vec<(String, String)>,
    pub pvs: String,
    pub vgs: String,
    pub lvs: String,
    pub findmnt: String,
    pub blkid: String,
    pub swaps: String,
    pub ip: String,
    pub os_release: String,
    pub cmdline: String,
    pub fstab: String,
    pub hostname: String,
    pub kernel: String,
    pub efi: bool,
    /// boot loader detected from files ("grub2", "systemd-boot", "")
    pub bootloader: String,
    /// mount points below this prefix are the agent's own snapshot mounts
    pub skip_prefix: String,
    pub warnings: Vec<String>,
}

pub const LSBLK_COLS: &str = "NAME,KNAME,PATH,TYPE,SIZE,FSTYPE,FSVER,UUID,LABEL,PARTUUID,MOUNTPOINT,RM,MODEL,LOG-SEC";

fn s(v: &Value) -> String {
    match v {
        Value::String(x) => x.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

/// Numbers are strings in older util-linux / LVM JSON.
fn num(v: &Value) -> u64 {
    match v {
        Value::Number(n) => n.as_u64().unwrap_or(0),
        Value::String(x) => x.trim().trim_end_matches(['B', 'b']).parse().unwrap_or(0),
        _ => 0,
    }
}

fn flag(v: &Value) -> bool {
    match v {
        Value::Bool(b) => *b,
        Value::String(x) => x == "1" || x == "true",
        Value::Number(n) => n.as_u64() == Some(1),
        _ => false,
    }
}

/// One `lsblk` node, flattened with its parent.
#[derive(Clone, Debug, Default)]
struct Node {
    name: String,
    kname: String,
    path: String,
    kind: String,
    size: u64,
    fstype: String,
    fsver: String,
    uuid: String,
    label: String,
    removable: bool,
    model: String,
    sector: u32,
    parent: Option<usize>,
}

fn walk(v: &Value, parent: Option<usize>, out: &mut Vec<Node>) {
    let kind = s(&v["type"]);
    let name = s(&v["name"]);
    let path = Some(s(&v["path"])).filter(|p| !p.is_empty()).unwrap_or_else(|| {
        if matches!(kind.as_str(), "lvm" | "crypt" | "dm") {
            format!("/dev/mapper/{name}")
        } else {
            format!(
                "/dev/{}",
                Some(s(&v["kname"])).filter(|k| !k.is_empty()).unwrap_or(name.clone())
            )
        }
    });
    out.push(Node {
        kname: s(&v["kname"]),
        name,
        path,
        kind,
        size: num(&v["size"]),
        fstype: s(&v["fstype"]),
        fsver: s(&v["fsver"]),
        uuid: s(&v["uuid"]),
        label: s(&v["label"]),
        removable: flag(&v["rm"]),
        model: s(&v["model"]).trim().to_string(),
        sector: num(&v["log-sec"]) as u32,
        parent,
    });
    let me = out.len() - 1;
    for c in v["children"].as_array().into_iter().flatten() {
        walk(c, Some(me), out);
    }
}

fn parse_lsblk(text: &str) -> Vec<Node> {
    let v: Value = serde_json::from_str(text).unwrap_or_default();
    let mut out = vec![];
    for d in v["blockdevices"].as_array().into_iter().flatten() {
        walk(d, None, &mut out);
    }
    out
}

fn top(nodes: &[Node], mut i: usize) -> usize {
    while let Some(p) = nodes[i].parent {
        i = p;
    }
    i
}

/// `blkid -o export`: device → (TYPE, UUID, LABEL).
pub fn parse_blkid(text: &str) -> HashMap<String, (String, String, String)> {
    let mut out = HashMap::new();
    for block in text.split("\n\n") {
        let kv: HashMap<&str, &str> = block.lines().filter_map(|l| l.split_once('=')).collect();
        if let Some(dev) = kv.get("DEVNAME") {
            let g = |k: &str| kv.get(k).map(|v| v.to_string()).unwrap_or_default();
            out.insert(dev.to_string(), (g("TYPE"), g("UUID"), g("LABEL")));
        }
    }
    out
}

/// `sfdisk -J <disk>` → (table, id, partitions).
pub fn parse_sfdisk(text: &str) -> (String, String, Vec<Partition>) {
    let v: Value = serde_json::from_str(text).unwrap_or_default();
    let t = &v["partitiontable"];
    let parts = t["partitions"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|p| {
            let node = s(&p["node"]);
            let digits = node.bytes().rev().take_while(u8::is_ascii_digit).count();
            let number = node[node.len() - digits..].parse().unwrap_or(0);
            Partition {
                path: node,
                number,
                start: num(&p["start"]),
                size: num(&p["size"]),
                ptype: s(&p["type"]),
                uuid: s(&p["uuid"]),
                name: s(&p["name"]),
                bootable: flag(&p["bootable"]),
                attrs: s(&p["attrs"]),
            }
        })
        .collect();
    (s(&t["label"]), s(&t["id"]), parts)
}

/// Rows of an LVM JSON report (`pvs`/`vgs`/`lvs --reportformat json`).
fn lvm_rows<'a>(v: &'a Value, key: &str) -> Vec<&'a Value> {
    v["report"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|r| r[key].as_array().into_iter().flatten())
        .collect()
}

pub fn parse_lvm(pvs: &str, vgs: &str, lvs: &str) -> Vec<Vg> {
    let j = |t: &str| serde_json::from_str::<Value>(t).unwrap_or_default();
    let (pvs, vgs, lvs) = (j(pvs), j(vgs), j(lvs));
    let mut out: Vec<Vg> = lvm_rows(&vgs, "vg")
        .into_iter()
        .map(|g| Vg {
            name: s(&g["vg_name"]),
            uuid: s(&g["vg_uuid"]),
            extent_size: num(&g["vg_extent_size"]),
            ..Default::default()
        })
        .collect();
    for p in lvm_rows(&pvs, "pv") {
        if let Some(vg) = out.iter_mut().find(|g| g.name == s(&p["vg_name"])) {
            vg.pvs.push(Pv {
                device: s(&p["pv_name"]),
                uuid: s(&p["pv_uuid"]),
                size: num(&p["pv_size"]),
            });
        }
    }
    let rows = lvm_rows(&lvs, "lv");
    for l in &rows {
        let name = s(&l["lv_name"]);
        // hidden LVs ([pool_tmeta], [lvol0_pmspare]) and our own backup snapshots
        if name.starts_with('[') || name.starts_with(crate::snapshot::PREFIX) {
            continue;
        }
        let Some(vg) = out.iter_mut().find(|g| g.name == s(&l["vg_name"])) else {
            continue;
        };
        let segtype = s(&l["segtype"]);
        let tmeta = format!("[{name}_tmeta]");
        let metadata_size = if segtype == "thin-pool" {
            rows.iter()
                .find(|r| s(&r["lv_name"]) == tmeta && s(&r["vg_name"]) == vg.name)
                .map(|r| num(&r["lv_size"]))
                .unwrap_or_else(|| num(&l["lv_metadata_size"]))
        } else {
            0
        };
        let dm = s(&l["lv_dm_path"]);
        vg.lvs.push(Lv {
            dm_path: if dm.is_empty() {
                format!("/dev/mapper/{}-{}", vg.name.replace('-', "--"), name.replace('-', "--"))
            } else {
                dm
            },
            name,
            uuid: s(&l["lv_uuid"]),
            size: num(&l["lv_size"]),
            segtype,
            pool: s(&l["pool_lv"]),
            metadata_size,
        });
    }
    out
}

/// `findmnt -J -l -o TARGET,SOURCE,FSTYPE,OPTIONS`: (source device, target, fstype, options)
/// of block-device mounts (btrfs `/dev/x[/subvol]` → `/dev/x`).
pub fn parse_findmnt(text: &str, skip_prefix: &str) -> Vec<(String, String, String, String)> {
    let v: Value = serde_json::from_str(text).unwrap_or_default();
    v["filesystems"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| {
            let src = s(&m["source"]);
            let dev = src.split('[').next().unwrap_or_default().to_string();
            let target = s(&m["target"]);
            let skip =
                !skip_prefix.is_empty() && (target == skip_prefix || target.starts_with(&format!("{skip_prefix}/")));
            (dev.starts_with("/dev/") && !skip).then(|| (dev, target, s(&m["fstype"]), s(&m["options"])))
        })
        .collect()
}

/// `/proc/swaps` → swap partitions / LVs (swap files are restored as files).
pub fn parse_swaps(text: &str) -> Vec<String> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let (dev, kind) = (f.next()?, f.next()?);
            (kind == "partition").then(|| dev.replace("\\040", " "))
        })
        .collect()
}

pub fn parse_ip(text: &str) -> Vec<NetIf> {
    let v: Value = serde_json::from_str(text).unwrap_or_default();
    v.as_array()
        .into_iter()
        .flatten()
        .filter(|i| s(&i["ifname"]) != "lo")
        .map(|i| NetIf {
            name: s(&i["ifname"]),
            mac: s(&i["address"]),
            addrs: i["addr_info"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|a| s(&a["scope"]) != "link")
                .map(|a| format!("{}/{}", s(&a["local"]), num(&a["prefixlen"])))
                .collect(),
        })
        .collect()
}

fn os_field(os_release: &str, key: &str) -> String {
    os_release
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")))
        .map(|v| v.trim().trim_matches('"').to_string())
        .unwrap_or_default()
}

/// Resolve a device name as `/proc/swaps` or findmnt prints it (`/dev/dm-1`) to the
/// lsblk path (`/dev/mapper/vg-swap`).
fn canonical(nodes: &[Node], dev: &str) -> String {
    let k = dev.trim_start_matches("/dev/");
    nodes
        .iter()
        .find(|n| n.path == dev || n.name == k || n.kname == k || n.path == format!("/dev/{k}"))
        .map(|n| n.path.clone())
        .or_else(|| {
            fs::canonicalize(dev).ok().and_then(|c| {
                let c = c.to_string_lossy().to_string();
                let k = c.trim_start_matches("/dev/").to_string();
                nodes
                    .iter()
                    .find(|n| n.path == c || n.kname == k)
                    .map(|n| n.path.clone())
            })
        })
        .unwrap_or_else(|| dev.to_string())
}

/// The layout from the tool outputs.
pub fn build(src: &Sources) -> Layout {
    let mut warnings = src.warnings.clone();
    let nodes = parse_lsblk(&src.lsblk);
    let blkid = parse_blkid(&src.blkid);
    let mounts = parse_findmnt(&src.findmnt, &src.skip_prefix);
    let swaps: Vec<String> = parse_swaps(&src.swaps).iter().map(|d| canonical(&nodes, d)).collect();
    let used: HashSet<String> = mounts
        .iter()
        .map(|m| canonical(&nodes, &m.0))
        .chain(swaps.iter().cloned())
        .collect();
    // disks with a used node in their subtree
    let mut disk_idx: Vec<usize> = vec![];
    for (i, n) in nodes.iter().enumerate() {
        if used.contains(&n.path) {
            let t = top(&nodes, i);
            if !disk_idx.contains(&t) {
                disk_idx.push(t);
            }
        }
    }
    // LVs spanning several disks: every PV's disk (lsblk lists the LV below each PV)
    disk_idx.sort();
    disk_idx.dedup();
    let sfdisk: HashMap<&str, &str> = src.sfdisk.iter().map(|(d, j)| (d.as_str(), j.as_str())).collect();
    let mut disks = vec![];
    for &i in &disk_idx {
        let n = &nodes[i];
        if n.kind != "disk" || n.removable {
            warnings.push(format!(
                "{} ({}{}) holds mounted file systems but is not recorded as a disk",
                n.path,
                n.kind,
                if n.removable { ", removable" } else { "" }
            ));
            continue;
        }
        let (table, id, partitions) = sfdisk.get(n.path.as_str()).map(|j| parse_sfdisk(j)).unwrap_or_default();
        disks.push(Disk {
            name: n.name.clone(),
            path: n.path.clone(),
            size: n.size,
            sector_size: if n.sector == 0 { 512 } else { n.sector },
            model: n.model.clone(),
            table,
            id,
            partitions,
        });
    }
    let on_disk = |path: &str| {
        nodes
            .iter()
            .enumerate()
            .any(|(i, n)| n.path == path && disks.iter().any(|d| d.path == nodes[top(&nodes, i)].path))
    };
    let mut vgs = parse_lvm(&src.pvs, &src.vgs, &src.lvs);
    vgs.retain(|vg| vg.pvs.iter().any(|p| on_disk(&canonical(&nodes, &p.device))));
    for vg in &mut vgs {
        for p in &mut vg.pvs {
            p.device = canonical(&nodes, &p.device);
        }
    }
    let mut md = vec![];
    let mut luks = vec![];
    for (i, n) in nodes.iter().enumerate() {
        if !disks.iter().any(|d| d.path == nodes[top(&nodes, i)].path) {
            continue;
        }
        if n.kind.starts_with("raid") && !md.iter().any(|m: &Md| m.path == n.path) {
            md.push(Md {
                path: n.path.clone(),
                level: n.kind.clone(),
                devices: nodes
                    .iter()
                    .filter(|x| x.path == n.path)
                    .filter_map(|x| x.parent.map(|p| nodes[p].path.clone()))
                    .collect(),
            });
        }
        if n.kind == "crypt" {
            let parent = n.parent.map(|p| &nodes[p]);
            luks.push(Luks {
                device: parent.map(|p| p.path.clone()).unwrap_or_default(),
                uuid: parent.map(|p| p.uuid.clone()).unwrap_or_default(),
                mapping: n.path.clone(),
            });
        }
    }
    let mut filesystems: Vec<FileSystem> = vec![];
    for (dev, target, fstype, options) in &mounts {
        let dev = canonical(&nodes, dev);
        if !on_disk(&dev) {
            continue;
        }
        let m = Mount {
            mountpoint: target.clone(),
            options: options.clone(),
        };
        if let Some(f) = filesystems.iter_mut().find(|f| f.device == dev) {
            if !f.mounts.contains(&m) {
                f.mounts.push(m);
            }
            continue;
        }
        let n = nodes.iter().find(|n| n.path == dev).cloned().unwrap_or_default();
        let b = blkid.get(&dev).cloned().unwrap_or_default();
        let pick = |a: &str, b: &str| if a.is_empty() { b.to_string() } else { a.to_string() };
        filesystems.push(FileSystem {
            device: dev.clone(),
            fstype: pick(&n.fstype, &pick(&b.0, fstype)),
            version: n.fsver.clone(),
            uuid: pick(&n.uuid, &b.1),
            label: pick(&n.label, &b.2),
            mounts: vec![m],
        });
    }
    let swaps = swaps
        .iter()
        .filter(|d| on_disk(d))
        .map(|d| {
            let n = nodes.iter().find(|n| &n.path == d).cloned().unwrap_or_default();
            let b = blkid.get(d).cloned().unwrap_or_default();
            Swap {
                device: d.clone(),
                uuid: if n.uuid.is_empty() { b.1 } else { n.uuid },
                label: if n.label.is_empty() { b.2 } else { n.label },
            }
        })
        .collect();
    if !filesystems.iter().any(|f| f.mounts.iter().any(|m| m.mountpoint == "/")) {
        warnings.push("the root file system is not on a recorded block device (ZFS root, network root?)".into());
    }
    let mut os_id = os_field(&src.os_release, "ID");
    let like = os_field(&src.os_release, "ID_LIKE");
    if !like.is_empty() {
        os_id = format!("{os_id} {like}");
    }
    Layout {
        version: LAYOUT_VERSION,
        hostname: src.hostname.clone(),
        os: os_field(&src.os_release, "PRETTY_NAME"),
        os_id,
        kernel: src.kernel.clone(),
        cmdline: src.cmdline.trim().to_string(),
        firmware: if src.efi { "uefi" } else { "bios" }.into(),
        bootloader: src.bootloader.clone(),
        disks,
        vgs,
        md,
        luks,
        filesystems,
        swaps,
        fstab: src.fstab.clone(),
        network: parse_ip(&src.ip),
        warnings,
    }
}

/// Boot loader from the files below `root` ("" = unknown).
pub fn detect_bootloader(root: &Path) -> String {
    let has = |p: &str| root.join(p).exists();
    if has("boot/grub/grub.cfg") || has("boot/grub2/grub.cfg") || has("boot/grub2/grubenv") {
        "grub2".into()
    } else if [
        "boot/efi/loader/loader.conf",
        "efi/loader/loader.conf",
        "boot/loader/loader.conf",
    ]
    .iter()
    .any(|p| has(p))
    {
        "systemd-boot".into()
    } else {
        String::new()
    }
}

/// Runs the tools and builds the layout of this machine.
pub fn capture(skip_prefix: &str) -> Layout {
    let mut src = Sources {
        skip_prefix: skip_prefix.to_string(),
        ..Default::default()
    };
    let run = |name: &str, args: &[&str], w: &mut Vec<String>| match run_tool(name, args) {
        Ok(o) => o,
        Err(e) => {
            w.push(e.chars().take(300).collect());
            String::new()
        }
    };
    let mut w = vec![];
    src.lsblk = run("lsblk", &["-J", "-b", "-o", LSBLK_COLS], &mut w);
    if src.lsblk.is_empty() {
        // util-linux < 2.33 has no PATH / FSVER column
        src.lsblk = run(
            "lsblk",
            &[
                "-J",
                "-b",
                "-o",
                "NAME,KNAME,TYPE,SIZE,FSTYPE,UUID,LABEL,PARTUUID,MOUNTPOINT,RM,MODEL,LOG-SEC",
            ],
            &mut w,
        );
    }
    src.findmnt = run("findmnt", &["-J", "-l", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"], &mut w);
    src.blkid = run("blkid", &["-o", "export"], &mut w);
    if tool("lvm").is_some() {
        let lvm = ["--reportformat", "json", "--units", "b", "--nosuffix"];
        let a = |cmd: &str, cols: &str, w: &mut Vec<String>| {
            let mut v: Vec<&str> = vec![cmd];
            v.extend(lvm);
            v.extend(["-o", cols]);
            if cmd == "lvs" {
                v.push("-a");
            }
            run("lvm", &v, w)
        };
        src.pvs = a("pvs", "pv_name,pv_uuid,pv_size,vg_name", &mut w);
        src.vgs = a("vgs", "vg_name,vg_uuid,vg_extent_size", &mut w);
        src.lvs = a(
            "lvs",
            "lv_name,lv_uuid,lv_size,segtype,pool_lv,vg_name,lv_dm_path,lv_metadata_size",
            &mut w,
        );
    }
    if tool("ip").is_some() {
        src.ip = run("ip", &["-j", "addr", "show"], &mut w);
    }
    // sfdisk for every disk that lsblk shows (cheap; build() picks the used ones)
    for n in parse_lsblk(&src.lsblk) {
        if n.kind == "disk" && n.parent.is_none() && !n.removable {
            if let Ok(j) = run_tool("sfdisk", &["-J", &n.path]) {
                src.sfdisk.push((n.path.clone(), j));
            }
        }
    }
    let read = |p: &str| fs::read_to_string(p).unwrap_or_default();
    src.swaps = read("/proc/swaps");
    src.os_release = read("/etc/os-release");
    src.cmdline = read("/proc/cmdline");
    src.fstab = read("/etc/fstab");
    let (kernel, hostname) = crate::sys::uname();
    src.kernel = kernel;
    src.hostname = hostname;
    src.efi = Path::new("/sys/firmware/efi").exists();
    src.bootloader = detect_bootloader(Path::new("/"));
    src.warnings = w;
    let mut l = build(&src);
    // never ship megabytes of fstab comments
    l.fstab.truncate(64 << 10);
    l
}

/// `GetLayout` answer: the layout as JSON.
pub fn capture_json(skip_prefix: &str) -> String {
    serde_json::to_string(&capture(skip_prefix)).unwrap_or_default()
}

/// Map a layout's disks for display: name → size (used by the rescue console too).
pub fn disk_sizes(l: &Layout) -> BTreeMap<String, u64> {
    l.disks.iter().map(|d| (d.name.clone(), d.size)).collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/layout")
                .join(name),
        )
        .unwrap()
    }

    pub(crate) fn sources(dir: &str) -> Sources {
        let f = |n: &str| fixture(&format!("{dir}/{n}"));
        let lsblk = f("lsblk.json");
        let sfdisk = parse_lsblk(&lsblk)
            .into_iter()
            .filter(|n| n.kind == "disk")
            .filter_map(|n| {
                let p = Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/layout")
                    .join(dir)
                    .join(format!("sfdisk-{}.json", n.name));
                fs::read_to_string(p).ok().map(|j| (n.path, j))
            })
            .collect();
        Sources {
            lsblk,
            sfdisk,
            pvs: f("pvs.json"),
            vgs: f("vgs.json"),
            lvs: f("lvs.json"),
            findmnt: f("findmnt.json"),
            blkid: f("blkid.txt"),
            swaps: f("swaps"),
            ip: f("ip.json"),
            os_release: f("os-release"),
            cmdline: "BOOT_IMAGE=/vmlinuz root=/dev/mapper/vg0-root ro\n".into(),
            fstab: f("fstab"),
            hostname: "deb-lvm".into(),
            kernel: "6.12.48+deb13-cloud-amd64".into(),
            efi: true,
            bootloader: "grub2".into(),
            skip_prefix: "/run/nexus-agent".into(),
            warnings: vec![],
        }
    }

    #[test]
    fn debian_lvm_thin_uefi() {
        let l = build(&sources("deb-lvm"));
        assert_eq!(l.os_id, "debian");
        assert_eq!(l.firmware, "uefi");
        let names: Vec<&str> = l.disks.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(
            names,
            ["vda", "vdb"],
            "the seed CD and the removable disk are not recorded"
        );
        let vda = &l.disks[0];
        assert_eq!(vda.table, "gpt");
        assert_eq!(vda.sector_size, 512);
        assert_eq!(vda.size, 12 << 30);
        let esp = vda.partitions.iter().find(|p| p.number == 15).unwrap();
        assert_eq!(esp.ptype, "C12A7328-F81F-11D2-BA4B-00A0C93EC93B");
        assert_eq!(esp.path, "/dev/vda15");
        assert_eq!(l.esp().unwrap().device, "/dev/vda15");
        assert_eq!(l.esp().unwrap().version, "FAT16");
        let vg = l.vgs.iter().find(|v| v.name == "vgdata").unwrap();
        assert_eq!(vg.extent_size, 4 << 20);
        assert_eq!(vg.pvs[0].device, "/dev/vdb");
        let pool = vg.lvs.iter().find(|l| l.segtype == "thin-pool").unwrap();
        assert_eq!(pool.metadata_size, 4 << 20, "from the hidden _tmeta LV");
        let thin = vg.lvs.iter().find(|l| l.segtype == "thin").unwrap();
        assert_eq!(
            (thin.pool.as_str(), thin.dm_path.as_str()),
            ("pool", "/dev/mapper/vgdata-xfs")
        );
        assert!(!vg
            .lvs
            .iter()
            .any(|l| l.name.starts_with('[') || l.name.starts_with("nexus-snap-")));
        let root = l
            .filesystems
            .iter()
            .find(|f| f.mounts.iter().any(|m| m.mountpoint == "/"))
            .unwrap();
        assert_eq!(root.device, "/dev/mapper/vg0-root");
        assert_eq!(root.fstype, "ext4");
        assert_eq!(root.uuid, "6f1c2a5e-8f0b-4b1e-9d1c-0c8a3b2f4e11");
        assert!(
            !l.filesystems
                .iter()
                .any(|f| f.mounts.iter().any(|m| m.mountpoint.starts_with("/run/nexus-agent"))),
            "the agent's snapshot mounts are skipped"
        );
        let xfs = l.filesystems.iter().find(|f| f.fstype == "xfs").unwrap();
        assert_eq!(xfs.label, "srvxfs", "label from blkid when lsblk has none");
        assert_eq!(l.swaps.len(), 1);
        assert_eq!(l.swaps[0].device, "/dev/mapper/vg0-swap");
        assert_eq!(l.boot_disk().unwrap().name, "vda");
        assert_eq!(l.network[0].addrs, ["10.0.2.15/24"]);
        assert!(l.md.is_empty() && l.luks.is_empty());
        assert!(l.warnings.iter().any(|w| w.contains("/dev/sdc")), "{:?}", l.warnings);
    }

    #[test]
    fn btrfs_subvolumes_luks_md_and_old_formats() {
        let l = build(&sources("fedora-btrfs"));
        let b = l.filesystems.iter().find(|f| f.fstype == "btrfs").unwrap();
        let subs: Vec<&str> = b.mounts.iter().map(|m| m.subvol()).collect();
        assert_eq!(subs, ["root", "home"]);
        assert_eq!(l.os_id, "fedora");
        // dos label, numbers as strings (util-linux 2.32)
        let sda = &l.disks[0];
        assert_eq!(sda.table, "dos");
        assert_eq!(sda.id, "0x8e7f1a2b");
        assert!(sda.partitions[0].bootable);
        assert_eq!(sda.partitions[0].ptype, "83");
        assert_eq!(sda.size, 20 << 30);
        assert_eq!(l.luks.len(), 1);
        assert_eq!(l.luks[0].device, "/dev/sda3");
        assert_eq!(l.md.len(), 1);
        assert_eq!(l.md[0].level, "raid1");
        assert_eq!(l.md[0].devices, ["/dev/sdb1", "/dev/sdc1"]);
    }

    #[test]
    fn small_parsers() {
        assert_eq!(
            parse_swaps("Filename Type Size Used Priority\n/dev/dm-1 partition 1 0 -2\n/swapfile file 1 0 -3\n"),
            ["/dev/dm-1"]
        );
        let b = parse_blkid("DEVNAME=/dev/vda1\nUUID=abc\nTYPE=ext4\n\nDEVNAME=/dev/vda2\nTYPE=swap\n");
        assert_eq!(b["/dev/vda1"], ("ext4".into(), "abc".into(), String::new()));
        assert_eq!(b["/dev/vda2"].0, "swap");
        let (t, id, p) = parse_sfdisk(
            r#"{"partitiontable":{"label":"gpt","id":"X","partitions":[{"node":"/dev/nvme0n1p12","start":2048,"size":10,"type":"T"}]}}"#,
        );
        assert_eq!((t.as_str(), id.as_str(), p[0].number), ("gpt", "X", 12));
        assert!(parse_findmnt("garbage", "").is_empty());
    }
}
