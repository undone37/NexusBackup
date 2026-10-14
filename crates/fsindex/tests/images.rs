//! Real file system images, built with the local tools (mkfs.ext4 -d,
//! mkfs.vfat + mtools, mkntfs + ntfs-3g (FUSE), mkfs.exfat, sgdisk, mkfs.xfs,
//! mkswap) without root, listed through the sandboxed helper and compared
//! with what was put in. A test whose tools are missing prints why and
//! passes (the CI runner may lack ntfs-3g/FUSE). LVM metadata is written by
//! the test itself (pvcreate needs root); real LVM volumes made by LVM are
//! covered by the micro-VM fixtures (crates/pve/tests/restore_vm.rs).

use fsindex::parent::{self, Helper, Listed, Source};
use fsindex::{Limits, Volume};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

const MTIME: i64 = 1_700_000_000;

fn tool(name: &str) -> Option<PathBuf> {
    for d in std::env::var("PATH")
        .unwrap_or_default()
        .split(':')
        .chain(["/usr/sbin", "/sbin"])
    {
        let p = Path::new(d).join(name);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// Runs a tool; `false` (with a note) when it is missing or fails.
fn run(name: &str, args: &[&str]) -> bool {
    let Some(p) = tool(name) else {
        eprintln!("skip: {name} not installed");
        return false;
    };
    match Command::new(p).args(args).output() {
        Ok(o) if o.status.success() => true,
        Ok(o) => {
            eprintln!("skip: {name} {args:?}: {}", String::from_utf8_lossy(&o.stderr).trim());
            false
        }
        Err(e) => {
            eprintln!("skip: {name}: {e}");
            false
        }
    }
}

fn touch(p: &Path, t: i64) {
    let f = File::options().write(true).open(p).or_else(|_| File::open(p)).unwrap();
    f.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(t as u64))
        .unwrap();
}

/// The sample tree: (path, kind, size).
fn sample(root: &Path, fstab: &str) -> Vec<(String, u8, u64)> {
    let files = [
        ("etc/fstab", fstab.as_bytes().to_vec()),
        ("home/ann/report 2026.txt", b"quarterly numbers".to_vec()),
        ("home/ann/Projekte/ünïcödé.md", vec![b'x'; 70_000]),
        ("var/lib/mysql/ibdata1", vec![7; 4096]),
    ];
    let mut out = Vec::new();
    for (p, data) in &files {
        let path = root.join(p);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, data).unwrap();
        out.push((p.to_string(), 0u8, data.len() as u64));
    }
    for d in [
        "etc",
        "home",
        "home/ann",
        "home/ann/Projekte",
        "var",
        "var/lib",
        "var/lib/mysql",
    ] {
        out.push((d.to_string(), 1, 0));
    }
    // children before parents: a directory's mtime changes when entries are added
    let mut all: Vec<_> = out.iter().map(|e| e.0.clone()).collect();
    all.sort_by_key(|p| std::cmp::Reverse(p.matches('/').count()));
    for p in all {
        touch(&root.join(p), MTIME);
    }
    out.sort();
    out
}

struct Files {
    disks: Vec<File>,
}

impl Source for Files {
    fn names(&self) -> Vec<String> {
        (0..self.disks.len()).map(|i| format!("drive-scsi{i}")).collect()
    }
    fn size(&self, d: usize) -> u64 {
        self.disks[d].metadata().unwrap().len()
    }
    fn chunk_size(&self, _: usize) -> u64 {
        4 << 20
    }
    fn read(&mut self, d: usize, off: u64, buf: &mut [u8]) -> io::Result<()> {
        self.disks[d].read_exact_at(buf, off)
    }
}

fn helper() -> Helper {
    Helper::new(Path::new(env!("CARGO_BIN_EXE_nexus-fsindex")))
}

fn list(paths: &[&Path]) -> Vec<Listed> {
    let mut src = Files {
        disks: paths.iter().map(|p| File::open(p).unwrap()).collect(),
    };
    // live progress: (entries so far, the walker's estimate) per volume
    let mut seen: std::collections::HashMap<String, (u64, Option<u64>)> = Default::default();
    let l = parent::list_with_progress(
        &mut src,
        &helper(),
        Limits::default(),
        &mut |_| false,
        &mut |v, n, e| {
            let s = seen.entry(v.key.clone()).or_default();
            s.0 = n;
            s.1 = e.or(s.1);
        },
    )
    .unwrap();
    for x in l.iter().filter(|x| x.volume.state == "indexed") {
        let (n, e) = seen[&x.volume.key];
        assert_eq!(
            n,
            x.entries.len() as u64,
            "{}: last progress = all entries",
            x.volume.browse
        );
        if matches!(x.volume.fs.as_str(), "ext4" | "ntfs") {
            let e = e.unwrap_or_else(|| panic!("{}: no estimate", x.volume.browse));
            assert!(e >= n / 2, "{}: estimate {e} for {n} entries", x.volume.browse);
        }
    }
    l
}

fn vol<'a>(l: &'a [Listed], browse: &str) -> &'a Listed {
    l.iter().find(|x| x.volume.browse == browse).unwrap_or_else(|| {
        panic!(
            "no volume {browse}: {:#?}",
            l.iter().map(|x| &x.volume).collect::<Vec<_>>()
        )
    })
}

/// (path, kind, size) of a volume, without file system internals.
fn got(l: &Listed, ignore: &[&str]) -> Vec<(String, u8, u64)> {
    let mut v: Vec<_> = l
        .entries
        .iter()
        .filter(|e| {
            !ignore
                .iter()
                .any(|i| e.path == *i || e.path.starts_with(&format!("{i}/")))
        })
        .map(|e| (e.path.clone(), e.kind, e.size))
        .collect();
    v.sort();
    v
}

fn put(disk: &Path, off: u64, img: &Path) {
    let data = fs::read(img).unwrap();
    File::options()
        .write(true)
        .open(disk)
        .unwrap()
        .write_all_at(&data, off)
        .unwrap();
}

fn sized(p: &Path, n: u64) {
    File::create(p).unwrap().set_len(n).unwrap();
}

#[test]
fn gpt_disk_with_ext4_root_and_fat_esp_plus_ntfs_disk() {
    let d = tempfile::tempdir().unwrap();
    let p = |n: &str| d.path().join(n);
    let ext_uuid = "4f3c2b1a-0000-4000-8000-0000000000aa";
    let fstab = format!(
        "UUID={ext_uuid} / ext4 defaults 0 1\nUUID=7A3B-1C2D /boot/efi vfat umask=0077 0 1\n/dev/sdb1 none swap sw 0 0\n"
    );
    let tree = p("tree");
    let expect = sample(&tree, &fstab);
    // ext4 root (files and mtimes from the directory, no root needed)
    if !run(
        "mkfs.ext4",
        &[
            "-q",
            "-F",
            "-L",
            "root",
            "-U",
            ext_uuid,
            "-d",
            tree.to_str().unwrap(),
            p("ext.img").to_str().unwrap(),
            "24M",
        ],
    ) {
        return;
    }
    // FAT ESP via mtools
    let efi = p("grubx64.efi");
    fs::write(&efi, b"MZ boot loader").unwrap();
    touch(&efi, MTIME);
    let fat = p("fat.img");
    if !run(
        "mkfs.vfat",
        &["-C", "-i", "7A3B1C2D", "-n", "ESP", fat.to_str().unwrap(), "8192"],
    ) || !run("mmd", &["-i", fat.to_str().unwrap(), "::/EFI", "::/EFI/debian"])
        || !run(
            "mcopy",
            &[
                "-m",
                "-i",
                fat.to_str().unwrap(),
                efi.to_str().unwrap(),
                "::/EFI/debian/grubx64.efi",
            ],
        )
    {
        return;
    }
    // GPT: 1 = ESP at 1 MiB (8 MiB), 2 = Linux at 9 MiB (24 MiB)
    let disk = p("disk0.img");
    sized(&disk, 40 << 20);
    if !run(
        "sgdisk",
        &[
            "-n",
            "1:2048:+8M",
            "-t",
            "1:ef00",
            "-n",
            "2:18432:+24M",
            "-t",
            "2:8300",
            disk.to_str().unwrap(),
        ],
    ) {
        return;
    }
    put(&disk, 2048 * 512, &fat);
    put(&disk, 18432 * 512, &p("ext.img"));

    let l = list(&[&disk]);
    let root = vol(&l, "vda2");
    assert_eq!(
        (root.volume.fs.as_str(), root.volume.state.as_str()),
        ("ext4", "indexed"),
        "{:?}",
        root.volume
    );
    assert_eq!(got(root, &["lost+found"]), expect);
    assert!(
        root.entries.iter().all(|e| e.path == "lost+found" || e.mtime == MTIME),
        "{:?}",
        root.entries
    );
    assert_eq!(root.volume.uuid.as_deref(), Some(ext_uuid));
    assert!(root.volume.fstab.as_deref().unwrap().contains("/boot/efi"));
    let esp = vol(&l, "vda1");
    assert_eq!(
        (esp.volume.fs.as_str(), esp.volume.uuid.as_deref()),
        ("vfat", Some("7A3B-1C2D"))
    );
    assert_eq!(
        got(esp, &[]),
        [
            ("EFI".into(), 1, 0),
            ("EFI/debian".into(), 1, 0),
            ("EFI/debian/grubx64.efi".into(), 0, 14)
        ]
    );
    // the guest's mount points
    let mut vols: Vec<Volume> = l.iter().map(|x| x.volume.clone()).collect();
    fsindex::mapping::assign(&mut vols);
    let m = fsindex::mapping::Mapper::new(&vols);
    assert_eq!(m.guest("vda2/home/ann/report 2026.txt"), "/home/ann/report 2026.txt");
    assert_eq!(
        m.guest("vda1/EFI/debian/grubx64.efi"),
        "/boot/efi/EFI/debian/grubx64.efi"
    );
    // the parse of each volume read only part of the disk (its metadata)
    assert!(!root.reads.is_empty() && root.reads.iter().all(|(d, _)| *d == 0));
}

#[test]
fn ntfs_whole_disk_windows_volume() {
    let d = tempfile::tempdir().unwrap();
    let img = d.path().join("ntfs.img");
    sized(&img, 32 << 20);
    if !run("mkntfs", &["-F", "-Q", "-q", "-L", "WinSys", img.to_str().unwrap()]) {
        return;
    }
    let mnt = d.path().join("m");
    fs::create_dir(&mnt).unwrap();
    if !run("ntfs-3g", &[img.to_str().unwrap(), mnt.to_str().unwrap()]) {
        return;
    }
    let expect = (|| {
        fs::create_dir_all(mnt.join("Windows/System32"))?;
        fs::write(mnt.join("Windows/System32/kernel32.dll"), vec![1u8; 3000])?;
        fs::create_dir_all(mnt.join("Users/ann/Documents"))?;
        fs::write(mnt.join("Users/ann/Documents/Angebot Müller.docx"), b"PK docx")?;
        touch(&mnt.join("Users/ann/Documents/Angebot Müller.docx"), MTIME);
        io::Result::Ok(())
    })();
    let umount =
        run("fusermount", &["-u", mnt.to_str().unwrap()]) || run("fusermount3", &["-u", mnt.to_str().unwrap()]);
    expect.unwrap();
    assert!(umount, "unmount");
    let l = list(&[&img]);
    let v = vol(&l, "vda");
    assert_eq!(
        (v.volume.fs.as_str(), v.volume.state.as_str()),
        ("ntfs", "indexed"),
        "{:?}",
        v.volume
    );
    assert!(v.volume.windows);
    assert_eq!(v.volume.label.as_deref(), Some("WinSys"));
    let e = got(v, &[]);
    for want in [
        ("Users/ann/Documents/Angebot Müller.docx".to_string(), 0u8, 7u64),
        ("Windows/System32/kernel32.dll".into(), 0, 3000),
        ("Windows".into(), 1, 0),
    ] {
        assert!(e.contains(&want), "{want:?} not in {e:?}");
    }
    let doc = v.entries.iter().find(|x| x.path.ends_with(".docx")).unwrap();
    assert_eq!(doc.mtime, MTIME);
    let mut vols = vec![v.volume.clone()];
    fsindex::mapping::assign(&mut vols);
    assert_eq!(vols[0].mount.as_deref(), Some("C:"));
}

/// exFAT: an empty file system from mkfs.exfat, entries written by the test
/// (no tool fills an exFAT image without mounting it).
#[test]
fn exfat_entries() {
    let d = tempfile::tempdir().unwrap();
    let img = d.path().join("exfat.img");
    sized(&img, 16 << 20);
    if !run("mkfs.exfat", &["-L", "STICK", img.to_str().unwrap()]) {
        return;
    }
    let mut data = fs::read(&img).unwrap();
    let le32 = |b: &[u8], o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
    let bps = 1usize << data[108];
    let cs = bps << data[109];
    let heap = le32(&data, 88) as usize * bps;
    let count = le32(&data, 92) as usize;
    let root = heap + (le32(&data, 96) as usize - 2) * cs;
    let free_cl = count + 1; // the last cluster: unused on an empty volume
    let sub = heap + (free_cl - 2) * cs;
    // entry set: file (0x85), stream (0xc0), names (0xc1)
    let set = |name: &str, dir: bool, size: u64, cluster: u32, ts: u32| {
        let u: Vec<u16> = name.encode_utf16().collect();
        let names = u.len().div_ceil(15);
        let mut v = vec![0u8; 32 * (2 + names)];
        v[0] = 0x85;
        v[1] = (1 + names) as u8;
        v[4..6].copy_from_slice(&(if dir { 0x10u16 } else { 0x20 }).to_le_bytes());
        v[12..16].copy_from_slice(&ts.to_le_bytes());
        v[32] = 0xc0;
        v[33] = 0x03; // allocation possible, no FAT chain
        v[35] = u.len() as u8;
        v[32 + 8..32 + 16].copy_from_slice(&size.to_le_bytes());
        v[32 + 20..32 + 24].copy_from_slice(&cluster.to_le_bytes());
        v[32 + 24..32 + 32].copy_from_slice(&size.to_le_bytes());
        for (i, c) in u.iter().enumerate() {
            let at = 64 + (i / 15) * 32;
            v[at] = 0xc1;
            v[at + 2 + (i % 15) * 2..at + 4 + (i % 15) * 2].copy_from_slice(&c.to_le_bytes());
        }
        v
    };
    // 2023-11-14 22:13:20 = 1700000000 (seconds / 2 = 10)
    let ts = (2023 - 1980) << 25 | 11 << 21 | 14 << 16 | 22 << 11 | 13 << 5 | 10;
    let free = (0..cs / 32).map(|i| root + i * 32).find(|&o| data[o] == 0).unwrap();
    let mut entries = set("Fotos Sommer", true, cs as u64, free_cl as u32, ts);
    entries.extend(set("a-very-long-file-name-over-fifteen.txt", false, 123, 0, ts));
    data[free..free + entries.len()].copy_from_slice(&entries);
    let inner = set("IMG_0001.JPG", false, 4_000_000, 0, ts);
    data[sub..sub + inner.len()].copy_from_slice(&inner);
    fs::write(&img, &data).unwrap();

    let l = list(&[&img]);
    let v = vol(&l, "vda");
    assert_eq!(
        (v.volume.fs.as_str(), v.volume.state.as_str()),
        ("exfat", "indexed"),
        "{:?}",
        v.volume
    );
    assert_eq!(v.volume.label.as_deref(), Some("STICK"));
    assert_eq!(
        got(v, &[]),
        [
            ("Fotos Sommer".into(), 1, 0),
            ("Fotos Sommer/IMG_0001.JPG".into(), 0, 4_000_000),
            ("a-very-long-file-name-over-fifteen.txt".into(), 0, 123)
        ]
    );
    assert!(v.entries.iter().all(|e| e.mtime == MTIME));
}

// --------------------------------------------------------------- LVM

fn crc_lvm(b: &[u8]) -> u32 {
    let mut c = 0xf597_a6cfu32;
    for &x in b {
        c ^= x as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
        }
    }
    c
}

/// A PV label + metadata area like pvcreate writes (mda at 4 KiB, data at 1 MiB).
fn pv(disk: &mut [u8], uuid: &str, text: &str) {
    let mut lab = vec![0u8; 512];
    lab[0..8].copy_from_slice(b"LABELONE");
    lab[8..16].copy_from_slice(&1u64.to_le_bytes());
    lab[20..24].copy_from_slice(&32u32.to_le_bytes());
    lab[24..32].copy_from_slice(b"LVM2 001");
    let ph = 32;
    lab[ph..ph + 32].copy_from_slice(uuid.as_bytes());
    lab[ph + 32..ph + 40].copy_from_slice(&(disk.len() as u64).to_le_bytes());
    // data area (1 MiB, rest), end; metadata area (4 KiB, 1 MiB - 4 KiB), end
    lab[ph + 40..ph + 48].copy_from_slice(&(1u64 << 20).to_le_bytes());
    lab[ph + 72..ph + 80].copy_from_slice(&4096u64.to_le_bytes());
    lab[ph + 80..ph + 88].copy_from_slice(&((1u64 << 20) - 4096).to_le_bytes());
    let c = crc_lvm(&lab[20..512]);
    lab[16..20].copy_from_slice(&c.to_le_bytes());
    disk[512..1024].copy_from_slice(&lab);
    let mut h = vec![0u8; 512];
    h[4..20].copy_from_slice(b" LVM2 x[5A%r0N*>");
    h[20..24].copy_from_slice(&1u32.to_le_bytes());
    h[24..32].copy_from_slice(&4096u64.to_le_bytes());
    h[32..40].copy_from_slice(&((1u64 << 20) - 4096).to_le_bytes());
    h[40..48].copy_from_slice(&512u64.to_le_bytes());
    h[48..56].copy_from_slice(&(text.len() as u64).to_le_bytes());
    let c = crc_lvm(&h[4..512]);
    h[0..4].copy_from_slice(&c.to_le_bytes());
    disk[4096..4608].copy_from_slice(&h);
    disk[4608..4608 + text.len()].copy_from_slice(text.as_bytes());
}

#[test]
fn lvm_linear_and_striped_lvs_with_ext4() {
    let d = tempfile::tempdir().unwrap();
    let tree = d.path().join("tree");
    let expect = sample(
        &tree,
        "/dev/mapper/vg--data-root / ext4 defaults 0 1\n/dev/vg-data/home /home ext4 defaults 0 2\n",
    );
    let img = d.path().join("ext.img");
    if !run(
        "mkfs.ext4",
        &["-q", "-F", "-d", tree.to_str().unwrap(), img.to_str().unwrap(), "8M"],
    ) {
        return;
    }
    let fsimg = fs::read(&img).unwrap();
    let ext = 4usize << 20; // extent size 8192 sectors
    let text = r#"vg-data {
id = "aaaaaa-bbbb-cccc-dddd-eeee-ffff-gggggg"
seqno = 3
status = ["RESIZEABLE", "READ", "WRITE"]
extent_size = 8192
physical_volumes {
pv0 { id = "AAAAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAAAA" device = "/dev/vda" pe_start = 2048 pe_count = 6 }
pv1 { id = "BBBBBB-BBBB-BBBB-BBBB-BBBB-BBBB-BBBBBB" device = "/dev/vdb" pe_start = 2048 pe_count = 6 }
}
logical_volumes {
root { id = "root-lv-id" status = ["READ", "WRITE", "VISIBLE"] segment_count = 1
segment1 { start_extent = 0 extent_count = 2 type = "striped" stripe_count = 1 stripes = ["pv0", 0] } }
home { id = "home-lv-id" status = ["READ", "WRITE", "VISIBLE"] segment_count = 1
segment1 { start_extent = 0 extent_count = 2 type = "striped" stripe_count = 2 stripe_size = 128 stripes = ["pv0", 2, "pv1", 0] } }
}
}
"#;
    let mut a = vec![0u8; (1 << 20) + 6 * ext];
    let mut b = vec![0u8; (1 << 20) + 6 * ext];
    pv(&mut a, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", text);
    pv(&mut b, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", text);
    // root: linear on pv0 extents 0-1
    a[1 << 20..(1 << 20) + fsimg.len()].copy_from_slice(&fsimg);
    // home: 64 KiB stripes alternating pv0 (from extent 2) and pv1 (from extent 0)
    for (i, s) in fsimg.chunks(64 << 10).enumerate() {
        let leg_off = (i / 2) * (64 << 10);
        if i % 2 == 0 {
            let o = (1 << 20) + 2 * ext + leg_off;
            a[o..o + s.len()].copy_from_slice(s);
        } else {
            let o = (1 << 20) + leg_off;
            b[o..o + s.len()].copy_from_slice(s);
        }
    }
    let (pa, pb) = (d.path().join("a.img"), d.path().join("b.img"));
    fs::write(&pa, &a).unwrap();
    fs::write(&pb, &b).unwrap();
    let l = list(&[&pa, &pb]);
    for lv in ["lvm/vg--data-root", "lvm/vg--data-home"] {
        let v = vol(&l, lv);
        assert_eq!(
            (v.volume.fs.as_str(), v.volume.state.as_str()),
            ("ext4", "indexed"),
            "{lv}: {:?}",
            v.volume
        );
        assert_eq!(got(v, &["lost+found"]), expect, "{lv}");
    }
    let mut vols: Vec<Volume> = l.iter().map(|x| x.volume.clone()).collect();
    fsindex::mapping::assign(&mut vols);
    let m = fsindex::mapping::Mapper::new(&vols);
    assert_eq!(m.guest("lvm/vg--data-home/etc/fstab"), "/home/etc/fstab");
    assert_eq!(m.guest("lvm/vg--data-root/etc/fstab"), "/etc/fstab");
    // the striped LV read from both disks
    let home = vol(&l, "lvm/vg--data-home");
    assert!(home.reads.iter().any(|r| r.0 == 0) && home.reads.iter().any(|r| r.0 == 1));
    // without pv1 the volume group is skipped as a whole
    let l = list(&[&pa]);
    for lv in ["lvm/vg--data-root", "lvm/vg--data-home"] {
        let v = vol(&l, lv);
        assert_eq!(v.volume.state, "unsupported");
        assert!(v
            .volume
            .reason
            .as_deref()
            .unwrap()
            .contains("physical volume missing (pv1)"));
    }
}

#[test]
fn unsupported_volumes_are_reported() {
    let d = tempfile::tempdir().unwrap();
    let mut disks: Vec<PathBuf> = Vec::new();
    let xfs = d.path().join("xfs.img");
    sized(&xfs, 320 << 20);
    if run("mkfs.xfs", &["-q", xfs.to_str().unwrap()]) {
        disks.push(xfs);
    }
    let swap = d.path().join("swap.img");
    sized(&swap, 4 << 20);
    if run("mkswap", &[swap.to_str().unwrap()]) {
        disks.push(swap);
    }
    let luks = d.path().join("luks.img");
    let mut h = vec![0u8; 1 << 20];
    h[..6].copy_from_slice(b"LUKS\xba\xbe");
    fs::write(&luks, &h).unwrap();
    disks.push(luks);
    // GPT whose entry array checksum is wrong
    let bad = d.path().join("bad.img");
    sized(&bad, 8 << 20);
    if run("sgdisk", &["-n", "1:2048:+2M", bad.to_str().unwrap()]) {
        let f = File::options().read(true).write(true).open(&bad).unwrap();
        f.write_all_at(&[0x55], 1024 + 40).unwrap();
        // the backup header's array is damaged the same way
        let n = f.metadata().unwrap().len();
        f.write_all_at(&[0x55], n - 33 * 512 + 40).unwrap();
        disks.push(bad);
    }
    let refs: Vec<&Path> = disks.iter().map(|p| p.as_path()).collect();
    let l = list(&refs);
    let states: BTreeSet<(String, String, String)> = l
        .iter()
        .map(|x| {
            (
                x.volume.fs.clone(),
                x.volume.state.clone(),
                x.volume.reason.clone().unwrap_or_default(),
            )
        })
        .collect();
    let has =
        |fs: &str, state: &str, why: &str| states.iter().any(|(f, s, r)| f == fs && s == state && r.contains(why));
    assert!(has("luks", "unsupported", "LUKS"), "{states:?}");
    if tool("mkfs.xfs").is_some() {
        assert!(has("xfs", "unsupported", "XFS"), "{states:?}");
    }
    if tool("mkswap").is_some() {
        assert!(has("swap", "skipped", "swap"), "{states:?}");
    }
    if tool("sgdisk").is_some() {
        assert!(has("", "failed", "corrupted partition table"), "{states:?}");
    }
}

/// Garbage behind valid-looking signatures: the volume fails, the listing
/// of the other volumes completes.
#[test]
fn hostile_volumes_fail_alone() {
    let d = tempfile::tempdir().unwrap();
    let mut x = 0x1234_5678_9abc_def0u64;
    let mut noise = |n: usize| {
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect::<Vec<u8>>()
    };
    let mut ntfs = noise(4 << 20);
    ntfs[3..11].copy_from_slice(b"NTFS    ");
    let mut ext = noise(4 << 20);
    ext[1024 + 56..1024 + 58].copy_from_slice(&0xEF53u16.to_le_bytes());
    ext[1024 + 24..1024 + 28].copy_from_slice(&2u32.to_le_bytes());
    let mut exf = noise(4 << 20);
    exf[3..11].copy_from_slice(b"EXFAT   ");
    exf[510] = 0x55;
    exf[511] = 0xaa;
    let mut paths = Vec::new();
    for (n, b) in [("ntfs", ntfs), ("ext", ext), ("exfat", exf)] {
        let p = d.path().join(n);
        fs::write(&p, b).unwrap();
        paths.push(p);
    }
    let refs: Vec<&Path> = paths.iter().map(|p| p.as_path()).collect();
    let l = list(&refs);
    assert_eq!(l.len(), 3, "{l:?}");
    assert!(
        l.iter().all(|x| x.volume.state == "failed"),
        "{:?}",
        l.iter().map(|x| &x.volume).collect::<Vec<_>>()
    );
}

/// The helper cannot open files or sockets once confined.
#[test]
fn helper_sandbox() {
    let out = Command::new(env!("CARGO_BIN_EXE_nexus-fsindex"))
        .arg("--sandbox-check")
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{s} {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(s.trim(), "open: denied, socket: denied, exec: denied");
}

/// A volume whose listing the caller already has is not parsed again.
#[test]
fn reuse_skips_the_parse() {
    let d = tempfile::tempdir().unwrap();
    let tree = d.path().join("tree");
    sample(&tree, "");
    let img = d.path().join("ext.img");
    if !run(
        "mkfs.ext4",
        &["-q", "-F", "-d", tree.to_str().unwrap(), img.to_str().unwrap(), "8M"],
    ) {
        return;
    }
    let mut src = Files {
        disks: vec![File::open(&img).unwrap()],
    };
    let l = parent::list(&mut src, &helper(), Limits::default(), &mut |v| v.fs == "ext4").unwrap();
    assert!(l[0].reused && l[0].entries.is_empty() && l[0].reads.is_empty());
    // limits: the listing stops and says so
    let lim = Limits {
        max_entries: 3,
        budget_secs: 60,
    };
    let l = parent::list(&mut src, &helper(), lim, &mut |_| false).unwrap();
    assert_eq!((l[0].volume.state.as_str(), l[0].entries.len()), ("partial", 3));
    assert!(l[0].volume.reason.as_deref().unwrap().contains("entry limit"));
}
