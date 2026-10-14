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

/// (volume key, directory) -> (entries, record): what the previous listing left (Phase 31c)
type Hist = std::collections::HashMap<(String, String), (Vec<fsindex::Entry>, fsindex::DirRec)>;

struct Files {
    disks: Vec<File>,
    hist: Hist,
    /// bytes the helpers read
    bytes: std::sync::atomic::AtomicU64,
}

fn files(paths: &[&Path]) -> Files {
    Files {
        disks: paths.iter().map(|p| File::open(p).unwrap()).collect(),
        hist: Hist::new(),
        bytes: Default::default(),
    }
}

/// The history a listing leaves for the next one (every directory unchanged), less `drop`.
fn hist_of(l: &[Listed], drop: Option<&str>) -> Hist {
    let mut h = Hist::new();
    for x in l {
        for r in x.dirs.iter().filter(|r| Some(r.rel.as_str()) != drop) {
            let entries = x
                .entries
                .iter()
                .filter(|e| e.path.rsplit_once('/').map_or("", |(d, _)| d) == r.rel)
                .cloned()
                .collect();
            h.insert((x.volume.key.clone(), r.rel.clone()), (entries, r.clone()));
        }
    }
    h
}

impl Source for Files {
    fn dir(&self, key: &str, rel: &str) -> Option<(Vec<fsindex::Entry>, fsindex::DirRec)> {
        self.hist.get(&(key.to_owned(), rel.to_owned())).cloned()
    }
    fn names(&self) -> Vec<String> {
        (0..self.disks.len()).map(|i| format!("drive-scsi{i}")).collect()
    }
    fn size(&self, d: usize) -> u64 {
        self.disks[d].metadata().unwrap().len()
    }
    fn chunk_size(&self, _: usize) -> u64 {
        4 << 20
    }
    fn read(&self, d: usize, off: u64, buf: &mut [u8]) -> io::Result<()> {
        self.bytes
            .fetch_add(buf.len() as u64, std::sync::atomic::Ordering::Relaxed);
        self.disks[d].read_exact_at(buf, off)
    }
}

fn helper() -> Helper {
    Helper::new(Path::new(env!("CARGO_BIN_EXE_nexus-fsindex")))
}

fn list(paths: &[&Path]) -> Vec<Listed> {
    let src = files(paths);
    // live progress: (entries so far, the walker's estimate) per volume
    let mut seen: std::collections::HashMap<String, (u64, Option<u64>)> = Default::default();
    let l = parent::list_with_progress(&src, &helper(), Limits::default(), &mut |_| false, &mut |v, n, e| {
        let s = seen.entry(v.key.clone()).or_default();
        s.0 = n;
        s.1 = e.or(s.1);
    })
    .unwrap();
    // Phase 32: three helpers splitting the NTFS / ext4 trees list exactly the same
    let src3 = files(paths);
    let three = Helper { parts: 3, ..helper() };
    let mut l3 = parent::list(&src3, &three, Limits::default(), &mut |_| false).unwrap();
    let key = |x: &Listed| {
        let mut e: Vec<_> = x
            .entries
            .iter()
            .map(|e| (e.path.clone(), e.size, e.mtime, e.kind))
            .collect();
        e.sort();
        (
            x.volume.key.clone(),
            x.volume.state.clone(),
            x.volume.windows,
            x.volume.entries,
            e,
        )
    };
    l3.sort_by(|a, b| a.volume.key.cmp(&b.volume.key));
    let mut l1: Vec<_> = l.iter().map(key).collect();
    l1.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        l3.iter().map(key).collect::<Vec<_>>(),
        l1,
        "3 helpers list what 1 lists"
    );
    // Phase 31c: a listing that may take every directory over lists the same and reads less;
    // a directory missing from the history (changed) is listed again; with 1 and 3 helpers
    let first = src.bytes.load(std::sync::atomic::Ordering::Relaxed);
    for x in &l {
        for r in &x.dirs {
            assert!(
                matches!(x.volume.fs.as_str(), "ntfs" | "xfs"),
                "{}: directory records only for NTFS and XFS",
                x.volume.fs
            );
            assert!(!r.deps.is_empty(), "/{}: a record without what it read", r.rel);
        }
    }
    let deepest = l
        .iter()
        .flat_map(|x| x.dirs.iter().map(|r| r.rel.clone()))
        .max_by_key(|r| r.matches('/').count());
    for (drop, parts) in [(None, 1), (deepest.as_deref(), 1), (None, 3)] {
        let again = Files {
            hist: hist_of(&l, drop),
            ..files(paths)
        };
        let h = Helper { parts, ..helper() };
        let mut l2 = parent::list(&again, &h, Limits::default(), &mut |_| false).unwrap();
        l2.sort_by(|a, b| a.volume.key.cmp(&b.volume.key));
        assert_eq!(
            l2.iter().map(key).collect::<Vec<_>>(),
            l1,
            "taken over ({drop:?}, {parts}): same listing"
        );
        for (a, b) in l2.iter().zip(&l3) {
            assert_eq!(
                a.dirs.len(),
                b.dirs.len(),
                "{}: every directory has a record again",
                a.volume.key
            );
        }
        let read = again.bytes.load(std::sync::atomic::Ordering::Relaxed);
        // (with 3 helpers every one of them opens the volumes: on these tiny images that dominates)
        // (an empty volume reads its root directory anyway: XFS looks up etc/fstab)
        if drop.is_none() && parts == 1 && l.iter().map(|x| x.dirs.len()).sum::<usize>() > 3 {
            assert!(
                read < first,
                "taken over ({parts}): {read} bytes read, {first} the first time"
            );
        }
    }
    for x in l.iter().filter(|x| x.volume.state == "indexed") {
        let (n, e) = seen[&x.volume.key];
        assert_eq!(
            n,
            x.entries.len() as u64,
            "{}: last progress = all entries",
            x.volume.browse
        );
        if matches!(x.volume.fs.as_str(), "ext4" | "ntfs" | "xfs") {
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
        // enough MFT records that taking the directories over saves reads
        fs::create_dir_all(mnt.join("Users/ann/Mail"))?;
        for i in 0..400 {
            fs::write(mnt.join(format!("Users/ann/Mail/{i:04}.eml")), b"Subject: x")?;
        }
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
        assert!(has("xfs", "indexed", ""), "{states:?}");
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
    let mut xfs = noise(4 << 20);
    xfs[0..4].copy_from_slice(b"XFSB");
    let mut btrfs = noise(4 << 20);
    btrfs[0x10040..0x10048].copy_from_slice(b"_BHRfS_M");
    btrfs[0x10088..0x10090].copy_from_slice(&1u64.to_le_bytes());
    let mut paths = Vec::new();
    for (n, b) in [
        ("ntfs", ntfs),
        ("ext", ext),
        ("exfat", exf),
        ("xfs", xfs),
        ("btrfs", btrfs),
    ] {
        let p = d.path().join(n);
        fs::write(&p, b).unwrap();
        paths.push(p);
    }
    let refs: Vec<&Path> = paths.iter().map(|p| p.as_path()).collect();
    let l = list(&refs);
    assert_eq!(l.len(), 5, "{l:?}");
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
    let src = files(&[img.as_path()]);
    let l = parent::list(&src, &helper(), Limits::default(), &mut |v| v.fs == "ext4").unwrap();
    assert!(l[0].reused && l[0].entries.is_empty() && l[0].reads.is_empty());
    // limits: the listing stops and says so
    let lim = Limits {
        max_entries: 3,
        budget_secs: 60,
        ..Default::default()
    };
    let l = parent::list(&src, &helper(), lim, &mut |_| false).unwrap();
    assert_eq!((l[0].volume.state.as_str(), l[0].entries.len()), ("partial", 3));
    assert!(l[0].volume.reason.as_deref().unwrap().contains("entry limit"));
}

/// An NTFS image of `size` bytes with `files` (path, content), written through
/// ntfs-3g (FUSE); `false` when the tools are missing.
fn ntfs_img(img: &Path, size: u64, label: &str, files: &[(&str, Vec<u8>)]) -> bool {
    sized(img, size);
    if !run("mkntfs", &["-F", "-Q", "-q", "-L", label, img.to_str().unwrap()]) {
        return false;
    }
    let mnt = img.with_extension("mnt");
    fs::create_dir_all(&mnt).unwrap();
    if !run("ntfs-3g", &[img.to_str().unwrap(), mnt.to_str().unwrap()]) {
        return false;
    }
    let res = (|| {
        for (p, data) in files {
            let p = mnt.join(p);
            fs::create_dir_all(p.parent().unwrap())?;
            fs::write(&p, data)?;
        }
        io::Result::Ok(())
    })();
    let umount =
        run("fusermount", &["-u", mnt.to_str().unwrap()]) || run("fusermount3", &["-u", mnt.to_str().unwrap()]);
    res.unwrap();
    assert!(umount, "unmount");
    true
}

/// Phase 31c: drive letters from the SYSTEM hive (`MountedDevices`): a GPT disk
/// with the system volume and a data volume (by partition GUID), an MBR disk
/// with a data volume (by disk signature and offset).
#[test]
fn windows_drive_letters_from_the_system_hive() {
    use fsindex::regf::{build, dmio};
    let d = tempfile::tempdir().unwrap();
    let p = |n: &str| d.path().join(n);
    let (sys_g, data_g) = (
        "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
        "11223344-5566-7788-99aa-bbccddeeff00",
    );
    let mut mbr = 0x1234_abcdu32.to_le_bytes().to_vec();
    mbr.extend((1u64 << 20).to_le_bytes());
    let hive = build(&[(
        "MountedDevices",
        vec![
            ("\\DosDevices\\C:", 3, dmio(sys_g)),
            ("\\DosDevices\\E:", 3, dmio(data_g)),
            ("\\DosDevices\\F:", 3, mbr),
        ],
    )]);
    if !ntfs_img(
        &p("sys.img"),
        16 << 20,
        "System",
        &[
            ("Windows/System32/config/SYSTEM", hive),
            ("Windows/System32/kernel32.dll", vec![1; 100]),
        ],
    ) || !ntfs_img(
        &p("data.img"),
        8 << 20,
        "Daten",
        &[("Projekte/plan.txt", b"x".to_vec())],
    ) || !ntfs_img(&p("mbr.img"), 8 << 20, "Archiv", &[("alt.txt", b"y".to_vec())])
    {
        return;
    }
    let disk = p("disk0.img");
    sized(&disk, 40 << 20);
    if !run(
        "sgdisk",
        &[
            "-n",
            "1:2048:+16M",
            "-t",
            "1:0700",
            "-u",
            &format!("1:{sys_g}"),
            "-n",
            "2:34816:+8M",
            "-t",
            "2:0700",
            "-u",
            &format!("2:{data_g}"),
            disk.to_str().unwrap(),
        ],
    ) {
        return;
    }
    put(&disk, 2048 * 512, &p("sys.img"));
    put(&disk, 34816 * 512, &p("data.img"));
    // MBR disk: signature 0x1234abcd, one NTFS partition at 1 MiB
    let disk1 = p("disk1.img");
    sized(&disk1, 12 << 20);
    let mut m = vec![0u8; 512];
    m[440..444].copy_from_slice(&0x1234_abcdu32.to_le_bytes());
    m[446 + 4] = 0x07;
    m[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());
    m[446 + 12..446 + 16].copy_from_slice(&16384u32.to_le_bytes());
    m[510] = 0x55;
    m[511] = 0xaa;
    File::options()
        .write(true)
        .open(&disk1)
        .unwrap()
        .write_all_at(&m, 0)
        .unwrap();
    put(&disk1, 2048 * 512, &p("mbr.img"));

    let l = list(&[&disk, &disk1]);
    let sys = vol(&l, "vda1");
    assert!(sys.volume.windows, "{:?}", sys.volume);
    assert_eq!(sys.volume.drives.len(), 3, "{:?}", sys.volume.drives);
    assert_eq!(vol(&l, "vdb1").volume.partuuid.as_deref(), Some("1234abcd-01"));
    let mut vols: Vec<Volume> = l.iter().map(|x| x.volume.clone()).collect();
    fsindex::mapping::assign(&mut vols);
    let m = fsindex::mapping::Mapper::new(&vols);
    assert_eq!(
        m.guest("vda1/Windows/System32/kernel32.dll"),
        "C:/Windows/System32/kernel32.dll"
    );
    assert_eq!(m.guest("vda2/Projekte/plan.txt"), "E:/Projekte/plan.txt");
    assert_eq!(m.guest("vdb1/alt.txt"), "F:/alt.txt");
}

/// Phase 31c: XFS through the own parser, v5 (4 KiB and 1 KiB blocks: directory
/// blocks of several file system blocks) and v4 without file types; directories
/// in short form, block, leaf, node and B+tree format (a protofile interleaves
/// file data with the growing directories, so the big one gets fragmented).
#[test]
fn xfs_directory_formats() {
    let d = tempfile::tempdir().unwrap();
    let tree = d.path().join("tree");
    let uuid = "5e1f0c3a-1111-4222-8333-444455556666";
    let expect = sample(&tree, &format!("UUID={uuid} / xfs defaults 0 0\n"));
    let blk = d.path().join("blk");
    fs::write(&blk, vec![7u8; 5000]).unwrap();
    // protofile: the sample tree, then the directory formats
    let mut proto = vec!["/dev/null".to_string(), "0 0".into(), "d--755 0 0".into()];
    // (a protofile cannot hold names with spaces)
    let mut want: Vec<_> = expect.iter().map(|(p, k, n)| (p.replace(' ', "_"), *k, *n)).collect();
    fn add(dir: &Path, rel: &str, proto: &mut Vec<String>) {
        let mut names: Vec<_> = fs::read_dir(dir.join(rel)).unwrap().map(|e| e.unwrap()).collect();
        names.sort_by_key(|e| e.file_name());
        for e in names {
            let real = e.file_name().into_string().unwrap();
            let n = real.replace(' ', "_");
            let p = if rel.is_empty() { real } else { format!("{rel}/{real}") };
            if e.file_type().unwrap().is_dir() {
                proto.push(format!("{n} d--755 0 0"));
                add(dir, &p, proto);
                proto.push("$".into());
            } else {
                // the source path may not contain spaces either
                let src = dir.with_extension(format!("src{}", proto.len()));
                fs::copy(dir.join(&p), &src).unwrap();
                proto.push(format!("{n} ---644 0 0 {}", src.display()));
            }
        }
    }
    add(&tree, "", &mut proto);
    for (dir, n) in [("block", 60), ("leaf", 300), ("node", 3000)] {
        proto.push(format!("{dir} d--755 0 0"));
        want.push((dir.into(), 1, 0));
        for i in 0..n {
            let f = format!("file-number-{i:05}.dat");
            proto.push(format!("{f} ---644 0 0 {}", blk.display()));
            want.push((format!("{dir}/{f}"), 0, 5000));
        }
        proto.push("$".into());
    }
    proto.push("link l--777 0 0 etc/fstab".into());
    want.push(("link".into(), 2, 0));
    proto.push("$".into());
    want.sort();
    let pf = d.path().join("proto");
    fs::write(&pf, proto.join("\n") + "\n").unwrap();
    let t0 = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut ran = 0;
    for (name, args) in [
        ("v5", vec![]),
        ("v5-1k", vec!["-b", "size=1024"]),
        ("v4", vec!["-m", "crc=0", "-n", "ftype=0", "-i", "size=256"]),
    ] {
        let img = d.path().join(format!("{name}.img"));
        sized(&img, 320 << 20);
        let mut a: Vec<&str> = vec!["-q", "-L", "data"];
        a.extend(&args);
        let u = format!("uuid={uuid}");
        a.extend(["-m", &u, "-p", pf.to_str().unwrap(), img.to_str().unwrap()]);
        if !run("mkfs.xfs", &a) {
            continue;
        }
        ran += 1;
        let l = list(&[&img]);
        let v = vol(&l, "vda");
        assert_eq!(
            (v.volume.fs.as_str(), v.volume.state.as_str()),
            ("xfs", "indexed"),
            "{name}: {:?}",
            v.volume
        );
        assert_eq!(got(v, &[]), want, "{name}");
        assert!(
            v.entries.iter().all(|e| (t0 - 120..t0 + 120).contains(&e.mtime)),
            "{name}: mtimes"
        );
        assert_eq!(v.volume.label.as_deref(), Some("data"));
        assert_eq!(v.volume.uuid.as_deref(), Some(uuid));
        let mut vols = vec![v.volume.clone()];
        fsindex::mapping::assign(&mut vols);
        assert_eq!(vols[0].mount.as_deref(), Some("/"), "{name}: root from its own fstab");
        assert!(!v.dirs.is_empty(), "{name}: directory records");
    }
    if tool("mkfs.xfs").is_some() {
        assert!(ran >= 2, "mkfs.xfs ran");
    }
}

/// A dm-thin B+tree node: `leaf`, (key, value) pairs; at block `blk`.
fn thin_node(blk: u64, leaf: bool, kv: &[(u64, u64)]) -> Vec<u8> {
    let max = 252usize;
    let mut b = vec![0u8; 4096];
    b[4..8].copy_from_slice(&(if leaf { 2u32 } else { 1 }).to_le_bytes());
    b[8..16].copy_from_slice(&blk.to_le_bytes());
    b[16..20].copy_from_slice(&(kv.len() as u32).to_le_bytes());
    b[20..24].copy_from_slice(&(max as u32).to_le_bytes());
    b[24..28].copy_from_slice(&8u32.to_le_bytes());
    for (i, (k, v)) in kv.iter().enumerate() {
        b[32 + i * 8..40 + i * 8].copy_from_slice(&k.to_le_bytes());
        b[32 + max * 8 + i * 8..40 + max * 8 + i * 8].copy_from_slice(&v.to_le_bytes());
    }
    let c = fsindex::lvm::pd_csum(&b, 121_107);
    b[0..4].copy_from_slice(&c.to_le_bytes());
    b
}

/// dm-thin pool metadata: superblock (block 0), the top-level tree (block 1: device 1 ->
/// block 2), device 1's mapping tree (block 2: internal node over the leaves 3 and 4).
fn thin_metadata(maps: &[(u64, u64)], block_sectors: u32) -> Vec<u8> {
    let mut m = vec![0u8; 5 * 4096];
    let mut sb = vec![0u8; 4096];
    sb[32..40].copy_from_slice(&27_022_010u64.to_le_bytes());
    sb[40..44].copy_from_slice(&2u32.to_le_bytes());
    sb[320..328].copy_from_slice(&1u64.to_le_bytes());
    sb[336..340].copy_from_slice(&block_sectors.to_le_bytes());
    sb[340..344].copy_from_slice(&8u32.to_le_bytes());
    let c = fsindex::lvm::pd_csum(&sb, 160_774);
    sb[0..4].copy_from_slice(&c.to_le_bytes());
    m[..4096].copy_from_slice(&sb);
    m[4096..8192].copy_from_slice(&thin_node(1, true, &[(1, 2)]));
    let vals: Vec<(u64, u64)> = maps.iter().map(|&(v, d)| (v, d << 24 | 5)).collect();
    let (a, b) = vals.split_at(vals.len() / 2);
    m[8192..12288].copy_from_slice(&thin_node(2, false, &[(a[0].0, 3), (b[0].0, 4)]));
    m[12288..16384].copy_from_slice(&thin_node(3, true, a));
    m[16384..20480].copy_from_slice(&thin_node(4, true, b));
    m
}

/// Phase 31c: a thin LV in a thin pool (metadata and data LVs on a PV), its ext4
/// spread over the pool's data blocks in reverse order, zero blocks unmapped.
#[test]
fn lvm_thin_volume_with_ext4() {
    let d = tempfile::tempdir().unwrap();
    let tree = d.path().join("tree");
    let expect = sample(&tree, "/dev/vg0/thin1 / ext4 defaults 0 1\n");
    let img = d.path().join("ext.img");
    if !run(
        "mkfs.ext4",
        &["-q", "-F", "-d", tree.to_str().unwrap(), img.to_str().unwrap(), "8M"],
    ) {
        return;
    }
    let fsimg = fs::read(&img).unwrap();
    let ext = 4usize << 20;
    let bs = 64usize << 10;
    let text = r#"vg0 {
id = "thin-vg-id"
seqno = 9
status = ["RESIZEABLE", "READ", "WRITE"]
extent_size = 8192
physical_volumes {
pv0 { id = "AAAAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAAAA" device = "/dev/vda" pe_start = 2048 pe_count = 3 }
}
logical_volumes {
pool { id = "pool-id" status = ["READ", "WRITE", "VISIBLE"] segment_count = 1
segment1 { start_extent = 0 extent_count = 2 type = "thin-pool" metadata = "pool_tmeta" pool = "pool_tdata" transaction_id = 2 chunk_size = 128 discards = "passdown" zero_new_blocks = 1 } }
thin1 { id = "thin1-id" status = ["READ", "WRITE", "VISIBLE"] segment_count = 1
segment1 { start_extent = 0 extent_count = 2 type = "thin" thin_pool = "pool" transaction_id = 0 device_id = 1 } }
gone { id = "gone-id" status = ["READ", "WRITE", "VISIBLE"] segment_count = 1
segment1 { start_extent = 0 extent_count = 1 type = "thin" thin_pool = "pool" transaction_id = 1 device_id = 2 } }
pool_tmeta { id = "tmeta-id" status = ["READ", "WRITE"] segment_count = 1
segment1 { start_extent = 0 extent_count = 1 type = "striped" stripe_count = 1 stripes = ["pv0", 0] } }
pool_tdata { id = "tdata-id" status = ["READ", "WRITE"] segment_count = 1
segment1 { start_extent = 0 extent_count = 2 type = "striped" stripe_count = 1 stripes = ["pv0", 1] } }
}
}
"#;
    let mut a = vec![0u8; (1 << 20) + 3 * ext];
    pv(&mut a, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", text);
    // the thin LV's 64 KiB blocks: zero ones unmapped, the others at data block 127 - n
    let mut maps = Vec::new();
    let data = (1 << 20) + ext;
    for (n, chunk) in fsimg.chunks(bs).enumerate() {
        if chunk.iter().all(|b| *b == 0) {
            continue;
        }
        let db = 127 - n;
        a[data + db * bs..data + db * bs + chunk.len()].copy_from_slice(chunk);
        maps.push((n as u64, db as u64));
    }
    assert!(maps.len() > 2 && maps.len() < 128, "{} blocks mapped", maps.len());
    let meta = thin_metadata(&maps, 128);
    a[1 << 20..(1 << 20) + meta.len()].copy_from_slice(&meta);
    let pa = d.path().join("a.img");
    fs::write(&pa, &a).unwrap();
    let l = list(&[&pa]);
    let v = vol(&l, "lvm/vg0-thin1");
    assert_eq!(
        (v.volume.fs.as_str(), v.volume.state.as_str()),
        ("ext4", "indexed"),
        "{:?}",
        v.volume
    );
    assert_eq!(got(v, &["lost+found"]), expect);
    let mut vols: Vec<Volume> = l.iter().map(|x| x.volume.clone()).collect();
    fsindex::mapping::assign(&mut vols);
    let m = fsindex::mapping::Mapper::new(&vols);
    assert_eq!(m.guest("lvm/vg0-thin1/etc/fstab"), "/etc/fstab");
    let pool = vol(&l, "lvm/vg0-pool");
    assert_eq!(
        (pool.volume.state.as_str(), pool.volume.fs.as_str()),
        ("skipped", "thin-pool")
    );
    let gone = vol(&l, "lvm/vg0-gone");
    assert_eq!(gone.volume.state, "unsupported");
    assert!(gone
        .volume
        .reason
        .as_deref()
        .unwrap()
        .contains("thin device 2 not in the pool metadata"));
    // a damaged metadata node: the thin LV is reported, nothing else breaks
    a[(1 << 20) + 3 * 4096 + 40] ^= 1;
    fs::write(&pa, &a).unwrap();
    let l = list(&[&pa]);
    let v = vol(&l, "lvm/vg0-thin1");
    assert_eq!(v.volume.state, "unsupported", "{:?}", v.volume);
    assert!(
        v.volume.reason.as_deref().unwrap().contains("damaged"),
        "{:?}",
        v.volume
    );
}

/// Phase 31c: btrfs through the own parser (mkfs.btrfs --rootdir, no root): the
/// top-level subvolume with nested subvolumes (listed as directories with their
/// contents), a default subvolume (listed alone, as the micro-VM mounts it),
/// 4 KiB nodes, zstd-compressed files (sizes are logical).
#[test]
fn btrfs_subvolumes() {
    let d = tempfile::tempdir().unwrap();
    let tree = d.path().join("tree");
    let uuid = "0b7e5c1d-2222-4333-8444-555566667777";
    let mut expect = sample(&tree, &format!("UUID={uuid} / btrfs defaults 0 0\n"));
    fs::create_dir_all(tree.join("srv/data/inner")).unwrap();
    for i in 0..300 {
        fs::write(tree.join(format!("srv/data/f{i:03}.txt")), format!("{i}")).unwrap();
        expect.push((format!("srv/data/f{i:03}.txt"), 0, format!("{i}").len() as u64));
    }
    fs::write(tree.join("srv/data/inner/x.bin"), vec![3u8; 70_000]).unwrap();
    std::os::unix::fs::symlink("../etc/fstab", tree.join("srv/link")).unwrap();
    expect.extend([
        ("srv".into(), 1, 0),
        ("srv/data".into(), 1, 0),
        ("srv/data/inner".into(), 1, 0),
        ("srv/data/inner/x.bin".into(), 0, 70_000),
        ("srv/link".into(), 2, 0),
    ]);
    expect.sort();
    let home: Vec<(String, u8, u64)> = expect
        .iter()
        .filter_map(|(p, k, n)| Some((p.strip_prefix("home/")?.to_owned(), *k, *n)))
        .collect();
    let mut ran = 0;
    for (name, args, want) in [
        (
            "subvolumes",
            vec!["-u", "rw:srv/data", "-u", "rw:srv/data/inner"],
            &expect,
        ),
        ("default", vec!["-u", "default:home", "-n", "4096"], &home),
        ("zstd", vec!["--compress", "zstd", "-u", "rw:srv"], &expect),
    ] {
        let img = d.path().join(format!("{name}.img"));
        sized(&img, 256 << 20);
        let mut a = vec!["-q", "-L", "pool", "-U", uuid, "-r", tree.to_str().unwrap()];
        a.extend(&args);
        a.push(img.to_str().unwrap());
        if !run("mkfs.btrfs", &a) {
            continue;
        }
        ran += 1;
        let l = list(&[&img]);
        let v = vol(&l, "vda");
        assert_eq!(
            (v.volume.fs.as_str(), v.volume.state.as_str()),
            ("btrfs", "indexed"),
            "{name}: {:?}",
            v.volume
        );
        assert_eq!(&got(v, &[]), want, "{name}");
        assert_eq!(v.volume.label.as_deref(), Some("pool"));
        assert_eq!(v.volume.uuid.as_deref(), Some(uuid));
        let mtime = v
            .entries
            .iter()
            .find(|e| e.path.ends_with("a.bin") || e.path == "etc/fstab");
        if let Some(e) = mtime {
            assert_eq!(e.mtime, MTIME, "{name}: {e:?}");
        }
        if name == "subvolumes" {
            let mut vols = vec![v.volume.clone()];
            fsindex::mapping::assign(&mut vols);
            assert_eq!(vols[0].mount.as_deref(), Some("/"), "root from its own fstab");
        }
    }
    if tool("mkfs.btrfs").is_some() {
        assert!(ran >= 1, "mkfs.btrfs ran");
    }
}

/// Phase 31c: Windows dynamic disks (LDM) on two MBR disks: a simple NTFS
/// volume (the system volume, whose SYSTEM hive names the dynamic volumes by
/// their GUIDs), an ext4 spanned over both disks, a striped and a RAID-5 volume
/// (reported). The database is written by the test (no tool builds one).
#[test]
fn ldm_simple_and_spanned_volumes() {
    use fsindex::ldm::build::{component, database, disk4, partition, privhead, volume};
    use fsindex::regf::{build, dmio};
    let d = tempfile::tempdir().unwrap();
    let p = |n: &str| d.path().join(n);
    let guid = |b: u8| -> [u8; 16] { [b; 16] };
    let text = |g: &[u8; 16]| {
        let h = fsindex::hex(g);
        format!(
            "{}-{}-{}-{}-{}",
            &h[0..8],
            &h[8..12],
            &h[12..16],
            &h[16..20],
            &h[20..32]
        )
    };
    let (ga, gb) = (guid(0xa1), guid(0xb2));
    let (g1, g2) = (guid(0x11), guid(0x22));
    // MountedDevices: DMIO:ID: + the volume GUID bytes
    let id = |g: &[u8; 16]| {
        let mut v = b"DMIO:ID:".to_vec();
        v.extend(g);
        v
    };
    let _ = dmio;
    let hive = build(&[(
        "MountedDevices",
        vec![("\\DosDevices\\C:", 3, id(&g1)), ("\\DosDevices\\D:", 3, id(&g2))],
    )]);
    let tree = p("tree");
    // (no etc/fstab: a volume with one would be taken for a Linux root)
    let mut expect = sample(&tree, "");
    fs::remove_file(tree.join("etc/fstab")).unwrap();
    expect.retain(|e| e.0 != "etc/fstab");
    // users' files: enough MFT records that taking the directories over saves reads
    let mut files: Vec<(String, Vec<u8>)> = vec![("Windows/System32/config/SYSTEM".into(), hive)];
    for u in ["ann", "bob", "eve"] {
        for i in 0..150 {
            files.push((format!("Users/{u}/Documents/{i:03}.txt"), b"x".to_vec()));
        }
    }
    let files: Vec<(&str, Vec<u8>)> = files.iter().map(|(n, d)| (n.as_str(), d.clone())).collect();
    if !ntfs_img(&p("sys.img"), 8 << 20, "System", &files)
        || !run(
            "mkfs.ext4",
            &[
                "-q",
                "-F",
                "-d",
                tree.to_str().unwrap(),
                p("ext.img").to_str().unwrap(),
                "8M",
            ],
        )
    {
        return;
    }
    let recs = vec![
        disk4(1, "Disk1", &ga),
        disk4(2, "Disk2", &gb),
        volume(10, "Volume1", "gen", 1, 16384, &g1),
        component(11, "Volume1-01", 2, 1, 10),
        partition(12, "Disk1-01", 1985, 0, 16384, 11, 1),
        volume(20, "Volume2", "gen", 1, 16384, &g2),
        component(21, "Volume2-01", 2, 2, 20),
        partition(22, "Disk1-02", 18369, 0, 2048, 21, 1),
        partition(23, "Disk2-01", 1985, 2048, 14336, 21, 2),
        volume(30, "Volume3", "gen", 1, 100, &guid(0x33)),
        component(31, "Volume3-01", 1, 2, 30),
        volume(40, "Volume4", "raid5", 1, 100, &guid(0x44)),
        component(41, "Volume4-01", 3, 3, 40),
    ];
    let db = database(&recs, 128, 2048);
    let disk = |sectors: usize, g: &[u8; 16]| {
        let mut b = vec![0u8; sectors * 512];
        b[446 + 4] = 0x42;
        b[446 + 8..446 + 12].copy_from_slice(&63u32.to_le_bytes());
        b[446 + 12..446 + 16].copy_from_slice(&(sectors as u32 - 63).to_le_bytes());
        b[510] = 0x55;
        b[511] = 0xaa;
        let cs = sectors - 2048;
        b[6 * 512..7 * 512].copy_from_slice(&privhead(&text(g), 63, cs as u64, 2048));
        b[cs * 512..].copy_from_slice(&db);
        b
    };
    let (mut a, mut b) = (disk(28672, &ga), disk(20480, &gb));
    let ntfs = fs::read(p("sys.img")).unwrap();
    let ext = fs::read(p("ext.img")).unwrap();
    a[2048 * 512..2048 * 512 + ntfs.len()].copy_from_slice(&ntfs);
    // the first MiB on the first disk, the rest (inode tables, directories) on the second
    a[18432 * 512..18432 * 512 + (1 << 20)].copy_from_slice(&ext[..1 << 20]);
    b[2048 * 512..2048 * 512 + (7 << 20)].copy_from_slice(&ext[1 << 20..]);
    let (pa, pb) = (p("a.img"), p("b.img"));
    fs::write(&pa, &a).unwrap();
    fs::write(&pb, &b).unwrap();

    let l = list(&[&pa, &pb]);
    let v1 = vol(&l, "ldm/Volume1");
    assert_eq!(
        (v1.volume.fs.as_str(), v1.volume.state.as_str()),
        ("ntfs", "indexed"),
        "{:?}",
        v1.volume
    );
    assert!(v1.volume.windows);
    let v2 = vol(&l, "ldm/Volume2");
    assert_eq!(
        (v2.volume.fs.as_str(), v2.volume.state.as_str()),
        ("ext4", "indexed"),
        "{:?}",
        v2.volume
    );
    assert_eq!(got(v2, &["lost+found"]), expect);
    assert!(v2.reads.iter().any(|r| r.0 == 0) && v2.reads.iter().any(|r| r.0 == 1));
    for (n, why) in [("ldm/Volume3", "striped"), ("ldm/Volume4", "RAID-5")] {
        let v = vol(&l, n);
        assert_eq!(v.volume.state, "unsupported");
        assert!(v.volume.reason.as_deref().unwrap().contains(why), "{:?}", v.volume);
    }
    // the LDM partitions themselves are containers, not reported
    assert!(l.iter().all(|x| !x.volume.browse.starts_with("vd")), "{l:?}");
    let mut vols: Vec<Volume> = l.iter().map(|x| x.volume.clone()).collect();
    fsindex::mapping::assign(&mut vols);
    let m = fsindex::mapping::Mapper::new(&vols);
    assert_eq!(m.guest("ldm/Volume1/Windows"), "C:/Windows");
    assert_eq!(m.guest("ldm/Volume2/var/lib"), "D:/var/lib");
    // the second disk missing: the spanned volume is reported, the simple one still listed
    let l = list(&[&pa]);
    assert_eq!(vol(&l, "ldm/Volume1").volume.state, "indexed");
    let v2 = vol(&l, "ldm/Volume2");
    assert_eq!(v2.volume.state, "unsupported");
    assert!(
        v2.volume.reason.as_deref().unwrap().contains("missing"),
        "{:?}",
        v2.volume
    );
}
