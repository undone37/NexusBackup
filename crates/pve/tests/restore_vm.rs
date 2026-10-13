//! Restore micro-VM end to end: fixture disks (built by the micro-VM itself,
//! no root) → chunk store → NBD → micro-VM (read-only) → mounts/ls/tar/zip.
//! Needs `restore-vm/build.sh` output in target/restore-vm and /dev/kvm;
//! skips otherwise. Run: `cargo test --release -p pve --test restore_vm -- --nocapture`.

use chunkstore::{Index, Keyring, Options, Store};
use pve::files::Format;
use pve::restorevm::{self, Config, Disk, WorkDir};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Size of the large file: > 100 MiB, deliberately not chunk/sector aligned.
const BIG: u64 = (100 << 20) + 12345;
const FIXTURE_VERSION: &str = "v1";

fn target() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target")
}

/// Deterministic incompressible payload.
fn big_payload() -> Vec<u8> {
    let mut x = 0x2545_f491_4f6c_dd1du64;
    let mut v = Vec::with_capacity(BIG as usize);
    while (v.len() as u64) < BIG {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.truncate(BIG as usize);
    v
}

fn sha(d: &[u8]) -> String {
    format!("{:x}", Sha256::digest(d))
}

/// Builds disk0/disk1 by booting the micro-VM with the fixture overlay and
/// writable disks (restore-vm/fixture.sh). Cached under target/.
fn fixtures(cfg: &Config, big: &[u8]) -> PathBuf {
    let dir = target().join("restore-vm-fixtures").join(FIXTURE_VERSION);
    if dir.join("done").exists() {
        return dir;
    }
    fs::create_dir_all(&dir).unwrap();
    let mut seed = big.to_vec();
    seed.resize(seed.len().div_ceil(512) * 512, 0);
    fs::write(dir.join("seed.img"), seed).unwrap();
    for (n, size) in [("disk0.img", 1100u64 << 20), ("disk1.img", 256 << 20)] {
        let f = File::create(dir.join(n)).unwrap();
        f.set_len(size).unwrap();
    }
    // initramfs + overlay concatenated: the kernel unpacks both
    let mut initrd = fs::read(cfg.image_dir.join("initrd.img")).unwrap();
    initrd.extend(fs::read(cfg.image_dir.join("fixture-overlay.img")).unwrap());
    let w = WorkDir::new().unwrap();
    let initrd_p = w.0.join("initrd-fixture.img");
    fs::write(&initrd_p, initrd).unwrap();
    let (d0, d1, s) = (dir.join("disk0.img"), dir.join("disk1.img"), dir.join("seed.img"));
    let disks = [
        Disk::File {
            name: "fx0",
            path: &d0,
            writable: true,
        },
        Disk::File {
            name: "fx1",
            path: &d1,
            writable: true,
        },
        Disk::File {
            name: "seed",
            path: &s,
            writable: false,
        },
    ];
    let log = w.0.join("console.log");
    let agent = w.0.join("agent.sock");
    let _l = std::os::unix::net::UnixListener::bind(&agent).unwrap(); // QEMU connects here
    let t = Instant::now();
    let st = restorevm::qemu_command(
        cfg,
        &initrd_p,
        &disks,
        &agent,
        &log,
        &format!("nexus.fixture=1 nexus.bigsize={BIG}"),
    )
    .status()
    .unwrap();
    let out = fs::read_to_string(&log).unwrap_or_default();
    assert!(
        st.success() && out.contains("FIXTURE OK"),
        "fixture VM failed ({st}):\n{out}"
    );
    eprintln!("fixtures built in {:.1?}", t.elapsed());
    fs::remove_file(dir.join("seed.img")).unwrap();
    fs::write(dir.join("done"), "").unwrap();
    dir
}

fn store_image(s: &Store, p: &Path) -> Index {
    s.store_image(std::io::BufReader::new(File::open(p).unwrap()), 4 << 20)
        .unwrap()
}

fn tar_files(data: impl Read) -> Vec<(String, tar::EntryType, Vec<u8>, Option<String>)> {
    let mut a = tar::Archive::new(data);
    a.entries()
        .unwrap()
        .map(|e| {
            let mut e = e.unwrap();
            let p = e.path().unwrap().to_string_lossy().into_owned();
            let t = e.header().entry_type();
            let l = e.link_name().unwrap().map(|l| l.to_string_lossy().into_owned());
            let mut d = Vec::new();
            e.read_to_end(&mut d).unwrap();
            (p, t, d, l)
        })
        .collect()
}

#[test]
fn single_file_restore_from_disk_images() {
    let mut cfg = Config {
        image_dir: target().join("restore-vm"),
        ..Default::default()
    };
    cfg.boot_timeout = Duration::from_secs(60);
    let have = ["vmlinuz", "initrd.img", "fixture-overlay.img"]
        .iter()
        .all(|f| cfg.image_dir.join(f).is_file());
    if !have || !restorevm::kvm_usable() {
        eprintln!("restore VM image (restore-vm/build.sh) or /dev/kvm missing, skipping");
        return;
    }
    let big = big_payload();
    let big_sha = sha(&big);
    let fx = fixtures(&cfg, &big);

    let sd = tempfile::tempdir_in(target()).unwrap();
    let store = Store::open(sd.path(), Keyring::new("t", &[(1, [7; 32])]), Options::default()).unwrap();
    let t = Instant::now();
    let i0 = store_image(&store, &fx.join("disk0.img"));
    let i1 = store_image(&store, &fx.join("disk1.img"));
    eprintln!("fixture images stored in {:.1?}", t.elapsed());

    let t = Instant::now();
    restorevm::with_vm(&store, &[("drive-scsi0", &i0), ("drive-scsi1", &i1)], &cfg, |vm| {
        let mounts = vm.mounts()?;
        eprintln!("time to first mounts: {:.1?} (boot {:.1?})", t.elapsed(), vm.boot_time);
        eprintln!("console:\n{}", vm.console());
        let mp = |p: &str| mounts.iter().find(|m| m.mountpoint.as_deref() == Some(p));
        let expect = [
            ("/vda1", "ext4", "ext4"),
            ("/vda2", "xfs", "xfs"),
            ("/vda3", "ntfs", "ntfs"),
            ("/vda4", "btrfs", "btrfs"),
            ("/vda5", "vfat", "vfat"),
            ("/lvm/vgtest-data", "ext4", "lvm"),
            ("/zfs/tank+data", "zfs", "zfs"),
        ];
        for (p, ty, _) in expect {
            let m = mp(p).unwrap_or_else(|| panic!("{p} not mounted"));
            assert_eq!(m.fstype, ty);
        }
        assert_eq!(mp("/vda1").unwrap().label.as_deref(), Some("fx-ext4"));
        assert_eq!(mp("/vda1").unwrap().disk.as_deref(), Some("drive-scsi0"));
        assert!(mp("/zfs/tank").is_some());

        // listing: virtual root, unicode names, symlinks
        let root: Vec<String> = vm.ls("/")?.into_iter().map(|e| e.name).collect();
        assert!(root.contains(&"vda1".into()) && root.contains(&"lvm".into()) && root.contains(&"zfs".into()));
        for (p, _, name) in expect {
            let ls = vm.ls(p)?;
            let names: Vec<&str> = ls.iter().map(|e| e.name.as_str()).collect();
            assert!(names.contains(&"hello.txt") && names.contains(&"dir"), "{p}: {names:?}");
            let sub = vm.ls(&format!("{p}/dir/sub"))?;
            assert_eq!(sub[0].name, "ünïcödé ✓.txt", "{p}");
            assert_eq!(sub[0].size, 16);
            if name != "vfat" {
                let l = ls.iter().find(|e| e.name == "link-to-hello").expect("symlink");
                assert_eq!((l.kind.as_str(), l.link.as_deref()), ("symlink", Some("hello.txt")));
                // an absolute symlink resolves inside the guest file system, never the VM's
                assert!(vm.ls(&format!("{p}/abs-link")).is_err());
                let via: Vec<String> = vm.ls(&format!("{p}/rootlink"))?.into_iter().map(|e| e.name).collect();
                assert_eq!(via, names, "{p}: / symlink stays in the file system");
            }
            // single file via tar
            let mut t = vm.tar(&[format!("{p}/hello.txt")])?;
            let files = tar_files(&mut t);
            let sum = t.finish()?;
            assert_eq!(sum.entries, 1);
            assert!(sum.errors.is_empty(), "{:?}", sum.errors);
            assert_eq!(files[0].0, format!("{}/hello.txt", &p[1..]));
            assert_eq!(files[0].2, format!("hello from {name}\n").as_bytes());
        }
        for bad in ["/vda1/../vda2", "vda1", "/vda9", "/vda1/dir/../../x", "/vda1/a\0b"] {
            assert!(vm.ls(bad).is_err(), "{bad:?} accepted");
            assert!(vm.tar(&[bad.to_string()]).is_err(), "{bad:?} accepted for tar");
        }
        assert!(vm.ls("/vda1/hello.txt").is_err(), "ls of a file");

        // the name index walk (file search, groups.index_files): every file system,
        // paths as in the file browser; the entry cap stops it early
        let t = Instant::now();
        let (names, complete) = restorevm::index(vm, 1_000_000, Duration::from_secs(300))?;
        eprintln!("name index: {} entries in {:.1?}", names.len(), t.elapsed());
        assert!(complete);
        for (p, _, _) in expect {
            let want = format!("{}/dir/sub/ünïcödé ✓.txt", &p[1..]);
            assert!(names.iter().any(|e| e.0 == want && e.1 == 16), "{want} not indexed");
        }
        let (few, complete) = restorevm::index(vm, 3, Duration::from_secs(300))?;
        assert!(!complete && few.len() < 100);

        // large file as tar (ext4) and a whole dataset as zip (ZFS)
        let d = tempfile::tempdir_in(target())?;
        let tar_p = d.path().join("big.tar");
        let t = Instant::now();
        let (n, sum) = vm.extract(&["/vda1/big.bin".into()], Format::Tar, File::create(&tar_p)?)?;
        let secs = t.elapsed().as_secs_f64();
        eprintln!("get big.bin (tar): {:.1} MiB/s", BIG as f64 / secs / 1048576.0);
        assert_eq!((n, sum.entries), (1, 1));
        let files = tar_files(File::open(&tar_p)?);
        assert_eq!((files[0].0.as_str(), files[0].2.len() as u64), ("vda1/big.bin", BIG));
        assert_eq!(sha(&files[0].2), big_sha);

        let zip_p = d.path().join("data.zip");
        let t = Instant::now();
        let (n, _) = vm.extract(&["/zfs/tank+data".into()], Format::Zip, File::create(&zip_p)?)?;
        eprintln!("get tank/data (zip, deflate): {:.1?}", t.elapsed());
        assert!(n >= 8, "{n} entries");
        let mut f = File::open(&zip_p)?;
        f.rewind()?;
        let mut z = zip::ZipArchive::new(f)?;
        let mut buf = Vec::new();
        z.by_name("zfs/tank+data/big.bin")?.read_to_end(&mut buf)?;
        assert_eq!(sha(&buf), big_sha);
        let mut s = String::new();
        z.by_name("zfs/tank+data/dir/sub/ünïcödé ✓.txt")?
            .read_to_string(&mut s)?;
        assert_eq!(s, "unicode content\n");
        assert!(z.by_name("zfs/tank+data/link-to-hello")?.is_symlink());

        // several paths from different file systems in one tar
        let mut t = vm.tar(&["/vda2/dir".into(), "/lvm/vgtest-data/hello.txt".into()])?;
        let files = tar_files(&mut t);
        t.finish()?;
        let names: Vec<&str> = files.iter().map(|f| f.0.as_str()).collect();
        assert!(names.contains(&"vda2/dir/sub/ünïcödé ✓.txt") && names.contains(&"lvm/vgtest-data/hello.txt"));
        assert_eq!(files.iter().find(|f| f.0 == "vda2/dir/70k.txt").unwrap().2.len(), 70000);

        // YARA scan in the VM (Phase 21e): every file system, symlinks never followed
        // (`rootlink -> /` would reach the VM's own /etc/hostname), large files skipped
        assert!(vm
            .rules(&serde_json::json!([{"name": "bad.yar", "text": "rule {"}]))
            .is_err());
        vm.rules(&serde_json::json!([
            {"name": "a.yar", "text": "rule HelloXfs { strings: $a = \"hello from xfs\" condition: $a }"},
            {"name": "b.yar", "text": "rule Uni { strings: $a = \"unicode content\" condition: $a }\n\
                                       rule VmHost { strings: $a = \"nexus-restore-vm\" condition: $a }"}
        ]))?;
        let t = Instant::now();
        let r = vm.scan(&pve::scan::limits(600, 2), Duration::from_secs(900))?;
        eprintln!("yara scan: {r} in {:.1?}", t.elapsed());
        let m: Vec<(String, String)> = r["matches"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| (m["rule"].as_str().unwrap().into(), m["path"].as_str().unwrap().into()))
            .collect();
        assert!(
            m.contains(&("a.yar:HelloXfs".into(), "/vda2/hello.txt".into())),
            "{m:?}"
        );
        for (p, _, _) in expect {
            assert!(
                m.contains(&("b.yar:Uni".into(), format!("{p}/dir/sub/ünïcödé ✓.txt"))),
                "{p}: {m:?}"
            );
        }
        assert!(!m.iter().any(|x| x.0.contains("VmHost")), "followed a symlink: {m:?}");
        assert!(r["skipped"].as_u64().unwrap() >= 2, "big.bin is over the size limit");
        assert_eq!(r["complete"], true);
        Ok(())
    })
    .unwrap();

    // file-tree snapshots: a tar from the store streamed into a VM without disks
    let (data, n) = store.store_file(&b"padding X5O-TEST-SIGNATURE padding"[..]).unwrap();
    let tree = Index::Tree {
        entries: vec![chunkstore::TreeEntry {
            path: b"home/u/report.docx".to_vec(),
            kind: chunkstore::TreeKind::File,
            mode: 0o644,
            uid: 0,
            gid: 0,
            size: n,
            mtime_ns: 0,
            ctime_ns: 0,
            inode: 1,
            rdev: 0,
            link_target: None,
            xattrs: vec![],
            chunks: data,
            inconsistent: false,
        }],
    };
    let m = store.commit_snapshot("host-a", 5, &[("files", tree)]).unwrap();
    let r = restorevm::with_vm(&store, &[], &cfg, |vm| {
        vm.rules(
            &serde_json::json!([{"name": "t.yar", "text": "rule Sig { strings: $a = \"X5O-TEST\" condition: $a }"}]),
        )?;
        vm.scan_tar(&pve::scan::limits(600, 1), Duration::from_secs(900), |w| {
            pve::scan::tree_tar(&store, &m, pve::scan::MAX_SIZE, w)?;
            Ok(())
        })
    })
    .unwrap();
    eprintln!("yara tree scan: {r}");
    assert_eq!(r["files"], 1);
    assert_eq!(r["matches"][0]["rule"], "t.yar:Sig");
    assert_eq!(r["matches"][0]["path"], "home/u/report.docx");
    let _ = std::io::stderr().flush();
}

/// Phase 31a: the sandboxed parser lists the same entries as the micro-VM walk
/// for every file system it reads (ext4, NTFS, FAT, ext4 on LVM); XFS, btrfs
/// and ZFS are reported as unsupported. Directory sizes and times differ by
/// design (the kernel reports block sizes; not compared).
/// Needs the micro-VM image, its fixtures, /dev/kvm and a built nexus-fsindex:
/// `cargo build --release -p fsindex && cargo test --release -p pve --test restore_vm fsindex_matches -- --ignored --nocapture`
#[test]
#[ignore]
fn fsindex_matches_micro_vm_listing() {
    let cfg = Config {
        image_dir: target().join("restore-vm"),
        boot_timeout: Duration::from_secs(60),
        ..Default::default()
    };
    if !cfg.image_dir.join("vmlinuz").is_file() || !restorevm::kvm_usable() {
        eprintln!("restore VM image or /dev/kvm missing, skipping");
        return;
    }
    let fx = fixtures(&cfg, &big_payload());
    let sd = tempfile::tempdir_in(target()).unwrap();
    let store = Store::open(sd.path(), Keyring::new("t", &[(1, [7; 32])]), Options::default()).unwrap();
    let i0 = store_image(&store, &fx.join("disk0.img"));
    let i1 = store_image(&store, &fx.join("disk1.img"));
    let m = store
        .commit_snapshot("vm-300", 7, &[("drive-scsi0", i0.clone()), ("drive-scsi1", i1.clone())])
        .unwrap();
    let t = Instant::now();
    let (vm_names, complete) = restorevm::with_vm(&store, &[("drive-scsi0", &i0), ("drive-scsi1", &i1)], &cfg, |vm| {
        restorevm::index(vm, 1_000_000, Duration::from_secs(600))
    })
    .unwrap();
    assert!(complete);
    let vm_secs = t.elapsed();
    let exe = std::env::current_exe().unwrap();
    let helper = exe.parent().unwrap().parent().unwrap().join("nexus-fsindex");
    assert!(helper.is_file(), "build nexus-fsindex first (cargo build -p fsindex)");
    std::env::set_var("NEXUS_FSINDEX", &helper);
    std::env::set_var("NEXUS_FSINDEX_NO_VM", "1");
    let t = Instant::now();
    let r = pve::fsindex::index(&store, &m, fsindex::Limits::default()).unwrap();
    eprintln!("micro-VM walk {vm_secs:.1?}, nexus-fsindex {:.1?}: {r}", t.elapsed());
    let ours = store.load_names(&m).unwrap().unwrap();
    type Set = std::collections::BTreeSet<(String, u8, u64, i64)>;
    let set = |n: &chunkstore::NameIndex, root: &str| -> Set {
        n.iter()
            .filter(|e| e.0.starts_with(&format!("{root}/")))
            .map(|(p, s, t, k)| (p.to_owned(), k, if k == 0 { s } else { 0 }, if k == 0 { t } else { 0 }))
            .collect()
    };
    for root in ["vda1", "vda3", "vda5", "lvm/vgtest-data"] {
        let (a, b) = (set(&vm_names, root), set(&ours, root));
        assert!(!a.is_empty(), "{root}: micro-VM listed nothing");
        assert_eq!(a, b, "{root}: micro-VM vs nexus-fsindex");
    }
    let states: Vec<(String, String)> = r["volumes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| (v["browse"].as_str().unwrap().into(), v["state"].as_str().unwrap().into()))
        .collect();
    for b in ["vda2", "vda4", "vdb1"] {
        assert!(states.contains(&(b.into(), "unsupported".into())), "{b}: {states:?}");
    }

    // the next snapshot: unchanged volumes reused, XFS / btrfs / ZFS through the micro-VM
    std::env::remove_var("NEXUS_FSINDEX_NO_VM");
    std::env::set_var("NEXUS_RESTORE_VM_DIR", &cfg.image_dir);
    let m2 = store
        .commit_snapshot("vm-300", 8, &[("drive-scsi0", i0.clone()), ("drive-scsi1", i1.clone())])
        .unwrap();
    let t = Instant::now();
    let r = pve::fsindex::index(&store, &m2, fsindex::Limits::default()).unwrap();
    eprintln!("second snapshot with the micro-VM fallback {:.1?}: {r}", t.elapsed());
    assert_eq!((r["reused"].as_u64(), r["micro_vm"].as_bool()), (Some(4), Some(true)), "{r}");
    let ours = store.load_names(&m2).unwrap().unwrap();
    for root in ["vda1", "vda2", "vda3", "vda4", "vda5", "lvm/vgtest-data", "zfs"] {
        assert_eq!(set(&vm_names, root), set(&ours, root), "{root}: micro-VM vs nexus-fsindex + fallback");
    }
}
