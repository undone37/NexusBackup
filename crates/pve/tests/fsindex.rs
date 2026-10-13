//! VM file index without the micro-VM (Phase 31a): a disk image in the chunk
//! store → sandboxed nexus-fsindex → sealed name index + volume report; the
//! next snapshot reuses unchanged volumes and re-parses changed ones.
//! Needs mkfs.ext4 and sgdisk (skips otherwise).

use chunkstore::{Keyring, NameIndex, Options, Store};
use fsindex::{Report, REPORT_FILE};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn tool(name: &str) -> Option<PathBuf> {
    ["/usr/sbin", "/sbin", "/usr/bin", "/bin"]
        .iter()
        .map(|d| Path::new(d).join(name))
        .find(|p| p.is_file())
}

/// target/<profile>/nexus-fsindex, built if the test run did not build it.
fn helper() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let dir = exe.parent().unwrap().parent().unwrap().to_path_buf();
    let bin = dir.join("nexus-fsindex");
    if !bin.is_file() {
        let release = dir.file_name().is_some_and(|n| n == "release");
        let mut c = Command::new(env!("CARGO"));
        c.args(["build", "-q", "-p", "fsindex", "--bin", "nexus-fsindex"]);
        if release {
            c.arg("--release");
        }
        assert!(c.status().unwrap().success(), "build nexus-fsindex");
    }
    bin
}

fn ext4(dir: &Path, files: &[(&str, &str)], uuid: &str, out: &Path) -> bool {
    let tree = dir.join(format!("tree-{}", out.file_name().unwrap().to_string_lossy()));
    for (p, c) in files {
        let p = tree.join(p);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, c).unwrap();
    }
    let Some(mkfs) = tool("mkfs.ext4") else { return false };
    // fixed hash seed + no lazy init: the same tree gives the same metadata bytes
    Command::new(mkfs)
        .args([
            "-q",
            "-F",
            "-U",
            uuid,
            "-E",
            "hash_seed=6d5c5e5d-0000-4000-8000-000000000001,lazy_itable_init=0",
        ])
        .arg("-d")
        .arg(&tree)
        .arg(out)
        .arg("16M")
        .env("E2FSPROGS_FAKE_TIME", "1700000000")
        .status()
        .is_ok_and(|s| s.success())
}

/// GPT disk: 1 = the root file system image (`root`, the same bytes for
/// every snapshot), 2 = a /home built from `home`.
fn disk(dir: &Path, name: &str, root: &Path, home: &[(&str, &str)]) -> Option<Vec<u8>> {
    let homei = dir.join(format!("{name}-home.img"));
    if !ext4(dir, home, "66666666-7777-4888-8999-000000000000", &homei) {
        return None;
    }
    let img = dir.join(format!("{name}.img"));
    fs::File::create(&img).unwrap().set_len(40 << 20).unwrap();
    let ok = Command::new(tool("sgdisk")?)
        .args([
            "-U",
            "12345678-0000-4000-8000-0000000000ab",
            "-n",
            "1:2048:+16M",
            "-n",
            "2:34816:+16M",
        ])
        .args([
            "-u",
            "1:aaaaaaaa-0000-4000-8000-000000000001",
            "-u",
            "2:aaaaaaaa-0000-4000-8000-000000000002",
        ])
        .arg(&img)
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        return None;
    }
    let mut d = fs::read(&img).unwrap();
    let r = fs::read(root).unwrap();
    let h = fs::read(&homei).unwrap();
    d[2048 * 512..2048 * 512 + r.len()].copy_from_slice(&r);
    d[34816 * 512..34816 * 512 + h.len()].copy_from_slice(&h);
    Some(d)
}

fn paths(n: &NameIndex) -> Vec<String> {
    let mut v: Vec<String> = n
        .iter()
        .map(|e| e.0.to_owned())
        .filter(|p| !p.contains("lost+found"))
        .collect();
    v.sort();
    v
}

#[test]
fn index_reuse_and_change() {
    let d = tempfile::tempdir().unwrap();
    let fstab = "UUID=11111111-2222-4333-8444-555555555555 / ext4 defaults 0 1\n\
                 UUID=66666666-7777-4888-8999-000000000000 /home ext4 defaults 0 2\n";
    let root = d.path().join("root.img");
    let built = ext4(
        d.path(),
        &[("etc/fstab", fstab), ("etc/hostname", "web1")],
        "11111111-2222-4333-8444-555555555555",
        &root,
    );
    let a = built
        .then(|| disk(d.path(), "a", &root, &[("ann/notes.txt", "v1"), ("bob/x.bin", "0123")]))
        .flatten();
    let Some(a) = a else {
        eprintln!("skip: mkfs.ext4 / sgdisk missing");
        return;
    };
    std::env::set_var("NEXUS_FSINDEX", helper());
    std::env::set_var("NEXUS_FSINDEX_NO_VM", "1");
    let s = Store::open(
        d.path().join("store"),
        Keyring::new("acme", &[(1, [9; 32])]),
        Options {
            min_lock_secs: 0,
            ..Options::default()
        },
    )
    .unwrap();
    let idx = s.store_image(&a[..], 4 << 20).unwrap();
    let m1 = s
        .commit_snapshot("vm-100", 1000, &[("drive-scsi0", idx.clone())])
        .unwrap();
    let r1 = pve::fsindex::index(&s, &m1, fsindex::Limits::default()).unwrap();
    assert_eq!(
        (r1["parsed"].as_u64(), r1["reused"].as_u64()),
        (Some(2), Some(0)),
        "{r1}"
    );
    let n1 = s.load_names(&m1).unwrap().unwrap();
    assert_eq!(
        paths(&n1),
        [
            "vda1",
            "vda1/etc",
            "vda1/etc/fstab",
            "vda1/etc/hostname",
            "vda2",
            "vda2/ann",
            "vda2/ann/notes.txt",
            "vda2/bob",
            "vda2/bob/x.bin"
        ]
    );
    let rep: Report = serde_json::from_slice(&s.read_snap_file("vm-100", 1000, REPORT_FILE).unwrap().unwrap()).unwrap();
    let mounts: Vec<_> = rep
        .volumes
        .iter()
        .map(|v| (v.volume.browse.as_str(), v.volume.mount.as_deref()))
        .collect();
    assert_eq!(mounts, [("vda1", Some("/")), ("vda2", Some("/home"))]);
    assert!(rep.volumes.iter().all(|v| !v.reads.is_empty()));
    // the job result names no labels / UUIDs / fstab contents
    let txt = r1.to_string();
    assert!(!txt.contains("11111111") && !txt.contains("fstab\":"), "{txt}");

    // the same disk again: both volumes reused, the same listing
    let m2 = s.commit_snapshot("vm-100", 2000, &[("drive-scsi0", idx)]).unwrap();
    let r2 = pve::fsindex::index(&s, &m2, fsindex::Limits::default()).unwrap();
    assert_eq!(
        (r2["parsed"].as_u64(), r2["reused"].as_u64()),
        (Some(0), Some(2)),
        "{r2}"
    );
    assert_eq!(paths(&s.load_names(&m2).unwrap().unwrap()), paths(&n1));

    // /home changed: only that volume is parsed again
    let Some(b) = disk(
        d.path(),
        "b",
        &root,
        &[
            ("ann/notes.txt", "v2 longer"),
            ("bob/x.bin", "0123"),
            ("bob/new.doc", "n"),
        ],
    ) else {
        return;
    };
    let idx = s.store_image(&b[..], 4 << 20).unwrap();
    let m3 = s.commit_snapshot("vm-100", 3000, &[("drive-scsi0", idx)]).unwrap();
    let r3 = pve::fsindex::index(&s, &m3, fsindex::Limits::default()).unwrap();
    assert_eq!(
        (r3["parsed"].as_u64(), r3["reused"].as_u64()),
        (Some(1), Some(1)),
        "{r3}"
    );
    let n3 = s.load_names(&m3).unwrap().unwrap();
    assert!(paths(&n3).contains(&"vda2/bob/new.doc".to_string()));
    let notes = n3.iter().find(|e| e.0 == "vda2/ann/notes.txt").unwrap();
    assert_eq!(notes.1, 9);
}
