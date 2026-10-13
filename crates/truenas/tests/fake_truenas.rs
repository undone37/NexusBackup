//! The connector against the in-process TrueNAS fake (tests/support):
//! exercises the whole backup path: full read, incremental with
//! renames/deletes/new hard links, rotation, lost reference, hostile paths
//! against the forced command, downloads.

mod support;

use agent_conn::files::{self, Format};
use chunkstore::{Keyring, Options, Store, TreeEntry, TreeKind};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use support::*;
use truenas::api::Nas;
use truenas::backup::{backup, Spec};
use truenas::remote::Transport;

const SID: u64 = 7;

struct Lab {
    _td: tempfile::TempDir,
    nas: FakeNas,
    store: Store,
    t: LocalFc,
    data: PathBuf,
}

fn lab() -> Lab {
    let td = tempfile::tempdir().unwrap();
    let (nas, t, data) = fake(td.path());
    let store = Store::open(
        td.path().join("store"),
        Keyring::new("acme", &[(1, [3; 32])]),
        Options::default(),
    )
    .unwrap();
    Lab {
        _td: td,
        nas,
        store,
        t,
        data,
    }
}

fn tree(store: &Store, source: &str, time: u64) -> Vec<TreeEntry> {
    support::tree(store, source, time, "tree")
}

fn spec() -> Spec {
    Spec {
        source_id: SID,
        datasets: vec!["tank/data".into()],
        recursive: true,
        existing: None,
        pace: None,
        full_read: false,
    }
}

#[test]
fn backup_incremental_rotation_and_download() {
    let mut l = lab();
    let d = l.data.clone();
    put(&d.join("docs/readme.txt"), b"hello truenas\n");
    put(&d.join("docs/sp ace"), b"space\n");
    put(&d.join("docs/new\nline"), b"newline\n");
    put(&d.join("docs/Grüße\\back"), b"utf8 + backslash\n");
    put(&d.join("docs/-dash"), b"dash\n");
    put(&d.join("big/random.bin"), &pseudo_random(3 << 20, 1));
    put(&d.join("many/f1"), b"1");
    put(&d.join("many/f2"), b"2");
    put(&d.join("hl/a"), b"linked\n");
    fs::hard_link(d.join("hl/a"), d.join("hl/b")).unwrap();
    fs::create_dir_all(d.join("links")).unwrap();
    std::os::unix::fs::symlink("/", d.join("links/root")).unwrap();
    std::os::unix::fs::symlink("../docs/readme.txt", d.join("links/rel")).unwrap();
    fs::set_permissions(d.join("docs/-dash"), fs::Permissions::from_mode(0o4750)).unwrap();
    let xattrs = xattr_set(&d.join("docs/readme.txt"), "user.nexus", b"v1");
    put(&d.join("child/c.txt"), b"child dataset\n");
    // snapshots that are not ours: never touched
    l.nas.create_snapshot("tank/data", "auto-2026-01-01", true).unwrap();
    l.nas.create_snapshot("tank/data", "nexus-8-100", false).unwrap();

    let mut log = Vec::new();
    let r1 = backup(&l.store, &mut l.nas, &l.t, &spec(), &mut |s| log.push(s.to_owned())).unwrap();
    assert!(r1.failed.is_empty(), "{:?} {log:?}", r1.failed);
    assert_eq!(r1.committed.len(), 2, "{log:?}");
    let c1 = &r1.committed[0];
    assert!(c1.full && c1.source == "nas-7-tank.data");
    assert_eq!(r1.committed[1].source, "nas-7-tank.data.child");
    let t1 = tree(&l.store, "nas-7-tank.data", r1.time);
    assert_matches(&l.store, &t1, &d);
    if xattrs {
        assert!(t1
            .iter()
            .any(|e| e.xattrs.iter().any(|(k, v)| k == b"user.nexus" && v == b"v1")));
    }
    // the child's mount point is an empty directory in the parent's snapshot
    assert!(t1.iter().any(|e| e.path == b"child" && e.kind == TreeKind::Dir));
    assert!(!t1.iter().any(|e| e.path.starts_with(b"child/")));
    assert_matches(
        &l.store,
        &tree(&l.store, "nas-7-tank.data.child", r1.time),
        &d.join("child"),
    );
    let snap1 = format!("nexus-7-{}", r1.time);
    assert_eq!(l.nas.snaps["tank/data"], vec!["auto-2026-01-01", "nexus-8-100", &snap1]);

    // round 2: in-place edit (new object), rename file + directory, delete, new file, new hard link
    put(&d.join("docs/readme.txt"), b"hello truenas, changed\n");
    fs::rename(d.join("docs/sp ace"), d.join("docs/space-renamed")).unwrap();
    fs::rename(d.join("many"), d.join("renamed-many")).unwrap();
    fs::remove_file(d.join("docs/-dash")).unwrap();
    put(&d.join("docs/new.txt"), b"brand new\n");
    fs::hard_link(d.join("docs/new.txt"), d.join("hl/new-link")).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100)); // next snapshot time
    let r2 = backup(&l.store, &mut l.nas, &l.t, &spec(), &mut |s| log.push(s.to_owned())).unwrap();
    assert!(r2.failed.is_empty(), "{:?}", r2.failed);
    let c2 = &r2.committed[0];
    assert!(!c2.full);
    // only readme.txt and new.txt have new content; the 3 MiB file is reused
    // readme.txt and new.txt (new objects), space-renamed (R: a rename may hide a modification)
    assert_eq!(c2.files_read, 3, "{log:?}");
    assert!(c2.reused_files >= 6, "{c2:?}");
    assert!(c2.bytes_read < 100);
    assert!(c2.transferred_bytes < 64 << 10, "{c2:?}");
    let t2 = tree(&l.store, "nas-7-tank.data", r2.time);
    assert_matches(&l.store, &t2, &d);
    let big1 = t1.iter().find(|e| e.path == b"big/random.bin").unwrap();
    let big2 = t2.iter().find(|e| e.path == b"big/random.bin").unwrap();
    assert!(big1.chunks.len() > 1 && big1.chunks == big2.chunks);
    let f1 = t2.iter().find(|e| e.path == b"renamed-many/f1").unwrap();
    assert_eq!(f1.chunks, t1.iter().find(|e| e.path == b"many/f1").unwrap().chunks);
    // rotation: our previous snapshot is gone, foreign ones stay
    let snap2 = format!("nexus-7-{}", r2.time);
    assert_eq!(l.nas.snaps["tank/data"], vec!["auto-2026-01-01", "nexus-8-100", &snap2]);
    assert_eq!(
        l.nas.snaps["tank/data/child"],
        vec!["auto-2026-01-01".to_owned(), snap2.clone()]
    );
    assert!(r2.deleted_snapshots.contains(&format!("tank/data@{snap1}")));

    // lost reference (deleted on TrueNAS): full read, still correct
    l.nas.delete_snapshot("tank/data", &snap2).unwrap();
    put(&d.join("docs/after.txt"), b"after\n");
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let r3 = backup(&l.store, &mut l.nas, &l.t, &spec(), &mut |s| log.push(s.to_owned())).unwrap();
    assert!(r3.committed[0].full && !r3.committed[1].full);
    assert_matches(&l.store, &tree(&l.store, "nas-7-tank.data", r3.time), &d);
    assert!(log
        .iter()
        .any(|s| s.contains("reference snapshot") && s.contains("is gone")));

    // downloads from the snapshot (agent-conn's tar/zip code)
    let out = l._td.path().join("dl.tar");
    let n = files::extract(
        &l.store,
        &t2,
        &["/docs".into(), "/hl".into()],
        Format::Tar,
        fs::File::create_new(&out).unwrap(),
    )
    .unwrap();
    assert!(n >= 7);
    let mut ar = tar::Archive::new(fs::File::open(&out).unwrap());
    let mut names = Vec::new();
    for e in ar.entries().unwrap() {
        let mut e = e.unwrap();
        let name = e.path_bytes().to_vec();
        if name == b"docs/readme.txt" {
            let mut s = String::new();
            e.read_to_string(&mut s).unwrap();
            assert_eq!(s, "hello truenas, changed\n");
        }
        names.push(name);
    }
    assert!(names.iter().any(|n| n == b"docs/new\nline") && names.iter().any(|n| n == b"hl/new-link"));
    let z = l._td.path().join("dl.zip");
    files::extract(
        &l.store,
        &t2,
        &["/big".into()],
        Format::Zip,
        fs::File::create_new(&z).unwrap(),
    )
    .unwrap();
}

/// Runs one forced-command request; (exit ok, stdout, stderr).
fn fc_run(t: &LocalFc, cmd: &str, stdin: &[u8]) -> (bool, Vec<u8>, String) {
    let mut c = t
        .command(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(stdin).unwrap();
    let o = c.wait_with_output().unwrap();
    (
        o.status.success(),
        o.stdout,
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

#[test]
fn forced_command_refuses_hostile_requests() {
    let mut l = lab();
    let d = l.data.clone();
    put(&d.join("docs/a"), b"a");
    fs::create_dir_all(d.join("links")).unwrap();
    std::os::unix::fs::symlink("/", d.join("links/root")).unwrap();
    std::os::unix::fs::symlink("/etc/hostname", d.join("links/host")).unwrap();
    l.nas.create_snapshot("tank/data", "nexus-7-5", true).unwrap();
    let ok = fc_run(&l.t, "read tank/data nexus-7-5", b"docs/a\0docs\0");
    assert!(ok.0, "{}", ok.2);
    assert!(fc_run(&l.t, "hello", b"").1.starts_with(b"nexus-fc 1"));
    let w = fc_run(&l.t, "walk tank/data/child nexus-7-5", b"");
    assert!(w.0, "{}", w.2);
    for (cmd, stdin) in [
        ("read tank/data nexus-7-5", &b"links/root/etc/hostname\0"[..]), // through a symlink to /
        ("read tank/data nexus-7-5", b"links/host\0"),                   // a symlink: canonical form differs
        ("read tank/data nexus-7-5", b"../../../../etc/hostname\0"),
        ("read tank/data nexus-7-5", b"docs/../docs/a\0"),
        ("read tank/data nexus-7-5", b"/etc/hostname\0"),
        ("read tank/data nexus-7-5", b"docs//a\0"),
        ("read tank/data nexus-7-5", b"docs/a/\0"),
        ("read tank/data nexus-7-5", b"\0"),
        ("read tank/data nexus-7-5", b""),
        ("read tank/data nexus-7-5", b"docs/missing\0"),
        ("walk tank/smb nexus-7-5", b""),      // not configured
        ("walk tank nexus-7-5", b""),          // parent of a root
        ("walk tank/database nexus-7-5", b""), // prefix trick
        ("walk tank/data nexus-7-5;id", b""),  // injection
        ("walk tank/data $(id)", b""),
        ("walk tank/data nexus-7-05", b""),
        ("walk tank/data ../../x", b""),
        ("walk tank/data/../smb nexus-7-5", b""),
        ("walk tank/data nexus-7-5 extra", b""),
        ("walk tank/data nexus-7-5\nid", b""),
        ("diff tank/data nexus-7-5", b""),
        ("diff tank/data nexus-7-5 x@y", b""),
        ("rm -rf /", b""),
        ("", b""),
        ("read", b""),
    ] {
        let (st, out, err) = fc_run(&l.t, cmd, stdin);
        assert!(!st, "{cmd:?} {stdin:?} was accepted");
        assert!(
            !out.windows(8).any(|w| w == b"localhost") && out.len() < 1024,
            "{cmd:?}: leaked {out:?}"
        );
        assert!(err.contains("nexus-fc"), "{cmd:?}: {err}");
    }
}

/// Hostile walk output: the dataset fails, its new snapshot is deleted, the reference stays.
#[test]
fn hostile_walk_fails_dataset_and_keeps_reference() {
    let mut l = lab();
    put(&l.data.join("a"), b"a");
    let r1 = backup(&l.store, &mut l.nas, &l.t, &spec(), &mut |_| {}).unwrap();
    assert!(r1.failed.is_empty());
    struct Evil(LocalFc);
    impl Transport for Evil {
        fn command(&self, cmd: &str) -> Command {
            if cmd.starts_with("walk tank/data ") {
                let mut c = Command::new("printf");
                c.arg("f 644 0 0 1 1.0 1.0 5 1\\0../../etc/shadow\\0\\0");
                c
            } else {
                self.0.command(cmd)
            }
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let evil = Evil(LocalFc {
        command: l.t.command.clone(),
    });
    let r2 = backup(&l.store, &mut l.nas, &evil, &spec(), &mut |_| {}).unwrap();
    assert_eq!(r2.failed.len(), 1);
    assert!(r2.failed[0].1.contains("invalid"), "{:?}", r2.failed);
    // tank/data: still only the first snapshot; the child succeeded and rotated
    assert_eq!(l.nas.snaps["tank/data"], vec![format!("nexus-7-{}", r1.time)]);
    assert_eq!(l.nas.snaps["tank/data/child"], vec![format!("nexus-7-{}", r2.time)]);
    assert!(l.store.load_manifest("nas-7-tank.data", r2.time).is_err());
}

/// "Use existing snapshots" (Phase 22b): the newest `auto-*` snapshot is read,
/// nothing is created or deleted, the next run diffs against the snapshot the
/// last backup came from; no new periodic snapshot = skipped, not failed.
#[test]
fn existing_snapshots_mode() {
    use std::collections::HashMap;
    use truenas::backup::Existing;
    let mut l = lab();
    put(&l.data.join("docs/a.txt"), b"first\n");
    put(&l.data.join("big.bin"), &pseudo_random(1 << 20, 3));
    let ex = |refs: HashMap<String, (u64, String)>| Spec {
        datasets: vec!["tank/data".into()],
        recursive: false,
        existing: Some(Existing {
            prefix: "auto-".into(),
            references: refs,
        }),
        ..spec()
    };
    // no periodic snapshot yet: the dataset fails with a hint
    let r0 = backup(&l.store, &mut l.nas, &l.t, &ex(HashMap::new()), &mut |_| {}).unwrap();
    assert!(r0.failed[0].1.contains("periodic snapshot task"), "{:?}", r0.failed);

    l.nas
        .create_snapshot("tank/data", "auto-2026-10-12_00-00", false)
        .unwrap();
    put(&l.data.join("docs/b.txt"), b"after the first periodic snapshot\n");
    l.nas
        .create_snapshot("tank/data", "auto-2026-10-13_00-00", false)
        .unwrap();
    put(&l.data.join("docs/live.txt"), b"not in any snapshot\n");
    let mut log = Vec::new();
    let r1 = backup(&l.store, &mut l.nas, &l.t, &ex(HashMap::new()), &mut |s| {
        log.push(s.to_owned())
    })
    .unwrap();
    assert!(r1.failed.is_empty(), "{:?} {log:?}", r1.failed);
    let c1 = &r1.committed[0];
    assert!(c1.full);
    assert_eq!(c1.snapshot, "auto-2026-10-13_00-00", "the newest one");
    let t1 = tree(&l.store, "nas-7-tank.data", r1.time);
    assert!(t1.iter().any(|e| e.path == b"docs/b.txt"));
    assert!(
        !t1.iter().any(|e| e.path == b"docs/live.txt"),
        "read from the snapshot, not live"
    );
    assert_eq!(
        l.nas.snaps["tank/data"],
        vec!["auto-2026-10-12_00-00", "auto-2026-10-13_00-00"],
        "nothing created or deleted"
    );
    let refs = HashMap::from([(
        "nas-7-tank.data".to_string(),
        (r1.time, "auto-2026-10-13_00-00".to_string()),
    )]);
    // same newest snapshot again: skipped
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let r2 = backup(&l.store, &mut l.nas, &l.t, &ex(refs.clone()), &mut |_| {}).unwrap();
    assert!(r2.failed.is_empty() && r2.committed.is_empty());
    assert!(r2.skipped[0].1.contains("no new snapshot"), "{:?}", r2.skipped);
    // a new periodic snapshot: incremental via zfs diff against the recorded one
    l.nas
        .create_snapshot("tank/data", "auto-2026-10-14_00-00", false)
        .unwrap();
    let r3 = backup(&l.store, &mut l.nas, &l.t, &ex(refs), &mut |_| {}).unwrap();
    let c3 = &r3.committed[0];
    assert!(!c3.full && c3.snapshot == "auto-2026-10-14_00-00", "{c3:?}");
    assert_eq!(c3.files_read, 1, "only live.txt is new: {c3:?}");
    let t3 = tree(&l.store, "nas-7-tank.data", r3.time);
    let big = |t: &[TreeEntry]| t.iter().find(|e| e.path == b"big.bin").unwrap().chunks.clone();
    assert_eq!(big(&t1), big(&t3), "unchanged file reused");
    // a reference recorded for an older store snapshot is not trusted: full read
    std::thread::sleep(std::time::Duration::from_millis(1100));
    l.nas
        .create_snapshot("tank/data", "auto-2026-10-15_00-00", false)
        .unwrap();
    let stale = HashMap::from([(
        "nas-7-tank.data".to_string(),
        (r1.time, "auto-2026-10-13_00-00".to_string()),
    )]);
    let r4 = backup(&l.store, &mut l.nas, &l.t, &ex(stale), &mut |_| {}).unwrap();
    assert!(r4.committed[0].full);
}

/// Phase 29: a full read reads every file and finds the in-place change zfs diff
/// (the fake reports no `M` for an edit of the same object) and the size/mtime
/// check missed.
#[test]
fn full_read_finds_what_zfs_diff_missed() {
    let mut l = lab();
    let d = l.data.clone();
    put(&d.join("docs/a.txt"), b"first\n");
    put(&d.join("docs/b.txt"), b"other\n");
    put(&d.join("big.bin"), &pseudo_random(1 << 20, 5));
    let spec = || Spec {
        recursive: false,
        ..spec()
    };
    let r1 = backup(&l.store, &mut l.nas, &l.t, &spec(), &mut |_| {}).unwrap();
    assert!(r1.committed[0].full_read.is_none());
    // same object, same size and mtime, other content
    let p = d.join("docs/a.txt");
    let mtime = fs::metadata(&p).unwrap().modified().unwrap();
    let mut f = fs::OpenOptions::new().write(true).open(&p).unwrap();
    f.write_all(b"FIRST\n").unwrap();
    f.set_modified(mtime).unwrap();
    drop(f);
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let mut log = Vec::new();
    let full = Spec {
        full_read: true,
        ..spec()
    };
    let r2 = backup(&l.store, &mut l.nas, &l.t, &full, &mut |s| log.push(s.to_owned())).unwrap();
    let c2 = &r2.committed[0];
    assert!(!c2.full && c2.reused_files == 0, "{c2:?}");
    assert_matches(&l.store, &tree(&l.store, "nas-7-tank.data", r2.time), &d);
    let x = c2.full_read.as_ref().unwrap();
    assert_eq!((x.tracker.as_str(), x.baseline), ("zfs-diff", Some(r1.time)));
    assert_eq!((x.compared, x.changed, x.unreported, x.unreported_bytes), (3, 1, 1, 6));
    assert_eq!(x.examples, ["docs/a.txt"]);
    let want = format!("full-read nas-7-tank.data/{} {{\"tracker\":\"zfs-diff\"", r2.time);
    assert!(log.iter().any(|s| s.starts_with(&want)), "{log:?}");
}
