//! The connector against a local directory as the "mounted share" (no root):
//! parallel scan determinism, metadata-cache reuse, change detection (ctime),
//! inconsistent files, hard links, excludes, NAS snapshot selection, downloads.

use agent_conn::files::{self, Format};
use chunkstore::{Index, Keyring, Options, Store, TreeEntry, TreeKind};
use nas::backup::{self, Snap, Spec};
use nas::mount::{self, Order};
use nas::scan;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn store(dir: &Path) -> Store {
    Store::open(dir, Keyring::new("t", &[(1, [9; 32])]), Options::default()).unwrap()
}

fn setxattr(p: &Path, n: &str, v: &[u8]) -> bool {
    let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
    let n = std::ffi::CString::new(n).unwrap();
    unsafe { libc::lsetxattr(c.as_ptr(), n.as_ptr(), v.as_ptr().cast(), v.len(), 0) == 0 }
}

/// A share-like tree: nested dirs, a big directory, odd names, symlinks, hard
/// links, a fifo, xattrs, and a `.snapshot` dir that must not be backed up.
fn tree(root: &Path) {
    fs::create_dir_all(root.join("docs/deep/a/b/c")).unwrap();
    fs::write(root.join("docs/README.txt"), "hello share\n").unwrap();
    fs::write(root.join("docs/deep/a/b/c/leaf"), vec![7u8; 300_000]).unwrap();
    fs::create_dir(root.join("many")).unwrap();
    for i in 0..1000 {
        fs::write(
            root.join(format!("many/f{i:04}")),
            format!("file {i} {}", "x".repeat(i % 97)),
        )
        .unwrap();
    }
    fs::write(root.join("Übergröße – 日本語.txt"), "unicode").unwrap();
    fs::write(root.join("new\nline"), "nl").unwrap();
    fs::write(root.join("-dash"), "dash").unwrap();
    symlink("docs/README.txt", root.join("rel-link")).unwrap();
    symlink("/etc/shadow", root.join("abs-link")).unwrap();
    fs::write(root.join("hl1"), "linked content").unwrap();
    fs::hard_link(root.join("hl1"), root.join("docs/hl2")).unwrap();
    fs::hard_link(root.join("hl1"), root.join("many/hl3")).unwrap();
    let f = std::ffi::CString::new(root.join("fifo").as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(f.as_ptr(), 0o640) }, 0);
    fs::set_permissions(root.join("docs/README.txt"), fs::Permissions::from_mode(0o640)).unwrap();
    fs::create_dir_all(root.join(".snapshot/nightly")).unwrap();
    fs::write(root.join(".snapshot/nightly/old"), "snapshot copy").unwrap();
    fs::create_dir_all(root.join("docs/.snapshot")).unwrap();
    fs::write(root.join("docs/.snapshot/x"), "nested snapshot dir").unwrap();
    fs::write(root.join("skip.tmp"), "excluded").unwrap();
}

fn opts(threads: usize) -> scan::Options {
    let mut ex: Vec<String> = nas::DEFAULT_EXCLUDES.iter().map(|s| s.to_string()).collect();
    ex.push("*.tmp".into());
    scan::Options {
        threads,
        xattrs: true,
        extra_xattrs: Vec::new(),
        excludes: agent_core::glob::Excludes::new(&ex),
        batch: 7,
        before_read: None,
    }
}

fn spec(o: scan::Options) -> Spec {
    Spec {
        source_id: 4,
        scan: o,
        snapshot: None,
    }
}

fn quiet(_: &str) {}

fn tree_of(st: &Store, source: &str, t: u64) -> Vec<TreeEntry> {
    let m = st.load_manifest(source, t).unwrap();
    match st.load_index(&m, "tree").unwrap() {
        Index::Tree { entries } => entries,
        _ => panic!(),
    }
}

fn by_path(t: &[TreeEntry]) -> BTreeMap<Vec<u8>, &TreeEntry> {
    t.iter().map(|e| (e.path.clone(), e)).collect()
}

#[test]
fn scan_is_deterministic_and_complete() {
    let d = tempfile::tempdir().unwrap();
    let share = d.path().join("share");
    tree(&share);
    let xattrs =
        setxattr(&share.join("docs/README.txt"), "user.note", b"v1") && setxattr(&share.join("docs"), "user.dir", b"d");
    let root = mount::open_local(&share).unwrap();
    let st = store(&d.path().join("store"));
    let (one, r1) = scan::scan(&st, &root, &opts(1), None, &quiet).unwrap();
    let (many, r8) = scan::scan(&st, &root, &opts(8), None, &quiet).unwrap();
    assert_eq!(one, many, "same tree with 1 and 8 threads");
    assert_eq!(r1.entries, r8.entries);
    assert_eq!(r1.error_count, 0, "{:?}", r1.errors);
    let paths: Vec<String> = one
        .iter()
        .map(|e| String::from_utf8_lossy(&e.path).into_owned())
        .collect();
    // pre-order with sorted names, parents first
    for (i, p) in paths.iter().enumerate() {
        if let Some((parent, _)) = p.rsplit_once('/') {
            assert!(paths[..i].contains(&parent.to_string()), "{p} before its parent");
        }
    }
    assert!(
        !paths.iter().any(|p| p.contains(".snapshot") || p.ends_with(".tmp")),
        "excluded"
    );
    assert_eq!(paths.iter().filter(|p| p.starts_with("many/f")).count(), 1000);
    let m = by_path(&one);
    let e = |p: &str| *m.get(p.as_bytes()).unwrap_or_else(|| panic!("{p} missing"));
    assert_eq!(e("rel-link").kind, TreeKind::Symlink);
    assert_eq!(e("abs-link").link_target.as_deref(), Some(&b"/etc/shadow"[..]));
    assert_eq!(e("fifo").kind, TreeKind::Fifo);
    assert_eq!(e("docs/README.txt").mode, 0o640);
    assert!(m.contains_key("new\nline".as_bytes()) && m.contains_key("Übergröße – 日本語.txt".as_bytes()));
    // hard links: first name in tree order is the file, the others point to it
    assert_eq!(e("docs/hl2").kind, TreeKind::File);
    assert_eq!(e("docs/hl2").size, 14);
    assert_eq!(e("hl1").kind, TreeKind::Hardlink);
    assert_eq!(e("hl1").link_target.as_deref(), Some(&b"docs/hl2"[..]));
    assert_eq!(e("many/hl3").kind, TreeKind::Hardlink);
    assert_eq!(r1.files_read, 1004 + 2, "hard-linked content read once");
    if xattrs {
        assert_eq!(
            e("docs/README.txt").xattrs,
            vec![(b"user.note".to_vec(), b"v1".to_vec())]
        );
        assert_eq!(e("docs").xattrs, vec![(b"user.dir".to_vec(), b"d".to_vec())]);
    }
}

/// Under the scheduler's seccomp filter openat2 answers ENOSYS: the
/// component-wise fallback must produce the same tree.
#[test]
fn scan_without_openat2_is_the_same() {
    let d = tempfile::tempdir().unwrap();
    let share = d.path().join("share");
    tree(&share);
    let root = mount::open_local(&share).unwrap();
    let st = store(&d.path().join("store"));
    let (a, _) = scan::scan(&st, &root, &opts(4), None, &quiet).unwrap();
    nas::sys::disable_openat2();
    let (b, r) = scan::scan(&st, &root, &opts(4), None, &quiet).unwrap();
    assert_eq!(r.error_count, 0, "{:?}", r.errors);
    assert_eq!(a, b);
}

#[test]
fn incremental_reuses_unchanged_files_and_rereads_changes() {
    let d = tempfile::tempdir().unwrap();
    let share = d.path().join("share");
    tree(&share);
    let root = mount::open_local(&share).unwrap();
    let st = store(&d.path().join("store"));
    let o1 = backup::backup(&st, &root, &spec(opts(4)), &quiet).unwrap();
    assert!(!o1.incremental && !o1.consistent, "live share: not consistent");
    assert_eq!(o1.report.reused_files, 0);
    let o2 = backup::backup(&st, &root, &spec(opts(4)), &quiet).unwrap();
    assert!(o2.incremental && o2.time > o1.time);
    assert_eq!(o2.report.files_read, 0, "nothing changed: nothing read");
    assert_eq!(
        o2.report.reused_files, o1.report.files,
        "every name of every file reused"
    );
    assert_eq!(tree_of(&st, "share-4", o1.time), tree_of(&st, "share-4", o2.time));

    // same size + mtime restored, but ctime moved: must be re-read
    let p = share.join("many/f0005");
    let old = fs::metadata(&p).unwrap().modified().unwrap();
    let len = fs::metadata(&p).unwrap().len() as usize;
    fs::write(&p, "Y".repeat(len)).unwrap();
    fs::File::options()
        .write(true)
        .open(&p)
        .unwrap()
        .set_modified(old)
        .unwrap();
    // a renamed file (ctime changes on rename) and a new file
    fs::rename(share.join("docs/deep/a/b/c/leaf"), share.join("docs/leaf-moved")).unwrap();
    fs::write(share.join("docs/new"), "new").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    let o3 = backup::backup(&st, &root, &spec(opts(4)), &quiet).unwrap();
    let t3 = tree_of(&st, "share-4", o3.time);
    let m = by_path(&t3);
    let mut content = Vec::new();
    let f = m.get(&b"many/f0005"[..]).unwrap();
    st.write_chunks(&f.chunks, &mut content).unwrap();
    assert_eq!(
        content,
        "Y".repeat(len).as_bytes(),
        "re-read despite equal size and mtime"
    );
    assert!(
        o3.report.files_read >= 2 && o3.report.files_read <= 4,
        "{:?}",
        o3.report
    );
    assert!(m.contains_key(&b"docs/leaf-moved"[..]) && !m.contains_key(&b"docs/deep/a/b/c/leaf"[..]));
    // the moved 300 kB file is deduplicated: no new chunk for it
    assert!(o3.report.new_bytes < 1000, "{:?}", o3.report);

    // chunks lost from the store force a re-read
    let leaf = m.get(&b"docs/README.txt"[..]).unwrap();
    let chunk_file = |id: &chunkstore::ChunkId| {
        let h: String = id.iter().map(|b| format!("{b:02x}")).collect();
        d.path().join("store/chunks").join(&h[..4]).join(&h)
    };
    fs::remove_file(chunk_file(&leaf.chunks[0])).unwrap();
    let o4 = backup::backup(&st, &root, &spec(opts(4)), &quiet).unwrap();
    assert_eq!(o4.report.files_read, 1);
}

#[test]
fn files_changed_while_read_are_inconsistent() {
    let d = tempfile::tempdir().unwrap();
    let share = d.path().join("share");
    fs::create_dir_all(&share).unwrap();
    fs::write(share.join("stable"), "stable").unwrap();
    fs::write(share.join("busy.log"), vec![1u8; 100_000]).unwrap();
    let root = mount::open_local(&share).unwrap();
    let st = store(&d.path().join("store"));
    let target = share.join("busy.log");
    let hit = Arc::new(AtomicBool::new(false));
    let mut o = opts(2);
    let h = hit.clone();
    o.before_read = Some(Box::new(move |p: &[u8]| {
        if p == b"busy.log" {
            // a writer appends while the connector reads the file
            std::io::Write::write_all(
                &mut fs::OpenOptions::new().append(true).open(&target).unwrap(),
                b"appended during the read",
            )
            .unwrap();
            h.store(true, Ordering::SeqCst);
        }
    }));
    let out = backup::backup(&st, &root, &spec(o), &quiet).unwrap();
    assert!(hit.load(Ordering::SeqCst));
    assert_eq!(out.report.inconsistent, 1);
    let t = tree_of(&st, "share-4", out.time);
    let m = by_path(&t);
    assert!(m[&b"busy.log"[..]].inconsistent && !m[&b"stable"[..]].inconsistent);
    // an inconsistent file is never reused: the next run reads it again
    let o2 = backup::backup(&st, &root, &spec(opts(2)), &quiet).unwrap();
    assert_eq!(o2.report.files_read, 1);
    assert_eq!(o2.report.inconsistent, 0);
}

#[test]
fn reads_the_newest_nas_snapshot() {
    let d = tempfile::tempdir().unwrap();
    let share = d.path().join("share");
    fs::create_dir_all(share.join(".zfs/snapshot/auto-1/data")).unwrap();
    fs::create_dir_all(share.join(".zfs/snapshot/auto-2/data")).unwrap();
    fs::write(share.join(".zfs/snapshot/auto-1/data/f"), "old").unwrap();
    fs::write(share.join(".zfs/snapshot/auto-2/data/f"), "new").unwrap();
    fs::create_dir_all(share.join("data")).unwrap();
    fs::write(share.join("data/f"), "live").unwrap();
    let root = mount::open_local(&share).unwrap();
    let st = store(&d.path().join("store"));
    let mut sp = spec(opts(2));
    sp.snapshot = Some(Snap {
        dir: ".zfs/snapshot".into(),
        prefix: "auto-".into(),
        order: Order::Name,
    });
    let o = backup::backup(&st, &root, &sp, &quiet).unwrap();
    assert_eq!(o.snapshot.as_deref(), Some("auto-2"));
    assert!(o.consistent);
    let t = tree_of(&st, "share-4", o.time);
    let paths: Vec<&[u8]> = t.iter().map(|e| e.path.as_slice()).collect();
    assert_eq!(paths, vec![&b"data"[..], b"data/f"]);
    let mut c = Vec::new();
    st.write_chunks(&t[1].chunks, &mut c).unwrap();
    assert_eq!(c, b"new");
    // no snapshot matching: the live share, not consistent
    sp.snapshot.as_mut().unwrap().prefix = "hourly.".into();
    let o = backup::backup(&st, &root, &sp, &quiet).unwrap();
    assert!(o.snapshot.is_none() && !o.consistent);
}

#[test]
fn download_matches_the_share() {
    let d = tempfile::tempdir().unwrap();
    let share = d.path().join("share");
    tree(&share);
    let root = mount::open_local(&share).unwrap();
    let st = store(&d.path().join("store"));
    let o = backup::backup(&st, &root, &spec(opts(8)), &quiet).unwrap();
    let t = backup::load_tree(&st, "share-4", o.time).unwrap();
    let out = d.path().join("dl.tar");
    files::extract(&st, &t, &["/".into()], Format::Tar, fs::File::create_new(&out).unwrap()).unwrap();
    let mut a = tar::Archive::new(fs::File::open(&out).unwrap());
    let mut got = BTreeMap::new();
    for m in a.entries().unwrap() {
        let mut m = m.unwrap();
        if m.header().entry_type().is_file() {
            let p = m.path().unwrap().to_string_lossy().trim_start_matches('/').to_owned();
            let mut h = Sha256::new();
            std::io::copy(&mut m, &mut h).unwrap();
            got.insert(p, h.finalize().to_vec());
        }
    }
    let mut want = BTreeMap::new();
    for e in &t {
        if e.kind == TreeKind::File {
            let p = String::from_utf8_lossy(&e.path).into_owned();
            want.insert(p.clone(), Sha256::digest(fs::read(share.join(&p)).unwrap()).to_vec());
        }
    }
    assert_eq!(got.len(), want.len());
    assert_eq!(got, want);
}
