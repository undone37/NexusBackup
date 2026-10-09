//! In-process TrueNAS fake: the API side is an in-memory `Nas` whose
//! snapshots are hard-link copies under `<mountpoint>/.zfs/snapshot/<name>`;
//! the SSH side runs the *real* forced-command script (crate::fc) with bash,
//! GNU find/tar/realpath/xargs of the host and a `zfs` stub that answers
//! `get mountpoint|mounted` and replays `zfs diff` output computed by the fake
//! (with zfs's escaping). Exercises the whole backup path: full read,
//! incremental with renames/deletes/new hard links, rotation, lost reference,
//! hostile paths against the forced command, downloads.

use agent_conn::files::{self, Format};
use anyhow::{bail, Result};
use chunkstore::{Index, Keyring, Options, Store, TreeEntry, TreeKind};
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use truenas::api::{Dataset, Nas};
use truenas::backup::{backup, Spec};
use truenas::fc::{self, Fc, Tools};
use truenas::remote::Transport;

const SID: u64 = 7;

struct FakeNas {
    root: PathBuf,
    /// dataset -> mount point
    datasets: BTreeMap<String, PathBuf>,
    /// dataset -> snapshot names (creation order)
    snaps: BTreeMap<String, Vec<String>>,
    deleted: Vec<String>,
}

fn snapdir(mp: &Path, name: &str) -> PathBuf {
    mp.join(".zfs/snapshot").join(name)
}

/// zfs diff's stream_bytes escaping.
fn esc(p: &[u8]) -> String {
    p.iter()
        .map(|&c| {
            if c > b' ' && c != b'\\' && c < 0x7f {
                (c as char).to_string()
            } else {
                format!("\\{c:04o}")
            }
        })
        .collect()
}

/// path -> (inode, zfs diff type)
type Scan = BTreeMap<Vec<u8>, (u64, char)>;

fn scan(dir: &Path) -> Scan {
    fn rec(base: &Path, d: &Path, out: &mut Scan) {
        for e in fs::read_dir(d).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            let rel = p.strip_prefix(base).unwrap().as_os_str().as_bytes().to_vec();
            if rel == b".zfs" {
                continue;
            }
            let m = fs::symlink_metadata(&p).unwrap();
            let t = if m.is_dir() {
                '/'
            } else if m.file_type().is_symlink() {
                '@'
            } else {
                'F'
            };
            out.insert(rel, (m.ino(), t));
            if m.is_dir() {
                rec(base, &p, out);
            }
        }
    }
    let mut out = BTreeMap::new();
    rec(dir, dir, &mut out);
    out
}

/// What zfs diff would say (by object number), with the live mount point as prefix.
/// Directories get new inodes in every fake snapshot (only files are hard-linked),
/// so they show up as removed + added; a file whose own name changed is `R`,
/// files moved along with a renamed parent are not listed (as in zfs).
fn fake_diff(mp: &Path, a: &Path, b: &Path) -> String {
    let (old, new) = (scan(a), scan(b));
    let old_by_ino: HashMap<u64, &Vec<u8>> = old.iter().map(|(p, v)| (v.0, p)).collect();
    let new_by_ino: HashMap<u64, &Vec<u8>> = new.iter().map(|(p, v)| (v.0, p)).collect();
    let full = |p: &[u8]| format!("{}/{}", esc(mp.as_os_str().as_bytes()), esc(p));
    let base = |p: &[u8]| p.rsplit(|c| *c == b'/').next().unwrap().to_vec();
    let mut out = String::new();
    for (p, (ino, t)) in &new {
        if old.get(p).map(|v| v.0) == Some(*ino) {
            continue;
        }
        match old_by_ino.get(ino) {
            None => out.push_str(&format!("+\t{t}\t{}\n", full(p))),
            Some(op) if base(op) != base(p) => out.push_str(&format!("R\t{t}\t{}\t{}\n", full(op), full(p))),
            Some(_) => {}
        }
    }
    for (p, (ino, t)) in &old {
        if !new_by_ino.contains_key(ino) {
            out.push_str(&format!("-\t{t}\t{}\n", full(p)));
        }
    }
    out
}

impl FakeNas {
    fn stub_dir(&self) -> PathBuf {
        self.root.join("zfs-state")
    }

    fn key(ds: &str) -> String {
        ds.replace('/', "_")
    }

    /// Hard-link copy of the live tree, without .zfs and child mount points' content.
    fn copy_tree(&self, from: &Path, to: &Path, children: &[PathBuf]) {
        fs::create_dir_all(to).unwrap();
        for e in fs::read_dir(from).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            if p.file_name() == Some(OsStr::new(".zfs")) {
                continue;
            }
            let dst = to.join(e.file_name());
            let m = fs::symlink_metadata(&p).unwrap();
            if m.is_dir() {
                if children.contains(&p) {
                    fs::create_dir(&dst).unwrap();
                } else {
                    self.copy_tree(&p, &dst, children);
                }
                fs::set_permissions(&dst, m.permissions()).unwrap();
            } else {
                fs::hard_link(&p, &dst).unwrap();
            }
        }
    }
}

impl Nas for FakeNas {
    fn datasets(&mut self, root: &str, recursive: bool) -> Result<Vec<Dataset>> {
        Ok(self
            .datasets
            .iter()
            .filter(|(n, _)| *n == root || (recursive && n.starts_with(&format!("{root}/"))))
            .map(|(n, mp)| Dataset {
                name: n.clone(),
                mountpoint: Some(mp.to_str().unwrap().to_owned()),
                filesystem: true,
            })
            .collect())
    }
    fn snapshots(&mut self, ds: &str) -> Result<Vec<String>> {
        Ok(self.snaps.get(ds).cloned().unwrap_or_default())
    }
    fn create_snapshot(&mut self, root: &str, name: &str, recursive: bool) -> Result<()> {
        let all: Vec<(String, PathBuf)> = self.datasets.iter().map(|(a, b)| (a.clone(), b.clone())).collect();
        for (ds, mp) in &all {
            if !(ds == root || (recursive && ds.starts_with(&format!("{root}/")))) {
                continue;
            }
            if self.snaps.get(ds).is_some_and(|s| s.iter().any(|n| n == name)) {
                bail!("snapshot exists");
            }
            let children: Vec<PathBuf> = all
                .iter()
                .filter(|(c, _)| c.starts_with(&format!("{ds}/")))
                .map(|(_, m)| m.clone())
                .collect();
            let dst = snapdir(mp, name);
            self.copy_tree(mp, &dst, &children);
            let dir = self.stub_dir().join(Self::key(ds));
            fs::create_dir_all(&dir).unwrap();
            for old in self.snaps.get(ds).cloned().unwrap_or_default() {
                fs::write(
                    dir.join(format!("{old}@{name}")),
                    fake_diff(mp, &snapdir(mp, &old), &dst),
                )
                .unwrap();
            }
            self.snaps.entry(ds.clone()).or_default().push(name.to_owned());
        }
        Ok(())
    }
    fn delete_snapshot(&mut self, ds: &str, name: &str) -> Result<()> {
        let mp = &self.datasets[ds];
        fs::remove_dir_all(snapdir(mp, name))?;
        self.snaps.get_mut(ds).unwrap().retain(|n| n != name);
        self.deleted.push(format!("{ds}@{name}"));
        Ok(())
    }
}

/// Runs the generated authorized_keys command like sshd: `sh -c <command>`.
struct LocalFc {
    command: String,
}

impl Transport for LocalFc {
    fn command(&self, cmd: &str) -> Command {
        let mut c = Command::new("sh");
        c.arg("-c").arg(&self.command).env("SSH_ORIGINAL_COMMAND", cmd);
        c
    }
}

struct Lab {
    _td: tempfile::TempDir,
    nas: FakeNas,
    store: Store,
    t: LocalFc,
    data: PathBuf,
}

fn write_stub(path: &Path, state: &Path, mounts: &BTreeMap<String, PathBuf>) {
    let mut s = String::from("#!/bin/bash\nset -e\n");
    s.push_str("if [[ $1 == get && $5 == mountpoint ]]; then case $6 in\n");
    for (ds, mp) in mounts {
        s.push_str(&format!("  {ds}) echo \"{}\";;\n", mp.display()));
    }
    s.push_str("  *) echo \"cannot open '$6': dataset does not exist\" >&2; exit 1;;\nesac; exit 0; fi\n");
    s.push_str("if [[ $1 == get && $5 == mounted ]]; then echo yes; exit 0; fi\n");
    s.push_str(&format!(
        "if [[ $1 == diff && $2 == -FH ]]; then ds=${{3%%@*}}; exec cat \"{}/${{ds//\\//_}}/${{3#*@}}@${{4#*@}}\"; fi\n",
        state.display()
    ));
    s.push_str("echo \"zfs stub: unsupported $*\" >&2; exit 1\n");
    fs::write(path, s).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn lab() -> Lab {
    let td = tempfile::tempdir().unwrap();
    let root = td.path().to_path_buf();
    let data = root.join("mnt/tank/data");
    let child = data.join("child");
    let smb = root.join("mnt/tank/smb");
    for d in [&data, &child, &smb] {
        fs::create_dir_all(d).unwrap();
    }
    let datasets: BTreeMap<String, PathBuf> = [
        ("tank/data".to_owned(), data.clone()),
        ("tank/data/child".to_owned(), child.clone()),
        ("tank/smb".to_owned(), smb.clone()),
    ]
    .into();
    let nas = FakeNas {
        root: root.clone(),
        datasets: datasets.clone(),
        snaps: BTreeMap::new(),
        deleted: Vec::new(),
    };
    fs::create_dir_all(nas.stub_dir()).unwrap();
    fs::create_dir_all(root.join("bin")).unwrap();
    let zfs = root.join("bin/zfs");
    write_stub(&zfs, &nas.stub_dir(), &datasets);
    let tools = Tools {
        zfs: zfs.to_str().unwrap().to_owned(),
        ..Tools::default()
    };
    let fc = Fc {
        datasets: vec!["tank/data".into()],
        recursive: true,
        sudo: false,
        zfs_sudo: false,
    };
    // the authorized_keys line, dequoted the way sshd does it
    let line = fc::authorized_keys(&fc, &tools, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest t@x", None).unwrap();
    let start = line.find("command=\"").unwrap() + 9;
    let end = line.rfind("\" ssh-ed25519").unwrap();
    let command = line[start..end].replace("\\\"", "\"");
    let store = Store::open(
        root.join("store"),
        Keyring::new("acme", &[(1, [3; 32])]),
        Options::default(),
    )
    .unwrap();
    Lab {
        _td: td,
        nas,
        store,
        t: LocalFc { command },
        data,
    }
}

fn put(p: &Path, data: &[u8]) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    // new inode on every write: snapshots are hard-link copies of the live tree
    let tmp = p.with_extension("nexus-tmp");
    fs::write(&tmp, data).unwrap();
    fs::rename(&tmp, p).unwrap();
}

fn pseudo_random(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn tree(store: &Store, source: &str, time: u64) -> Vec<TreeEntry> {
    let m = store.load_manifest(source, time).unwrap();
    match store.load_index(&m, "tree").unwrap() {
        Index::Tree { entries } => entries,
        _ => panic!(),
    }
}

/// The tree must describe the live directory exactly (paths, kinds, sizes, content, link targets, xattrs).
fn assert_matches(store: &Store, entries: &[TreeEntry], live: &Path) {
    let child = |p: &[u8]| p.starts_with(b"child/");
    let mut seen = 0;
    let mut first: HashMap<u64, Vec<u8>> = HashMap::new();
    for e in entries {
        let p = live.join(OsStr::from_bytes(&e.path));
        let m = fs::symlink_metadata(&p).unwrap_or_else(|_| panic!("{p:?} missing live"));
        seen += 1;
        match e.kind {
            TreeKind::File => {
                let mut data = Vec::new();
                store.chunk_reader(&e.chunks).read_to_end(&mut data).unwrap();
                assert_eq!(data, fs::read(&p).unwrap(), "{p:?}");
                first.insert(m.ino(), e.path.clone());
                assert_eq!(e.mode & 0o7777, m.mode() & 0o7777);
                let x = xattr_get(&p, "user.nexus");
                assert_eq!(
                    e.xattrs
                        .iter()
                        .find(|(k, _)| k == b"user.nexus")
                        .map(|(_, v)| v.clone()),
                    x,
                    "{p:?}"
                );
            }
            TreeKind::Hardlink => {
                assert_eq!(first.get(&m.ino()), e.link_target.as_ref(), "{p:?}");
            }
            TreeKind::Dir => assert!(m.is_dir()),
            TreeKind::Symlink => {
                assert_eq!(
                    fs::read_link(&p).unwrap().as_os_str().as_bytes(),
                    e.link_target.as_deref().unwrap()
                )
            }
            _ => {}
        }
    }
    let live_count = scan(live).keys().filter(|p| !child(p)).count();
    assert_eq!(seen, live_count, "entry count");
}

fn xattr_set(p: &Path, k: &str, v: &[u8]) -> bool {
    let c = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
    let n = std::ffi::CString::new(k).unwrap();
    unsafe { libc::lsetxattr(c.as_ptr(), n.as_ptr(), v.as_ptr().cast(), v.len(), 0) == 0 }
}

fn xattr_get(p: &Path, k: &str) -> Option<Vec<u8>> {
    let c = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
    let n = std::ffi::CString::new(k).unwrap();
    let mut buf = vec![0u8; 4096];
    let r = unsafe { libc::lgetxattr(c.as_ptr(), n.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    (r >= 0).then(|| {
        buf.truncate(r as usize);
        buf
    })
}

fn spec() -> Spec {
    Spec {
        source_id: SID,
        datasets: vec!["tank/data".into()],
        recursive: true,
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
