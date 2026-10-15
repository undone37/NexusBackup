//! Shared by the TrueNAS tests (`#[path]`-included by `plugins/truenas` too):
//! an in-process TrueNAS fake. The API side is an in-memory `Nas` whose
//! snapshots are hard-link copies under `<mountpoint>/.zfs/snapshot/<name>`;
//! the SSH side runs the *real* forced-command script (truenas::fc) with bash,
//! GNU find/tar/realpath/xargs of the host and a `zfs` stub that answers
//! `get mountpoint|mounted` and replays `zfs diff` output computed by the fake
//! (with zfs's escaping). Plus data helpers, tree assertions and the lab's
//! `data.sh sums` parser.
#![allow(dead_code)]

use anyhow::{bail, Result};
use chunkstore::{Index, Store, TreeEntry, TreeKind};
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use truenas::api::{Dataset, Nas};
use truenas::fc::{self, Fc, Tools};
use truenas::remote::Transport;

pub struct FakeNas {
    pub root: PathBuf,
    /// dataset -> mount point
    pub datasets: BTreeMap<String, PathBuf>,
    /// dataset -> snapshot names (creation order)
    pub snaps: BTreeMap<String, Vec<String>>,
    pub deleted: Vec<String>,
}

pub fn snapdir(mp: &Path, name: &str) -> PathBuf {
    mp.join(".zfs/snapshot").join(name)
}

/// zfs diff's stream_bytes escaping.
pub fn esc(p: &[u8]) -> String {
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
pub type Scan = BTreeMap<Vec<u8>, (u64, char)>;

pub fn scan(dir: &Path) -> Scan {
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
pub fn fake_diff(mp: &Path, a: &Path, b: &Path) -> String {
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
                if let Some(v) = xattr_get(&p, "user.dir") {
                    xattr_set(&dst, "user.dir", &v); // directory xattrs: only this one
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
#[derive(Clone)]
pub struct LocalFc {
    pub command: String,
}

impl Transport for LocalFc {
    fn command(&self, cmd: &str) -> Command {
        let mut c = Command::new("sh");
        c.arg("-c").arg(&self.command).env("SSH_ORIGINAL_COMMAND", cmd);
        c
    }
}

pub fn write_stub(path: &Path, state: &Path, mounts: &BTreeMap<String, PathBuf>) {
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

/// A fake TrueNAS below `root`: datasets `tank/data` (mounted at
/// `<root>/mnt/tank/data`), its child `tank/data/child` and `tank/smb`; the
/// forced command allows `tank/data` recursively (no sudo, the `zfs` stub).
/// Returns (nas, forced command, mount point of tank/data).
pub fn fake(root: &Path) -> (FakeNas, LocalFc, PathBuf) {
    let root = root.to_path_buf();
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
        existing_prefix: Some("auto-".into()),
    };
    // the authorized_keys line, dequoted the way sshd does it
    let line = fc::authorized_keys(&fc, &tools, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest t@x", None).unwrap();
    let start = line.find("command=\"").unwrap() + 9;
    let end = line.rfind("\" ssh-ed25519").unwrap();
    let command = line[start..end].replace("\\\"", "\"");
    (nas, LocalFc { command }, data)
}

pub fn put(p: &Path, data: &[u8]) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    // new inode on every write: snapshots are hard-link copies of the live tree
    let tmp = p.with_extension("nexus-tmp");
    fs::write(&tmp, data).unwrap();
    fs::rename(&tmp, p).unwrap();
}

pub fn pseudo_random(n: usize, seed: u64) -> Vec<u8> {
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

pub fn tree(store: &Store, source: &str, time: u64, index: &str) -> Vec<TreeEntry> {
    let m = store.load_manifest(source, time).unwrap();
    match store.load_index(&m, index).unwrap() {
        Index::Tree { entries } => entries,
        _ => panic!(),
    }
}

/// The tree must describe the live directory exactly (paths, kinds, sizes, content, link targets, xattrs).
pub fn assert_matches(store: &Store, entries: &[TreeEntry], live: &Path) {
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
                );
            }
            _ => {}
        }
    }
    let live_count = scan(live).keys().filter(|p| !child(p)).count();
    assert_eq!(seen, live_count, "entry count");
}

pub fn xattr_set(p: &Path, k: &str, v: &[u8]) -> bool {
    let c = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
    let n = std::ffi::CString::new(k).unwrap();
    unsafe { libc::lsetxattr(c.as_ptr(), n.as_ptr(), v.as_ptr().cast(), v.len(), 0) == 0 }
}

pub fn xattr_get(p: &Path, k: &str) -> Option<Vec<u8>> {
    let c = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
    let n = std::ffi::CString::new(k).unwrap();
    let mut buf = vec![0u8; 4096];
    let r = unsafe { libc::lgetxattr(c.as_ptr(), n.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    (r >= 0).then(|| {
        buf.truncate(r as usize);
        buf
    })
}

/// `data.sh sums` output: `== <dataset>` headers, then `sha256  ./path` lines.
pub fn sums(text: &str) -> BTreeMap<String, BTreeMap<Vec<u8>, String>> {
    let mut out: BTreeMap<String, BTreeMap<Vec<u8>, String>> = BTreeMap::new();
    let mut cur = String::new();
    for l in text.lines() {
        if let Some(ds) = l.strip_prefix("== ") {
            cur = format!("tank/{ds}");
            continue;
        }
        // sha256sum escapes names with `\` or newline: leading `\`, then `\\` / `\n`
        let (escaped, l) = match l.strip_prefix('\\') {
            Some(r) => (true, r),
            None => (false, l),
        };
        let (h, p) = l.split_once("  ./").unwrap();
        let p = if escaped {
            p.replace("\\\\", "\0").replace("\\n", "\n").replace('\0', "\\")
        } else {
            p.to_owned()
        };
        out.entry(cur.clone()).or_default().insert(p.into_bytes(), h.to_owned());
    }
    out
}
