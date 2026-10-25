//! Instant rollback of a container in place (#55, `pve::ctrollback`), end to end without
//! PVE: the snapshot's tar made by GNU tar (as the node plugin does), the real SSH helper
//! (`rollback-ct-begin` / `rollback-ct` / `rollback-ct-end`), the real root service
//! (`pve-plugin/rollback`, socket-activated by a stand-in) against the stub PVE modules
//! (`pve-plugin/t/rollback-lib`: the container's root file system is a directory, no id
//! mapping). Skipped without perl's JSON module or GNU tar.

use chunkstore::{FileEntry, Index, Keyring, Options, Store};
use pve::ctrollback::{self, CtOps, Outcome};
use pve::rollback::RollbackOpts;
use serde_json::{json, Map, Value};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, UNIX_EPOCH};

fn plugin_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../pve-plugin")
}

fn have_tools() -> bool {
    let ok = |c: &mut Command| c.output().is_ok_and(|o| o.status.success() && !o.stdout.is_empty());
    ok(Command::new("perl").args(["-MJSON", "-e", "print 1"])) && ok(Command::new("tar").arg("--version"))
}

fn write(p: &Path, data: &str, mtime: u64) {
    fs::write(p, data).unwrap();
    fs::File::options()
        .write(true)
        .open(p)
        .unwrap()
        .set_modified(UNIX_EPOCH + Duration::from_secs(mtime))
        .unwrap();
}

/// type, mode, mtime (not for directories: extracting into them moves it until tar's
/// final pass, and the root's own entry is what tar sets last), content or link target
fn tree(root: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut todo = vec![root.to_owned()];
    while let Some(p) = todo.pop() {
        let m = fs::symlink_metadata(&p).unwrap();
        let rel = p.strip_prefix(root).unwrap().display().to_string();
        let v = if m.is_dir() {
            todo.extend(fs::read_dir(&p).unwrap().map(|e| e.unwrap().path()));
            format!("dir {:o} {}", m.mode() & 0o7777, m.mtime())
        } else if m.file_type().is_symlink() {
            format!("link {}", fs::read_link(&p).unwrap().display())
        } else {
            format!(
                "file {:o} {} {}",
                m.mode() & 0o7777,
                m.mtime(),
                fs::read_to_string(&p).unwrap()
            )
        };
        out.insert(rel, v);
    }
    out
}

/// The node: container configuration as JSON for the stub PVE modules, its root file
/// system a directory, the helper run locally (as the SSH forced command would).
struct Local {
    dir: PathBuf,
    running: Cell<bool>,
}

impl Local {
    fn conf_path(&self) -> PathBuf {
        self.dir.join("pve/300.json")
    }
    fn helper_cmd(&self, cmd: &str) -> Command {
        let mut c = Command::new("perl");
        c.arg(plugin_dir().join("helper"))
            .env("SSH_ORIGINAL_COMMAND", cmd)
            .env_remove("SSH_CONNECTION")
            .env("NEXUSBACKUP_ROLLBACK_SOCK", self.dir.join("rollback.sock"));
        c
    }
}

impl CtOps for Local {
    fn locate(&self, _: u32) -> anyhow::Result<Option<String>> {
        Ok(Some("pve1".into()))
    }
    fn config(&self, _: &str, _: u32) -> anyhow::Result<Map<String, Value>> {
        Ok(serde_json::from_slice(&fs::read(self.conf_path())?)?)
    }
    fn set_config(&self, n: &str, v: u32, changes: &[(String, Option<String>)]) -> anyhow::Result<()> {
        let mut c = self.config(n, v)?;
        for (k, v) in changes {
            match v {
                Some(v) => c.insert(k.clone(), json!(v)),
                None => c.remove(k),
            };
        }
        fs::write(self.conf_path(), serde_json::to_vec(&c)?)?;
        Ok(())
    }
    fn running(&self, _: &str, _: u32) -> anyhow::Result<bool> {
        Ok(self.running.get())
    }
    fn act(&self, _: &str, _: u32, action: &str) -> anyhow::Result<()> {
        self.running.set(action == "start");
        let flag = self.dir.join("pve/300.running");
        if self.running.get() {
            fs::write(flag, "")?;
        } else {
            let _ = fs::remove_file(flag);
        }
        Ok(())
    }
    fn helper(&self, _: &str, cmd: &str) -> anyhow::Result<String> {
        let out = self.helper_cmd(cmd).output()?;
        anyhow::ensure!(out.status.success(), "{cmd}: {}", String::from_utf8_lossy(&out.stderr));
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    }
    fn session(&self, _: &str, vmid: u32) -> anyhow::Result<Child> {
        Ok(self
            .helper_cmd(&format!("rollback-ct {vmid}"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?)
    }
}

/// systemd `Accept=yes` stand-in: one root-side rollback process per connection.
fn service(dir: &Path) {
    let l = UnixListener::bind(dir.join("rollback.sock")).unwrap();
    let dir = dir.to_owned();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(s) = s else { continue };
            let out = s.try_clone().unwrap();
            let _ = Command::new("perl")
                .arg(plugin_dir().join("rollback"))
                .env("PERL5LIB", plugin_dir().join("t/rollback-lib"))
                .env("NEXUSBACKUP_TEST_PVE", dir.join("pve"))
                .env("NEXUSBACKUP_ROLLBACK_RUNDIR", dir.join("run"))
                .stdin(Stdio::from(std::os::fd::OwnedFd::from(s)))
                .stdout(Stdio::from(std::os::fd::OwnedFd::from(out)))
                .stderr(Stdio::inherit())
                .spawn();
        }
    });
}

#[test]
fn writes_only_the_differing_files_through_helper_and_service() {
    if !have_tools() {
        eprintln!("perl JSON or GNU tar missing, skipping");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(
        d.path().join("store"),
        Keyring::new("acme", &[(1, [9; 32])]),
        Options {
            min_lock_secs: 0,
            ..Options::default()
        },
    )
    .unwrap();

    // the snapshot: a small container tree, archived as the node plugin does
    let snap = d.path().join("snap");
    for p in ["", "etc", "var", "var/lib", "x"] {
        fs::create_dir_all(snap.join(p)).unwrap();
    }
    fs::remove_dir(snap.join("x")).unwrap();
    write(&snap.join("etc/hostname"), "web\n", 1_700_000_000);
    write(&snap.join("etc/same"), "unchanged\n", 1_700_000_100);
    write(&snap.join("etc/mtime"), "same content\n", 1_700_000_200);
    write(&snap.join("var/lib/db"), "rows 1-100\n", 1_700_000_300);
    write(&snap.join("x"), "x was a file\n", 1_700_000_400);
    write(&snap.join("etc/mode"), "mode\n", 1_700_000_500);
    fs::set_permissions(snap.join("etc/mode"), fs::Permissions::from_mode(0o600)).unwrap();
    symlink("hostname", snap.join("etc/link")).unwrap();
    let tar = Command::new("tar")
        .args([
            "--create",
            "--file=-",
            "--numeric-owner",
            "--sparse",
            "--one-file-system",
        ])
        .arg(format!("--directory={}", snap.display()))
        .arg(".")
        .output()
        .unwrap();
    assert!(tar.status.success());
    let (chunks, size) = s.store_file(&tar.stdout[..]).unwrap();
    let conf = "hostname: web\nunprivileged: 1\nrootfs: local:subvol-300-disk-0,size=8G\n";
    let (cchunks, csize) = s.store_file(conf.as_bytes()).unwrap();
    let entry = |path: &str, size, chunks| FileEntry {
        path: path.into(),
        mode: 0o640,
        size,
        mtime: 0,
        chunks,
    };
    s.commit_snapshot(
        "ct-300",
        1000,
        &[
            (
                "root.tar",
                Index::Dynamic {
                    entries: vec![entry("root.tar", size, chunks)],
                },
            ),
            (
                "config",
                Index::Dynamic {
                    entries: vec![entry("pct.conf", csize, cchunks)],
                },
            ),
        ],
    )
    .unwrap();

    // the container now: copied, then changed
    fs::create_dir_all(d.path().join("pve")).unwrap();
    let root = d.path().join("pve/ct-300-root");
    assert!(Command::new("cp")
        .arg("-a")
        .arg(&snap)
        .arg(&root)
        .status()
        .unwrap()
        .success());
    write(&root.join("etc/hostname"), "db\n", 1_800_000_000);
    write(&root.join("etc/mtime"), "same content\n", 1_800_000_200);
    write(&root.join("var/lib/db"), "rows 1-100 and 101-900\n", 1_800_000_300);
    fs::set_permissions(root.join("etc/mode"), fs::Permissions::from_mode(0o644)).unwrap();
    write(&root.join("etc/new"), "added later\n", 1_800_000_400);
    fs::create_dir_all(root.join("var/cache/junk")).unwrap();
    write(&root.join("var/cache/junk/a"), "junk\n", 1_800_000_500);
    fs::remove_file(root.join("x")).unwrap();
    fs::create_dir(root.join("x")).unwrap();
    write(&root.join("x/inside"), "now a directory\n", 1_800_000_600);
    fs::remove_file(root.join("etc/link")).unwrap();
    symlink("new", root.join("etc/link")).unwrap();
    assert_ne!(tree(&root), tree(&snap));

    let live = json!({"hostname": "web", "unprivileged": 1, "rootfs": "local:subvol-300-disk-0,size=8G",
                      "tags": "prod", "net0": "name=eth0,bridge=vmbr0"});
    fs::write(d.path().join("pve/300.json"), serde_json::to_vec(&live).unwrap()).unwrap();
    fs::write(d.path().join("pve/300.running"), "").unwrap();
    service(d.path());
    let n = Local {
        dir: d.path().to_owned(),
        running: Cell::new(true),
    };
    let o = RollbackOpts {
        start: true,
        link_down: false,
    };
    let Outcome::RolledBack(r) = ctrollback::rollback(&n, &s, 300, 1000, &o).unwrap() else {
        panic!("fell back")
    };
    let mut want = tree(&snap);
    let mut got = tree(&root);
    // directory mtimes: tar restores them, but this test's own writes above moved the
    // snapshot's too; compare the files
    for t in [&mut want, &mut got] {
        t.retain(|_, v| !v.starts_with("dir"));
    }
    assert_eq!(got, want, "the container is the snapshot again");
    assert!(!root.join("var/cache").exists() && root.join("var/lib").is_dir());
    // hostname, mtime, db, mode, x (a file again), link
    assert_eq!((r.files_written, r.unchanged > 0), (6, true), "{r:?}");
    // new, var/cache, var/cache/junk, var/cache/junk/a, x/inside, and x (a directory before)
    assert_eq!(r.deleted, 6, "{r:?}");
    assert!(r.started && n.running.get());
    let c: Map<String, Value> = serde_json::from_slice(&fs::read(n.conf_path()).unwrap()).unwrap();
    assert_eq!(c.get("lock"), None, "unlocked");
    assert_eq!(c["tags"], "prod", "untagged");

    // a privileged container is restored in full instead; nothing is changed
    fs::write(
        n.conf_path(),
        serde_json::to_vec(&json!({"hostname": "web", "unprivileged": 0})).unwrap(),
    )
    .unwrap();
    let out = ctrollback::rollback(&n, &s, 300, 1000, &o).unwrap();
    assert!(
        matches!(out, Outcome::Fallback(ref w) if w.contains("privileged")),
        "{out:?}"
    );
    // the service refuses a container that is not marked (a stolen SSH key alone writes nothing)
    fs::write(n.conf_path(), serde_json::to_vec(&live).unwrap()).unwrap();
    n.act("pve1", 300, "shutdown").unwrap();
    let err = n.helper("pve1", "rollback-ct-begin 300").unwrap_err();
    assert!(format!("{err:#}").contains("not marked for a rollback"), "{err:#}");
}
