//! Instant rollback in place (Phase 30, `pve::rollback`).
//!
//! - The orchestration against an in-memory node (pause, pre-rollback backup,
//!   stop, tag, lock, writes of the differing chunks only, unlock, untag; the
//!   fallbacks; an interrupted rollback resumed).
//! - The data path end to end without PVE: the real SSH helper
//!   (`rollback-begin` / `rollback-nbd` / `rollback-end`), the real root service
//!   (`pve-plugin/rollback`, socket-activated by a stand-in here) against stub PVE
//!   modules (`pve-plugin/t/rollback-lib`), a real qemu-nbd writing a raw volume,
//!   and the appliance's NBD client. Skipped without perl's JSON module or qemu-nbd.

use chunkstore::{FileEntry, Index, Keyring, Options, Store};
use pve::rollback::{self, DiskWriter, Outcome, Power, RollbackOps, RollbackOpts};
use serde_json::{json, Map, Value};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::rc::Rc;

const CS: usize = 1 << 20;
/// not a multiple of the chunk size (a short last chunk), but of 512 (qemu-nbd sizes)
const SIZE: usize = (16 << 20) + 3 * 512;
const CONF: &str = "name: web\nvmgenid: 1111\nsmbios1: uuid=aaaa\nscsi0: local:vm-100-disk-0,size=16781824\n";

fn store(d: &Path) -> Store {
    Store::open(
        d.join("store"),
        Keyring::new("acme", &[(1, [9; 32])]),
        Options {
            min_lock_secs: 0,
            ..Options::default()
        },
    )
    .unwrap()
}

/// Deterministic incompressible disk content, `seed` per version.
fn disk(seed: u64) -> Vec<u8> {
    let mut x = 0x2545_f491_4f6c_dd1du64 ^ seed;
    let mut v = Vec::with_capacity(SIZE);
    while v.len() < SIZE {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.truncate(SIZE);
    v
}

/// `data` with chunk `i` (some bytes of it) changed.
fn touch(data: &mut [u8], chunks: &[usize], b: u8) {
    for &i in chunks {
        let at = (i * CS + 100).min(data.len() - 1);
        data[at] = b;
    }
}

fn snap(s: &Store, time: u64, data: &[u8], conf: &str) {
    let idx = s.store_image(data, CS).unwrap();
    let (chunks, size) = s.store_file(conf.as_bytes()).unwrap();
    let cfg = Index::Dynamic {
        entries: vec![FileEntry {
            path: "qemu-server.conf".into(),
            mode: 0o640,
            size,
            mtime: 0,
            chunks,
        }],
    };
    s.commit_snapshot("vm-100", time, &[("drive-scsi0", idx), ("config", cfg)])
        .unwrap();
}

fn live(conf: &str) -> BTreeMap<String, String> {
    rollback::conf_map(conf)
}

// ---------------------------------------------------------------- in-memory node

struct Mem {
    conf: BTreeMap<String, String>,
    power: Power,
    disk: Rc<RefCell<Vec<u8>>>,
    bitmap: bool,
    next_time: u64,
    /// the writer fails after this many writes (once)
    fail_after: Option<usize>,
    calls: Vec<String>,
}

struct Node<'a> {
    m: RefCell<Mem>,
    store: &'a Store,
}

struct MemDisk {
    disk: Rc<RefCell<Vec<u8>>>,
    fail_after: Option<usize>,
}

impl DiskWriter for MemDisk {
    fn size(&self) -> u64 {
        self.disk.borrow().len() as u64
    }
    fn write(
        &mut self,
        writes: &mut dyn Iterator<Item = io::Result<(u64, Vec<u8>)>>,
        done: &mut dyn FnMut(usize, u64),
    ) -> io::Result<()> {
        for (n, w) in writes.enumerate() {
            if self.fail_after == Some(n) {
                return Err(io::Error::other("connection lost"));
            }
            let (off, data) = w?;
            self.disk.borrow_mut()[off as usize..off as usize + data.len()].copy_from_slice(&data);
            done(n, data.len() as u64);
        }
        Ok(())
    }
    fn finish(self: Box<Self>) -> io::Result<()> {
        Ok(())
    }
}

impl RollbackOps for Node<'_> {
    fn locate(&self, _: u32) -> anyhow::Result<Option<String>> {
        Ok(Some("pve1".into()))
    }
    fn config(&self, _: &str, _: u32) -> anyhow::Result<Map<String, Value>> {
        Ok(self
            .m
            .borrow()
            .conf
            .iter()
            .map(|(k, v)| (k.clone(), json!(v)))
            .collect())
    }
    fn set_config(&self, _: &str, _: u32, changes: &[(String, Option<String>)]) -> anyhow::Result<()> {
        let mut m = self.m.borrow_mut();
        for (k, v) in changes {
            match v {
                Some(v) => m.conf.insert(k.clone(), v.clone()),
                None => m.conf.remove(k),
            };
        }
        m.calls.push(format!("config {changes:?}"));
        Ok(())
    }
    fn power(&self, _: &str, _: u32) -> anyhow::Result<Power> {
        Ok(self.m.borrow().power)
    }
    fn act(&self, _: &str, _: u32, action: &str) -> anyhow::Result<()> {
        let mut m = self.m.borrow_mut();
        m.power = match action {
            "suspend" => Power::Paused,
            "resume" | "start" => Power::Running,
            "stop" => Power::Stopped,
            a => anyhow::bail!("unknown action {a}"),
        };
        m.calls.push(action.into());
        Ok(())
    }
    fn pre_backup(&self, store: &Store, _: u32) -> anyhow::Result<Option<u64>> {
        let mut m = self.m.borrow_mut();
        assert_eq!(m.power, Power::Paused, "backed up while paused");
        m.calls.push("backup".into());
        if !m.bitmap {
            return Ok(None);
        }
        let t = m.next_time;
        let conf: String = m.conf.iter().map(|(k, v)| format!("{k}: {v}\n")).collect();
        snap(store, t, &m.disk.borrow(), &conf);
        Ok(Some(t))
    }
    fn helper(&self, _: &str, cmd: &str) -> anyhow::Result<String> {
        let mut m = self.m.borrow_mut();
        m.calls.push(cmd.into());
        if cmd.starts_with("rollback-begin") {
            assert_eq!(m.power, Power::Stopped);
            assert!(m.conf.get("tags").is_some_and(|t| t.contains("nexus-rollback")));
            m.conf.insert("lock".into(), "rollback".into());
        } else {
            m.conf.remove("lock");
        }
        Ok("ok".into())
    }
    fn open_disk(&self, _: &str, _: u32, device: &str) -> anyhow::Result<Box<dyn DiskWriter>> {
        assert_eq!(device, "drive-scsi0");
        let mut m = self.m.borrow_mut();
        let fail_after = m.fail_after.take();
        Ok(Box::new(MemDisk {
            disk: m.disk.clone(),
            fail_after,
        }))
    }
}

fn node<'a>(s: &'a Store, current: Vec<u8>) -> Node<'a> {
    let mut conf = live(CONF);
    conf.insert("tags".into(), "prod".into());
    Node {
        m: RefCell::new(Mem {
            conf,
            power: Power::Running,
            disk: Rc::new(RefCell::new(current)),
            bitmap: true,
            next_time: 3000,
            fail_after: None,
            calls: Vec::new(),
        }),
        store: s,
    }
}

/// Target snapshot 1000 (A), newest snapshot 2000 (A + chunks 1, 2), current disk
/// = 2000 + chunk 9 written since: exactly chunks 1, 2, 9 are written back.
#[test]
fn rolls_back_only_the_differing_chunks() {
    let d = tempfile::tempdir().unwrap();
    let s = store(d.path());
    let a = disk(1);
    snap(&s, 1000, &a, CONF);
    let mut newest = a.clone();
    touch(&mut newest, &[1, 2], 0x11);
    snap(&s, 2000, &newest, CONF);
    let mut current = newest.clone();
    touch(&mut current, &[9, 16], 0x22);
    let n = node(&s, current);
    let o = RollbackOpts {
        start: true,
        link_down: false,
    };
    let Outcome::RolledBack(r) = rollback::rollback(&n, n.store, 100, 1000, &o).unwrap() else {
        panic!("fell back")
    };
    let m = n.m.borrow();
    assert_eq!(*m.disk.borrow(), a, "the disk is the snapshot again");
    assert_eq!((r.pre_snapshot, r.resumed, r.started), (3000, false, true));
    assert_eq!(r.disks.len(), 1);
    let dr = &r.disks[0];
    assert_eq!((dr.chunks, dr.changed), (17, 4), "{dr:?}");
    // chunks 1, 2, 9 full, chunk 16 = the short last one
    assert_eq!(dr.bytes_written, 3 * CS as u64 + 3 * 512);
    assert_eq!(
        m.calls
            .iter()
            .filter(|c| !c.starts_with("config"))
            .cloned()
            .collect::<Vec<_>>(),
        [
            "suspend",
            "backup",
            "stop",
            "rollback-begin 100",
            "rollback-end 100",
            "start"
        ]
    );
    assert_eq!(
        m.conf.get("tags").map(String::as_str),
        Some("prod"),
        "tag removed again"
    );
    assert!(!m.conf.contains_key("lock"));
    assert_eq!(m.power, Power::Running);
}

#[test]
fn falls_back_when_in_place_is_impossible() {
    let d = tempfile::tempdir().unwrap();
    let s = store(d.path());
    let a = disk(2);
    snap(&s, 1000, &a, CONF);
    let o = RollbackOpts::default();
    // stopped: the bitmap is gone
    let n = node(&s, a.clone());
    n.m.borrow_mut().power = Power::Stopped;
    let out = rollback::rollback(&n, n.store, 100, 1000, &o).unwrap();
    assert!(matches!(&out, Outcome::Fallback(w) if w.contains("stopped")), "{out:?}");
    // another VM behind the VMID
    let n = node(&s, a.clone());
    n.m.borrow_mut().conf.insert("vmgenid".into(), "2222".into());
    let out = rollback::rollback(&n, n.store, 100, 1000, &o).unwrap();
    assert!(
        matches!(&out, Outcome::Fallback(w) if w.contains("identity")),
        "{out:?}"
    );
    assert!(n.m.borrow().calls.is_empty(), "nothing touched");
    // PVE would read a disk in full: resumed, nothing committed
    let n = node(&s, a.clone());
    n.m.borrow_mut().bitmap = false;
    let out = rollback::rollback(&n, n.store, 100, 1000, &o).unwrap();
    assert!(
        matches!(&out, Outcome::Fallback(w) if w.contains("dirty bitmap")),
        "{out:?}"
    );
    let m = n.m.borrow();
    assert_eq!(m.calls, ["suspend", "backup", "resume"]);
    assert_eq!(m.power, Power::Running);
}

/// A connection lost while writing leaves the VM stopped, tagged and locked; the
/// next run resumes from the pre-rollback snapshot and finishes.
#[test]
fn interrupted_rollback_resumes() {
    let d = tempfile::tempdir().unwrap();
    let s = store(d.path());
    let a = disk(3);
    snap(&s, 1000, &a, CONF);
    let mut current = a.clone();
    touch(&mut current, &[0, 3, 5, 7], 0x33);
    let n = node(&s, current);
    n.m.borrow_mut().fail_after = Some(2);
    let err = rollback::rollback(&n, n.store, 100, 1000, &RollbackOpts::default()).unwrap_err();
    assert!(format!("{err:#}").contains("run the rollback again"), "{err:#}");
    {
        let m = n.m.borrow();
        assert_eq!(m.power, Power::Stopped);
        assert_eq!(m.conf.get("lock").map(String::as_str), Some("rollback"));
        assert!(m.conf["tags"].contains("nexus-rollback"));
        assert_ne!(*m.disk.borrow(), a);
    }
    let Outcome::RolledBack(r) = rollback::rollback(&n, n.store, 100, 1000, &RollbackOpts::default()).unwrap() else {
        panic!("fell back")
    };
    assert!(r.resumed && !r.started);
    assert_eq!(r.pre_snapshot, 3000);
    let m = n.m.borrow();
    assert_eq!(*m.disk.borrow(), a);
    assert_eq!(m.calls.iter().filter(|c| *c == "backup").count(), 1, "no second backup");
    assert!(!m.conf.contains_key("lock") && m.conf.get("tags").map(String::as_str) == Some("prod"));
}

// ---------------------------------------------------------------- real helper + service + qemu-nbd

fn plugin_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../pve-plugin")
}

fn have_tools() -> bool {
    let perl = Command::new("perl")
        .args(["-MJSON", "-e", "1"])
        .status()
        .is_ok_and(|s| s.success());
    perl && Path::new("/usr/bin/qemu-nbd").exists()
}

/// The node: VM configuration as JSON for the stub PVE modules, the volume as a
/// raw file, the helper run locally (as the SSH forced command would).
struct Local<'a> {
    dir: PathBuf,
    power: RefCell<Power>,
    store: &'a Store,
}

impl Local<'_> {
    fn conf_path(&self) -> PathBuf {
        self.dir.join("pve/100.json")
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

impl RollbackOps for Local<'_> {
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
    fn power(&self, _: &str, _: u32) -> anyhow::Result<Power> {
        Ok(*self.power.borrow())
    }
    fn act(&self, _: &str, _: u32, action: &str) -> anyhow::Result<()> {
        *self.power.borrow_mut() = match action {
            "suspend" => Power::Paused,
            "stop" => Power::Stopped,
            _ => Power::Running,
        };
        // the stub's check_running
        let running = self.dir.join("pve/100.running");
        if *self.power.borrow() == Power::Stopped {
            let _ = fs::remove_file(&running);
        } else {
            fs::write(&running, "")?;
        }
        Ok(())
    }
    fn pre_backup(&self, store: &Store, _: u32) -> anyhow::Result<Option<u64>> {
        // what vzdump would read: the volume as it is now
        snap(
            store,
            3000,
            &fs::read(self.dir.join("pve/volumes/vm-100-disk-0"))?,
            CONF,
        );
        Ok(Some(3000))
    }
    fn helper(&self, _: &str, cmd: &str) -> anyhow::Result<String> {
        let out = self.helper_cmd(cmd).output()?;
        anyhow::ensure!(out.status.success(), "{cmd}: {}", String::from_utf8_lossy(&out.stderr));
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    }
    fn open_disk(&self, _: &str, vmid: u32, device: &str) -> anyhow::Result<Box<dyn DiskWriter>> {
        let c = self.helper_cmd(&format!("rollback-nbd {vmid} {device}"));
        rollback::open_nbd(c, device)
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
fn data_path_through_helper_service_and_qemu_nbd() {
    if !have_tools() {
        eprintln!("perl JSON or qemu-nbd missing, skipping");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let s = store(d.path());
    fs::create_dir_all(d.path().join("pve/volumes")).unwrap();
    let a = disk(4);
    snap(&s, 1000, &a, CONF);
    let mut current = a.clone();
    touch(&mut current, &[2, 8, 16], 0x44);
    fs::write(d.path().join("pve/volumes/vm-100-disk-0"), &current).unwrap();
    let mut conf: Map<String, Value> = live(CONF).into_iter().map(|(k, v)| (k, json!(v))).collect();
    conf.insert("tags".into(), json!("prod"));
    fs::write(d.path().join("pve/100.json"), serde_json::to_vec(&conf).unwrap()).unwrap();
    fs::write(d.path().join("pve/100.running"), "").unwrap();
    service(d.path());
    let n = Local {
        dir: d.path().to_owned(),
        power: RefCell::new(Power::Running),
        store: &s,
    };
    let o = RollbackOpts {
        start: false,
        link_down: false,
    };
    let Outcome::RolledBack(r) = rollback::rollback(&n, n.store, 100, 1000, &o).unwrap() else {
        panic!("fell back")
    };
    assert_eq!(r.disks[0].changed, 3);
    assert_eq!(
        fs::read(d.path().join("pve/volumes/vm-100-disk-0")).unwrap(),
        a,
        "the volume is the snapshot again"
    );
    let c: Map<String, Value> = serde_json::from_slice(&fs::read(d.path().join("pve/100.json")).unwrap()).unwrap();
    assert_eq!(c.get("lock"), None, "unlocked");
    assert_eq!(c["tags"], "prod", "untagged");
    // the service refuses a VM that is not marked (a stolen SSH key alone cannot write disks)
    let err = n.helper("pve1", "rollback-begin 100").unwrap_err();
    assert!(format!("{err:#}").contains("not marked for a rollback"), "{err:#}");
    let _ = n.store;
}
