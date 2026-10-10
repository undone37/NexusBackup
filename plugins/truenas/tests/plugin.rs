//! The TrueNAS plugin against the real host code (plugin_sdk::testing) and the
//! TrueNAS fake of crate truenas (tests/support, shared with the built-in
//! connector's tests): in-process (fake API + the real forced command run
//! locally, as the connector's tests do) and as the real binary in the real
//! sandbox (JSON-RPC over wss against a mock server backed by the fake, the
//! system's `ssh` against a local unprivileged sshd running the forced command).

#[path = "../../../crates/truenas/tests/support/mod.rs"]
mod support;

use anyhow::Result;
use plugin_sdk::testing::Host;
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use support::*;
use truenas::api::{Dataset, Nas};
use truenas::fc::{self, Fc, Tools};
use truenas::remote::Transport;
use truenas_plugin::{Config, Connect, TrueNasPlugin};

const MANIFEST: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/manifest.json");
const SID: u64 = 7;
/// throwaway test key (only its public half matters in-process)
const TEST_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAGiGO1XSiMFJ4aFk8yIP8edSkcIjiEjlrRoKEga9U9VAAAAIgkFq/JJBav
yQAAAAtzc2gtZWQyNTUxOQAAACAGiGO1XSiMFJ4aFk8yIP8edSkcIjiEjlrRoKEga9U9VA
AAAEAYwlodicdqEsljYIYnIx2w7u6f6SciWBKbizIUHXcNogaIY7VdKIwUnhoWTzIg/x51
KRwiOISOWtGgoSBr1T1UAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
";
const TEST_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAaIY7VdKIwUnhoWTzIg/x51KRwiOISOWtGgoSBr1T1U";

/// The fake shared by the test and every plugin run (one per op).
#[derive(Clone)]
struct SharedNas(Arc<Mutex<FakeNas>>);

impl Nas for SharedNas {
    fn datasets(&mut self, root: &str, recursive: bool) -> Result<Vec<Dataset>> {
        self.0.lock().unwrap().datasets(root, recursive)
    }
    fn snapshots(&mut self, ds: &str) -> Result<Vec<String>> {
        self.0.lock().unwrap().snapshots(ds)
    }
    fn create_snapshot(&mut self, ds: &str, name: &str, recursive: bool) -> Result<()> {
        self.0.lock().unwrap().create_snapshot(ds, name, recursive)
    }
    fn delete_snapshot(&mut self, ds: &str, name: &str) -> Result<()> {
        self.0.lock().unwrap().delete_snapshot(ds, name)
    }
}

/// Hostile TrueNAS side: a walk naming a path outside the snapshot.
struct EvilWalk(LocalFc);

impl Transport for EvilWalk {
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

#[derive(Clone)]
struct Fake {
    nas: SharedNas,
    fc: LocalFc,
    evil: Arc<Mutex<bool>>,
}

impl Connect for Fake {
    fn nas(&self, _c: &Config) -> Result<Box<dyn Nas>> {
        Ok(Box::new(self.nas.clone()))
    }
    fn transport(&self, _c: &Config) -> Result<Box<dyn Transport>> {
        Ok(if *self.evil.lock().unwrap() {
            Box::new(EvilWalk(self.fc.clone()))
        } else {
            Box::new(self.fc.clone())
        })
    }
}

fn config() -> Value {
    json!({
        "host": "truenas.test", "ca_pem": "-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n",
        "api_key": "1-test", "ssh_host": "truenas.test", "ssh_host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5",
        "ssh_private_key": TEST_KEY, "datasets": ["tank/data"], "recursive": true,
    })
}

struct Lab {
    _td: tempfile::TempDir,
    nas: Arc<Mutex<FakeNas>>,
    fake: Fake,
    host: Host,
    data: std::path::PathBuf,
}

fn lab() -> Lab {
    let td = tempfile::tempdir().unwrap();
    let (nas, fc, data) = fake(td.path());
    let nas = Arc::new(Mutex::new(nas));
    let fake = Fake {
        nas: SharedNas(nas.clone()),
        fc,
        evil: Arc::new(Mutex::new(false)),
    };
    let f = fake.clone();
    let mut host = Host::in_process(MANIFEST.as_ref(), "truenas", move || TrueNasPlugin {
        connect: f.clone(),
    })
    .unwrap();
    host.source_id = SID;
    Lab {
        _td: td,
        nas,
        fake,
        host,
        data,
    }
}

const SRC: &str = "plugin-truenas-7-tank.data";

fn ours(l: &Lab, ds: &str) -> Vec<String> {
    l.nas.lock().unwrap().snaps.get(ds).cloned().unwrap_or_default()
}

fn ago(ms: u64) {
    std::thread::sleep(std::time::Duration::from_millis(ms)); // next snapshot time
}

/// The data of the connector's own test (fake_truenas.rs) in round 1.
fn round1(d: &Path) -> bool {
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
    put(&d.join("child/c.txt"), b"child dataset\n");
    xattr_set(&d.join("docs/readme.txt"), "user.nexus", b"v1") && xattr_set(&d.join("docs"), "user.dir", b"d1")
}

/// Round 2: in-place edit (new object), file + directory rename, delete, new file, new hard link.
fn round2(d: &Path) {
    put(&d.join("docs/readme.txt"), b"hello truenas, changed\n");
    fs::rename(d.join("docs/sp ace"), d.join("docs/space-renamed")).unwrap();
    fs::rename(d.join("many"), d.join("renamed-many")).unwrap();
    fs::remove_file(d.join("docs/-dash")).unwrap();
    put(&d.join("docs/new.txt"), b"brand new\n");
    fs::hard_link(d.join("docs/new.txt"), d.join("hl/new-link")).unwrap();
}

#[test]
fn guests_and_validate() {
    let l = lab();
    let g = l.host.guests(&config()).unwrap();
    let ids: Vec<&str> = g["guests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["tank.data", "tank.data.child"], "{g}");
    let v = l.host.validate(&config()).unwrap();
    assert_eq!(v["valid"], true, "{v} {:?}", l.host.log());
    // the authorized_keys line for the configured datasets is logged
    let line = fc::authorized_keys(
        &Config::parse(&config()).unwrap().fc(),
        &Tools::default(),
        TEST_PUB,
        None,
    )
    .unwrap();
    assert!(
        l.host.log().iter().any(|x| x.contains(&line[..60])),
        "{:?}",
        l.host.log()
    );
    let mut bad = config();
    bad["datasets"] = json!(["tank/missing"]);
    let v = l.host.validate(&bad).unwrap();
    assert_eq!(
        (v["valid"].clone(), v["field"].clone()),
        (json!(false), json!("datasets")),
        "{v}"
    );
    let mut bad = config();
    bad["ssh_private_key"] = json!("-----BEGIN RSA PRIVATE KEY-----\nAA==\n-----END RSA PRIVATE KEY-----\n");
    let v = l.host.validate(&bad).unwrap();
    assert_eq!(v["field"], "ssh_private_key", "{v}");
}

#[test]
fn backup_incremental_rotation() {
    let l = lab();
    let d = l.data.clone();
    let xattrs = round1(&d);
    // snapshots that are not ours: never touched
    l.nas
        .lock()
        .unwrap()
        .create_snapshot("tank/data", "auto-2026-01-01", true)
        .unwrap();
    l.nas
        .lock()
        .unwrap()
        .create_snapshot("tank/data", "nexus-8-100", false)
        .unwrap();

    let b1 = l.host.backup(&config(), Some("tank.data")).unwrap();
    assert_eq!(b1.source, SRC);
    assert!(b1.base.is_none() && b1.consistent && b1.unchanged == 0, "{b1:?}");
    let t1 = tree(l.host.store(), SRC, b1.time, "files");
    assert_matches(l.host.store(), &t1, &d);
    if xattrs {
        let x = |p: &[u8], k: &[u8]| {
            t1.iter()
                .find(|e| e.path == p)
                .unwrap()
                .xattrs
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(x(b"docs/readme.txt", b"user.nexus").as_deref(), Some(&b"v1"[..]));
        assert_eq!(x(b"docs", b"user.dir").as_deref(), Some(&b"d1"[..]));
    }
    // the child's mount point is an empty directory; the child is its own guest
    assert!(t1.iter().any(|e| e.path == b"child") && !t1.iter().any(|e| e.path.starts_with(b"child/")));
    let c1 = l.host.backup(&config(), Some("tank.data.child")).unwrap();
    assert_matches(
        l.host.store(),
        &tree(l.host.store(), "plugin-truenas-7-tank.data.child", c1.time, "files"),
        &d.join("child"),
    );
    let s = ours(&l, "tank/data");
    assert_eq!(s[..2], ["auto-2026-01-01", "nexus-8-100"]);
    assert_eq!(s.len(), 3, "{s:?}");
    let snap1 = s[2].clone();
    assert!(snap1.starts_with("nexus-7-"));

    round2(&d);
    ago(1100);
    let b2 = l.host.backup(&config(), Some("tank.data")).unwrap();
    assert_eq!(b2.base, Some(b1.time));
    let t2 = tree(l.host.store(), SRC, b2.time, "files");
    assert_matches(l.host.store(), &t2, &d);
    // the 3 MiB file and the unchanged small files are not sent again; renamed paths
    // are (the host reuses data only for the same path), dedup keeps them stored once
    assert!(b2.unchanged >= 4, "{b2:?}");
    assert!(b2.transferred < 64 << 10, "{b2:?}");
    let big = |t: &[chunkstore::TreeEntry]| t.iter().find(|e| e.path == b"big/random.bin").unwrap().chunks.clone();
    assert!(big(&t1).len() > 1 && big(&t1) == big(&t2));
    if xattrs {
        assert!(t2.iter().any(|e| e.path == b"docs" && !e.xattrs.is_empty()));
    }
    // rotation one run later: the reference stays until the host committed the new one
    let s = ours(&l, "tank/data");
    assert_eq!(s.len(), 4, "{s:?}");
    assert!(s.contains(&snap1));
    let snap2 = s[3].clone();
    ago(1100);
    let b3 = l.host.backup(&config(), Some("tank.data")).unwrap();
    assert_eq!(b3.files, b3.unchanged, "no changes: everything unchanged {b3:?}");
    let s = ours(&l, "tank/data");
    assert_eq!(s[..3], ["auto-2026-01-01", "nexus-8-100", snap2.as_str()], "{s:?}");
    assert!(l
        .host
        .log()
        .iter()
        .any(|x| x.contains(&format!("deleted tank/data@{snap1}"))));
    let snap3 = s[3].clone();

    // lost reference (deleted on TrueNAS): full read, still correct
    l.nas.lock().unwrap().delete_snapshot("tank/data", &snap3).unwrap();
    put(&d.join("docs/after.txt"), b"after\n");
    ago(1100);
    let b4 = l.host.backup(&config(), Some("tank.data")).unwrap();
    assert_eq!(b4.unchanged, 0, "{b4:?}");
    assert_matches(l.host.store(), &tree(l.host.store(), SRC, b4.time, "files"), &d);
    assert!(l
        .host
        .log()
        .iter()
        .any(|s| s.contains("reference snapshot") && s.contains("is gone")));
}

/// Hostile walk output: the backup fails, nothing is committed, the new ZFS
/// snapshot is deleted and the reference stays.
#[test]
fn hostile_walk_fails_and_keeps_reference() {
    let l = lab();
    put(&l.data.join("a"), b"a");
    let b1 = l.host.backup(&config(), Some("tank.data")).unwrap();
    let before = ours(&l, "tank/data");
    *l.fake.evil.lock().unwrap() = true;
    ago(1100);
    let e = l.host.backup(&config(), Some("tank.data")).unwrap_err();
    assert!(format!("{e:#}").contains("invalid"), "{e:#}");
    assert_eq!(ours(&l, "tank/data"), before);
    let snaps = l.host.store().list_snapshots().unwrap();
    assert_eq!(snaps.iter().filter(|s| s.source == SRC).count(), 1);
    assert_eq!(snaps.iter().find(|s| s.source == SRC).unwrap().time, b1.time);
}

#[test]
fn refuses_wrong_guests_and_restores() {
    let l = lab();
    for g in [None, Some("tank.smb"), Some("tank.database")] {
        let e = l.host.backup(&config(), g).unwrap_err();
        assert!(format!("{e:#}").contains("(22)"), "{g:?}: {e:#}");
    }
    put(&l.data.join("a"), b"a");
    let b = l.host.backup(&config(), Some("tank.data")).unwrap();
    let e = l
        .host
        .restore(&config(), &b.source, b.time, "to_target", json!({}))
        .unwrap_err();
    assert!(
        format!("{e:#}").contains("not offered") || format!("{e:#}").contains("download"),
        "{e:#}"
    );
}

// ---- the real binary in the real sandbox -------------------------------------------

/// Minimal TrueNAS JSON-RPC 2.0 server over wss (the five methods the plugin uses), backed by the fake.
fn api_server(nas: Arc<Mutex<FakeNas>>) -> (u16, String) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = ck.cert.pem();
    let cfg = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![ck.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(ck.key_pair.serialize_der().into()),
            )
            .unwrap(),
    );
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for tcp in l.incoming().flatten() {
            let tls = rustls::StreamOwned::new(rustls::ServerConnection::new(cfg.clone()).unwrap(), tcp);
            let Ok(mut ws) = tungstenite::accept(tls) else { continue };
            while let Ok(m) = ws.read() {
                let tungstenite::Message::Text(t) = m else { continue };
                let req: Value = serde_json::from_str(t.as_str()).unwrap();
                let p = &req["params"];
                let mut n = nas.lock().unwrap();
                let r: Result<Value> = match req["method"].as_str().unwrap() {
                    "auth.login_ex" => Ok(json!({"response_type": "SUCCESS"})),
                    "pool.dataset.query" => {
                        let rec = p[0][0][0] == "OR";
                        let root = if rec { &p[0][0][1][0][2] } else { &p[0][0][2] };
                        n.datasets(root.as_str().unwrap(), rec).map(|l| {
                            l.into_iter()
                                .map(|d| {
                                    json!({"id": d.name, "type": "FILESYSTEM", "mounted": {"parsed": true},
                                                "mountpoint": {"value": d.mountpoint}})
                                })
                                .collect()
                        })
                    }
                    "pool.snapshot.query" => {
                        let ds = p[0][0][2].as_str().unwrap().to_owned();
                        n.snapshots(&ds).map(|l| {
                            l.into_iter()
                                .map(|s| json!({"id": format!("{ds}@{s}"), "dataset": ds, "snapshot_name": s}))
                                .collect()
                        })
                    }
                    "pool.snapshot.create" => n
                        .create_snapshot(
                            p[0]["dataset"].as_str().unwrap(),
                            p[0]["name"].as_str().unwrap(),
                            p[0]["recursive"].as_bool().unwrap(),
                        )
                        .map(|_| json!({})),
                    "pool.snapshot.delete" => {
                        let (ds, s) = p[0].as_str().unwrap().split_once('@').unwrap();
                        n.delete_snapshot(ds, s).map(|_| json!(true))
                    }
                    m => Err(anyhow::anyhow!("method {m} not allowed")),
                };
                let ans = match r {
                    Ok(v) => json!({"jsonrpc": "2.0", "id": req["id"], "result": v}),
                    Err(e) => json!({"jsonrpc": "2.0", "id": req["id"], "error": {"message": format!("{e:#}")}}),
                };
                if ws.send(tungstenite::Message::text(ans.to_string())).is_err() {
                    break;
                }
            }
        }
    });
    (port, cert_pem)
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn whoami() -> String {
    let o = Command::new("id").arg("-un").output().unwrap();
    String::from_utf8(o.stdout).unwrap().trim().to_owned()
}

struct Sshd(std::process::Child);

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn sandboxed_binary_over_wss_and_ssh() {
    let sshd_bin = Path::new("/usr/sbin/sshd");
    let keygen = |p: &Path| {
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "", "-f"])
            .arg(p)
            .status()
            .is_ok_and(|s| s.success())
    };
    let td = tempfile::tempdir().unwrap();
    let k = td.path().join("keys");
    fs::create_dir_all(&k).unwrap();
    if !sshd_bin.exists() || !keygen(&k.join("host")) || !keygen(&k.join("client")) {
        eprintln!("OpenSSH server/ssh-keygen not available: skipped");
        return;
    }
    let (nas, _, data) = fake(&td.path().join("nas"));
    let nas = Arc::new(Mutex::new(nas));
    let (api_port, cert_pem) = api_server(nas.clone());
    // an unprivileged sshd running the forced command (the fake's zfs stub, no sudo)
    let fc_line = fc::authorized_keys(
        &Fc {
            datasets: vec!["tank/data".into()],
            recursive: true,
            sudo: false,
            zfs_sudo: false,
        },
        &Tools {
            zfs: td.path().join("nas/bin/zfs").to_str().unwrap().to_owned(),
            ..Tools::default()
        },
        fs::read_to_string(k.join("client.pub")).unwrap().trim(),
        Some("127.0.0.1"),
    )
    .unwrap();
    fs::write(k.join("authorized_keys"), format!("{fc_line}\n")).unwrap();
    let ssh_port = free_port();
    fs::write(
        k.join("sshd_config"),
        format!(
            "Port {ssh_port}\nListenAddress 127.0.0.1\nHostKey {0}/host\nPidFile none\nAuthorizedKeysFile {0}/authorized_keys\n\
             StrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n",
            k.display()
        ),
    )
    .unwrap();
    let _sshd = Sshd(
        Command::new(sshd_bin)
            .args(["-D", "-e", "-f"])
            .arg(k.join("sshd_config"))
            .stderr(fs::File::create(k.join("sshd.log")).unwrap())
            .spawn()
            .unwrap(),
    );
    for _ in 0..50 {
        if std::net::TcpStream::connect(("127.0.0.1", ssh_port)).is_ok() {
            break;
        }
        ago(100);
    }
    let cfg = json!({
        "host": "127.0.0.1", "port": api_port, "ca_pem": cert_pem, "api_key": "1-test",
        // an unprivileged sshd only logs in its own user
        "ssh_host": "127.0.0.1", "ssh_port": ssh_port, "ssh_user": whoami(),
        "ssh_host_key": fs::read_to_string(k.join("host.pub")).unwrap().trim(),
        "ssh_private_key": fs::read_to_string(k.join("client")).unwrap(),
        "datasets": ["tank/data"], "recursive": true, "sudo": false, "zfs_sudo": false,
    });
    let mut h = Host::binary(
        MANIFEST.as_ref(),
        env!("CARGO_BIN_EXE_truenas-plugin").as_ref(),
        "truenas",
    )
    .unwrap();
    h.source_id = SID;
    let sshd_log = || fs::read_to_string(k.join("sshd.log")).unwrap_or_default();
    let v = h.validate(&cfg).unwrap();
    assert_eq!(v["valid"], true, "{v}\n{:#?}\n{}", h.log(), sshd_log());
    let g = h.guests(&cfg).unwrap();
    assert_eq!(g["guests"].as_array().unwrap().len(), 2, "{g}");

    let xattrs = round1(&data);
    let b1 = h.backup(&cfg, Some("tank.data")).unwrap();
    let t1 = tree(h.store(), SRC, b1.time, "files");
    assert_matches(h.store(), &t1, &data);
    if xattrs {
        assert!(t1.iter().any(|e| e.path == b"docs" && !e.xattrs.is_empty()));
    }
    round2(&data);
    ago(1100);
    let b2 = h.backup(&cfg, Some("tank.data")).unwrap();
    assert!(b2.unchanged >= 4 && b2.transferred < 64 << 10, "{b2:?}");
    assert_matches(h.store(), &tree(h.store(), SRC, b2.time, "files"), &data);
    let s = nas.lock().unwrap().snaps["tank/data"].clone();
    assert_eq!(s.len(), 2, "{s:?}");
    // the plugin really ran sandboxed (the host's spawn report is the first log line)
    assert!(h.log().iter().any(|l| l.contains("landlock")), "{:?}", h.log());
}
