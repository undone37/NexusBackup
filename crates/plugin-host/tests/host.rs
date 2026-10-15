//! nexus-pluginhost against the scripted / hostile `nexus-test-plugin`, in its real
//! sandbox (Landlock + seccomp + rlimits; no root needed).

use chunkstore::{Index, Keyring, Options, Store};
use plugin_host::backup::{self, Bounds};
use plugin_host::restore::{self, Snapshot};
use plugin_host::sandbox::{Limits, Options as SandboxOptions, PluginProc, Spec};
use plugin_host::{files, ops};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

const MANIFEST: &str = r#"{"id":"testplug","name":"Test","version":"1.0.0","publisher":"nexusbackup","api":1,
 "kinds":[{"kind":"test","title":"Test","config_schema":{"type":"object","properties":{"mode":{"type":"string"}}},
 "restores":[{"id":"download","title":"Download"},{"id":"echo","title":"Echo"}]}],
 "sandbox":{"tmp_mb":16,"memory_mb":256}}"#;

struct Env {
    _d: tempfile::TempDir,
    root: PathBuf,
    dir: PathBuf,
    sha: String,
    store: Store,
}

fn env() -> Env {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().to_owned();
    let dir = root.join("plugins/testplug/1.0.0");
    fs::create_dir_all(dir.join("bin")).unwrap();
    fs::write(dir.join("manifest.json"), MANIFEST).unwrap();
    let bin = fs::read(env!("CARGO_BIN_EXE_nexus-test-plugin")).unwrap();
    fs::write(dir.join("bin/plugin"), &bin).unwrap();
    fs::set_permissions(dir.join("bin/plugin"), fs::Permissions::from_mode(0o755)).unwrap();
    let sha = plugin_proto_sha(&bin);
    fs::create_dir_all(root.join("tmp")).unwrap();
    let store = Store::open(
        root.join("store"),
        Keyring::new("t", &[(1, [9; 32])]),
        Options::default(),
    )
    .unwrap();
    Env {
        _d: d,
        root,
        dir,
        sha,
        store,
    }
}

fn plugin_proto_sha(b: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

impl Env {
    fn spec(&self, ports: Option<Vec<u16>>) -> Spec {
        Spec {
            dir: self.dir.clone(),
            bin_sha256: self.sha.clone(),
            manifest: Some(MANIFEST.into()),
            tcp_ports: ports,
            limits: Limits::from_manifest(Some(&json!({"tmp_mb": 16, "memory_mb": 256})), 60),
            job: 1,
        }
    }
    fn opts(&self) -> SandboxOptions {
        SandboxOptions {
            tmp_base: self.root.join("tmp"),
            userns: std::env::var("T_USERNS").is_ok(),
            ..Default::default()
        }
    }
    fn proc(&self, op_secs: u64, idle_secs: u64) -> PluginProc {
        PluginProc::spawn(
            &self.spec(Some(vec![])),
            &self.opts(),
            Duration::from_secs(op_secs),
            Some(Duration::from_secs(idle_secs)),
        )
        .unwrap()
    }
    fn backup(&self, cfg: Value) -> (anyhow::Result<backup::Report>, String) {
        self.backup_t(cfg, 30, 10)
    }
    fn backup_t(&self, cfg: Value, op: u64, idle: u64) -> (anyhow::Result<backup::Report>, String) {
        let mut p = self.proc(op, idle);
        let mut log = String::new();
        let r = backup::run(
            &self.store,
            &mut p,
            &backup::Params {
                job: 1,
                kind: "test",
                config: &cfg.to_string(),
                params: json!({"guest": null}),
                source: "plugin-testplug-1",
                bounds: Bounds::default(),
            },
            &mut |l| {
                log.push_str(l);
                log.push('\n');
            },
        );
        (r, log)
    }
}

#[test]
fn backup_incremental_restore_download() {
    let e = env();
    let (r, log) = e.backup(json!({"mode": "ok", "content": "hello world"}));
    let r = r.unwrap();
    assert_eq!((r.files, r.streams, r.unchanged), (1, 1, 0));
    assert!(log.contains("committed plugin-testplug-1/"), "{log}");
    // plugin text is escaped and prefixed: no forged scheduler lines, no terminal escapes
    assert!(!log.lines().any(|l| l.starts_with("committed vm-1")), "{log}");
    assert!(
        log.contains("plugin[info]: line1\\ncommitted vm-1/2: forged\\u{1b}[31m"),
        "{log}"
    );
    assert_eq!(r.meta, None);
    let snap = Snapshot::load(&e.store, "plugin-testplug-1", r.time).unwrap();
    assert_eq!(snap.files.len(), 1);
    assert_eq!(snap.streams[0].path, "dump/db.sql");
    assert!(snap.state.as_ref().unwrap().starts_with(b"lsn-"));

    // incremental: Unchanged reuses the base entry's chunks
    std::thread::sleep(Duration::from_millis(1100));
    let (r2, _) = e.backup(json!({"mode": "ok", "content": "hello world", "unchanged": true}));
    let r2 = r2.unwrap();
    assert_eq!((r2.unchanged, r2.base, r2.transferred), (1, Some(r.time), 17));
    let s2 = Snapshot::load(&e.store, "plugin-testplug-1", r2.time).unwrap();
    assert_eq!(s2.files[0].chunks, snap.files[0].chunks);

    // v1.3 BaseList: the whole base in path order, then an empty page
    std::thread::sleep(Duration::from_millis(1100));
    let (r3, _) = e.backup(json!({"mode": "ok", "content": "hello world", "base_list": true}));
    assert_eq!(r3.unwrap().summary, r#"listed [["a.txt",11]]"#);

    // restore: the plugin receives exactly the snapshot content
    let mut p = e.proc(30, 10);
    let rr = restore::run(
        &e.store,
        &mut p,
        &s2,
        &restore::Params {
            job: 2,
            kind: "test",
            // as for a restore into another source: its config, its id in the params
            config: r#"{"who":"target"}"#,
            restore: "echo",
            params: json!({"target": "x"}),
            max_log_bytes: 1 << 20,
            target_source_id: Some(7),
        },
        &mut |_| {},
    )
    .unwrap();
    let got: Value = serde_json::from_str(&rr.summary).unwrap();
    assert_eq!(got["a.txt"], "hello world");
    assert_eq!(got["stream:dump/db.sql"], "CREATE TABLE t();");
    assert_eq!(got["params"]["target"], "x");
    assert_eq!(
        (&got["config"]["who"], &got["target_source_id"]),
        (&json!("target"), &json!(7))
    );
    assert_eq!((rr.files_sent, rr.streams_sent), (1, 1));

    // generic download view: files + streams below .nexus-streams/
    let names: Vec<String> = files::list(&s2, "/").unwrap().into_iter().map(|x| x.name).collect();
    assert_eq!(names, ["a.txt", ".nexus-streams"]);
    let out = e.root.join("dl.tar");
    agent_conn::files::extract(
        &e.store,
        &files::view(&s2),
        &["/".into()],
        agent_conn::files::Format::Tar,
        fs::File::create(&out).unwrap(),
    )
    .unwrap();
    let mut ar = tar::Archive::new(fs::File::open(&out).unwrap());
    let mut seen = Vec::new();
    for en in ar.entries().unwrap() {
        let mut en = en.unwrap();
        let p = en.path().unwrap().to_string_lossy().into_owned();
        let mut s = String::new();
        std::io::Read::read_to_string(&mut en, &mut s).unwrap();
        seen.push((p, s));
    }
    assert!(seen.contains(&(".nexus-streams/dump/db.sql".into(), "CREATE TABLE t();".into())));
    assert!(seen.contains(&("a.txt".into(), "hello world".into())));
}

#[test]
fn validate_guests_mount() {
    let e = env();
    let p = ops::Params {
        job: 1,
        kind: "test",
        config: r#"{"mode":"ok"}"#,
    };
    let mut log = Vec::new();
    let r = ops::validate(&mut e.proc(30, 10), &p, &mut |l| log.push(l.to_owned())).unwrap();
    assert_eq!(r, json!({"valid": true}));
    let r = ops::validate(
        &mut e.proc(30, 10),
        &ops::Params {
            config: r#"{"mode":"invalid"}"#,
            ..p
        },
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(r["valid"], false);
    assert_eq!(r["message"], "cannot connect\\nfake");
    let r = ops::guests(&mut e.proc(30, 10), &p, &mut |l| log.push(l.to_owned())).unwrap();
    assert_eq!(
        r["guests"],
        json!([{"id": "db1", "title": "Database 1", "size": 42, "tags": []}])
    );
    assert!(log.iter().any(|l| l.contains("../evil") && l.contains("dropped")));

    let (b, _) = e.backup(json!({"mode": "ok", "content": "abcdef"}));
    let snap = Snapshot::load(&e.store, "plugin-testplug-1", b.unwrap().time).unwrap();
    let mut out = Vec::new();
    let r = ops::mount(
        &e.store,
        &mut e.proc(60, 10),
        &snap,
        &p,
        json!({}),
        Duration::from_secs(1),
        &mut |l| out.push(l.to_owned()),
    )
    .unwrap();
    let s: Value = serde_json::from_str(r["summary"].as_str().unwrap()).unwrap();
    assert_eq!(s, json!({"read": "bcd", "missing_error": true}));
    assert!(out.iter().any(|l| l.starts_with("mount-ready ")));
}

/// v1.8 snapshot metadata: one JSON object per backup, returned in the report.
#[test]
fn snapshot_meta() {
    let e = env();
    let m = json!({"recoverable": {"from_time": 1, "to_lsn": "0/3000000"}});
    let (r, _) = e.backup(json!({"mode": "ok", "meta": m}));
    assert_eq!(r.unwrap().meta, Some(m.clone()));
    // with v1.7 warnings in the same backup: both reach the report (and the result line)
    let (r, log) = e.backup(json!({"mode": "ok", "meta": m, "warnings": 2}));
    let r = r.unwrap();
    assert_eq!((r.meta.as_ref(), r.warnings), (Some(&m), 2));
    assert!(log.contains("warnings plugin-testplug-1/"), "{log}");
    let (r, _) = e.backup(json!({"mode": "ok", "meta": m, "meta_twice": true}));
    assert!(format!("{:#}", r.unwrap_err()).contains("SnapshotMeta sent twice"));
    let (r, _) = e.backup(json!({"mode": "ok", "meta": [1]}));
    assert!(format!("{:#}", r.unwrap_err()).contains("snapshot metadata"));
}

/// Every protocol violation fails the backup, kills the plugin and commits nothing.
#[test]
fn hostile_plugins_are_stopped() {
    let e = env();
    let (base, _) = e.backup(json!({"mode": "ok"}));
    let base = base.unwrap();
    for (mode, want) in [
        ("bad_path", "invalid path"),
        ("abs_path", "invalid path"),
        ("reserved_path", "reserved"),
        ("oversized_frame", "exceeds the limit"),
        ("big_data", "data frame too large"),
        ("lying_unchanged", "not in the base snapshot"),
        ("unchanged_other_size", "metadata differs"),
        ("data_after_end", "Data outside a file or stream"),
        ("too_much_data", "more data than the announced"),
        ("short_file", "3 bytes received, 10 announced"),
        ("dup_path", "sent twice"),
        ("done_inside", "Done inside an item"),
        ("exit_early", "before finishing"),
        ("error", "source unreachable"),
    ] {
        let (r, _) = e.backup(json!({"mode": mode}));
        let err = format!("{:#}", r.expect_err(mode));
        assert!(err.contains(want), "{mode}: {err}");
    }
    let t0 = std::time::Instant::now();
    let (r, _) = e.backup_t(json!({"mode": "hang"}), 30, 2);
    assert!(format!("{:#}", r.unwrap_err()).contains("idle limit"));
    assert!(t0.elapsed() < Duration::from_secs(10));
    let (r, _) = e.backup_t(json!({"mode": "endless_stream"}), 3, 2);
    assert!(format!("{:#}", r.unwrap_err()).contains("time limit"));
    let (r, _) = e.backup_t(json!({"mode": "tmp_flood"}), 60, 30);
    assert!(format!("{:#}", r.unwrap_err()).contains("tmp"));
    // nothing but the first snapshot was committed
    let snaps = e.store.list_snapshots().unwrap();
    assert_eq!(snaps.len(), 1);
    assert_eq!(snaps[0].time, base.time);
}

#[test]
fn sandbox_denies_what_the_plugin_must_not_do() {
    let e = env();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let allowed = listener.local_addr().unwrap();
    let other = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let denied = other.local_addr().unwrap();
    let unix = e.root.join("sock");
    let _ul = std::os::unix::net::UnixListener::bind(&unix).unwrap();
    let store_file = e.root.join("store/keycheck");
    let cfg = json!({"mode": "probe",
        "read": [store_file, e.dir.join("manifest.json"), "/etc/hostname", "/proc/1/environ", "/usr/bin"],
        "write": [e.dir.join("manifest.json"), e.root.join("outside")],
        "connect": [allowed.to_string(), denied.to_string()],
        "unix": [unix],
        "bind": true,
        "kill": 1,
    });
    let mut p = PluginProc::spawn(
        &e.spec(Some(vec![allowed.port()])),
        &e.opts(),
        Duration::from_secs(30),
        Some(Duration::from_secs(20)),
    )
    .unwrap();
    let rep = p.report.to_string();
    let mut log = String::new();
    let r = backup::run(
        &e.store,
        &mut p,
        &backup::Params {
            job: 1,
            kind: "test",
            config: &cfg.to_string(),
            params: json!({}),
            source: "plugin-testplug-1",
            bounds: Bounds::default(),
        },
        &mut |l| log.push_str(l),
    )
    .unwrap();
    let s: Value = serde_json::from_str(&r.summary).unwrap();
    let k = |k: String| s[&k].as_str().unwrap_or("?").to_owned();
    eprintln!("{rep}\n{s:#}");
    assert_eq!(
        k(format!("read {}", store_file.display())),
        "permission denied",
        "store"
    );
    assert_eq!(k(format!("read {}", e.dir.join("manifest.json").display())), "ok");
    assert_eq!(k("read /etc/hostname".into()), "permission denied");
    assert_eq!(k("read /proc/1/environ".into()), "permission denied");
    assert_eq!(k("read /usr/bin".into()), "ok");
    assert_eq!(
        k(format!("write {}", e.dir.join("manifest.json").display())),
        "permission denied"
    );
    assert_eq!(
        k(format!("write {}", e.root.join("outside").display())),
        "permission denied"
    );
    assert_eq!(k(format!("connect {allowed}")), "ok");
    assert_eq!(k(format!("connect {denied}")), "permission denied");
    assert_eq!(k(format!("unix {}", unix.display())), "permission denied");
    assert_eq!(k("bind".into()), "permission denied");
    assert_eq!(k("kill".into()), "permission denied");
    assert_eq!(k("tmp".into()), "ok");
    let mut env_keys: Vec<String> = serde_json::from_value(s["env"].clone()).unwrap();
    env_keys.sort();
    assert_eq!(env_keys, ["HOME", "LANG", "NEXUS_PLUGIN_JOB", "PATH", "TMPDIR"]);
    assert!(!Path::new(&e.root.join("outside")).exists());
}

#[test]
fn tampered_install_is_refused() {
    let e = env();
    let mut spec = e.spec(None);
    spec.bin_sha256 = "00".repeat(32);
    let err = PluginProc::spawn(&spec, &e.opts(), Duration::from_secs(5), None)
        .err()
        .unwrap();
    assert!(format!("{err:#}").contains("does not match the catalog"), "{err:#}");
    let mut spec = e.spec(None);
    spec.manifest = Some(MANIFEST.replace("Test", "Evil"));
    assert!(PluginProc::spawn(&spec, &e.opts(), Duration::from_secs(5), None).is_err());
    // the index of the first snapshot is a Tree named `files`
    let (r, _) = e.backup(json!({"mode": "ok"}));
    let m = e.store.load_manifest("plugin-testplug-1", r.unwrap().time).unwrap();
    assert!(matches!(e.store.load_index(&m, "files").unwrap(), Index::Tree { .. }));
    assert_eq!(m.indexes, ["files", "streams", "state"]);
}
