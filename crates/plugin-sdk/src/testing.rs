//! Test harness (feature `testing`): runs a plugin — its real binary in the real
//! sandbox, or in-process on a thread — against the real host code
//! (crate `plugin-host`) and a real chunk store in a temp dir.
//!
//! ```ignore
//! # use plugin_sdk::testing::Host;
//! let h = Host::binary("manifest.json".as_ref(), env!("CARGO_BIN_EXE_my-plugin").as_ref(), "mykind").unwrap();
//! let cfg = serde_json::json!({"path": "/data"});
//! assert_eq!(h.validate(&cfg).unwrap()["valid"], true);
//! let b = h.backup(&cfg, None).unwrap();
//! let r = h.restore(&cfg, &b.source, b.time, "to_dir", serde_json::json!({"target": "/tmp/x"})).unwrap();
//! ```

use crate::Plugin;
use anyhow::{bail, Context, Result};
use chunkstore::{Keyring, Options, Store};
use plugin_host::backup::{self, Bounds};
use plugin_host::inproc::InProc;
use plugin_host::ops;
use plugin_host::restore::{self, Snapshot};
use plugin_host::sandbox::{Limits, Options as SandboxOptions, Peer, PluginProc, Spec};
use plugin_proto::{source_name, Manifest};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

type Make = Arc<
    dyn Fn() -> Box<dyn FnOnce(Box<dyn std::io::Read + Send>, Box<dyn std::io::Write + Send>) + Send> + Send + Sync,
>;

enum Launch {
    Binary {
        dir: PathBuf,
        sha: String,
        manifest: String,
    },
    InProcess(Make),
}

/// A host with its own temp store for one plugin kind.
pub struct Host {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    store: Store,
    launch: Launch,
    manifest: Manifest,
    pub kind: String,
    /// sandbox: extra readable / writable paths (the data a test plugin reads, restore targets)
    pub read_paths: Vec<PathBuf>,
    pub write_paths: Vec<PathBuf>,
    pub timeout: Duration,
    pub idle: Duration,
    pub source_id: u64,
    log: RefCell<Vec<String>>,
    job: RefCell<u64>,
}

impl Host {
    fn new(launch: Launch, manifest: Manifest, kind: &str) -> Result<Host> {
        if !manifest.kinds.iter().any(|k| k.kind == kind) {
            bail!("manifest has no kind {kind}");
        }
        let tmp = tempfile::tempdir()?;
        let root = tmp.path().to_owned();
        fs::create_dir_all(root.join("tmp"))?;
        let store = Store::open(
            root.join("store"),
            Keyring::new("test", &[(1, [42; 32])]),
            Options::default(),
        )?;
        Ok(Host {
            _tmp: tmp,
            root,
            store,
            launch,
            manifest,
            kind: kind.into(),
            read_paths: Vec::new(),
            write_paths: Vec::new(),
            timeout: Duration::from_secs(120),
            idle: Duration::from_secs(60),
            source_id: 1,
            log: RefCell::new(Vec::new()),
            job: RefCell::new(0),
        })
    }

    /// The plugin binary in the real sandbox (installed into a temp plugins dir).
    pub fn binary(manifest: &Path, bin: &Path, kind: &str) -> Result<Host> {
        let raw = fs::read_to_string(manifest).with_context(|| format!("{}", manifest.display()))?;
        let m: Manifest = serde_json::from_str(&raw)?;
        m.validate().map_err(anyhow::Error::msg)?;
        let b = fs::read(bin).with_context(|| format!("{}", bin.display()))?;
        let mut h = Host::new(
            Launch::Binary {
                dir: PathBuf::new(),
                sha: String::new(),
                manifest: raw.clone(),
            },
            m.clone(),
            kind,
        )?;
        let dir = h.root.join("plugins").join(&m.id).join(&m.version);
        fs::create_dir_all(dir.join("bin"))?;
        fs::write(dir.join("manifest.json"), &raw)?;
        fs::write(dir.join("bin/plugin"), &b)?;
        fs::set_permissions(dir.join("bin/plugin"), fs::Permissions::from_mode(0o755))?;
        use sha2::Digest;
        let sha = sha2::Sha256::digest(&b).iter().map(|x| format!("{x:02x}")).collect();
        h.launch = Launch::Binary {
            dir,
            sha,
            manifest: raw,
        };
        Ok(h)
    }

    /// The plugin in-process (no sandbox; quick unit tests of plugin logic).
    pub fn in_process<P: Plugin + 'static>(
        manifest: &Path,
        kind: &str,
        make: impl Fn() -> P + Send + Sync + 'static,
    ) -> Result<Host> {
        let raw = fs::read_to_string(manifest)?;
        let m: Manifest = serde_json::from_str(&raw)?;
        m.validate().map_err(anyhow::Error::msg)?;
        let make = Arc::new(make);
        let f: Make = Arc::new(move || {
            let make = make.clone();
            Box::new(move |r, w| {
                crate::run_with(make(), r, w);
            })
        });
        Host::new(Launch::InProcess(f), m, kind)
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Job log lines so far (host output incl. the escaped plugin log).
    pub fn log(&self) -> Vec<String> {
        self.log.borrow().clone()
    }

    fn peer(&self, config: &Value, op_secs: Duration) -> Result<Box<dyn Peer>> {
        *self.job.borrow_mut() += 1;
        Ok(match &self.launch {
            Launch::Binary { dir, sha, manifest } => {
                let spec = Spec {
                    dir: dir.clone(),
                    bin_sha256: sha.clone(),
                    manifest: Some(manifest.clone()),
                    tcp_ports: Some(self.ports(config)),
                    limits: Limits::from_manifest(self.manifest.sandbox.as_ref(), op_secs.as_secs()),
                    job: *self.job.borrow(),
                };
                let opts = SandboxOptions {
                    tmp_base: self.root.join("tmp"),
                    read_paths: self.read_paths.clone(),
                    write_paths: self.write_paths.clone(),
                    ..Default::default()
                };
                let p = PluginProc::spawn(&spec, &opts, op_secs, Some(self.idle))?;
                self.log.borrow_mut().push(p.report.to_string());
                Box::new(p)
            }
            Launch::InProcess(f) => Box::new(InProc::start(f(), op_secs, Some(self.idle))?),
        })
    }

    /// As `nexus-pluginhost`: the endpoint ports resolved in the source config.
    fn ports(&self, config: &Value) -> Vec<u16> {
        let net = self.manifest.sandbox.as_ref().and_then(|s| s["network"].as_str());
        if net == Some("none") {
            return Vec::new();
        }
        self.manifest
            .kinds
            .iter()
            .find(|k| k.kind == self.kind)
            .map(|k| k.tcp_ports(config))
            .unwrap_or_default()
    }

    fn out(&self) -> impl FnMut(&str) + '_ {
        move |l: &str| self.log.borrow_mut().push(l.to_owned())
    }

    fn ops_params<'a>(&'a self, cfg: &'a str) -> ops::Params<'a> {
        ops::Params {
            job: *self.job.borrow(),
            kind: &self.kind,
            config: cfg,
        }
    }

    pub fn validate(&self, config: &Value) -> Result<Value> {
        let cfg = config.to_string();
        let mut p = self.peer(config, self.timeout)?;
        ops::validate(p.as_mut(), &self.ops_params(&cfg), &mut self.out())
    }

    pub fn guests(&self, config: &Value) -> Result<Value> {
        let cfg = config.to_string();
        let mut p = self.peer(config, self.timeout)?;
        ops::guests(p.as_mut(), &self.ops_params(&cfg), &mut self.out())
    }

    /// One backup → `plugin-<id>-<source_id>[-<guest>]` snapshot.
    pub fn backup(&self, config: &Value, guest: Option<&str>) -> Result<backup::Report> {
        let cfg = config.to_string();
        let source = source_name(&self.manifest.id, self.source_id, guest);
        let mut p = self.peer(config, self.timeout)?;
        backup::run(
            &self.store,
            p.as_mut(),
            &backup::Params {
                job: *self.job.borrow(),
                kind: &self.kind,
                config: &cfg,
                params: json!({ "guest": guest }),
                source: &source,
                bounds: Bounds::default(),
            },
            &mut self.out(),
        )
    }

    pub fn snapshot(&self, source: &str, time: u64) -> Result<Snapshot> {
        Snapshot::load(&self.store, source, time)
    }

    pub fn restore(
        &self,
        config: &Value,
        source: &str,
        time: u64,
        restore_id: &str,
        params: Value,
    ) -> Result<restore::Report> {
        let cfg = config.to_string();
        let snap = self.snapshot(source, time)?;
        let mut p = self.peer(config, self.timeout)?;
        restore::run(
            &self.store,
            p.as_mut(),
            &snap,
            &restore::Params {
                job: *self.job.borrow(),
                kind: &self.kind,
                config: &cfg,
                restore: restore_id,
                params,
                max_log_bytes: 4 << 20,
            },
            &mut self.out(),
        )
    }

    pub fn mount(&self, config: &Value, source: &str, time: u64, params: Value, duration: Duration) -> Result<Value> {
        let cfg = config.to_string();
        let snap = self.snapshot(source, time)?;
        let mut p = self.peer(config, self.timeout + duration)?;
        ops::mount(
            &self.store,
            p.as_mut(),
            &snap,
            &self.ops_params(&cfg),
            params,
            duration,
            &mut self.out(),
        )
    }
}
