//! `nexus-nas <config.json> backup | check | files <share-source> <time> ls <dir> |
//! files <share-source> <time> get <out.tar|out.zip> <path>...`
//!
//! Spawned by the scheduler with a generated 0600 config (docs/nas-connector.md).
//! The share comes from the mount helper (`mount_socket`) as a detached
//! read-only mount fd; `local_root` (tests, dev lab) scans a local directory
//! instead. Machine-readable lines on stdout: `committed share-<id>/<time> …`,
//! `inconsistent share-<id>/<time>: …` (no NAS snapshot, files changed while
//! read, or unreadable entries), `result {json}`; `files … ls` prints the JSON
//! listing only.

use agent_conn::files::{self, Format};
use anyhow::{bail, Context, Result};
use chunkstore::{Options, Store};
use nas::backup::{self, Snap, Spec};
use nas::mount::{self, Order};
use nas::proto::{Fs, Request, Sec};
use nas::{parse_source_name, scan, sys};
use serde::Deserialize;
use serde_json::json;
use std::fs;
use std::net::{IpAddr, ToSocketAddrs};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    tenant: String,
    #[serde(default)]
    store: Option<PathBuf>,
    #[serde(default)]
    keyd_socket: Option<PathBuf>,
    source_id: u64,
    #[serde(default)]
    share: Option<ShareCfg>,
    #[serde(default = "socket")]
    mount_socket: PathBuf,
    /// tests / dev lab only: scan this directory instead of mounting
    #[serde(default)]
    local_root: Option<PathBuf>,
    #[serde(default)]
    snapshot_dir: Option<String>,
    #[serde(default)]
    snapshot_prefix: String,
    #[serde(default = "name_order")]
    snapshot_order: String,
    #[serde(default)]
    excludes: Vec<String>,
    #[serde(default = "threads")]
    threads: usize,
    #[serde(default = "yes")]
    xattrs: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShareCfg {
    kind: String,
    host: String,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    export: String,
    #[serde(default)]
    mount_port: Option<u16>,
    #[serde(default)]
    share: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    domain: String,
    #[serde(default)]
    sec: Option<String>,
    #[serde(default = "yes")]
    sign: bool,
    #[serde(default)]
    seal: bool,
    #[serde(default)]
    password_file: Option<PathBuf>,
    #[serde(default)]
    keytab_file: Option<PathBuf>,
    #[serde(default)]
    principal: Option<String>,
    #[serde(default = "timeout")]
    timeout_secs: u32,
}

fn socket() -> PathBuf {
    nas::MOUNT_SOCKET.into()
}
fn name_order() -> String {
    "name".into()
}
fn threads() -> usize {
    16
}
fn yes() -> bool {
    true
}
fn timeout() -> u32 {
    60
}

fn resolve(host: &str, port: u16) -> Result<IpAddr> {
    if let Ok(a) = host.parse::<IpAddr>() {
        return Ok(a);
    }
    let addrs: Vec<IpAddr> = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolving {host}"))?
        .map(|a| a.ip())
        .collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or(addrs.first())
        .copied()
        .with_context(|| format!("{host} has no address"))
}

impl ShareCfg {
    fn request(&self) -> Result<Request> {
        let secret = |p: &Option<PathBuf>, what: &str| -> Result<Option<Vec<u8>>> {
            p.as_ref()
                .map(|p| fs::read(p).with_context(|| format!("{what} file")))
                .transpose()
        };
        let mut r = match self.kind.as_str() {
            "nfs" => {
                let mut r = Request::nfs(
                    &self.host,
                    resolve(&self.host, self.port.unwrap_or(2049))?,
                    &self.export,
                );
                if let Some(v) = &self.version {
                    r.version = v.clone();
                }
                if let Some(p) = self.mount_port {
                    r.mount_port = p;
                }
                r
            }
            "smb" => {
                let mut r = Request::smb(
                    &self.host,
                    resolve(&self.host, self.port.unwrap_or(445))?,
                    &self.share,
                    &self.user,
                    "",
                );
                // one trailing newline of the file is not part of the password
                r.password = secret(&self.password_file, "password")?
                    .map(|p| String::from_utf8(p).context("password is not UTF-8"))
                    .transpose()?
                    .map(|p| {
                        p.strip_suffix('\n')
                            .map(|q| q.strip_suffix('\r').unwrap_or(q))
                            .unwrap_or(&p)
                            .to_owned()
                    });
                if let Some(v) = &self.version {
                    r.version = v.clone();
                }
                r.domain = self.domain.clone();
                r.sign = self.sign;
                r.seal = self.seal;
                match self.sec.as_deref().unwrap_or("ntlmssp") {
                    "ntlmssp" => r.sec = Sec::Ntlmssp,
                    "krb5" => {
                        r.sec = Sec::Krb5;
                        r.password = None;
                        r.keytab = secret(&self.keytab_file, "keytab")?;
                        r.principal = self.principal.clone();
                    }
                    s => bail!("share.sec: ntlmssp or krb5, not {s:?}"),
                }
                r
            }
            k => bail!("share.kind: nfs or smb, not {k:?}"),
        };
        if let Some(p) = self.port {
            r.port = p;
        }
        r.timeout_secs = self.timeout_secs;
        r.check()?;
        Ok(r)
    }
}

impl Config {
    fn store(&self) -> Result<Store> {
        let root = self.store.as_ref().context("config: store missing")?;
        let sock = self.keyd_socket.as_ref().context("config: keyd_socket missing")?;
        let keys = keyd::fetch_keyring(sock, &self.tenant).context("keyd")?;
        Ok(Store::open(root, keys, Options::default())?)
    }

    /// (mount fd if mounted, readable root dir fd)
    fn root(&self, log: &dyn Fn(&str)) -> Result<(Option<OwnedFd>, OwnedFd, Option<Fs>)> {
        if let Some(p) = &self.local_root {
            log(&format!("local directory {} as the share (test mode)", p.display()));
            return Ok((None, mount::open_local(p)?, None));
        }
        let s = self.share.as_ref().context("config: share missing")?;
        let req = s.request()?;
        let wait = Duration::from_secs(u64::from(req.timeout_secs) * 3 + 30);
        let mnt = mount::mount_share(&self.mount_socket, &req, wait)?;
        log(&format!(
            "mounted {} {} read-only (detached mount from nexus-nasmount)",
            req.fs.as_str(),
            match req.fs {
                Fs::Nfs => format!("{}:{} (NFS {})", req.host, req.export, req.version),
                Fs::Smb => format!(
                    "//{}/{} (SMB {}, sec={}{}{})",
                    req.host,
                    req.share,
                    req.version,
                    req.sec.as_str(),
                    if req.sign { ", signed" } else { "" },
                    if req.seal { ", encrypted" } else { "" }
                ),
            }
        ));
        let root = mount::open_root(&mnt)?;
        Ok((Some(mnt), root, Some(req.fs)))
    }

    fn scan_options(&self, fs: Option<Fs>, version: Option<&str>) -> Result<scan::Options> {
        if !(1..=64).contains(&self.threads) {
            bail!("threads: 1..=64");
        }
        let mut ex: Vec<String> = nas::DEFAULT_EXCLUDES.iter().map(|s| s.to_string()).collect();
        ex.extend(self.excludes.iter().cloned());
        Ok(scan::Options {
            threads: self.threads,
            xattrs: self.xattrs,
            extra_xattrs: match (fs, version) {
                (Some(Fs::Nfs), Some(v)) if v != "3" => vec!["system.nfs4_acl"],
                (Some(Fs::Smb), _) => vec!["system.cifs_acl", "user.cifs.dosattrib", "user.cifs.creationtime"],
                _ => Vec::new(),
            },
            excludes: agent_core::glob::Excludes::new(&ex),
            batch: 256,
            before_read: None,
        })
    }
}

fn main() -> Result<()> {
    keyd::deny_dumps();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: nexus-nas <config.json> backup | check | files <share-source> <time> ls <dir> | files <share-source> <time> get <out.tar|out.zip> <path>...";
    let [cfg_path, cmd, rest @ ..] = args.as_slice() else {
        bail!("{usage}");
    };
    let cfg: Config = serde_json::from_slice(&fs::read(cfg_path)?).context("config")?;
    let log = |l: &str| println!("{l}");
    match (cmd.as_str(), rest) {
        ("backup", []) => {
            let store = cfg.store()?;
            let (_mnt, root, fs) = cfg.root(&log)?;
            let version = cfg
                .share
                .as_ref()
                .and_then(|s| s.version.clone())
                .unwrap_or_else(|| "4.2".into());
            let spec = Spec {
                source_id: cfg.source_id,
                scan: cfg.scan_options(fs, Some(&version))?,
                snapshot: cfg
                    .snapshot_dir
                    .as_ref()
                    .map(|d| -> Result<Snap> {
                        Ok(Snap {
                            dir: d.clone(),
                            prefix: cfg.snapshot_prefix.clone(),
                            order: Order::parse(&cfg.snapshot_order)?,
                        })
                    })
                    .transpose()?,
            };
            let o = backup::backup(&store, &root, &spec, &log)?;
            let r = &o.report;
            for e in &r.errors {
                println!("error {}", e.escape_debug());
            }
            println!(
                "committed {}/{} in {:.1}s: {} entries, {} files read ({} bytes), {} unchanged files reused ({} bytes), {} new chunks ({} bytes), {} bytes transferred, {} inconsistent, {} errors, {:.0} entries/s, {}",
                o.source,
                o.time,
                r.secs,
                r.entries,
                r.files_read,
                r.bytes_read,
                r.reused_files,
                r.reused_bytes,
                r.new_chunks,
                r.new_bytes,
                r.bytes_read,
                r.inconsistent,
                r.error_count,
                r.files_per_sec(),
                match &o.snapshot {
                    Some(s) => format!("NAS snapshot {s}"),
                    None => "live share (no NAS snapshot)".into(),
                }
            );
            if !o.consistent {
                println!(
                    "inconsistent {}/{}: consistent=false ({}; {} files changed while read; {} entries unreadable)",
                    o.source,
                    o.time,
                    if o.snapshot.is_some() {
                        "NAS snapshot"
                    } else {
                        "no NAS snapshot"
                    },
                    r.inconsistent,
                    r.error_count
                );
            }
            println!(
                "result {}",
                json!({
                    "source": o.source, "time": o.time, "snapshot": o.snapshot, "consistent": o.consistent,
                    "incremental": o.incremental, "entries": r.entries, "files": r.files, "dirs": r.dirs,
                    "files_read": r.files_read, "bytes_read": r.bytes_read, "reused_files": r.reused_files,
                    "reused_bytes": r.reused_bytes, "new_chunks": r.new_chunks, "new_bytes": r.new_bytes,
                    "transferred_bytes": r.bytes_read, "inconsistent_files": r.inconsistent, "errors": r.error_count,
                    "vanished": r.vanished, "skipped_mounts": r.skipped_mounts, "secs": r.secs,
                    "entries_per_sec": r.files_per_sec(),
                })
            );
        }
        ("check", []) => {
            let (_mnt, root, _) = cfg.root(&log)?;
            let names = sys::read_dir(&root)?;
            let st = sys::fstatx(root.as_raw_fd(), false)?;
            println!(
                "share root: {} entries, mode {:o}, uid {} gid {}",
                names.len(),
                st.mode & 0o7777,
                st.uid,
                st.gid
            );
            if let Some(d) = &cfg.snapshot_dir {
                match mount::newest_snapshot(&root, d, &cfg.snapshot_prefix, Order::parse(&cfg.snapshot_order)?)? {
                    Some((n, _)) => println!("newest snapshot: {d}/{n}"),
                    None => println!("no snapshot {}* in {d}", cfg.snapshot_prefix),
                }
            }
            println!("ok");
        }
        ("files", [source, time, op, args @ ..]) => {
            if parse_source_name(source).is_none() {
                bail!("invalid source {source:?} (expected share-<id>)");
            }
            let store = cfg.store()?;
            let tree = backup::load_tree(&store, source, time.parse()?)?;
            match (op.as_str(), args) {
                ("ls", [dir]) => println!("{}", serde_json::to_string_pretty(&files::list(&tree, dir)?)?),
                ("get", [out, paths @ ..]) if !paths.is_empty() => {
                    let out = Path::new(out);
                    let n = files::extract(
                        &store,
                        &tree,
                        paths,
                        Format::from_path(out)?,
                        fs::File::create_new(out)?,
                    )?;
                    println!("{n} entries written to {}", out.display());
                }
                _ => bail!("{usage}"),
            }
        }
        _ => bail!("{usage}"),
    }
    Ok(())
}
