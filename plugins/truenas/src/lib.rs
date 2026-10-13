//! The TrueNAS connector as a plugin (docs/truenas-connector.md §9): the client
//! side of crate `truenas` (JSON-RPC API, forced-command SSH streams and their
//! strict parsers) feeding the plugin SDK instead of the store. One guest = one
//! dataset (`tank/data` → guest `tank.data`) = one snapshot
//! `plugin-truenas-<source>-<guest>`.
//!
//! Backup of a dataset: ZFS snapshot `nexus-<source>-<time>` through the API;
//! `zfs diff` against the reference (the ZFS snapshot named in the base
//! snapshot's state blob, if it still exists); metadata walk; base metadata of
//! every file/directory `zfs diff` does not name; then, in walk order: files and
//! directories whose base entry has the same object, type, mode, owner, size and
//! mtime go out as `Unchanged` / entry with the base's xattrs, the others are
//! read from the `read` tar stream, everything else is an entry. Without a
//! reference everything is read. The plugin does not see the host's commit, so
//! rotation runs one backup later: after success every other
//! `nexus-<source>-*` snapshot of the dataset except the reference and the new
//! one is deleted (TrueNAS keeps two per dataset); after a failure the new one
//! is deleted.

use anyhow::{bail, Context};
use base64::Engine;
use chunkstore::TreeKind;
use plugin_sdk::{error, BackupResult, Ctx, Guest, Kind, Meta, Plugin, Result, Sink, Source, Validation};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use truenas::api::{Api, ApiConfig, Nas};
use truenas::fc::{self, Fc, Tools};
use truenas::remote::{Remote, Ssh, Transport};
use truenas::stream;
use truenas::tree::{changed_inodes, end_of_requested, next_requested};
use truenas::walk::WalkEntry;
use truenas::{parse_snap_name, snap_name, under, valid_dataset};

/// Paths per base query: the host drops the xattrs of a whole answer that would not
/// fit one frame (8 MiB); with 64 entries that needs > 128 KiB of xattrs per entry.
const BASE_BATCH: usize = 64;

/// The source config (manifest `config_schema`; secrets `api_key`, `ssh_private_key`).
#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub ca_pem: String,
    pub user: String,
    pub api_key: String,
    pub ssh_host: String,
    pub ssh_port: u16,
    pub ssh_user: String,
    pub ssh_host_key: String,
    pub ssh_private_key: String,
    pub ssh_from: Option<String>,
    pub datasets: Vec<String>,
    pub recursive: bool,
    pub sudo: bool,
    pub zfs_sudo: bool,
}

/// (config field, problem)
pub type Bad = (&'static str, String);

impl Config {
    pub fn parse(v: &Value) -> std::result::Result<Config, Bad> {
        let s = |k: &'static str| -> std::result::Result<String, Bad> {
            v[k].as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .ok_or((k, "required".into()))
        };
        let user = |k: &'static str| {
            v[k].as_str()
                .filter(|s| !s.is_empty())
                .unwrap_or("nexusbackup")
                .to_owned()
        };
        let port = |k: &'static str, def: u16| -> std::result::Result<u16, Bad> {
            match &v[k] {
                Value::Null => Ok(def),
                x => x
                    .as_u64()
                    .and_then(|p| u16::try_from(p).ok())
                    .filter(|p| *p > 0)
                    .ok_or((k, "expected a port".into())),
            }
        };
        let flag = |k: &str, def: bool| v[k].as_bool().unwrap_or(def);
        let c = Config {
            host: s("host")?,
            port: port("port", 443)?,
            ca_pem: s("ca_pem")?,
            user: user("user"),
            api_key: s("api_key")?,
            ssh_host: s("ssh_host")?,
            ssh_port: port("ssh_port", 22)?,
            ssh_user: user("ssh_user"),
            ssh_host_key: s("ssh_host_key")?,
            ssh_private_key: s("ssh_private_key")?,
            ssh_from: v["ssh_from"].as_str().filter(|s| !s.is_empty()).map(str::to_owned),
            datasets: v["datasets"]
                .as_array()
                .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect())
                .unwrap_or_default(),
            recursive: flag("recursive", false),
            sudo: flag("sudo", true),
            zfs_sudo: flag("zfs_sudo", true),
        };
        if !c.ca_pem.contains("-----BEGIN CERTIFICATE-----") {
            return Err(("ca_pem", "expected a PEM certificate".into()));
        }
        if c.ssh_host_key.split_whitespace().count() < 2 || c.ssh_host_key.contains(['\n', '\r']) {
            return Err(("ssh_host_key", "expected `ssh-ed25519 AAAA…`".into()));
        }
        if c.datasets.is_empty() || c.datasets.len() > 64 {
            return Err(("datasets", "1..=64 datasets".into()));
        }
        for d in &c.datasets {
            if !valid_dataset(d) {
                return Err((
                    "datasets",
                    format!("{d:?}: not supported (pool/a/b, components of A-Z a-z 0-9 _ -)"),
                ));
            }
            if c.datasets.iter().filter(|o| under(d, o) || under(o, d)).count() > 1 {
                return Err(("datasets", format!("{d:?} overlaps another dataset")));
            }
        }
        // the forced command must be buildable (also checks `ssh_from`)
        fc::authorized_keys(&c.fc(), &Tools::default(), "ssh-ed25519 AAAA", c.ssh_from.as_deref())
            .map_err(|e| ("ssh_from", format!("{e:#}")))?;
        Ok(c)
    }

    pub fn fc(&self) -> Fc {
        Fc {
            datasets: self.datasets.clone(),
            recursive: self.recursive,
            sudo: self.sudo,
            zfs_sudo: self.zfs_sudo,
            existing_prefix: None,
        }
    }

    /// The dataset of a guest id (`tank.data` → `tank/data`), if this source covers it.
    pub fn dataset_of(&self, guest: &str) -> Option<String> {
        let ds = guest.replace('.', "/");
        let covered = self
            .datasets
            .iter()
            .any(|r| if self.recursive { under(&ds, r) } else { &ds == r });
        (valid_dataset(&ds) && covered).then_some(ds)
    }

    /// The line for the TrueNAS user's "SSH public key" field.
    pub fn authorized_keys(&self) -> Result<String> {
        fc::authorized_keys(
            &self.fc(),
            &Tools::default(),
            &public_key(&self.ssh_private_key)?,
            self.ssh_from.as_deref(),
        )
    }
}

/// Guest id of a dataset (the same `/` → `.` mapping as the built-in connector's sources).
pub fn guest_id(dataset: &str) -> String {
    dataset.replace('/', ".")
}

/// The public half of an OpenSSH private key (`openssh-key-v1` stores the public
/// key blob unencrypted, also for passphrase-protected keys).
pub fn public_key(private: &str) -> Result<String> {
    let p = pem::parse(private.trim()).context("ssh_private_key: not an OpenSSH private key")?;
    if p.tag() != "OPENSSH PRIVATE KEY" {
        bail!(
            "ssh_private_key: expected an OpenSSH private key (ssh-keygen -t ed25519), not {}",
            p.tag()
        );
    }
    fn string<'a>(r: &mut &'a [u8]) -> Result<&'a [u8]> {
        let n = r
            .get(..4)
            .map(|b| u32::from_be_bytes(b.try_into().unwrap()) as usize)
            .context("ssh_private_key: truncated")?;
        let v = r.get(4..4 + n).context("ssh_private_key: truncated")?;
        *r = &r[4 + n..];
        Ok(v)
    }
    let mut r = p
        .contents()
        .strip_prefix(b"openssh-key-v1\0")
        .context("ssh_private_key: not openssh-key-v1")?;
    for _ in 0..3 {
        string(&mut r)?; // cipher, kdf, kdf options
    }
    if r.get(..4) != Some(&1u32.to_be_bytes()[..]) {
        bail!("ssh_private_key: exactly one key expected");
    }
    r = &r[4..];
    let blob = string(&mut r)?;
    let ty = std::str::from_utf8(string(&mut &blob[..])?).context("ssh_private_key: key type")?;
    if ty.is_empty() || !ty.bytes().all(|b| b.is_ascii_alphanumeric() || b"-@.".contains(&b)) {
        bail!("ssh_private_key: invalid key type");
    }
    Ok(format!(
        "{ty} {}",
        base64::engine::general_purpose::STANDARD.encode(blob)
    ))
}

/// How the plugin reaches TrueNAS (tests: the in-process fake).
pub trait Connect {
    fn nas(&self, c: &Config) -> Result<Box<dyn Nas>>;
    fn transport(&self, c: &Config) -> Result<Box<dyn Transport>>;
}

/// The real TrueNAS: API over `wss` (pinned certificate), the system's `ssh` client
/// (run inside the plugin's sandbox; key and pinned host key in its private tmp dir).
pub struct Real;

impl Connect for Real {
    fn nas(&self, c: &Config) -> Result<Box<dyn Nas>> {
        Ok(Box::new(Api::connect(&ApiConfig {
            host: c.host.clone(),
            port: c.port,
            connect_addr: None,
            ca_pem: c.ca_pem.as_bytes().to_vec(),
            user: c.user.clone(),
            api_key: c.api_key.clone(),
            timeout: Duration::from_secs(120),
        })?))
    }

    fn transport(&self, c: &Config) -> Result<Box<dyn Transport>> {
        let dir = std::env::temp_dir();
        let key = dir.join("nexus-ssh.key");
        let _ = fs::remove_file(&key);
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key)
            .with_context(|| format!("{}", key.display()))?;
        f.write_all(c.ssh_private_key.trim().as_bytes())?;
        f.write_all(b"\n")?;
        let known_hosts = dir.join("nexus-known_hosts");
        let name = if c.ssh_port == 22 {
            c.ssh_host.clone()
        } else {
            format!("[{}]:{}", c.ssh_host, c.ssh_port)
        };
        fs::write(&known_hosts, format!("{name} {}\n", c.ssh_host_key.trim()))?;
        Ok(Box::new(Ssh {
            host: c.ssh_host.clone(),
            port: c.ssh_port,
            user: c.ssh_user.clone(),
            key,
            known_hosts,
        }))
    }
}

pub struct TrueNasPlugin<C: Connect> {
    pub connect: C,
}

fn invalid(field: &str, message: impl Into<String>) -> Validation {
    Validation::Invalid {
        field: field.into(),
        message: message.into(),
    }
}

fn config(ctx: &Ctx) -> Result<Config> {
    Config::parse(&ctx.config).map_err(|(f, m)| error(22, format!("config.{f}: {m}")))
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// The ZFS snapshot time recorded in the base snapshot's state blob for `ds`.
fn reference_of(state: Option<&[u8]>, ds: &str) -> Option<u64> {
    let v: Value = serde_json::from_slice(state?).ok()?;
    (v["dataset"] == ds).then(|| v["time"].as_u64())?
}

impl<C: Connect> Plugin for TrueNasPlugin<C> {
    /// Config, API login + datasets, SSH forced command (`hello`). Logs the
    /// `authorized_keys` line; an SSH failure repeats it in the message.
    fn validate(&mut self, ctx: &Ctx) -> Result<Validation> {
        let c = match Config::parse(&ctx.config) {
            Ok(c) => c,
            Err((f, m)) => return Ok(invalid(f, m)),
        };
        let line = match c.authorized_keys() {
            Ok(l) => l,
            Err(e) => return Ok(invalid("ssh_private_key", format!("{e:#}"))),
        };
        ctx.info(format!(
            "authorized_keys line for the \"SSH public key\" field of the TrueNAS user {:?}: {line}",
            c.ssh_user
        ));
        let mut nas = match self.connect.nas(&c) {
            Ok(n) => n,
            Err(e) => return Ok(invalid("host", format!("TrueNAS API: {e:#}"))),
        };
        for root in &c.datasets {
            match nas.datasets(root, false) {
                Ok(l) if l.iter().any(|d| &d.name == root && d.mountpoint.is_some()) => {}
                Ok(_) => {
                    return Ok(invalid(
                        "datasets",
                        format!("{root}: not found or not a mounted file system"),
                    ))
                }
                Err(e) => return Ok(invalid("datasets", format!("{root}: {e:#}"))),
            }
        }
        let t = self.connect.transport(&c)?;
        if let Err(e) = Remote::new(t.as_ref()).hello() {
            return Ok(invalid(
                "ssh_host",
                format!(
                    "SSH: {e:#} (is this line in the \"SSH public key\" field of the TrueNAS user {:?}? {line})",
                    c.ssh_user
                ),
            ));
        }
        Ok(Validation::Valid)
    }

    /// Mounted file system datasets of the configured roots (with children if `recursive`).
    fn list_guests(&mut self, ctx: &Ctx) -> Result<Vec<Guest>> {
        let c = config(ctx)?;
        let mut nas = self.connect.nas(&c)?;
        let mut out = Vec::new();
        for root in &c.datasets {
            for d in nas.datasets(root, c.recursive)? {
                let Some(mp) = d.mountpoint.as_deref().filter(|_| valid_dataset(&d.name)) else {
                    ctx.info(format!(
                        "skipping {}: not a mounted file system with a supported name",
                        d.name
                    ));
                    continue;
                };
                let id = guest_id(&d.name);
                if !plugin_sdk::proto::valid_guest_id(&id) {
                    ctx.warn(format!("skipping {}: name longer than 64 characters", d.name));
                    continue;
                }
                out.push(Guest {
                    id,
                    title: format!("{} ({mp})", d.name),
                    size: None,
                });
            }
        }
        Ok(out)
    }

    fn backup(&mut self, ctx: &Ctx, sink: &mut Sink) -> Result<BackupResult> {
        let c = config(ctx)?;
        let sid = ctx
            .source_id()
            .ok_or_else(|| error(22, "the host passed no source_id (nexus-pluginhost too old)"))?;
        let guest = ctx.guest().ok_or_else(|| {
            error(
                22,
                "select the datasets to back up in the group (each dataset is a guest)",
            )
        })?;
        let ds = c
            .dataset_of(guest)
            .ok_or_else(|| error(22, format!("guest {guest:?} is not a dataset of this source")))?;
        let mut nas = self.connect.nas(&c)?;
        let t = self.connect.transport(&c)?;
        let d = nas
            .datasets(&ds, false)?
            .into_iter()
            .find(|d| d.name == ds)
            .with_context(|| format!("dataset {ds} not found"))?;
        let mp = d
            .mountpoint
            .with_context(|| format!("{ds}: not a mounted file system"))?;
        let ours: Vec<u64> = nas
            .snapshots(&ds)?
            .iter()
            .filter_map(|n| parse_snap_name(sid, n))
            .collect();
        let prev = if sink.has_base() {
            reference_of(ctx.state.as_deref(), &ds)
        } else {
            None
        };
        let reference = prev.filter(|p| ours.contains(p));
        if let (Some(p), None) = (prev, reference) {
            ctx.info(format!(
                "{ds}: reference snapshot {} is gone, reading everything",
                snap_name(sid, p)
            ));
        }
        let time = now().max(ours.iter().max().map_or(0, |t| t + 1));
        let snap = snap_name(sid, time);
        nas.create_snapshot(&ds, &snap, false)?;
        let mut remote = Remote::new(t.as_ref());
        match send_dataset(ctx, sink, &mut remote, sid, &ds, &mp, time, reference) {
            Err(e) => {
                if let Err(d) = nas.delete_snapshot(&ds, &snap) {
                    ctx.warn(format!("deleting {ds}@{snap} failed: {d:#}"));
                }
                Err(e)
            }
            Ok(summary) => {
                for t in ours.iter().filter(|t| Some(**t) != reference) {
                    let n = snap_name(sid, *t);
                    match nas.delete_snapshot(&ds, &n) {
                        Ok(()) => ctx.info(format!("deleted {ds}@{n}")),
                        Err(e) => ctx.warn(format!("deleting {ds}@{n} failed (retried next run): {e:#}")),
                    }
                }
                Ok(BackupResult {
                    state: Some(json!({"dataset": ds, "time": time}).to_string().into_bytes()),
                    consistent: true,
                    summary,
                })
            }
        }
    }

    fn restore(&mut self, _ctx: &Ctx, _src: &mut Source) -> Result<String> {
        Err(error(
            95,
            "restore into TrueNAS is not supported (download only, docs/truenas-connector.md §6)",
        ))
    }
}

enum Act {
    /// same object and metadata as in the base snapshot
    Unchanged,
    /// from the `read` tar stream (file content, directory xattrs)
    Read,
    /// metadata only (directories unchanged since the base, links, special files)
    Entry,
}

struct Item {
    path: Vec<u8>,
    meta: Meta,
    act: Act,
}

#[derive(Default)]
struct Stats {
    read: u64,
    bytes_read: u64,
    unchanged: u64,
    unchanged_bytes: u64,
}

fn proto_kind(k: &TreeKind) -> Kind {
    match k {
        TreeKind::File => Kind::File,
        TreeKind::Dir => Kind::Dir,
        TreeKind::Symlink => Kind::Symlink,
        TreeKind::Hardlink => Kind::Hardlink,
        TreeKind::Device => Kind::Device,
        TreeKind::Fifo => Kind::Fifo,
        TreeKind::Socket => Kind::Socket,
    }
}

/// Base metadata of the files and directories `zfs diff` does not name.
fn base_meta(sink: &mut Sink, walk: &[WalkEntry], changed: &HashSet<u64>) -> Result<HashMap<Vec<u8>, Meta>> {
    let paths: Vec<Vec<u8>> = walk
        .iter()
        .filter(|w| matches!(w.kind, TreeKind::File | TreeKind::Dir) && !changed.contains(&w.inode))
        .map(|w| w.path.clone())
        .collect();
    let mut out = HashMap::new();
    for batch in paths.chunks(BASE_BATCH) {
        out.extend(sink.base(batch)?.into_iter().map(|b| (b.path, b.meta)));
    }
    Ok(out)
}

/// What to send for every walk entry (walk order). Hard links: the first name is
/// the file, later names link to it.
fn plan(walk: Vec<WalkEntry>, base: &HashMap<Vec<u8>, Meta>) -> Vec<Item> {
    let mut first: HashMap<u64, Vec<u8>> = HashMap::new();
    walk.into_iter()
        .map(|w| {
            let mut meta = Meta {
                kind: Some(proto_kind(&w.kind)),
                mode: w.mode,
                uid: w.uid,
                gid: w.gid,
                size: if w.kind == TreeKind::File { w.size } else { 0 },
                mtime_ns: w.mtime_ns,
                ctime_ns: w.ctime_ns,
                inode: w.inode,
                link_target: w.link.clone(),
                xattrs: Vec::new(),
            };
            let same = |b: &Meta| {
                b.kind == meta.kind
                    && b.mode == meta.mode
                    && b.uid == meta.uid
                    && b.gid == meta.gid
                    && b.size == meta.size
                    && b.mtime_ns == meta.mtime_ns
                    && b.inode == meta.inode
            };
            let act = match w.kind {
                TreeKind::File if first.contains_key(&w.inode) => {
                    meta.kind = Some(Kind::Hardlink);
                    meta.link_target = first.get(&w.inode).cloned();
                    meta.size = 0;
                    Act::Entry
                }
                TreeKind::File | TreeKind::Dir => {
                    if w.kind == TreeKind::File {
                        first.insert(w.inode, w.path.clone());
                    }
                    match base.get(&w.path) {
                        Some(b) if same(b) => {
                            meta.xattrs = b.xattrs.clone();
                            if w.kind == TreeKind::File {
                                Act::Unchanged
                            } else {
                                Act::Entry
                            }
                        }
                        _ => Act::Read,
                    }
                }
                _ => Act::Entry,
            };
            Item {
                path: w.path,
                meta,
                act,
            }
        })
        .collect()
}

/// Counts what `sink.file` takes from the tar member.
struct Counted<'a, R> {
    r: &'a mut R,
    n: u64,
}

impl<R: Read> Read for Counted<'_, R> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let n = self.r.read(b)?;
        self.n += n as u64;
        Ok(n)
    }
}

/// Sends the items in order; `Read` items take the next member of `tar` (which must
/// be exactly the requested path with the walk's type and size).
fn emit<R: Read>(
    ctx: &Ctx,
    sink: &mut Sink,
    items: &[Item],
    mut tar: Option<&mut stream::Reader<R>>,
    st: &mut Stats,
) -> Result<()> {
    for (i, it) in items.iter().enumerate() {
        if i % 50_000 == 0 {
            ctx.progress(i as u64, items.len() as u64, "entries");
        }
        match it.act {
            Act::Unchanged => {
                sink.unchanged(&it.path, it.meta.clone())?;
                st.unchanged += 1;
                st.unchanged_bytes += it.meta.size;
            }
            Act::Entry => sink.entry(&it.path, it.meta.clone())?,
            Act::Read => {
                let tar = tar.as_deref_mut().context("no content stream")?;
                let kind = if it.meta.kind == Some(Kind::Dir) {
                    TreeKind::Dir
                } else {
                    TreeKind::File
                };
                let m = next_requested(tar, &it.path, &kind, it.meta.size)?;
                let meta = Meta {
                    xattrs: m.xattrs,
                    ..it.meta.clone()
                };
                if kind == TreeKind::Dir {
                    sink.entry(&it.path, meta)?;
                    continue;
                }
                let mut data = tar.data();
                let mut c = Counted { r: &mut data, n: 0 };
                sink.file(&it.path, meta, &mut c)?;
                if c.n != it.meta.size {
                    bail!("{:?}: short content", String::from_utf8_lossy(&it.path));
                }
                st.read += 1;
                st.bytes_read += c.n;
            }
        }
    }
    if let Some(tar) = tar {
        end_of_requested(tar)?;
    }
    Ok(())
}

/// diff (with a reference), walk, base metadata, then the item stream. Returns the summary.
#[allow(clippy::too_many_arguments)]
fn send_dataset(
    ctx: &Ctx,
    sink: &mut Sink,
    remote: &mut Remote,
    sid: u64,
    ds: &str,
    mountpoint: &str,
    time: u64,
    reference: Option<u64>,
) -> Result<String> {
    let snap = snap_name(sid, time);
    let diff = match reference {
        Some(p) => Some(remote.diff(ds, &snap_name(sid, p), &snap, mountpoint)?),
        None => None,
    };
    let walk = remote.walk(ds, &snap)?;
    let changed = diff.as_ref().map(|l| changed_inodes(&walk, l));
    let base = match &changed {
        Some(ch) => base_meta(sink, &walk, ch)?,
        None => HashMap::new(),
    };
    let items = plan(walk, &base);
    let need: Vec<Vec<u8>> = items
        .iter()
        .filter(|i| matches!(i.act, Act::Read))
        .map(|i| i.path.clone())
        .collect();
    let mut st = Stats::default();
    if need.is_empty() {
        emit::<&[u8]>(ctx, sink, &items, None, &mut st)?;
    } else {
        remote.read(ds, &snap, need, |tar| emit(ctx, sink, &items, Some(tar), &mut st))?;
    }
    Ok(format!(
        "{ds}@{snap}: {} entries, {} changes, {} files read ({} bytes), {} unchanged files ({} bytes), {} bytes received over SSH{}",
        items.len(),
        diff.as_ref().map_or(0, Vec::len),
        st.read,
        st.bytes_read,
        st.unchanged,
        st.unchanged_bytes,
        remote.received,
        if reference.is_none() {
            ", full read (no reference snapshot)"
        } else {
            ""
        }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Value {
        json!({
            "host": "truenas.example", "ca_pem": "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n",
            "api_key": "1-abc", "ssh_host": "truenas.example", "ssh_host_key": "ssh-ed25519 AAAAC3Nza",
            "ssh_private_key": "k", "datasets": ["tank/data", "tank/smb"],
        })
    }

    #[test]
    fn config_defaults_and_checks() {
        let c = Config::parse(&cfg()).unwrap();
        assert_eq!(
            (c.port, c.ssh_port, c.user.as_str(), c.ssh_user.as_str()),
            (443, 22, "nexusbackup", "nexusbackup")
        );
        assert!(!c.recursive && c.sudo && c.zfs_sudo && c.ssh_from.is_none());
        assert_eq!(c.dataset_of("tank.data").as_deref(), Some("tank/data"));
        assert_eq!(c.dataset_of("tank.data.child"), None); // not recursive
        assert_eq!(c.dataset_of("tank.other"), None);
        let mut v = cfg();
        v["recursive"] = json!(true);
        let c = Config::parse(&v).unwrap();
        assert_eq!(c.dataset_of("tank.data.child").as_deref(), Some("tank/data/child"));
        assert_eq!(c.dataset_of("tank.database"), None);
        assert_eq!(guest_id("tank/data/child"), "tank.data.child");
        for (k, bad, field) in [
            ("api_key", json!(null), "api_key"),
            ("ssh_private_key", json!(""), "ssh_private_key"),
            ("ca_pem", json!("not a cert"), "ca_pem"),
            ("port", json!(0), "port"),
            ("ssh_port", json!(70000), "ssh_port"),
            ("ssh_host_key", json!("ssh-ed25519 AAAA\nx y"), "ssh_host_key"),
            ("datasets", json!([]), "datasets"),
            ("datasets", json!(["tank/a.b"]), "datasets"),
            ("datasets", json!(["tank/data", "tank/data/x"]), "datasets"),
            ("ssh_from", json!("10.0.0.1\" x"), "ssh_from"),
        ] {
            let mut v = cfg();
            v[k] = bad;
            assert_eq!(Config::parse(&v).unwrap_err().0, field, "{k}");
        }
    }

    #[test]
    fn state_reference() {
        let s = json!({"dataset": "tank/data", "time": 17}).to_string();
        assert_eq!(reference_of(Some(s.as_bytes()), "tank/data"), Some(17));
        assert_eq!(reference_of(Some(s.as_bytes()), "tank/smb"), None);
        assert_eq!(reference_of(Some(b"junk"), "tank/data"), None);
        assert_eq!(reference_of(None, "tank/data"), None);
    }

    #[test]
    fn public_key_of_openssh_keys() {
        let td = tempfile::tempdir().unwrap();
        for ty in ["ed25519", "ecdsa"] {
            let k = td.path().join(ty);
            let ok = std::process::Command::new("ssh-keygen")
                .args(["-q", "-t", ty, "-N", "", "-C", "", "-f"])
                .arg(&k)
                .status()
                .is_ok_and(|s| s.success());
            if !ok {
                eprintln!("ssh-keygen not available: skipped");
                return;
            }
            let want = fs::read_to_string(k.with_extension("pub")).unwrap();
            let got = public_key(&fs::read_to_string(&k).unwrap()).unwrap();
            assert_eq!(got, want.split_whitespace().take(2).collect::<Vec<_>>().join(" "));
        }
        assert!(public_key("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n").is_err());
        assert!(public_key("junk").is_err());
        let truncated = pem::encode(&pem::Pem::new(
            "OPENSSH PRIVATE KEY",
            b"openssh-key-v1\0\0\0\0\x04none".to_vec(),
        ));
        assert!(public_key(&truncated).is_err());
    }

    fn w(path: &str, kind: TreeKind, inode: u64, size: u64, mtime: i64) -> WalkEntry {
        WalkEntry {
            kind,
            mode: 0o644,
            uid: 0,
            gid: 0,
            size,
            mtime_ns: mtime,
            ctime_ns: mtime,
            inode,
            nlink: 1,
            path: path.as_bytes().to_vec(),
            link: None,
        }
    }

    #[test]
    fn plan_uses_base_only_for_same_object_and_metadata() {
        let base_of = |w: &WalkEntry, x: &[u8]| Meta {
            kind: Some(proto_kind(&w.kind)),
            mode: w.mode,
            size: if w.kind == TreeKind::File { w.size } else { 0 },
            mtime_ns: w.mtime_ns,
            inode: w.inode,
            xattrs: vec![(b"user.a".to_vec(), x.to_vec())],
            ..Meta::default()
        };
        let walk = vec![
            w("d", TreeKind::Dir, 2, 0, 1),
            w("d/same", TreeKind::File, 3, 5, 1),
            w("d/mtime", TreeKind::File, 4, 5, 2),
            w("d/other-object", TreeKind::File, 9, 5, 1),
            w("d/new", TreeKind::File, 6, 1, 1),
            w("d/link", TreeKind::File, 3, 5, 1),
            w("d/sym", TreeKind::Symlink, 7, 0, 1),
            w("e", TreeKind::Dir, 8, 0, 1),
        ];
        let mut base = HashMap::new();
        base.insert(b"d".to_vec(), base_of(&walk[0], b"dir"));
        base.insert(b"d/same".to_vec(), base_of(&walk[1], b"f"));
        base.insert(
            b"d/mtime".to_vec(),
            base_of(&w("d/mtime", TreeKind::File, 4, 5, 1), b""),
        );
        base.insert(
            b"d/other-object".to_vec(),
            base_of(&w("x", TreeKind::File, 5, 5, 1), b""),
        );
        base.insert(b"e".to_vec(), base_of(&w("e", TreeKind::File, 8, 0, 1), b"")); // was a file
        let items = plan(walk, &base);
        let acts: Vec<&str> = items
            .iter()
            .map(|i| match i.act {
                Act::Unchanged => "unchanged",
                Act::Read => "read",
                Act::Entry => "entry",
            })
            .collect();
        assert_eq!(
            acts,
            ["entry", "unchanged", "read", "read", "read", "entry", "entry", "read"]
        );
        assert_eq!(items[0].meta.xattrs, vec![(b"user.a".to_vec(), b"dir".to_vec())]);
        assert_eq!(items[1].meta.xattrs, vec![(b"user.a".to_vec(), b"f".to_vec())]);
        assert_eq!(items[5].meta.kind, Some(Kind::Hardlink));
        assert_eq!(items[5].meta.link_target.as_deref(), Some(&b"d/same"[..]));
        assert_eq!(items[5].meta.size, 0);
    }
}
