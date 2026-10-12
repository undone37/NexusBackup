//! `nexus-offsite <config.json> upload | retention | gc | verify [packs] | check | list [--json]
//! | restore <source> <time> [<keep-secs>]`, `nexus-offsite <config.json> dr [--tenant-key] <keyd-dir>`
//! (fresh appliance: the appliance recovery key on stdin, or with `--tenant-key` the tenant
//! recovery key; never on the command line, where other processes could read it) and
//! `nexus-offsite <config.json> attach <key-file>` (web UI, Phase 17d: the escrow and the
//! appliance recovery key go to keyd over its socket, the file is removed once read; then the
//! inventory is rebuilt from the box).

use anyhow::{bail, Context, Result};
use chunkstore::retention::Gfs;
use chunkstore::{Keyring, Options as StoreOptions, Store};
use offsite::remote::{LocalDir, Remote};
use offsite::s3::{S3Config, S3Remote};
use offsite::sftp::{SftpConfig, SftpRemote};
use offsite::target::{Options, Target};
use serde::Deserialize;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
struct Config {
    store: PathBuf,
    tenant: String,
    keyd_socket: PathBuf,
    /// output of `keyd export-escrow` (wrapped keys only)
    escrow_dir: PathBuf,
    /// local offsite inventory for this target
    state: PathBuf,
    remote: RemoteCfg,
    gfs: Option<GfsCfg>,
    /// `[source, time]` under legal hold: never deleted by offsite retention
    #[serde(default)]
    held: Vec<(String, u64)>,
    #[serde(default = "four")]
    uploaders: usize,
    /// bytes per second over all uploaders
    bwlimit: Option<u64>,
}

fn four() -> usize {
    4
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum RemoteCfg {
    Local {
        path: PathBuf,
    },
    Sftp {
        host: String,
        port: Option<u16>,
        user: String,
        key_file: PathBuf,
        host_key: String,
        base_dir: Option<String>,
    },
    /// S3 with optional Object Lock (docs/s3-offsite.md). The secret key and
    /// the trusted certificate(s) are files in the 0600 job dir.
    S3 {
        endpoint: String,
        region: String,
        bucket: String,
        #[serde(default)]
        prefix: String,
        access_key: String,
        secret_key_file: PathBuf,
        #[serde(default)]
        path_style: bool,
        ca_file: Option<PathBuf>,
        storage_class_packs: Option<String>,
        storage_class_meta: Option<String>,
        #[serde(default)]
        lock: bool,
        conditional_put: Option<bool>,
    },
}

#[derive(Deserialize)]
struct GfsCfg {
    daily: u32,
    weekly: u32,
    monthly: u32,
    yearly: u32,
}

fn remote(cfg: &RemoteCfg, connections: usize) -> Result<Box<dyn Remote>> {
    Ok(match cfg {
        RemoteCfg::Local { path } => Box::new(LocalDir(path.clone())),
        RemoteCfg::Sftp {
            host,
            port,
            user,
            key_file,
            host_key,
            base_dir,
        } => {
            let mut c = SftpConfig::new(host, user, key_file, host_key);
            c.port = port.unwrap_or(c.port);
            c.base_dir = base_dir.clone().unwrap_or_default();
            c.max_connections = connections;
            Box::new(SftpRemote::new(c)?)
        }
        RemoteCfg::S3 {
            endpoint,
            region,
            bucket,
            prefix,
            access_key,
            secret_key_file,
            path_style,
            ca_file,
            storage_class_packs,
            storage_class_meta,
            lock,
            conditional_put,
        } => {
            let secret = fs::read_to_string(secret_key_file).context("secret_key_file")?;
            let mut c = S3Config::new(
                endpoint,
                region,
                bucket,
                access_key,
                secret.trim_end_matches(['\r', '\n']),
            );
            c.prefix = prefix.clone();
            c.path_style = *path_style;
            c.ca_pem = ca_file.as_ref().map(fs::read).transpose().context("ca_file")?;
            c.storage_class_packs = storage_class_packs.clone();
            c.storage_class_meta = storage_class_meta.clone();
            c.lock = *lock;
            c.conditional_put = conditional_put.unwrap_or(true);
            Box::new(S3Remote::new(c)?)
        }
    })
}

fn escrow_files(dir: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let mut out = vec![(
        "kek.recovery".to_owned(),
        fs::read(dir.join("kek.recovery")).context("escrow dir")?,
    )];
    for t in fs::read_dir(dir.join("tenants"))? {
        let t = t?;
        for f in fs::read_dir(t.path())? {
            let f = f?;
            let name = format!(
                "tenants/{}/{}",
                t.file_name().to_string_lossy(),
                f.file_name().to_string_lossy()
            );
            out.push((name, fs::read(f.path())?));
        }
    }
    Ok(out)
}

fn main() -> Result<()> {
    keyd::deny_dumps();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [cfg_path, cmd, rest @ ..] = args.as_slice() else {
        bail!("usage: nexus-offsite <config.json> upload | retention | gc | verify [packs] | check | list [--json] | restore <source> <time> [<keep-secs>] | dr [--tenant-key] <keyd-dir> | attach <recovery-key-file>");
    };
    let cfg: Config = serde_json::from_slice(&fs::read(cfg_path)?).context("config")?;
    let remote = remote(&cfg.remote, cfg.uploaders.clamp(1, 10))?;
    let opts = || Options {
        uploaders: cfg.uploaders,
        bwlimit: cfg.bwlimit,
        ..Default::default()
    };

    if cmd == "attach" {
        // running appliance (web UI): keyd re-wraps the escrowed DEKs under its own KEK
        let key_file = PathBuf::from(rest.first().context("attach <recovery-key-file>")?);
        let rk = zeroize::Zeroizing::new(fs::read_to_string(&key_file).context("recovery key file")?);
        let _ = fs::remove_file(&key_file);
        let files = offsite::dr::appliance_escrow(remote.as_ref(), &cfg.tenant)?;
        let vs = keyd::request_attach(&cfg.keyd_socket, &cfg.tenant, &rk, &files).context(
            "keyd refused the keys: wrong recovery key, or the tenant has other keys on this appliance (keyd journal)",
        )?;
        println!("keys of tenant {} imported: versions {vs:?}", cfg.tenant);
        let keys = keyd::fetch_keyring(&cfg.keyd_socket, &cfg.tenant).context("keyd")?;
        let store = Store::open(&cfg.store, keys, StoreOptions::default())?;
        let mut t = Target::open(&store, remote.as_ref(), cfg.state.clone(), opts())?;
        let packs = t.rebuild_from_remote()?;
        println!(
            "attach: keys recovered, {packs} packs and {} snapshots indexed",
            t.snapshots()?.len()
        );
        return Ok(());
    }

    if cmd == "dr" {
        // Fresh appliance: escrowed keys from the box + recovery key, inventory from the box.
        let (tenant_mode, keyd_dir) = match rest {
            [flag, d] if flag == "--tenant-key" => (true, PathBuf::from(d)),
            [d] => (false, PathBuf::from(d)),
            _ => bail!("dr [--tenant-key] <keyd-dir>"),
        };
        let mut rk = zeroize::Zeroizing::new(String::new());
        std::io::stdin().read_to_string(&mut rk)?;
        let deks = if tenant_mode {
            offsite::dr::tenant_keys(remote.as_ref(), &cfg.tenant, &keyd_dir, &rk)?
        } else {
            offsite::dr::appliance_keys(remote.as_ref(), &cfg.tenant, &keyd_dir, &rk)?
        };
        let store = Store::open(&cfg.store, Keyring::new(&cfg.tenant, &deks), StoreOptions::default())?;
        let mut t = Target::open(&store, remote.as_ref(), cfg.state.clone(), opts())?;
        let packs = t.rebuild_from_remote()?;
        println!(
            "DR: keys recovered{}, {packs} packs and {} snapshots indexed",
            if tenant_mode {
                " with the tenant recovery key"
            } else {
                ""
            },
            t.snapshots()?.len()
        );
        return Ok(());
    }

    let keys = keyd::fetch_keyring(&cfg.keyd_socket, &cfg.tenant).context("keyd")?;
    let store = Store::open(&cfg.store, keys, StoreOptions::default())?;
    let mut t = Target::open(&store, remote.as_ref(), cfg.state.clone(), opts())?;
    let gfs = cfg.gfs.as_ref().map_or_else(Gfs::default, |g| Gfs {
        daily: g.daily,
        weekly: g.weekly,
        monthly: g.monthly,
        yearly: g.yearly,
    });
    match (cmd.as_str(), rest) {
        ("upload", []) => {
            let escrow = escrow_files(&cfg.escrow_dir)?;
            for (name, bytes) in &escrow {
                t.put_if_missing(&format!("keys/{name}"), bytes)?;
            }
            let st = t.upload()?;
            // the keys must outlive every locked snapshot (DR needs them)
            for (name, _) in &escrow {
                t.protect(&format!("keys/{name}"))?;
            }
            for n in offsite::dr::prune_tenant_escrow(remote.as_ref(), &cfg.tenant, &escrow) {
                println!("removed old tenant escrow {n}");
            }
            println!(
                "uploaded {} snapshots, {} packs, {} chunks, {} bytes",
                st.snapshots, st.packs, st.chunks, st.bytes
            );
        }
        ("retention", []) => {
            let held = cfg.held.iter().cloned().collect();
            let (k, d, l) = t.apply_retention(&gfs, &held)?;
            for (name, _) in escrow_files(&cfg.escrow_dir).unwrap_or_default() {
                t.protect(&format!("keys/{name}"))?;
            }
            println!("offsite retention: kept {k}, deleted {d}, still locked {l}");
        }
        ("gc", []) => println!("{:?}", t.gc()?),
        ("verify", n) => {
            let n = n.first().map(|s| s.parse()).transpose()?.unwrap_or(3);
            let (packs, bad) = t.verify_sample(n)?;
            println!("verified {packs} packs, {bad} corrupt chunks");
            if bad > 0 {
                bail!("offsite verification failed");
            }
        }
        ("check", []) => {
            let r = t.check_inventory()?;
            println!("missing: {:?}\nunknown: {:?}", r.missing, r.unknown);
            if !r.ok() {
                bail!("offsite inventory anomaly: {} expected files missing", r.missing.len());
            }
        }
        ("list", []) => t.snapshots()?.iter().for_each(|(s, time)| println!("{s}/{time}")),
        ("list", [json]) if json == "--json" => println!("{}", serde_json::to_string(&t.listing()?)?),
        ("restore", [source, time]) => {
            let m = t.restore(source, time.parse()?)?;
            println!("restored {}/{} into the local store", m.source, m.time);
        }
        ("restore", [source, time, keep]) => {
            let m = t.fetch(source, time.parse()?, keep.parse()?)?;
            println!(
                "restored {}/{} into the local store, kept locally for at least {keep} s",
                m.source, m.time
            );
        }
        _ => bail!("unknown command"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The remote part of the job config the scheduler writes for S3.
    #[test]
    fn s3_job_config() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("s"), "SK\n").unwrap();
        let cfg = serde_json::json!({"type": "s3", "endpoint": "https://minio.lan:9000", "region": "us-east-1",
            "bucket": "nexus", "prefix": "t1", "access_key": "appliance", "secret_key_file": d.path().join("s"),
            "path_style": true, "lock": true, "storage_class_packs": "STANDARD_IA"});
        let r: RemoteCfg = serde_json::from_value(cfg.clone()).unwrap();
        assert!(remote(&r, 4).unwrap().supports_locks());
        let mut missing = cfg;
        missing["secret_key_file"] = serde_json::json!(d.path().join("nope"));
        let r: RemoteCfg = serde_json::from_value(missing).unwrap();
        assert!(remote(&r, 4).is_err());
    }
}
