//! `nexus-offsite <config.json> upload | retention | gc | verify [packs] | check | list | restore <source> <time>`
//! and `nexus-offsite <config.json> dr <keyd-dir>` (fresh appliance: recovery key on stdin).

use anyhow::{bail, Context, Result};
use chunkstore::retention::Gfs;
use chunkstore::{Keyring, Options as StoreOptions, Store};
use offsite::remote::{LocalDir, Remote};
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
        bail!("usage: nexus-offsite <config.json> upload | retention | gc | verify [packs] | check | list | restore <source> <time> | dr <keyd-dir>");
    };
    let cfg: Config = serde_json::from_slice(&fs::read(cfg_path)?).context("config")?;
    let remote = remote(&cfg.remote, cfg.uploaders.clamp(1, 10))?;
    let opts = || Options {
        uploaders: cfg.uploaders,
        bwlimit: cfg.bwlimit,
        ..Default::default()
    };

    if cmd == "dr" {
        // Fresh appliance: escrowed keys from the box + recovery key, inventory from the box.
        let keyd_dir = PathBuf::from(rest.first().context("dr <keyd-dir>")?);
        let mut rk = String::new();
        std::io::stdin().read_to_string(&mut rk)?;
        let mut files = vec![("kek.recovery".to_owned(), remote.get("keys/kek.recovery", 0, None)?)];
        for (n, _, _) in remote.list(&format!("keys/tenants/{}", cfg.tenant))? {
            let name = format!("tenants/{}/{n}", cfg.tenant);
            files.push((name.clone(), remote.get(&format!("keys/{name}"), 0, None)?));
        }
        keyd::import_escrow(&keyd_dir, &files)?;
        keyd::recover(&keyd_dir, &rk)?;
        let deks: Vec<(u32, [u8; 32])> = keyd::tenant_deks(&keyd_dir, &cfg.tenant)?
            .into_iter()
            .map(|(v, k)| (v, *k))
            .collect();
        let store = Store::open(&cfg.store, Keyring::new(&cfg.tenant, &deks), StoreOptions::default())?;
        let mut t = Target::open(&store, remote.as_ref(), cfg.state.clone(), opts())?;
        let packs = t.rebuild_from_remote()?;
        println!(
            "DR: keys recovered, {packs} packs and {} snapshots indexed",
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
            for (name, bytes) in escrow_files(&cfg.escrow_dir)? {
                t.put_if_missing(&format!("keys/{name}"), &bytes)?;
            }
            let st = t.upload()?;
            println!(
                "uploaded {} snapshots, {} packs, {} chunks, {} bytes",
                st.snapshots, st.packs, st.chunks, st.bytes
            );
        }
        ("retention", []) => {
            let (k, d, l) = t.apply_retention(&gfs)?;
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
        ("restore", [source, time]) => {
            let m = t.restore(source, time.parse()?)?;
            println!("restored {}/{} into the local store", m.source, m.time);
        }
        _ => bail!("unknown command"),
    }
    Ok(())
}
