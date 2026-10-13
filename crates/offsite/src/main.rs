//! `nexus-offsite <config.json> upload | retention | gc | verify [packs] | check | list [--json]
//! | restore <source> <time> [<keep-secs>]`, `nexus-offsite <config.json> dr [--tenant-key] <keyd-dir>`
//! (fresh appliance: the appliance recovery key on stdin, or with `--tenant-key` the tenant
//! recovery key; never on the command line, where other processes could read it) and
//! `nexus-offsite <config.json> attach <key-file>` (web UI, Phase 17d: the escrow and the
//! appliance recovery key go to keyd over its socket, the file is removed once read; then the
//! inventory is rebuilt from the box) and `nexus-offsite <config.json> rekey` (after a configuration
//! restore: the tenant's DEKs, wrapped under the restored KEK, from the box to keyd; then the inventory).
//!
//! Appliance configuration backups (`offsite::config`): `config-put <bundle> <appliance-id> <time>`
//! (scheduler, job `config_upload`), `config-list` and `config-get <out-file> [<appliance-id>]`
//! (`nexus-setup restore-config`). These need only `remote` in the config file.

use anyhow::{bail, Context, Result};
use catalog::schedule::{self, Bandwidth, RateWindow};
use chunkstore::retention::Gfs;
use chunkstore::{Keyring, Options as StoreOptions, Store};
use offsite::cfg::{remote, RemoteCfg};
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
    /// bandwidth windows (pause / limit) in `timezone` (Phase 17a)
    #[serde(default)]
    windows: Vec<RateWindow>,
    timezone: Option<String>,
}

fn four() -> usize {
    4
}

#[derive(Deserialize)]
struct GfsCfg {
    daily: u32,
    weekly: u32,
    monthly: u32,
    yearly: u32,
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

/// Only the target: enough for the configuration backup commands.
#[derive(Deserialize)]
struct RemoteOnly {
    remote: RemoteCfg,
}

fn config_cmd(cfg_path: &str, cmd: &str, rest: &[String]) -> Result<()> {
    let cfg: RemoteOnly = serde_json::from_slice(&fs::read(cfg_path)?).context("config")?;
    let remote = remote(&cfg.remote, 1)?;
    let now = catalog::now() as u64;
    match (cmd, rest) {
        ("config-put", [file, id, time]) => {
            let bundle = fs::read(file).with_context(|| format!("reading {file}"))?;
            let (p, deleted) = offsite::config::put(remote.as_ref(), id, time.parse()?, &bundle, now)?;
            println!("uploaded {p} ({} bytes)", bundle.len());
            for d in deleted {
                println!("removed old configuration backup {d}");
            }
        }
        ("config-list", []) => {
            for a in offsite::config::appliances(remote.as_ref())? {
                for (t, size) in offsite::config::list(remote.as_ref(), &a)? {
                    println!("{a} {t} {size}");
                }
            }
        }
        ("config-get", [out, id @ ..]) if id.len() <= 1 => {
            let (a, t, b) = offsite::config::latest(remote.as_ref(), id.first().map(String::as_str))?;
            fs::write(out, &b).with_context(|| format!("writing {out}"))?;
            println!("{a} {t} {}", b.len());
        }
        _ => bail!("config-put <bundle> <appliance-id> <time> | config-list | config-get <out-file> [<appliance-id>]"),
    }
    Ok(())
}

fn main() -> Result<()> {
    keyd::deny_dumps();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [cfg_path, cmd, rest @ ..] = args.as_slice() else {
        bail!("usage: nexus-offsite <config.json> upload | retention | gc | verify [packs] | check | list [--json] | restore <source> <time> [<keep-secs>] | dr [--tenant-key] <keyd-dir> | attach <recovery-key-file> | config-put <bundle> <appliance-id> <time> | config-list | config-get <out-file> [<appliance-id>]");
    };
    if cmd.starts_with("config-") {
        return config_cmd(cfg_path, cmd, rest);
    }
    let cfg: Config = serde_json::from_slice(&fs::read(cfg_path)?).context("config")?;
    let remote = remote(&cfg.remote, cfg.uploaders.clamp(1, 10))?;
    schedule::check_windows(&cfg.windows)?;
    let bandwidth = Bandwidth {
        base: cfg.bwlimit,
        windows: cfg.windows.clone(),
        tz: schedule::tz(cfg.timezone.as_deref().unwrap_or("UTC"))?,
    };
    let opts = || Options {
        uploaders: cfg.uploaders,
        bandwidth: bandwidth.clone(),
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

    if cmd == "rekey" {
        // after a configuration restore (same KEK): the tenant's wrapped DEKs from the box to
        // keyd, no recovery key needed; then the inventory from the box
        let files: Vec<(String, Vec<u8>)> = offsite::dr::appliance_escrow(remote.as_ref(), &cfg.tenant)?
            .into_iter()
            .filter(|(n, _)| n != "kek.recovery")
            .collect();
        let vs = keyd::request_import_wrapped(&cfg.keyd_socket, &cfg.tenant, &files)
            .context("keyd refused the keys: they were not made by this appliance's key (keyd journal)")?;
        let keys = keyd::fetch_keyring(&cfg.keyd_socket, &cfg.tenant).context("keyd")?;
        let store = Store::open(&cfg.store, keys, StoreOptions::default())?;
        let mut t = Target::open(&store, remote.as_ref(), cfg.state.clone(), opts())?;
        let packs = t.rebuild_from_remote()?;
        println!(
            "rekey: keys of tenant {} restored (versions {vs:?}), {packs} packs and {} snapshots indexed",
            cfg.tenant,
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
        recent: 0,
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
