//! `nexus-replica <config.json> enroll|sync` (secondary, spawned by the
//! scheduler; docs/replication.md §4, §7).
//!
//! Config: `{source_id, name, url, connect_addr?, cert_pin, peer_id, cred_dir,
//! keyd_socket, token_file? (enroll), tenant?, store? (sync: the tenant store),
//! gfs?, bwlimit?, parallel?}`.
//!
//! Output lines the scheduler parses: `enrolled {json}`, `replicated {json}`,
//! `key-mismatch {json}`, `verify-failed {json}`.

use anyhow::{bail, Context, Result};
use chunkstore::retention::Gfs;
use replication::client::{enroll, sync, EnrollParams, KeysMissing, SyncParams, VerifyFailed};
use replication::http::Target;
use serde::Deserialize;
use serde_json::json;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Deserialize)]
struct Config {
    name: String,
    url: String,
    connect_addr: Option<std::net::SocketAddr>,
    cert_pin: String,
    peer_id: String,
    cred_dir: PathBuf,
    keyd_socket: PathBuf,
    token_file: Option<PathBuf>,
    tenant: Option<String>,
    store: Option<PathBuf>,
    #[serde(default)]
    gfs: Option<GfsCfg>,
    bwlimit: Option<u64>,
    parallel: Option<usize>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct GfsCfg {
    daily: Option<u32>,
    weekly: Option<u32>,
    monthly: Option<u32>,
    yearly: Option<u32>,
}

fn run() -> Result<()> {
    keyd::deny_dumps();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [cfg, cmd] = args.as_slice() else {
        bail!("usage: nexus-replica <config.json> enroll|sync");
    };
    let c: Config = serde_json::from_slice(&std::fs::read(cfg)?).context("config")?;
    let mut target = Target::parse(&c.url, &c.cert_pin)?;
    target.connect_addr = c.connect_addr;
    match cmd.as_str() {
        "enroll" => {
            let digest = std::fs::read_to_string(c.token_file.as_ref().context("token_file")?)?;
            let keyd_pub = keyd::fetch_replica_pubkey(&c.keyd_socket).context("keyd replica-pubkey")?;
            let e = enroll(&EnrollParams {
                target: &target,
                peer_id: &c.peer_id,
                token_digest: digest.trim(),
                name: &c.name,
                cred_dir: &c.cred_dir,
                keyd_pub,
            })?;
            println!("enrolled {}", serde_json::to_string(&e)?);
        }
        "sync" => {
            let d = Gfs::default();
            let g = c.gfs.unwrap_or_default();
            let p = SyncParams {
                target,
                cred_dir: c.cred_dir,
                tenant: c.tenant.context("tenant")?,
                store: c.store.context("store")?,
                keyd_socket: c.keyd_socket,
                gfs: Gfs {
                    daily: g.daily.unwrap_or(d.daily),
                    weekly: g.weekly.unwrap_or(d.weekly),
                    monthly: g.monthly.unwrap_or(d.monthly),
                    yearly: g.yearly.unwrap_or(d.yearly),
                },
                parallel: c.parallel.unwrap_or(4),
                bwlimit: c.bwlimit,
            };
            let tenant = p.tenant.clone();
            let r = sync(&p, &mut |l| println!("{l}"));
            match r {
                Ok(rep) => println!("replicated {}", serde_json::to_string(&rep)?),
                Err(e) => {
                    if let Some(v) = e.downcast_ref::<VerifyFailed>() {
                        println!("verify-failed {}", json!({"tenant": tenant, "error": v.0}));
                    } else if let Some(k) = e.downcast_ref::<KeysMissing>() {
                        println!("key-mismatch {}", json!({"tenant": tenant, "error": k.0}));
                    }
                    return Err(e);
                }
            }
        }
        _ => bail!("unknown command {cmd:?}"),
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("nexus-replica: {e:#}");
            ExitCode::FAILURE
        }
    }
}
