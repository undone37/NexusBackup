//! `nexus-pluginhost <job.json> validate | guests | backup | restore | mount |
//!  files <source> <time> ls <dir> | files <source> <time> get <out.tar|out.zip> <path>...`
//!
//! Spawned by the scheduler with a generated 0600 job config (secrets of the
//! source opened, docs/plugin-system.md). Machine-readable lines on stdout:
//! `committed <source>/<time>: …`, `inconsistent <source>/<time>: …`,
//! `summary <source>/<time>: …` per guest and `result {json}` (backup);
//! `restored {json}` (restore); `mount-ready {json}` / `unmounted {json}` (mount).
//! validate / guests print only their JSON result on stdout (log on stderr).
//! Everything the plugin says is escaped and prefixed (`plugin[…]: `).

use agent_conn::files::Format;
use anyhow::{bail, Context, Result};
use chunkstore::{Options, Store};
use plugin_host::sandbox::{Limits, Options as SandboxOptions, PluginProc, Spec};
use plugin_host::{backup, files, ops, restore, set_log_stderr, Timeouts};
use plugin_proto::{parse_source_name, source_name, Manifest, Op};
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginCfg {
    id: String,
    version: String,
    /// `/var/lib/nexus/plugins/<id>/<version>`
    dir: PathBuf,
    bin_sha256: String,
    /// manifest.json as recorded in the catalog
    manifest: String,
    #[serde(default = "yes")]
    enabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapCfg {
    source: String,
    time: u64,
    /// restore id (restore only)
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    params: Value,
    /// mount only
    #[serde(default)]
    minutes: Option<u64>,
    /// restore only: run with another source's config (manifest `target_source`)
    #[serde(default)]
    target: Option<TargetCfg>,
}

/// Another source of the same kind and tenant (checked by the scheduler), secrets opened.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetCfg {
    source_id: u64,
    config: Value,
}

/// Config the restore runs with and the target source id: the snapshot source's
/// config, or the target source's if the job names one (only for restores whose
/// manifest entry allows it).
fn restore_config(own: &str, s: &SnapCfg, action: &plugin_proto::RestoreAction) -> Result<(String, Option<u64>)> {
    match &s.target {
        None => Ok((own.to_owned(), None)),
        Some(_) if !action.target_source => bail!("restore {:?} cannot run into another source", action.id),
        Some(t) => Ok((t.config.to_string(), Some(t.source_id))),
    }
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct TimeoutCfg {
    op_secs: Option<u64>,
    idle_secs: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JobConfig {
    tenant: String,
    #[serde(default)]
    store: Option<PathBuf>,
    #[serde(default)]
    keyd_socket: Option<PathBuf>,
    #[serde(default)]
    job: u64,
    #[serde(default)]
    plugin: Option<PluginCfg>,
    #[serde(default)]
    source_id: Option<u64>,
    /// manifest kind (without `plugin:`)
    #[serde(default)]
    kind: Option<String>,
    /// source config, secrets opened
    #[serde(default)]
    config: Option<Value>,
    /// backup: guests (empty = the source as a whole)
    #[serde(default)]
    guests: Vec<String>,
    #[serde(default)]
    restore: Option<SnapCfg>,
    #[serde(default)]
    mount: Option<SnapCfg>,
    #[serde(default)]
    timeouts: Option<TimeoutCfg>,
    #[serde(default)]
    tmp_base: Option<PathBuf>,
    /// backup: guests at once (group `parallel_guests`, 1..=8)
    #[serde(default = "one")]
    parallel: usize,
}

fn one() -> usize {
    1
}

fn yes() -> bool {
    true
}

struct Run {
    cfg: JobConfig,
    manifest: Manifest,
    plugin: PluginCfg,
    kind: String,
    source_id: u64,
    config: String,
}

impl Run {
    fn new(mut cfg: JobConfig) -> Result<Run> {
        let plugin = cfg.plugin.take().context("config: plugin missing")?;
        if !plugin.enabled {
            bail!("plugin {} is disabled", plugin.id);
        }
        let manifest: Manifest = serde_json::from_str(&plugin.manifest).context("plugin manifest")?;
        manifest.validate().map_err(anyhow::Error::msg)?;
        if manifest.id != plugin.id || manifest.version != plugin.version {
            bail!("plugin manifest does not match {} {}", plugin.id, plugin.version);
        }
        let kind = cfg.kind.clone().context("config: kind missing")?;
        if !manifest.kinds.iter().any(|k| k.kind == kind) {
            bail!("plugin {} does not provide kind {kind}", plugin.id);
        }
        let source_id = cfg.source_id.context("config: source_id missing")?;
        let config = cfg.config.take().unwrap_or(json!({})).to_string();
        Ok(Run {
            cfg,
            manifest,
            plugin,
            kind,
            source_id,
            config,
        })
    }

    /// TCP ports of the kind's endpoints, resolved in the source config.
    fn ports(&self) -> Option<Vec<u16>> {
        let cfg: Value = serde_json::from_str(&self.config).unwrap_or_default();
        plugin_host::endpoint_ports(&self.manifest, &self.kind, &cfg)
    }

    fn timeouts(&self, op: Op) -> Timeouts {
        let mut t = Timeouts::for_op(op);
        if let Some(c) = &self.cfg.timeouts {
            if let Some(s) = c.op_secs {
                t.op = Duration::from_secs(s.max(1));
            }
            if let Some(s) = c.idle_secs {
                t.idle = Duration::from_secs(s.max(1));
            }
        }
        t
    }

    fn spawn(&self, op: Op, t: Timeouts) -> Result<PluginProc> {
        let spec = Spec {
            dir: self.plugin.dir.clone(),
            bin_sha256: self.plugin.bin_sha256.clone(),
            manifest: Some(self.plugin.manifest.clone()),
            tcp_ports: self.ports(),
            limits: Limits::from_manifest(self.manifest.sandbox.as_ref(), t.op.as_secs()),
            job: self.cfg.job,
        };
        let mut opts = SandboxOptions::default();
        if let Some(b) = &self.cfg.tmp_base {
            opts.tmp_base = b.clone();
        }
        let p = PluginProc::spawn(&spec, &opts, t.op, Some(t.idle))
            .with_context(|| format!("plugin {} {} ({op:?})", self.plugin.id, self.plugin.version))?;
        plugin_host::log_line(&p.report.to_string());
        Ok(p)
    }

    fn snapshot_of(&self, s: &SnapCfg) -> Result<Option<String>> {
        let (id, sid, guest) =
            parse_source_name(&s.source).with_context(|| format!("invalid plugin snapshot source {:?}", s.source))?;
        if id != self.plugin.id || sid != self.source_id {
            bail!(
                "snapshot {} does not belong to source {} of plugin {}",
                s.source,
                self.source_id,
                self.plugin.id
            );
        }
        Ok(guest)
    }

    fn ops_params(&self) -> ops::Params<'_> {
        ops::Params {
            job: self.cfg.job,
            kind: &self.kind,
            config: &self.config,
        }
    }
}

fn open_store(cfg: &JobConfig) -> Result<Store> {
    let root = cfg.store.as_ref().context("config: store missing")?;
    let sock = cfg.keyd_socket.as_ref().context("config: keyd_socket missing")?;
    let keys = keyd::fetch_keyring(sock, &cfg.tenant).context("keyd")?;
    Ok(Store::open(root, keys, Options::default())?)
}

fn out_line(l: &str) {
    plugin_host::log_line(l);
}

fn main() -> Result<()> {
    keyd::deny_dumps();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: nexus-pluginhost <job.json> validate | guests | backup | restore | mount | files <source> <time> ls <dir> | files <source> <time> get <out.tar|out.zip> <path>...";
    let [cfg_path, cmd, rest @ ..] = args.as_slice() else {
        bail!("{usage}");
    };
    let cfg: JobConfig = serde_json::from_slice(&fs::read(cfg_path)?).context("job config")?;
    match (cmd.as_str(), rest) {
        ("validate" | "guests", []) => {
            set_log_stderr(true);
            let run = Run::new(cfg)?;
            let op = if cmd == "validate" {
                Op::Validate
            } else {
                Op::ListGuests
            };
            let t = run.timeouts(op);
            let mut p = run.spawn(op, t)?;
            let r = if op == Op::Validate {
                ops::validate(&mut p, &run.ops_params(), &mut |l| eprintln!("{l}"))?
            } else {
                ops::guests(&mut p, &run.ops_params(), &mut |l| eprintln!("{l}"))?
            };
            println!("{r}");
        }
        ("backup", []) => {
            let run = Run::new(cfg)?;
            let parallel = run.cfg.parallel.clamp(1, 8);
            // in parallel every guest gets its own Store handle: `written()` deltas
            // (nexus-stats, new_bytes) stay per snapshot
            let shared = if parallel == 1 {
                Some(open_store(&run.cfg)?)
            } else {
                None
            };
            let guests: Vec<Option<String>> = if run.cfg.guests.is_empty() {
                vec![None]
            } else {
                run.cfg.guests.iter().cloned().map(Some).collect()
            };
            // Ok = snapshot summary, Err = failure record
            let one = |g: &Option<String>| -> Result<Value, Value> {
                if let Some(g) = g {
                    if !plugin_proto::valid_guest_id(g) {
                        return Err(json!({"guest": g, "error": "invalid guest id"}));
                    }
                }
                let source = source_name(&run.plugin.id, run.source_id, g.as_deref());
                let into = |store: &Store| {
                    let mut p = run.spawn(Op::Backup, run.timeouts(Op::Backup))?;
                    backup::run(
                        store,
                        &mut p,
                        &backup::Params {
                            job: run.cfg.job,
                            kind: &run.kind,
                            config: &run.config,
                            params: json!({ "guest": g, "source_id": run.source_id }),
                            source: &source,
                            bounds: backup::Bounds::default(),
                        },
                        &mut |l| out_line(l),
                    )
                };
                let r = match &shared {
                    Some(s) => into(s),
                    None => open_store(&run.cfg).and_then(|s| into(&s)),
                };
                match r {
                    Ok(r) => Ok(json!({
                        "source": r.source, "time": r.time, "base": r.base, "entries": r.entries, "files": r.files,
                        "streams": r.streams, "unchanged": r.unchanged, "bytes": r.bytes,
                        "transferred_bytes": r.transferred, "new_bytes": r.new_bytes, "consistent": r.consistent,
                    })),
                    Err(e) => {
                        out_line(&format!(
                            "failed {source}: {}",
                            plugin_host::escape(&format!("{e:#}"), 2000)
                        ));
                        Err(json!({"source": source, "error": format!("{e:#}")}))
                    }
                }
            };
            let (mut done, mut failed) = (Vec::new(), Vec::new());
            for r in plugin_host::run_parallel(&guests, parallel, one) {
                match r {
                    Ok(v) => done.push(v),
                    Err(v) => failed.push(v),
                }
            }
            out_line(&format!("result {}", json!({"snapshots": done, "failed": failed})));
            if !failed.is_empty() {
                bail!("{} of {} backups failed", failed.len(), guests.len());
            }
        }
        ("restore", []) => {
            let mut run = Run::new(cfg)?;
            let s = run.cfg.restore.take().context("config: restore missing")?;
            let guest = run.snapshot_of(&s)?;
            let id = s.id.clone().context("config: restore.id missing")?;
            let kind = run.manifest.kinds.iter().find(|k| k.kind == run.kind).unwrap();
            let Some(action) = kind.restores.iter().find(|r| r.id == id).filter(|_| id != "download") else {
                bail!(
                    "restore {id:?} is not offered by kind {} (download runs as files_get)",
                    run.kind
                );
            };
            // manifest v1.4 `applies_to`: a guest restore never runs on a whole-source
            // snapshot and vice versa
            if !action.applies(guest.is_some()) {
                bail!(
                    "restore {id:?} applies to {} snapshots, {} is a {} snapshot",
                    action.applies_to.as_deref().unwrap_or("any"),
                    s.source,
                    if guest.is_some() { "guest" } else { "source" }
                );
            }
            let (config, target_source_id) = restore_config(&run.config, &s, action)?;
            // endpoints (sandbox ports) and credentials: those of the target source
            run.config = config;
            let store = open_store(&run.cfg)?;
            let snap = restore::Snapshot::load(&store, &s.source, s.time)?;
            let mut params = s.params.clone();
            if let (Some(o), Some(g)) = (params.as_object_mut(), &guest) {
                o.insert("guest".into(), json!(g));
            }
            let t = run.timeouts(Op::Restore);
            let mut p = run.spawn(Op::Restore, t)?;
            let r = restore::run(
                &store,
                &mut p,
                &snap,
                &restore::Params {
                    job: run.cfg.job,
                    kind: &run.kind,
                    config: &run.config,
                    restore: &id,
                    params,
                    max_log_bytes: 4 << 20,
                    target_source_id,
                },
                &mut |l| out_line(l),
            )?;
            out_line(&format!(
                "restored {}",
                json!({"restore": id, "source": s.source, "time": s.time, "files": r.files_sent,
                       "streams": r.streams_sent, "bytes": r.bytes_sent, "summary": plugin_host::escape(&r.summary, 4000)})
            ));
        }
        ("mount", []) => {
            let run = Run::new(cfg)?;
            let s = run.cfg.mount.as_ref().context("config: mount missing")?;
            run.snapshot_of(s)?;
            let minutes = s.minutes.unwrap_or(60).clamp(1, 24 * 60);
            let store = open_store(&run.cfg)?;
            let snap = restore::Snapshot::load(&store, &s.source, s.time)?;
            let mut t = run.timeouts(Op::Mount);
            t.op = t.op.max(Duration::from_secs(minutes * 60 + 600));
            let mut p = run.spawn(Op::Mount, t)?;
            let r = ops::mount(
                &store,
                &mut p,
                &snap,
                &run.ops_params(),
                s.params.clone(),
                Duration::from_secs(minutes * 60),
                &mut |l| out_line(l),
            )?;
            out_line(&format!("unmounted {r}"));
        }
        ("files", [source, time, op, args @ ..]) => {
            if parse_source_name(source).is_none() {
                bail!("invalid source {source:?} (expected plugin-<id>-<source>[-<guest>])");
            }
            let store = open_store(&cfg)?;
            let snap = restore::Snapshot::load(&store, source, time.parse()?)?;
            match (op.as_str(), args) {
                ("ls", [dir]) => println!("{}", serde_json::to_string_pretty(&files::list(&snap, dir)?)?),
                ("get", [out, paths @ ..]) if !paths.is_empty() => {
                    let out = Path::new(out);
                    let n = agent_conn::files::extract(
                        &store,
                        &files::view(&snap),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_runs_with_the_target_sources_credentials() {
        let mut action: plugin_proto::RestoreAction =
            serde_json::from_value(json!({"id": "to_other", "title": "x"})).unwrap();
        let snap = |target: Value| -> SnapCfg {
            serde_json::from_value(
                json!({"source": "plugin-m365-3-u.x", "time": 1, "id": "to_other", "target": target}),
            )
            .unwrap()
        };
        let own = r#"{"client_id":"own"}"#;
        assert_eq!(
            restore_config(own, &snap(Value::Null), &action).unwrap(),
            (own.to_owned(), None)
        );
        let other = snap(json!({"source_id": 9, "config": {"client_id": "other"}}));
        // a restore whose manifest entry does not allow it never gets another source's secrets
        assert!(restore_config(own, &other, &action).is_err());
        action.target_source = true;
        let (cfg, sid) = restore_config(own, &other, &action).unwrap();
        let cfg: Value = serde_json::from_str(&cfg).unwrap();
        assert_eq!((cfg["client_id"].clone(), sid), (json!("other"), Some(9)));
    }
}
