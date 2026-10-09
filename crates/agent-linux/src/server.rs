//! Linux half of the agent: [`Linux`] implements `agent_core::server::Platform`
//! (volumes, hooks, snapshots, the walk, restore, self-update). Listener, enrollment
//! and the session state machine live in `agent_core::server`.

use crate::cache::Cache;
use crate::glob::Excludes;
use crate::restore::Restore;
use crate::scan::{Locator, Root, Scanner};
use crate::snapshot::{self, Snap};
use crate::{hooks, update, volumes};
use agent_core::server::{Ctx, HostInfo, Platform, PreparedJob, Refused, ScanError, ScanOutput};
use agent_proto::{Entry, Overwrite, Volume};
use std::collections::HashSet;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::time::Duration;

pub use agent_core::server::{
    failures, load_mode, log, Mode, E_AUTH, E_BAD_REQUEST, E_BUSY, E_CHUNKS_GONE, E_INTERNAL, E_LOCKED, E_REFUSED,
    E_UNKNOWN_JOB, E_VERSION, MAX_FAILED_PROOFS,
};

/// The Linux agent.
pub type Agent = agent_core::server::Agent<Linux>;

#[derive(Default)]
pub struct Linux;

pub struct Job {
    snaps: Vec<Snap>,
    roots: Vec<Root>,
    excludes: Excludes,
    hooks: bool,
}

fn run_hooks(ctx: Ctx, phase: &str, env: &[(&str, String)]) -> (bool, String) {
    hooks::run(
        &ctx.paths.hooks(),
        phase,
        ctx.settings.hook_owner,
        Duration::from_secs(ctx.settings.hook_timeout_secs),
        env,
    )
}

fn bad(msg: impl Into<String>) -> Refused {
    Refused(E_BAD_REQUEST, msg.into())
}

impl Platform for Linux {
    type Job = Job;
    type Restore = Restore;

    fn host_info(&self) -> HostInfo {
        let (kernel, hostname) = crate::sys::uname();
        HostInfo {
            os: os_name(),
            kernel,
            hostname,
            caps: caps(),
            agent_version: env!("CARGO_PKG_VERSION").into(),
        }
    }

    fn list_volumes(&self) -> Vec<Volume> {
        volumes::list_volumes()
    }

    fn prepare(
        &self,
        ctx: Ctx,
        job: u64,
        paths: &[String],
        excludes: &[String],
        hooks: bool,
    ) -> Result<PreparedJob<Job>, Refused> {
        let mut norm = vec![];
        for p in paths {
            norm.push(volumes::normalize(p).map_err(bad)?);
        }
        let mut mounts = volumes::mounts();
        // nested btrfs subvolumes count as volumes of their own (like mount points): a
        // path inside one is read from its own snapshot, and they are not included
        // unless requested (a snapshot of the parent shows them as empty directories)
        let mut nested_notes = vec![];
        let btrfs: Vec<volumes::Mount> = mounts
            .iter()
            .filter(|m| m.fstype == "btrfs" && norm.iter().any(|p| p.starts_with(&m.mountpoint)))
            .cloned()
            .collect();
        for m in &btrfs {
            for n in volumes::btrfs_nested(m, &mounts) {
                let below = norm.iter().any(|p| n.mountpoint.starts_with(p) && *p != n.mountpoint);
                let requested = norm.iter().any(|p| p.starts_with(&n.mountpoint));
                if below && !requested && !Excludes::new(excludes).matches(n.mountpoint.as_os_str().as_bytes()) {
                    nested_notes.push(format!(
                        "btrfs subvolume {} is not included (like a mount point): add it to the paths to back it up",
                        n.mountpoint.display()
                    ));
                }
                mounts.push(n);
            }
        }
        let mut by_mount: Vec<(volumes::Mount, Vec<PathBuf>)> = vec![];
        for p in norm {
            let Some(m) = volumes::containing(&mounts, &p) else {
                return Err(bad(format!("{} is not on a mounted file system", p.display())));
            };
            if !volumes::is_data_fs(m) {
                return Err(bad(format!(
                    "{} is on {} ({}), not a data file system",
                    p.display(),
                    m.mountpoint.display(),
                    m.fstype
                )));
            }
            match by_mount.iter_mut().find(|(x, _)| x.mountpoint == m.mountpoint) {
                Some((_, v)) => v.push(p),
                None => by_mount.push((m.clone(), vec![p])),
            }
        }
        let mut log_text = String::new();
        let env = [("NEXUS_JOB", job.to_string())];
        if hooks {
            let (ok, l) = run_hooks(ctx, "pre", &env);
            log_text.push_str(&l);
            if !ok {
                let (_, l) = run_hooks(
                    ctx,
                    "post",
                    &[("NEXUS_JOB", job.to_string()), ("NEXUS_SUCCESS", "0".into())],
                );
                log_text.push_str(&l);
                return Err(Refused(
                    E_REFUSED,
                    format!("pre hook failed, nothing snapshotted:\n{log_text}"),
                ));
            }
        }
        for n in nested_notes {
            log(&n);
            log_text.push_str(&n);
            log_text.push('\n');
        }
        let mut snaps = vec![];
        let mut roots = vec![];
        for (idx, (m, mut ps)) in by_mount.into_iter().enumerate() {
            let (snap, note) = snapshot::prepare(ctx.paths, ctx.settings, job, idx, &m);
            if let Some(n) = note {
                log(&n);
                log_text.push_str(&n);
                log_text.push('\n');
            }
            ps.sort();
            ps.dedup();
            let mut kept: Vec<PathBuf> = vec![];
            for p in ps {
                if !kept.iter().any(|k| p.starts_with(k)) {
                    kept.push(p);
                }
            }
            for p in kept {
                roots.push(Root {
                    src: snapshot::source_path(&snap, &p),
                    host: p,
                    live: !snap.consistent(),
                });
            }
            snaps.push(snap);
        }
        let consistent = snaps.iter().all(Snap::consistent);
        let snapshots = snaps.iter().filter_map(|s| s.info.clone()).collect();
        Ok(PreparedJob {
            job: Job {
                snaps,
                roots,
                excludes: Excludes::new(excludes),
                hooks,
            },
            snapshots,
            consistent,
            hook_log: log_text,
            writers: vec![],
        })
    }

    fn scan(
        &self,
        ctx: Ctx,
        j: &mut Job,
        id: u64,
        base: Option<u64>,
        cache: Option<&Cache>,
        emit: &mut dyn FnMut(Entry) -> io::Result<()>,
    ) -> Result<ScanOutput, ScanError> {
        let live = j.roots.iter().any(|r| r.live);
        let locator = Locator::new(
            live.then(|| ctx.paths.spool_dir()).as_deref(),
            ctx.settings.spool_max_bytes,
        )
        .map_err(|e| ScanError::Refused(Refused(E_INTERNAL, format!("spool: {e}"))))?;
        let mut scanner = Scanner::new(&j.excludes, cache, locator, Cache::new(id, base));
        scanner.mountpoints = volumes::mounts()
            .into_iter()
            .map(|m| m.mountpoint)
            .collect::<HashSet<_>>();
        scanner.run(&j.roots, emit)?;
        let stats = std::mem::take(&mut scanner.stats);
        let Scanner { locator, new_cache, .. } = scanner;
        Ok(ScanOutput {
            stats,
            locator,
            cache: new_cache,
        })
    }

    fn release_snapshots(&self, ctx: Ctx, j: &mut Job, _id: u64, _success: bool) -> String {
        let mut text = String::new();
        for snap in &mut j.snaps {
            for e in snap.release(ctx.paths) {
                log(&e);
                text.push_str(&format!("snapshot cleanup: {e}\n"));
            }
        }
        text
    }

    fn finish_job(&self, ctx: Ctx, j: Job, id: u64, success: bool) -> String {
        if !j.hooks {
            return String::new();
        }
        run_hooks(
            ctx,
            "post",
            &[
                ("NEXUS_JOB", id.to_string()),
                ("NEXUS_SUCCESS", if success { "1" } else { "0" }.into()),
            ],
        )
        .1
    }

    fn restore_begin(
        &self,
        _ctx: Ctx,
        job: u64,
        target: &str,
        overwrite: Overwrite,
        confirm: &str,
    ) -> io::Result<Restore> {
        Restore::begin(job, target, overwrite, confirm)
    }

    fn update(&self, ctx: Ctx, version: &str, binary: &[u8], signature: &[u8]) -> Result<String, String> {
        let exe = std::env::current_exe()
            .and_then(fs::canonicalize)
            .map_err(|e| format!("current executable: {e}"))?;
        let keys = update::load_keys(&ctx.paths.release_keys());
        update::apply(version, binary, signature, &keys, env!("CARGO_PKG_VERSION"), &exe)
    }

    fn restart_after_update(&self) -> ! {
        // systemd restarts the service (RestartForceExitStatus=75)
        std::process::exit(update::RESTART_EXIT_CODE)
    }
}

pub fn os_name() -> String {
    let t = fs::read_to_string("/etc/os-release").unwrap_or_default();
    t.lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim_matches('"').to_string())
        .unwrap_or_else(|| "Linux".into())
}

pub fn caps() -> Vec<String> {
    let mut c: Vec<String> = ["fallback", "xattrs", "acl", "hardlinks", "hooks", "restore", "update"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    for (tool, cap) in [("lvcreate", "lvm"), ("zfs", "zfs"), ("btrfs", "btrfs")] {
        if volumes::tool(tool).is_some() {
            c.push(cap.into());
        }
    }
    c
}
