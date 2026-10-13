//! Linux half of the agent: [`Linux`] implements `agent_core::server::Platform`
//! (volumes, hooks, snapshots, the walk, restore, self-update). Listener, enrollment
//! and the session state machine live in `agent_core::server`.

use crate::cache::Cache;
use crate::glob::Excludes;
use crate::restore::Restore;
use crate::scan::{Locator, Root, Scanner};
use crate::snapshot::{self, Snap};
use crate::{hooks, update, volumes};
use agent_core::filter::Filter;
use agent_core::server::{Ctx, HostInfo, Installed, Platform, PreparedJob, Refused, ScanError, ScanOutput, Staged};
use agent_proto::{Entry, Filters, Overwrite, Volume};
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
pub struct Linux {
    /// the binary a `binary` update replaces (tests); default: the running executable
    pub exe: Option<PathBuf>,
    /// desktop package version (asked once: the process restarts after an update)
    gui: std::sync::OnceLock<Option<String>>,
}

impl Linux {
    pub fn with_exe(exe: PathBuf) -> Linux {
        Linux {
            exe: Some(exe),
            ..Default::default()
        }
    }

    fn exe(&self) -> Result<PathBuf, String> {
        match &self.exe {
            Some(e) => Ok(e.clone()),
            None => std::env::current_exe()
                .and_then(fs::canonicalize)
                .map_err(|e| format!("current executable: {e}")),
        }
    }

    fn install(&self) -> String {
        agent_core::update::install_type(
            agent_core::update::packaged(&agent_core::update::package_marker()).as_deref(),
            "bundle",
        )
    }
}

pub struct Job {
    snaps: Vec<Snap>,
    roots: Vec<Root>,
    filter: Filter,
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
        filters: &Filters,
        hooks: bool,
    ) -> Result<PreparedJob<Job>, Refused> {
        let mut norm = vec![];
        for p in paths {
            norm.push(volumes::normalize(p).map_err(bad)?);
        }
        let mut include = vec![];
        for p in &filters.include {
            include.push(volumes::normalize(p).map_err(bad)?.to_string_lossy().into_owned());
        }
        let filter = Filter::new(Excludes::new(excludes), &include, &filters.exclude_regex, false).map_err(bad)?;
        let mut mounts = volumes::mounts();
        let mut nested_notes = vec![];
        if filters.cross_mounts {
            let (add, notes) = volumes::nested_roots(&mounts, &norm, &filters.skip_fstypes, &filter);
            nested_notes.extend(notes);
            norm.extend(add);
        }
        // nested btrfs subvolumes count as volumes of their own (like mount points): a
        // path inside one is read from its own snapshot, and they are not included
        // unless requested (a snapshot of the parent shows them as empty directories)
        let mut nested_subvols = vec![];
        let btrfs: Vec<volumes::Mount> = mounts
            .iter()
            .filter(|m| m.fstype == "btrfs" && norm.iter().any(|p| p.starts_with(&m.mountpoint)))
            .cloned()
            .collect();
        for m in &btrfs {
            for n in volumes::btrfs_nested(m, &mounts) {
                let below = norm.iter().any(|p| n.mountpoint.starts_with(p) && *p != n.mountpoint);
                let requested = norm.iter().any(|p| p.starts_with(&n.mountpoint));
                if below && !requested && !filter.excluded(n.mountpoint.as_os_str().as_bytes()) {
                    if filters.cross_mounts {
                        nested_subvols.push(n.mountpoint.clone());
                    } else {
                        nested_notes.push(format!(
                            "btrfs subvolume {} is not included (like a mount point): add it to the paths to back it up",
                            n.mountpoint.display()
                        ));
                    }
                }
                mounts.push(n);
            }
        }
        norm.extend(nested_subvols);
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
                filter,
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
        let mut scanner = Scanner::new(&j.filter, cache, locator, Cache::new(id, base));
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

    fn lower_priority(&self, nice: u8) -> String {
        match crate::sys::lower_priority(nice) {
            Ok((n, idle)) => format!(
                "priority lowered: nice {n}, {} I/O",
                if idle { "idle" } else { "best-effort" }
            ),
            Err(e) => format!("priority not lowered: {e}"),
        }
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
        let exe = self.exe()?;
        let keys = update::load_keys(&ctx.paths.release_keys());
        update::apply(version, binary, signature, &keys, env!("CARGO_PKG_VERSION"), &exe)
    }

    fn restart_after_update(&self) -> ! {
        // systemd restarts the service (RestartForceExitStatus=75)
        std::process::exit(update::RESTART_EXIT_CODE)
    }

    fn layout(&self) -> Result<String, Refused> {
        let run = agent_core::config::Paths::default().run;
        Ok(crate::layout::capture_json(&run.to_string_lossy()))
    }

    fn power_state(&self) -> agent_proto::PowerState {
        crate::power::state()
    }

    fn host_facts(&self) -> Option<agent_proto::release::HostFacts> {
        let install = self.install();
        let gui = self.gui.get_or_init(|| update::desktop_version(&install)).clone();
        Some(agent_proto::release::HostFacts {
            os: "linux".into(),
            arch: update::arch().into(),
            install,
            gui_version: gui,
        })
    }

    fn native_binary(&self, binary: &[u8]) -> bool {
        update::native(binary)
    }

    fn install_update(&self, ctx: Ctx, staged: &[Staged], rollback: bool) -> Result<Installed, String> {
        let main = staged.last().ok_or("nothing staged")?;
        match main.kind.as_str() {
            agent_proto::release::KIND_BINARY => {
                if staged.len() != 1 {
                    return Err("a binary update carries one artifact".into());
                }
                let exe = self.exe()?;
                let data = fs::read(&main.path).map_err(|e| format!("{}: {e}", main.path.display()))?;
                update::swap(&exe, &data)?;
                let _ = fs::remove_file(&main.path);
                Ok(Installed::Restart(format!(
                    "updated {} -> {} ({})",
                    env!("CARGO_PKG_VERSION"),
                    main.version,
                    exe.display()
                )))
            }
            kind @ ("deb" | "rpm") => {
                let files: Vec<PathBuf> = staged.iter().map(|s| s.path.clone()).collect();
                let argv = update::package_command(
                    kind,
                    &files,
                    &agent_core::update::staging_dir(ctx.paths),
                    rollback,
                    &update::Tools::probe(),
                )?;
                // a failed unit of an earlier attempt would block the name
                let _ = crate::volumes::run_tool("systemctl", &["reset-failed", update::UPDATE_UNIT]);
                let out = std::process::Command::new(&argv[0])
                    .args(&argv[1..])
                    .env_clear()
                    .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
                    .stdin(std::process::Stdio::null())
                    .output()
                    .map_err(|e| format!("{}: {e}", argv[0]))?;
                if !out.status.success() {
                    return Err(format!(
                        "systemd-run failed ({}): {}",
                        out.status,
                        String::from_utf8_lossy(&out.stderr).trim()
                    ));
                }
                Ok(Installed::Started(
                    format!(
                        "installing {} with {} in {}",
                        staged.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(", "),
                        argv.iter()
                            .skip_while(|a| *a != "--")
                            .nth(1)
                            .map_or("?", String::as_str),
                        update::UPDATE_UNIT
                    ),
                    update::UPDATE_UNIT.into(),
                ))
            }
            k => Err(format!("{k} artifacts are not installed on Linux")),
        }
    }

    fn install_result(&self, _ctx: Ctx, pending: &agent_core::update::Pending) -> agent_core::update::InstallResult {
        use agent_core::update::InstallResult;
        let unit = if pending.unit.is_empty() {
            update::UPDATE_UNIT
        } else {
            pending.unit.as_str()
        };
        let Ok(show) = crate::volumes::run_tool(
            "systemctl",
            &["show", unit, "--property=LoadState,ActiveState,Result,ExecMainStatus"],
        ) else {
            return InstallResult::Unknown;
        };
        match update::parse_unit_show(&show) {
            InstallResult::Failed(e, _) => {
                let log = crate::volumes::run_tool("journalctl", &["-u", unit, "-n", "30", "--no-pager", "-o", "cat"])
                    .map(|t| agent_core::update::tail_lines(&t, 30))
                    .unwrap_or_default();
                let _ = crate::volumes::run_tool("systemctl", &["reset-failed", unit]);
                InstallResult::Failed(e, log)
            }
            r => r,
        }
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
    let mut c: Vec<String> = [
        "fallback",
        "xattrs",
        "acl",
        "hardlinks",
        "hooks",
        "restore",
        "update",
        agent_proto::CAP_LAYOUT,
    ]
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
