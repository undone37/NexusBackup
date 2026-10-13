//! Windows half of the agent: [`Windows`] implements `agent_core::server::Platform`.

pub mod acl;
pub mod cli;
pub mod host;
pub mod pipe;
pub mod power;
pub mod restore;
pub mod source;
pub mod sys;
pub mod usnio;
pub mod volumes;
pub mod vss;

use crate::paths::WinPath;
use crate::scan::{Root, Walker};
use crate::usn::{continuity, Changes, Continuity, JournalData};
use crate::{update, writers};
use agent_core::cache::{Cache, JournalMark};
use agent_core::chunk::Locator;
use agent_core::filter::Filter;
use agent_core::server::{
    log, Ctx, HostInfo, Platform, PreparedJob, Refused, ScanError, ScanOutput, E_BAD_REQUEST, E_INTERNAL,
};
use agent_proto::{Entry, Filters, Overwrite, SnapshotInfo, SnapshotKind, Volume};
use std::io;
use std::path::PathBuf;
use volumes::Vol;

/// Privileges the service enables at start (LocalSystem holds them).
pub const PRIVILEGES: [&str; 4] = [
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeSecurityPrivilege",
    "SeTakeOwnershipPrivilege",
];

#[derive(Default)]
pub struct Windows {
    /// SeSecurityPrivilege is enabled: SACLs are read and restored
    pub sacl: bool,
}

/// The Windows agent.
pub type Agent = agent_core::server::Agent<Windows>;

struct VolJob {
    vol: Vol,
    /// journal state queried before the snapshot (None = no journal support)
    journal: Option<JournalData>,
}

pub struct Job {
    set: Option<vss::SnapshotSet>,
    vols: Vec<VolJob>,
    roots: Vec<Root>,
    filter: Filter,
}

/// A requested path must not pass through a symlink or junction below its volume's
/// mount point: inside a shadow copy such a link would resolve to the *live* file
/// system (or another volume) and the data would silently not come from the snapshot.
fn through_link(p: &WinPath, mount: &WinPath) -> Result<(), String> {
    for k in mount.comps.len() + 1..p.comps.len() {
        let prefix = WinPath {
            drive: p.drive,
            comps: p.comps[..k].to_vec(),
        };
        let Ok(h) = sys::open_meta(std::path::Path::new(&prefix.verbatim()), 0) else {
            return Ok(()); // missing: reported by the scan
        };
        let t = sys::tag_info(&h).map_err(|e| format!("{}: {e}", prefix.win32()))?;
        if t.FileAttributes & crate::meta::FILE_ATTRIBUTE_REPARSE_POINT != 0 && crate::meta::is_link_tag(t.ReparseTag) {
            return Err(format!(
                "{} goes through the link {}; select the link target instead",
                p.win32(),
                prefix.win32()
            ));
        }
    }
    Ok(())
}

impl Platform for Windows {
    type Job = Job;
    type Restore = restore::Restore;

    fn host_info(&self) -> HostInfo {
        host::info()
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
        let bad = |m: String| Refused(E_BAD_REQUEST, m);
        // cross_mounts / skip_fstypes: volumes are walked as requested (mounted
        // folders are reparse points, never followed), nothing to cross
        let filter = crate::filter(excludes, filters).map_err(bad)?;
        let excluded_writers = writers::parse_exclusions(&ctx.settings.vss_exclude_writers).map_err(bad)?;
        let mut wanted: Vec<WinPath> = vec![];
        for p in paths {
            wanted.push(WinPath::parse(p).map_err(bad)?);
        }
        wanted.sort();
        wanted.dedup();
        let mut kept: Vec<WinPath> = vec![];
        for p in wanted {
            if !kept.iter().any(|k| p.starts_with(k)) {
                kept.push(p);
            }
        }
        let mut log_text = String::new();
        if hooks {
            log_text
                .push_str("hooks: not supported by the Windows agent (VSS writers provide application consistency)\n");
        }
        // group by volume
        let mut vols: Vec<VolJob> = vec![];
        let mut by_path: Vec<(WinPath, usize)> = vec![];
        for p in kept {
            let v = volumes::containing(&p).map_err(|e| bad(format!("{}: {e}", p.win32())))?;
            through_link(&p, &v.mount).map_err(bad)?;
            let i = match vols.iter().position(|x| x.vol.guid == v.guid) {
                Some(i) => i,
                None => {
                    vols.push(VolJob { vol: v, journal: None });
                    vols.len() - 1
                }
            };
            by_path.push((p, i));
        }
        // journal positions *before* the snapshot (see usn.rs)
        for vj in &mut vols {
            match usnio::query(&vj.vol.guid, true) {
                Ok(Some((jd, created))) => {
                    if created {
                        log_text.push_str(&format!("{}: USN journal created\n", vj.vol.mount.win32()));
                    }
                    vj.journal = Some(jd);
                }
                Ok(None) => log_text.push_str(&format!(
                    "{} ({}): no change journal, files are compared by metadata\n",
                    vj.vol.mount.win32(),
                    vj.vol.fstype
                )),
                Err(e) => log_text.push_str(&format!("{}: USN journal: {e}\n", vj.vol.mount.win32())),
            }
        }
        // VSS
        let mut set = None;
        let mut snap_of: Vec<Option<usize>> = vec![None; vols.len()];
        if vols.iter().any(|v| volumes::vss_capable(&v.vol.fstype)) {
            match vss::SnapshotSet::begin(&excluded_writers) {
                Ok(mut s) => {
                    for (i, vj) in vols.iter().enumerate() {
                        if !volumes::vss_capable(&vj.vol.fstype) {
                            continue;
                        }
                        match s.add(&vj.vol.guid) {
                            Ok(()) => snap_of[i] = Some(s.members.len() - 1),
                            Err(e) => log_text.push_str(&format!("{}: {e}\n", vj.vol.mount.win32())),
                        }
                    }
                    if s.members.is_empty() {
                        drop(s.finish(false));
                    } else {
                        match s.create(&excluded_writers) {
                            Ok(()) => set = Some(s),
                            Err(e) => {
                                log_text.push_str(&format!("{e}\n"));
                                for n in s.finish(false) {
                                    log_text.push_str(&format!("{n}\n"));
                                }
                                snap_of = vec![None; vols.len()];
                            }
                        }
                    }
                }
                Err(e) => log_text.push_str(&format!("{e}\n")),
            }
        }
        let mut snapshots = vec![];
        let mut devices: Vec<Option<String>> = vec![None; vols.len()];
        if let Some(s) = &set {
            for (i, vj) in vols.iter().enumerate() {
                if let Some(m) = snap_of[i] {
                    match s.device(m) {
                        Ok(d) => {
                            snapshots.push(SnapshotInfo {
                                mountpoint: vj.vol.mount.slash(),
                                kind: SnapshotKind::Vss,
                                name: format!("{} {d}", s.set_id()),
                            });
                            devices[i] = Some(d);
                        }
                        Err(e) => log_text.push_str(&format!("{}: {e}\n", vj.vol.mount.win32())),
                    }
                }
            }
        }
        for (i, vj) in vols.iter().enumerate() {
            if devices[i].is_none() {
                let n = format!(
                    "{} ({}): no shadow copy, read live (files changed while read are marked inconsistent)",
                    vj.vol.mount.win32(),
                    vj.vol.fstype
                );
                log(&n);
                log_text.push_str(&n);
                log_text.push('\n');
            }
        }
        let mut roots = vec![];
        for (p, i) in by_path {
            let rel = p.strip_prefix(&vols[i].vol.mount).unwrap_or_default().join("\\");
            let (src, live) = match &devices[i] {
                Some(d) => (PathBuf::from(format!("{d}\\{rel}")), false),
                None => (PathBuf::from(p.verbatim()), true),
            };
            roots.push(Root {
                entry: p.entry_path(),
                src,
                volume: i,
                live,
            });
        }
        let writers_list = set.as_ref().map(|s| s.writers.clone()).unwrap_or_default();
        if let Some(s) = &set {
            log(format!("job {job}: shadow copy set {}", s.set_id()));
            log_text.push_str(&writers::summary(&writers_list));
        }
        let consistent = devices.iter().all(Option::is_some) && writers::all_application_writers_ok(&writers_list);
        Ok(PreparedJob {
            job: Job {
                set,
                vols,
                roots,
                filter,
            },
            snapshots,
            consistent,
            hook_log: log_text,
            writers: writers_list,
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
        let mut changes = vec![];
        let mut new_cache = Cache::new(id, base);
        for vj in &j.vols {
            let c = match (&vj.journal, cache) {
                (None, _) => Changes::Unsupported,
                (Some(_), None) => Changes::Reset("no base backup".into()),
                (Some(before), Some(c)) => match usnio::query(&vj.vol.guid, false) {
                    Ok(Some((now, _))) => match continuity(c.journal(&vj.vol.guid), &now) {
                        Continuity::From(usn) => usnio::changes_since(&vj.vol.guid, before.journal_id, usn)
                            .unwrap_or_else(|e| Changes::Reset(format!("reading the USN journal: {e}"))),
                        Continuity::Reset(r) => Changes::Reset(r),
                    },
                    Ok(None) => Changes::Reset("journal disappeared".into()),
                    Err(e) => Changes::Reset(format!("USN journal: {e}")),
                },
            };
            if let Changes::Reset(r) = &c {
                log(format!("{}: full read ({r})", vj.vol.mount.win32()));
            }
            if let Some(jd) = &vj.journal {
                new_cache.journals.push(JournalMark {
                    volume: vj.vol.guid.clone(),
                    journal_id: jd.journal_id,
                    next_usn: jd.next_usn,
                });
            }
            changes.push(c);
        }
        let live = j.roots.iter().any(|r| r.live);
        let locator = Locator::new(
            live.then(|| ctx.paths.spool_dir()).as_deref(),
            ctx.settings.spool_max_bytes,
        )
        .map_err(|e| ScanError::Refused(Refused(E_INTERNAL, format!("spool: {e}"))))?;
        let mut src = source::WinSource { sacl: self.sacl };
        let mut w = Walker::new(&mut src, &j.filter, cache, &changes, locator, new_cache);
        w.run(&j.roots, emit)?;
        Ok(ScanOutput {
            stats: std::mem::take(&mut w.stats),
            locator: w.locator,
            cache: w.new_cache,
        })
    }

    fn lower_priority(&self, nice: u8) -> String {
        match sys::background_mode() {
            Ok(()) => format!("priority lowered (nice {nice}): thread background mode (low CPU and I/O priority)"),
            Err(e) => format!("priority not lowered: {e}"),
        }
    }

    fn release_snapshots(&self, _ctx: Ctx, j: &mut Job, _id: u64, success: bool) -> String {
        let mut text = String::new();
        if let Some(s) = j.set.take() {
            for n in s.finish(success) {
                log(&n);
                text.push_str(&format!("snapshot cleanup: {n}\n"));
            }
        }
        text
    }

    fn finish_job(&self, _ctx: Ctx, _j: Job, _id: u64, _success: bool) -> String {
        String::new()
    }

    fn restore_begin(
        &self,
        _ctx: Ctx,
        job: u64,
        target: &str,
        overwrite: Overwrite,
        confirm: &str,
    ) -> io::Result<restore::Restore> {
        restore::begin(job, target, overwrite, confirm, self.sacl)
    }

    fn update(&self, ctx: Ctx, version: &str, binary: &[u8], signature: &[u8]) -> Result<String, String> {
        let keys = agent_core::update::load_keys(&ctx.paths.release_keys());
        let (key, new) = agent_core::update::check_candidate(
            version,
            binary,
            signature,
            &keys,
            env!("CARGO_PKG_VERSION"),
            update::is_pe_x64,
        )?;
        let exe = std::env::current_exe().map_err(|e| format!("current executable: {e}"))?;
        match update::install(&exe, binary, sys::move_at_reboot).map_err(|e| format!("installing update: {e}"))? {
            update::Installed::Now => Ok(format!(
                "updated {} -> {new} (signed by {key})",
                env!("CARGO_PKG_VERSION")
            )),
            update::Installed::AtReboot => Ok(format!(
                "update to {new} (signed by {key}) staged; it takes effect after the next reboot"
            )),
        }
    }

    fn restart_after_update(&self) -> ! {
        // the service control manager restarts the service (failure actions)
        std::process::exit(update::RESTART_EXIT_CODE)
    }
    fn power_state(&self) -> agent_proto::PowerState {
        power::state()
    }
}
