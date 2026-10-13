//! Job execution on worker threads: a [`Plan`] is a list of steps (spawned CLI
//! or in-process chunk-store operation) run in order until the first failure.
//! Secrets for the CLIs go into a private per-job directory (0700, files 0600)
//! that is removed afterwards.

use chunkstore::retention::Gfs;
use chunkstore::{Keyring, Options, Store};
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use crate::progress::Tracker;
use catalog::rusqlite;
use chunkstore::progress::{Line, PREFIX};

pub type KeySource = Arc<dyn Fn(&str) -> io::Result<Keyring> + Send + Sync>;

/// Output kept from a job: the tail, so the final error survives truncation.
pub struct BoundedLog {
    buf: String,
    max: usize,
    truncated: bool,
    /// changes so far (the live writer compares)
    seq: u64,
    /// second of the last `@<unix seconds>` time mark
    mark: u64,
}

/// A time mark line of a job log: `@<unix seconds>`, written before output whenever the second
/// changed. Parsers match line prefixes (`committed `, `nexus-stats ` …) and pass over these; the
/// UI shows them as the time of the lines that follow.
pub fn is_time_mark(line: &str) -> bool {
    line.strip_prefix('@')
        .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
}

impl BoundedLog {
    pub fn new(max: usize) -> Self {
        BoundedLog {
            buf: String::new(),
            max: max.max(64),
            truncated: false,
            seq: 0,
            mark: 0,
        }
    }

    pub fn push(&mut self, s: &str) {
        self.seq += 1;
        if self.buf.is_empty() || self.buf.ends_with('\n') {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            if now != self.mark && !s.is_empty() {
                self.mark = now;
                self.buf.push_str(&format!("@{now}\n"));
            }
        }
        self.buf.push_str(s);
        if self.buf.len() > self.max {
            let mut cut = self.buf.len() - self.max * 3 / 4;
            while !self.buf.is_char_boundary(cut) {
                cut += 1;
            }
            self.buf.drain(..cut);
            self.truncated = true;
        }
    }

    pub fn line(&mut self, s: &str) {
        self.push(s);
        self.push("\n");
    }

    pub fn finish(self) -> String {
        if self.truncated {
            format!("[… earlier output truncated …]\n{}", self.buf)
        } else {
            self.buf
        }
    }

    /// The log so far, as [`BoundedLog::finish`] would return it.
    pub fn snapshot(&self) -> String {
        if self.truncated {
            format!("[… earlier output truncated …]\n{}", self.buf)
        } else {
            self.buf.clone()
        }
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }
}

#[derive(Debug)]
pub enum Step {
    /// Spawned CLI. A non-zero exit fails the job; `alert` selects a specific
    /// alert kind (`verify`, `inventory`) instead of the generic `job_failed`.
    Cli {
        bin: PathBuf,
        args: Vec<String>,
        alert: Option<&'static str>,
        /// stdout becomes the job result instead of going to the log
        capture: bool,
    },
    Retention {
        sources: Vec<String>,
        /// plus every store source starting with one of these (TrueNAS child
        /// datasets: `nas-<id>-<pool.ds>.`)
        prefixes: Vec<String>,
        gfs: Gfs,
    },
    /// GFS for the store sources no group covers ([`crate::orphans`]); stdout
    /// becomes `{"orphans": {source: deleted}}`
    Orphans {
        coverage: crate::orphans::Coverage,
        gfs: Gfs,
    },
    /// one snapshot (approved `snapshot.delete`); refused while locked
    Delete {
        source: String,
        time: u64,
    },
    Gc {
        approved: bool,
    },
    Verify {
        part: u64,
        parts: u64,
    },
    /// In-process work without the store (appliance jobs): `Ok` output becomes
    /// the captured stdout, `Err` goes to the log and fails the job.
    Func(InProc),
    /// In-process read/maintenance work on the tenant's store (file search,
    /// name index backfill, crate::search): `Ok` output becomes the captured stdout.
    Store(StoreOp),
}

/// Held times of one source.
fn held_of(held: &BTreeSet<(String, u64)>, source: &str) -> BTreeSet<u64> {
    held.iter().filter(|(s, _)| s == source).map(|(_, t)| *t).collect()
}

pub struct InProc(pub Box<dyn Fn() -> Result<String, String> + Send>);

pub type StoreFn = dyn Fn(&Store) -> Result<String, String> + Send;

pub struct StoreOp(pub Box<StoreFn>);

impl std::fmt::Debug for StoreOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoreOp")
    }
}

impl std::fmt::Debug for InProc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InProc")
    }
}

#[derive(Debug)]
pub struct Plan {
    /// exclusivity key: at most one running job per key
    pub key: String,
    pub tenant: String,
    pub store: PathBuf,
    pub dir: PathBuf,
    /// (file name in `dir`, contents), written 0600 before the first step
    pub files: Vec<(String, Vec<u8>)>,
    pub steps: Vec<Step>,
    /// files_get output (removed on failure)
    pub download: Option<PathBuf>,
    /// `(source, time)` under a legal hold when the job was planned: never
    /// deleted by its retention or delete steps
    pub held: BTreeSet<(String, u64)>,
}

#[derive(Debug, PartialEq)]
pub enum Outcome {
    Ok,
    Failed {
        alert: Option<&'static str>,
    },
    /// GC refused: deleting this much needs quorum approval
    Quorum {
        message: String,
    },
    /// stopped on request ([`Cancels`])
    Cancelled,
}

pub struct Finished {
    pub id: i64,
    pub outcome: Outcome,
    pub log: String,
    pub stdout: Option<String>,
}

pub struct Ctx {
    pub keys: KeySource,
    pub store_options: fn() -> Options,
    pub log_max: usize,
    pub cancels: Cancels,
    /// live view of running jobs (`jobs.live_log`, `jobs.progress`); None = only at the end
    pub live: Option<LiveSink>,
}

/// Where and how often a running job's log so far and progress are written
/// (docs/control-plane.md "Live progress"): from a thread of its own, only
/// when something changed, so the connectors' pipes never wait for the catalog.
pub struct LiveSink {
    pub db: Arc<catalog::Catalog>,
    pub every: Duration,
}

pub type Progress = Arc<Mutex<Tracker>>;

/// Writes `live_log` / `progress` of job `id` every `every` while it runs.
fn live_writer(
    id: i64,
    sink: &LiveSink,
    log: Arc<Mutex<BoundedLog>>,
    progress: Progress,
    stop: mpsc::Receiver<()>,
) -> std::thread::JoinHandle<()> {
    let (db, every) = (sink.db.clone(), sink.every);
    std::thread::spawn(move || {
        let mut log_seq = 0;
        while let Err(mpsc::RecvTimeoutError::Timeout) = stop.recv_timeout(every) {
            let text = {
                let l = log.lock().unwrap();
                (l.seq() != log_seq).then(|| {
                    log_seq = l.seq();
                    l.snapshot()
                })
            };
            // rewritten every round once there is progress: the rate decays while nothing arrives
            let prog = progress.lock().unwrap().snapshot(Instant::now()).map(|v| v.to_string());
            let r = match (text, prog) {
                (None, None) => continue,
                (Some(t), None) => db.conn().execute(
                    "UPDATE jobs SET live_log = ?2 WHERE id = ?1 AND state = 'running'",
                    rusqlite::params![id, t],
                ),
                (None, Some(p)) => db.conn().execute(
                    "UPDATE jobs SET progress = ?2 WHERE id = ?1 AND state = 'running'",
                    rusqlite::params![id, p],
                ),
                (Some(t), Some(p)) => db.conn().execute(
                    "UPDATE jobs SET live_log = ?2, progress = ?3 WHERE id = ?1 AND state = 'running'",
                    rusqlite::params![id, t, p],
                ),
            };
            if let Err(e) = r {
                eprintln!("job {id}: live progress not written: {e}");
            }
        }
    })
}

/// Cancel requests for running jobs (Phase 13b, docs/control-plane.md "Run
/// control"). The worker checks the mark before each step; a spawned CLI runs
/// in its own process group, which gets SIGTERM on request and SIGKILL from
/// [`Cancels::kill`] (the scheduler calls it after the grace period).
/// In-process steps (retention, GC, verify) are not interrupted: the job stops
/// after the current step.
#[derive(Default)]
pub struct Cancels(Mutex<HashMap<i64, Slot>>);

#[derive(Default)]
struct Slot {
    requested: bool,
    /// process group of the CLI currently running for the job
    pgid: Option<i32>,
}

fn signal_group(pgid: i32, sig: i32) {
    // SAFETY: plain kill(2) on a process group we created and have not reaped yet
    unsafe {
        libc::kill(-pgid, sig);
    }
}

impl Cancels {
    pub fn request(&self, id: i64) {
        let mut m = self.0.lock().unwrap();
        let s = m.entry(id).or_default();
        if !s.requested {
            s.requested = true;
            if let Some(p) = s.pgid {
                signal_group(p, libc::SIGTERM);
            }
        }
    }

    pub fn kill(&self, id: i64) {
        if let Some(p) = self.0.lock().unwrap().get(&id).and_then(|s| s.pgid) {
            signal_group(p, libc::SIGKILL);
        }
    }

    pub fn requested(&self, id: i64) -> bool {
        self.0.lock().unwrap().get(&id).is_some_and(|s| s.requested)
    }

    /// The job finished: forget it.
    pub fn remove(&self, id: i64) {
        self.0.lock().unwrap().remove(&id);
    }

    /// Registers the child's process group; a request that came first stops it now.
    fn spawned(&self, id: i64, pgid: i32) {
        let mut m = self.0.lock().unwrap();
        let s = m.entry(id).or_default();
        s.pgid = Some(pgid);
        if s.requested {
            signal_group(pgid, libc::SIGTERM);
        }
    }

    /// Before the child is reaped: no signals to a group id that may be reused.
    fn exited(&self, id: i64) {
        if let Some(s) = self.0.lock().unwrap().get_mut(&id) {
            s.pgid = None;
        }
    }
}

const MAX_CAPTURE: usize = 4 << 20;

pub fn write_private(dir: &Path, files: &[(String, Vec<u8>)]) -> io::Result<()> {
    fs::DirBuilder::new().mode(0o700).create(dir)?;
    for (name, data) in files {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join(name))?
            .write_all(data)?;
    }
    Ok(())
}

pub fn execute(id: i64, plan: &Plan, ctx: &Ctx) -> Finished {
    let log = Arc::new(Mutex::new(BoundedLog::new(ctx.log_max)));
    let progress: Progress = Default::default();
    let (stop, stopped) = mpsc::channel();
    let writer = ctx
        .live
        .as_ref()
        .map(|sink| live_writer(id, sink, log.clone(), progress.clone(), stopped));
    let mut stdout = None;
    let outcome = match write_private(&plan.dir, &plan.files) {
        Err(e) => {
            log.lock()
                .unwrap()
                .line(&format!("[scheduler] cannot write job config: {e}"));
            Outcome::Failed { alert: None }
        }
        Ok(()) => run_steps(id, plan, ctx, &log, &progress, &mut stdout),
    };
    drop(stop);
    if let Some(w) = writer {
        let _ = w.join(); // no live write after the final one (Scheduler::finish)
    }
    let _ = fs::remove_dir_all(&plan.dir);
    if outcome != Outcome::Ok {
        if let Some(d) = &plan.download {
            let _ = fs::remove_file(d);
        }
    }
    let log = Arc::try_unwrap(log)
        .ok()
        .map(|m| m.into_inner().unwrap().finish())
        .unwrap_or_default();
    Finished {
        id,
        outcome,
        log,
        stdout,
    }
}

fn run_steps(
    id: i64,
    plan: &Plan,
    ctx: &Ctx,
    log: &Arc<Mutex<BoundedLog>>,
    progress: &Progress,
    stdout: &mut Option<String>,
) -> Outcome {
    let clis = plan.steps.iter().filter(|s| matches!(s, Step::Cli { .. })).count() as u32;
    let mut cli = 0;
    let needs_store = plan
        .steps
        .iter()
        .any(|s| !matches!(s, Step::Cli { .. } | Step::Func(_)));
    let store = if needs_store {
        match (ctx.keys)(&plan.tenant).and_then(|k| Store::open(&plan.store, k, (ctx.store_options)())) {
            Ok(s) => Some(s),
            Err(e) => {
                log.lock()
                    .unwrap()
                    .line(&format!("[scheduler] cannot open store of tenant {}: {e}", plan.tenant));
                return Outcome::Failed { alert: None };
            }
        }
    } else {
        None
    };
    for step in &plan.steps {
        if ctx.cancels.requested(id) {
            log.lock().unwrap().line("[scheduler] cancelled");
            return Outcome::Cancelled;
        }
        let failed = Outcome::Failed { alert: None };
        match step {
            Step::Cli {
                bin,
                args,
                alert,
                capture,
            } => {
                log.lock().unwrap().line(&format!(
                    "$ {} {}",
                    bin.file_name().unwrap_or_default().to_string_lossy(),
                    args.join(" ")
                ));
                cli += 1;
                progress.lock().unwrap().step(cli, clis);
                match run_cli_live(bin, args, log, *capture, Some((id, &ctx.cancels)), Some(progress)) {
                    Ok((true, out)) => {
                        if *capture {
                            *stdout = Some(out);
                        }
                    }
                    Ok((false, _)) if ctx.cancels.requested(id) => {
                        stop_task(bin, args, log);
                        log.lock().unwrap().line("[scheduler] cancelled");
                        return Outcome::Cancelled;
                    }
                    Ok((false, _)) => return Outcome::Failed { alert: *alert },
                    Err(e) => {
                        log.lock().unwrap().line(&format!("[scheduler] cannot run: {e}"));
                        return failed;
                    }
                }
            }
            Step::Retention { sources, prefixes, gfs } => {
                let s = store.as_ref().unwrap();
                let mut all = sources.clone();
                if !prefixes.is_empty() {
                    match s.list_snapshots() {
                        Ok(ms) => {
                            for m in ms {
                                if prefixes.iter().any(|p| m.source.starts_with(p.as_str())) && !all.contains(&m.source)
                                {
                                    all.push(m.source);
                                }
                            }
                        }
                        Err(e) => {
                            log.lock()
                                .unwrap()
                                .line(&format!("retention: listing snapshots failed: {e}"));
                            return failed;
                        }
                    }
                }
                for src in &all {
                    match s.apply_retention_held(src, gfs, &held_of(&plan.held, src)) {
                        Ok((k, d, l)) => log
                            .lock()
                            .unwrap()
                            .line(&format!("retention {src}: kept {k}, deleted {d}, still locked {l}")),
                        Err(e) => {
                            log.lock().unwrap().line(&format!("retention {src} failed: {e}"));
                            return failed;
                        }
                    }
                }
            }
            Step::Orphans { coverage, gfs } => {
                let s = store.as_ref().unwrap();
                let mut sources: Vec<String> = match s.list_snapshots() {
                    Ok(ms) => ms
                        .into_iter()
                        .map(|m| m.source)
                        .filter(|x| !coverage.covers(x))
                        .collect(),
                    Err(e) => {
                        log.lock()
                            .unwrap()
                            .line(&format!("orphans: listing snapshots failed: {e}"));
                        return failed;
                    }
                };
                sources.dedup(); // sorted by source
                let mut out = serde_json::Map::new();
                for src in &sources {
                    match s.apply_retention_held(src, gfs, &held_of(&plan.held, src)) {
                        Ok((k, d, l)) => {
                            log.lock().unwrap().line(&format!(
                                "retention {src} (in no group): kept {k}, deleted {d}, still locked {l}"
                            ));
                            out.insert(src.clone(), d.into());
                        }
                        Err(e) => {
                            log.lock().unwrap().line(&format!("retention {src} failed: {e}"));
                            return failed;
                        }
                    }
                }
                *stdout = Some(serde_json::json!({ "orphans": out }).to_string());
            }
            Step::Delete { source, time } if plan.held.contains(&(source.clone(), *time)) => {
                log.lock()
                    .unwrap()
                    .line(&format!("snapshot {source}/{time} is under a legal hold: not deleted"));
                return failed;
            }
            Step::Delete { source, time } => match store.as_ref().unwrap().delete_snapshot(source, *time) {
                Ok(()) => log.lock().unwrap().line(&format!("deleted snapshot {source}/{time}")),
                Err(e) => {
                    log.lock()
                        .unwrap()
                        .line(&format!("deleting snapshot {source}/{time} failed: {e}"));
                    return failed;
                }
            },
            Step::Store(StoreOp(f)) => match f(store.as_ref().unwrap()) {
                Ok(out) => *stdout = Some(out),
                Err(e) => {
                    log.lock().unwrap().line(&format!("[scheduler] {e}"));
                    return failed;
                }
            },
            Step::Func(InProc(f)) => match f() {
                Ok(out) => *stdout = Some(out),
                Err(e) => {
                    log.lock().unwrap().line(&format!("[scheduler] {e}"));
                    return failed;
                }
            },
            Step::Gc { approved } => match store.as_ref().unwrap().gc(*approved) {
                Ok(st) => log.lock().unwrap().line(&format!(
                    "local gc{}: {} chunks, {} referenced, {} deleted, {} kept (grace)",
                    if *approved { " (approved)" } else { "" },
                    st.total,
                    st.marked,
                    st.deleted,
                    st.kept_grace
                )),
                Err(e)
                    if e.kind() == io::ErrorKind::PermissionDenied
                        && e.to_string().contains("quorum approval required") =>
                {
                    log.lock().unwrap().line(&format!("local gc: {e}"));
                    return Outcome::Quorum { message: e.to_string() };
                }
                Err(e) => {
                    log.lock().unwrap().line(&format!("local gc failed: {e}"));
                    return failed;
                }
            },
            Step::Verify { part, parts } => {
                let (part, parts) = (*part, (*parts).max(1));
                match store
                    .as_ref()
                    .unwrap()
                    .verify(|id| u64::from(id[0]) % parts == part % parts)
                {
                    Ok(r) => {
                        log.lock().unwrap().line(&format!(
                            "local verify (share {}/{parts}): {} chunks re-read, {} corrupt, {} missing",
                            part % parts + 1,
                            r.checked,
                            r.corrupt.len(),
                            r.missing.len()
                        ));
                        // Phase 21d: bad chunks listed, damaged snapshots reported (crate::repair)
                        match crate::repair::after_verify(store.as_ref().unwrap(), &r) {
                            Ok(out) => *stdout = Some(out),
                            Err(e) => {
                                log.lock().unwrap().line(&format!("marking bad chunks failed: {e}"));
                                return Outcome::Failed { alert: Some("verify") };
                            }
                        }
                        if !r.corrupt.is_empty() || !r.missing.is_empty() {
                            return Outcome::Failed { alert: Some("verify") };
                        }
                    }
                    Err(e) => {
                        log.lock().unwrap().line(&format!("local verify failed: {e}"));
                        return Outcome::Failed { alert: Some("verify") };
                    }
                }
            }
        }
    }
    Outcome::Ok
}

/// A cancelled connector that reported a PVE task (`upid: <UPID>` line) gets
/// `<bin> <config> task-stop <UPID>` for each of them (newest first; parallel
/// guests run several vzdump tasks at once), so vzdump / qmrestore on the node
/// stops too (nexus-pve; the DELETE task API leaves ended tasks alone).
fn stop_task(bin: &Path, args: &[String], log: &Arc<Mutex<BoundedLog>>) {
    let upids = reported_upids(&log.lock().unwrap().buf);
    let Some(cfg) = args.first() else { return };
    for upid in upids {
        let args = [cfg.clone(), "task-stop".into(), upid];
        if let Err(e) = run_cli(bin, &args, log, false, None) {
            log.lock().unwrap().line(&format!("[scheduler] task-stop: {e}"));
        }
    }
}

/// Distinct `upid: <UPID>` lines of a log, newest first.
fn reported_upids(log: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for u in log.lines().rev().filter_map(|l| l.strip_prefix("upid: ")) {
        let u = u.trim();
        if u.starts_with("UPID:") && !out.iter().any(|x| x == u) {
            out.push(u.to_owned());
        }
    }
    out
}

/// Runs a CLI with stdout/stderr streamed into `log` (or stdout captured).
/// Returns (success, captured stdout). With `job`, the child runs in its own
/// process group registered for cancellation.
pub fn run_cli(
    bin: &Path,
    args: &[String],
    log: &Arc<Mutex<BoundedLog>>,
    capture: bool,
    job: Option<(i64, &Cancels)>,
) -> io::Result<(bool, String)> {
    run_cli_live(bin, args, log, capture, job, None)
}

/// Longest partial line held back (a longer one goes to the log as it is).
const MAX_LINE: usize = 64 << 10;

/// Splits output into lines: `progress {json}` lines go to `progress` (never
/// into the log), everything else to the log, one lock per read.
#[derive(Default)]
struct Lines {
    partial: Vec<u8>,
}

impl Lines {
    fn feed(&mut self, data: &[u8], log: &Mutex<BoundedLog>, progress: Option<&Progress>, eof: bool) {
        self.partial.extend_from_slice(data);
        let mut text = String::new();
        let mut lines = Vec::new();
        let mut start = 0;
        while let Some(n) = self.partial[start..].iter().position(|&b| b == b'\n') {
            let line = &self.partial[start..start + n + 1];
            start += n + 1;
            if line.starts_with(PREFIX.as_bytes()) {
                // malformed progress lines are dropped as well
                lines.extend(Line::parse(&String::from_utf8_lossy(line)));
            } else {
                text.push_str(&String::from_utf8_lossy(line));
            }
        }
        self.partial.drain(..start);
        if eof || self.partial.len() > MAX_LINE {
            text.push_str(&String::from_utf8_lossy(&self.partial));
            self.partial.clear();
        }
        if !text.is_empty() {
            log.lock().unwrap().push(&text);
        }
        if let (Some(p), false) = (progress, lines.is_empty()) {
            let mut p = p.lock().unwrap();
            let now = Instant::now();
            for l in lines {
                p.line(l, now);
            }
        }
    }
}

/// [`run_cli`] with the child's progress lines going to `progress`.
pub fn run_cli_live(
    bin: &Path,
    args: &[String],
    log: &Arc<Mutex<BoundedLog>>,
    capture: bool,
    job: Option<(i64, &Cancels)>,
    progress: Option<&Progress>,
) -> io::Result<(bool, String)> {
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if job.is_some() {
        cmd.process_group(0);
    }
    let mut child = cmd.spawn()?;
    if let Some((id, c)) = job {
        c.spawned(id, child.id() as i32);
    }
    let pump = |mut r: Box<dyn Read + Send>, log: Arc<Mutex<BoundedLog>>, keep: bool| {
        let progress = progress.cloned();
        std::thread::spawn(move || {
            let mut kept = Vec::new();
            let mut lines = Lines::default();
            let mut buf = [0u8; 8192];
            loop {
                match r.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) if keep => {
                        if kept.len() < MAX_CAPTURE {
                            kept.extend_from_slice(&buf[..n]);
                        }
                    }
                    Ok(n) => lines.feed(&buf[..n], &log, progress.as_ref(), false),
                }
            }
            lines.feed(&[], &log, progress.as_ref(), true);
            String::from_utf8_lossy(&kept).into_owned()
        })
    };
    let out = pump(Box::new(child.stdout.take().unwrap()), log.clone(), capture);
    let err = pump(Box::new(child.stderr.take().unwrap()), log.clone(), false);
    if let Some((id, c)) = job {
        // wait for the exit without reaping (WNOWAIT): the group id stays ours
        // until it is unregistered, so a late signal cannot hit a reused id
        // SAFETY: waitid on our own child with a zeroed siginfo out-parameter
        unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            while libc::waitid(libc::P_PID, child.id(), &mut info, libc::WEXITED | libc::WNOWAIT) != 0
                && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
            {}
        }
        c.exited(id);
    }
    let status = child.wait()?;
    let captured = out.join().unwrap_or_default();
    let _ = err.join();
    if capture && captured.len() >= MAX_CAPTURE {
        log.lock()
            .unwrap()
            .line("[scheduler] output exceeds 4 MiB, result truncated");
    }
    if !status.success() {
        if capture {
            log.lock().unwrap().push(&captured);
        }
        log.lock().unwrap().line(&format!("[scheduler] exited with {status}"));
    }
    Ok((status.success(), captured))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_reported_tasks_are_stopped_newest_first() {
        let log = "upid: UPID:pve1:1:a:\ncommitted vm-100/5\nupid: UPID:pve2:2:b:\nupid: bogus\n\
                   upid: UPID:pve1:1:a:\nupid: UPID:pve1:3:c: \n";
        assert_eq!(
            reported_upids(log),
            vec!["UPID:pve1:3:c:", "UPID:pve1:1:a:", "UPID:pve2:2:b:"]
        );
        assert!(reported_upids("nothing\n").is_empty());
    }

    #[test]
    fn log_gets_time_marks_parsers_ignore() {
        let mut l = BoundedLog::new(1 << 20);
        l.line("committed vm-1/2");
        l.line("nexus-stats {}");
        let out = l.finish();
        assert!(is_time_mark(out.lines().next().unwrap()), "{out}");
        assert!(out.lines().filter(|x| is_time_mark(x)).count() <= 2, "{out}");
        assert!(out.lines().any(|x| x == "committed vm-1/2"));
        assert!(!is_time_mark("@") && !is_time_mark("@12a") && !is_time_mark("committed @1"));
    }

    #[test]
    fn progress_lines_split_across_reads_stay_out_of_the_log() {
        let log = Mutex::new(BoundedLog::new(1 << 16));
        let progress: Progress = Default::default();
        let mut l = Lines::default();
        l.feed(b"one\nprogress {\"item\":\"vm-1\",\"do", &log, Some(&progress), false);
        l.feed(
            b"ne\":7,\"total\":9}\ntwo\nprogress nonsense\nthr",
            &log,
            Some(&progress),
            false,
        );
        let text = |log: &Mutex<BoundedLog>| {
            let s = log.lock().unwrap().snapshot();
            s.split_inclusive('\n')
                .filter(|x| !is_time_mark(x.trim_end()))
                .collect::<String>()
        };
        assert_eq!(text(&log), "one\ntwo\n");
        l.feed(b"ee", &log, Some(&progress), true);
        assert_eq!(text(&log), "one\ntwo\nthree");
        let p = progress.lock().unwrap().snapshot(Instant::now()).unwrap();
        assert_eq!((p["item"].as_str(), p["done"].as_u64()), (Some("vm-1"), Some(7)));
    }

    #[test]
    fn bounded_log_keeps_tail() {
        let mut l = BoundedLog::new(100);
        for i in 0..100 {
            l.line(&format!("line {i}"));
        }
        let s = l.finish();
        assert!(s.starts_with("[… earlier output truncated …]"));
        assert!(s.ends_with("line 99\n"));
        assert!(s.len() < 160);
        let mut l = BoundedLog::new(100);
        l.push(&"ä".repeat(80)); // multi-byte: cut on a char boundary
        assert!(l.finish().contains('ä'));
    }

    #[test]
    fn private_files_and_cli_capture() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("job-1");
        write_private(&dir, &[("a.json".into(), b"{}".to_vec())]).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(
            fs::metadata(dir.join("a.json")).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let log = Arc::new(Mutex::new(BoundedLog::new(1 << 16)));
        let args = vec!["-c".into(), "echo out; echo err >&2; exit 3".into()];
        let (ok, out) = run_cli(Path::new("/bin/sh"), &args, &log, true, None).unwrap();
        assert!(!ok);
        assert_eq!(out, "out\n");
        let l = log.lock().unwrap().buf.clone();
        assert!(l.contains("err") && l.contains("exit status: 3"), "{l}");
    }
}
