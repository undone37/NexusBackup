//! Job execution on worker threads: a [`Plan`] is a list of steps (spawned CLI
//! or in-process chunk-store operation) run in order until the first failure.
//! Secrets for the CLIs go into a private per-job directory (0700, files 0600)
//! that is removed afterwards.

use chunkstore::retention::Gfs;
use chunkstore::{Keyring, Options, Store};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

pub type KeySource = Arc<dyn Fn(&str) -> io::Result<Keyring> + Send + Sync>;

/// Output kept from a job: the tail, so the final error survives truncation.
pub struct BoundedLog {
    buf: String,
    max: usize,
    truncated: bool,
}

impl BoundedLog {
    pub fn new(max: usize) -> Self {
        BoundedLog {
            buf: String::new(),
            max: max.max(64),
            truncated: false,
        }
    }

    pub fn push(&mut self, s: &str) {
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
    Gc {
        approved: bool,
    },
    Verify {
        part: u64,
        parts: u64,
    },
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
    let mut stdout = None;
    let outcome = match write_private(&plan.dir, &plan.files) {
        Err(e) => {
            log.lock()
                .unwrap()
                .line(&format!("[scheduler] cannot write job config: {e}"));
            Outcome::Failed { alert: None }
        }
        Ok(()) => run_steps(plan, ctx, &log, &mut stdout),
    };
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

fn run_steps(plan: &Plan, ctx: &Ctx, log: &Arc<Mutex<BoundedLog>>, stdout: &mut Option<String>) -> Outcome {
    let needs_store = plan.steps.iter().any(|s| !matches!(s, Step::Cli { .. }));
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
                match run_cli(bin, args, log, *capture) {
                    Ok((true, out)) => {
                        if *capture {
                            *stdout = Some(out);
                        }
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
                    match s.apply_retention(src, gfs) {
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

/// Runs a CLI with stdout/stderr streamed into `log` (or stdout captured).
/// Returns (success, captured stdout).
pub fn run_cli(bin: &Path, args: &[String], log: &Arc<Mutex<BoundedLog>>, capture: bool) -> io::Result<(bool, String)> {
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let pump = |mut r: Box<dyn Read + Send>, log: Arc<Mutex<BoundedLog>>, keep: bool| {
        std::thread::spawn(move || {
            let mut kept = Vec::new();
            let mut buf = [0u8; 8192];
            loop {
                match r.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) if keep => {
                        if kept.len() < MAX_CAPTURE {
                            kept.extend_from_slice(&buf[..n]);
                        }
                    }
                    Ok(n) => log.lock().unwrap().push(&String::from_utf8_lossy(&buf[..n])),
                }
            }
            String::from_utf8_lossy(&kept).into_owned()
        })
    };
    let out = pump(Box::new(child.stdout.take().unwrap()), log.clone(), capture);
    let err = pump(Box::new(child.stderr.take().unwrap()), log.clone(), false);
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
        let (ok, out) = run_cli(Path::new("/bin/sh"), &args, &log, true).unwrap();
        assert!(!ok);
        assert_eq!(out, "out\n");
        let l = log.lock().unwrap().buf.clone();
        assert!(l.contains("err") && l.contains("exit status: 3"), "{l}");
    }
}
