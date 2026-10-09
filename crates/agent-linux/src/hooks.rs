//! Local pre/post hooks (`/etc/nexus-agent/hooks.d/{pre,post}/`).
//!
//! The appliance can only say "run the configured hooks"; what runs is decided on the
//! host. A phase is refused entirely if `hooks.d`, the phase directory or any hook is
//! not owned by root (the configured owner) or is group/world-writable, or if a hook is
//! a symlink. Hooks run in name order with a clean environment, stdin from /dev/null,
//! in their own process group, and are killed (whole group) after the timeout.
//! Names starting with `.` or ending in `.example`, `.disabled`, `~` are ignored,
//! as are non-executable files.

use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MAX_LOG: usize = 64 << 10;

fn check_owner(p: &Path, owner: u32, dir: bool) -> Result<(), String> {
    let md = fs::symlink_metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
    if md.file_type().is_symlink() {
        return Err(format!("{}: is a symlink", p.display()));
    }
    if dir != md.is_dir() || (!dir && !md.is_file()) {
        return Err(format!("{}: unexpected file type", p.display()));
    }
    if md.uid() != owner {
        return Err(format!("{}: owned by uid {}, must be {owner}", p.display(), md.uid()));
    }
    if md.mode() & 0o022 != 0 {
        return Err(format!(
            "{}: group/world-writable (mode {:o})",
            p.display(),
            md.mode() & 0o7777
        ));
    }
    Ok(())
}

/// The hooks of one phase in execution order, after all permission checks.
/// Missing directories mean "no hooks".
pub fn list(hooks_dir: &Path, phase: &str, owner: u32) -> Result<Vec<PathBuf>, String> {
    let dir = hooks_dir.join(phase);
    if !hooks_dir.exists() || !dir.exists() {
        return Ok(vec![]);
    }
    if let Some(parent) = hooks_dir.parent() {
        check_owner(parent, owner, true)?;
    }
    check_owner(hooks_dir, owner, true)?;
    check_owner(&dir, owner, true)?;
    let mut names: Vec<_> = fs::read_dir(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.file_name()))
        .collect();
    names.sort();
    let mut out = vec![];
    for n in names {
        let s = n.to_string_lossy();
        if s.starts_with('.') || s.ends_with(".example") || s.ends_with(".disabled") || s.ends_with('~') {
            continue;
        }
        let p = dir.join(&n);
        check_owner(&p, owner, false)?;
        if fs::symlink_metadata(&p)
            .map(|m| m.permissions().mode() & 0o100 != 0)
            .unwrap_or(false)
        {
            out.push(p);
        }
    }
    Ok(out)
}

/// Run all hooks of `phase`; stops at the first failure for `pre`, runs all for
/// `post`. Returns (all succeeded, log).
pub fn run(hooks_dir: &Path, phase: &str, owner: u32, timeout: Duration, env: &[(&str, String)]) -> (bool, String) {
    let hooks = match list(hooks_dir, phase, owner) {
        Ok(h) => h,
        Err(e) => return (false, format!("[{phase}] refused: {e}\n")),
    };
    let mut log = String::new();
    let mut ok = true;
    for h in hooks {
        let (good, out) = run_one(&h, phase, timeout, env);
        log.push_str(&out);
        if !good {
            ok = false;
            if phase == "pre" {
                break;
            }
        }
    }
    (ok, log)
}

fn run_one(hook: &Path, phase: &str, timeout: Duration, env: &[(&str, String)]) -> (bool, String) {
    let name = hook
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut cmd = Command::new(hook);
    cmd.env_clear()
        .env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C.UTF-8")
        .env("NEXUS_PHASE", phase)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    if let Ok(home) = std::env::var("HOME") {
        cmd.env("HOME", home);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    if let Some(d) = hook.parent() {
        cmd.current_dir(d);
    }
    let start = Instant::now();
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return (false, format!("[{phase}/{name}] cannot start: {e}\n")),
    };
    let pid = child.id() as i32;
    let readers: Vec<_> = [
        child.stdout.take().map(|s| Box::new(s) as Box<dyn Read + Send>),
        child.stderr.take().map(|s| Box::new(s) as Box<dyn Read + Send>),
    ]
    .into_iter()
    .flatten()
    .map(|mut r| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            while let Ok(n) = r.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                if buf.len() < MAX_LOG {
                    buf.extend_from_slice(&chunk[..n.min(MAX_LOG - buf.len())]);
                }
            }
            buf
        })
    })
    .collect();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if start.elapsed() >= timeout => {
                timed_out = true;
                // SAFETY: kill the hook's whole process group (it is its own leader).
                unsafe { libc::kill(-pid, libc::SIGKILL) };
                break child.wait().ok();
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(_) => break None,
        }
    };
    // descendants that kept the pipes open die with the group
    unsafe { libc::kill(-pid, libc::SIGKILL) };
    let mut out = String::new();
    for r in readers {
        out.push_str(&String::from_utf8_lossy(&r.join().unwrap_or_default()));
    }
    let ok = !timed_out && status.is_some_and(|s| s.success());
    let verdict = if timed_out {
        format!("killed after {}s timeout", timeout.as_secs())
    } else {
        status.map(|s| s.to_string()).unwrap_or_else(|| "unknown status".into())
    };
    let mut log = format!("[{phase}/{name}] {verdict} ({:.1}s)\n", start.elapsed().as_secs_f64());
    for l in out.lines() {
        log.push_str("  ");
        log.push_str(l);
        log.push('\n');
    }
    (ok, log)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_lets_hooks_change_user() {
        // NoNewPrivileges=yes + an explicit User= makes systemd drop CAP_SETUID, which
        // breaks `setpriv --reuid=postgres` in the DB hook examples (lab: Debian 13)
        let unit = include_str!("../dist/nexus-agent.service");
        assert!(!unit.lines().any(|l| l.trim_start().starts_with("User=")));
        assert!(unit.contains("CAP_SETUID CAP_SETGID"));
        let pg = include_str!("../dist/hooks.d/pre/10-postgresql.example");
        assert!(pg.contains("setpriv --reuid"));
    }

    fn me() -> u32 {
        crate::sys::geteuid()
    }

    fn setup() -> (tempfile::TempDir, PathBuf) {
        let t = tempfile::tempdir().unwrap();
        fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let h = t.path().join("hooks.d");
        fs::create_dir_all(h.join("pre")).unwrap();
        fs::create_dir_all(h.join("post")).unwrap();
        for d in [&h, &h.join("pre"), &h.join("post")] {
            fs::set_permissions(d, fs::Permissions::from_mode(0o700)).unwrap();
        }
        (t, h)
    }

    fn hook(dir: &Path, name: &str, body: &str, mode: u32) {
        let p = dir.join(name);
        fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn runs_in_order_and_captures_output() {
        let (_t, h) = setup();
        hook(&h.join("pre"), "20-b", "echo second; echo err >&2", 0o700);
        hook(&h.join("pre"), "10-a", "echo first job=$NEXUS_JOB", 0o755);
        hook(&h.join("pre"), "30-c.example", "exit 1", 0o755);
        hook(&h.join("pre"), "40-noexec", "exit 1", 0o600);
        let (ok, log) = run(&h, "pre", me(), Duration::from_secs(10), &[("NEXUS_JOB", "7".into())]);
        assert!(ok, "{log}");
        assert!(log.find("first job=7").unwrap() < log.find("second").unwrap(), "{log}");
        assert!(log.contains("err"));
        assert!(!log.contains("example"));
    }

    #[test]
    fn refuses_bad_permissions_and_symlinks() {
        let (_t, h) = setup();
        hook(&h.join("pre"), "10-a", "true", 0o757);
        let (ok, log) = run(&h, "pre", me(), Duration::from_secs(5), &[]);
        assert!(!ok && log.contains("world-writable"), "{log}");
        fs::set_permissions(h.join("pre/10-a"), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(list(&h, "pre", me()).is_ok());
        fs::set_permissions(h.join("pre"), fs::Permissions::from_mode(0o775)).unwrap();
        assert!(list(&h, "pre", me()).unwrap_err().contains("group/world-writable"));
        fs::set_permissions(h.join("pre"), fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink("/bin/true", h.join("pre/20-link")).unwrap();
        assert!(list(&h, "pre", me()).unwrap_err().contains("symlink"));
        fs::remove_file(h.join("pre/20-link")).unwrap();
        // wrong owner: pretend root must own it (we are not root in CI)
        if me() != 0 {
            assert!(list(&h, "pre", 0).unwrap_err().contains("owned by uid"));
        }
        assert!(list(&h.join("missing"), "pre", me()).unwrap().is_empty());
    }

    #[test]
    fn timeout_kills_process_group_and_pre_stops_on_failure() {
        let (_t, h) = setup();
        hook(&h.join("pre"), "10-slow", "sleep 30 & sleep 30", 0o700);
        hook(&h.join("pre"), "20-never", "echo should-not-run", 0o700);
        let start = Instant::now();
        let (ok, log) = run(&h, "pre", me(), Duration::from_millis(300), &[]);
        assert!(!ok);
        assert!(log.contains("timeout"), "{log}");
        assert!(!log.contains("should-not-run"));
        assert!(start.elapsed() < Duration::from_secs(10));
        hook(&h.join("post"), "10-fail", "exit 3", 0o700);
        hook(&h.join("post"), "20-runs", "echo post-ran", 0o700);
        let (ok, log) = run(&h, "post", me(), Duration::from_secs(5), &[]);
        assert!(!ok && log.contains("post-ran"), "post hooks all run: {log}");
    }
}
