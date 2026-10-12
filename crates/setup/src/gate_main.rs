//! `nexus-console-gate` (nexus-console-gate.service on tty2, Phase 14c): asks
//! for a one-time unlock code or the recovery key and starts a time-limited
//! root shell. The logic is in `setup::gate`; this is only the terminal and
//! the shell: `systemd-run --scope -p RuntimeMaxSec=` puts the shell into its
//! own transient scope, which systemd stops (all its processes) when the time
//! is up. SELinux moves the shell from nexus_consolegate_t to unconfined_t
//! when bash is executed (os/selinux/nexus.te); no other nexus domain may.

use anyhow::{bail, Context, Result};
use setup::gate::{Gate, Limiter, Method, Session, MAX_FAILS, WINDOW_SECS};
use setup::Paths;
use std::io::{BufRead, Write};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;
use zeroize::Zeroizing;

const USAGE: &str = "usage: nexus-console-gate [--root DIR] [--once]
  --root DIR   prefix for the appliance paths (dev/tests)      env NEXUS_SETUP_ROOT
  --once       exit after one root shell (lab)
env NEXUS_CONSOLE_UNLOCK_DIR (default <root>/var/lib/nexus/console-unlock),
    NEXUS_CONSOLE_GATE_STATE (failed attempts, default /run/nexus-console-gate/attempts)";

const BANNER: &str = "
NexusBackup appliance: emergency console

A root shell opens only with a one-time unlock code (web UI: Settings > Console
access, approved by a second person while approvals are enabled) or with the
recovery key printed at first boot. Every attempt is audited; a shell raises a
critical alert and shows a banner in the web UI while it runs.
";

fn now() -> i64 {
    catalog::now()
}

fn utc(ts: i64) -> String {
    let s = ts.rem_euclid(86400);
    format!("{:02}:{:02} UTC", s / 3600, s % 3600 / 60)
}

/// One line from the terminal, without echo for secrets; `None` at EOF.
fn read(prompt: &str, secret: bool) -> std::io::Result<Option<Zeroizing<String>>> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut old: libc::termios = unsafe { std::mem::zeroed() };
    let tty = secret && unsafe { libc::tcgetattr(0, &mut old) } == 0;
    if tty {
        let mut t = old;
        t.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(0, libc::TCSANOW, &t) };
    }
    let mut s = Zeroizing::new(String::new());
    let n = std::io::stdin().lock().read_line(&mut s);
    if tty {
        unsafe { libc::tcsetattr(0, libc::TCSANOW, &old) };
        println!();
    }
    Ok((n? > 0).then_some(s))
}

fn ask_hours() -> std::io::Result<Option<u32>> {
    loop {
        let Some(l) = read("Shell duration in hours (1-8) [1]: ", false)? else {
            return Ok(None);
        };
        match l.trim() {
            "" => return Ok(Some(1)),
            v => match v.parse() {
                Ok(h) if (1..=catalog::console::MAX_HOURS).contains(&h) => return Ok(Some(h)),
                _ => println!("1 to 8"),
            },
        }
    }
}

/// The root shell in its own scope; the terminal is taken back afterwards.
fn shell(s: &Session) -> std::io::Result<std::process::ExitStatus> {
    let mut cmd = Command::new("systemd-run");
    // --no-ask-password: no password agent (nothing to ask; it would need extra policy)
    cmd.args(["--scope", "--quiet", "--no-ask-password", "--unit", &s.unit])
        .arg("--description=NexusBackup console root shell (nexus-console-gate)")
        .arg(format!("--property=RuntimeMaxSec={}", u64::from(s.hours) * 3600))
        .args(["--", "/bin/bash", "--login"])
        .env("HOME", "/root")
        .env("USER", "root")
        .env("LOGNAME", "root")
        .env("SHELL", "/bin/bash")
        .env("NEXUS_CONSOLE_SHELL_UNTIL", s.until.to_string());
    // the gate ignores terminal signals and runs with umask 077: not the shell
    unsafe {
        cmd.pre_exec(|| {
            for sig in [libc::SIGINT, libc::SIGQUIT, libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU] {
                libc::signal(sig, libc::SIG_DFL);
            }
            libc::umask(0o022);
            Ok(())
        });
    }
    let r = cmd.status();
    unsafe { libc::tcsetpgrp(0, libc::getpgrp()) };
    // leftovers (background jobs) end with the shell
    stop(&s.unit);
    r
}

fn stop(unit: &str) {
    let _ = Command::new("systemctl")
        .args(["stop", "--quiet", "--no-ask-password", &format!("{unit}.scope")])
        .stderr(Stdio::null())
        .status();
}

fn session(gate: &Gate, m: &Method) -> Result<()> {
    let hours = match m {
        Method::Code(u) => u.hours,
        Method::RecoveryKey => match ask_hours()? {
            Some(h) => h,
            None => return Ok(()),
        },
    };
    let s = gate.begin(m, hours, now())?;
    match m {
        Method::Code(u) => println!(
            "\nCode #{} accepted (requested by {}, approved by {}).",
            u.id, u.requested_by, u.approved_by
        ),
        Method::RecoveryKey => println!("\nRecovery key accepted."),
    }
    println!(
        "Root shell for up to {hours} h (until {}). It is audited and alerted; leave it with `exit`.\n",
        utc(s.until)
    );
    let r = shell(&s);
    let how = match &r {
        _ if now() >= s.until - 5 => "timeout".to_owned(),
        Ok(st) if st.success() => "exit".to_owned(),
        Ok(st) => format!("ended: {st}"),
        Err(e) => format!("could not start: {e}"),
    };
    println!("\nRoot shell ended ({how}).");
    gate.end(&s, &how, now())
}

fn run(args: &[String]) -> Result<()> {
    let mut root = std::env::var_os("NEXUS_SETUP_ROOT").map_or_else(|| PathBuf::from("/"), PathBuf::from);
    let mut once = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--root" => root = it.next().context("--root needs a value")?.into(),
            "--once" => once = true,
            _ => bail!("unknown argument {a}\n{USAGE}"),
        }
    }
    if root == std::path::Path::new("/") && unsafe { libc::geteuid() } != 0 {
        bail!("must run as root (nexus-console-gate.service)");
    }
    let unlock = std::env::var_os("NEXUS_CONSOLE_UNLOCK_DIR")
        .map_or_else(|| root.join("var/lib/nexus/console-unlock"), PathBuf::from);
    let state = std::env::var_os("NEXUS_CONSOLE_GATE_STATE")
        .map_or_else(|| PathBuf::from("/run/nexus-console-gate/attempts"), PathBuf::from);
    let gate = Gate::new(Paths::under(&root), unlock);
    // Ctrl-C / Ctrl-\ / Ctrl-Z at the prompt do nothing; SIGTTOU: taking the terminal back
    for sig in [libc::SIGINT, libc::SIGQUIT, libc::SIGTSTP, libc::SIGTTOU] {
        unsafe { libc::signal(sig, libc::SIG_IGN) };
    }
    match gate.clear_stale(now()) {
        Ok(Some(unit)) => stop(&unit),
        Ok(None) => {}
        Err(e) => eprintln!("<3>nexus-console-gate: clearing the banner of an earlier shell: {e:#}"),
    }
    loop {
        let mut lim = Limiter::load(&state);
        let wait = lim.wait(now());
        if wait > 0 {
            println!("Too many rejected attempts: the next one is possible in {wait} s.");
            std::thread::sleep(Duration::from_secs(wait.clamp(1, 60) as u64));
            continue;
        }
        println!("{BANNER}");
        if !gate.ready() {
            println!("The appliance is not set up yet: the setup wizard runs on tty1 (Alt+F1).");
            if read("Press Enter to check again. ", false)?.is_none() {
                return Ok(());
            }
            continue;
        }
        gate.remove_expired(now());
        let Some(input) = read("Unlock code or recovery key: ", true)? else {
            return Ok(());
        };
        if input.trim().is_empty() {
            continue;
        }
        match gate.check(&input, now()) {
            Ok(Some(m)) => {
                lim.clear();
                let _ = lim.save(&state);
                drop(input);
                if let Err(e) = session(&gate, &m) {
                    eprintln!("<3>nexus-console-gate: {e:#}");
                    println!("Error: {e:#}");
                }
                if once {
                    return Ok(());
                }
            }
            Ok(None) => {
                lim.fail(now());
                if let Err(e) = lim.save(&state) {
                    eprintln!("<3>nexus-console-gate: {e:#}");
                }
                let n = lim.count(now());
                if let Err(e) = gate.failed(n) {
                    eprintln!("<3>nexus-console-gate: audit: {e:#}");
                }
                println!(
                    "Not accepted ({n} of {MAX_FAILS} attempts per {} min).",
                    WINDOW_SECS / 60
                );
                std::thread::sleep(Duration::from_secs(1));
            }
            Err(e) => {
                println!("Error: {e:#}");
                std::thread::sleep(Duration::from_secs(3));
            }
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    // umask 077, not dumpable, memory locked: the recovery key passes through here
    keyd::harden_process();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("nexus-console-gate: {e:#}");
            ExitCode::FAILURE
        }
    }
}
