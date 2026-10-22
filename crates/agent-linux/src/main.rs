//! `nexus-agent` CLI.

use nexus_agent::config::{ensure_dir, Paths, Settings};
use nexus_agent::endpoint::{self, cli, exit, Clock};
use nexus_agent::{server, snapshot, sys};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

const USAGE: &str = "\
usage:
  nexus-agent init --token <T> [--port 7444] [--state DIR] [--config DIR]
  nexus-agent init --fleet-secret <S> [--port 7444] [--state DIR] [--config DIR]
  nexus-agent run [--state DIR] [--config DIR]
  nexus-agent hooks test [--config DIR]
  nexus-agent rescue [--rescue-config FILE]   (rescue ISO: bare-metal recovery console)
  nexus-agent version (or --version)
standalone mode (root; a repository of its own, no appliance; docs/agent-standalone.md):
  nexus-agent repo init <dir>            new repository; prints the 24-word recovery key once
  nexus-agent repo open <dir>            on another machine: the 24 words on stdin open it
  nexus-agent repo backup <dir> <path>…  back up these paths (snapshot where possible)
  nexus-agent repo list <dir> [--json]
  nexus-agent repo restore <dir> <time> <target> [--path P] [--overwrite never|if-older|always]
end users (root or members of the group nexus-agent-ui):
  nexus-agent tui                        control panel: sessions, status, back up now
  nexus-agent status [--json]            protection status (as root also local diagnostics)
  nexus-agent sessions [--limit N] [--json]
  nexus-agent session <id> [--json]      one session with its log tail
  nexus-agent request-backup [--json]    ask the appliance for a backup at its next poll
  exit codes: 0 ok, 1 error, 2 no permission on the socket, 3 agent service not running,
  4 refused by the agent (rate limit, policy, unknown session); --socket PATH for tests
defaults: --config /etc/nexus-agent --state /var/lib/nexus-agent
--token - / --fleet-secret - read the value from stdin (keeps it out of the process list);
a fleet secret in /etc/nexus-agent/fleet-secret is adopted (and deleted) at the next start";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match real_main(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("nexus-agent: {e}");
            ExitCode::FAILURE
        }
    }
}

fn real_main(args: &[String]) -> Result<ExitCode, String> {
    let mut paths = Paths::default();
    let mut token = None;
    let mut fleet = None;
    let mut port = None;
    let mut rescue_config = None;
    let mut json = false;
    let mut limit = 20;
    let mut sock = PathBuf::from(endpoint::proto::SOCKET_PATH);
    let mut words = vec![];
    let (mut only, mut overwrite) = (String::new(), agent_proto::Overwrite::Never);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = |name: &str| it.next().cloned().ok_or(format!("{name} needs a value"));
        match a.as_str() {
            "--token" => token = Some(val("--token")?),
            "--fleet-secret" => fleet = Some(val("--fleet-secret")?),
            "--port" => port = Some(val("--port")?.parse::<u16>().map_err(|_| "invalid --port")?),
            "--state" => paths.state = PathBuf::from(val("--state")?),
            "--config" => paths.config = PathBuf::from(val("--config")?),
            "--rescue-config" => rescue_config = Some(PathBuf::from(val("--rescue-config")?)),
            "--json" => json = true,
            "--limit" => limit = val("--limit")?.parse::<usize>().map_err(|_| "invalid --limit")?,
            "--socket" => sock = PathBuf::from(val("--socket")?),
            "--path" => only = val("--path")?,
            "--overwrite" => {
                overwrite = match val("--overwrite")?.as_str() {
                    "never" => agent_proto::Overwrite::Never,
                    "if-older" => agent_proto::Overwrite::IfOlder,
                    "always" => agent_proto::Overwrite::Always,
                    o => return Err(format!("--overwrite: never, if-older or always, not {o}")),
                }
            }
            "--version" | "-V" => words.push("version".into()),
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(ExitCode::SUCCESS);
            }
            w if !w.starts_with('-') => words.push(w.to_string()),
            other => return Err(format!("unknown option {other}\n{USAGE}")),
        }
    }
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["init"] => {
            let (prompt, value) = match (token, fleet) {
                (Some(t), None) => ("One-time enrollment token: ", t),
                (None, Some(f)) => ("Fleet secret: ", f),
                _ => return Err("init needs --token <T> or --fleet-secret <S>".into()),
            };
            let mut value = value;
            if value == "-" {
                value.clear();
                if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                    eprint!("{prompt}");
                }
                std::io::stdin()
                    .read_line(&mut value)
                    .map_err(|e| format!("stdin: {e}"))?;
            }
            if prompt.starts_with("Fleet") {
                println!("{}", nexus_agent::init_fleet(&paths, &value, port)?);
            } else {
                println!("{}", nexus_agent::init(&paths, &value, port)?);
            }
            Ok(ExitCode::SUCCESS)
        }
        ["run"] => run(paths),
        ["rescue"] => {
            nexus_agent::rescue::main(rescue_config)?;
            Ok(ExitCode::SUCCESS)
        }
        ["status"] => {
            let res = cli::run(&cli::Command::Status, &sock, json, Clock::Local);
            if let Ok(out) = &res {
                print!("{out}");
            }
            // root: the local diagnostics too (also when the service is down)
            // SAFETY: trivial syscall
            if !json && unsafe { libc::geteuid() } == 0 {
                if res.is_ok() {
                    println!();
                }
                print!("{}", nexus_agent::status(&paths));
            }
            Ok(user_exit(res.map(|_| String::new())))
        }
        ["sessions"] => Ok(user_exit(cli::run(
            &cli::Command::Sessions { limit },
            &sock,
            json,
            Clock::Local,
        ))),
        ["session", id] => {
            let id = id.parse::<u64>().map_err(|_| format!("invalid session id {id}"))?;
            Ok(user_exit(cli::run(
                &cli::Command::Session { id },
                &sock,
                json,
                Clock::Local,
            )))
        }
        ["request-backup"] => Ok(user_exit(cli::run(
            &cli::Command::RequestBackup,
            &sock,
            json,
            Clock::Local,
        ))),
        ["tui"] => {
            endpoint::tui::run(&sock).map_err(|e| format!("terminal: {e}"))?;
            Ok(ExitCode::SUCCESS)
        }
        ["hooks", "test"] => {
            let (ok, out) = nexus_agent::hooks_test(&paths);
            print!("{out}");
            Ok(if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE })
        }
        ["repo", rest @ ..] => repo(&paths, rest, json, &only, overwrite),
        ["version"] => {
            println!("nexus-agent {}", env!("CARGO_PKG_VERSION"));
            // keep the version marker in the binary (self-update reads it)
            std::hint::black_box(nexus_agent::update::VERSION_MARKER);
            Ok(ExitCode::SUCCESS)
        }
        _ => Err(USAGE.into()),
    }
}

/// `nexus-agent repo …`: standalone mode (Phase 38b/38c, docs/agent-standalone.md).
fn repo(
    paths: &Paths,
    args: &[&str],
    json: bool,
    only: &str,
    overwrite: agent_proto::Overwrite,
) -> Result<ExitCode, String> {
    use agent_core::standalone;
    // SAFETY: trivial syscall; keys, caches and spool files are never group/world-readable
    unsafe { libc::umask(0o077) };
    let settings = Settings::load(paths)?;
    let sp = standalone::state_paths(paths);
    let ctx = agent_core::server::Ctx {
        paths: &sp,
        settings: &settings,
    };
    let platform = server::Linux::default();
    match args {
        ["init", dir] => {
            let words = standalone::init(paths, Path::new(dir), &sys::uname().1)?;
            println!("Repository {dir} created.\nRECOVERY KEY (record it now, it is shown only once):\n{words}");
        }
        ["open", dir] => {
            let mut words = String::new();
            std::io::stdin()
                .read_line(&mut words)
                .map_err(|e| format!("stdin: {e}"))?;
            let r = standalone::open(paths, Path::new(dir), Some(words.trim()))?;
            println!(
                "{dir}: opened, {} snapshot(s); this machine keeps its key",
                standalone::list(&r)?.len()
            );
        }
        ["backup", dir, roots @ ..] if !roots.is_empty() => {
            let r = standalone::open(paths, Path::new(dir), None)?;
            ensure_dir(&sp.state, 0o700).map_err(|e| format!("{}: {e}", sp.state.display()))?;
            let roots: Vec<String> = roots.iter().map(|s| (*s).to_owned()).collect();
            let job = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(1, |d| d.as_secs());
            let s = standalone::backup(&platform, ctx, &r, job, &roots, &[], &Default::default(), true)?;
            print!("{}", s.log);
            println!(
                "snapshot {} of {}: {} entries, {} files, {} bytes, {} new chunks{}",
                s.time,
                r.source,
                s.entries,
                s.files,
                s.bytes,
                s.new_chunks,
                if s.consistent {
                    ""
                } else {
                    " (not consistent: no snapshot)"
                }
            );
        }
        ["list", dir] => {
            let r = standalone::open(paths, Path::new(dir), None)?;
            let snaps = standalone::list(&r)?;
            if json {
                println!("{}", serde_json::to_string(&snaps).map_err(|e| e.to_string())?);
            } else {
                for s in snaps {
                    println!("{}  {}", s.time, s.source);
                }
            }
        }
        ["restore", dir, time, target] => {
            let r = standalone::open(paths, Path::new(dir), None)?;
            let time = time
                .parse::<u64>()
                .map_err(|_| format!("invalid snapshot time {time}"))?;
            let st = standalone::restore(&platform, ctx, &r, time, only, target, overwrite)?;
            for e in &st.errors {
                eprintln!("{e}");
            }
            println!("restored {} files, {} bytes to {target}", st.files, st.bytes);
            if !st.errors.is_empty() {
                return Ok(ExitCode::FAILURE);
            }
        }
        _ => return Err(USAGE.into()),
    }
    Ok(ExitCode::SUCCESS)
}

/// The local UI socket (docs/endpoint-ui.md): `/run/nexus-agent/ui.sock`, group
/// `nexus-agent-ui`; the run directory only allows traversal (0711).
fn serve_ui(agent: &Arc<server::Agent>) {
    let paths = &agent.paths;
    if let Err(e) = ensure_dir(&paths.run, 0o711) {
        eprintln!("nexus-agent: {}: {e}; no local UI socket", paths.run.display());
        return;
    }
    let group = agent_core::ui::unix::group_id(agent_ui_proto::SOCKET_GROUP);
    if group.is_none() {
        eprintln!(
            "nexus-agent: group {} missing: the UI socket is root-only",
            agent_ui_proto::SOCKET_GROUP
        );
    }
    match agent_core::ui::unix::bind(&paths.ui_socket(), group) {
        Ok(l) => {
            let a = agent.clone();
            std::thread::spawn(move || agent_core::ui::unix::serve(a, l));
        }
        Err(e) => eprintln!("nexus-agent: {}: {e}; no local UI socket", paths.ui_socket().display()),
    }
}

/// Prints the output of an end-user command, or its error with the documented exit code.
fn user_exit(res: Result<String, endpoint::Failure>) -> ExitCode {
    match res {
        Ok(out) => {
            print!("{out}");
            ExitCode::from(exit::OK)
        }
        Err(f) => {
            eprintln!("nexus-agent: {}", f.message);
            ExitCode::from(f.code)
        }
    }
}

fn run(paths: Paths) -> Result<ExitCode, String> {
    // SAFETY: trivial syscall; private keys, caches and spool files are never group/world-readable
    unsafe { libc::umask(0o077) };
    std::hint::black_box(nexus_agent::update::VERSION_MARKER);
    // start watchdog of a freshly swapped binary (docs/agent-update-plan.md): first, so
    // a configuration the new version cannot load counts as a failed start as well
    if let Ok(exe) = std::env::current_exe().and_then(std::fs::canonicalize) {
        let restore = || nexus_agent::update::restore_prev(&exe);
        if agent_core::update::watchdog_on_start(&paths, env!("CARGO_PKG_VERSION"), &restore)
            == agent_core::update::Watchdog::Reverted
        {
            eprintln!("nexus-agent: the new version did not start; the previous binary is back, restarting");
            return Ok(ExitCode::from(nexus_agent::update::RESTART_EXIT_CODE as u8));
        }
    }
    let settings = Settings::load(&paths)?;
    // before any thread exists: snapshot mounts stay in our own namespace
    if let Err(e) = sys::private_mount_namespace() {
        eprintln!("nexus-agent: no private mount namespace ({e}); LVM snapshots cannot be mounted");
    }
    ensure_dir(&paths.state, 0o700).map_err(|e| format!("{}: {e}", paths.state.display()))?;
    let _ = std::fs::remove_dir_all(paths.spool_dir());
    for m in snapshot::cleanup_leftovers(&paths) {
        eprintln!("nexus-agent: {m}");
    }
    // a package deployment's fleet secret (docs/agent-linux.md "Fleet deployment")
    match agent_core::adopt_fleet_secret(&paths, &sys::uname().1) {
        Some(Ok(m)) => eprintln!("nexus-agent: {m}"),
        Some(Err(e)) => eprintln!("nexus-agent: fleet secret: {e}"),
        None => {}
    }
    let agent = server::Agent::new(paths, settings.clone())?;
    match agent.mode() {
        server::Mode::Uninitialized => {
            return Err("not initialised: run nexus-agent init --token <T> (or --fleet-secret <S>)".into())
        }
        server::Mode::Locked(_) => eprintln!("nexus-agent: enrollment LOCKED; run nexus-agent init again"),
        server::Mode::Enroll(_) => eprintln!("nexus-agent: waiting for enrollment by the appliance"),
        server::Mode::Mtls { agent_id, .. } => eprintln!("nexus-agent: enrolled as {agent_id}"),
    }
    let listener = agent_core::listen(&settings.listen, settings.port)
        .map_err(|e| format!("listen {}:{}: {e}", settings.listen, settings.port))?;
    eprintln!(
        "nexus-agent {} listening on {}",
        env!("CARGO_PKG_VERSION"),
        listener.local_addr().map_err(|e| e.to_string())?
    );
    let agent = Arc::new(agent);
    serve_ui(&agent);
    agent.serve(listener).map_err(|e| e.to_string())?;
    Ok(ExitCode::SUCCESS)
}
