//! `nexus-agent` CLI.

use nexus_agent::config::{ensure_dir, Paths, Settings};
use nexus_agent::endpoint::{self, cli, exit, Clock};
use nexus_agent::{server, snapshot, sys};
use std::path::PathBuf;
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
end users (root or members of the group nexus-agent-ui):
  nexus-agent tui                        control panel: sessions, status, back up now
  nexus-agent status [--json]            protection status (as root also local diagnostics)
  nexus-agent sessions [--limit N] [--json]
  nexus-agent session <id> [--json]      one session with its log tail
  nexus-agent request-backup [--json]    ask the appliance for a backup at its next poll
  nexus-agent jobs [--json]              standalone jobs of this computer with their last result
  nexus-agent run-job <name> [--json]    run a standalone job now
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
    let mut repo_opts = agent_core::standalone::CliOpts::default();
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
            "--path" | "--overwrite" | "--keep" => repo_opts.set(a, &val(a)?)?,
            "--version" | "-V" => words.push("version".into()),
            "-h" | "--help" => {
                println!("{USAGE}\n{}", agent_core::standalone::usage("nexus-agent"));
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
        // the service's ExecStartPre, run as `<exe>.prev` (#93): see agent_core::update::watchdog_pre
        ["update-watchdog"] => {
            let me = std::env::current_exe()
                .and_then(std::fs::canonicalize)
                .map_err(|e| e.to_string())?;
            let Some(exe) = me
                .to_str()
                .and_then(|s| s.strip_suffix(".prev"))
                .map(std::path::PathBuf::from)
            else {
                return Err("update-watchdog runs as the previous binary (<exe>.prev) only".into());
            };
            let restore = || nexus_agent::update::restore_prev(&exe);
            if agent_core::update::watchdog_pre(&paths, &restore) == agent_core::update::Watchdog::Reverted {
                eprintln!("nexus-agent: the new version did not start 3 times; the previous binary is back");
            }
            Ok(ExitCode::SUCCESS)
        }
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
        ["jobs"] => Ok(user_exit(cli::run(&cli::Command::Jobs, &sock, json, Clock::Local))),
        ["run-job", name] => Ok(user_exit(cli::run(
            &cli::Command::RunJob {
                name: (*name).to_owned(),
            },
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
        ["repo", rest @ ..] => {
            repo_opts.json = json;
            repo(&paths, rest, &repo_opts)
        }
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
fn repo(paths: &Paths, args: &[&str], opts: &agent_core::standalone::CliOpts) -> Result<ExitCode, String> {
    // SAFETY: trivial syscall; keys, caches and spool files are never group/world-readable
    unsafe { libc::umask(0o077) };
    let settings = Settings::load(paths)?;
    let ok = agent_core::standalone::cli(&server::Linux::default(), paths, &settings, &sys::uname().1, args, opts)
        .map_err(|e| {
            if e.is_empty() {
                agent_core::standalone::usage("nexus-agent")
            } else {
                e
            }
        })?;
    Ok(if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE })
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
    // the running executable, resolved before the private mount namespace below: inside it the kernel can report
    // /proc/self/exe wrong (the hot-add proxy image, #35: /var/usrlocal/sbin/nexus-agent showed as
    // /usrlocal/sbin/nexus-agent and the self-update failed with "current executable: No such file or directory")
    let exe = std::env::current_exe().and_then(std::fs::canonicalize).ok();
    // start watchdog of a freshly swapped binary (docs/agent-update-plan.md): first, so
    // a configuration the new version cannot load counts as a failed start as well
    if let Some(exe) = &exe {
        let restore = || nexus_agent::update::restore_prev(exe);
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
    let platform = exe.map_or_else(server::Linux::default, server::Linux::with_exe);
    let agent = server::Agent::with_platform(platform, paths, settings.clone())?;
    // Phase 38e: scheduled standalone jobs (<config>/standalone.json) run in this service as well
    let standalone = match agent_core::standalone::load_jobs(&agent.paths) {
        Ok(j) => !j.is_empty(),
        Err(e) => {
            eprintln!("nexus-agent: {e}");
            false
        }
    };
    match agent.mode() {
        // standalone only: no appliance, nothing to listen for
        server::Mode::Uninitialized if standalone => {
            eprintln!(
                "nexus-agent {}: standalone jobs only (not enrolled)",
                env!("CARGO_PKG_VERSION")
            );
            // the local UI still shows the jobs and can run one now
            let agent = Arc::new(agent);
            serve_ui(&agent);
            agent_core::standalone::run_jobs(&agent.platform, &agent.paths, &agent.settings);
            return Ok(ExitCode::SUCCESS);
        }
        server::Mode::Uninitialized => return Err(
            "not initialised: run nexus-agent init --token <T> (or --fleet-secret <S>), or configure standalone jobs"
                .into(),
        ),
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
    if standalone {
        let a = agent.clone();
        std::thread::spawn(move || agent_core::standalone::run_jobs(&a.platform, &a.paths, &a.settings));
    }
    serve_ui(&agent);
    agent.serve(listener).map_err(|e| e.to_string())?;
    Ok(ExitCode::SUCCESS)
}
