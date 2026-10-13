//! `nexus-agent` CLI.

use nexus_agent::config::{ensure_dir, Paths, Settings};
use nexus_agent::{server, snapshot, sys};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

const USAGE: &str = "\
usage:
  nexus-agent init --token <T> [--port 7444] [--state DIR] [--config DIR]
  nexus-agent run [--state DIR] [--config DIR]
  nexus-agent status [--json] [--state DIR] [--config DIR]
  nexus-agent hooks test [--config DIR]
  nexus-agent version (or --version)
defaults: --config /etc/nexus-agent --state /var/lib/nexus-agent
--token - reads the token from stdin (keeps it out of the process list)";

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
    let mut port = None;
    let mut words = vec![];
    let mut json = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = |name: &str| it.next().cloned().ok_or(format!("{name} needs a value"));
        match a.as_str() {
            "--token" => token = Some(val("--token")?),
            "--port" => port = Some(val("--port")?.parse::<u16>().map_err(|_| "invalid --port")?),
            "--state" => paths.state = PathBuf::from(val("--state")?),
            "--config" => paths.config = PathBuf::from(val("--config")?),
            "--version" | "-V" => words.push("version".into()),
            "--json" => json = true,
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
            let mut token = token.ok_or("init needs --token <T>")?;
            if token == "-" {
                token.clear();
                if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                    eprint!("One-time enrollment token: ");
                }
                std::io::stdin()
                    .read_line(&mut token)
                    .map_err(|e| format!("stdin: {e}"))?;
            }
            println!("{}", nexus_agent::init(&paths, &token, port)?);
            Ok(ExitCode::SUCCESS)
        }
        ["run"] => run(paths),
        ["status"] if json => status_json(),
        ["status"] => {
            print!("{}", nexus_agent::status(&paths));
            Ok(ExitCode::SUCCESS)
        }
        ["hooks", "test"] => {
            let (ok, out) = nexus_agent::hooks_test(&paths);
            print!("{out}");
            Ok(if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE })
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

/// `nexus-agent status --json`: the service's view over the local UI socket
/// (agent_ui_proto `status`), for scripts and the lab.
fn status_json() -> Result<ExitCode, String> {
    let mut c = agent_ui_proto::Client::connect_default().map_err(|e| {
        format!(
            "{}: {e} (is the service running and are you in group {}?)",
            agent_ui_proto::SOCKET_PATH,
            agent_ui_proto::SOCKET_GROUP
        )
    })?;
    let st = c.status().map_err(|e| e.to_string())?;
    println!("{}", serde_json::to_string_pretty(&st).map_err(|e| e.to_string())?);
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

fn run(paths: Paths) -> Result<ExitCode, String> {
    // SAFETY: trivial syscall; private keys, caches and spool files are never group/world-readable
    unsafe { libc::umask(0o077) };
    std::hint::black_box(nexus_agent::update::VERSION_MARKER);
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
    let agent = server::Agent::new(paths, settings.clone())?;
    match agent.mode() {
        server::Mode::Uninitialized => return Err("not initialised: run nexus-agent init --token <T>".into()),
        server::Mode::Locked(_) => eprintln!("nexus-agent: enrollment LOCKED; run nexus-agent init again"),
        server::Mode::Enroll(_) => eprintln!("nexus-agent: waiting for enrollment by the appliance"),
        server::Mode::Mtls { agent_id, .. } => eprintln!("nexus-agent: enrolled as {agent_id}"),
    }
    let listener = TcpListener::bind((settings.listen.as_str(), settings.port))
        .or_else(|e| {
            if settings.listen == "::" {
                TcpListener::bind(("0.0.0.0", settings.port))
            } else {
                Err(e)
            }
        })
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
