//! `nexus-agent.exe` commands and the Windows service.

use super::{acl, host, sys, volumes, vss, Agent, Windows, PRIVILEGES};
use agent_core::config::{Paths, Settings};
use agent_core::server::Mode;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceErrorControl,
    ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState,
    ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

pub const SERVICE_NAME: &str = "NexusAgent";
const DISPLAY_NAME: &str = "NexusBackup Agent";

const USAGE: &str = "\
usage:
  nexus-agent.exe init --token <T|-> [--port 7444]   initialise enrollment (token from the UI)
  nexus-agent.exe init --fleet-secret <S|->          initialise fleet enrollment (MSI FLEETSECRET=...)
  nexus-agent.exe install                            register + start the service (auto start, restart on failure)
  nexus-agent.exe uninstall                          stop and remove the service (keeps config/state)
  nexus-agent.exe service-setup                      MSI: secure %ProgramData%\\NexusAgent, failure actions of the service
  nexus-agent.exe purge-data --yes                   MSI uninstall with PURGE=1: delete config and state (enrollment)
  nexus-agent.exe msi-run MSI LOG STAGING            in-band update: msiexec, then the service started if it is not
  nexus-agent.exe status
  nexus-agent.exe run                                run in the foreground (debugging)
  nexus-agent.exe version
options: --config DIR --state DIR (default %ProgramData%\\NexusAgent\\{config,state})
--token - / --fleet-secret - read the value from stdin (keeps it out of the process list)";

fn base_of(paths: &Paths) -> PathBuf {
    paths
        .config
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| paths.config.clone())
}

fn secure(paths: &Paths) -> Result<(), String> {
    acl::secure(&base_of(paths), &[&paths.config, &paths.state])
        .map_err(|e| format!("securing {}: {e}", base_of(paths).display()))
}

pub fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match real_main(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("nexus-agent: {e}");
            ExitCode::FAILURE
        }
    }
}

fn real_main(args: &[String]) -> Result<ExitCode, String> {
    let mut paths = Paths::default();
    let (mut token, mut port, mut words, mut yes) = (None, None, vec![], false);
    let (mut repo_opts, mut json) = (agent_core::standalone::CliOpts::default(), false);
    let mut fleet = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = |n: &str| it.next().cloned().ok_or(format!("{n} needs a value"));
        match a.as_str() {
            "--token" => token = Some(val("--token")?),
            "--fleet-secret" => fleet = Some(val("--fleet-secret")?),
            "--port" => port = Some(val("--port")?.parse::<u16>().map_err(|_| "invalid --port")?),
            "--state" => paths.state = PathBuf::from(val("--state")?),
            "--config" => paths.config = PathBuf::from(val("--config")?),
            "--version" | "-V" => words.push("version".into()),
            "--yes" => yes = true,
            "--json" => json = true,
            "--path" | "--overwrite" | "--keep" => repo_opts.set(a, &val(a)?)?,
            "-h" | "--help" | "/?" => {
                println!("{USAGE}\n{}", agent_core::standalone::usage("nexus-agent.exe"));
                return Ok(ExitCode::SUCCESS);
            }
            w if !w.starts_with('-') => words.push(w.to_string()),
            o => return Err(format!("unknown option {o}\n{USAGE}")),
        }
    }
    match words.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["init"] => {
            let (prompt, mut t) = match (token, fleet) {
                (Some(t), None) => ("One-time enrollment token: ", t),
                (None, Some(f)) => ("Fleet secret: ", f),
                _ => return Err("init needs --token <T> or --fleet-secret <S>".into()),
            };
            if t == "-" {
                t.clear();
                if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                    eprint!("{prompt}");
                }
                std::io::stdin().read_line(&mut t).map_err(|e| format!("stdin: {e}"))?;
            }
            secure(&paths)?;
            let fp = if prompt.starts_with("Fleet") {
                agent_core::init_fleet(&paths, &t, port, &host::hostname())?
            } else {
                agent_core::init(&paths, &t, port, &host::hostname())?
            };
            println!(
                "initialised for enrollment (stored as sha256 only)\nenrollment certificate sha256 {fp}\n(re)start the service: sc.exe stop {SERVICE_NAME} & sc.exe start {SERVICE_NAME}"
            );
            Ok(ExitCode::SUCCESS)
        }
        ["install"] => install(&paths).map(|_| ExitCode::SUCCESS),
        ["uninstall"] => uninstall().map(|_| ExitCode::SUCCESS),
        ["service-setup"] => service_setup(&paths).map(|_| ExitCode::SUCCESS),
        ["msi-run", msi, log, staging] => msi_run(msi, log, staging).map(|_| ExitCode::SUCCESS),
        ["purge-data"] if yes => {
            let base = base_of(&paths);
            match std::fs::remove_dir_all(&base) {
                Ok(()) => println!("{} deleted", base.display()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("{}: {e}", base.display())),
            }
            Ok(ExitCode::SUCCESS)
        }
        ["status"] => {
            print!("{}", status(&paths));
            Ok(ExitCode::SUCCESS)
        }
        ["run"] => run(paths, None).map(|_| ExitCode::SUCCESS),
        // Phase 38b/38c standalone mode (an elevated prompt: backup privilege, VSS)
        ["repo", rest @ ..] => {
            repo_opts.json = json;
            let settings = Settings::load(&paths)?;
            secure(&paths)?;
            let failed = sys::enable_privileges(&PRIVILEGES);
            vss::com_security();
            let platform = Windows {
                sacl: !failed.iter().any(|p| p == "SeSecurityPrivilege"),
            };
            let ok = agent_core::standalone::cli(&platform, &paths, &settings, &host::hostname(), rest, &repo_opts)
                .map_err(|e| {
                    if e.is_empty() {
                        agent_core::standalone::usage("nexus-agent.exe")
                    } else {
                        e
                    }
                })?;
            Ok(if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE })
        }
        ["service"] => {
            *SERVICE_PATHS.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(paths);
            service_dispatcher::start(SERVICE_NAME, ffi_service_main)
                .map_err(|e| format!("service dispatcher: {e}"))?;
            Ok(ExitCode::SUCCESS)
        }
        ["version"] => {
            println!("nexus-agent {}", env!("CARGO_PKG_VERSION"));
            std::hint::black_box(crate::update::VERSION_MARKER);
            Ok(ExitCode::SUCCESS)
        }
        _ => Err(USAGE.into()),
    }
}

fn status(paths: &Paths) -> String {
    let mut out = agent_core::status_common(paths, env!("CARGO_PKG_VERSION"));
    let (os, build) = host::os_version();
    out.push_str(&format!("host: {} {os} {build}\n", host::hostname()));
    out.push_str("volumes:\n");
    for v in volumes::list() {
        out.push_str(&format!(
            "  {} {} {} snapshot={:?}\n",
            v.mount.win32(),
            v.fstype,
            v.guid,
            v.snapshot_kind()
        ));
    }
    out
}

fn install(paths: &Paths) -> Result<(), String> {
    secure(paths)?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let m = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| format!("service manager: {}", werr(&e)))?;
    let mut launch: Vec<OsString> = vec![];
    if paths.config != Paths::default().config {
        launch.extend(["--config".into(), paths.config.clone().into_os_string()]);
    }
    if paths.state != Paths::default().state {
        launch.extend(["--state".into(), paths.state.clone().into_os_string()]);
    }
    launch.push("service".into());
    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: launch,
        dependencies: vec![],
        account_name: None, // LocalSystem: backup/restore/security privileges
        account_password: None,
    };
    let s = m
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .map_err(|e| format!("create service: {}", werr(&e)))?;
    let _ = s.set_description("NexusBackup pull-model backup agent (mTLS, VSS, USN journal)");
    failure_actions(&s)?;
    s.start::<&str>(&[])
        .map_err(|e| format!("start service: {}", werr(&e)))?;
    println!("service {SERVICE_NAME} installed and started");
    Ok(())
}

/// Restart after 2 s / 10 s / 60 s (counter reset after a day), also after a stop with a
/// non-zero exit code (self-update exits with 75).
/// windows-service errors print "IO error in winapi call" and keep the OS error as the source.
fn werr(e: &windows_service::Error) -> String {
    match std::error::Error::source(e) {
        Some(src) => format!("{e}: {src}"),
        None => e.to_string(),
    }
}

fn failure_actions(s: &windows_service::service::Service) -> Result<(), String> {
    s.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(2),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(10),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(60),
            },
        ]),
    })
    .map_err(|e| format!("failure actions: {}", werr(&e)))?;
    // a stop with a non-zero exit code (self-update) also triggers the restart
    s.set_failure_actions_on_non_crash_failures(true)
        .map_err(|e| format!("failure actions flag: {}", werr(&e)))
}

/// The MSI registers the service itself (ServiceInstall table) and runs this deferred,
/// as LocalSystem, after InstallServices: the protected ACL on `%ProgramData%\NexusAgent`
/// (also covers the release keys the MSI put there) and the failure actions, which the
/// MSI tables cannot express without the WiX util extension.
fn service_setup(paths: &Paths) -> Result<(), String> {
    secure(paths)?;
    let m = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("service manager: {}", werr(&e)))?;
    let s = m
        // SC_ACTION_RESTART in the failure actions needs SERVICE_START (else ERROR_ACCESS_DENIED)
        .open_service(SERVICE_NAME, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .map_err(|e| format!("open service: {}", werr(&e)))?;
    failure_actions(&s)?;
    println!(
        "service {SERVICE_NAME}: failure actions set, {} secured",
        base_of(paths).display()
    );
    Ok(())
}

/// In-band MSI update (started detached by the service from a copy of this exe in the staging directory, so the
/// MSI can replace the installed one): msiexec with the fixed arguments of [`crate::update::msiexec_args`], then
/// the service started if it does not run. After a failed upgrade Windows Installer rolls back to the old version
/// but leaves its service stopped (#96: nothing then reported the failure); after a successful one the MSI has
/// started it already.
fn msi_run(msi: &str, log: &str, staging: &str) -> Result<(), String> {
    let args = crate::update::msiexec_args(msi.as_ref(), log.as_ref(), staging.as_ref())?;
    let exe = crate::update::msiexec(std::env::var_os("SystemRoot"));
    let st = std::process::Command::new(&exe)
        .args(&args)
        .status()
        .map_err(|e| format!("{}: {e}", exe.display()))?;
    println!("msiexec: {st}");
    // the service may be in the middle of starting or being recreated: a few tries
    let mut last = String::new();
    for _ in 0..30 {
        match start_service() {
            Ok(()) => return Ok(()),
            Err(e) => last = e,
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    Err(format!("service {SERVICE_NAME} not started after the update: {last}"))
}

/// Starts the service unless it runs or is starting.
fn start_service() -> Result<(), String> {
    let m = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("service manager: {}", werr(&e)))?;
    let s = m
        .open_service(SERVICE_NAME, ServiceAccess::START | ServiceAccess::QUERY_STATUS)
        .map_err(|e| format!("open service: {}", werr(&e)))?;
    let state = s
        .query_status()
        .map_err(|e| format!("query service: {}", werr(&e)))?
        .current_state;
    if matches!(state, ServiceState::Running | ServiceState::StartPending) {
        return Ok(());
    }
    s.start(&[] as &[&std::ffi::OsStr])
        .map_err(|e| format!("start service: {}", werr(&e)))
}

fn uninstall() -> Result<(), String> {
    let m = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("service manager: {}", werr(&e)))?;
    let s = m
        .open_service(
            SERVICE_NAME,
            ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
        )
        .map_err(|e| format!("open service: {}", werr(&e)))?;
    let _ = s.stop();
    s.delete().map_err(|e| format!("delete service: {}", werr(&e)))?;
    println!(
        "service {SERVICE_NAME} removed (config and state kept in {})",
        base_of(&Paths::default()).display()
    );
    Ok(())
}

static SERVICE_PATHS: std::sync::Mutex<Option<Paths>> = std::sync::Mutex::new(None);

define_windows_service!(ffi_service_main, service_main);

static STATUS_HANDLE: std::sync::OnceLock<service_control_handler::ServiceStatusHandle> = std::sync::OnceLock::new();

fn svc_status(state: ServiceState, code: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(code),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    }
}

fn service_main(_args: Vec<OsString>) {
    let handler = move |c| match c {
        // a requested stop is reported as such (no restart by the failure actions);
        // non-persistent shadow copies vanish with the process, nothing to flush
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(h) = STATUS_HANDLE.get() {
                let _ = h.set_service_status(svc_status(ServiceState::Stopped, 0));
            }
            std::process::exit(0)
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(h) = service_control_handler::register(SERVICE_NAME, handler) else {
        return;
    };
    let _ = STATUS_HANDLE.set(h);
    let _ = h.set_service_status(svc_status(ServiceState::Running, 0));
    let paths = SERVICE_PATHS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
        .unwrap_or_default();
    log_to_file(&paths);
    let code = match run(paths, Some(())) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("nexus-agent: {e}");
            1
        }
    };
    let _ = h.set_service_status(svc_status(ServiceState::Stopped, code));
}

/// A service has no console: stderr goes to `state\\nexus-agent.log` (rotated at
/// 10 MiB, one old file kept), with timestamps.
fn log_to_file(paths: &Paths) {
    use std::os::windows::io::IntoRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Console::{SetStdHandle, STD_ERROR_HANDLE};
    let _ = std::fs::create_dir_all(&paths.state);
    let p = paths.state.join("nexus-agent.log");
    if std::fs::metadata(&p).is_ok_and(|m| m.len() > 10 << 20) {
        let _ = std::fs::rename(&p, paths.state.join("nexus-agent.log.1"));
    }
    if let Ok(f) = std::fs::OpenOptions::new().create(true).append(true).open(&p) {
        // SAFETY: the handle is leaked on purpose and stays valid for the process.
        let _ = unsafe { SetStdHandle(STD_ERROR_HANDLE, HANDLE(f.into_raw_handle())) };
    }
    agent_core::server::log_timestamps(true);
}

fn run(paths: Paths, service: Option<()>) -> Result<(), String> {
    std::hint::black_box(crate::update::VERSION_MARKER);
    // start watchdog of a freshly swapped binary (docs/agent-update-plan.md): the third
    // start without reaching "listening" puts nexus-agent.exe.prev back
    if let Ok(exe) = std::env::current_exe() {
        let restore = || crate::update::restore_prev(&exe);
        if agent_core::update::watchdog_on_start(&paths, env!("CARGO_PKG_VERSION"), &restore)
            == agent_core::update::Watchdog::Reverted
        {
            eprintln!("nexus-agent: the new version did not start; the previous binary is back, restarting");
            // the service control manager restarts the service (failure actions)
            std::process::exit(crate::update::RESTART_EXIT_CODE);
        }
    }
    let settings = Settings::load(&paths)?;
    secure(&paths)?;
    let _ = std::fs::remove_dir_all(paths.spool_dir());
    let failed = sys::enable_privileges(&PRIVILEGES);
    if !failed.is_empty() {
        eprintln!(
            "nexus-agent: privileges not available: {} (run as LocalSystem)",
            failed.join(", ")
        );
    }
    vss::com_security();
    let platform = Windows {
        sacl: !failed.iter().any(|p| p == "SeSecurityPrivilege"),
    };
    match agent_core::adopt_fleet_secret(&paths, &host::hostname()) {
        Some(Ok(m)) => eprintln!("nexus-agent: {m}"),
        Some(Err(e)) => eprintln!("nexus-agent: fleet secret: {e}"),
        None => {}
    }
    let agent = Agent::with_platform(platform, paths, settings.clone())?;
    // Phase 38e: scheduled standalone jobs (<config>\standalone.json) run in this service as well
    let standalone = match agent_core::standalone::load_jobs(&agent.paths) {
        Ok(j) => !j.is_empty(),
        Err(e) => {
            eprintln!("nexus-agent: {e}");
            false
        }
    };
    match agent.mode() {
        // standalone only: no appliance, nothing to listen for
        Mode::Uninitialized if standalone => {
            eprintln!(
                "nexus-agent {}: standalone jobs only (not enrolled)",
                env!("CARGO_PKG_VERSION")
            );
            // the local UI still shows the jobs and can run one now
            let agent = Arc::new(agent);
            let a = agent.clone();
            std::thread::spawn(move || {
                if let Err(e) = super::pipe::serve(a) {
                    eprintln!("nexus-agent: local UI pipe {}: {e}", agent_ui_proto::PIPE_NAME);
                }
            });
            agent_core::standalone::run_jobs(&agent.platform, &agent.paths, &agent.settings);
            return Ok(());
        }
        // the MSI starts the service before enrollment: stop cleanly (no failure-action restarts)
        Mode::Uninitialized if service.is_some() => {
            eprintln!("nexus-agent: not initialised; run nexus-agent.exe init --token - and start the service");
            return Ok(());
        }
        Mode::Uninitialized => return Err("not initialised: run nexus-agent.exe init --token <T>".into()),
        Mode::Locked(_) => eprintln!("nexus-agent: enrollment LOCKED; run nexus-agent.exe init again"),
        Mode::Enroll(_) => eprintln!("nexus-agent: waiting for enrollment by the appliance"),
        Mode::Mtls { agent_id, .. } => eprintln!("nexus-agent: enrolled as {agent_id}"),
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
    let a = agent.clone();
    std::thread::spawn(move || {
        if let Err(e) = super::pipe::serve(a) {
            eprintln!("nexus-agent: local UI pipe {}: {e}", agent_ui_proto::PIPE_NAME);
        }
    });
    agent.serve(listener).map_err(|e| e.to_string())
}
