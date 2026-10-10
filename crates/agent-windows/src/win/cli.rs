//! `nexus-agent.exe` commands and the Windows service.

use super::{acl, host, sys, volumes, vss, Agent, Windows, PRIVILEGES};
use agent_core::config::{Paths, Settings};
use agent_core::server::Mode;
use std::ffi::OsString;
use std::net::TcpListener;
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
  nexus-agent.exe install                            register + start the service (auto start, restart on failure)
  nexus-agent.exe uninstall                          stop and remove the service (keeps config/state)
  nexus-agent.exe status
  nexus-agent.exe run                                run in the foreground (debugging)
  nexus-agent.exe version
options: --config DIR --state DIR (default %ProgramData%\\NexusAgent\\{config,state})
--token - reads the token from stdin (keeps it out of the process list)";

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
    let (mut token, mut port, mut words) = (None, None, vec![]);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = |n: &str| it.next().cloned().ok_or(format!("{n} needs a value"));
        match a.as_str() {
            "--token" => token = Some(val("--token")?),
            "--port" => port = Some(val("--port")?.parse::<u16>().map_err(|_| "invalid --port")?),
            "--state" => paths.state = PathBuf::from(val("--state")?),
            "--config" => paths.config = PathBuf::from(val("--config")?),
            "-h" | "--help" | "/?" => {
                println!("{USAGE}");
                return Ok(ExitCode::SUCCESS);
            }
            w if !w.starts_with('-') => words.push(w.to_string()),
            o => return Err(format!("unknown option {o}\n{USAGE}")),
        }
    }
    match words.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["init"] => {
            let mut t = token.ok_or("init needs --token <T>")?;
            if t == "-" {
                t.clear();
                if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                    eprint!("One-time enrollment token: ");
                }
                std::io::stdin().read_line(&mut t).map_err(|e| format!("stdin: {e}"))?;
            }
            secure(&paths)?;
            let fp = agent_core::init(&paths, &t, port, &host::hostname())?;
            println!(
                "initialised for enrollment (token stored as sha256 only)\nenrollment certificate sha256 {fp}\n(re)start the service: sc.exe stop {SERVICE_NAME} & sc.exe start {SERVICE_NAME}"
            );
            Ok(ExitCode::SUCCESS)
        }
        ["install"] => install(&paths).map(|_| ExitCode::SUCCESS),
        ["uninstall"] => uninstall().map(|_| ExitCode::SUCCESS),
        ["status"] => {
            print!("{}", status(&paths));
            Ok(ExitCode::SUCCESS)
        }
        ["run"] => run(paths, None).map(|_| ExitCode::SUCCESS),
        ["service"] => {
            *SERVICE_PATHS.lock().unwrap_or_else(|e| e.into_inner()) = Some(paths);
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
    .map_err(|e| format!("service manager: {e}"))?;
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
        .map_err(|e| format!("create service: {e}"))?;
    let _ = s.set_description("NexusBackup pull-model backup agent (mTLS, VSS, USN journal)");
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
    .map_err(|e| format!("failure actions: {e}"))?;
    // a stop with a non-zero exit code (self-update) also triggers the restart
    s.set_failure_actions_on_non_crash_failures(true)
        .map_err(|e| format!("failure actions flag: {e}"))?;
    s.start::<&str>(&[]).map_err(|e| format!("start service: {e}"))?;
    println!("service {SERVICE_NAME} installed and started");
    Ok(())
}

fn uninstall() -> Result<(), String> {
    let m = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("service manager: {e}"))?;
    let s = m
        .open_service(
            SERVICE_NAME,
            ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
        )
        .map_err(|e| format!("open service: {e}"))?;
    let _ = s.stop();
    s.delete().map_err(|e| format!("delete service: {e}"))?;
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
        .unwrap_or_else(|e| e.into_inner())
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

fn run(paths: Paths, _service: Option<()>) -> Result<(), String> {
    std::hint::black_box(crate::update::VERSION_MARKER);
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
    let agent = Agent::with_platform(platform, paths, settings.clone())?;
    match agent.mode() {
        Mode::Uninitialized => return Err("not initialised: run nexus-agent.exe init --token <T>".into()),
        Mode::Locked(_) => eprintln!("nexus-agent: enrollment LOCKED; run nexus-agent.exe init again"),
        Mode::Enroll(_) => eprintln!("nexus-agent: waiting for enrollment by the appliance"),
        Mode::Mtls { agent_id, .. } => eprintln!("nexus-agent: enrolled as {agent_id}"),
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
    Arc::new(agent).serve(listener).map_err(|e| e.to_string())
}
