//! `nexus-agent.exe` CLI (Windows). On other platforms the binary only explains that.

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    nexus_agent_windows::win::cli::main()
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    // keep the version marker referenced in every build
    std::hint::black_box(nexus_agent_windows::update::VERSION_MARKER);
    eprintln!("nexus-agent (Windows agent) runs on Windows only; build it with crates/agent-windows/build.sh");
    std::process::ExitCode::FAILURE
}
