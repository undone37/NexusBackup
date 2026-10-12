//! `nexus-config-backup tick [<control-dir> [<root> [<keyd-run-dir>]]]`: the root
//! helper behind `nexus-config-backup.path` (request from the scheduler's
//! `config_backup` job). The logic is in `setup::cfgbackup`.

use setup::cfgbackup;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    // umask 077 (files are chmod'ed explicitly), not dumpable, memory locked: key files pass through
    keyd::harden_process();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg = |i: usize, d: &str| PathBuf::from(args.get(i).map_or(d, String::as_str));
    if args.first().map(String::as_str) != Some("tick") || args.len() > 4 {
        eprintln!("usage: nexus-config-backup tick [<control-dir> [<root> [<keyd-run-dir>]]]");
        return ExitCode::from(2);
    }
    match cfgbackup::tick(&arg(1, cfgbackup::DIR), &arg(2, "/"), &arg(3, cfgbackup::KEYD_RUN)) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("nexus-config-backup: {e:#}");
            ExitCode::FAILURE
        }
    }
}
