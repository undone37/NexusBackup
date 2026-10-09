//! `nexus-scheduler [--config /etc/nexus/scheduler.json] [--once]`
//! Runs the tick loop (docs/control-plane.md "Scheduler"). The config file is
//! optional; see `scheduler::Config` for keys and defaults. `--once` runs one
//! tick, waits for the started jobs and exits.

use anyhow::{bail, Result};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

fn main() -> Result<()> {
    keyd::deny_dumps();
    let mut cfg_path = PathBuf::from("/etc/nexus/scheduler.json");
    let mut once = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => cfg_path = args.next().map(PathBuf::from).unwrap_or_default(),
            "--once" => once = true,
            _ => bail!("usage: nexus-scheduler [--config <scheduler.json>] [--once]"),
        }
    }
    let cfg = scheduler::load_config(&cfg_path)?;
    let mut s = scheduler::Scheduler::open(cfg)?;
    if once {
        s.tick(catalog::now())?;
        s.wait_idle(Duration::from_secs(u64::MAX / 4))?;
        // let the delivery thread flush
        std::thread::sleep(Duration::from_secs(1));
        return Ok(());
    }
    // SIGTERM ends the process; jobs left running are failed by recovery on the next start.
    s.run(&AtomicBool::new(false))
}
