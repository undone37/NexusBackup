//! `nexus-nft-sync [--dry-run | --status] [--allowed FILE] [--hosts FILE] [--resolv FILE] [--chrony FILE] [--nft BIN]`
//! Root oneshot (nexus-nft-sync.service): refreshes the allow-list sets of
//! `table inet nexus` (see the crate docs). `--dry-run` prints the nft script
//! instead of applying it; `--status` (nexus-nft-status.service, every minute)
//! only writes the status file for the web UI, which every sync also does.

use anyhow::{bail, Result};
use nftsync::{
    apply, chrony_includes, desired, parse_chrony, parse_hosts, parse_resolv, resolve, resolve_hosts, script, status,
    Allowed, State, ALLOWED_FILE, STATUS_FILE,
};
use std::path::PathBuf;

fn main() -> Result<()> {
    let mut status_file = PathBuf::from(STATUS_FILE);
    let mut status_only = false;
    let mut allowed = PathBuf::from(ALLOWED_FILE);
    let mut hosts = PathBuf::from("/etc/nexus/allowed-hosts");
    let mut resolv = PathBuf::from("/etc/resolv.conf");
    let mut chrony = PathBuf::from("/etc/chrony.conf");
    let mut nft = PathBuf::from("/usr/sbin/nft");
    // what the last successful run put into the sets (RuntimeDirectory, tmpfs: gone after boot)
    let mut state = PathBuf::from("/run/nexus-nft-sync/state.json");
    let mut dry = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || args.next().map(PathBuf::from).unwrap_or_default();
        match a.as_str() {
            "--allowed" => allowed = val(),
            "--hosts" => hosts = val(),
            "--resolv" => resolv = val(),
            "--chrony" => chrony = val(),
            "--nft" => nft = val(),
            "--state" => state = val(),
            "--status-file" => status_file = val(),
            "--status" => status_only = true,
            "--dry-run" => dry = true,
            _ => bail!(
                "usage: nexus-nft-sync [--dry-run | --status] [--allowed F] [--hosts F] [--resolv F] [--chrony F] [--nft BIN] [--state F] [--status-file F]"
            ),
        }
    }
    if status_only {
        return status::refresh(&nft, &status_file);
    }
    let mut allowed = Allowed::load(&allowed)?;
    let from_scheduler = allowed.endpoints.len();
    let dns = parse_resolv(&std::fs::read_to_string(&resolv).unwrap_or_default());
    let mut prev: Option<State> = std::fs::read(&state).ok().and_then(|b| serde_json::from_slice(&b).ok());
    let mut run = |want: State| -> Result<()> {
        let s = script(prev.as_ref(), &want);
        if dry {
            print!("{s}");
            return Ok(());
        }
        apply(&nft, &s)?;
        let mut all = prev.take().unwrap_or_default();
        all.extend(want);
        // without the state the next run flushes and refills instead (still correct)
        if let Err(e) = std::fs::write(&state, serde_json::to_vec(&all)?) {
            eprintln!("<4>nexus-nft-sync: cannot write {}: {e}", state.display());
        }
        prev = Some(all);
        Ok(())
    };
    // 1. resolvers first, so the names below can be resolved
    run(desired(Some(&dns), None, None))?;
    let main_conf = std::fs::read_to_string(&chrony).unwrap_or_default();
    let mut ntp = parse_chrony(&main_conf);
    for f in chrony_includes(&main_conf) {
        for h in parse_chrony(&std::fs::read_to_string(&f).unwrap_or_default()) {
            if !ntp.contains(&h) {
                ntp.push(h);
            }
        }
    }
    let (nts, mut errors) = resolve(&ntp);
    let (fixed, e2) = resolve_hosts(&parse_hosts(&std::fs::read_to_string(&hosts).unwrap_or_default()));
    errors.extend(e2);
    allowed.endpoints.extend(fixed);
    for e in &errors {
        eprintln!("<4>nexus-nft-sync: cannot resolve {e}");
    }
    // 2. everything in one transaction; NTS sets stay as they are if no name resolved
    let nts = (!nts.is_empty() || ntp.is_empty()).then_some(nts.as_slice());
    run(desired(Some(&dns), nts, Some(&allowed)))?;
    eprintln!(
        "nexus-nft-sync: {} endpoints ({} from the scheduler), {} resolvers, {} NTS addresses{}",
        allowed.endpoints.len(),
        from_scheduler,
        dns.len(),
        nts.map_or(0, <[_]>::len),
        if nts.is_none() { " (NTS sets kept)" } else { "" }
    );
    if !dry {
        // the web UI shows the new state right away (not fatal: the timer retries)
        if let Err(e) = status::refresh(&nft, &status_file) {
            eprintln!("<4>nexus-nft-sync: status: {e:#}");
        }
    }
    Ok(())
}
