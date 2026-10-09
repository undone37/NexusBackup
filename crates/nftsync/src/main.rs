//! `nexus-nft-sync [--dry-run] [--allowed FILE] [--hosts FILE] [--resolv FILE] [--chrony FILE] [--nft BIN]`
//! Root oneshot (nexus-nft-sync.service): refreshes the outbound allow-list
//! sets of `table inet nexus` (see the crate docs). `--dry-run` prints the nft
//! script instead of applying it.

use anyhow::{bail, Result};
use nftsync::{
    apply, desired, parse_chrony, parse_hosts, parse_resolv, resolve, resolve_hosts, script, Allowed, State,
    ALLOWED_FILE,
};
use std::path::PathBuf;

fn main() -> Result<()> {
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
            "--dry-run" => dry = true,
            _ => bail!(
                "usage: nexus-nft-sync [--dry-run] [--allowed F] [--hosts F] [--resolv F] [--chrony F] [--nft BIN] [--state F]"
            ),
        }
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
    let ntp = parse_chrony(&std::fs::read_to_string(&chrony).unwrap_or_default());
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
    Ok(())
}
