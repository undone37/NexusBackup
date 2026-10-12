//! `nexus-tls [--tls DIR] [--req DIR]`: root oneshot (nexus-tls.service, started by
//! nexus-tls.path when the web-api writes a request). Handles the pending request
//! (CSR, install, revert; see the crate docs) and exits.

use anyhow::{bail, Result};
use webtls::Paths;

fn main() -> Result<()> {
    let mut p = Paths::default();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match (a.as_str(), args.next()) {
            ("--tls", Some(v)) => p.tls = v.into(),
            ("--req", Some(v)) => p.req = v.into(),
            _ => bail!("usage: nexus-tls [--tls DIR] [--req DIR]"),
        }
    }
    // the web-api serialises its requests; a second one may arrive while this runs
    for _ in 0..8 {
        if !webtls::process(&p)? {
            break;
        }
    }
    Ok(())
}
