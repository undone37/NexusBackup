//! Fleet scan (docs/agent-protocol.md "Fleet enrollment"): probe every address of a
//! fleet's ranges on the agent port for agents initialised with the fleet secret.
//! TLS as for enrollment (nothing to pin yet); the appliance proves the secret first
//! (`FleetProbe`), the agent answers with its own proof and hostname / OS / version.
//! Enrollment itself is the normal `enroll` with the fleet secret digest as token.

use crate::ca::Ca;
use crate::tls::{enroll_config, Session};
use agent_proto::{enroll_proof, proof_eq, Message};
use anyhow::{bail, Result};
use serde::Serialize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Found {
    pub host: String,
    pub port: u16,
    pub hostname: String,
    pub os: String,
    pub version: String,
}

/// One probe. `Ok(None)`: something answered, but no agent of this fleet (an
/// enrolled agent, another fleet, an old agent).
pub fn probe(ca: &Ca, host: &str, port: u16, fleet_id: &str, digest: &str, timeout: Duration) -> Result<Option<Found>> {
    let mut s = Session::connect(host, port, enroll_config(ca)?, timeout)?;
    let ex = s.exporter()?;
    s.send(&Message::FleetProbe {
        fleet_id: fleet_id.to_owned(),
        proof: enroll_proof(digest, "fleet-appliance", &ex),
    })?;
    let Ok(m) = s.recv() else {
        return Ok(None);
    };
    s.close();
    let Message::FleetInfo {
        proof,
        hostname,
        os,
        agent_version,
    } = m
    else {
        bail!("unexpected answer to FleetProbe: {}", crate::name(&m));
    };
    if !proof_eq(&proof, &enroll_proof(digest, "fleet-agent", &ex)) {
        bail!("the agent's fleet proof is invalid (a man in the middle?)");
    }
    let clean = |s: String| s.chars().filter(|c| !c.is_control()).take(128).collect::<String>();
    Ok(Some(Found {
        host: host.to_owned(),
        port,
        hostname: clean(hostname),
        os: clean(os),
        version: clean(agent_version),
    }))
}

/// Scan pacing: at most `parallel` connections at a time and `rate` new ones per
/// second, `timeout` per connect and answer.
pub struct Pace {
    pub parallel: usize,
    pub rate: u32,
    pub timeout: Duration,
}

/// Probes `targets` on `port`; `found` is called for every agent of the fleet.
/// Returns the number found.
pub fn scan(
    ca: &Ca,
    targets: &[String],
    port: u16,
    fleet_id: &str,
    digest: &str,
    pace: &Pace,
    found: &(dyn Fn(&Found) + Sync),
) -> usize {
    let next = AtomicUsize::new(0);
    let hits = AtomicUsize::new(0);
    let slot = Mutex::new(Instant::now());
    let gap = Duration::from_secs(1) / pace.rate.max(1);
    std::thread::scope(|sc| {
        for _ in 0..pace.parallel.clamp(1, 32) {
            sc.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::SeqCst);
                let Some(h) = targets.get(i) else { break };
                let wait = {
                    let mut t = slot.lock().unwrap_or_else(|e| e.into_inner());
                    let now = Instant::now();
                    let start = (*t).max(now);
                    *t = start + gap;
                    start - now
                };
                std::thread::sleep(wait);
                match probe(ca, h, port, fleet_id, digest, pace.timeout) {
                    Ok(Some(f)) => {
                        hits.fetch_add(1, Ordering::SeqCst);
                        found(&f);
                    }
                    Ok(None) => {}
                    // a bad proof is worth a line in the job log; closed ports are not
                    Err(e) if format!("{e:#}").contains("proof") => eprintln!("{h}: {e:#}"),
                    Err(_) => {}
                }
            });
        }
    });
    hits.into_inner()
}
