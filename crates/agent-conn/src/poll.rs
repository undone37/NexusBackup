//! Endpoint status sessions (protocol v1.4, docs/endpoint-ui.md): one short mTLS
//! session per agent — `Hello`, pending `SessionSummary`s (each answered with
//! `SummaryAck`), then `Poll` → `PollReply` (queued "back up now" requests, power /
//! network state). Agents without CAP_POLL only get the `Hello` (reachability,
//! version). Run by `nexus-agentctl <cfg> poll` for all due agents at once with
//! bounded concurrency; one `poll {json}` line per agent.

use crate::ca::Ca;
use crate::tls::{session_config_pins, Session};
use agent_proto::{ApplianceStatus, Message, Summary, CAP_POLL};
use anyhow::{bail, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub id: String,
    pub host: String,
    pub port: u16,
    /// accepted certificate fingerprints (recorded + renewed-but-unconfirmed)
    pub pins: Vec<String>,
    pub status: ApplianceStatus,
    /// request ids the appliance has acted on
    #[serde(default)]
    pub ack: Vec<String>,
    /// summaries not yet delivered (oldest first)
    #[serde(default)]
    pub summaries: Vec<Summary>,
}

/// One agent: never fails, the error goes into the result line.
pub fn poll_one(ca: &Ca, t: &Target, timeout: Duration) -> Value {
    let mut delivered = Vec::new();
    match session(ca, t, timeout, &mut delivered) {
        Ok(mut v) => {
            v["agent_id"] = json!(t.id);
            v["ok"] = json!(true);
            v["delivered"] = json!(delivered);
            v
        }
        Err(e) => json!({"agent_id": t.id, "ok": false, "error": format!("{e:#}"), "delivered": delivered}),
    }
}

fn session(ca: &Ca, t: &Target, timeout: Duration, delivered: &mut Vec<u64>) -> Result<Value> {
    if !crate::valid_agent_id(&t.id) || t.pins.is_empty() {
        bail!("agent {:?} is not enrolled", t.id);
    }
    let pins: Vec<&str> = t.pins.iter().map(String::as_str).collect();
    let mut s = Session::connect(&t.host, t.port, session_config_pins(ca, &t.id, &pins)?, timeout)?;
    let info = s.hello(&t.id)?;
    let mut out = json!({"info": info, "poll": s.has_cap(CAP_POLL)});
    if !s.has_cap(CAP_POLL) {
        s.close();
        return Ok(out);
    }
    for sum in &t.summaries {
        let job = sum.job;
        s.send(&Message::SessionSummary {
            summary: sum.clone(),
            status: t.status.clone(),
        })?;
        match s.recv()? {
            Message::SummaryAck { job: j } if j == job => delivered.push(job),
            m => bail!("unexpected answer to SessionSummary: {}", crate::name(&m)),
        }
    }
    s.send(&Message::Poll {
        status: t.status.clone(),
        ack: t.ack.clone(),
    })?;
    match s.recv()? {
        Message::PollReply {
            requests,
            power,
            policy_version,
            busy,
        } => {
            // request ids become job parameters and audit entries: hex only
            let requests: Vec<Value> = requests
                .into_iter()
                .filter(|r| !r.id.is_empty() && r.id.len() <= 64 && r.id.bytes().all(|b| b.is_ascii_hexdigit()))
                .map(|r| json!({"id": r.id, "queued_at": r.queued_at}))
                .collect();
            out["requests"] = json!(requests);
            out["power"] = json!({
                "on_battery": power.on_battery,
                "battery_percent": power.battery_percent,
                "metered": power.metered,
                "network_name": power.network_name,
            });
            out["policy_version"] = json!(policy_version);
            out["busy"] = json!(busy);
        }
        m => bail!("unexpected answer to Poll: {}", crate::name(&m)),
    }
    s.close();
    Ok(out)
}

/// All targets, at most `concurrency` sessions at once; `out` gets one result per
/// target (in completion order).
pub fn poll_all(ca: &Ca, targets: &[Target], concurrency: usize, timeout: Duration, out: &mut dyn FnMut(Value)) {
    let next = AtomicUsize::new(0);
    let (tx, rx) = mpsc::channel();
    std::thread::scope(|sc| {
        for _ in 0..concurrency.clamp(1, 64).min(targets.len()) {
            let (tx, next) = (tx.clone(), &next);
            sc.spawn(move || {
                while let Some(t) = targets.get(next.fetch_add(1, Ordering::SeqCst)) {
                    if tx.send(poll_one(ca, t, timeout)).is_err() {
                        break;
                    }
                }
            });
        }
        drop(tx);
        for v in rx {
            out(v);
        }
    });
}
