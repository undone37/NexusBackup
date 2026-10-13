//! Edge proxy protocol (`nexus-edge`, docs/edge.md): agents and the appliance both
//! connect *out* to the edge, which pairs a stream the appliance asked for with a
//! fresh connection of the agent and then relays bytes. Inside a relayed stream the
//! appliance and the agent run the normal agent protocol (TLS end to end, pinned
//! certificates): the edge sees only TLS records.
//!
//! Framing as for [`crate::Message`]: `u32 BE length | postcard(EdgeMsg)`; the
//! public (agent) port accepts at most [`MAX_PUBLIC_FRAME`], the control port
//! [`MAX_CONTROL_FRAME`] (signed edge updates).

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

pub const ALPN: &[u8] = b"nexus-edge/1";
pub const VERSION: u32 = 1;
/// default public (agent) port of an edge
pub const DEFAULT_PUBLIC_PORT: u16 = 443;
/// default control port (appliance only)
pub const DEFAULT_CONTROL_PORT: u16 = 7445;
/// TLS exporter label of the enrollment proofs (`crate::enroll_proof` with roles
/// `edge-appliance` / `edge`)
pub const EXPORTER_LABEL: &[u8] = b"nexus-edge enroll";
pub const MAX_PUBLIC_FRAME: usize = 64 << 10;
pub const MAX_CONTROL_FRAME: usize = 32 << 20;
/// at most this many agents in one `Configure`
pub const MAX_AGENTS: usize = 100_000;
/// longest `Wait`
pub const MAX_WAIT_SECS: u32 = 60;

/// An agent the edge lets in: its id and accepted certificate fingerprints (SHA-256 hex).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EdgeAgent {
    pub id: String,
    pub pins: Vec<String>,
}

/// Rate limits of the public port (0 = the edge's default).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct EdgeLimits {
    /// new connections per source IP and minute
    pub per_ip_per_min: u32,
    /// connections per agent certificate and minute
    pub per_agent_per_min: u32,
    /// concurrent public connections
    pub max_connections: u32,
}

/// What the edge reports with every `Events` (connection metadata only).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct EdgeHealth {
    pub version: String,
    pub uptime_secs: u64,
    /// SHA-256 of the edge certificate
    pub cert_sha256: String,
    /// agents with a rendezvous connection now
    pub agents_online: Vec<String>,
    /// open public connections
    pub connections: u32,
    /// streams being relayed
    pub relays: u32,
    /// refused handshakes / requests since start
    pub refused: u64,
    /// connections dropped by a rate limit since start
    pub rate_limited: u64,
    /// the appliance pushed a configuration since start
    pub configured: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum EdgeMsg {
    // ---- appliance → edge (control port)
    /// enrollment (edge not yet enrolled): `enroll_proof(digest, "edge-appliance", exporter)`
    Enroll {
        proof: [u8; 32],
    },
    /// `enroll_proof(digest, "edge", exporter)`; the edge pinned the appliance's client certificate
    Enrolled {
        proof: [u8; 32],
        version: String,
    },
    /// the agents to let in and the CA their certificates chain to → `Ok`
    Configure {
        ca_pem: String,
        agents: Vec<EdgeAgent>,
        limits: EdgeLimits,
    },
    /// long poll: answered with `Events` at once if a wake is pending, else after `secs`
    Wait {
        secs: u32,
    },
    Events {
        health: EdgeHealth,
        /// agents that asked for a session ("back up now")
        wakes: Vec<String>,
        /// new log lines since the last `Events`
        log: Vec<String>,
    },
    /// signed edge binary (cosign blob signature, release keys of the edge image) → `Ok`, then restart
    Update {
        version: String,
        binary: Vec<u8>,
        signature: Vec<u8>,
    },
    /// a stream to this agent → `Opened`, then the connection relays bytes
    Open {
        agent_id: String,
    },
    Opened,
    Ok,
    Error {
        code: u32,
        message: String,
    },
    // ---- agent → edge (public port)
    /// long-lived: the edge sends `Ping` and `Connect`
    Rendezvous,
    Ping,
    /// edge → agent: open a new connection with `Stream { nonce }`
    Connect {
        nonce: [u8; 16],
    },
    /// this connection is the stream `nonce`; then the agent runs its TLS server over it
    Stream {
        nonce: [u8; 16],
    },
    /// a local user asked for a backup: tell the appliance now (short connection)
    Wake,
}

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

pub fn encode(m: &EdgeMsg, max: usize) -> io::Result<Vec<u8>> {
    let body = postcard::to_stdvec(m).map_err(|e| bad(format!("encode: {e}")))?;
    if body.len() > max {
        return Err(bad("frame too large"));
    }
    let mut out = (body.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decodes a frame body and enforces the structural limits.
pub fn decode(body: &[u8]) -> io::Result<EdgeMsg> {
    let m: EdgeMsg = postcard::from_bytes(body).map_err(|e| bad(format!("decode: {e}")))?;
    let ok = match &m {
        EdgeMsg::Configure { agents, ca_pem, .. } => {
            agents.len() <= MAX_AGENTS
                && ca_pem.len() <= 64 << 10
                && agents
                    .iter()
                    .all(|a| a.id.len() <= 128 && a.pins.len() <= 4 && a.pins.iter().all(|p| p.len() <= 64))
        }
        EdgeMsg::Open { agent_id } => agent_id.len() <= 128,
        EdgeMsg::Events { wakes, log, .. } => wakes.len() <= 10_000 && log.len() <= 10_000,
        EdgeMsg::Error { message, .. } => message.len() <= 4096,
        _ => true,
    };
    if !ok {
        return Err(bad("edge message exceeds limits"));
    }
    Ok(m)
}

pub fn write(w: &mut impl Write, m: &EdgeMsg, max: usize) -> io::Result<()> {
    w.write_all(&encode(m, max)?)?;
    w.flush()
}

pub fn read(r: &mut impl Read, max: usize) -> io::Result<EdgeMsg> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > max {
        return Err(bad(format!("frame of {len} bytes exceeds the limit")));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    decode(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_limits() {
        let m = EdgeMsg::Stream { nonce: [7; 16] };
        let mut buf = Vec::new();
        write(&mut buf, &m, MAX_PUBLIC_FRAME).unwrap();
        assert_eq!(read(&mut &buf[..], MAX_PUBLIC_FRAME).unwrap(), m);
        let big = EdgeMsg::Update {
            version: "1.0.0".into(),
            binary: vec![0; MAX_PUBLIC_FRAME],
            signature: vec![],
        };
        assert!(encode(&big, MAX_PUBLIC_FRAME).is_err());
        let buf = encode(&big, MAX_CONTROL_FRAME).unwrap();
        assert!(
            read(&mut &buf[..], MAX_PUBLIC_FRAME).is_err(),
            "public port refuses big frames"
        );
        let bad = EdgeMsg::Open {
            agent_id: "x".repeat(129),
        };
        let buf = encode(&bad, MAX_PUBLIC_FRAME).unwrap();
        assert!(read(&mut &buf[..], MAX_PUBLIC_FRAME).is_err());
    }
}
