//! Enrollment (docs/agent-protocol.md "Enrollment"): TLS 1.3 without
//! certificate validation, both sides prove knowledge of the token digest
//! bound to this session's TLS exporter, the appliance signs the agent's CSR.

use crate::ca::Ca;
use crate::tls::{enroll_config, Session};
use agent_proto::{enroll_proof, proof_eq, Message};
use anyhow::{bail, Result};
use std::time::Duration;

pub struct Enrolled {
    pub cert_pem: String,
    pub cert_sha256: String,
}

/// `token_digest` = `agent_proto::token_digest(token)` (what the appliance keeps).
pub fn enroll(
    ca: &Ca,
    host: &str,
    port: u16,
    token_digest: &str,
    agent_id: &str,
    timeout: Duration,
) -> Result<Enrolled> {
    let mut s = Session::connect(host, port, enroll_config(ca)?, timeout)?;
    let ex = s.exporter()?;
    s.send(&Message::Enroll {
        proof: enroll_proof(token_digest, "appliance", &ex),
    })?;
    let (proof, csr_pem) = match s.recv()? {
        Message::EnrollReply { proof, csr_pem } => (proof, csr_pem),
        m => bail!("unexpected answer to Enroll: {}", crate::name(&m)),
    };
    if !proof_eq(&proof, &enroll_proof(token_digest, "agent", &ex)) {
        bail!("the agent's enrollment proof is invalid (wrong token, or a man in the middle): not enrolled");
    }
    let (cert_pem, cert_sha256) = ca.sign_agent(&csr_pem, agent_id)?;
    s.send(&Message::EnrollDone {
        cert_pem: cert_pem.clone(),
        ca_pem: ca.ca_pem.clone(),
        agent_id: agent_id.to_owned(),
    })?;
    s.close();
    Ok(Enrolled { cert_pem, cert_sha256 })
}
