//! Certificate renewal over an mTLS session (docs/agent-protocol.md "Certificate
//! renewal"): `RenewCert` → the agent generates a new key pair and answers
//! `RenewCsr`; the appliance signs it like at enrollment (same CN, same CA) and
//! sends `RenewDone`; the agent checks it, swaps key + certificate atomically and
//! answers `RenewOk`. New connections then present the new certificate.
//!
//! `issued` is called with the new certificate's fingerprint before `RenewDone` is
//! sent, so the scheduler can accept it as a second pin: if the connection breaks
//! after the agent swapped but before `RenewOk` arrived, the next session still
//! verifies (and confirms the new pin).

use crate::ca::{cert_validity, pem_to_der, Ca};
use crate::tls::Session;
use agent_proto::{Message, CAP_RENEW};
use anyhow::{bail, Context, Result};

pub struct Renewed {
    pub cert_sha256: String,
    pub not_before: i64,
    pub not_after: i64,
}

pub fn renew(ca: &Ca, s: &mut Session, agent_id: &str, issued: &mut dyn FnMut(&Renewed)) -> Result<Renewed> {
    if !s.has_cap(CAP_RENEW) {
        bail!("this agent version cannot renew its certificate over the session: update the agent (or re-enroll it)");
    }
    s.send(&Message::RenewCert)?;
    let csr_pem = match s.recv()? {
        Message::RenewCsr { csr_pem } => csr_pem,
        m => bail!("unexpected answer to RenewCert: {}", crate::name(&m)),
    };
    let (cert_pem, cert_sha256) = ca.sign_agent(&csr_pem, agent_id)?;
    let (not_before, not_after) =
        cert_validity(&pem_to_der(&cert_pem)?).context("validity of the issued certificate")?;
    let r = Renewed {
        cert_sha256,
        not_before,
        not_after,
    };
    issued(&r);
    s.send(&Message::RenewDone {
        cert_pem,
        ca_pem: ca.ca_pem.clone(),
    })?;
    match s.recv()? {
        Message::RenewOk => Ok(r),
        m => bail!("unexpected answer to RenewDone: {}", crate::name(&m)),
    }
}
