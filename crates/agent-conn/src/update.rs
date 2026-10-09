//! Signed self-update of an agent: the appliance only transports the binary
//! and its cosign blob signature from the update directory; the agent checks
//! the signature against its pinned release key before replacing itself.
//!
//! Update directory: `nexus-agent` (binary), `nexus-agent.sig` (signature),
//! `nexus-agent.version` (version string).

use crate::tls::Session;
use agent_proto::{Message, MAX_FRAME};
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;

pub struct Bundle {
    pub version: String,
    pub binary: Vec<u8>,
    pub signature: Vec<u8>,
}

pub fn load(dir: &Path) -> Result<Bundle> {
    let rd = |n: &str| fs::read(dir.join(n)).with_context(|| format!("{}", dir.join(n).display()));
    let b = Bundle {
        version: String::from_utf8(rd("nexus-agent.version")?)?.trim().to_owned(),
        binary: rd("nexus-agent")?,
        signature: rd("nexus-agent.sig")?,
    };
    if b.version.is_empty() || b.version.len() > 64 || !b.version.bytes().all(|c| c.is_ascii_graphic()) {
        bail!("invalid version in nexus-agent.version");
    }
    if b.signature.is_empty() || b.signature.len() > 64 << 10 {
        bail!("nexus-agent.sig: missing or too large");
    }
    // one frame carries the whole binary (agent-proto: Update { binary })
    if b.binary.len() + b.signature.len() + 1024 > MAX_FRAME {
        bail!(
            "agent binary of {} bytes does not fit into one protocol frame ({} bytes)",
            b.binary.len(),
            MAX_FRAME
        );
    }
    Ok(b)
}

pub fn push(s: &mut Session, b: &Bundle) -> Result<()> {
    s.send(&Message::Update {
        version: b.version.clone(),
        binary: b.binary.clone(),
        signature: b.signature.clone(),
    })?;
    match s.recv()? {
        Message::UpdateDone => Ok(()),
        m => bail!("unexpected answer to Update: {}", crate::name(&m)),
    }
}
