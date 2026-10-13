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

// ------------------------------------------------------------------ v1.8 (Phase 27)

use agent_core::releases::Release;
use agent_proto::release::{Artifact, HostFacts};
use agent_proto::CAP_UPDATE2;
use sha2::{Digest, Sha256};
use std::io::Read;

/// Bytes per `UpdateChunk` (the frame limit allows 4 MiB; 1 MiB keeps the agent's
/// memory flat and progress visible).
pub const CHUNK: usize = 1 << 20;

/// What `update` will send to one agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// v1.8 agent: these artifacts of the release (the agent's own last)
    Chunked(Vec<Artifact>),
    /// agent before v1.8: the release's binary in one `Update` frame
    Legacy(Artifact),
}

/// Picks what to send: the host's own install type for v1.8 agents; agents before
/// v1.8 only take a binary in one frame (bundles; Windows manual installs).
pub fn plan(release: &Release, host: &HostFacts, caps: &[String]) -> Result<Plan> {
    let m = release
        .manifest
        .as_ref()
        .filter(|_| release.usable())
        .with_context(|| {
            format!(
                "release {} is not usable: {}",
                release.version,
                release.error.clone().unwrap_or_default()
            )
        })?;
    if caps.iter().any(|c| c == CAP_UPDATE2) {
        let arts: Vec<Artifact> = m.select(host).into_iter().cloned().collect();
        if arts.is_empty() {
            bail!(
                "release {} has nothing for {} {} ({} install)",
                m.version,
                host.os,
                host.arch,
                host.install
            );
        }
        return Ok(Plan::Chunked(arts));
    }
    let bin = m
        .artifacts
        .iter()
        .find(|a| a.kind == agent_proto::release::KIND_BINARY && a.os == host.os && a.arch == host.arch)
        .with_context(|| format!("release {} has no {} {} binary", m.version, host.os, host.arch))?;
    if bin.size as usize + 64 * 1024 > MAX_FRAME {
        bail!(
            "the agent (protocol before v1.8) takes the binary in one frame; {} bytes do not fit (update it by hand once)",
            bin.size
        );
    }
    Ok(Plan::Legacy(bin.clone()))
}

/// Sends the planned artifacts; `progress(sent, total)` after each chunk.
pub fn push_release(
    s: &mut Session,
    release: &Release,
    plan: &Plan,
    rollback: bool,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<()> {
    match plan {
        Plan::Legacy(a) => {
            if rollback {
                bail!("agents before protocol v1.8 cannot be rolled back in-band");
            }
            let b = Bundle {
                version: a.version.clone(),
                binary: fs::read(release.path_of(a)).with_context(|| a.name.clone())?,
                signature: release.signature_of(a).with_context(|| format!("{}.sig", a.name))?,
            };
            push(s, &b)
        }
        Plan::Chunked(arts) => {
            let total: u64 = arts.iter().map(|a| a.size).sum();
            let mut sent = 0u64;
            for (i, a) in arts.iter().enumerate() {
                let last = i + 1 == arts.len();
                let path = release.path_of(a);
                let mut f = fs::File::open(&path).with_context(|| path.display().to_string())?;
                let sha: [u8; 32] = {
                    let mut h = Sha256::new();
                    std::io::copy(&mut fs::File::open(&path)?, &mut h)?;
                    h.finalize().into()
                };
                if agent_proto::release::hex(&sha) != a.sha256 {
                    bail!("{}: SHA-256 differs from the manifest (store damaged?)", a.name);
                }
                s.send(&Message::UpdateBegin {
                    kind: a.kind.clone(),
                    name: a.name.clone(),
                    size: a.size,
                    sha256: sha,
                    signature: release.signature_of(a).with_context(|| format!("{}.sig", a.name))?,
                    manifest: release.manifest_bytes.clone(),
                    manifest_sig: release.manifest_sig.clone(),
                    rollback,
                })?;
                match s.recv()? {
                    Message::UpdateReady => {}
                    m => bail!("unexpected answer to UpdateBegin: {}", crate::name(&m)),
                }
                let mut buf = vec![0u8; CHUNK];
                let mut n_file = 0u64;
                loop {
                    let n = read_full(&mut f, &mut buf)?;
                    if n == 0 {
                        break;
                    }
                    s.send(&Message::UpdateChunk {
                        data: buf[..n].to_vec(),
                    })?;
                    n_file += n as u64;
                    sent += n as u64;
                    progress(sent, total);
                }
                if n_file != a.size {
                    bail!("{}: {} bytes read, the manifest says {}", a.name, n_file, a.size);
                }
                s.send(&Message::UpdateCommit { apply: last })?;
                match (s.recv()?, last) {
                    (Message::UpdateStaged, false) | (Message::UpdateDone, true) => {}
                    (m, _) => bail!("unexpected answer to UpdateCommit: {}", crate::name(&m)),
                }
            }
            Ok(())
        }
    }
}

fn read_full(f: &mut fs::File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match f.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

/// The agent's update state (`UpdateStatus`, v1.8); `{}` for older agents.
pub fn status(s: &mut Session) -> Result<serde_json::Value> {
    if !s.has_cap(CAP_UPDATE2) {
        return Ok(serde_json::json!({}));
    }
    s.send(&Message::UpdateStatus)?;
    match s.recv()? {
        Message::UpdateState { json } => Ok(serde_json::from_str(&json).unwrap_or_else(|_| serde_json::json!({}))),
        m => bail!("unexpected answer to UpdateStatus: {}", crate::name(&m)),
    }
}

/// Seconds the reconnect check waits for the new version: package installs run a
/// package manager first, binary swaps only restart.
pub fn reconnect_secs(plan: &Plan) -> u64 {
    match plan {
        Plan::Chunked(a) if a.iter().any(|a| a.kind != agent_proto::release::KIND_BINARY) => 600,
        _ => 120,
    }
}
