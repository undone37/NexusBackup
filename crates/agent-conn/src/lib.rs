//! Appliance side of the Linux agent protocol (docs/agent-protocol.md):
//! appliance CA, enrollment, mTLS sessions, file-level backup into
//! `Index::Tree` snapshots (`host-<agent-id>`) with the plain→keyed chunk
//! mapping index, restore to a path on the agent (from any file-tree snapshot of
//! the tenant, or VM/CT files through a tar), file downloads from tree
//! snapshots and signed agent self-updates. CLI: `nexus-agentctl` (spawned by
//! the scheduler like `nexus-pve`).

pub mod backup;
pub mod ca;
pub mod edge;
pub mod enroll;
pub mod files;
pub mod fleet;
pub mod map;
pub mod poll;
pub mod renew;
pub mod rescue;
pub mod restore;
pub mod tarbridge;
pub mod tls;
pub mod update;

use agent_proto::Message;

/// Agent ids are chosen by the web-api: 16 lowercase hex characters.
pub fn valid_agent_id(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Snapshot source of an agent.
pub fn source_name(agent_id: &str) -> String {
    format!("host-{agent_id}")
}

/// Index name inside a host snapshot.
pub const TREE_INDEX: &str = "tree";

/// Variant name for error messages (never the payload).
pub fn name(m: &Message) -> &'static str {
    match m {
        Message::Enroll { .. } => "Enroll",
        Message::EnrollReply { .. } => "EnrollReply",
        Message::EnrollDone { .. } => "EnrollDone",
        Message::Hello { .. } => "Hello",
        Message::HelloReply { .. } => "HelloReply",
        Message::ListVolumes => "ListVolumes",
        Message::Volumes { .. } => "Volumes",
        Message::Prepare { .. } => "Prepare",
        Message::Prepared { .. } => "Prepared",
        Message::Scan { .. } => "Scan",
        Message::Entries { .. } => "Entries",
        Message::ScanDone { .. } => "ScanDone",
        Message::Want { .. } => "Want",
        Message::Chunk { .. } => "Chunk",
        Message::WantLz4 { .. } => "WantLz4",
        Message::ChunkLz4 { .. } => "ChunkLz4",
        Message::RestoreChunkLz4 { .. } => "RestoreChunkLz4",
        Message::WantDone => "WantDone",
        Message::Release { .. } => "Release",
        Message::Released { .. } => "Released",
        Message::RestoreBegin { .. } => "RestoreBegin",
        Message::RestoreReady => "RestoreReady",
        Message::RestoreEntries { .. } => "RestoreEntries",
        Message::RestoreChunk { .. } => "RestoreChunk",
        Message::RestoreEnd => "RestoreEnd",
        Message::RestoreDone { .. } => "RestoreDone",
        Message::Update { .. } => "Update",
        Message::UpdateDone => "UpdateDone",
        Message::Error { .. } => "Error",
        Message::Writers { .. } => "Writers",
        Message::WritersReport { .. } => "WritersReport",
        Message::PrepareEx { .. } => "PrepareEx",
        Message::RenewCert => "RenewCert",
        Message::RenewCsr { .. } => "RenewCsr",
        Message::RenewDone { .. } => "RenewDone",
        Message::RenewOk => "RenewOk",
        Message::FleetProbe { .. } => "FleetProbe",
        Message::FleetInfo { .. } => "FleetInfo",
        Message::SessionSummary { .. } => "SessionSummary",
        Message::SummaryAck { .. } => "SummaryAck",
        Message::Poll { .. } => "Poll",
        Message::PollReply { .. } => "PollReply",
        Message::GetLayout => "GetLayout",
        Message::Layout { .. } => "Layout",
        Message::RescueApply { .. } => "RescueApply",
        Message::RescueFinish { .. } => "RescueFinish",
        Message::RescueDone { .. } => "RescueDone",
        Message::SetEdge { .. } => "SetEdge",
        Message::EdgeSet => "EdgeSet",
        Message::UpdateBegin { .. } => "UpdateBegin",
        Message::UpdateReady => "UpdateReady",
        Message::UpdateChunk { .. } => "UpdateChunk",
        Message::UpdateCommit { .. } => "UpdateCommit",
        Message::UpdateStaged => "UpdateStaged",
        Message::UpdateStatus => "UpdateStatus",
        Message::UpdateState { .. } => "UpdateState",
        Message::ScanHashed { .. } => "ScanHashed",
        Message::EntryHashes { .. } => "EntryHashes",
        Message::BlockScan { .. } => "BlockScan",
        Message::BlockHashes { .. } => "BlockHashes",
        Message::BlockScanDone { .. } => "BlockScanDone",
    }
}

/// Paths in entries and requests: relative to the host's `/`, raw bytes,
/// components separated by `/`, never empty, `.` or `..`, no NUL.
pub fn valid_rel_path(p: &[u8]) -> bool {
    !p.is_empty()
        && !p.contains(&0)
        && p.split(|b| *b == b'/')
            .all(|c| !c.is_empty() && c != b"." && c != b"..")
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}
