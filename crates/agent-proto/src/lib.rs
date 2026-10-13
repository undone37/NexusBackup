//! Wire protocol between the appliance and `nexus-agent` (docs/agent-protocol.md).
//! Framing: `u32 BE length | postcard(Message)`, max `MAX_FRAME`.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io::{self, Read, Write};

pub mod edge;
pub mod layout;
pub mod release;

pub const VERSION: u32 = 1;
pub const DEFAULT_PORT: u16 = 7444;
pub const ALPN: &[u8] = b"nexus-agent/1";
pub const MAX_FRAME: usize = 8 << 20;
pub const MAX_CHUNK: usize = 4 << 20;
pub const MAX_BATCH: usize = 10_000;
pub const MAX_PATH: usize = 4096;
pub const MAX_XATTR: usize = 64 << 10;
/// include roots / regexes / file system types per `PrepareEx` (each)
pub const MAX_FILTERS: usize = 256;
pub const CDC_MIN: u32 = 128 << 10;
pub const CDC_AVG: u32 = 512 << 10;
pub const CDC_MAX: u32 = 4 << 20;
pub const EXPORTER_LABEL: &[u8] = b"nexus-agent enroll";

/// Plain (unkeyed) BLAKE3 of a chunk; mapped to keyed IDs only on the appliance.
pub type Hash = [u8; 32];

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotKind {
    Lvm,
    Zfs,
    Btrfs,
    None,
    /// Windows Volume Shadow Copy (appended in v1.1, additive)
    Vss,
}

/// One VSS writer's part in a Windows backup (`WritersReport`, additive in v1.1).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct VssWriter {
    /// writer name, e.g. "SqlServerWriter", "Microsoft Exchange Writer", "NTDS"
    pub name: String,
    /// writer class id (GUID, `{...}`)
    pub class_id: String,
    /// instance name ("" if none)
    pub instance: String,
    /// writer components were added to the backup (the writer was asked to freeze)
    pub participated: bool,
    /// final state after `BackupComplete`, e.g. "stable", "failed_at_prepare_snapshot"
    pub state: String,
    /// writer failure HRESULT as hex text ("" = none) and VSS error name
    pub failure: String,
    /// true for SQL Server / Exchange / AD writers (the UI warns if they did not take part)
    pub application: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Volume {
    pub mountpoint: String,
    pub device: String,
    pub fstype: String,
    pub snapshot: SnapshotKind,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SnapshotInfo {
    pub mountpoint: String,
    pub kind: SnapshotKind,
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
    Hardlink,
    Device,
    Fifo,
    Socket,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Entry {
    /// relative to the volume root, raw bytes (not necessarily UTF-8)
    pub path: Vec<u8>,
    pub kind: Kind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    pub inode: u64,
    pub rdev: u64,
    /// symlink target or hardlink target path
    pub link_target: Option<Vec<u8>>,
    pub xattrs: Vec<(Vec<u8>, Vec<u8>)>,
    pub chunks: Vec<(Hash, u32)>,
    pub unchanged: bool,
    pub inconsistent: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct ScanStats {
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    pub read_bytes: u64,
    pub unchanged: u64,
    pub inconsistent: u64,
    pub errors: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BaseRef {
    /// appliance snapshot time of the previous successful backup of this agent
    pub time: u64,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Overwrite {
    Never,
    IfOlder,
    Always,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Message {
    // enrollment (agent in enrollment mode, self-signed cert)
    Enroll {
        proof: [u8; 32],
    },
    EnrollReply {
        proof: [u8; 32],
        csr_pem: String,
    },
    EnrollDone {
        cert_pem: String,
        ca_pem: String,
        agent_id: String,
    },
    // session
    Hello {
        version: u32,
    },
    HelloReply {
        version: u32,
        agent_id: String,
        os: String,
        kernel: String,
        hostname: String,
        agent_version: String,
        caps: Vec<String>,
    },
    ListVolumes,
    Volumes {
        list: Vec<Volume>,
    },
    Prepare {
        job: u64,
        paths: Vec<String>,
        excludes: Vec<String>,
        hooks: bool,
    },
    Prepared {
        job: u64,
        snapshots: Vec<SnapshotInfo>,
        consistent: bool,
        hook_log: String,
    },
    Scan {
        job: u64,
        base: Option<BaseRef>,
    },
    Entries {
        batch: Vec<Entry>,
    },
    ScanDone {
        stats: ScanStats,
    },
    Want {
        job: u64,
        hashes: Vec<Hash>,
    },
    Chunk {
        hash: Hash,
        data: Vec<u8>,
    },
    WantDone,
    Release {
        job: u64,
        success: bool,
    },
    Released {
        job: u64,
        hook_log: String,
    },
    RestoreBegin {
        job: u64,
        target: String,
        overwrite: Overwrite,
        confirm: String,
    },
    RestoreReady,
    RestoreEntries {
        batch: Vec<Entry>,
    },
    RestoreChunk {
        hash: Hash,
        data: Vec<u8>,
    },
    RestoreEnd,
    RestoreDone {
        stats: ScanStats,
    },
    Update {
        version: String,
        binary: Vec<u8>,
        signature: Vec<u8>,
    },
    UpdateDone,
    Error {
        code: u32,
        message: String,
    },
    // --- v1.1, appended (old peers never send/receive these) ---
    /// Appliance → agent after `Prepared`, only if `HelloReply.caps` contains
    /// `"vss-writers"`: which VSS writers took part in the job's snapshot.
    Writers {
        job: u64,
    },
    WritersReport {
        job: u64,
        writers: Vec<VssWriter>,
    },
    // --- v1.2, appended: LZ4 on the wire (only if HelloReply.caps contains CAP_LZ4) ---
    /// Like `Want`, but the agent may answer with `ChunkLz4` for compressible chunks.
    WantLz4 {
        job: u64,
        hashes: Vec<Hash>,
    },
    /// LZ4 block of a chunk; `hash`/`raw_len` describe the uncompressed data.
    ChunkLz4 {
        hash: Hash,
        raw_len: u32,
        data: Vec<u8>,
    },
    /// Restore direction, appliance → agent (agent advertised CAP_LZ4).
    RestoreChunkLz4 {
        hash: Hash,
        raw_len: u32,
        data: Vec<u8>,
    },
    // --- v1.3, appended: file filters + limits, certificate renewal ---
    /// `Prepare` with the full filter set and the appliance-side limits (only if
    /// `HelloReply.caps` contains CAP_PREPARE2; old agents get `Prepare` with the
    /// globs only). Answered with `Prepared`.
    PrepareEx {
        job: u64,
        paths: Vec<String>,
        excludes: Vec<String>,
        hooks: bool,
        filters: Filters,
        limits: Limits,
    },
    /// Appliance → agent (CAP_RENEW): generate a new key pair, answer `RenewCsr`.
    RenewCert,
    RenewCsr {
        csr_pem: String,
    },
    /// The certificate issued for the `RenewCsr` key (same CN, same CA). The agent
    /// checks it, swaps key + certificate atomically and answers `RenewOk`; new
    /// connections use the new identity.
    RenewDone {
        cert_pem: String,
        ca_pem: String,
    },
    RenewOk,
    // --- v1.4, appended: endpoint status (only if HelloReply.caps contains CAP_POLL) ---
    /// Appliance → agent after a backup / restore session ended: its summary for the
    /// endpoint UI, the next scheduled run and the per-agent UI policy. Answered with
    /// `SummaryAck`; the agent keeps the last 100 summaries.
    SessionSummary {
        summary: Summary,
        status: ApplianceStatus,
    },
    SummaryAck {
        job: u64,
    },
    /// Appliance → agent every few minutes (short session): the current appliance view,
    /// and `ack` = ids of earlier `BackupRequest`s the appliance has acted on (the agent
    /// drops them). Answered with `PollReply`.
    Poll {
        status: ApplianceStatus,
        ack: Vec<String>,
    },
    PollReply {
        /// "back up now" requests queued by local users, not yet acknowledged
        requests: Vec<BackupRequest>,
        power: PowerState,
        /// `ApplianceStatus::policy_version` the agent stored
        policy_version: u32,
        /// a backup session is active on the agent right now
        busy: bool,
    },
    // --- v1.5, appended: fleet enrollment (docs/agent-protocol.md "v1.5"); sent in
    // enrollment mode, before any Hello, so there is no capability to announce ---
    /// Appliance → agent in enrollment mode, instead of `Enroll`: a scan for agents
    /// initialised with a fleet secret. `proof` = [`enroll_proof`] of the fleet secret
    /// digest with role `"fleet-appliance"`. Old agents fail to decode it (no failure
    /// counted); agents of another fleet answer `Error` without counting a failure.
    FleetProbe {
        fleet_id: String,
        proof: [u8; 32],
    },
    /// The agent's answer: its proof (role `"fleet-agent"`) and what the admin sees
    /// before accepting it. The session ends here; enrollment is a later `Enroll`.
    FleetInfo {
        proof: [u8; 32],
        hostname: String,
        os: String,
        agent_version: String,
    },
    // --- v1.6, appended: machine layout + bare-metal recovery (docs/bmr.md) ---
    /// Appliance → agent (CAP_LAYOUT), at the start of a backup: the machine layout.
    GetLayout,
    /// [`layout::Layout`] as JSON (at most `MAX_LAYOUT` bytes).
    Layout {
        json: String,
    },
    /// Appliance → rescue agent (CAP_RESCUE): recreate partitions, LVM, file systems
    /// and swap of `layout` (JSON) on the disks confirmed at the rescue console and
    /// mount them below the restore target. Answered with `RescueDone`.
    RescueApply {
        job: u64,
        layout: String,
    },
    /// Appliance → rescue agent after the restore: fix up the restored system
    /// (`/etc/fstab` UUIDs, boot loader, initramfs), unmount; `reboot` after the answer.
    RescueFinish {
        job: u64,
        reboot: bool,
    },
    /// Answer to `RescueApply` / `RescueFinish`: what was done (one step per line);
    /// `target` = where the file systems are mounted (the restore target).
    RescueDone {
        job: u64,
        target: String,
        log: String,
    },
    /// v1.7 (CAP_EDGE), appliance → agent: keep a rendezvous connection to this edge
    /// proxy (`addr` = `host:port`, `cert_sha256` = pinned edge certificate); an empty
    /// `addr` removes it. `agent.conf` (`edge`, `edge_sha256`) takes precedence.
    SetEdge {
        addr: String,
        cert_sha256: String,
    },
    /// Answer to `SetEdge`.
    EdgeSet,
    // --- v1.8, appended: chunked updates and package installs (CAP_UPDATE2,
    // docs/agent-update-plan.md "Implementation") ---
    /// Appliance → agent: one artifact of a signed release follows in `UpdateChunk`s.
    /// `kind` / `name` as in the release manifest; `signature` = cosign blob signature
    /// of the artifact; `manifest` + `manifest_sig` = the signed `manifest.json`.
    /// Answered with `UpdateReady` or `Error` (refused before any data is sent).
    UpdateBegin {
        kind: String,
        name: String,
        size: u64,
        sha256: [u8; 32],
        signature: Vec<u8>,
        manifest: Vec<u8>,
        manifest_sig: Vec<u8>,
        /// an approved rollback to an older release (see `agent_core::update::ROLLBACK_FLOOR`)
        rollback: bool,
    },
    UpdateReady,
    /// The next piece of the artifact announced by `UpdateBegin` (no answer).
    UpdateChunk {
        data: Vec<u8>,
    },
    /// End of the artifact: the agent checks it; `apply = false` stages it (answer
    /// `UpdateStaged`, more artifacts follow), `apply = true` installs everything staged
    /// (answer `UpdateDone`, or `Error`).
    UpdateCommit {
        apply: bool,
    },
    UpdateStaged,
    /// Appliance → agent: the agent's update state (`update-state.json`).
    UpdateStatus,
    /// `json` = `{state, kind, from, to, at, error, log}` or `{}` when no update ran.
    UpdateState {
        json: String,
    },
}

/// Capability: the agent understands `UpdateBegin` / `UpdateChunk` / `UpdateCommit` /
/// `UpdateStatus` (v1.8) and reports its host facts as `arch=`, `install=`, `gui=` caps
/// ([`release::HostFacts`]).
pub const CAP_UPDATE2: &str = "update2";
/// Largest update artifact accepted (MSI with the desktop UI stays far below).
pub const MAX_UPDATE: u64 = 512 << 20;
/// Largest signature / manifest / state document in update messages.
pub const MAX_SIGNATURE: usize = 64 << 10;
pub const MAX_MANIFEST: usize = 256 << 10;
pub const MAX_UPDATE_STATE: usize = 16 << 10;
pub const MAX_ARTIFACT_NAME: usize = 200;

/// Capability: the agent understands `SetEdge` and keeps an edge rendezvous (v1.7).
pub const CAP_EDGE: &str = "edge";

/// Capability: the agent understands `SessionSummary` and `Poll` (v1.4).
pub const CAP_POLL: &str = "poll";
/// Longest `Summary::log_tail` (lines) and line length (bytes) accepted.
pub const MAX_LOG_TAIL: usize = 200;
pub const MAX_LOG_LINE: usize = 1024;
/// At most this many requests in one `PollReply`.
pub const MAX_REQUESTS: usize = 16;
/// Longest free-text field (names, header, errors) accepted in v1.4 messages.
pub const MAX_TEXT: usize = 256;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionKind {
    Backup,
    Restore,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionResult {
    Success,
    Warning,
    Failed,
    Cancelled,
}

/// One finished backup / restore session of this agent (times: Unix seconds).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Summary {
    /// appliance job id
    pub job: u64,
    pub kind: SessionKind,
    pub started: u64,
    pub ended: u64,
    pub result: SessionResult,
    pub read_bytes: u64,
    pub transferred_bytes: u64,
    pub new_bytes: u64,
    pub warnings: u32,
    /// "" = none
    pub first_error: String,
    pub snapshot_time: Option<u64>,
    /// the session's job log lines (as shown to operators), last ≤ MAX_LOG_TAIL
    pub log_tail: Vec<String>,
}

/// Branding / visibility of the endpoint UIs, set per agent by an administrator.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct UiPolicy {
    /// `#rrggbb` or ""
    pub accent: String,
    /// "" = product name
    pub header: String,
    pub hide_backup_now: bool,
    pub hide_tray: bool,
}

/// What the appliance tells the agent with every summary and poll.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct ApplianceStatus {
    /// appliance display name ("managed by")
    pub appliance: String,
    pub now: u64,
    pub next_run: Option<u64>,
    pub ui_policy: UiPolicy,
    pub policy_version: u32,
}

/// A "back up now" request queued on the agent by a local user.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BackupRequest {
    /// random hex, ≤ 64 characters
    pub id: String,
    pub queued_at: u64,
}

/// Power and network state of the agent host (laptops). `None` = unknown.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct PowerState {
    pub on_battery: Option<bool>,
    pub battery_percent: Option<u8>,
    pub metered: Option<bool>,
    pub network_name: Option<String>,
}

/// Capability: the peer understands `WantLz4` / `ChunkLz4` / `RestoreChunkLz4`.
pub const CAP_LZ4: &str = "lz4";
/// Capability: the agent understands `PrepareEx` (include roots, regex excludes,
/// nested mounts by file system type, bandwidth / CPU limits).
pub const CAP_PREPARE2: &str = "prepare2";
/// Capability: the agent renews its certificate over the session (`RenewCert`).
pub const CAP_RENEW: &str = "cert-renew";
/// Capability: the agent answers `GetLayout` (Linux agents since v1.6).
pub const CAP_LAYOUT: &str = "layout";
/// Capability: a rescue agent (rescue ISO) that takes `RescueApply` / `RescueFinish`.
pub const CAP_RESCUE: &str = "rescue";
/// Largest layout JSON accepted (a machine with hundreds of LVs stays far below).
pub const MAX_LAYOUT: usize = 1 << 20;

/// File selection beyond the glob `excludes` of `Prepare` (docs/agent-protocol.md
/// "Filters"). Precedence: excluded (glob or regex) wins over included.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Filters {
    /// whitelist roots (absolute host paths): if not empty, only entries inside one
    /// of them (and the directories leading to them) are backed up
    pub include: Vec<String>,
    /// regular expressions matched against the absolute host path (`/`-separated)
    pub exclude_regex: Vec<String>,
    /// back up file systems mounted below the requested paths (each from its own
    /// snapshot), except the types in `skip_fstypes`
    pub cross_mounts: bool,
    /// file system types never descended into when `cross_mounts` is set (empty =
    /// the agent's default list: proc, sysfs, tmpfs, overlay, nfs, cifs, …)
    pub skip_fstypes: Vec<String>,
}

/// Appliance-side limits for one job, enforced by the agent.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Default)]
pub struct Limits {
    /// bytes per second for chunk data sent to the appliance (0 = unlimited)
    pub bwlimit: u64,
    /// CPU / I/O priority of the job: 0 = normal, 1..=19 = nicer (Linux nice +
    /// best-effort I/O class; Windows background mode for any value > 0)
    pub nice: u8,
}

/// LZ4-compresses a chunk for the wire if that saves at least 10 %; `None` =
/// send it raw (already compressed/encrypted data costs only one fast attempt).
pub fn lz4_pack(data: &[u8]) -> Option<Vec<u8>> {
    let c = lz4_flex::block::compress(data);
    (c.len() < data.len() - data.len() / 10).then_some(c)
}

/// Decompresses a wire chunk. The output size is fixed by `raw_len` (bounded by
/// `check` to MAX_CHUNK), so a hostile peer cannot inflate memory use.
pub fn lz4_unpack(data: &[u8], raw_len: u32) -> io::Result<Vec<u8>> {
    let out = lz4_flex::block::decompress(data, raw_len as usize).map_err(|e| bad(format!("lz4: {e}")))?;
    if out.len() != raw_len as usize {
        return Err(bad("lz4: decompressed size differs from raw_len"));
    }
    Ok(out)
}

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

pub fn write_msg(w: &mut impl Write, m: &Message) -> io::Result<()> {
    let body = postcard::to_stdvec(m).map_err(|e| bad(format!("encode: {e}")))?;
    if body.len() > MAX_FRAME {
        return Err(bad("frame too large"));
    }
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

pub fn read_msg(r: &mut impl Read) -> io::Result<Message> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(bad(format!("frame of {len} bytes exceeds the limit")));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    let m: Message = postcard::from_bytes(&body).map_err(|e| bad(format!("decode: {e}")))?;
    check(&m)?;
    Ok(m)
}

/// Structural limits every receiver enforces (docs/agent-protocol.md "Limits").
pub fn check(m: &Message) -> io::Result<()> {
    let entries = match m {
        Message::Entries { batch } | Message::RestoreEntries { batch } => batch.as_slice(),
        Message::Chunk { data, .. } | Message::RestoreChunk { data, .. } if data.len() > MAX_CHUNK => {
            return Err(bad("chunk too large"))
        }
        Message::ChunkLz4 { raw_len, data, .. } | Message::RestoreChunkLz4 { raw_len, data, .. }
            if *raw_len as usize > MAX_CHUNK || data.len() > MAX_CHUNK =>
        {
            return Err(bad("chunk too large"))
        }
        Message::Want { hashes, .. } | Message::WantLz4 { hashes, .. } if hashes.len() > MAX_BATCH => {
            return Err(bad("want list too long"))
        }
        Message::PrepareEx { filters: f, .. }
            if f.include.len() > MAX_FILTERS
                || f.exclude_regex.len() > MAX_FILTERS
                || f.skip_fstypes.len() > MAX_FILTERS
                || f.include.iter().chain(&f.exclude_regex).any(|p| p.len() > MAX_PATH) =>
        {
            return Err(bad("filters exceed limits"))
        }
        Message::Layout { json } | Message::RescueApply { layout: json, .. } if json.len() > MAX_LAYOUT => {
            return Err(bad("layout too large"))
        }
        Message::SetEdge { addr, cert_sha256 } if addr.len() > MAX_TEXT || cert_sha256.len() > 64 => {
            return Err(bad("edge setting exceeds limits"))
        }
        Message::UpdateBegin {
            kind,
            name,
            size,
            signature,
            manifest,
            manifest_sig,
            ..
        } if kind.len() > 32
            || name.len() > MAX_ARTIFACT_NAME
            || *size > MAX_UPDATE
            || signature.len() > MAX_SIGNATURE
            || manifest_sig.len() > MAX_SIGNATURE
            || manifest.len() > MAX_MANIFEST =>
        {
            return Err(bad("update exceeds limits"))
        }
        Message::UpdateChunk { data } if data.len() > MAX_CHUNK => return Err(bad("update chunk too large")),
        Message::UpdateState { json } if json.len() > MAX_UPDATE_STATE => {
            return Err(bad("update state too large"))
        }
        Message::SessionSummary { summary, status } => {
            let s = summary;
            if s.log_tail.len() > MAX_LOG_TAIL
                || s.log_tail.iter().any(|l| l.len() > MAX_LOG_LINE)
                || s.first_error.len() > MAX_LOG_LINE
                || !status_ok(status)
            {
                return Err(bad("session summary exceeds limits"));
            }
            return Ok(());
        }
        Message::Poll { status, ack } => {
            if ack.len() > MAX_REQUESTS || ack.iter().any(|a| a.len() > 64) || !status_ok(status) {
                return Err(bad("poll exceeds limits"));
            }
            return Ok(());
        }
        Message::PollReply { requests, power, .. } => {
            if requests.len() > MAX_REQUESTS
                || requests.iter().any(|r| r.id.len() > 64)
                || power.network_name.as_ref().is_some_and(|n| n.len() > MAX_TEXT)
            {
                return Err(bad("poll reply exceeds limits"));
            }
            return Ok(());
        }
        _ => return Ok(()),
    };
    if entries.len() > MAX_BATCH {
        return Err(bad("batch too large"));
    }
    for e in entries {
        let xattrs: usize = e.xattrs.iter().map(|(k, v)| k.len() + v.len()).sum();
        if e.path.len() > MAX_PATH || e.link_target.as_ref().is_some_and(|t| t.len() > MAX_PATH) || xattrs > MAX_XATTR {
            return Err(bad("entry exceeds limits"));
        }
        if e.chunks.iter().any(|(_, l)| *l as usize > MAX_CHUNK) {
            return Err(bad("chunk length exceeds limit"));
        }
    }
    Ok(())
}

fn status_ok(s: &ApplianceStatus) -> bool {
    s.appliance.len() <= MAX_TEXT && s.ui_policy.header.len() <= MAX_TEXT && s.ui_policy.accent.len() <= 16
}

/// Enrollment proof bound to one TLS session (`exporter` = TLS keying material
/// exported with `EXPORTER_LABEL`, 32 bytes). `role` is "appliance" or "agent".
pub fn enroll_proof(token: &str, role: &str, exporter: &[u8; 32]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(token.trim().as_bytes()).expect("hmac accepts any key");
    mac.update(role.as_bytes());
    mac.update(b"\0");
    mac.update(exporter);
    mac.finalize().into_bytes().into()
}

/// What both sides keep of the one-time enrollment token and use as the
/// `token` argument of [`enroll_proof`]: lowercase hex SHA-256 of the trimmed
/// token. The agent stores only this (`/etc/nexus-agent/token`), the appliance
/// stores it sealed to its scheduler; the plaintext token exists only in the
/// install command shown once.
pub fn token_digest(token: &str) -> String {
    use sha2::Digest;
    Sha256::digest(token.trim().as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Public lookup key of a recovery token (docs/bmr.md "Recovery token"): the rescue
/// console sends it with its check-in, the appliance stores it in clear to find the
/// session. It reveals nothing about the token digest the enrollment proofs use.
pub fn rescue_lookup(token: &str) -> String {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(b"nexus-rescue-lookup\0");
    h.update(token_digest(token).as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Fleet secrets (`nxf1.<fleet id: 16 hex>.<secret>`): the fleet id, if `s` is one.
/// The id is not secret (it only lets an agent tell fleets apart); the whole string
/// is, and both sides use its [`token_digest`] like an enrollment token's.
pub fn fleet_id(s: &str) -> Option<&str> {
    let mut it = s.trim().splitn(3, '.');
    let (Some("nxf1"), Some(id), Some(rest)) = (it.next(), it.next(), it.next()) else {
        return None;
    };
    (id.len() == 16
        && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        && rest.len() >= 16
        && rest.bytes().all(|b| b.is_ascii_alphanumeric()))
    .then_some(id)
}

/// Constant-time comparison of two proofs.
pub fn proof_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Entry {
        Entry {
            path: b"etc/passwd".to_vec(),
            kind: Kind::File,
            mode: 0o644,
            uid: 0,
            gid: 0,
            size: 3,
            mtime_ns: 1,
            ctime_ns: 2,
            inode: 3,
            rdev: 0,
            link_target: None,
            xattrs: vec![(
                b"security.selinux".to_vec(),
                b"system_u:object_r:passwd_file_t:s0".to_vec(),
            )],
            chunks: vec![(*blake3::hash(b"abc").as_bytes(), 3)],
            unchanged: false,
            inconsistent: false,
        }
    }

    #[test]
    fn framing_roundtrip_and_limits() {
        let mut buf = Vec::new();
        let m = Message::Entries { batch: vec![entry()] };
        write_msg(&mut buf, &m).unwrap();
        assert_eq!(read_msg(&mut &buf[..]).unwrap(), m);
        // oversized length prefix is refused before allocating
        let mut big = ((MAX_FRAME + 1) as u32).to_be_bytes().to_vec();
        big.extend([0u8; 16]);
        assert!(read_msg(&mut &big[..]).is_err());
        let mut long = entry();
        long.path = vec![b'a'; MAX_PATH + 1];
        let mut buf = Vec::new();
        write_msg(&mut buf, &Message::Entries { batch: vec![long] }).unwrap();
        assert!(read_msg(&mut &buf[..]).is_err(), "receiver enforces path limit");
        let mut buf = Vec::new();
        write_msg(
            &mut buf,
            &Message::Chunk {
                hash: [0; 32],
                data: vec![0; MAX_CHUNK + 1],
            },
        )
        .unwrap();
        assert!(read_msg(&mut &buf[..]).is_err());
    }

    #[test]
    fn appended_variants_keep_old_encodings() {
        // v1 tags must not move: Error is still the last v1 variant (index 25)
        let old = postcard::to_stdvec(&Message::Error {
            code: 1,
            message: String::new(),
        })
        .unwrap();
        assert_eq!(old[0], 25);
        assert_eq!(postcard::to_stdvec(&SnapshotKind::None).unwrap(), vec![3]);
        let m = Message::WritersReport {
            job: 1,
            writers: vec![VssWriter {
                name: "SqlServerWriter".into(),
                class_id: "{a65faa63-5ea8-4ebc-9dbd-a0c4db26912a}".into(),
                instance: String::new(),
                participated: true,
                state: "stable".into(),
                failure: String::new(),
                application: true,
            }],
        };
        let mut buf = Vec::new();
        write_msg(&mut buf, &m).unwrap();
        assert_eq!(read_msg(&mut &buf[..]).unwrap(), m);
    }

    #[test]
    fn v13_messages_keep_old_encodings() {
        // an old appliance's Prepare decodes unchanged; the new variants come after RestoreChunkLz4 (30)
        let old = Message::Prepare {
            job: 7,
            paths: vec!["/etc".into()],
            excludes: vec!["*.tmp".into()],
            hooks: true,
        };
        let enc = postcard::to_stdvec(&old).unwrap();
        assert_eq!(enc[0], 7);
        assert_eq!(postcard::from_bytes::<Message>(&enc).unwrap(), old);
        let ex = Message::PrepareEx {
            job: 7,
            paths: vec!["/".into()],
            excludes: vec![],
            hooks: false,
            filters: Filters {
                include: vec!["/home".into()],
                exclude_regex: vec![r"\.bak$".into()],
                cross_mounts: true,
                skip_fstypes: vec![],
            },
            limits: Limits {
                bwlimit: 1 << 20,
                nice: 10,
            },
        };
        assert_eq!(postcard::to_stdvec(&ex).unwrap()[0], 31);
        assert_eq!(postcard::to_stdvec(&Message::RenewOk).unwrap(), vec![35]);
        let probe = Message::FleetProbe {
            fleet_id: "0123456789abcdef".into(),
            proof: [1; 32],
        };
        assert_eq!(postcard::to_stdvec(&probe).unwrap()[0], 40);
        let mut buf = Vec::new();
        write_msg(&mut buf, &ex).unwrap();
        assert_eq!(read_msg(&mut &buf[..]).unwrap(), ex);
        let Message::PrepareEx { mut filters, .. } = ex else {
            unreachable!()
        };
        filters.exclude_regex = vec!["x".into(); MAX_FILTERS + 1];
        let mut buf = Vec::new();
        write_msg(
            &mut buf,
            &Message::PrepareEx {
                job: 1,
                paths: vec![],
                excludes: vec![],
                hooks: false,
                filters,
                limits: Limits::default(),
            },
        )
        .unwrap();
        assert!(read_msg(&mut &buf[..]).is_err(), "filter count limit");
    }

    #[test]
    fn v14_messages_keep_old_encodings() {
        // RenewOk stays 35; the v1.4 variants follow
        assert_eq!(postcard::to_stdvec(&Message::RenewOk).unwrap(), vec![35]);
        let status = ApplianceStatus {
            appliance: "nexus01".into(),
            now: 1_700_000_000,
            next_run: Some(1_700_003_600),
            ui_policy: UiPolicy {
                accent: "#0a7f5a".into(),
                header: "ACME IT".into(),
                hide_backup_now: false,
                hide_tray: true,
            },
            policy_version: 3,
        };
        let sum = Message::SessionSummary {
            summary: Summary {
                job: 9,
                kind: SessionKind::Backup,
                started: 1,
                ended: 2,
                result: SessionResult::Warning,
                read_bytes: 10,
                transferred_bytes: 5,
                new_bytes: 4,
                warnings: 1,
                first_error: "x".into(),
                snapshot_time: Some(2),
                log_tail: vec!["scan: 3 entries".into()],
            },
            status: status.clone(),
        };
        assert_eq!(postcard::to_stdvec(&sum).unwrap()[0], 36);
        let poll = Message::Poll {
            status,
            ack: vec!["ab".into()],
        };
        assert_eq!(postcard::to_stdvec(&poll).unwrap()[0], 38);
        let reply = Message::PollReply {
            requests: vec![BackupRequest {
                id: "ab".into(),
                queued_at: 5,
            }],
            power: PowerState {
                on_battery: Some(true),
                battery_percent: Some(55),
                metered: None,
                network_name: Some("office".into()),
            },
            policy_version: 3,
            busy: false,
        };
        for m in [sum, poll, reply, Message::SummaryAck { job: 9 }] {
            let mut buf = Vec::new();
            write_msg(&mut buf, &m).unwrap();
            assert_eq!(read_msg(&mut &buf[..]).unwrap(), m);
        }
        // limits
        let mut buf = Vec::new();
        write_msg(
            &mut buf,
            &Message::PollReply {
                requests: vec![
                    BackupRequest {
                        id: "x".into(),
                        queued_at: 0
                    };
                    MAX_REQUESTS + 1
                ],
                power: PowerState::default(),
                policy_version: 0,
                busy: false,
            },
        )
        .unwrap();
        assert!(read_msg(&mut &buf[..]).is_err());
    }

    #[test]
    fn v17_messages_are_appended() {
        let m = Message::SetEdge {
            addr: "edge.example.com:443".into(),
            cert_sha256: "ab".repeat(32),
        };
        assert_eq!(postcard::to_stdvec(&m).unwrap()[0], 47);
        assert_eq!(postcard::to_stdvec(&Message::EdgeSet).unwrap(), vec![48]);
        let mut buf = Vec::new();
        write_msg(&mut buf, &m).unwrap();
        assert_eq!(read_msg(&mut &buf[..]).unwrap(), m);
        let mut buf = Vec::new();
        write_msg(
            &mut buf,
            &Message::SetEdge {
                addr: "x".repeat(MAX_TEXT + 1),
                cert_sha256: String::new(),
            },
        )
        .unwrap();
        assert!(read_msg(&mut &buf[..]).is_err());
    }

    #[test]
    fn v18_messages_are_appended() {
        let begin = Message::UpdateBegin {
            kind: "deb".into(),
            name: "linux-x86_64/nexus-agent_0.2.0_amd64.deb".into(),
            size: 10,
            sha256: [7; 32],
            signature: b"sig".to_vec(),
            manifest: b"{}".to_vec(),
            manifest_sig: b"msig".to_vec(),
            rollback: false,
        };
        assert_eq!(postcard::to_stdvec(&begin).unwrap()[0], 49);
        assert_eq!(postcard::to_stdvec(&Message::UpdateReady).unwrap(), vec![50]);
        assert_eq!(postcard::to_stdvec(&Message::UpdateCommit { apply: true }).unwrap(), vec![52, 1]);
        assert_eq!(postcard::to_stdvec(&Message::UpdateStaged).unwrap(), vec![53]);
        assert_eq!(postcard::to_stdvec(&Message::UpdateStatus).unwrap(), vec![54]);
        // the old single-frame update keeps its tag (old agents)
        let old = Message::Update {
            version: "0.2.0".into(),
            binary: vec![1],
            signature: vec![2],
        };
        assert_eq!(postcard::to_stdvec(&old).unwrap()[0], 23);
        assert_eq!(postcard::to_stdvec(&Message::UpdateDone).unwrap(), vec![24]);
        for m in [
            begin.clone(),
            Message::UpdateChunk { data: vec![1; 100] },
            Message::UpdateState { json: "{}".into() },
        ] {
            let mut buf = Vec::new();
            write_msg(&mut buf, &m).unwrap();
            assert_eq!(read_msg(&mut &buf[..]).unwrap(), m);
        }
        for m in [
            Message::UpdateChunk {
                data: vec![0; MAX_CHUNK + 1],
            },
            Message::UpdateBegin {
                kind: "binary".into(),
                name: "x".into(),
                size: MAX_UPDATE + 1,
                sha256: [0; 32],
                signature: vec![],
                manifest: vec![],
                manifest_sig: vec![],
                rollback: false,
            },
            Message::UpdateState {
                json: "x".repeat(MAX_UPDATE_STATE + 1),
            },
        ] {
            let mut buf = Vec::new();
            write_msg(&mut buf, &m).unwrap();
            assert!(read_msg(&mut &buf[..]).is_err());
        }
    }

    #[test]
    fn v16_messages_keep_old_encodings() {
        assert_eq!(postcard::to_stdvec(&Message::GetLayout).unwrap(), vec![42]);
        let m = Message::RescueDone {
            job: 3,
            target: "/mnt/nexus-target".into(),
            log: "ok".into(),
        };
        assert_eq!(postcard::to_stdvec(&m).unwrap()[0], 46);
        let mut buf = Vec::new();
        write_msg(&mut buf, &m).unwrap();
        assert_eq!(read_msg(&mut &buf[..]).unwrap(), m);
        let mut buf = Vec::new();
        write_msg(
            &mut buf,
            &Message::Layout {
                json: "x".repeat(MAX_LAYOUT + 1),
            },
        )
        .unwrap();
        assert!(read_msg(&mut &buf[..]).is_err(), "layout size limit");
    }

    #[test]
    fn lz4_wire_compression() {
        let text = b"backup ".repeat(70_000);
        let c = lz4_pack(&text).expect("compressible");
        assert!(c.len() < text.len() / 10);
        assert_eq!(lz4_unpack(&c, text.len() as u32).unwrap(), text);
        let mut x = 0x9e3779b97f4a7c15u64;
        let random: Vec<u8> = (0..65536)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        assert!(lz4_pack(&random).is_none(), "incompressible data goes raw");
        assert!(lz4_unpack(&c, text.len() as u32 - 1).is_err(), "raw_len must match");
        assert!(lz4_unpack(b"\xff\xff\xff", 1000).is_err(), "garbage refused");
        // a lying raw_len above the limit is refused by the frame check before decompression
        let mut buf = Vec::new();
        write_msg(
            &mut buf,
            &Message::ChunkLz4 {
                hash: [0; 32],
                raw_len: MAX_CHUNK as u32 + 1,
                data: c,
            },
        )
        .unwrap();
        assert!(read_msg(&mut &buf[..]).is_err());
    }

    #[test]
    fn proofs_bind_token_role_and_session() {
        let ex = [7u8; 32];
        let a = enroll_proof("TOKEN", "appliance", &ex);
        assert!(proof_eq(&a, &enroll_proof("TOKEN\n", "appliance", &ex)));
        assert!(!proof_eq(&a, &enroll_proof("TOKEN", "agent", &ex)));
        assert!(!proof_eq(&a, &enroll_proof("OTHER", "appliance", &ex)));
        assert!(!proof_eq(&a, &enroll_proof("TOKEN", "appliance", &[8u8; 32])));
        assert_ne!(rescue_lookup("ABC"), token_digest("ABC"));
        assert_eq!(rescue_lookup("ABC\n").len(), 64);
        assert_eq!(
            fleet_id("nxf1.0123456789abcdef.ABCDEFGHIJKLMNOPQRSTUVWXYZ\n"),
            Some("0123456789abcdef")
        );
        assert_eq!(fleet_id("nxf1.0123456789ABCDEF.ABCDEFGHIJKLMNOPQRSTUVWXYZ"), None);
        assert_eq!(fleet_id("nxf1.0123456789abcdef.short"), None);
        assert_eq!(fleet_id("ABCDEFGHIJKLMNOPQRSTUVWXYZ"), None);
        let d = token_digest("ABC\n");
        assert_eq!(d, token_digest("ABC"));
        assert_eq!(d, "b5d4045c3f466fa91fe2cc6abe79232a1a57cdf104f7a26e716e0a1e2789df78");
    }
}
