//! Wire protocol between the appliance and `nexus-agent` (docs/agent-protocol.md).
//! Framing: `u32 BE length | postcard(Message)`, max `MAX_FRAME`.

#![warn(missing_docs)]

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io::{self, Read, Write};

pub mod edge;
pub mod layout;
pub mod release;

/// Protocol major version exchanged in `Hello` / `HelloReply` (must match). Minor
/// versions (v1.1 to v1.8) are additive and negotiated by capabilities.
pub const VERSION: u32 = 1;
/// TCP port the agent listens on unless configured otherwise.
pub const DEFAULT_PORT: u16 = 7444;
/// TLS ALPN of agent sessions (enrollment and mTLS).
pub const ALPN: &[u8] = b"nexus-agent/1";
/// Largest frame body (postcard bytes after the length prefix).
pub const MAX_FRAME: usize = 8 << 20;
/// Largest chunk, bytes (raw and LZ4-compressed data, `raw_len`, update pieces).
pub const MAX_CHUNK: usize = 4 << 20;
/// Most entries per `Entries` / `RestoreEntries` batch, hashes per `Want` / `EntryHashes`.
pub const MAX_BATCH: usize = 10_000;
/// Longest `Entry::path` / `link_target` and filter path or regex, bytes.
pub const MAX_PATH: usize = 4096;
/// Largest sum of xattr name and value bytes of one entry.
pub const MAX_XATTR: usize = 64 << 10;
/// include roots / regexes / file system types per `PrepareEx` (each)
pub const MAX_FILTERS: usize = 256;
/// FastCDC minimum chunk size of agent file data, bytes.
pub const CDC_MIN: u32 = 128 << 10;
/// FastCDC average chunk size, bytes.
pub const CDC_AVG: u32 = 512 << 10;
/// FastCDC maximum chunk size, bytes.
pub const CDC_MAX: u32 = 4 << 20;
/// TLS exporter label of the enrollment proofs ([`enroll_proof`], 32 bytes, no context).
pub const EXPORTER_LABEL: &[u8] = b"nexus-agent enroll";

/// Plain (unkeyed) BLAKE3 of a chunk; mapped to keyed IDs only on the appliance.
pub type Hash = [u8; 32];

/// How the agent snapshots a volume (postcard tags fixed: new kinds are appended).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotKind {
    /// LVM snapshot of the logical volume
    Lvm,
    /// ZFS snapshot of the dataset
    Zfs,
    /// btrfs read-only snapshot of the subvolume
    Btrfs,
    /// no snapshot support: read live, changed files are marked `inconsistent`
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

/// A mounted volume of the agent host (`Volumes`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Volume {
    /// mount point: Linux absolute path, Windows `/C` (drive letter)
    pub mountpoint: String,
    /// Linux: mount source (`/dev/...`, dataset); Windows: volume GUID path
    pub device: String,
    /// file system type (`ext4`, `xfs`, `zfs`, `NTFS`, ...)
    pub fstype: String,
    /// how a backup would snapshot it
    pub snapshot: SnapshotKind,
}

/// A snapshot the agent created for a job (`Prepared`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SnapshotInfo {
    /// mount point of the snapshotted volume (as in [`Volume::mountpoint`])
    pub mountpoint: String,
    /// snapshot technique
    pub kind: SnapshotKind,
    /// snapshot name on the host (LV, ZFS / btrfs snapshot, VSS shadow set id), for logs
    pub name: String,
}

/// File type of an [`Entry`].
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// regular file; the only kind with chunks
    File,
    /// directory
    Dir,
    /// symbolic link; `link_target` = its target
    Symlink,
    /// further name of a file sent earlier in the same scan; `link_target` = that path
    Hardlink,
    /// block or character device (`mode` keeps `S_IFBLK` / `S_IFCHR`, `rdev` the number)
    Device,
    /// named pipe
    Fifo,
    /// unix socket
    Socket,
}

/// One file system object with its metadata and chunk list (`Entries`, `RestoreEntries`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Entry {
    /// relative to the host's `/` (Windows: `C/Users/x`), `/`-separated, raw bytes
    /// (not necessarily UTF-8); see docs/agent-protocol.md "Paths"
    pub path: Vec<u8>,
    /// file type
    pub kind: Kind,
    /// permission bits (`& 0o7777`; devices the full `st_mode`); Windows: synthesized from the attributes
    pub mode: u32,
    /// owner uid; `0xFFFFFFFF` on restore to another host = keep the restoring user
    pub uid: u32,
    /// owner gid; `0xFFFFFFFF` as for `uid`
    pub gid: u32,
    /// file size in bytes (0 for everything but regular files)
    pub size: u64,
    /// modification time, nanoseconds since the Unix epoch
    pub mtime_ns: i64,
    /// status change time (Windows: change time), nanoseconds since the Unix epoch
    pub ctime_ns: i64,
    /// inode number (Windows: file id); with size and times the key of the agent's metadata cache
    pub inode: u64,
    /// device number of a `Device` entry, else 0
    pub rdev: u64,
    /// symlink target or hardlink target path
    pub link_target: Option<Vec<u8>>,
    /// extended attributes (name, value), raw bytes; Windows metadata as `win.*` (docs/agent-windows.md)
    pub xattrs: Vec<(Vec<u8>, Vec<u8>)>,
    /// content of a regular file in order: (plain BLAKE3 of the chunk, chunk length in bytes)
    pub chunks: Vec<(Hash, u32)>,
    /// taken from the metadata cache without reading the file (size, times and inode match `base`)
    pub unchanged: bool,
    /// the file changed while it was read without a snapshot
    pub inconsistent: bool,
}

/// Counters of a scan (`ScanDone`) or a restore (`RestoreDone`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct ScanStats {
    /// regular files and hard links (restore: files written)
    pub files: u64,
    /// directories
    pub dirs: u64,
    /// total size of the regular files, bytes (restore: data bytes written)
    pub bytes: u64,
    /// bytes actually read from changed files (scan only)
    pub read_bytes: u64,
    /// files taken from the metadata cache without reading (scan only)
    pub unchanged: u64,
    /// files marked `inconsistent` (scan only)
    pub inconsistent: u64,
    /// one message per entry that was skipped or failed; a restore with errors fails the job
    pub errors: Vec<String>,
}

/// The previous backup a scan compares against (`Scan::base`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BaseRef {
    /// appliance snapshot time of the previous successful backup of this agent
    pub time: u64,
}

/// What a restore does with a file that already exists at the target.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Overwrite {
    /// keep the existing file
    Never,
    /// replace it if it is older than the restored version (mtime)
    IfOlder,
    /// always replace it
    Always,
}

/// One frame of the agent protocol (docs/agent-protocol.md "Messages"). The appliance
/// sends requests, the agent answers; `job` is the appliance job id. Postcard encodes
/// the variant index, so variants are only ever appended (v1.1 to v1.8 below).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Message {
    // enrollment (agent in enrollment mode, self-signed cert)
    /// Appliance → agent: proof of the enrollment token (role `"appliance"`).
    Enroll {
        /// [`enroll_proof`] of the token digest, bound to this TLS session
        proof: [u8; 32],
    },
    /// Agent → appliance: its own proof and a certificate request.
    EnrollReply {
        /// [`enroll_proof`] with role `"agent"`
        proof: [u8; 32],
        /// PKCS#10 CSR of the agent's key pair, PEM
        csr_pem: String,
    },
    /// Appliance → agent: the issued certificate; no answer, the agent switches to mTLS.
    EnrollDone {
        /// agent certificate (`CN=nexus-agent:<agent_id>`, serverAuth), PEM
        cert_pem: String,
        /// appliance agent CA certificate, PEM
        ca_pem: String,
        /// agent id assigned by the appliance (16 hex)
        agent_id: String,
    },
    // session
    /// Appliance → agent: first message of every mTLS session.
    Hello {
        /// the appliance's [`VERSION`]
        version: u32,
    },
    /// Agent → appliance: who it is and what it supports.
    HelloReply {
        /// the agent's [`VERSION`]; the session ends if it differs
        version: u32,
        /// must equal the id the appliance expects for this endpoint
        agent_id: String,
        /// OS name (Linux: `PRETTY_NAME` of /etc/os-release; Windows: product name and
        /// display version)
        os: String,
        /// kernel release (Windows: `10.0.<build>.<ubr>`)
        kernel: String,
        /// host name
        hostname: String,
        /// agent version, `X.Y.Z`
        agent_version: String,
        /// capabilities (`CAP_*`, `vss-writers`, `xattrs`, `win-sd`) and v1.8 host facts
        /// (`arch=`, `install=`, `gui=`, [`release::HostFacts`])
        caps: Vec<String>,
    },
    /// Appliance → agent: list the volumes; answer `Volumes`.
    ListVolumes,
    /// Agent → appliance: answer to `ListVolumes`.
    Volumes {
        /// the mounted volumes and how each would be snapshotted
        list: Vec<Volume>,
    },
    /// Appliance → agent: run the pre-hooks and snapshot the volumes of `paths`;
    /// answer `Prepared`. Agents with CAP_PREPARE2 get `PrepareEx` instead.
    Prepare {
        /// appliance job id
        job: u64,
        /// absolute host paths to back up (Windows `/C/...`)
        paths: Vec<String>,
        /// glob patterns of paths to skip
        excludes: Vec<String>,
        /// run the hooks configured locally in `/etc/nexus-agent/hooks.d/`
        hooks: bool,
    },
    /// Agent → appliance: answer to `Prepare` / `PrepareEx`.
    Prepared {
        /// job id of the request
        job: u64,
        /// the snapshots created (empty for volumes read live)
        snapshots: Vec<SnapshotInfo>,
        /// every volume has a snapshot and every hook succeeded; false raises `backup_inconsistent`
        consistent: bool,
        /// hook output and notes (live volumes, skipped mounts, applied limits), text
        hook_log: String,
    },
    /// Appliance → agent: walk the snapshots; answer a stream of `Entries`, then `ScanDone`.
    Scan {
        /// job id of the `Prepare`
        job: u64,
        /// previous backup to compare with; `None`: read every file
        base: Option<BaseRef>,
    },
    /// Agent → appliance: up to [`MAX_BATCH`] entries of a scan.
    Entries {
        /// entries in walk order, each path once
        batch: Vec<Entry>,
    },
    /// Agent → appliance: end of a scan.
    ScanDone {
        /// counters of the whole scan
        stats: ScanStats,
    },
    /// Appliance → agent: send these chunks; answer one `Chunk` per hash (any order), then `WantDone`.
    Want {
        /// job id
        job: u64,
        /// plain BLAKE3 hashes, sorted, at most [`MAX_BATCH`]
        hashes: Vec<Hash>,
    },
    /// Agent → appliance: the data of one requested chunk.
    Chunk {
        /// plain BLAKE3 of `data` (the appliance verifies it)
        hash: Hash,
        /// raw chunk bytes, at most [`MAX_CHUNK`]
        data: Vec<u8>,
    },
    /// Agent → appliance: every chunk of the `Want` was sent.
    WantDone,
    /// Appliance → agent: drop the snapshots and run the post-hooks; answer `Released`.
    Release {
        /// job id
        job: u64,
        /// the snapshot was committed: the agent commits its metadata cache for the next `base`
        success: bool,
    },
    /// Agent → appliance: answer to `Release`.
    Released {
        /// job id
        job: u64,
        /// post-hook output, text
        hook_log: String,
    },
    /// Appliance → agent: start a restore below `target`; answer `RestoreReady` or `Error`.
    RestoreBegin {
        /// appliance job id
        job: u64,
        /// absolute host path the entries are written below
        target: String,
        /// what to do with existing files
        overwrite: Overwrite,
        /// the target agent's name as typed by the user in the UI (logged by the agent)
        confirm: String,
    },
    /// Agent → appliance: ready for `RestoreEntries`.
    RestoreReady,
    /// Appliance → agent: up to 1000 entries; their chunks follow as `RestoreChunk`s.
    RestoreEntries {
        /// entries to write, parents before children; paths relative to `target`
        batch: Vec<Entry>,
    },
    /// Appliance → agent: one chunk of the last batch, in entry and chunk order
    /// (repeated chunks are sent again).
    RestoreChunk {
        /// plain BLAKE3 of `data`
        hash: Hash,
        /// raw chunk bytes, at most [`MAX_CHUNK`]
        data: Vec<u8>,
    },
    /// Appliance → agent: no more entries; answer `RestoreDone`.
    RestoreEnd,
    /// Agent → appliance: end of the restore.
    RestoreDone {
        /// what was written; `errors` not empty fails the job
        stats: ScanStats,
    },
    /// Appliance → agent: self-update in one frame (agents before v1.8); answer
    /// `UpdateDone` or `Error`.
    Update {
        /// version of the new binary, `X.Y.Z`
        version: String,
        /// the agent executable (below [`MAX_FRAME`])
        binary: Vec<u8>,
        /// cosign blob signature of `binary` with the pinned release key
        signature: Vec<u8>,
    },
    /// Agent → appliance: the update is installed; the agent restarts into it.
    UpdateDone,
    /// Either side: a request failed.
    Error {
        /// HTTP-like status (`agent_core::server::E_*`): 400 invalid request, 401 wrong proof
        /// or other fleet, 403 refused, 404 unknown job, 409 busy, 410 chunks gone (file
        /// changed after the scan), 423 locked, 426 version mismatch, 500 failure on the host
        code: u32,
        /// human-readable reason
        message: String,
    },
    // --- v1.1, appended (old peers never send/receive these) ---
    /// Appliance → agent after `Prepared`, only if `HelloReply.caps` contains
    /// `"vss-writers"`: which VSS writers took part in the job's snapshot.
    Writers {
        /// job id of the `Prepare`
        job: u64,
    },
    /// Agent → appliance (v1.1): answer to `Writers`.
    WritersReport {
        /// job id
        job: u64,
        /// every VSS writer the agent saw
        writers: Vec<VssWriter>,
    },
    // --- v1.2, appended: LZ4 on the wire (only if HelloReply.caps contains CAP_LZ4) ---
    /// Like `Want`, but the agent may answer with `ChunkLz4` for compressible chunks.
    WantLz4 {
        /// job id
        job: u64,
        /// plain BLAKE3 hashes, sorted, at most [`MAX_BATCH`]
        hashes: Vec<Hash>,
    },
    /// LZ4 block of a chunk; `hash`/`raw_len` describe the uncompressed data.
    ChunkLz4 {
        /// plain BLAKE3 of the uncompressed data
        hash: Hash,
        /// uncompressed length in bytes, at most [`MAX_CHUNK`]
        raw_len: u32,
        /// LZ4 block ([`lz4_pack`]), at most [`MAX_CHUNK`]
        data: Vec<u8>,
    },
    /// Restore direction, appliance → agent (agent advertised CAP_LZ4).
    RestoreChunkLz4 {
        /// plain BLAKE3 of the uncompressed data
        hash: Hash,
        /// uncompressed length in bytes, at most [`MAX_CHUNK`]
        raw_len: u32,
        /// LZ4 block ([`lz4_pack`]), at most [`MAX_CHUNK`]
        data: Vec<u8>,
    },
    // --- v1.3, appended: file filters + limits, certificate renewal ---
    /// `Prepare` with the full filter set and the appliance-side limits (only if
    /// `HelloReply.caps` contains CAP_PREPARE2; old agents get `Prepare` with the
    /// globs only). Answered with `Prepared`.
    PrepareEx {
        /// appliance job id
        job: u64,
        /// absolute host paths to back up (Windows `/C/...`)
        paths: Vec<String>,
        /// glob patterns of paths to skip
        excludes: Vec<String>,
        /// run the locally configured hooks
        hooks: bool,
        /// include roots, regex excludes, nested mounts
        filters: Filters,
        /// bandwidth and priority of the job
        limits: Limits,
    },
    /// Appliance → agent (CAP_RENEW): generate a new key pair, answer `RenewCsr`.
    RenewCert,
    /// Agent → appliance (v1.3): request for the new key pair.
    RenewCsr {
        /// PKCS#10 CSR of the new key (kept in memory until `RenewDone`), PEM
        csr_pem: String,
    },
    /// The certificate issued for the `RenewCsr` key (same CN, same CA). The agent
    /// checks it, swaps key + certificate atomically and answers `RenewOk`; new
    /// connections use the new identity.
    RenewDone {
        /// the new agent certificate, PEM
        cert_pem: String,
        /// the appliance agent CA certificate, PEM (must be the one the agent trusts)
        ca_pem: String,
    },
    /// Agent → appliance (v1.3): the new key and certificate are in place.
    RenewOk,
    // --- v1.4, appended: endpoint status (only if HelloReply.caps contains CAP_POLL) ---
    /// Appliance → agent after a backup / restore session ended: its summary for the
    /// endpoint UI, the next scheduled run and the per-agent UI policy. Answered with
    /// `SummaryAck`; the agent keeps the last 100 summaries.
    SessionSummary {
        /// the finished session
        summary: Summary,
        /// the current appliance view
        status: ApplianceStatus,
    },
    /// Agent → appliance (v1.4): the summary is stored; the appliance marks it delivered.
    SummaryAck {
        /// `Summary::job` of the stored summary
        job: u64,
    },
    /// Appliance → agent every few minutes (short session): the current appliance view,
    /// and `ack` = ids of earlier `BackupRequest`s the appliance has acted on (the agent
    /// drops them). Answered with `PollReply`.
    Poll {
        /// the current appliance view
        status: ApplianceStatus,
        /// [`BackupRequest::id`]s acted on, at most [`MAX_REQUESTS`]
        ack: Vec<String>,
    },
    /// Agent → appliance (v1.4): answer to `Poll`.
    PollReply {
        /// "back up now" requests queued by local users, not yet acknowledged
        requests: Vec<BackupRequest>,
        /// power and network state of the host (laptop policies)
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
        /// fleet id of the secret (16 hex, [`fleet_id`])
        fleet_id: String,
        /// appliance proof of the fleet secret
        proof: [u8; 32],
    },
    /// The agent's answer: its proof (role `"fleet-agent"`) and what the admin sees
    /// before accepting it. The session ends here; enrollment is a later `Enroll`.
    FleetInfo {
        /// [`enroll_proof`] of the fleet secret digest with role `"fleet-agent"`
        proof: [u8; 32],
        /// host name
        hostname: String,
        /// OS name as in `HelloReply::os`
        os: String,
        /// agent version, `X.Y.Z`
        agent_version: String,
    },
    // --- v1.6, appended: machine layout + bare-metal recovery (docs/bmr.md) ---
    /// Appliance → agent (CAP_LAYOUT), at the start of a backup: the machine layout.
    GetLayout,
    /// [`layout::Layout`] as JSON (at most `MAX_LAYOUT` bytes).
    Layout {
        /// [`layout::Layout`] serialized as JSON
        json: String,
    },
    /// Appliance → rescue agent (CAP_RESCUE): recreate partitions, LVM, file systems
    /// and swap of `layout` (JSON) on the disks confirmed at the rescue console and
    /// mount them below the restore target. Answered with `RescueDone`.
    RescueApply {
        /// appliance job id
        job: u64,
        /// [`layout::Layout`] as JSON (at most `MAX_LAYOUT` bytes)
        layout: String,
    },
    /// Appliance → rescue agent after the restore: fix up the restored system
    /// (`/etc/fstab` UUIDs, boot loader, initramfs), unmount; `reboot` after the answer.
    RescueFinish {
        /// appliance job id
        job: u64,
        /// reboot the machine after answering
        reboot: bool,
    },
    /// Answer to `RescueApply` / `RescueFinish`: what was done (one step per line);
    /// `target` = where the file systems are mounted (the restore target).
    RescueDone {
        /// job id of the request
        job: u64,
        /// absolute path where the restored file systems are mounted
        target: String,
        /// the steps done, one per line
        log: String,
    },
    /// v1.7 (CAP_EDGE), appliance → agent: keep a rendezvous connection to this edge
    /// proxy (`addr` = `host:port`, `cert_sha256` = pinned edge certificate); an empty
    /// `addr` removes it. `agent.conf` (`edge`, `edge_sha256`) takes precedence.
    SetEdge {
        /// `host:port` of the edge's public port; "" = no edge (at most [`MAX_TEXT`] bytes)
        addr: String,
        /// SHA-256 of the edge certificate, hex (at most 64 bytes)
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
        /// artifact kind ([`release::KINDS`]), must be the install's own
        kind: String,
        /// artifact name as in the manifest (at most [`MAX_ARTIFACT_NAME`] bytes)
        name: String,
        /// artifact size in bytes (at most [`MAX_UPDATE`])
        size: u64,
        /// SHA-256 of the artifact
        sha256: [u8; 32],
        /// cosign blob signature of the artifact (at most [`MAX_SIGNATURE`] bytes)
        signature: Vec<u8>,
        /// the release's `manifest.json` (at most [`MAX_MANIFEST`] bytes)
        manifest: Vec<u8>,
        /// cosign signature of `manifest` (at most [`MAX_SIGNATURE`] bytes)
        manifest_sig: Vec<u8>,
        /// an approved rollback to an older release (see `agent_core::update::ROLLBACK_FLOOR`)
        rollback: bool,
    },
    /// Agent → appliance (v1.8): `UpdateBegin` accepted, send the data.
    UpdateReady,
    /// The next piece of the artifact announced by `UpdateBegin` (no answer).
    UpdateChunk {
        /// at most [`MAX_CHUNK`] bytes
        data: Vec<u8>,
    },
    /// End of the artifact: the agent checks it; `apply = false` stages it (answer
    /// `UpdateStaged`, more artifacts follow), `apply = true` installs everything staged
    /// (answer `UpdateDone`, or `Error`).
    UpdateCommit {
        /// install everything staged now (else only stage this artifact)
        apply: bool,
    },
    /// Agent → appliance (v1.8): the artifact is checked and staged.
    UpdateStaged,
    /// Appliance → agent: the agent's update state (`update-state.json`).
    UpdateStatus,
    /// `json` = `{state, kind, from, to, at, error, log}` or `{}` when no update ran.
    UpdateState {
        /// JSON text, at most [`MAX_UPDATE_STATE`] bytes
        json: String,
    },
    // --- Phase 28, appended after the v1.8 update messages (CAP_FILE_HASH; documented with the v1.8 notes, no
    // version change: only agents announcing the capability are sent these) ---
    /// Like `Scan`, but the agent sends `EntryHashes` right after every `Entries`
    /// batch: the SHA-256 of the regular files it read (IOC hash hunt).
    ScanHashed {
        /// job id of the `Prepare`
        job: u64,
        /// previous backup to compare with; `None`: read every file
        base: Option<BaseRef>,
    },
    /// Agent → appliance after each `Entries` batch of a `ScanHashed`: one element
    /// per entry of that batch (same order); `None` = not a regular file, not read
    /// in this scan (unchanged) or the read failed. The appliance never trusts it
    /// for anything but the IOC search (a lying agent only hides its own files).
    EntryHashes {
        /// SHA-256 per entry of the batch (not BLAKE3), at most [`MAX_BATCH`]
        hashes: Vec<Option<Hash>>,
    },
    // --- v1.9, appended: block reads of hot-added disks (CAP_BLOCK_READ, the VMware proxy role,
    // docs/vmware-design.md; only agents announcing the capability are sent these) ---
    /// Appliance → agent: read these block ranges of the disk at SCSI target `0:target` of the
    /// proxy (a snapshot disk the appliance hot-added through the vSphere API), in blocks of
    /// [`BLOCK_SIZE`] (the last one may be shorter: `size`). Answer: `BlockHashes` batches, then
    /// `BlockScanDone`; the data follows on `Want` (job `job`); `Release` ends the job.
    BlockScan {
        /// job id chosen by the appliance (no `Prepare`)
        job: u64,
        /// SCSI target of the disk on controller 0, 1..=[`MAX_BLOCK_TARGET`]
        target: u32,
        /// the disk's size in bytes (the agent checks the device has it)
        size: u64,
        /// `(first block, count)` ranges, at most [`MAX_BATCH`]
        ranges: Vec<(u64, u64)>,
    },
    /// Agent → appliance: plain BLAKE3 of the blocks `first..first + hashes.len()` of the last
    /// range in order (at most [`MAX_BATCH`] per message).
    BlockHashes {
        /// job id
        job: u64,
        /// index of the first block
        first: u64,
        /// one hash per block
        hashes: Vec<Hash>,
    },
    /// Agent → appliance: every range of the `BlockScan` was read.
    BlockScanDone {
        /// job id
        job: u64,
        /// blocks hashed
        blocks: u64,
        /// bytes read
        bytes: u64,
    },
}

/// Capability (v1.9): the agent reads hot-added disks for the VMware connector (`BlockScan`).
/// Announced only with `proxy = on` in `agent.conf`.
pub const CAP_BLOCK_READ: &str = "block-read";
/// Block size of `BlockScan` (the appliance's VM image index granularity).
pub const BLOCK_SIZE: u64 = 4 << 20;
/// Highest SCSI target a `BlockScan` may name (0:1..0:15; 0:0 is the proxy's own disk).
pub const MAX_BLOCK_TARGET: u32 = 15;

/// Capability: the agent understands `UpdateBegin` / `UpdateChunk` / `UpdateCommit` /
/// `UpdateStatus` (v1.8) and reports its host facts as `arch=`, `install=`, `gui=` caps
/// ([`release::HostFacts`]).
pub const CAP_UPDATE2: &str = "update2";
/// Largest update artifact accepted (MSI with the desktop UI stays far below).
pub const MAX_UPDATE: u64 = 512 << 20;
/// Largest signature in update messages, bytes.
pub const MAX_SIGNATURE: usize = 64 << 10;
/// Largest `manifest.json` in `UpdateBegin`, bytes.
pub const MAX_MANIFEST: usize = 256 << 10;
/// Largest `UpdateState::json`, bytes.
pub const MAX_UPDATE_STATE: usize = 16 << 10;
/// Longest artifact name, bytes.
pub const MAX_ARTIFACT_NAME: usize = 200;

/// Capability: the agent computes the SHA-256 of the files it reads when asked
/// with `ScanHashed` and answers `EntryHashes` (Phase 28).
pub const CAP_FILE_HASH: &str = "file-hash";

/// Capability: the agent understands `SetEdge` and keeps an edge rendezvous (v1.7).
pub const CAP_EDGE: &str = "edge";

/// Capability: the agent understands `SessionSummary` and `Poll` (v1.4).
pub const CAP_POLL: &str = "poll";
/// Longest `Summary::log_tail`, lines.
pub const MAX_LOG_TAIL: usize = 200;
/// Longest `Summary::log_tail` line and `first_error`, bytes.
pub const MAX_LOG_LINE: usize = 1024;
/// At most this many requests in one `PollReply`.
pub const MAX_REQUESTS: usize = 16;
/// Longest free-text field (names, header, errors) accepted in v1.4 messages.
pub const MAX_TEXT: usize = 256;

/// What a summarized session did.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionKind {
    /// backup of this agent
    Backup,
    /// file restore to this agent
    Restore,
}

/// Outcome of a summarized session.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionResult {
    /// finished without warnings
    Success,
    /// finished with warnings (`Summary::warnings`)
    Warning,
    /// no snapshot committed (backup) or not every file restored
    Failed,
    /// cancelled by an operator
    Cancelled,
}

/// One finished backup / restore session of this agent (times: Unix seconds).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Summary {
    /// appliance job id
    pub job: u64,
    /// backup or restore
    pub kind: SessionKind,
    /// job start
    pub started: u64,
    /// job end
    pub ended: u64,
    /// outcome
    pub result: SessionResult,
    /// source bytes the agent scanned (restore: bytes written)
    pub read_bytes: u64,
    /// bytes the appliance received from the agent (restore: sent)
    pub transferred_bytes: u64,
    /// bytes newly stored after deduplication (0 for a restore)
    pub new_bytes: u64,
    /// warning lines in the agent's part of the job log
    pub warnings: u32,
    /// first error line of a failed session (at most [`MAX_LOG_LINE`] bytes); "" = none
    pub first_error: String,
    /// time of the snapshot a backup committed; `None`: restore or nothing committed
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
    /// hide "request backup now" in the endpoint UIs; the agent also refuses such requests
    pub hide_backup_now: bool,
    /// no tray icon in the desktop UI
    pub hide_tray: bool,
}

/// What the appliance tells the agent with every summary and poll.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct ApplianceStatus {
    /// appliance display name ("managed by")
    pub appliance: String,
    /// the appliance's clock, Unix seconds
    pub now: u64,
    /// next scheduled backup of this agent, Unix seconds; `None`: none scheduled
    pub next_run: Option<u64>,
    /// branding and visibility of the endpoint UIs
    pub ui_policy: UiPolicy,
    /// version of `ui_policy` on the appliance, echoed in `PollReply`
    pub policy_version: u32,
}

/// A "back up now" request queued on the agent by a local user.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BackupRequest {
    /// random hex, ≤ 64 characters
    pub id: String,
    /// when it was queued, Unix seconds (the agent drops it after 7 days)
    pub queued_at: u64,
}

/// Power and network state of the agent host (laptops). `None` = unknown.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct PowerState {
    /// running on battery
    pub on_battery: Option<bool>,
    /// battery charge, 0..=100
    pub battery_percent: Option<u8>,
    /// the active network connection is metered
    pub metered: Option<bool>,
    /// name of the active network connection (at most [`MAX_TEXT`] bytes)
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

/// Writes and flushes one frame; refuses a body above [`MAX_FRAME`].
pub fn write_msg(w: &mut impl Write, m: &Message) -> io::Result<()> {
    let body = postcard::to_stdvec(m).map_err(|e| bad(format!("encode: {e}")))?;
    if body.len() > MAX_FRAME {
        return Err(bad("frame too large"));
    }
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

/// Reads one frame and applies [`check`]; a length above [`MAX_FRAME`] is refused
/// before the body is allocated.
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
        Message::EntryHashes { hashes } if hashes.len() > MAX_BATCH => return Err(bad("too many hashes in one batch")),
        Message::BlockHashes { hashes, .. } if hashes.len() > MAX_BATCH => {
            return Err(bad("too many hashes in one batch"))
        }
        Message::BlockScan { target, ranges, .. }
            if *target == 0 || *target > MAX_BLOCK_TARGET || ranges.len() > MAX_BATCH =>
        {
            return Err(bad("block scan exceeds limits"))
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
        Message::UpdateState { json } if json.len() > MAX_UPDATE_STATE => return Err(bad("update state too large")),
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

    /// Phase 28 (CAP_FILE_HASH): appended after the v1.8 update messages (56, 57), bounded like a batch.
    #[test]
    fn file_hash_messages_are_appended() {
        let m = Message::ScanHashed {
            job: 7,
            base: Some(BaseRef { time: 9 }),
        };
        assert_eq!(postcard::to_stdvec(&m).unwrap()[0], 56);
        let h = Message::EntryHashes {
            hashes: vec![None, Some([3; 32])],
        };
        assert_eq!(postcard::to_stdvec(&h).unwrap()[0], 57);
        for m in [m, h] {
            let mut buf = Vec::new();
            write_msg(&mut buf, &m).unwrap();
            assert_eq!(read_msg(&mut &buf[..]).unwrap(), m);
        }
        let mut buf = Vec::new();
        write_msg(
            &mut buf,
            &Message::EntryHashes {
                hashes: vec![None; MAX_BATCH + 1],
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
        assert_eq!(
            postcard::to_stdvec(&Message::UpdateCommit { apply: true }).unwrap(),
            vec![52, 1]
        );
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
