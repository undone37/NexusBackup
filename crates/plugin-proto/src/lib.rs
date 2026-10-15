//! Protocol between `nexus-pluginhost` (trusted) and a plugin process (untrusted),
//! see docs/plugin-system.md. Framing: `u32 BE length | postcard(Message)`, max `MAX_FRAME`.

#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

/// Protocol major version; `Init.api` and the manifest's `api` must equal it.
/// Additive changes (v1.1 to v1.9) keep it at 1.
pub const API: u32 = 1;
/// Largest encoded message in bytes (8 MiB, without the 4-byte length prefix).
pub const MAX_FRAME: usize = 8 << 20;
/// Largest payload of one `Data`, `FileData` or `Output` frame in bytes (4 MiB).
pub const MAX_DATA: usize = 4 << 20;
/// Largest path or symlink target in bytes.
pub const MAX_PATH: usize = 4096;
/// Largest state blob (`Done.state`, `Init.state`) in bytes (1 MiB).
pub const MAX_STATE: usize = 1 << 20;
/// Largest sum of xattr names and values of one entry in bytes (64 KiB).
pub const MAX_XATTR: usize = 64 << 10;
/// Most paths, names or entries in one `NeedFiles`, `NeedStreams`, `BaseQuery` or
/// `BaseEntries` message.
pub const MAX_BATCH: usize = 10_000;

/// Operation of one plugin run, sent in `Init.op`. The wire index is the variant
/// order: new operations are only appended.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// Check config, connectivity and permissions; answered with `Valid` or `Invalid`.
    Validate,
    /// List the selectable guests; answered with `Guests` or `TaggedGuests`.
    ListGuests,
    /// Stream files and/or streams of a new snapshot, then `Done`.
    Backup,
    /// Restore to the source or a target (not `download`): the plugin asks with
    /// `NeedFiles`/`NeedStreams` and writes to its target.
    Restore,
    /// Serve the snapshot read-only: `MountReady`, then `ReadFile` requests until `Unmount`.
    Mount,
    /// v1.9 (appended): the generic download with plugin-side conversion (`download`
    /// restore with a `params_schema`); the plugin lists (`BaseList`) and reads
    /// (`ReadFile`) the snapshot and writes the download's files with `Output`.
    Export,
}

/// Entry type in [`Meta::kind`].
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Regular file; the only kind that carries `Data` (exactly `Meta::size` bytes).
    File,
    /// Directory.
    Dir,
    /// Symbolic link; needs [`Meta::link_target`].
    Symlink,
    /// Hard link to a regular file sent earlier in the same backup ([`Meta::link_target`]
    /// names its path).
    Hardlink,
    /// Character or block device (stored without `rdev`).
    Device,
    /// Named pipe.
    Fifo,
    /// Unix socket.
    Socket,
}

/// File metadata as the plugin knows it (POSIX-ish; plugins fill what they have).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Meta {
    /// Entry type; `None` is stored as a regular file.
    pub kind: Option<Kind>,
    /// Unix mode (`st_mode`, type and permission bits, at most `0o177777`).
    pub mode: u32,
    /// Owner user id.
    pub uid: u32,
    /// Owner group id.
    pub gid: u32,
    /// Size in bytes; for regular files the exact number of `Data` bytes that follow
    /// `FileBegin`, 0 for everything else.
    pub size: u64,
    /// Modification time, nanoseconds since the Unix epoch.
    pub mtime_ns: i64,
    /// Status change time, nanoseconds since the Unix epoch.
    pub ctime_ns: i64,
    /// Inode number on the source (stored as is, 0 if unknown).
    pub inode: u64,
    /// Target of a symlink, or the path of the earlier file a hard link points to;
    /// at most [`MAX_PATH`] bytes, no NUL.
    pub link_target: Option<Vec<u8>>,
    /// Extended attributes as (name, value); names and values together at most
    /// [`MAX_XATTR`] bytes.
    pub xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

/// One selectable guest of a source (database, mailbox, dataset ...), answer to
/// `ListGuests`. Postcard is not self-describing, so this struct never gets new
/// fields; tags live in [`TaggedGuest`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Guest {
    /// Stable id, part of the snapshot source name; see [`valid_guest_id`] (invalid
    /// ids are dropped by the host).
    pub id: String,
    /// Name shown in the UI.
    pub title: String,
    /// Approximate size in bytes, if known.
    pub size: Option<u64>,
}

/// v1.5: a guest with tags (`type:user`, `pool:x`, …) that auto-protect groups
/// select on (docs/plugin-system.md "v1.5"). Sent as [`Message::TaggedGuests`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TaggedGuest {
    /// As [`Guest::id`].
    pub id: String,
    /// As [`Guest::title`].
    pub title: String,
    /// As [`Guest::size`].
    pub size: Option<u64>,
    /// Free-form `key:value` tags; at most [`MAX_GUEST_TAGS`], each at most
    /// [`MAX_TAG`] bytes. The host keeps only printable, trimmed tags.
    pub tags: Vec<String>,
}

/// Tags per guest (`TaggedGuests`).
pub const MAX_GUEST_TAGS: usize = 64;
/// Bytes per tag (`TaggedGuests`).
pub const MAX_TAG: usize = 128;

impl From<Guest> for TaggedGuest {
    fn from(g: Guest) -> Self {
        TaggedGuest {
            id: g.id,
            title: g.title,
            size: g.size,
            tags: Vec::new(),
        }
    }
}

impl From<TaggedGuest> for Guest {
    fn from(g: TaggedGuest) -> Self {
        Guest {
            id: g.id,
            title: g.title,
            size: g.size,
        }
    }
}

/// What the host knows about the previous snapshot of this source.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BaseInfo {
    /// Snapshot time, Unix seconds.
    pub time: u64,
}

/// One entry of the base snapshot (answer to `BaseQuery` or `BaseList`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BaseEntry {
    /// Relative path as stored in the snapshot.
    pub path: Vec<u8>,
    /// Metadata as stored (xattrs may be dropped from a `BaseQuery` answer that would
    /// not fit one frame).
    pub meta: Meta,
}

/// One protocol frame, in either direction. The wire index is the variant order:
/// new variants are only appended (v1.3 and later), so older peers decode the
/// existing ones unchanged.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Message {
    // host -> plugin, first message
    /// Host to plugin, always first: what to do and with which config.
    Init {
        /// Protocol version of the host ([`API`]).
        api: u32,
        /// Appliance job id (for logs).
        job: u64,
        /// Manifest kind the source is of (without the `plugin:` prefix).
        kind: String,
        /// Operation to run.
        op: Op,
        /// source config (JSON) with secrets opened
        config: String,
        /// op parameters (JSON): guests for Backup, restore id + params for Restore, …
        params: String,
        /// Previous snapshot of this source (backup: the base for `Unchanged`;
        /// restore, mount, export: the snapshot itself), `None` for a first backup.
        base: Option<BaseInfo>,
        /// State blob the plugin returned in `Done` of that snapshot.
        state: Option<Vec<u8>>,
    },
    // validate / list guests
    /// Plugin to host: the validation passed.
    Valid,
    /// Plugin to host: the validation failed.
    Invalid {
        /// Config field at fault (property name), or empty.
        field: String,
        /// Reason shown to the admin.
        message: String,
    },
    /// Plugin to host: answer to `ListGuests` without tags.
    Guests {
        /// The guests.
        list: Vec<Guest>,
    },
    // backup stream (plugin -> host)
    /// Plugin to host: start of an entry; a regular file is followed by `Data`
    /// frames with exactly `meta.size` bytes, every entry by `FileEnd`.
    FileBegin {
        /// Relative path ([`valid_path`]), unique in the snapshot, not below [`STREAMS_DIR`].
        path: Vec<u8>,
        /// Metadata of the entry.
        meta: Meta,
    },
    /// Content of the open file or stream (either direction), at most [`MAX_DATA`] bytes.
    Data {
        /// The bytes.
        bytes: Vec<u8>,
    },
    /// End of the entry opened with `FileBegin`.
    FileEnd,
    /// Plugin to host: reuse the base snapshot's entry at `path`; type, mode, uid,
    /// gid, mtime, link target (and size for files) must match the base entry.
    Unchanged {
        /// Relative path in the base snapshot.
        path: Vec<u8>,
        /// Current metadata of the entry.
        meta: Meta,
    },
    /// Start of an application stream (dump, WAL ...), followed by `Data`* and `StreamEnd`.
    Stream {
        /// Stream name ([`valid_stream_name`]), unique in the snapshot.
        name: String,
    },
    /// End of the stream opened with `Stream`.
    StreamEnd,
    /// Plugin to host: the operation finished; for a backup the host commits now.
    Done {
        /// Opaque blob (at most [`MAX_STATE`] bytes) returned in the next `Init.state`.
        state: Option<Vec<u8>>,
        /// Whether the snapshot is consistent (`false` raises `backup_inconsistent`).
        consistent: bool,
        /// One line for the job log.
        summary: String,
    },
    // base metadata on demand
    /// Plugin to host, backup only: metadata of these base snapshot paths; answered
    /// with one `BaseEntries` (found paths only).
    BaseQuery {
        /// Relative paths, at most [`MAX_BATCH`].
        paths: Vec<Vec<u8>>,
    },
    /// Host to plugin: answer to `BaseQuery` or one page of `BaseList`.
    BaseEntries {
        /// Entries in path order, at most [`MAX_BATCH`].
        entries: Vec<BaseEntry>,
    },
    // restore (plugin asks, host streams FileBegin/Data/FileEnd and Stream/Data/StreamEnd back)
    /// Plugin to host, restore only: send these entries or subtrees of the snapshot
    /// (`FileBegin`/`Data`/`FileEnd`), then `NeedDone`. Unknown paths are skipped.
    NeedFiles {
        /// Relative paths, at most [`MAX_BATCH`].
        paths: Vec<Vec<u8>>,
    },
    /// Plugin to host, restore only: send these streams (`Stream`/`Data`/`StreamEnd`),
    /// then `NeedDone`. Unknown names are skipped.
    NeedStreams {
        /// Stream names, at most [`MAX_BATCH`].
        names: Vec<String>,
    },
    /// Host to plugin: end of the answer to `NeedFiles` or `NeedStreams`.
    NeedDone,
    /// Plugin to host: progress for the job page.
    Progress {
        /// Units done (bytes or items, the plugin's choice).
        done: u64,
        /// Units in total, 0 if unknown.
        total: u64,
        /// Short description of the current step.
        text: String,
    },
    // mount
    /// Plugin to host, mount only: the mount is ready.
    MountReady {
        /// How to reach it (shown to the user, e.g. an address).
        info: String,
    },
    /// Plugin to host (mount, export): read a byte range of a regular file of the
    /// snapshot; answered with `FileData`, or `Error { code: 2 }` for a missing or
    /// non-regular file.
    ReadFile {
        /// Relative path.
        path: Vec<u8>,
        /// Byte offset.
        offset: u64,
        /// Bytes to read, at most [`MAX_DATA`].
        len: u32,
    },
    /// Host to plugin: answer to `ReadFile` (shorter than asked at the end of the file).
    FileData {
        /// The bytes.
        bytes: Vec<u8>,
    },
    /// Host to plugin, mount only: the mount time ended; the plugin answers `Done`
    /// within 120 s.
    Unmount,
    // any time
    /// Plugin to host, any time: a line for the job log (escaped and truncated by the host).
    Log {
        /// 0 error, 1 warn, 2 info, 3 and above debug.
        level: u8,
        /// The text, at most 64 KiB.
        text: String,
    },
    /// Either direction, any time: the operation failed and ends.
    Error {
        /// Error code (errno-like; 2 = not found, 95 = not supported, 1 = other).
        code: u32,
        /// Reason for the job log, at most 64 KiB.
        message: String,
    },
    // v1.3 (appended: older variants keep their wire index)
    /// The base snapshot's entries in path order (bytes) after `after`; answered
    /// with one `BaseEntries` page (empty = end). Backup only.
    BaseList {
        /// Last path of the previous page; `None` starts at the beginning.
        after: Option<Vec<u8>>,
    },
    // v1.5 (appended)
    /// Answer to `ListGuests` with tags; plugins without tags keep sending `Guests`
    /// (the SDK does that), so they still run on a v1.4 host.
    TaggedGuests {
        /// The guests.
        list: Vec<TaggedGuest>,
    },
    // v1.7 (appended)
    /// Backup only, before `Done`: `count` items could not be read and are missing
    /// from the snapshot (the plugin skipped them); `samples` names the first few
    /// with their error. The job ends `ok` with warnings. The SDK sends it only when
    /// `count > 0`, so plugins without skipped items still run on a v1.6 host.
    Warnings {
        /// Items skipped since the previous `Warnings` (the host adds the counts up).
        count: u64,
        /// At most [`MAX_WARNING_SAMPLES`] lines of at most [`MAX_WARNING_SAMPLE`] bytes.
        samples: Vec<String>,
    },
    // v1.8 (appended after `Warnings`)
    /// Metadata of the snapshot being written (plugin → host, backup only, at most
    /// once, before `Done`): a JSON object of at most `MAX_SNAPSHOT_META` bytes that
    /// the appliance keeps with the snapshot in its catalog (e.g. PostgreSQL's
    /// recoverable range, shown in the restore dialog).
    SnapshotMeta {
        /// The JSON object as text.
        json: String,
    },
    // v1.9 (appended after `SnapshotMeta`)
    /// Export only (plugin → host): write `bytes` at `offset` of the output file
    /// `name` (a relative path below the download; created on first use). Writes may
    /// go back (e.g. a PST header written last); the host packs the files as the
    /// download's tar/zip after `Done`.
    Output {
        /// Relative path of the output file, at most 1024 bytes, not below [`STREAMS_DIR`].
        name: String,
        /// Byte offset in that file; `offset + bytes.len()` at most [`MAX_OUTPUT_FILE`].
        offset: u64,
        /// The bytes, at most [`MAX_DATA`].
        bytes: Vec<u8>,
    },
}

/// Upper bound of one export output file (`Output.offset + len`): 64 GiB.
pub const MAX_OUTPUT_FILE: u64 = 64 << 30;

/// Samples per `Warnings` message.
pub const MAX_WARNING_SAMPLES: usize = 20;
/// Bytes per `Warnings` sample.
pub const MAX_WARNING_SAMPLE: usize = 1024;

/// Largest `SnapshotMeta` JSON in bytes (16 KiB).
pub const MAX_SNAPSHOT_META: usize = 16 << 10;

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Encodes `m`, writes it as one frame and flushes. Fails for a message above
/// [`MAX_FRAME`] or on an I/O error; does not run [`check`].
pub fn write_msg(w: &mut impl Write, m: &Message) -> io::Result<()> {
    let body = postcard::to_stdvec(m).map_err(|e| bad(format!("encode: {e}")))?;
    if body.len() > MAX_FRAME {
        return Err(bad("frame too large"));
    }
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

/// Reads one frame and decodes it. Fails (`InvalidData`) for a frame above
/// [`MAX_FRAME`], an undecodable body or a message that fails [`check`]; EOF is
/// `UnexpectedEof`.
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

/// Relative path, no `..` / `.` components, no NUL, no leading `/`, bounded.
pub fn valid_path(p: &[u8]) -> bool {
    !p.is_empty()
        && p.len() <= MAX_PATH
        && p[0] != b'/'
        && !p.contains(&0)
        && p.split(|&b| b == b'/')
            .all(|c| !c.is_empty() && c != b"." && c != b"..")
}

/// Stream names: `[A-Za-z0-9._/-]{1,255}`, no `..` component, no leading `/`.
pub fn valid_stream_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 255
        && n.bytes().all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
        && valid_path(n.as_bytes())
}

fn check_meta(m: &Meta) -> io::Result<()> {
    let x: usize = m.xattrs.iter().map(|(k, v)| k.len() + v.len()).sum();
    if x > MAX_XATTR
        || m.link_target
            .as_ref()
            .is_some_and(|t| t.len() > MAX_PATH || t.contains(&0))
    {
        return Err(bad("metadata exceeds limits"));
    }
    Ok(())
}

/// Structural limits every receiver enforces (the host additionally checks ordering).
pub fn check(m: &Message) -> io::Result<()> {
    match m {
        Message::FileBegin { path, meta } | Message::Unchanged { path, meta } => {
            if !valid_path(path) {
                return Err(bad("invalid path"));
            }
            check_meta(meta)
        }
        Message::Output { name, offset, bytes }
            if bytes.len() > MAX_DATA
                || !valid_path(name.as_bytes())
                || name.len() > 1024
                || name.split('/').next() == Some(STREAMS_DIR)
                || offset.saturating_add(bytes.len() as u64) > MAX_OUTPUT_FILE =>
        {
            Err(bad("invalid output write"))
        }
        Message::Data { bytes } | Message::FileData { bytes } if bytes.len() > MAX_DATA => {
            Err(bad("data frame too large"))
        }
        Message::Stream { name } if !valid_stream_name(name) => Err(bad("invalid stream name")),
        Message::NeedStreams { names } if names.len() > MAX_BATCH || names.iter().any(|n| !valid_stream_name(n)) => {
            Err(bad("invalid stream list"))
        }
        Message::BaseList { after: Some(p) } if !valid_path(p) => Err(bad("invalid path")),
        Message::NeedFiles { paths } | Message::BaseQuery { paths }
            if paths.len() > MAX_BATCH || paths.iter().any(|p| !valid_path(p)) =>
        {
            Err(bad("invalid path list"))
        }
        Message::BaseEntries { entries } if entries.len() > MAX_BATCH => Err(bad("too many entries")),
        Message::TaggedGuests { list }
            if list
                .iter()
                .any(|g| g.tags.len() > MAX_GUEST_TAGS || g.tags.iter().any(|t| t.len() > MAX_TAG)) =>
        {
            Err(bad("too many or too long guest tags"))
        }
        Message::Warnings { samples, .. }
            if samples.len() > MAX_WARNING_SAMPLES || samples.iter().any(|t| t.len() > MAX_WARNING_SAMPLE) =>
        {
            Err(bad("too many or too long warning samples"))
        }
        Message::Done { state: Some(s), .. } | Message::Init { state: Some(s), .. } if s.len() > MAX_STATE => {
            Err(bad("state blob too large"))
        }
        Message::ReadFile { path, len, .. } if !valid_path(path) || *len as usize > MAX_DATA => {
            Err(bad("invalid read"))
        }
        Message::Log { text, .. } | Message::Error { message: text, .. } if text.len() > 64 << 10 => {
            Err(bad("log text too long"))
        }
        Message::SnapshotMeta { json }
            if json.len() > MAX_SNAPSHOT_META
                || !serde_json::from_str::<serde_json::Value>(json).is_ok_and(|v| v.is_object()) =>
        {
            Err(bad("snapshot metadata: a JSON object of at most 16 KiB"))
        }
        _ => Ok(()),
    }
}

// ---- manifest -----------------------------------------------------------------

/// A network endpoint a kind's sources connect to; the firewall and the sandbox open
/// exactly these (see [`KindSpec::tcp_targets`]).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Endpoint {
    /// JSON pointer into the source config to the host (a string, or v1.8 an array
    /// of `host[:port]` strings).
    pub host: String,
    /// JSON pointer into the source config to the port (number or numeric string).
    pub port: Option<String>,
    /// Port used when the config has none at `port`.
    pub default_port: u16,
    /// `tcp` or `udp` (UDP endpoints are not opened by the appliance firewall).
    pub proto: String,
    /// v1.3: host used when the config has no (or an empty) value at `host`, e.g. a
    /// fixed cloud API host that a config field may override (national clouds, tests)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_host: Option<String>,
}

/// One restore a kind offers (manifest `restores[]`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RestoreAction {
    /// `[a-z0-9_-]{2,32}`, unique per kind. Reserved: `download` (required; done by
    /// the host, or v1.9 with a `params_schema` by [`Op::Export`]) and `mount` (runs
    /// [`Op::Mount`]); every other id runs [`Op::Restore`].
    pub id: String,
    /// Name shown in the restore dialog.
    pub title: String,
    /// JSON-Schema subset (an object) of the restore's parameters; the UI renders a
    /// form from it. Parameters are visible to operators: never put secrets here.
    #[serde(default)]
    pub params_schema: Option<serde_json::Value>,
    /// An application-specific restore (e.g. point-in-time), shown as such in the UI.
    #[serde(default)]
    pub app_specific: bool,
    /// v1.4: which snapshots the restore is offered for: `guest`
    /// (`plugin-<p>-<sid>-<guest>`), `source` (`plugin-<p>-<sid>`) or `any` (default)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applies_to: Option<String>,
    /// v1.6: the restore may run with the credentials of another source of the same
    /// kind and tenant (job parameter `target_source_id`; e.g. M365 into another
    /// Microsoft 365 tenant). The plugin then sees `target_source_id` in its params.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub target_source: bool,
}

/// Values of [`RestoreAction::applies_to`].
pub const APPLIES_TO: &[&str] = &["guest", "source", "any"];

impl RestoreAction {
    /// Whether the restore may run on a snapshot of a guest (`true`) or of the
    /// whole source (`false`).
    pub fn applies(&self, guest_snapshot: bool) -> bool {
        match self.applies_to.as_deref() {
            Some("guest") => guest_snapshot,
            Some("source") => !guest_snapshot,
            _ => true,
        }
    }
}

/// One source kind a plugin provides (manifest `kinds[]`); sources of it have the
/// catalog kind `plugin:<kind>`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KindSpec {
    /// `[a-z0-9-]{2,32}`, unique in the manifest and across installed plugins.
    pub kind: String,
    /// Name shown in the UI.
    pub title: String,
    /// JSON-Schema subset (an object) of the source config; the UI renders the source
    /// form from it.
    pub config_schema: serde_json::Value,
    /// Top-level properties of `config_schema` that hold secrets (write-only, sealed;
    /// v1.6 also inside lists of objects).
    #[serde(default)]
    pub secret_fields: Vec<String>,
    /// Endpoints the plugin may connect to.
    #[serde(default)]
    pub endpoints: Vec<Endpoint>,
    /// Guest selection, e.g. `{"title": "Databases", "list": true}` (`list`: guests
    /// come from `ListGuests`); `None` = the source is backed up as a whole.
    #[serde(default)]
    pub guests: Option<serde_json::Value>,
    /// Backup properties shown in the UI, e.g. `{"incremental": true, "consistent": "application"}`.
    #[serde(default)]
    pub backup: Option<serde_json::Value>,
    /// Restore actions offered for snapshots of this kind; must contain `download`.
    pub restores: Vec<RestoreAction>,
}

/// `manifest.json` of a plugin bundle (docs/plugin-system.md "Package").
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Manifest {
    /// Plugin id, see [`valid_plugin_id`]; owned by the first publisher that installs it.
    pub id: String,
    /// Display name, 1 to 64 printable characters.
    pub name: String,
    /// `MAJOR.MINOR.PATCH` (digits only); an upgrade must be strictly newer.
    pub version: String,
    /// `[a-z0-9-]{2,32}`; must equal the publisher of the signing key (`nexusbackup`
    /// = project keys only).
    pub publisher: String,
    /// Protocol major version the plugin speaks; must equal [`API`].
    pub api: u32,
    /// Source kinds, at least one.
    pub kinds: Vec<KindSpec>,
    /// Sandbox limits: `network` (`endpoints` default, or `none`), `tmp_mb`,
    /// `memory_mb`, `cpu_quota` (not enforced in v1).
    #[serde(default)]
    pub sandbox: Option<serde_json::Value>,
}

fn valid_ident(s: &str, max: usize) -> bool {
    (2..=max).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !s.starts_with('-')
}

/// Plugin ids additionally have no empty and no all-digit `-` component, so a
/// snapshot source name `plugin-<id>-<source id>[-<guest>]` parses unambiguously
/// (the first all-digit component is the source id), see [`parse_source_name`].
pub fn valid_plugin_id(s: &str) -> bool {
    valid_ident(s, 32)
        && s.split('-')
            .all(|c| !c.is_empty() && !c.bytes().all(|b| b.is_ascii_digit()))
}

/// Guest ids (ListGuests, group guests): `[A-Za-z0-9._-]{1,64}`, not starting with `.`/`-`;
/// they become part of the snapshot source name.
pub fn valid_guest_id(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && !s.starts_with(['.', '-'])
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// Snapshot source of a plugin source (`plugin-<id>-<source id>`) or of one of its
/// guests (`plugin-<id>-<source id>-<guest>`).
pub fn source_name(plugin: &str, source_id: u64, guest: Option<&str>) -> String {
    match guest {
        Some(g) => format!("plugin-{plugin}-{source_id}-{g}"),
        None => format!("plugin-{plugin}-{source_id}"),
    }
}

/// Inverse of [`source_name`]: (plugin id, source id, guest).
pub fn parse_source_name(s: &str) -> Option<(String, u64, Option<String>)> {
    let rest = s.strip_prefix("plugin-")?;
    let parts: Vec<&str> = rest.split('-').collect();
    let i = parts
        .iter()
        .position(|c| !c.is_empty() && c.len() <= 19 && c.bytes().all(|b| b.is_ascii_digit()))?;
    let id = parts[..i].join("-");
    let sid: u64 = parts[i].parse().ok()?;
    let guest = (i + 1 < parts.len()).then(|| parts[i + 1..].join("-"));
    (valid_plugin_id(&id) && guest.as_deref().is_none_or(valid_guest_id)).then_some((id, sid, guest))
}

/// Restore/download view: streams appear below this top-level directory; plugins
/// may not use it as the first component of a file path.
pub const STREAMS_DIR: &str = ".nexus-streams";

/// `host`, `host:port`, `[v6]`, `[v6]:port` or a bare IPv6 address → (host, port);
/// None for an empty host or a bad port.
pub fn split_host_port(s: &str, default_port: u16) -> Option<(String, u16)> {
    let s = s.trim();
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, after) = rest.split_once(']')?;
        match after.strip_prefix(':') {
            Some(p) => (h, Some(p)),
            None if after.is_empty() => (h, None),
            None => return None,
        }
    } else {
        match s.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (h, Some(p)),
            _ => (s, None),
        }
    };
    let port = match port {
        Some(p) => p.parse().ok().filter(|p| *p > 0)?,
        None => default_port,
    };
    (!host.is_empty()).then(|| (host.to_owned(), port))
}

impl KindSpec {
    /// (host, port) of the TCP endpoints configured in `cfg`: host from the config
    /// (else `default_host`; unconfigured endpoints without one are skipped), port from
    /// the config (else `default_port`). v1.8: a pointer to an array of strings yields
    /// one target per item, each `host` or `host:port` (`[v6]:port`); the port of an
    /// item without one comes from the endpoint's port field. The appliance firewall
    /// opens these.
    pub fn tcp_targets(&self, cfg: &serde_json::Value) -> Vec<(String, u16)> {
        let mut out = Vec::new();
        for e in self.endpoints.iter().filter(|e| e.proto == "tcp") {
            let port = e
                .port
                .as_deref()
                .and_then(|p| cfg.pointer(p))
                .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
                .and_then(|p| u16::try_from(p).ok())
                .unwrap_or(e.default_port);
            match cfg.pointer(&e.host) {
                Some(serde_json::Value::Array(items)) => {
                    out.extend(items.iter().filter_map(|v| split_host_port(v.as_str()?, port)));
                }
                v => {
                    let host = v
                        .and_then(|v| v.as_str())
                        .map(|h| h.trim_matches(['[', ']']))
                        .filter(|h| !h.is_empty())
                        .or(e.default_host.as_deref());
                    if let Some(h) = host {
                        out.push((h.to_owned(), port));
                    }
                }
            }
        }
        out
    }

    /// TCP ports of [`KindSpec::tcp_targets`]: the plugin's connect allow-list (Landlock).
    pub fn tcp_ports(&self, cfg: &serde_json::Value) -> Vec<u16> {
        let mut ports: Vec<u16> = self.tcp_targets(cfg).into_iter().map(|(_, p)| p).collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }
}

/// Host names a manifest may name literally (`default_host`): DNS names only
/// (no IP literals, no wildcards), so the firewall resolves them like config hosts.
fn valid_fixed_host(h: &str) -> bool {
    (1..=253).contains(&h.len())
        && h.split('.').count() >= 2
        && h.split('.').all(|l| {
            (1..=63).contains(&l.len())
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
        && !h.bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

impl Manifest {
    /// Static checks before a bundle is accepted (signature is checked separately).
    pub fn validate(&self) -> Result<(), String> {
        if !valid_plugin_id(&self.id) {
            return Err("id: [a-z0-9-]{2,32}, no empty or all-digit `-` component".into());
        }
        if self.api != API {
            return Err(format!("api {} not supported (appliance speaks {API})", self.api));
        }
        if !semver_like(&self.version) {
            return Err("version: MAJOR.MINOR.PATCH".into());
        }
        if self.kinds.is_empty() {
            return Err("kinds: at least one".into());
        }
        if self.name.is_empty() || self.name.len() > 64 || self.name.chars().any(char::is_control) {
            return Err("name: 1..=64 printable characters".into());
        }
        if !valid_ident(&self.publisher, 32) {
            return Err("publisher: [a-z0-9-]{2,32}".into());
        }
        let mut kinds = std::collections::HashSet::new();
        for k in &self.kinds {
            if !valid_ident(&k.kind, 32) {
                return Err(format!("kind {:?}: [a-z0-9-]{{2,32}}", k.kind));
            }
            if !kinds.insert(k.kind.as_str()) {
                return Err(format!("kind {}: listed twice", k.kind));
            }
            let mut ids = std::collections::HashSet::new();
            for r in &k.restores {
                let id_ok = (2..=32).contains(&r.id.len())
                    && r.id
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
                if !id_ok || !ids.insert(r.id.as_str()) {
                    return Err(format!(
                        "kind {}: restore id {:?} invalid or listed twice",
                        k.kind, r.id
                    ));
                }
                if r.applies_to.as_deref().is_some_and(|a| !APPLIES_TO.contains(&a)) {
                    return Err(format!(
                        "kind {}: restore {}: applies_to must be guest, source or any",
                        k.kind, r.id
                    ));
                }
                if r.params_schema.as_ref().is_some_and(|p| !p.is_object()) {
                    return Err(format!(
                        "kind {}: restore {}: params_schema must be an object",
                        k.kind, r.id
                    ));
                }
            }
            for f in &k.secret_fields {
                if k.config_schema["properties"].get(f).is_none() {
                    return Err(format!("kind {}: secret field {f:?} is not a config property", k.kind));
                }
            }
            if !k.config_schema.is_object() {
                return Err(format!("kind {}: config_schema must be an object", k.kind));
            }
            if !k.restores.iter().any(|r| r.id == "download") {
                return Err(format!(
                    "kind {}: the generic `download` restore must be listed",
                    k.kind
                ));
            }
            for e in &k.endpoints {
                if !e.host.starts_with('/') || e.port.as_ref().is_some_and(|p| !p.starts_with('/')) {
                    return Err(format!("kind {}: endpoints use JSON pointers", k.kind));
                }
                if e.proto != "tcp" && e.proto != "udp" {
                    return Err(format!("kind {}: endpoint proto tcp|udp", k.kind));
                }
                if e.default_host.as_deref().is_some_and(|h| !valid_fixed_host(h)) {
                    return Err(format!("kind {}: endpoint default_host must be a DNS name", k.kind));
                }
            }
        }
        Ok(())
    }

    /// Source kind as stored in the catalog: `plugin:<kind>`.
    pub fn source_kind(kind: &str) -> String {
        format!("plugin:{kind}")
    }
}

fn semver_like(v: &str) -> bool {
    let p: Vec<_> = v.split('.').collect();
    p.len() == 3
        && p.iter()
            .all(|x| !x.is_empty() && x.len() <= 6 && x.bytes().all(|b| b.is_ascii_digit()))
}

/// Strictly newer version (numeric MAJOR.MINOR.PATCH).
pub fn newer(a: &str, than: &str) -> bool {
    let n = |v: &str| v.split('.').map(|x| x.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    n(a) > n(than)
}

/// Bundle reader/packer and signatures (feature `bundle`).
#[cfg(feature = "bundle")]
pub mod bundle;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_names() {
        assert_eq!(source_name("example-files", 5, None), "plugin-example-files-5");
        assert_eq!(
            parse_source_name("plugin-example-files-5"),
            Some(("example-files".into(), 5, None))
        );
        assert_eq!(
            parse_source_name("plugin-postgresql-12-db-1"),
            Some(("postgresql".into(), 12, Some("db-1".into())))
        );
        assert_eq!(
            parse_source_name(&source_name("pg", 7, Some("2024"))),
            Some(("pg".into(), 7, Some("2024".into())))
        );
        for bad in [
            "plugin-",
            "plugin-x",
            "plugin-5",
            "vm-100",
            "plugin-a-b",
            "plugin-ab-1-.x",
            "plugin-Ab-1",
        ] {
            assert_eq!(parse_source_name(bad), None, "{bad}");
        }
        assert!(valid_plugin_id("example-files") && !valid_plugin_id("pg-15") && !valid_plugin_id("a--b"));
        assert!(valid_guest_id("db_1.x") && !valid_guest_id("-x") && !valid_guest_id("a/b") && !valid_guest_id(""));
    }

    /// v1.9: `Output` is appended after `SnapshotMeta` (27), `Op::Export` after `Mount`;
    /// output names are relative paths outside the streams dir, files at most 64 GiB.
    #[test]
    fn export_output() {
        let m = Message::Output {
            name: "mail/Inbox.mbox".into(),
            offset: 7,
            bytes: b"From x".to_vec(),
        };
        let mut buf = Vec::new();
        write_msg(&mut buf, &m).unwrap();
        assert_eq!(buf[4], 27, "wire index: after SnapshotMeta (26)");
        assert_eq!(read_msg(&mut &buf[..]).unwrap(), m);
        assert_eq!(postcard::to_stdvec(&Op::Export).unwrap(), [5]);
        let bad = |name: &str, offset: u64| {
            check(&Message::Output {
                name: name.into(),
                offset,
                bytes: vec![0; 10],
            })
            .is_err()
        };
        assert!(!bad("a/b.pst", 0) && !bad("x", MAX_OUTPUT_FILE - 10));
        for n in ["", "/abs", "a/../b", ".nexus-streams/x", "a//b"] {
            assert!(bad(n, 0), "{n:?}");
        }
        assert!(bad("x", MAX_OUTPUT_FILE - 9) && bad("x", u64::MAX));
    }

    /// v1.5 tags are a new appended variant: a v1.4 plugin's `Guests` frame is byte
    /// for byte what it was (old plugins keep working), `TaggedGuests` round-trips and
    /// its limits hold.
    /// v1.8: `SnapshotMeta` is appended after `Warnings` (v1.7); both indices are pinned so
    /// neither changes for a host or plugin built on the other; only small JSON objects pass.
    #[test]
    fn snapshot_meta() {
        let m = Message::SnapshotMeta {
            json: r#"{"recoverable":{"from_time":1}}"#.into(),
        };
        let mut buf = Vec::new();
        write_msg(&mut buf, &m).unwrap();
        assert_eq!(buf[4], 26, "wire index: after Warnings (25)");
        let mut w = Vec::new();
        write_msg(
            &mut w,
            &Message::Warnings {
                count: 1,
                samples: vec![],
            },
        )
        .unwrap();
        assert_eq!(w[4], 25, "Warnings keeps its index");
        assert_eq!(read_msg(&mut &buf[..]).unwrap(), m);
        for bad in ["[1]", "nope", r#""x""#] {
            assert!(check(&Message::SnapshotMeta { json: bad.into() }).is_err(), "{bad}");
        }
        let big = format!(r#"{{"a":"{}"}}"#, "x".repeat(MAX_SNAPSHOT_META));
        assert!(check(&Message::SnapshotMeta { json: big }).is_err());
    }

    #[test]
    fn tagged_guests_are_wire_compatible() {
        let g = Guest {
            id: "db".into(),
            title: "D".into(),
            size: Some(5),
        };
        let mut buf = Vec::new();
        write_msg(&mut buf, &Message::Guests { list: vec![g.clone()] }).unwrap();
        // length 9 | variant 3 | 1 guest | "db" | "D" | Some(5)
        assert_eq!(buf, [0, 0, 0, 9, 3, 1, 2, b'd', b'b', 1, b'D', 1, 5]);
        assert_eq!(
            read_msg(&mut &buf[..]).unwrap(),
            Message::Guests { list: vec![g.clone()] }
        );
        let mut t = TaggedGuest::from(g.clone());
        t.tags = vec!["type:user".into(), "license:none".into()];
        let m = Message::TaggedGuests { list: vec![t.clone()] };
        buf.clear();
        write_msg(&mut buf, &m).unwrap();
        assert_eq!(read_msg(&mut &buf[..]).unwrap(), m);
        assert_eq!(Guest::from(t.clone()), g);
        t.tags = vec!["x".repeat(MAX_TAG + 1)];
        assert!(check(&Message::TaggedGuests { list: vec![t.clone()] }).is_err());
        t.tags = vec!["t".into(); MAX_GUEST_TAGS + 1];
        assert!(check(&Message::TaggedGuests { list: vec![t] }).is_err());
    }

    /// v1.7 warnings: appended (wire index after `TaggedGuests`; `Done` unchanged), limits hold.
    #[test]
    fn warnings_are_appended() {
        let m = Message::Warnings {
            count: 3,
            samples: vec!["mail/x.eml: 500".into()],
        };
        let mut buf = Vec::new();
        write_msg(&mut buf, &m).unwrap();
        assert_eq!(buf[4], 25, "variant index after TaggedGuests (24)");
        assert_eq!(read_msg(&mut &buf[..]).unwrap(), m);
        let many = Message::Warnings {
            count: 99,
            samples: vec!["x".into(); MAX_WARNING_SAMPLES + 1],
        };
        assert!(check(&many).is_err());
        let long = Message::Warnings {
            count: 1,
            samples: vec!["x".repeat(MAX_WARNING_SAMPLE + 1)],
        };
        assert!(check(&long).is_err());
    }

    #[test]
    fn framing_and_limits() {
        let m = Message::FileBegin {
            path: b"base/16384/1259".to_vec(),
            meta: Meta {
                size: 8192,
                ..Default::default()
            },
        };
        let mut buf = Vec::new();
        write_msg(&mut buf, &m).unwrap();
        assert_eq!(read_msg(&mut &buf[..]).unwrap(), m);
        for bad_path in [&b"/etc/passwd"[..], b"a/../b", b"a//b", b"./a", b"a\0b", b""] {
            let mut buf = Vec::new();
            write_msg(
                &mut buf,
                &Message::FileBegin {
                    path: bad_path.to_vec(),
                    meta: Meta::default(),
                },
            )
            .unwrap();
            assert!(read_msg(&mut &buf[..]).is_err(), "{bad_path:?}");
        }
        let mut buf = Vec::new();
        write_msg(
            &mut buf,
            &Message::Stream {
                name: "db/app/dump.sql".into(),
            },
        )
        .unwrap();
        assert!(read_msg(&mut &buf[..]).is_ok());
        let mut buf = Vec::new();
        write_msg(&mut buf, &Message::Stream { name: "../x".into() }).unwrap();
        assert!(read_msg(&mut &buf[..]).is_err());
        for (after, ok) in [
            (None, true),
            (Some(b"mail/Inbox".to_vec()), true),
            (Some(b"../x".to_vec()), false),
        ] {
            let mut buf = Vec::new();
            write_msg(&mut buf, &Message::BaseList { after }).unwrap();
            assert_eq!(read_msg(&mut &buf[..]).is_ok(), ok);
        }
        let mut big = ((MAX_FRAME + 1) as u32).to_be_bytes().to_vec();
        big.extend([0u8; 8]);
        assert!(read_msg(&mut &big[..]).is_err());
    }

    #[test]
    fn manifest_validation() {
        let m: Manifest = serde_json::from_value(serde_json::json!({
            "id": "postgresql", "name": "PostgreSQL", "version": "1.0.0", "publisher": "nexusbackup", "api": 1,
            "kinds": [{"kind": "postgresql", "title": "PostgreSQL server",
                       "config_schema": {"type": "object", "properties": {"host": {"type": "string"}, "port": {"type": "integer"}, "password": {"type": "string"}}},
                       "secret_fields": ["password"],
                       "endpoints": [{"host": "/host", "port": "/port", "default_port": 5432, "proto": "tcp"}],
                       "restores": [{"id": "download", "title": "Download"}, {"id": "to_target", "title": "Restore"}]}]
        }))
        .unwrap();
        assert_eq!(m.validate(), Ok(()));
        let k = &m.kinds[0];
        assert_eq!(k.tcp_ports(&serde_json::json!({"host": "db", "port": 6432})), [6432]);
        assert_eq!(k.tcp_ports(&serde_json::json!({"host": "db"})), [5432]);
        assert!(k.tcp_ports(&serde_json::json!({})).is_empty(), "unconfigured endpoint");
        assert!(k.tcp_ports(&serde_json::json!({"host": ""})).is_empty(), "empty host");
        // v1.3: fixed default hosts (overridable by the config field the pointer names)
        let mut fixed = m.clone();
        fixed.kinds[0].endpoints.push(Endpoint {
            host: "/api_host".into(),
            port: Some("/port".into()),
            default_port: 443,
            proto: "tcp".into(),
            default_host: Some("graph.microsoft.com".into()),
        });
        assert_eq!(fixed.validate(), Ok(()));
        let f = &fixed.kinds[0];
        assert_eq!(
            f.tcp_targets(&serde_json::json!({})),
            [("graph.microsoft.com".into(), 443)]
        );
        assert_eq!(
            f.tcp_targets(&serde_json::json!({"host": "db", "api_host": "127.0.0.1", "port": 8443})),
            [("db".into(), 8443), ("127.0.0.1".into(), 8443)]
        );
        assert_eq!(f.tcp_ports(&serde_json::json!({"api_host": ""})), [443]);
        // v1.8: arrays of `host[:port]` (PostgreSQL HA hosts)
        let mut ha = m.clone();
        ha.kinds[0].endpoints.push(Endpoint {
            host: "/hosts".into(),
            port: Some("/port".into()),
            default_port: 5432,
            proto: "tcp".into(),
            default_host: None,
        });
        assert_eq!(
            ha.kinds[0].tcp_targets(&serde_json::json!({"host": "a", "port": 6432,
                "hosts": ["b", "c:5433", "[fd00::1]:5434", "fd00::2", "", "d:x", 7]})),
            [
                ("a".into(), 6432),
                ("b".into(), 6432),
                ("c".into(), 5433),
                ("fd00::1".into(), 5434),
                ("fd00::2".into(), 6432)
            ]
        );
        assert_eq!(split_host_port("[::1]", 1), Some(("::1".into(), 1)));
        assert_eq!(split_host_port("h:0", 1), None);
        assert_eq!(split_host_port("[::1]x", 1), None);
        for bad_host in ["1.2.3.4", "*.example.com", "localhost", "a..b", "-a.b", "a b.c"] {
            let mut bad = fixed.clone();
            bad.kinds[0].endpoints[1].default_host = Some(bad_host.into());
            assert!(bad.validate().is_err(), "{bad_host}");
        }
        let mut bad = m.clone();
        bad.id = "Bad_ID".into();
        assert!(bad.validate().is_err());
        let mut bad = m.clone();
        bad.kinds[0].restores.clear();
        assert!(bad.validate().is_err(), "download is mandatory");
        let mut bad = m.clone();
        bad.api = 2;
        assert!(bad.validate().is_err());
        assert!(newer("1.10.0", "1.9.9") && !newer("1.0.0", "1.0.0"));
        let mut bad = m.clone();
        bad.id = "pg-15".into();
        assert!(
            bad.validate().is_err(),
            "all-digit component makes source names ambiguous"
        );
        let mut bad = m.clone();
        bad.kinds[0].secret_fields.push("nope".into());
        assert!(bad.validate().is_err(), "secret fields must be config properties");
        assert_eq!(Manifest::source_kind("postgresql"), "plugin:postgresql");
        // v1.4: applies_to
        let r = &m.kinds[0].restores[1];
        assert!(r.applies(true) && r.applies(false), "default any");
        let mut v14 = m.clone();
        v14.kinds[0].restores[1].applies_to = Some("guest".into());
        assert_eq!(v14.validate(), Ok(()));
        let r = &v14.kinds[0].restores[1];
        assert!(r.applies(true) && !r.applies(false));
        v14.kinds[0].restores[1].applies_to = Some("source".into());
        let r = &v14.kinds[0].restores[1];
        assert!(!r.applies(true) && r.applies(false));
        v14.kinds[0].restores[1].applies_to = Some("guests".into());
        assert!(v14.validate().is_err());
        // older manifests (no field) serialize as before
        assert!(!serde_json::to_string(&m).unwrap().contains("applies_to"));
    }

    /// The shipped PostgreSQL manifest: dumps restore per database, PITR per cluster.
    #[test]
    fn postgresql_manifest_applies_to() {
        let m: Manifest = serde_json::from_str(include_str!("../../../plugins/postgresql/manifest.json")).unwrap();
        assert_eq!(m.validate(), Ok(()));
        let r = |id: &str| {
            m.kinds[0]
                .restores
                .iter()
                .find(|r| r.id == id)
                .unwrap()
                .applies_to
                .clone()
        };
        assert_eq!(r("to_target").as_deref(), Some("guest"));
        assert_eq!(r("pitr").as_deref(), Some("source"));
        assert_eq!(r("download"), None);
    }

    /// The shipped MySQL/MariaDB manifest (Phase 23b): valid, same restore split as PostgreSQL.
    #[test]
    fn mysql_manifest() {
        let m: Manifest = serde_json::from_str(include_str!("../../../plugins/mysql/manifest.json")).unwrap();
        assert_eq!(m.validate(), Ok(()));
        let k = &m.kinds[0];
        let r = |id: &str| k.restores.iter().find(|r| r.id == id).unwrap().applies_to.clone();
        assert_eq!(r("to_target").as_deref(), Some("guest"));
        assert_eq!(r("pitr").as_deref(), Some("source"));
        assert_eq!(Manifest::source_kind(&k.kind), "plugin:mysql");
    }
}
