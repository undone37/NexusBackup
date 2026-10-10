//! `nexus-pluginhost` (docs/plugin-system.md): the trusted side of a plugin.
//!
//! A plugin is untrusted code. It only speaks the framed protocol of crate
//! `plugin-proto` on its stdin/stdout; everything security relevant happens here:
//! verification of the installed binary, the sandbox ([`sandbox`]), validation of
//! every message (limits, paths, ordering), chunking/sealing/dedup into the tenant
//! store, `Unchanged` reuse only from the base snapshot's own entries, commit with
//! the manifest last, serving restores/mounts from the store, escaping of
//! everything the plugin says before it reaches the job log.

pub mod backup;
pub mod files;
pub mod inproc;
pub mod landlock;
pub mod ops;
pub mod restore;
pub mod sandbox;
pub mod seccomp;

use plugin_proto::{Kind, Manifest, Meta};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static LOG_STDERR: AtomicBool = AtomicBool::new(false);

/// Ops whose stdout is their JSON result (validate, guests) log to stderr.
pub fn set_log_stderr(on: bool) {
    LOG_STDERR.store(on, Ordering::Relaxed);
}

/// One line for the job log (stdout, or stderr, see [`set_log_stderr`]).
pub fn log_line(l: &str) {
    if LOG_STDERR.load(Ordering::Relaxed) {
        eprintln!("{l}");
    } else {
        println!("{l}");
    }
}

/// TCP ports of a kind's endpoints, resolved in the source config (the sandbox's
/// Landlock connect rules). None: unknown kind; empty: `sandbox.network = "none"`.
pub fn endpoint_ports(manifest: &Manifest, kind: &str, cfg: &serde_json::Value) -> Option<Vec<u16>> {
    let net = manifest
        .sandbox
        .as_ref()
        .and_then(|s| s["network"].as_str())
        .unwrap_or("endpoints");
    if net == "none" {
        return Some(Vec::new());
    }
    Some(manifest.kinds.iter().find(|k| k.kind == kind)?.tcp_ports(cfg))
}

/// Index names of a plugin snapshot.
pub const FILES_INDEX: &str = "files";
pub const STREAMS_INDEX: &str = "streams";
/// The plugin's opaque state blob (≤ 1 MiB): a dynamic index with one entry whose
/// chunks hold the blob (sealed like every chunk; replicated/offsited with the snapshot).
pub const STATE_INDEX: &str = "state";

/// Time limits of one operation.
#[derive(Clone, Copy, Debug)]
pub struct Timeouts {
    /// whole operation
    pub op: Duration,
    /// between two messages of the plugin
    pub idle: Duration,
}

impl Timeouts {
    pub fn for_op(op: plugin_proto::Op) -> Timeouts {
        use plugin_proto::Op::*;
        match op {
            Validate | ListGuests => Timeouts {
                op: Duration::from_secs(300),
                idle: Duration::from_secs(120),
            },
            Backup | Restore => Timeouts {
                op: Duration::from_secs(24 * 3600),
                idle: Duration::from_secs(900),
            },
            Mount => Timeouts {
                op: Duration::from_secs(24 * 3600 + 600),
                idle: Duration::from_secs(900),
            },
        }
    }
}

/// Plugin text for the job log: control characters escaped (no forged lines,
/// no terminal escapes), bounded. Callers prefix it, so it never starts a line
/// the scheduler parses (`committed …`, `inconsistent …`).
pub fn escape(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max) + 8);
    for (i, c) in s.chars().enumerate() {
        if i >= max {
            out.push('…');
            break;
        }
        if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}' | '\u{202e}' | '\u{200b}') {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

pub fn level_name(l: u8) -> &'static str {
    match l {
        0 => "error",
        1 => "warn",
        2 => "info",
        _ => "debug",
    }
}

pub(crate) fn tree_kind(k: Option<Kind>) -> chunkstore::TreeKind {
    use chunkstore::TreeKind as T;
    match k.unwrap_or(Kind::File) {
        Kind::File => T::File,
        Kind::Dir => T::Dir,
        Kind::Symlink => T::Symlink,
        Kind::Hardlink => T::Hardlink,
        Kind::Device => T::Device,
        Kind::Fifo => T::Fifo,
        Kind::Socket => T::Socket,
    }
}

pub(crate) fn proto_kind(k: &chunkstore::TreeKind) -> Kind {
    use chunkstore::TreeKind as T;
    match k {
        T::File => Kind::File,
        T::Dir => Kind::Dir,
        T::Symlink => Kind::Symlink,
        T::Hardlink => Kind::Hardlink,
        T::Device => Kind::Device,
        T::Fifo => Kind::Fifo,
        T::Socket => Kind::Socket,
    }
}

/// Metadata of a stored entry as the plugin sees it.
pub fn meta_of(e: &chunkstore::TreeEntry) -> Meta {
    Meta {
        kind: Some(proto_kind(&e.kind)),
        mode: e.mode,
        uid: e.uid,
        gid: e.gid,
        size: e.size,
        mtime_ns: e.mtime_ns,
        ctime_ns: e.ctime_ns,
        inode: e.inode,
        link_target: e.link_target.clone(),
        xattrs: e.xattrs.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping() {
        assert_eq!(escape("a\nb", 100), "a\\nb");
        assert_eq!(escape("\u{1b}[31mred", 100), "\\u{1b}[31mred");
        assert_eq!(escape("abcdef", 3), "abc…");
        assert!(!escape("x\ncommitted vm-1/2", 100).contains('\n'));
    }
}
