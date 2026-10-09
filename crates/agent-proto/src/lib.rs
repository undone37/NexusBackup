//! Wire protocol between the appliance and `nexus-agent` (docs/agent-protocol.md).
//! Framing: `u32 BE length | postcard(Message)`, max `MAX_FRAME`.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io::{self, Read, Write};

pub const VERSION: u32 = 1;
pub const DEFAULT_PORT: u16 = 7444;
pub const ALPN: &[u8] = b"nexus-agent/1";
pub const MAX_FRAME: usize = 8 << 20;
pub const MAX_CHUNK: usize = 4 << 20;
pub const MAX_BATCH: usize = 10_000;
pub const MAX_PATH: usize = 4096;
pub const MAX_XATTR: usize = 64 << 10;
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
        Message::Want { hashes, .. } if hashes.len() > MAX_BATCH => return Err(bad("want list too long")),
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

/// Enrollment proof bound to one TLS session (`exporter` = TLS keying material
/// exported with `EXPORTER_LABEL`, 32 bytes). `role` is "appliance" or "agent".
pub fn enroll_proof(token: &str, role: &str, exporter: &[u8; 32]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(token.trim().as_bytes()).expect("hmac accepts any key");
    mac.update(role.as_bytes());
    mac.update(b"\0");
    mac.update(exporter);
    mac.finalize().into_bytes().into()
}

/// What both sides store instead of the enrollment token: lowercase hex of
/// `sha256(token.trim())`. Neither side keeps the plain token after `init` / creation,
/// so this string is the HMAC key passed to [`enroll_proof`] on both sides.
pub fn token_hash(token: &str) -> String {
    use sha2::Digest;
    Sha256::digest(token.trim().as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
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
    fn proofs_bind_token_role_and_session() {
        let ex = [7u8; 32];
        let a = enroll_proof("TOKEN", "appliance", &ex);
        assert!(proof_eq(&a, &enroll_proof("TOKEN\n", "appliance", &ex)));
        assert!(!proof_eq(&a, &enroll_proof("TOKEN", "agent", &ex)));
        assert!(!proof_eq(&a, &enroll_proof("OTHER", "appliance", &ex)));
        assert!(!proof_eq(&a, &enroll_proof("TOKEN", "appliance", &[8u8; 32])));
    }

    #[test]
    fn token_hash_is_hex_sha256_of_trimmed_token() {
        let h = token_hash(" abc\n");
        assert_eq!(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
