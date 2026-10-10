//! Appliance replication (docs/replication.md): the secondary pulls sealed
//! snapshots from the primary's management port (8443) with an enrolled client
//! certificate; the primary holds no credentials for the secondary.
//!
//! This module (always built) holds the wire protocol shared by nexus-web-api,
//! nexus-replicad and nexus-replica: ALPNs, limits, name validation, the JSON
//! types of the peer API and the web-api ↔ replicad socket protocol. The
//! `daemons` feature adds the replication CA, nexus-replicad (primary) and the
//! client side (secondary).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(feature = "daemons")]
pub mod ca;
#[cfg(feature = "daemons")]
pub mod client;
#[cfg(feature = "daemons")]
pub mod http;
#[cfg(feature = "daemons")]
pub mod replicad;

/// Peer sessions: client certificate required (replication CA, EKU clientAuth).
pub const ALPN_PEER: &[u8] = b"nexus-replication/1";
/// Enrollment: no client certificate; proofs bound to the TLS exporter.
pub const ALPN_ENROLL: &[u8] = b"nexus-replication-enroll/1";
/// `export_keying_material(32, EXPORTER_LABEL, None)` for the enrollment proofs.
pub const EXPORTER_LABEL: &[u8] = b"nexus-replication enroll";
/// Subject CN of a peer certificate: `nexus-replica:<peer-id>`.
pub const CN_PREFIX: &str = "nexus-replica:";
/// URL prefix of the peer API on the primary.
pub const PREFIX: &str = "/replication/v1";

/// Chunk ids per `POST …/chunks`.
pub const MAX_IDS: usize = 1024;
/// Request bodies of the peer API.
pub const MAX_BODY: usize = 64 << 10;
/// Manifest / index files.
pub const MAX_FILE: u64 = 256 << 20;
/// A sealed chunk (4 MiB plain + header/tag, incompressible worst case).
pub const MAX_CHUNK: u64 = (4 << 20) + 4096;
/// Concurrent requests per peer (web-api, 429 above).
pub const MAX_CONCURRENT: usize = 8;
/// Frame length marking a chunk the primary no longer has.
pub const MISSING: u32 = u32::MAX;
/// Failed enrollment proofs before the token is voided.
pub const MAX_ENROLL_FAILURES: i64 = 5;
/// Enrollment token lifetime after the quorum approval.
pub const TOKEN_TTL_SECS: i64 = 24 * 3600;

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

/// Short display fingerprint of a 32-byte public key (`ab12:cd34:…`, 8 groups).
pub fn key_fingerprint(pk: &[u8]) -> String {
    let h = sha256_hex(pk);
    (0..8).map(|i| &h[i * 4..i * 4 + 4]).collect::<Vec<_>>().join(":")
}

/// Tenant / source / index names: the chunk store's path-safe charset.
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && !s.starts_with('.')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// Files of a snapshot directory: `manifest` or `<index name>.idx`.
pub fn valid_file(s: &str) -> bool {
    s == "manifest" || s.strip_suffix(".idx").is_some_and(valid_name)
}

/// Peer ids: 16 lowercase hex characters (chosen by the primary's web-api).
pub fn valid_peer_id(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// 64 lowercase hex (SHA-256 fingerprints, chunk ids).
pub fn valid_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Enrollment code shown once on the primary: `<peer-id>.<token>`.
pub fn split_code(code: &str) -> Option<(&str, &str)> {
    let (id, token) = code.trim().split_once('.')?;
    (valid_peer_id(id) && token.len() >= 16 && token.bytes().all(|b| b.is_ascii_alphanumeric())).then_some((id, token))
}

/// Enrollment proof (docs/replication.md §4): `role` = "secondary" | "primary",
/// `token_digest` = `agent_proto::token_digest(token)`.
pub fn proof(token_digest: &str, role: &str, exporter: &[u8; 32]) -> [u8; 32] {
    agent_proto::enroll_proof(token_digest, role, exporter)
}

pub use agent_proto::{proof_eq, token_digest};

// ---------------------------------------------------------------- peer API types

/// One committed snapshot on the primary (`GET …/tenants/{t}/snapshots`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SnapshotInfo {
    pub source: String,
    pub time: u64,
    /// DEK version of the sealed manifest (clear blob header)
    pub key_version: u32,
    /// `manifest` and `<name>.idx`
    pub files: Vec<String>,
    /// bytes of the sealed manifest + indexes
    pub size: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct EnrollRequest {
    pub peer_id: String,
    /// secondary's host name (display only)
    pub name: String,
    pub csr_pem: String,
    /// secondary keyd's X25519 public key (hex)
    pub keyd_pub: String,
    /// hex of `proof(digest, "secondary", exporter)`
    pub proof: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct EnrollResponse {
    /// hex of `proof(digest, "primary", exporter)`
    pub proof: String,
    pub cert_pem: String,
    pub ca_pem: String,
    pub tenants: Vec<String>,
}

/// `GET …/tenants/{t}/keys`: DEKs sealed to the secondary keyd (hex).
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct KeyExport {
    pub tenant: String,
    pub versions: Vec<u32>,
    pub blob: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct SessionEnd {
    pub snapshots: u64,
    pub chunks: u64,
    pub bytes: u64,
    pub error: Option<String>,
}

// ---------------------------------------------------------------- web-api ↔ replicad

/// One request per Unix-socket connection, one JSON line. `scope` is the peer's
/// tenant list as the web-api found it in the catalog; replicad re-checks it.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    List {
        scope: Vec<String>,
        tenant: String,
    },
    File {
        scope: Vec<String>,
        tenant: String,
        source: String,
        time: u64,
        file: String,
    },
    Chunks {
        scope: Vec<String>,
        tenant: String,
        /// 64 hex each, at most `MAX_IDS`
        ids: Vec<String>,
    },
    /// Checks a secondary's proof and signs its CSR. `token_sealed` is the
    /// peer's `token_hash` (sealed to replicad), `exporter` the TLS exporter of
    /// the enrollment connection (hex).
    Enroll {
        peer_id: String,
        token_sealed: String,
        exporter: String,
        proof: String,
        csr_pem: String,
    },
}

impl Request {
    pub fn check(&self) -> Result<(), String> {
        let scoped = |scope: &[String], t: &str| {
            if !valid_name(t) {
                Err(format!("invalid tenant {t:?}"))
            } else if !scope.iter().any(|s| s == t) {
                Err(format!("tenant {t} is not in the peer's scope"))
            } else {
                Ok(())
            }
        };
        match self {
            Request::List { scope, tenant } => scoped(scope, tenant),
            Request::File {
                scope,
                tenant,
                source,
                file,
                ..
            } => {
                scoped(scope, tenant)?;
                if !valid_name(source) || !valid_file(file) {
                    return Err("invalid snapshot file".into());
                }
                Ok(())
            }
            Request::Chunks { scope, tenant, ids } => {
                scoped(scope, tenant)?;
                if ids.is_empty() || ids.len() > MAX_IDS || !ids.iter().all(|i| valid_hex64(i)) {
                    return Err(format!("1..={MAX_IDS} chunk ids (64 hex) required"));
                }
                Ok(())
            }
            Request::Enroll {
                peer_id,
                exporter,
                proof,
                ..
            } => {
                if !valid_peer_id(peer_id) || !valid_hex64(exporter) || !valid_hex64(proof) {
                    return Err("invalid enrollment request".into());
                }
                Ok(())
            }
        }
    }
}

/// First line of every replicad answer; the body follows until EOF.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// replicad's answer to `Enroll` (JSON body).
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct EnrollOutcome {
    pub proof: String,
    pub cert_pem: String,
    pub ca_pem: String,
    pub cert_sha256: String,
}

/// Parses the 32-byte chunk ids of a `POST …/chunks` body.
pub fn parse_ids(body: &[u8]) -> Result<Vec<String>, String> {
    if body.is_empty() || !body.len().is_multiple_of(32) || body.len() / 32 > MAX_IDS {
        return Err(format!("body must be 1..={MAX_IDS} chunk ids of 32 bytes"));
    }
    Ok(body.chunks(32).map(hex).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_codes() {
        assert!(valid_file("manifest") && valid_file("drive-scsi0.idx") && valid_file("tree.idx"));
        for bad in [
            "",
            "../manifest",
            ".idx",
            "a/b.idx",
            "x.idx.tmp",
            "keycheck",
            ".hidden.idx",
        ] {
            assert!(!valid_file(bad), "{bad}");
        }
        assert!(valid_name("vm-100") && !valid_name("..") && !valid_name("a/b") && !valid_name(""));
        assert_eq!(
            split_code(" 0123456789abcdef.ABCDEFGHIJKLMNOPQRSTUVWXYZ "),
            Some(("0123456789abcdef", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
        );
        assert!(split_code("0123456789abcdef").is_none() && split_code("xyz.ABCDEFGHIJKLMNOPQ").is_none());
        assert_eq!(unhex(&hex(b"\x00\xffab")).unwrap(), b"\x00\xffab");
        assert!(unhex("abc").is_none() && unhex("zz").is_none());
        assert_eq!(key_fingerprint(&[0; 32]).len(), 39);
    }

    #[test]
    fn requests_are_scoped_and_bounded() {
        let scope = vec!["acme".to_string()];
        let list = |t: &str| Request::List {
            scope: scope.clone(),
            tenant: t.into(),
        };
        assert!(list("acme").check().is_ok());
        assert!(list("other").check().is_err());
        assert!(list("../acme").check().is_err());
        let ids = |n: usize| Request::Chunks {
            scope: scope.clone(),
            tenant: "acme".into(),
            ids: vec!["ab".repeat(32); n],
        };
        assert!(ids(1).check().is_ok() && ids(MAX_IDS).check().is_ok());
        assert!(ids(0).check().is_err() && ids(MAX_IDS + 1).check().is_err());
        let file = |s: &str, f: &str| Request::File {
            scope: scope.clone(),
            tenant: "acme".into(),
            source: s.into(),
            time: 1,
            file: f.into(),
        };
        assert!(file("vm-100", "manifest").check().is_ok());
        assert!(file("..", "manifest").check().is_err() && file("vm-100", "../../keycheck").check().is_err());
        // the wire format is one JSON line with an `op` tag; unknown fields are refused
        let l = serde_json::to_string(&list("acme")).unwrap();
        assert!(l.contains("\"op\":\"list\""), "{l}");
        assert!(serde_json::from_str::<Request>(r#"{"op":"list","scope":[],"tenant":"a","x":1}"#).is_err());
        assert_eq!(parse_ids(&[7u8; 64]).unwrap().len(), 2);
        assert!(parse_ids(&[7u8; 33]).is_err() && parse_ids(&[]).is_err());
        assert!(parse_ids(&vec![0u8; 32 * (MAX_IDS + 1)]).is_err());
    }
}
