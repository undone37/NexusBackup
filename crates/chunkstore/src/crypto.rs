//! Tenant keys, keyed chunk IDs and the sealed blob format shared by chunks,
//! indexes and manifests (dedup -> compress -> encrypt).
//!
//! Sealed blob: `MAGIC(4) | flags(1) | key_version(u32 LE) | nonce(24) | ciphertext+tag`.
//! AAD = header(9) | tenant | context, so a blob cannot be swapped between
//! tenants, chunk IDs or index names without failing authentication.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use std::io;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub type ChunkId = [u8; 32];

const MAGIC: &[u8; 4] = b"NXB1";
const HEADER: usize = 4 + 1 + 4 + 24;
const FLAG_ZSTD: u8 = 1;

pub fn hex(id: &ChunkId) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn parse_hex(s: &str) -> Option<ChunkId> {
    if s.len() != 64 {
        return None;
    }
    let mut id = [0u8; 32];
    for (i, b) in id.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(id)
}

pub(crate) fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Fresh random 256-bit key (DEK, KEK or recovery key).
pub fn generate_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    OsRng.fill_bytes(&mut k);
    k
}

/// Wrap a key under another key (DEK under KEK, KEK under recovery key).
pub fn wrap_key(kek: &[u8; 32], key: &[u8; 32], label: &str) -> Vec<u8> {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new(kek.into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: key,
                aad: label.as_bytes(),
            },
        )
        .expect("xchacha encrypt cannot fail");
    [nonce.as_slice(), &ct].concat()
}

pub fn unwrap_key(kek: &[u8; 32], wrapped: &[u8], label: &str) -> io::Result<[u8; 32]> {
    if wrapped.len() != 24 + 32 + 16 {
        return Err(invalid("wrapped key has wrong length"));
    }
    let (nonce, ct) = wrapped.split_at(24);
    let mut pt = XChaCha20Poly1305::new(kek.into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: label.as_bytes(),
            },
        )
        .map_err(|_| invalid("key unwrap failed (wrong key or tampered)"))?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&pt);
    pt.zeroize();
    Ok(key)
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct TenantKey {
    id_key: [u8; 32],
    aead_key: [u8; 32],
}

impl TenantKey {
    fn from_dek(dek: &[u8; 32]) -> Self {
        TenantKey {
            id_key: blake3::derive_key("NexusBackup 2026 chunk-id v1", dek),
            aead_key: blake3::derive_key("NexusBackup 2026 aead v1", dek),
        }
    }
}

/// All DEK versions of one tenant. New data uses the highest version; older
/// versions stay readable.
// ponytail: chunk IDs are keyed by the writing key version, so a DEK rotation
// means one full re-store of new chunks (no dedup against pre-rotation chunks).
pub struct Keyring {
    tenant: String,
    current: u32,
    keys: HashMap<u32, TenantKey>,
}

impl Keyring {
    pub fn new(tenant: &str, deks: &[(u32, [u8; 32])]) -> Self {
        assert!(!deks.is_empty(), "keyring needs at least one DEK");
        Keyring {
            tenant: tenant.to_owned(),
            current: deks.iter().map(|(v, _)| *v).max().unwrap(),
            keys: deks.iter().map(|(v, k)| (*v, TenantKey::from_dek(k))).collect(),
        }
    }

    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    pub fn chunk_id(&self, data: &[u8]) -> ChunkId {
        self.chunk_id_v(self.current, data).unwrap()
    }

    fn chunk_id_v(&self, version: u32, data: &[u8]) -> Option<ChunkId> {
        Some(blake3::keyed_hash(&self.keys.get(&version)?.id_key, data).into())
    }

    fn aad(&self, header: &[u8], ctx: &[u8]) -> Vec<u8> {
        [header, self.tenant.as_bytes(), b"\0", ctx].concat()
    }

    pub fn seal(&self, ctx: &[u8], plain: &[u8]) -> Vec<u8> {
        let z = zstd::bulk::compress(plain, 3).expect("zstd compress");
        let (flags, body) = if z.len() < plain.len() {
            (FLAG_ZSTD, z.as_slice())
        } else {
            (0, plain)
        };
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let mut out = Vec::with_capacity(HEADER + body.len() + 16);
        out.extend_from_slice(MAGIC);
        out.push(flags);
        out.extend_from_slice(&self.current.to_le_bytes());
        out.extend_from_slice(&nonce);
        let aad = self.aad(&out[..9], ctx);
        let key = &self.keys[&self.current].aead_key;
        let ct = XChaCha20Poly1305::new(key.into())
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: body, aad: &aad })
            .expect("xchacha encrypt cannot fail");
        out.extend_from_slice(&ct);
        out
    }

    /// Returns (key version, plaintext). Fails on any tampering.
    pub fn open(&self, ctx: &[u8], sealed: &[u8]) -> io::Result<(u32, Vec<u8>)> {
        if sealed.len() < HEADER + 16 || &sealed[..4] != MAGIC {
            return Err(invalid("not a sealed blob"));
        }
        let flags = sealed[4];
        let version = u32::from_le_bytes(sealed[5..9].try_into().unwrap());
        let key = self
            .keys
            .get(&version)
            .ok_or_else(|| invalid(format!("unknown key version {version}")))?;
        let aad = self.aad(&sealed[..9], ctx);
        let body = XChaCha20Poly1305::new((&key.aead_key).into())
            .decrypt(
                XNonce::from_slice(&sealed[9..HEADER]),
                Payload {
                    msg: &sealed[HEADER..],
                    aad: &aad,
                },
            )
            .map_err(|_| invalid("authentication failed"))?;
        let plain = match flags {
            0 => body,
            FLAG_ZSTD => zstd::stream::decode_all(body.as_slice())?,
            _ => return Err(invalid("unknown flags")),
        };
        Ok((version, plain))
    }

    pub fn seal_chunk(&self, id: &ChunkId, data: &[u8]) -> Vec<u8> {
        self.seal(id, data)
    }

    /// Decrypts and re-derives the keyed hash, so every read is a full verify.
    pub fn open_chunk(&self, id: &ChunkId, sealed: &[u8]) -> io::Result<Vec<u8>> {
        let (version, data) = self.open(id, sealed)?;
        if self.chunk_id_v(version, &data) != Some(*id) {
            return Err(invalid(format!("chunk {} hash mismatch", hex(id))));
        }
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_roundtrip_and_tamper() {
        let k = Keyring::new("t1", &[(1, [7; 32])]);
        let data = vec![42u8; 100_000];
        let id = k.chunk_id(&data);
        let mut sealed = k.seal_chunk(&id, &data);
        assert!(sealed.len() < 1000, "compressible data is compressed");
        assert_eq!(k.open_chunk(&id, &sealed).unwrap(), data);
        // other tenant with same DEK cannot open (AAD binds tenant)
        assert!(Keyring::new("t2", &[(1, [7; 32])]).open_chunk(&id, &sealed).is_err());
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(k.open_chunk(&id, &sealed).is_err());
    }

    #[test]
    fn rotation_keeps_old_readable() {
        let old = Keyring::new("t", &[(1, [1; 32])]);
        let id = old.chunk_id(b"abc");
        let sealed = old.seal_chunk(&id, b"abc");
        let new = Keyring::new("t", &[(1, [1; 32]), (2, [2; 32])]);
        assert_eq!(new.open_chunk(&id, &sealed).unwrap(), b"abc");
        assert_ne!(new.chunk_id(b"abc"), id);
    }

    #[test]
    fn key_wrap() {
        let (kek, dek) = (generate_key(), generate_key());
        let w = wrap_key(&kek, &dek, "tenant-dek:t1:v1");
        assert_eq!(unwrap_key(&kek, &w, "tenant-dek:t1:v1").unwrap(), dek);
        assert!(unwrap_key(&kek, &w, "tenant-dek:t2:v1").is_err());
        assert!(unwrap_key(&generate_key(), &w, "tenant-dek:t1:v1").is_err());
        assert_eq!(parse_hex(&hex(&dek)), Some(dek));
    }
}
