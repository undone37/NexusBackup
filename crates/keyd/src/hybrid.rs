//! Hybrid post-quantum sealing (Phase 30, docs/adr.md ADR-014): X25519 and
//! ML-KEM-768 (FIPS 203, RustCrypto `ml-kem`, pure Rust) together, for the
//! long-lived secrets that rest outside the appliance under a public key: the
//! tenant recovery escrow (offsite for years), replication DEK exports and the
//! configuration bundles. Data harvested today stays closed unless *both*
//! X25519 and ML-KEM-768 are broken.
//!
//! ```text
//! NXHYB2\0\0 | X25519 ephemeral public (32) | ML-KEM-768 ciphertext (1088)
//!            | nonce (24) | XChaCha20-Poly1305(key, plaintext, aad = label | all bytes before the nonce)
//! key = BLAKE3 derive_key(COMBINER, x25519 shared | ML-KEM shared | ephemeral public
//!                                   | recipient X25519 public | ML-KEM ciphertext)
//! ```
//! The combiner binds both shared secrets to the ciphertext and the recipient
//! (like X-Wing); `label` separates the three uses. The recipient's key pair is
//! an X25519 secret plus an ML-KEM seed derived from it ([`Secret::derive`]), so
//! every existing 32-byte secret (a tenant recovery key, the replication key, the
//! KEK-derived bundle key) gains its post-quantum half without a new secret to
//! keep. A public key is `X25519 public (32) | ML-KEM-768 encapsulation key (1184)`.
//! Blobs without the magic are the X25519-only sealed boxes of earlier releases
//! (`crypto_box`), still opened by the callers.

use crate::err;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use curve25519_dalek::montgomery::MontgomeryPoint;
use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::ml_kem_768::{Ciphertext, DecapsulationKey, EncapsulationKey};
use ml_kem::{Seed, B32};
use rand::RngCore;
use std::io;
use zeroize::Zeroizing;

pub const MAGIC: &[u8; 8] = b"NXHYB2\0\0";
pub const MLKEM_PUBLIC_LEN: usize = 1184;
pub const MLKEM_CT_LEN: usize = 1088;
/// X25519 public + ML-KEM-768 encapsulation key
pub const PUBLIC_LEN: usize = 32 + MLKEM_PUBLIC_LEN;
const HEAD: usize = MAGIC.len() + 32 + MLKEM_CT_LEN;
const COMBINER: &str = "NexusBackup 2026 hybrid seal X25519+ML-KEM-768 v2";

/// Whether `blob` is a hybrid sealed box (else an X25519-only box of an earlier release).
pub fn is_hybrid(blob: &[u8]) -> bool {
    blob.starts_with(MAGIC)
}

/// A recipient's public key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Public {
    pub x25519: [u8; 32],
    pub mlkem: Vec<u8>,
}

impl Public {
    pub fn to_bytes(&self) -> Vec<u8> {
        [&self.x25519[..], &self.mlkem].concat()
    }

    /// `X25519 public | ML-KEM-768 encapsulation key`; the latter is validated (FIPS 203 modulus check).
    pub fn from_bytes(b: &[u8]) -> io::Result<Public> {
        let bad = || err(io::ErrorKind::InvalidInput, "invalid hybrid public key");
        if b.len() != PUBLIC_LEN {
            return Err(bad());
        }
        let p = Public {
            x25519: b[..32].try_into().unwrap(),
            mlkem: b[32..].to_vec(),
        };
        p.encapsulation_key()?;
        Ok(p)
    }

    fn encapsulation_key(&self) -> io::Result<EncapsulationKey> {
        let k = ml_kem::kem::Key::<EncapsulationKey>::try_from(&self.mlkem[..])
            .map_err(|_| err(io::ErrorKind::InvalidInput, "invalid ML-KEM public key"))?;
        EncapsulationKey::new(&k).map_err(|_| err(io::ErrorKind::InvalidInput, "invalid ML-KEM public key"))
    }
}

/// A recipient's secret: an X25519 secret and the ML-KEM key derived from it.
pub struct Secret {
    x25519: Zeroizing<[u8; 32]>,
    dk: DecapsulationKey,
}

impl Secret {
    /// The ML-KEM-768 seed (d | z, 64 bytes) is BLAKE3's derive-key output for
    /// `context` over the X25519 secret: deterministic, nothing new to store.
    pub fn derive(x25519: &[u8; 32], context: &str) -> Secret {
        let mut seed = Zeroizing::new([0u8; 64]);
        blake3::Hasher::new_derive_key(context)
            .update(x25519)
            .finalize_xof()
            .fill(&mut seed[..]);
        Secret {
            x25519: Zeroizing::new(*x25519),
            dk: DecapsulationKey::from_seed(Seed::from(*seed)),
        }
    }

    pub fn public(&self) -> Public {
        Public {
            x25519: MontgomeryPoint::mul_base_clamped(*self.x25519).to_bytes(),
            mlkem: self.dk.encapsulation_key().to_bytes().to_vec(),
        }
    }
}

fn combine(ss_x: &[u8; 32], ss_k: &[u8], eph: &[u8; 32], to_x: &[u8; 32], ct: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut h = blake3::Hasher::new_derive_key(COMBINER);
    h.update(ss_x).update(ss_k).update(eph).update(to_x).update(ct);
    Zeroizing::new(*h.finalize().as_bytes())
}

fn dh(secret: &[u8; 32], public: &[u8; 32]) -> io::Result<Zeroizing<[u8; 32]>> {
    let ss = Zeroizing::new(MontgomeryPoint(*public).mul_clamped(*secret).to_bytes());
    // a low-order point gives an all-zero shared secret: refused
    if ss.iter().all(|b| *b == 0) {
        return Err(err(io::ErrorKind::InvalidInput, "invalid X25519 public key"));
    }
    Ok(ss)
}

/// Seals `plaintext` to `to`; `label` names the use (part of the AAD).
pub fn seal(to: &Public, label: &[u8], plaintext: &[u8]) -> io::Result<Vec<u8>> {
    let mut rng = rand::rngs::OsRng;
    let mut eph_secret = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut eph_secret[..]);
    let eph = MontgomeryPoint::mul_base_clamped(*eph_secret).to_bytes();
    let ss_x = dh(&eph_secret, &to.x25519)?;
    let mut m = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut m[..]);
    let (ct, ss_k) = to.encapsulation_key()?.encapsulate_deterministic(&B32::from(*m));
    let key = combine(&ss_x, &ss_k, &eph, &to.x25519, &ct);
    let mut out = Vec::with_capacity(HEAD + 24 + plaintext.len() + 16);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&eph);
    out.extend_from_slice(&ct);
    let nonce: [u8; 24] = rand::random();
    let aad = [label, &out[..]].concat();
    let sealed = XChaCha20Poly1305::new((&*key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| err(io::ErrorKind::Other, "sealing failed"))?;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Opens a hybrid box sealed to `sk` under `label`.
pub fn open(sk: &Secret, label: &[u8], blob: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    let bad = || {
        err(
            io::ErrorKind::InvalidData,
            "hybrid box damaged, or not sealed to this key",
        )
    };
    if !is_hybrid(blob) || blob.len() < HEAD + 24 + 16 {
        return Err(bad());
    }
    let eph: [u8; 32] = blob[8..40].try_into().unwrap();
    let ct_bytes = &blob[40..HEAD];
    let ct = Ciphertext::try_from(ct_bytes).map_err(|_| bad())?;
    let ss_k = sk.dk.decapsulate(&ct);
    let ss_x = dh(&sk.x25519, &eph).map_err(|_| bad())?;
    let to_x = MontgomeryPoint::mul_base_clamped(*sk.x25519).to_bytes();
    let key = combine(&ss_x, &ss_k, &eph, &to_x, ct_bytes);
    let aad = [label, &blob[..HEAD]].concat();
    let (nonce, msg) = blob[HEAD..].split_at(24);
    XChaCha20Poly1305::new((&*key).into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg, aad: &aad })
        .map(Zeroizing::new)
        .map_err(|_| bad())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_labels_and_tampering() {
        let sk = Secret::derive(&[7; 32], "test context");
        let pk = sk.public();
        // the X25519 half is the crypto_box public key of the same secret
        assert_eq!(
            pk.x25519,
            *crypto_box::SecretKey::from_bytes([7; 32]).public_key().as_bytes()
        );
        assert_eq!(Public::from_bytes(&pk.to_bytes()).unwrap(), pk);
        assert_eq!(pk.to_bytes().len(), PUBLIC_LEN);
        let b = seal(&pk, b"label", b"secret DEK").unwrap();
        assert!(is_hybrid(&b));
        assert_eq!(b.len(), HEAD + 24 + 10 + 16);
        assert_eq!(&open(&sk, b"label", &b).unwrap()[..], b"secret DEK");
        assert!(open(&sk, b"other", &b).is_err(), "label is authenticated");
        for at in [10, 100, HEAD + 3, b.len() - 1] {
            let mut t = b.clone();
            t[at] ^= 1;
            assert!(open(&sk, b"label", &t).is_err(), "byte {at}");
        }
        // another context or secret: another ML-KEM key
        assert_ne!(Secret::derive(&[7; 32], "other").public().mlkem, pk.mlkem);
        assert!(open(&Secret::derive(&[8; 32], "test context"), b"label", &b).is_err());
        assert!(
            open(&Secret::derive(&[7; 32], "other"), b"label", &b).is_err(),
            "both halves count"
        );
        // deterministic derivation
        assert_eq!(Secret::derive(&[7; 32], "test context").public(), pk);
        assert!(Public::from_bytes(&[0u8; 10]).is_err());
        let mut bad = pk.to_bytes();
        bad[40..42].copy_from_slice(&[0xff, 0xff]); // coefficient >= q
        assert!(Public::from_bytes(&bad).is_err());
        // a low-order X25519 point is refused
        let weak = Public {
            x25519: [0; 32],
            mlkem: pk.mlkem.clone(),
        };
        assert!(seal(&weak, b"label", b"x").is_err());
    }
}
