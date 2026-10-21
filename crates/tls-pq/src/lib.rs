//! Post-quantum TLS key exchange (Phase 39 S5): the hybrid group X25519MLKEM768
//! (draft-ietf-tls-ecdhe-mlkem, code point 0x11EC, what current browsers and OpenSSL 3.5 offer) for
//! rustls's ring provider. rustls ships it only with the aws-lc-rs provider, a C library this
//! project does not build; ML-KEM-768 here is the pure-Rust `ml-kem` crate keyd already uses
//! (ADR-014), X25519 is ring's.
//!
//! Wire format (the draft): client share = ML-KEM-768 encapsulation key (1184 bytes) | X25519
//! public (32); server share = ML-KEM ciphertext (1088) | X25519 public (32); shared secret =
//! ML-KEM shared secret (32) | X25519 shared secret (32). The hybrid is as strong as the stronger
//! half: a broken ML-KEM leaves X25519, a quantum attacker on X25519 still faces ML-KEM.
//!
//! [`provider`] is ring's default provider with the hybrid group first; a peer without it
//! negotiates X25519 as before.

use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::ml_kem_768::{Ciphertext, DecapsulationKey, EncapsulationKey};
use ml_kem::{Seed, B32};
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};
use std::sync::Arc;
use zeroize::Zeroizing;

const EK_LEN: usize = 1184;
const CT_LEN: usize = 1088;
const X25519_LEN: usize = 32;

/// The hybrid group X25519MLKEM768.
#[derive(Debug)]
pub struct X25519MlKem768;

/// The group as rustls wants it.
pub static X25519MLKEM768: &dyn SupportedKxGroup = &X25519MlKem768;

fn invalid() -> Error {
    Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)
}

fn x25519() -> &'static dyn SupportedKxGroup {
    rustls::crypto::ring::kx_group::X25519
}

impl SupportedKxGroup for X25519MlKem768 {
    /// Client side: a fresh ML-KEM key pair and X25519 share.
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut seed = Zeroizing::new([0u8; 64]);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed[..]);
        let dk = DecapsulationKey::from_seed(Seed::from(*seed));
        let classical = x25519().start()?;
        let mut share = dk.encapsulation_key().to_bytes().to_vec();
        share.extend_from_slice(classical.pub_key());
        Ok(Box::new(Active { dk, classical, share }))
    }

    /// Server side: encapsulate to the client's key, complete X25519.
    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        if client_share.len() != EK_LEN + X25519_LEN {
            return Err(invalid());
        }
        let (ek, x) = client_share.split_at(EK_LEN);
        let key = ml_kem::kem::Key::<EncapsulationKey>::try_from(ek).map_err(|_| invalid())?;
        // FIPS 203 modulus check of the client's key
        let ek = EncapsulationKey::new(&key).map_err(|_| invalid())?;
        let mut m = Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut m[..]);
        let (ct, ss) = ek.encapsulate_deterministic(&B32::from(*m));
        let cl = x25519().start_and_complete(x)?;
        let mut share = ct.to_vec();
        share.extend_from_slice(&cl.pub_key);
        let mut secret = ss.to_vec();
        secret.extend_from_slice(cl.secret.secret_bytes());
        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: share,
            secret: SharedSecret::from(secret),
        })
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

struct Active {
    dk: DecapsulationKey,
    classical: Box<dyn ActiveKeyExchange>,
    share: Vec<u8>,
}

impl ActiveKeyExchange for Active {
    /// Client side: decapsulate the server's ciphertext, complete X25519.
    fn complete(self: Box<Self>, server_share: &[u8]) -> Result<SharedSecret, Error> {
        if server_share.len() != CT_LEN + X25519_LEN {
            return Err(invalid());
        }
        let (ct, x) = server_share.split_at(CT_LEN);
        let ct = Ciphertext::try_from(ct).map_err(|_| invalid())?;
        let ss = self.dk.decapsulate(&ct);
        let cl = self.classical.complete(x)?;
        let mut secret = ss.to_vec();
        secret.extend_from_slice(cl.secret_bytes());
        Ok(SharedSecret::from(secret))
    }

    /// The X25519 half for a server that picks plain X25519 (one round trip saved).
    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((self.classical.group(), self.classical.pub_key()))
    }

    fn complete_hybrid_component(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        self.classical.complete(peer)
    }

    fn pub_key(&self) -> &[u8] {
        &self.share
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}

/// ring's default provider with X25519MLKEM768 preferred, then ring's groups (X25519, P-256, P-384).
pub fn provider() -> CryptoProvider {
    let mut p = rustls::crypto::ring::default_provider();
    p.kx_groups.insert(0, X25519MLKEM768);
    p
}

/// [`provider`] in an `Arc`, as rustls's builders take it.
pub fn provider_arc() -> Arc<CryptoProvider> {
    Arc::new(provider())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};

    fn handshake(client_groups: Vec<&'static dyn SupportedKxGroup>) -> NamedGroup {
        let ck = rcgen::generate_simple_self_signed(vec!["nexus.test".into()]).unwrap();
        let cert = CertificateDer::from(ck.cert.der().to_vec());
        let key = PrivateKeyDer::try_from(ck.key_pair.serialize_der()).unwrap();
        let server = ServerConfig::builder_with_provider(provider_arc())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let mut cp = rustls::crypto::ring::default_provider();
        cp.kx_groups = client_groups;
        let client = ClientConfig::builder_with_provider(Arc::new(cp))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut c = ClientConnection::new(Arc::new(client), ServerName::try_from("nexus.test").unwrap()).unwrap();
        let mut s = ServerConnection::new(Arc::new(server)).unwrap();
        for _ in 0..10 {
            let mut buf = Vec::new();
            c.write_tls(&mut buf).unwrap();
            s.read_tls(&mut &buf[..]).unwrap();
            s.process_new_packets().unwrap();
            let mut buf = Vec::new();
            s.write_tls(&mut buf).unwrap();
            c.read_tls(&mut &buf[..]).unwrap();
            c.process_new_packets().unwrap();
            if !c.is_handshaking() && !s.is_handshaking() {
                break;
            }
        }
        assert!(!c.is_handshaking() && !s.is_handshaking(), "handshake did not finish");
        let g = s.negotiated_key_exchange_group().unwrap().name();
        assert_eq!(c.negotiated_key_exchange_group().unwrap().name(), g);
        g
    }

    #[test]
    fn hybrid_handshake_and_fallback() {
        assert_eq!(handshake(vec![X25519MLKEM768, x25519()]), NamedGroup::X25519MLKEM768);
        // an older peer without the hybrid group: X25519 as before
        assert_eq!(handshake(vec![x25519()]), NamedGroup::X25519);
    }

    #[test]
    fn malformed_shares_are_refused() {
        assert!(X25519MLKEM768.start_and_complete(&[0u8; 10]).is_err());
        assert!(X25519MLKEM768
            .start_and_complete(&[0u8; EK_LEN + X25519_LEN + 1])
            .is_err());
        let a = X25519MLKEM768.start().unwrap();
        assert_eq!(a.pub_key().len(), EK_LEN + X25519_LEN);
        assert!(a.complete(&[0u8; CT_LEN]).is_err());
    }

    #[test]
    fn both_sides_agree() {
        let client = X25519MLKEM768.start().unwrap();
        let server = X25519MLKEM768.start_and_complete(client.pub_key()).unwrap();
        assert_eq!(server.pub_key.len(), CT_LEN + X25519_LEN);
        let theirs = server.secret.secret_bytes().to_vec();
        let ours = client.complete(&server.pub_key).unwrap();
        assert_eq!(ours.secret_bytes(), &theirs[..]);
        assert_eq!(theirs.len(), 64);
    }
}
