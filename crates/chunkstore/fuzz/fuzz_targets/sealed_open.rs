//! Sealed blob parsing (chunks, indexes, manifests, packs from a hostile
//! Storage Box or a tampered disk): random bytes must never open, never panic;
//! honestly sealed bytes must round-trip.
#![no_main]

use chunkstore::crypto::{unwrap_key, wrap_key};
use chunkstore::Keyring;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn ring() -> &'static Keyring {
    static K: OnceLock<Keyring> = OnceLock::new();
    K.get_or_init(|| Keyring::new("t", &[(1, [1; 32]), (2, [2; 32])]))
}

fuzz_target!(|data: &[u8]| {
    let k = ring();
    let id: [u8; 32] = data.get(..32).map_or([0; 32], |b| b.try_into().unwrap());
    // random input: must fail authentication
    assert!(k.open(b"ctx", data).is_err());
    assert!(k.open_chunk(&id, data).is_err());
    let _ = unwrap_key(&[3; 32], data, "tenant-dek:t:v1");

    // honest blobs round-trip, and any single bit flip is detected
    let sealed = k.seal(b"ctx", data);
    assert_eq!(k.open(b"ctx", &sealed).unwrap(), (2, data.to_vec()));
    assert!(k.open(b"ctx2", &sealed).is_err());
    if !data.is_empty() {
        let mut t = sealed.clone();
        let i = data[0] as usize * 7 % t.len();
        t[i] ^= 1 << (data[data.len() - 1] % 8);
        assert!(k.open(b"ctx", &t).is_err());
    }
    let cid = k.chunk_id(data);
    assert_eq!(k.open_chunk(&cid, &k.seal_chunk(&cid, data)).unwrap(), data);
    if data.len() >= 32 {
        let key: [u8; 32] = data[..32].try_into().unwrap();
        assert_eq!(unwrap_key(&[3; 32], &wrap_key(&[3; 32], &key, "l"), "l").unwrap(), key);
    }
});
