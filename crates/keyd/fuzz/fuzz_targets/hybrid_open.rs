//! Hybrid sealed boxes (Phase 30, `keyd::hybrid`) as they come from an offsite
//! target or a replication primary: any bytes. Invariants: no panic; a blob
//! that opens is exactly one this key sealed (an attacker cannot forge one
//! without the public key, so random input never opens); hybrid public keys
//! from the wire either parse fully or are refused.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn key() -> &'static (keyd::hybrid::Secret, keyd::hybrid::Public) {
    static K: OnceLock<(keyd::hybrid::Secret, keyd::hybrid::Public)> = OnceLock::new();
    K.get_or_init(|| {
        let s = keyd::hybrid::Secret::derive(&[5; 32], "fuzz");
        let p = s.public();
        (s, p)
    })
}

fuzz_target!(|data: &[u8]| {
    let (sk, pk) = key();
    assert!(keyd::hybrid::open(sk, b"label", data).is_err(), "random bytes never open");
    // flip one byte of a real box: refused
    if let Some((&at, rest)) = data.split_first() {
        let mut b = keyd::hybrid::seal(pk, b"label", rest).unwrap();
        let i = at as usize % b.len();
        b[i] ^= 1;
        assert!(keyd::hybrid::open(sk, b"label", &b).is_err());
    }
    if let Ok(p) = keyd::hybrid::Public::from_bytes(data) {
        assert_eq!(p.to_bytes(), data);
        let _ = keyd::hybrid::seal(&p, b"label", b"x");
    }
});
