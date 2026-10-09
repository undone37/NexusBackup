//! Container backup record stream (`ct-stream`, tag + u32 BE length + payload)
//! from a compromised PVE node or container, read into a chunk store.
#![no_main]

use chunkstore::{Keyring, Options, Store};
use libfuzzer_sys::fuzz_target;
use std::io::Read;

fuzz_target!(|data: &[u8]| {
    // plain record reader with odd read sizes
    let mut r = pve::ct::Records::new(data);
    if r.config().is_ok() {
        let mut buf = [0u8; 7];
        let mut total = 0usize;
        while let Ok(n) = r.read(&mut buf) {
            if n == 0 {
                break;
            }
            total += n;
            assert!(total <= data.len(), "more payload than input");
        }
    }
    // full path into a (fresh, tmpfs) store: chunking + dedup
    let d = tempfile::tempdir_in("/dev/shm").unwrap();
    let store = Store::open(d.path(), Keyring::new("t", &[(1, [7; 32])]), Options::default()).unwrap();
    if let Ok((_, st)) = pve::ct::read_stream(&store, data) {
        assert!(st.size <= data.len() as u64);
    }
});
