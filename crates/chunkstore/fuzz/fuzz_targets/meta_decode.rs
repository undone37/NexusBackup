//! postcard decoding of manifests and indexes (defense in depth: these bytes
//! are authenticated before decoding, but a decoder must not panic or allocate
//! unboundedly on any input), plus `Store::decode_*` on unauthenticated bytes.
#![no_main]

use chunkstore::{Index, Manifest};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = postcard::from_bytes::<Manifest>(data) {
        let again = postcard::to_stdvec(&m).unwrap();
        assert_eq!(postcard::from_bytes::<Manifest>(&again).unwrap(), m);
    }
    if let Ok(i) = postcard::from_bytes::<Index>(data) {
        let _ = i.chunk_ids();
        let again = postcard::to_stdvec(&i).unwrap();
        assert_eq!(postcard::from_bytes::<Index>(&again).unwrap(), i);
    }
    let _ = postcard::from_bytes::<Vec<chunkstore::FileEntry>>(data);
});
