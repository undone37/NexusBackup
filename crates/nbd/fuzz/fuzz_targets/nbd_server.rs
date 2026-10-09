//! Read-only NBD server against a hostile client (the node side of a restore
//! or instant-recovery export): the input is everything the client sends.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io;

const SIZE: u64 = 3 << 20;

fuzz_target!(|data: &[u8]| {
    let _ = nbd::server::serve(data, io::sink(), "disk", SIZE, |off, buf| {
        assert!(off + buf.len() as u64 <= SIZE, "read beyond the export");
        buf.fill(0xa5);
        Ok(())
    });
});
