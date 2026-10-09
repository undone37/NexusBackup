//! NBD client against a hostile server (a compromised PVE node / its SSH
//! stdio): the input is everything the server sends.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::{self, Read, Seek, SeekFrom};

const BITMAP: &str = "qemu:dirty-bitmap:nexus";

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else { return };
    let meta: &[&str] = match sel % 3 {
        0 => &[],
        1 => &[BITMAP],
        _ => &[BITMAP, "base:allocation"],
    };
    let Ok(mut c) = nbd::Client::connect(rest, io::sink(), "drive-scsi0", meta) else {
        return;
    };
    if !meta.is_empty() {
        if let Ok(ext) = c.block_status(BITMAP) {
            let size = c.size();
            for (off, len, _) in &ext {
                assert!(*off < size && off + len <= size, "extent outside the export");
            }
            nbd::flagged(&ext, 1);
        }
    }
    let size = c.size();
    let mut buf = vec![0u8; size.min(64 << 10) as usize];
    let _ = c.read_at(size / 3, &mut buf[..(size - size / 3).min(64 << 10) as usize]);
    let _ = c.seek(SeekFrom::Start(size / 2));
    let _ = c.read(&mut buf);
});
