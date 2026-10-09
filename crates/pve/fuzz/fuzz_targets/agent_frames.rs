//! Appliance side of the restore micro-VM protocol: a (compromised) agent
//! sends tar frames and JSON response lines.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pve::restorevm::{parse_response, read_frame, Entry, Mount, TarSummary};

fuzz_target!(|data: &[u8]| {
    let mut r = data;
    let (mut left, mut done) = (0u32, false);
    let mut buf = [0u8; 13];
    let mut total = 0usize;
    loop {
        match read_frame(&mut r, &mut left, &mut done, &mut buf) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                assert!(total <= data.len());
            }
            Err(_) => break,
        }
    }
    // the rest are response lines, decoded like Vm::mounts / ls / TarStream::finish
    for line in r.split(|b| *b == b'\n') {
        if let Ok(ok) = parse_response(line) {
            let _ = serde_json::from_value::<Vec<Mount>>(ok.clone());
            let _ = serde_json::from_value::<Vec<Entry>>(ok.clone());
            let _ = serde_json::from_value::<TarSummary>(ok);
        }
    }
});
