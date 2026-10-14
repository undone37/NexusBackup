//! Registry hives (SYSTEM, `MountedDevices`): hostile bytes must give an
//! error or an answer, never a panic, an endless loop or an unbounded allocation.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(letters) = fsindex::regf::drive_letters(data) {
        assert!(letters.len() <= 26);
    }
    if let Ok(mut h) = fsindex::regf::Hive::open(data) {
        if let Ok(Some(k)) = h.find("Select") {
            let _ = h.values(k);
        }
    }
});
