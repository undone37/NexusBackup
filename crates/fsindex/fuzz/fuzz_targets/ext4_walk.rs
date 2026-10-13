//! ext2/3/4 through ext4-view: hostile bytes must not panic, loop or allocate without bound
//! A panic inside the third-party crate is contained per volume at runtime
//! (catch_unwind in walk.rs, the volume is reported as failed) and is not
//! counted here; hangs, memory blowups and aborts (stack overflow) are.
#![no_main]

use fsindex::disk::{Io, Local, Vol};
use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;
use std::rc::Rc;

fn vol(data: &[u8]) -> Vol {
    let io: Io = Rc::new(RefCell::new(Local {
        disks: vec![data.to_vec()],
    }));
    Vol::region(io, 0, 0, data.len() as u64)
}

fuzz_target!(|data: &[u8]| {
    let limits = fsindex::Limits {
        max_entries: 100_000,
        budget_secs: 10,
    };
    static QUIET: std::sync::Once = std::sync::Once::new();
    QUIET.call_once(|| std::panic::set_hook(Box::new(|_| {})));
    let v = vol(data);
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fsindex::walk::walk_one(&v, "ext4", limits)
    }));
});
