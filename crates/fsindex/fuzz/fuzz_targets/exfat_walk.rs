//! exFAT (own parser): hostile bytes must not panic, loop or allocate without bound
//! (the helper catches panics per volume, but a panic is still a bug).
#![no_main]

use fsindex::disk::{Io, Local, Vol};
use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;
use std::rc::Rc;

fn vol(data: &[u8]) -> Vol {
    let io: Io = Rc::new(RefCell::new(Local { disks: vec![data.to_vec()] }));
    Vol::region(io, 0, 0, data.len() as u64)
}

fuzz_target!(|data: &[u8]| {
    let limits = fsindex::Limits { max_entries: 100_000, budget_secs: 10 };
    let _ = fsindex::walk::walk_one(&vol(data), "exfat", limits);
});
