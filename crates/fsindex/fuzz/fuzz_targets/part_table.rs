//! GPT / MBR / EBR chains and the signature probe on hostile disks.
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
    let v = vol(data);
    if let Ok(fsindex::part::Table::Gpt(p) | fsindex::part::Table::Mbr(p)) = fsindex::part::parse(&v) {
        for p in p {
            assert!(p.start.checked_add(p.len).is_some_and(|e| e <= data.len() as u64), "{p:?} outside");
        }
    }
    let _ = fsindex::probe::probe(&v);
});
