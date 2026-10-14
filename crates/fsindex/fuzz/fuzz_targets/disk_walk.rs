//! The whole pipeline on one hostile disk: partition table, LVM, probe,
//! every parser (as the helper runs it, with panics caught per volume).
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

struct Null;
impl fsindex::walk::Driver for Null {
    fn begin(&mut self, _: &fsindex::Volume) -> std::io::Result<bool> {
        Ok(true)
    }
    fn entry(&mut self, _: &str, _: u64, _: i64, _: u8) -> std::io::Result<()> {
        Ok(())
    }
    fn end(&mut self, _: &fsindex::Volume) -> std::io::Result<()> {
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    // walk::run contains a parser's panic per volume, as at runtime; any
    // other panic (partition tables, LVM, probe) escapes and aborts
    static QUIET: std::sync::Once = std::sync::Once::new();
    QUIET.call_once(|| std::panic::set_hook(Box::new(|_| {})));
    let io: Io = Rc::new(RefCell::new(Local {
        disks: vec![data.to_vec()],
    }));
    let _ = vol(data);
    let limits = fsindex::Limits {
        max_entries: 100_000,
        budget_secs: 10,
        ..Default::default()
    };
    let _ = fsindex::walk::run(io, &["d0".to_string()], limits, &mut Null);
});
