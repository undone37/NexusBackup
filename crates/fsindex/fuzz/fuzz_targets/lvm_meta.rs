//! LVM2: PV label + metadata area on hostile bytes, then the text metadata
//! and the LV mapping (segments must stay inside the PVs' disks' address space
//! without overflow).
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
    let _ = fsindex::lvm::read_pv(&vol(data));
    let text = String::from_utf8_lossy(data).into_owned();
    let mut pvs = fsindex::lvm::PvMap::new();
    pvs.insert("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(), (0, 1 << 20));
    pvs.insert("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".into(), (1, 0));
    for lv in fsindex::lvm::volumes(&[text], &pvs) {
        if let Ok(segs) = lv.map {
            let mut at = 0u64;
            for s in segs {
                assert_eq!(s.start, at);
                at = at.checked_add(s.len).expect("overflow");
            }
        }
    }
});
