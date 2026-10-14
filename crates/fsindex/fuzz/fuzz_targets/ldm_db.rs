//! Windows dynamic disks (LDM): a hostile private header, table of contents,
//! database header and VBLK records (fragments too) must give an error or
//! volumes whose segments cover them exactly, never a panic, a loop or an
//! unbounded allocation.
#![no_main]

use fsindex::disk::{Io, Local};
use fsindex::ldm::{volumes, Member};
use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;
use std::rc::Rc;

fuzz_target!(|data: &[u8]| {
    let io: Io = Rc::new(RefCell::new(Local {
        disks: vec![data.to_vec()],
    }));
    if let Ok(vols) = volumes(&io, &[Member { disk: 0, privhead: 6 * 512 }]) {
        for v in vols {
            if let Ok(segs) = v.map {
                let mut at = 0u64;
                for s in segs {
                    assert_eq!(s.start, at);
                    assert!(s.legs.iter().all(|(d, o)| *d == 0 && o + s.len <= data.len() as u64));
                    at += s.len;
                }
                assert_eq!(at, v.size);
            }
        }
    }
});
