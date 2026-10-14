//! dm-thin pool metadata (LVM thin volumes): hostile superblocks and B+trees
//! must give an error or a mapping that covers the thin volume exactly, never a
//! panic, a loop or an unbounded allocation.
#![no_main]

use fsindex::disk::{Io, Local, Segment};
use fsindex::lvm::{thin_segments, Thin};
use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;
use std::rc::Rc;

fuzz_target!(|data: &[u8]| {
    let n = data.len() as u64;
    let io: Io = Rc::new(RefCell::new(Local {
        disks: vec![data.to_vec()],
    }));
    let seg = |len: u64| Segment {
        start: 0,
        len,
        legs: vec![(0, 0)],
        stripe: 0,
    };
    // the input is the metadata and (again) the pool's data; the thin LV is 1 GiB
    let t = Thin {
        meta: vec![seg(n)],
        data: vec![seg(n)],
        dev: 1,
        size: 1 << 30,
    };
    if let Ok(segs) = thin_segments(&io, &t) {
        let mut at = 0u64;
        for s in segs {
            assert_eq!(s.start, at);
            assert!(s.len > 0);
            at += s.len;
        }
        assert_eq!(at, t.size);
    }
});
