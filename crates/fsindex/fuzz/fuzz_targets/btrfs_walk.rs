//! btrfs (own parser): hostile bytes must not panic, loop or allocate without
//! bound. A btrfs keeps its superblock at 64 KiB and its trees megabytes
//! further, so the input describes a sparse 512 MiB disk: records of
//! `[u32 LE sector][u16 LE length][bytes]`, zeros elsewhere (seeds: the
//! non-zero blocks of small mkfs.btrfs images, lab/fuzz/mkseeds.py).
#![no_main]

use fsindex::disk::{DiskIo, Io, Vol};
use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;
use std::rc::Rc;

const SIZE: u64 = 512 << 20;

struct Sparse(Vec<(u64, Vec<u8>)>);

impl DiskIo for Sparse {
    fn disks(&self) -> usize {
        1
    }
    fn disk_size(&self, _: usize) -> u64 {
        SIZE
    }
    fn read(&mut self, _: usize, off: u64, buf: &mut [u8]) -> std::io::Result<()> {
        let end = off + buf.len() as u64;
        if end > SIZE {
            return Err(std::io::Error::other("beyond the disk"));
        }
        buf.fill(0);
        for (at, d) in &self.0 {
            let (a, b) = ((*at).max(off), (at + d.len() as u64).min(end));
            if a < b {
                buf[(a - off) as usize..(b - off) as usize].copy_from_slice(&d[(a - at) as usize..(b - at) as usize]);
            }
        }
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    let mut recs = Vec::new();
    let mut d = data;
    while d.len() >= 6 {
        let at = u64::from(u32::from_le_bytes(d[0..4].try_into().unwrap())) * 512 % SIZE;
        let n = (u16::from_le_bytes([d[4], d[5]]) as usize).min(d.len() - 6);
        recs.push((at, d[6..6 + n].to_vec()));
        d = &d[6 + n..];
    }
    let io: Io = Rc::new(RefCell::new(Sparse(recs)));
    let limits = fsindex::Limits {
        max_entries: 100_000,
        budget_secs: 10,
        ..Default::default()
    };
    let _ = fsindex::walk::walk_one(&Vol::region(io, 0, 0, SIZE), "btrfs", limits);
});
