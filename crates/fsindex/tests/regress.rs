//! Inputs the fuzz targets found (crates/fsindex/fuzz): each must list
//! without a panic. Plus the shapes behind them, built by hand.

use fsindex::disk::{Io, Local, Vol};
use fsindex::walk::Driver;
use fsindex::{Limits, Volume};
use std::cell::RefCell;
use std::io;
use std::rc::Rc;

struct Null;

impl Driver for Null {
    fn begin(&mut self, _: &Volume) -> io::Result<bool> {
        Ok(true)
    }
    fn entry(&mut self, _: &str, _: u64, _: i64, _: u8) -> io::Result<()> {
        Ok(())
    }
    fn end(&mut self, _: &Volume) -> io::Result<()> {
        Ok(())
    }
}

fn walk(data: Vec<u8>) {
    let io: Io = Rc::new(RefCell::new(Local { disks: vec![data] }));
    fsindex::walk::run(io, &["d0".to_string()], Limits::default(), &mut Null).unwrap();
}

#[test]
fn fuzz_findings() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/regress");
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        walk(std::fs::read(&p).unwrap());
        let v = std::fs::read(&p).unwrap();
        let n = v.len() as u64;
        let io: Io = Rc::new(RefCell::new(Local { disks: vec![v] }));
        let _ = fsindex::lvm::read_pv(&Vol::region(io, 0, 0, n));
    }
}

/// An LVM label near the end of a short volume, a metadata area pointer past
/// the end, an MBR partition past the end of the disk.
#[test]
fn short_structures() {
    let mut d = vec![0u8; 1000];
    d[512..520].copy_from_slice(b"LABELONE");
    d[536..544].copy_from_slice(b"LVM2 001");
    walk(d);
    let mut m = vec![0u8; 4096];
    m[446 + 4] = 0x83;
    m[446 + 8..446 + 12].copy_from_slice(&2u32.to_le_bytes());
    m[446 + 12..446 + 16].copy_from_slice(&100u32.to_le_bytes());
    m[510] = 0x55;
    m[511] = 0xaa;
    walk(m);
}
