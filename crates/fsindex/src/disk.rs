//! Byte access to the disks and to volumes on them (partitions, LVs).
//!
//! [`DiskIo`] reads raw disk bytes: from files (tests, fuzzing) or from the
//! parent over the pipe (the helper, [`crate::proto::Remote`]). A [`Vol`] is a
//! view of a volume as a list of segments (linear or striped over disks) and
//! offers the reader traits the file system crates want.

use std::cell::RefCell;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::rc::Rc;

pub trait DiskIo {
    fn disks(&self) -> usize;
    fn disk_size(&self, disk: usize) -> u64;
    /// Exactly `buf.len()` bytes at `off` (error beyond the end).
    fn read(&mut self, disk: usize, off: u64, buf: &mut [u8]) -> io::Result<()>;
    /// Drops cached bytes (start of a volume: every byte a parse depends on
    /// must be requested again, so the parent sees the volume's read set).
    fn forget(&mut self) {}
    /// The (disk, 64 KiB block) accessed since the last call, cache hits
    /// included (Phase 31c: what one directory's listing depended on).
    fn take_accessed(&mut self) -> Vec<(usize, u64)> {
        Vec::new()
    }
}

pub type Io = Rc<RefCell<dyn DiskIo>>;

pub fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Disk images as files or byte vectors (tests, fuzzing, `nexus-fsindex --local`).
pub struct Local<T> {
    pub disks: Vec<T>,
}

impl DiskIo for Local<Vec<u8>> {
    fn disks(&self) -> usize {
        self.disks.len()
    }
    fn disk_size(&self, d: usize) -> u64 {
        self.disks[d].len() as u64
    }
    fn read(&mut self, d: usize, off: u64, buf: &mut [u8]) -> io::Result<()> {
        let src = &self.disks[d];
        let end = off
            .checked_add(buf.len() as u64)
            .ok_or_else(|| invalid("offset overflow"))?;
        if end > src.len() as u64 {
            return Err(invalid("read beyond the end of the disk"));
        }
        buf.copy_from_slice(&src[off as usize..end as usize]);
        Ok(())
    }
}

impl DiskIo for Local<std::fs::File> {
    fn disks(&self) -> usize {
        self.disks.len()
    }
    fn disk_size(&self, d: usize) -> u64 {
        self.disks[d].metadata().map_or(0, |m| m.len())
    }
    fn read(&mut self, d: usize, off: u64, buf: &mut [u8]) -> io::Result<()> {
        use std::os::unix::fs::FileExt;
        if off.checked_add(buf.len() as u64).is_none_or(|e| e > self.disk_size(d)) {
            return Err(invalid("read beyond the end of the disk"));
        }
        self.disks[d].read_exact_at(buf, off)
    }
}

/// Part of a volume: `len` bytes from volume offset `start`.
#[derive(Clone, Debug, PartialEq)]
pub struct Segment {
    pub start: u64,
    pub len: u64,
    /// one leg: linear; several: striped with `stripe` bytes per stripe; none:
    /// zeros (unmapped blocks of a thin LV)
    pub legs: Vec<(usize, u64)>,
    pub stripe: u64,
}

/// A volume: segments sorted by `start`, contiguous from 0.
#[derive(Clone)]
pub struct Vol {
    io: Io,
    segs: Rc<Vec<Segment>>,
    size: u64,
    pos: u64,
}

impl Vol {
    /// A linear region of one disk.
    pub fn region(io: Io, disk: usize, off: u64, len: u64) -> Vol {
        Vol::new(
            io,
            vec![Segment {
                start: 0,
                len,
                legs: vec![(disk, off)],
                stripe: 0,
            }],
        )
    }

    pub fn new(io: Io, segs: Vec<Segment>) -> Vol {
        let size = segs.last().map_or(0, |s| s.start + s.len);
        Vol {
            io,
            segs: Rc::new(segs),
            size,
            pos: 0,
        }
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn segments(&self) -> &[Segment] {
        &self.segs
    }

    /// (disk and offset, `None` for zeros; bytes available there) of volume offset `off`.
    fn locate(&self, off: u64) -> io::Result<(Option<(usize, u64)>, u64)> {
        let i = self.segs.partition_point(|s| s.start + s.len <= off);
        let s = self
            .segs
            .get(i)
            .filter(|s| s.start <= off)
            .ok_or_else(|| invalid("read beyond the volume"))?;
        let rel = off - s.start;
        let left = s.len - rel;
        if s.legs.is_empty() {
            return Ok((None, left));
        }
        if s.legs.len() == 1 {
            let (d, o) = s.legs[0];
            return Ok((
                Some((d, o.checked_add(rel).ok_or_else(|| invalid("offset overflow"))?)),
                left,
            ));
        }
        let n = s.legs.len() as u64;
        let stripe_no = rel / s.stripe;
        let within = rel % s.stripe;
        let (d, o) = s.legs[(stripe_no % n) as usize];
        let at = (stripe_no / n)
            .checked_mul(s.stripe)
            .and_then(|x| x.checked_add(within))
            .and_then(|x| x.checked_add(o))
            .ok_or_else(|| invalid("offset overflow"))?;
        Ok((Some((d, at)), (s.stripe - within).min(left)))
    }

    pub fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        if off.checked_add(buf.len() as u64).is_none_or(|e| e > self.size) {
            return Err(invalid("read beyond the volume"));
        }
        let mut done = 0;
        while done < buf.len() {
            let (at, avail) = self.locate(off + done as u64)?;
            let k = (avail.min((buf.len() - done) as u64)) as usize;
            match at {
                Some((d, at)) => self.io.borrow_mut().read(d, at, &mut buf[done..done + k])?,
                None => buf[done..done + k].fill(0),
            }
            done += k;
        }
        Ok(())
    }

    /// The (disk, 64 KiB block) holding the volume's bytes `[off, off + len)`
    /// (Phase 31c: blocks a directory's read set leaves out).
    pub fn disk_blocks(&self, off: u64, len: u64) -> Vec<(usize, u64)> {
        let block = crate::proto::BLOCK;
        let end = off.saturating_add(len).min(self.size);
        let mut out = Vec::new();
        let mut p = off;
        while p < end {
            let Ok((at, avail)) = self.locate(p) else { break };
            let k = avail.min(end - p).max(1);
            // unmapped (thin) ranges read zeros: no disk block
            if let Some((d, at)) = at {
                out.extend((at / block..=(at + k - 1) / block).map(|b| (d, b)));
            }
            p += k;
        }
        out
    }

    /// Up to `n` bytes from `off` (fewer at the end of the volume).
    pub fn read_vec(&self, off: u64, n: usize) -> io::Result<Vec<u8>> {
        let n = (n as u64).min(self.size.saturating_sub(off)) as usize;
        let mut v = vec![0; n];
        self.read_at(off, &mut v)?;
        Ok(v)
    }
}

impl Read for Vol {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = (buf.len() as u64).min(self.size.saturating_sub(self.pos)) as usize;
        self.read_at(self.pos, &mut buf[..n])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for Vol {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let p = match to {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::End(d) => self.size.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        self.pos = p.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before the start"))?;
        Ok(self.pos)
    }
}

/// A volume that reads zeros past its end (crate `ntfs` turns a short read
/// inside a structure into a panic; zeros become a parse error instead).
#[derive(Clone)]
pub struct Padded(pub Vol);

impl Read for Padded {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let v = &mut self.0;
        let n = (buf.len() as u64).min(v.size.saturating_sub(v.pos)) as usize;
        v.read_at(v.pos, &mut buf[..n])?;
        buf[n..].fill(0);
        v.pos = v.pos.saturating_add(buf.len() as u64);
        Ok(buf.len())
    }
}

impl Seek for Padded {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        self.0.seek(to)
    }
}

/// Never writes (crate `fatfs` wants a read-write device): every write fails.
impl Write for Vol {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "read-only"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ext4_view::Ext4Read for Vol {
    fn read(&mut self, start: u64, dst: &mut [u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        self.read_at(start, dst).map_err(|e| Box::new(e) as _)
    }
}

/// Little-endian field readers that never panic (short input reads zeros).
pub fn le16(b: &[u8], at: usize) -> u16 {
    b.get(at..at + 2).map_or(0, |s| u16::from_le_bytes([s[0], s[1]]))
}

pub fn le32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4)
        .map_or(0, |s| u32::from_le_bytes(s.try_into().unwrap()))
}

pub fn le64(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 8)
        .map_or(0, |s| u64::from_le_bytes(s.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn io(disks: Vec<Vec<u8>>) -> Io {
        Rc::new(RefCell::new(Local { disks }))
    }

    fn io_of(disks: Vec<Vec<u8>>) -> Io {
        io(disks)
    }

    #[test]
    fn striped_and_linear() {
        let a: Vec<u8> = (0..64u8).collect();
        let b: Vec<u8> = (100..164u8).collect();
        let io = io(vec![a, b]);
        // stripes of 4 bytes alternating a[8..], b[0..]; then 8 linear bytes of a[40..]
        let v = Vol::new(
            io,
            vec![
                Segment {
                    start: 0,
                    len: 16,
                    legs: vec![(0, 8), (1, 0)],
                    stripe: 4,
                },
                Segment {
                    start: 16,
                    len: 8,
                    legs: vec![(0, 40)],
                    stripe: 0,
                },
            ],
        );
        let all = v.read_vec(0, 100).unwrap();
        assert_eq!(
            all,
            [8, 9, 10, 11, 100, 101, 102, 103, 12, 13, 14, 15, 104, 105, 106, 107, 40, 41, 42, 43, 44, 45, 46, 47]
        );
        let mut x = [0u8; 3];
        v.read_at(14, &mut x).unwrap();
        assert_eq!(x, [106, 107, 40]);
        assert!(v.read_at(23, &mut x).is_err());
        // a segment without legs reads zeros (unmapped thin blocks)
        let io2 = io_of(vec![(0..8u8).collect()]);
        let z = Vol::new(
            io2,
            vec![
                Segment {
                    start: 0,
                    len: 4,
                    legs: vec![],
                    stripe: 0,
                },
                Segment {
                    start: 4,
                    len: 4,
                    legs: vec![(0, 2)],
                    stripe: 0,
                },
            ],
        );
        assert_eq!(z.read_vec(0, 8).unwrap(), [0, 0, 0, 0, 2, 3, 4, 5]);
    }
}
