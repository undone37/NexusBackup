//! Minimal NBD client (fixed newstyle, structured replies, block status) for
//! reading PVE/QEMU exports and their dirty bitmaps. Transport-agnostic: works
//! over a Unix socket or the stdio of an `ssh` process.
//! Spec: https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md

use std::io::{self, Read, Seek, SeekFrom, Write};

const NBDMAGIC: u64 = 0x4e42_444d_4147_4943; // "NBDMAGIC"
const IHAVEOPT: u64 = 0x4948_4156_454f_5054; // "IHAVEOPT"
const REPLY_MAGIC: u64 = 0x0003_e889_0455_65a9;
const REQUEST_MAGIC: u32 = 0x2560_9513;
const SIMPLE_REPLY_MAGIC: u32 = 0x6744_6698;
const STRUCTURED_REPLY_MAGIC: u32 = 0x668e_33ef;

const FLAG_FIXED_NEWSTYLE: u16 = 1;
const FLAG_NO_ZEROES: u16 = 2;

const OPT_GO: u32 = 7;
const OPT_STRUCTURED_REPLY: u32 = 8;
const OPT_SET_META_CONTEXT: u32 = 10;
const REP_ACK: u32 = 1;
const REP_INFO: u32 = 3;
const REP_META_CONTEXT: u32 = 4;
const INFO_EXPORT: u16 = 0;

const CMD_READ: u16 = 0;
const CMD_DISC: u16 = 2;
const CMD_BLOCK_STATUS: u16 = 7;

const REPLY_FLAG_DONE: u16 = 1;
const REPLY_NONE: u16 = 0;
const REPLY_OFFSET_DATA: u16 = 1;
const REPLY_OFFSET_HOLE: u16 = 2;
const REPLY_BLOCK_STATUS: u16 = 5;

/// Largest single request; QEMU's default maximum block size.
pub const MAX_REQUEST: u32 = 32 << 20;

fn proto(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("nbd: {}", msg.into()))
}

pub struct Client<R, W> {
    r: R,
    w: W,
    size: u64,
    pos: u64,
    cookie: u64,
    /// meta context name -> id, as acknowledged by the server
    contexts: Vec<(String, u32)>,
}

fn rd<const N: usize>(r: &mut impl Read) -> io::Result<[u8; N]> {
    let mut b = [0u8; N];
    r.read_exact(&mut b)?;
    Ok(b)
}
fn u16_(r: &mut impl Read) -> io::Result<u16> {
    Ok(u16::from_be_bytes(rd(r)?))
}
fn u32_(r: &mut impl Read) -> io::Result<u32> {
    Ok(u32::from_be_bytes(rd(r)?))
}
fn u64_(r: &mut impl Read) -> io::Result<u64> {
    Ok(u64::from_be_bytes(rd(r)?))
}
fn bytes(r: &mut impl Read, n: usize) -> io::Result<Vec<u8>> {
    let mut b = vec![0u8; n];
    r.read_exact(&mut b)?;
    Ok(b)
}
fn with_len(s: &str) -> Vec<u8> {
    [&(s.len() as u32).to_be_bytes()[..], s.as_bytes()].concat()
}

impl<R: Read, W: Write> Client<R, W> {
    /// Handshake and enter transmission for `export`, requesting the given
    /// meta contexts (e.g. `qemu:dirty-bitmap:<name>`, `base:allocation`).
    pub fn connect(mut r: R, mut w: W, export: &str, meta: &[&str]) -> io::Result<Self> {
        if u64_(&mut r)? != NBDMAGIC || u64_(&mut r)? != IHAVEOPT {
            return Err(proto("not a newstyle NBD server"));
        }
        let flags = u16_(&mut r)?;
        if flags & FLAG_FIXED_NEWSTYLE == 0 || flags & FLAG_NO_ZEROES == 0 {
            return Err(proto("server lacks fixed newstyle / no-zeroes"));
        }
        w.write_all(&u32::from(FLAG_FIXED_NEWSTYLE | FLAG_NO_ZEROES).to_be_bytes())?;
        let mut c = Client {
            r,
            w,
            size: 0,
            pos: 0,
            cookie: 0,
            contexts: vec![],
        };

        c.option(OPT_STRUCTURED_REPLY, &[])?;
        c.expect_ack(OPT_STRUCTURED_REPLY)?;

        if !meta.is_empty() {
            let mut d = with_len(export);
            d.extend((meta.len() as u32).to_be_bytes());
            meta.iter().for_each(|m| d.extend(with_len(m)));
            c.option(OPT_SET_META_CONTEXT, &d)?;
            loop {
                let (ty, data) = c.opt_reply(OPT_SET_META_CONTEXT)?;
                match ty {
                    REP_ACK => break,
                    REP_META_CONTEXT if data.len() >= 4 => c.contexts.push((
                        String::from_utf8_lossy(&data[4..]).into_owned(),
                        u32::from_be_bytes(data[..4].try_into().unwrap()),
                    )),
                    _ => return Err(proto(format!("unexpected meta context reply {ty}"))),
                }
            }
            if let Some(missing) = meta.iter().find(|m| c.context_id(m).is_none()) {
                return Err(proto(format!("server does not offer meta context {missing}")));
            }
        }

        let mut d = with_len(export);
        d.extend(0u16.to_be_bytes()); // no extra info requests; INFO_EXPORT is mandatory
        c.option(OPT_GO, &d)?;
        loop {
            let (ty, data) = c.opt_reply(OPT_GO)?;
            match ty {
                REP_ACK => break,
                REP_INFO if data.len() >= 12 && u16::from_be_bytes([data[0], data[1]]) == INFO_EXPORT => {
                    c.size = u64::from_be_bytes(data[2..10].try_into().unwrap());
                }
                REP_INFO => {}
                _ => return Err(proto(format!("unexpected GO reply {ty}"))),
            }
        }
        Ok(c)
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn context_id(&self, name: &str) -> Option<u32> {
        self.contexts.iter().find(|(n, _)| n == name).map(|(_, id)| *id)
    }

    fn option(&mut self, opt: u32, data: &[u8]) -> io::Result<()> {
        let mut m = Vec::with_capacity(16 + data.len());
        m.extend(IHAVEOPT.to_be_bytes());
        m.extend(opt.to_be_bytes());
        m.extend((data.len() as u32).to_be_bytes());
        m.extend(data);
        self.w.write_all(&m)?;
        self.w.flush()
    }

    fn opt_reply(&mut self, opt: u32) -> io::Result<(u32, Vec<u8>)> {
        if u64_(&mut self.r)? != REPLY_MAGIC || u32_(&mut self.r)? != opt {
            return Err(proto("bad option reply"));
        }
        let ty = u32_(&mut self.r)?;
        let len = u32_(&mut self.r)? as usize;
        if len > 1 << 20 {
            return Err(proto("option reply too large"));
        }
        let data = bytes(&mut self.r, len)?;
        if ty & 0x8000_0000 != 0 {
            return Err(proto(format!(
                "option {opt} refused ({ty:#x}): {}",
                String::from_utf8_lossy(&data)
            )));
        }
        Ok((ty, data))
    }

    fn expect_ack(&mut self, opt: u32) -> io::Result<()> {
        match self.opt_reply(opt)?.0 {
            REP_ACK => Ok(()),
            t => Err(proto(format!("expected ACK, got {t}"))),
        }
    }

    fn request(&mut self, ty: u16, offset: u64, len: u32) -> io::Result<u64> {
        self.cookie += 1;
        let mut m = Vec::with_capacity(28);
        m.extend(REQUEST_MAGIC.to_be_bytes());
        m.extend(0u16.to_be_bytes());
        m.extend(ty.to_be_bytes());
        m.extend(self.cookie.to_be_bytes());
        m.extend(offset.to_be_bytes());
        m.extend(len.to_be_bytes());
        self.w.write_all(&m)?;
        self.w.flush()?;
        Ok(self.cookie)
    }

    /// Reads reply chunks for `cookie` until DONE, calling `f(type, payload)`.
    // ponytail: one request in flight; pipeline requests if SSH latency limits throughput.
    fn replies(&mut self, cookie: u64, mut f: impl FnMut(u16, Vec<u8>) -> io::Result<()>) -> io::Result<()> {
        loop {
            match u32_(&mut self.r)? {
                SIMPLE_REPLY_MAGIC => {
                    let err = u32_(&mut self.r)?;
                    if u64_(&mut self.r)? != cookie {
                        return Err(proto("cookie mismatch"));
                    }
                    return if err == 0 {
                        Ok(())
                    } else {
                        Err(proto(format!("server error {err}")))
                    };
                }
                STRUCTURED_REPLY_MAGIC => {
                    let flags = u16_(&mut self.r)?;
                    let ty = u16_(&mut self.r)?;
                    if u64_(&mut self.r)? != cookie {
                        return Err(proto("cookie mismatch"));
                    }
                    let len = u32_(&mut self.r)?;
                    if len > MAX_REQUEST + 4096 {
                        return Err(proto("reply chunk too large"));
                    }
                    let payload = bytes(&mut self.r, len as usize)?;
                    if ty & 0x8000 != 0 {
                        let (code, msg) = match payload.get(..6) {
                            Some(h) => {
                                let ml = u16::from_be_bytes([h[4], h[5]]) as usize;
                                (
                                    u32::from_be_bytes(h[..4].try_into().unwrap()),
                                    payload.get(6..6 + ml).unwrap_or(&[]),
                                )
                            }
                            None => (0, &[][..]),
                        };
                        return Err(proto(format!("error {code}: {}", String::from_utf8_lossy(msg))));
                    }
                    f(ty, payload)?;
                    if flags & REPLY_FLAG_DONE != 0 {
                        return Ok(());
                    }
                }
                m => return Err(proto(format!("bad reply magic {m:#x}"))),
            }
        }
    }

    /// Reads `buf.len()` bytes at `offset`; holes come back as zeroes.
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        for (i, piece) in buf.chunks_mut(MAX_REQUEST as usize).enumerate() {
            let off = offset + i as u64 * MAX_REQUEST as u64;
            piece.fill(0);
            let cookie = self.request(CMD_READ, off, piece.len() as u32)?;
            self.replies(cookie, |ty, p| {
                if ty != REPLY_OFFSET_DATA && ty != REPLY_OFFSET_HOLE {
                    return if ty == REPLY_NONE {
                        Ok(())
                    } else {
                        Err(proto(format!("unexpected read reply {ty}")))
                    };
                }
                if p.len() < 8 {
                    return Err(proto("short read chunk"));
                }
                let at = u64::from_be_bytes(p[..8].try_into().unwrap()).wrapping_sub(off) as usize;
                if ty == REPLY_OFFSET_DATA {
                    let data = &p[8..];
                    piece
                        .get_mut(at..at + data.len())
                        .ok_or_else(|| proto("read chunk out of range"))?
                        .copy_from_slice(data);
                }
                Ok(()) // holes: already zero
            })?;
        }
        Ok(())
    }

    /// Extents `(offset, length, flags)` of meta context `ctx` over the whole export.
    pub fn block_status(&mut self, ctx: &str) -> io::Result<Vec<(u64, u64, u32)>> {
        let id = self
            .context_id(ctx)
            .ok_or_else(|| proto(format!("meta context {ctx} not negotiated")))?;
        let mut out = Vec::new();
        let mut off = 0u64;
        while off < self.size {
            let len = (self.size - off).min(1 << 30) as u32;
            let cookie = self.request(CMD_BLOCK_STATUS, off, len)?;
            let mut got = 0u64;
            self.replies(cookie, |ty, p| {
                if ty != REPLY_BLOCK_STATUS || p.len() < 4 || u32::from_be_bytes(p[..4].try_into().unwrap()) != id {
                    return Ok(()); // other contexts / NONE
                }
                for d in p[4..].chunks_exact(8) {
                    let l = u32::from_be_bytes(d[..4].try_into().unwrap()) as u64;
                    out.push((off + got, l, u32::from_be_bytes(d[4..].try_into().unwrap())));
                    got += l;
                }
                Ok(())
            })?;
            if got == 0 {
                return Err(proto("block status made no progress"));
            }
            off += got;
        }
        if let Some(last) = out.last_mut() {
            last.1 = last.1.min(self.size - last.0); // servers may overshoot the end
        }
        Ok(out)
    }

    pub fn disconnect(mut self) -> io::Result<()> {
        self.request(CMD_DISC, 0, 0)?;
        Ok(())
    }
}

/// `(offset, len)` of extents with `flag` set (dirty bitmap: flag 1), adjacent ones merged.
pub fn flagged(extents: &[(u64, u64, u32)], flag: u32) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    for &(off, len, _) in extents.iter().filter(|e| e.2 & flag != 0 && e.1 > 0) {
        match out.last_mut() {
            Some(last) if last.0 + last.1 == off => last.1 += len,
            _ => out.push((off, len)),
        }
    }
    out
}

impl<R: Read, W: Write> Read for Client<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = (buf.len() as u64).min(self.size - self.pos).min(MAX_REQUEST as u64) as usize;
        self.read_at(self.pos, &mut buf[..n])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl<R: Read, W: Write> Seek for Client<R, W> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        self.pos = match to {
            SeekFrom::Start(p) => p,
            SeekFrom::End(d) => self
                .size
                .checked_add_signed(d)
                .ok_or_else(|| proto("seek before start"))?,
            SeekFrom::Current(d) => self
                .pos
                .checked_add_signed(d)
                .ok_or_else(|| proto("seek before start"))?,
        }
        .min(self.size);
        Ok(self.pos)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn flagged_merges_adjacent() {
        let ext = [(0, 100, 0), (100, 1, 1), (101, 299, 0), (400, 100, 1), (500, 100, 3)];
        assert_eq!(super::flagged(&ext, 1), vec![(100, 1), (400, 200)]);
    }
}
