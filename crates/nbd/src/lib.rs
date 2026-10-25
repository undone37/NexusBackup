//! Minimal NBD client (fixed newstyle, structured replies, block status) for
//! reading PVE/QEMU exports and their dirty bitmaps, and (Phase 30, in-place
//! rollback) writing to a writable export. Transport-agnostic: works over a
//! Unix socket or the stdio of an `ssh` process; with [`greet`], [`starttls`] and
//! [`Client::negotiate`] the caller puts TLS in between (XCP-ng's xapi-nbd, #40).
//! Spec: <https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md>

#![warn(missing_docs)]

pub mod server;

use std::io::{self, Read, Seek, SeekFrom, Write};

const NBDMAGIC: u64 = 0x4e42_444d_4147_4943; // "NBDMAGIC"
const IHAVEOPT: u64 = 0x4948_4156_454f_5054; // "IHAVEOPT"
const REPLY_MAGIC: u64 = 0x0003_e889_0455_65a9;
const REQUEST_MAGIC: u32 = 0x2560_9513;
const SIMPLE_REPLY_MAGIC: u32 = 0x6744_6698;
const STRUCTURED_REPLY_MAGIC: u32 = 0x668e_33ef;

const FLAG_FIXED_NEWSTYLE: u16 = 1;
const FLAG_NO_ZEROES: u16 = 2;

const OPT_EXPORT_NAME: u32 = 1;
const OPT_STARTTLS: u32 = 5;
const OPT_GO: u32 = 7;
const OPT_STRUCTURED_REPLY: u32 = 8;
const OPT_SET_META_CONTEXT: u32 = 10;
const REP_ACK: u32 = 1;
const REP_INFO: u32 = 3;
const REP_META_CONTEXT: u32 = 4;
const REP_ERR_UNSUP: u32 = 0x8000_0001;
const INFO_EXPORT: u16 = 0;

const CMD_READ: u16 = 0;
const CMD_WRITE: u16 = 1;
const CMD_DISC: u16 = 2;
const CMD_FLUSH: u16 = 3;
/// transmission flags (INFO_EXPORT)
const TFLAG_READ_ONLY: u16 = 1 << 1;
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

/// NBD client connection over a reader/writer pair (socket halves or an `ssh` process's stdout/stdin).
/// Created by [`Client::connect`] / [`Client::connect_opt`], which run the handshake and select the export.
pub struct Client<R, W> {
    r: R,
    w: W,
    size: u64,
    pos: u64,
    cookie: u64,
    /// meta context name -> id, as acknowledged by the server
    contexts: Vec<(String, u32)>,
    /// transmission flags of the export
    tflags: u16,
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

fn send_opt(w: &mut impl Write, opt: u32, data: &[u8]) -> io::Result<()> {
    let mut m = Vec::with_capacity(16 + data.len());
    m.extend(IHAVEOPT.to_be_bytes());
    m.extend(opt.to_be_bytes());
    m.extend((data.len() as u32).to_be_bytes());
    m.extend(data);
    w.write_all(&m)?;
    w.flush()
}

/// An option reply; an error reply is an `Err` (`ErrorKind::Unsupported` for `NBD_REP_ERR_UNSUP`).
fn recv_opt(r: &mut impl Read, opt: u32) -> io::Result<(u32, Vec<u8>)> {
    if u64_(r)? != REPLY_MAGIC || u32_(r)? != opt {
        return Err(proto("bad option reply"));
    }
    let ty = u32_(r)?;
    let len = u32_(r)? as usize;
    if len > 1 << 20 {
        return Err(proto("option reply too large"));
    }
    let data = bytes(r, len)?;
    if ty & 0x8000_0000 != 0 {
        let msg = format!(
            "nbd: option {opt} refused ({ty:#x}): {}",
            String::from_utf8_lossy(&data)
        );
        let kind = if ty == REP_ERR_UNSUP {
            io::ErrorKind::Unsupported
        } else {
            io::ErrorKind::InvalidData
        };
        return Err(io::Error::new(kind, msg));
    }
    Ok((ty, data))
}

/// The greeting of a fixed-newstyle server: its magic and handshake flags, our client flags. Returns whether the
/// server takes `NO_ZEROES` (xapi-nbd does not: its `NBD_OPT_EXPORT_NAME` reply then ends with 124 zero bytes).
pub fn greet(r: &mut impl Read, w: &mut impl Write) -> io::Result<bool> {
    if u64_(r)? != NBDMAGIC || u64_(r)? != IHAVEOPT {
        return Err(proto("not a newstyle NBD server"));
    }
    let flags = u16_(r)?;
    if flags & FLAG_FIXED_NEWSTYLE == 0 {
        return Err(proto("server lacks fixed newstyle"));
    }
    let no_zeroes = flags & FLAG_NO_ZEROES != 0;
    let ours = FLAG_FIXED_NEWSTYLE | if no_zeroes { FLAG_NO_ZEROES } else { 0 };
    w.write_all(&u32::from(ours).to_be_bytes())?;
    w.flush()?;
    Ok(no_zeroes)
}

/// `NBD_OPT_STARTTLS` after [`greet`]: on `Ok` the caller runs the TLS handshake on the same connection and continues
/// with [`Client::negotiate`] over it.
pub fn starttls(r: &mut impl Read, w: &mut impl Write) -> io::Result<()> {
    send_opt(w, OPT_STARTTLS, &[])?;
    match recv_opt(r, OPT_STARTTLS)?.0 {
        REP_ACK => Ok(()),
        t => Err(proto(format!("STARTTLS: expected ACK, got {t}"))),
    }
}

impl<R: Read, W: Write> Client<R, W> {
    /// Handshake and enter transmission for `export`, requesting the given
    /// meta contexts (e.g. `qemu:dirty-bitmap:<name>`, `base:allocation`).
    pub fn connect(r: R, w: W, export: &str, meta: &[&str]) -> io::Result<Self> {
        Self::connect_opt(r, w, export, meta, &[])
    }

    /// Like `connect`; the `optional` meta contexts are requested too, but a server
    /// without them is fine (check `context_id` afterwards).
    pub fn connect_opt(mut r: R, mut w: W, export: &str, meta: &[&str], optional: &[&str]) -> io::Result<Self> {
        let no_zeroes = greet(&mut r, &mut w)?;
        Self::negotiate(r, w, export, meta, optional, no_zeroes)
    }

    /// The options after [`greet`] (and [`starttls`]): structured replies and meta contexts where offered, then the
    /// export with `NBD_OPT_GO`, or `NBD_OPT_EXPORT_NAME` on a server without GO (xapi-nbd, which also denies the
    /// `NBD_OPT_LIST` some clients send first).
    pub fn negotiate(r: R, w: W, export: &str, meta: &[&str], optional: &[&str], no_zeroes: bool) -> io::Result<Self> {
        let mut c = Client {
            r,
            w,
            size: 0,
            pos: 0,
            cookie: 0,
            contexts: vec![],
            tflags: 0,
        };

        // structured replies are required for block status only; plain reads fall back to simple replies
        c.option(OPT_STRUCTURED_REPLY, &[])?;
        let structured = c.expect_ack(OPT_STRUCTURED_REPLY).is_ok();
        if !structured && !meta.is_empty() {
            return Err(proto("server refuses structured replies, needed for meta contexts"));
        }
        let wanted: Vec<&str> = if structured {
            meta.iter().chain(optional).copied().collect()
        } else {
            Vec::new()
        };

        if !wanted.is_empty() {
            let mut d = with_len(export);
            d.extend((wanted.len() as u32).to_be_bytes());
            wanted.iter().for_each(|m| d.extend(with_len(m)));
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
            let (ty, data) = match c.opt_reply(OPT_GO) {
                Ok(r) => r,
                Err(e) if e.kind() == io::ErrorKind::Unsupported && wanted.is_empty() => {
                    // the old way: the size and transmission flags follow at once (no zero padding: NO_ZEROES)
                    send_opt(&mut c.w, OPT_EXPORT_NAME, export.as_bytes())?;
                    c.size = u64_(&mut c.r)?;
                    c.tflags = u16_(&mut c.r)?;
                    if !no_zeroes {
                        bytes(&mut c.r, 124)?;
                    }
                    break;
                }
                Err(e) => return Err(e),
            };
            match ty {
                REP_ACK => break,
                REP_INFO if data.len() >= 12 && u16::from_be_bytes([data[0], data[1]]) == INFO_EXPORT => {
                    c.size = u64::from_be_bytes(data[2..10].try_into().unwrap());
                    c.tflags = u16::from_be_bytes([data[10], data[11]]);
                }
                REP_INFO => {}
                _ => return Err(proto(format!("unexpected GO reply {ty}"))),
            }
        }
        Ok(c)
    }

    /// Export size in bytes, as announced by the server.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The export refuses writes.
    pub fn read_only(&self) -> bool {
        self.tflags & TFLAG_READ_ONLY != 0
    }

    /// Id the server assigned to meta context `name` (for example `qemu:dirty-bitmap:...`); `None` if it was not
    /// requested or the server did not acknowledge it.
    pub fn context_id(&self, name: &str) -> Option<u32> {
        self.contexts.iter().find(|(n, _)| n == name).map(|(_, id)| *id)
    }

    fn option(&mut self, opt: u32, data: &[u8]) -> io::Result<()> {
        send_opt(&mut self.w, opt, data)
    }

    fn opt_reply(&mut self, opt: u32) -> io::Result<(u32, Vec<u8>)> {
        recv_opt(&mut self.r, opt)
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
    /// A simple reply to a read (`simple_read = (offset, len)`) is passed on as OFFSET_DATA.
    // ponytail: one request in flight; pipeline requests if SSH latency limits throughput.
    fn replies(
        &mut self,
        cookie: u64,
        simple_read: Option<(u64, usize)>,
        mut f: impl FnMut(u16, Vec<u8>) -> io::Result<()>,
    ) -> io::Result<()> {
        loop {
            match u32_(&mut self.r)? {
                SIMPLE_REPLY_MAGIC => {
                    let err = u32_(&mut self.r)?;
                    if u64_(&mut self.r)? != cookie {
                        return Err(proto("cookie mismatch"));
                    }
                    if err != 0 {
                        return Err(proto(format!("server error {err}")));
                    }
                    if let Some((off, len)) = simple_read {
                        let mut p = off.to_be_bytes().to_vec();
                        p.extend(bytes(&mut self.r, len)?);
                        f(REPLY_OFFSET_DATA, p)?;
                    }
                    return Ok(());
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
            self.replies(cookie, Some((off, piece.len())), |ty, p| {
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
                        .get_mut(
                            at..at
                                .checked_add(data.len())
                                .ok_or_else(|| proto("read chunk out of range"))?,
                        )
                        .ok_or_else(|| proto("read chunk out of range"))?
                        .copy_from_slice(data);
                }
                Ok(()) // holes: already zero
            })?;
        }
        Ok(())
    }

    /// Reads `ranges` (`(offset, len)`, each at most [`MAX_REQUEST`]) with up to `depth`
    /// requests in flight and hands each one's bytes to `sink(index, data)` in range order.
    /// Replies may arrive in any order and interleave (structured replies); holes come back as
    /// zeroes. At most `depth` ranges are held at once (in flight or waiting for delivery).
    /// One request at a time pays a full round trip per read; over SSH that, not bandwidth,
    /// limited VM backups.
    pub fn read_many(
        &mut self,
        ranges: &[(u64, u64)],
        depth: usize,
        mut sink: impl FnMut(usize, Vec<u8>) -> io::Result<()>,
    ) -> io::Result<()> {
        use std::collections::{BTreeMap, HashMap};
        let depth = depth.max(1);
        if let Some(r) = ranges.iter().find(|r| r.1 > MAX_REQUEST as u64) {
            return Err(proto(format!("read of {} bytes exceeds one request", r.1)));
        }
        // cookie -> (index, offset, buffer)
        let mut pending: HashMap<u64, (usize, u64, Vec<u8>)> = HashMap::new();
        let mut ready: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
        let (mut next_send, mut next_out) = (0usize, 0usize);
        while next_out < ranges.len() {
            let mut sent = false;
            while next_send < ranges.len() && pending.len() + ready.len() < depth {
                let (off, len) = ranges[next_send];
                self.cookie += 1;
                let mut m = Vec::with_capacity(28);
                m.extend(REQUEST_MAGIC.to_be_bytes());
                m.extend(0u16.to_be_bytes());
                m.extend(CMD_READ.to_be_bytes());
                m.extend(self.cookie.to_be_bytes());
                m.extend(off.to_be_bytes());
                m.extend((len as u32).to_be_bytes());
                self.w.write_all(&m)?;
                pending.insert(self.cookie, (next_send, off, vec![0u8; len as usize]));
                next_send += 1;
                sent = true;
            }
            if sent {
                self.w.flush()?;
            }
            if !pending.is_empty() {
                match u32_(&mut self.r)? {
                    SIMPLE_REPLY_MAGIC => {
                        let err = u32_(&mut self.r)?;
                        let cookie = u64_(&mut self.r)?;
                        let (idx, _, mut buf) = pending
                            .remove(&cookie)
                            .ok_or_else(|| proto("reply for an unknown cookie"))?;
                        if err != 0 {
                            return Err(proto(format!("server error {err}")));
                        }
                        self.r.read_exact(&mut buf)?;
                        ready.insert(idx, buf);
                    }
                    STRUCTURED_REPLY_MAGIC => {
                        let flags = u16_(&mut self.r)?;
                        let ty = u16_(&mut self.r)?;
                        let cookie = u64_(&mut self.r)?;
                        let len = u32_(&mut self.r)?;
                        if len > MAX_REQUEST + 4096 {
                            return Err(proto("reply chunk too large"));
                        }
                        let payload = bytes(&mut self.r, len as usize)?;
                        let entry = pending
                            .get_mut(&cookie)
                            .ok_or_else(|| proto("reply for an unknown cookie"))?;
                        if ty & 0x8000 != 0 {
                            let msg = payload
                                .get(6..)
                                .map(|m| String::from_utf8_lossy(m).into_owned())
                                .unwrap_or_default();
                            return Err(proto(format!("read error: {msg}")));
                        }
                        if ty == REPLY_OFFSET_DATA || ty == REPLY_OFFSET_HOLE {
                            if payload.len() < 8 {
                                return Err(proto("short read chunk"));
                            }
                            let at =
                                u64::from_be_bytes(payload[..8].try_into().unwrap()).wrapping_sub(entry.1) as usize;
                            let n = if ty == REPLY_OFFSET_DATA {
                                payload.len() - 8
                            } else {
                                u32::from_be_bytes(
                                    payload
                                        .get(8..12)
                                        .ok_or_else(|| proto("short hole chunk"))?
                                        .try_into()
                                        .unwrap(),
                                ) as usize
                            };
                            let dst = entry
                                .2
                                .get_mut(at..at.checked_add(n).ok_or_else(|| proto("read chunk out of range"))?)
                                .ok_or_else(|| proto("read chunk out of range"))?;
                            if ty == REPLY_OFFSET_DATA {
                                dst.copy_from_slice(&payload[8..]);
                            } else {
                                dst.fill(0);
                            }
                        } else if ty != REPLY_NONE {
                            return Err(proto(format!("unexpected read reply {ty}")));
                        }
                        if flags & REPLY_FLAG_DONE != 0 {
                            let (idx, _, buf) = pending.remove(&cookie).unwrap();
                            ready.insert(idx, buf);
                        }
                    }
                    m => return Err(proto(format!("bad reply magic {m:#x}"))),
                }
            }
            while let Some(buf) = ready.remove(&next_out) {
                sink(next_out, buf)?;
                next_out += 1;
            }
        }
        Ok(())
    }

    /// Writes `writes` (`(offset, data)`, each at most [`MAX_REQUEST`] bytes and inside
    /// the export) with up to `depth` requests in flight; `done(index)` is called once
    /// the server acknowledged a write (in any order). Writes are not durable before
    /// [`Client::flush`].
    pub fn write_many(
        &mut self,
        writes: impl IntoIterator<Item = io::Result<(u64, Vec<u8>)>>,
        depth: usize,
        mut done: impl FnMut(usize, u64),
    ) -> io::Result<()> {
        use std::collections::HashMap;
        if self.read_only() {
            return Err(proto("the export is read-only"));
        }
        let depth = depth.max(1);
        // cookie -> (index, bytes)
        let mut pending: HashMap<u64, (usize, u64)> = HashMap::new();
        let mut it = writes.into_iter().enumerate();
        let mut more = true;
        while more || !pending.is_empty() {
            let mut sent = false;
            while more && pending.len() < depth {
                let Some((i, w)) = it.next() else {
                    more = false;
                    break;
                };
                let (off, data) = w?;
                if data.len() > MAX_REQUEST as usize || off.checked_add(data.len() as u64).is_none_or(|e| e > self.size)
                {
                    return Err(proto(format!(
                        "write of {} bytes at {off} outside the export",
                        data.len()
                    )));
                }
                self.cookie += 1;
                let mut m = Vec::with_capacity(28);
                m.extend(REQUEST_MAGIC.to_be_bytes());
                m.extend(0u16.to_be_bytes());
                m.extend(CMD_WRITE.to_be_bytes());
                m.extend(self.cookie.to_be_bytes());
                m.extend(off.to_be_bytes());
                m.extend((data.len() as u32).to_be_bytes());
                self.w.write_all(&m)?;
                self.w.write_all(&data)?;
                pending.insert(self.cookie, (i, data.len() as u64));
                sent = true;
            }
            if sent {
                self.w.flush()?;
            }
            if pending.is_empty() {
                continue;
            }
            let (cookie, err) = match u32_(&mut self.r)? {
                SIMPLE_REPLY_MAGIC => {
                    let err = u32_(&mut self.r)?;
                    (u64_(&mut self.r)?, (err != 0).then(|| format!("server error {err}")))
                }
                STRUCTURED_REPLY_MAGIC => {
                    let flags = u16_(&mut self.r)?;
                    let ty = u16_(&mut self.r)?;
                    let cookie = u64_(&mut self.r)?;
                    let len = u32_(&mut self.r)?;
                    if len > 1 << 16 {
                        return Err(proto("write reply too large"));
                    }
                    let payload = bytes(&mut self.r, len as usize)?;
                    if ty & 0x8000 != 0 {
                        (
                            cookie,
                            Some(format!(
                                "write error: {}",
                                String::from_utf8_lossy(payload.get(6..).unwrap_or(&[]))
                            )),
                        )
                    } else if flags & REPLY_FLAG_DONE == 0 {
                        continue;
                    } else {
                        (cookie, None)
                    }
                }
                m => return Err(proto(format!("bad reply magic {m:#x}"))),
            };
            let (i, n) = pending
                .remove(&cookie)
                .ok_or_else(|| proto("reply for an unknown cookie"))?;
            if let Some(e) = err {
                return Err(proto(e));
            }
            done(i, n);
        }
        Ok(())
    }

    /// Writes `data` at `offset` (one request per [`MAX_REQUEST`] piece).
    pub fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()> {
        let pieces = data
            .chunks(MAX_REQUEST as usize)
            .enumerate()
            .map(|(i, p)| Ok((offset + i as u64 * MAX_REQUEST as u64, p.to_vec())));
        self.write_many(pieces, 1, |_, _| {})
    }

    /// Makes every acknowledged write durable (NBD_CMD_FLUSH).
    pub fn flush(&mut self) -> io::Result<()> {
        let cookie = self.request(CMD_FLUSH, 0, 0)?;
        self.replies(cookie, None, |_, _| Ok(()))
    }

    /// Extents `(offset, length, flags)` of meta context `ctx` over the whole export.
    pub fn block_status(&mut self, ctx: &str) -> io::Result<Vec<(u64, u64, u32)>> {
        let id = self
            .context_id(ctx)
            .ok_or_else(|| proto(format!("meta context {ctx} not negotiated")))?;
        let mut out = Vec::new();
        let mut off = 0u64;
        while off < self.size {
            let len = (self.size - off).min(1 << 30);
            let cookie = self.request(CMD_BLOCK_STATUS, off, len as u32)?;
            let mut got = 0u64;
            self.replies(cookie, None, |ty, p| {
                if ty != REPLY_BLOCK_STATUS || p.len() < 4 || u32::from_be_bytes(p[..4].try_into().unwrap()) != id {
                    return Ok(()); // other contexts / NONE
                }
                for d in p[4..].as_chunks::<8>().0 {
                    // servers may overshoot the requested range: clip, never step past it
                    let l = (u32::from_be_bytes(d[..4].try_into().unwrap()) as u64).min(len - got);
                    if l > 0 {
                        out.push((off + got, l, u32::from_be_bytes(d[4..].try_into().unwrap())));
                        got += l;
                    }
                }
                Ok(())
            })?;
            if got == 0 {
                return Err(proto("block status made no progress"));
            }
            off += got;
        }
        Ok(out)
    }

    /// Sends `NBD_CMD_DISC` and drops the connection. The server sends no reply.
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

    /// read_many with replies out of order and interleaved structured chunks (data, hole,
    /// done on a NONE chunk) delivers every range intact and in range order.
    #[test]
    fn read_many_reorders_and_reassembles() {
        fn chunk(flags: u16, ty: u16, cookie: u64, payload: &[u8]) -> Vec<u8> {
            let mut m = Vec::new();
            m.extend(STRUCTURED_REPLY_MAGIC.to_be_bytes());
            m.extend(flags.to_be_bytes());
            m.extend(ty.to_be_bytes());
            m.extend(cookie.to_be_bytes());
            m.extend((payload.len() as u32).to_be_bytes());
            m.extend(payload);
            m
        }
        let data = |off: u64, b: &[u8]| [&off.to_be_bytes()[..], b].concat();
        // three reads of 8 bytes at 0, 100, 200 (cookies 1, 2, 3)
        let mut r = Vec::new();
        r.extend(chunk(0, REPLY_OFFSET_DATA, 3, &data(204, b"WXYZ"))); // cookie 3, second half first
        r.extend(chunk(0, REPLY_OFFSET_DATA, 2, &data(100, b"ijklmnop")));
        r.extend(chunk(0, REPLY_OFFSET_DATA, 3, &data(200, b"STUV")));
        r.extend(chunk(REPLY_FLAG_DONE, REPLY_NONE, 3, &[]));
        r.extend(chunk(REPLY_FLAG_DONE, REPLY_NONE, 2, &[]));
        r.extend(chunk(0, REPLY_OFFSET_DATA, 1, &data(0, b"abcd")));
        r.extend(chunk(
            REPLY_FLAG_DONE,
            REPLY_OFFSET_HOLE,
            1,
            &[&4u64.to_be_bytes()[..], &4u32.to_be_bytes()[..]].concat(),
        ));
        let mut c = Client {
            r: std::io::Cursor::new(r),
            w: Vec::new(),
            size: 1 << 20,
            pos: 0,
            cookie: 0,
            contexts: vec![],
            tflags: 0,
        };
        let mut got = Vec::new();
        c.read_many(&[(0, 8), (100, 8), (200, 8)], 3, |i, b| {
            got.push((i, b));
            Ok(())
        })
        .unwrap();
        assert_eq!(
            got,
            vec![
                (0, b"abcd\0\0\0\0".to_vec()),
                (1, b"ijklmnop".to_vec()),
                (2, b"STUVWXYZ".to_vec())
            ]
        );
        // three requests went out before any reply was needed
        assert_eq!(c.w.len(), 3 * 28);
    }

    use super::*;

    fn optrep(opt: u32, ty: u32, data: &[u8]) -> Vec<u8> {
        [
            &REPLY_MAGIC.to_be_bytes()[..],
            &opt.to_be_bytes(),
            &ty.to_be_bytes(),
            &(data.len() as u32).to_be_bytes(),
            data,
        ]
        .concat()
    }

    /// Server side of a handshake with structured replies, one meta context (id 1)
    /// and an export of `size` bytes.
    fn handshake(size: u64) -> Vec<u8> {
        let mut info = INFO_EXPORT.to_be_bytes().to_vec();
        info.extend(size.to_be_bytes());
        info.extend(3u16.to_be_bytes());
        [
            &NBDMAGIC.to_be_bytes()[..],
            &IHAVEOPT.to_be_bytes(),
            &3u16.to_be_bytes(),
            &optrep(OPT_STRUCTURED_REPLY, REP_ACK, &[]),
            &optrep(OPT_SET_META_CONTEXT, REP_META_CONTEXT, b"\0\0\0\x01ctx"),
            &optrep(OPT_SET_META_CONTEXT, REP_ACK, &[]),
            &optrep(OPT_GO, REP_INFO, &info),
            &optrep(OPT_GO, REP_ACK, &[]),
        ]
        .concat()
    }

    fn chunk(flags: u16, ty: u16, cookie: u64, payload: &[u8]) -> Vec<u8> {
        [
            &STRUCTURED_REPLY_MAGIC.to_be_bytes()[..],
            &flags.to_be_bytes(),
            &ty.to_be_bytes(),
            &cookie.to_be_bytes(),
            &(payload.len() as u32).to_be_bytes(),
            payload,
        ]
        .concat()
    }

    /// xapi-nbd (#40): STARTTLS acknowledged, no structured replies, no GO: the export by NBD_OPT_EXPORT_NAME (and no
    /// NBD_OPT_LIST, which it denies); then plain reads with simple replies.
    #[test]
    fn starttls_and_export_name_without_go() {
        let mut s = [
            &NBDMAGIC.to_be_bytes()[..],
            &IHAVEOPT.to_be_bytes(),
            &1u16.to_be_bytes(), // fixed newstyle without NO_ZEROES, as xapi-nbd
        ]
        .concat();
        s.extend(optrep(OPT_STARTTLS, REP_ACK, &[]));
        s.extend(optrep(OPT_STRUCTURED_REPLY, REP_ERR_UNSUP, &[]));
        s.extend(optrep(OPT_GO, REP_ERR_UNSUP, &[]));
        s.extend((8u64 << 20).to_be_bytes());
        s.extend(TFLAG_READ_ONLY.to_be_bytes());
        s.extend([0u8; 124]);
        s.extend(SIMPLE_REPLY_MAGIC.to_be_bytes());
        s.extend(0u32.to_be_bytes());
        s.extend(1u64.to_be_bytes());
        s.extend([7u8; 4]);
        let mut r = &s[..];
        let mut w = Vec::new();
        assert!(!greet(&mut r, &mut w).unwrap(), "no NO_ZEROES offered");
        assert_eq!(w, 1u32.to_be_bytes(), "only the flags the server offers");
        starttls(&mut r, &mut w).unwrap();
        // (TLS would start here)
        let mut c = Client::negotiate(r, w, "/vdi?session_id=x", &[], &[], false).unwrap();
        assert_eq!((c.size(), c.read_only()), (8 << 20, true));
        let mut buf = [0u8; 4];
        c.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, [7; 4]);
        // client: flags, STARTTLS, STRUCTURED_REPLY, GO, EXPORT_NAME, the read; never LIST (3)
        let opts: Vec<u32> =
            c.w.windows(12)
                .filter(|m| m[..8] == IHAVEOPT.to_be_bytes())
                .map(|m| u32::from_be_bytes(m[8..12].try_into().unwrap()))
                .collect();
        assert_eq!(opts, [OPT_STARTTLS, OPT_STRUCTURED_REPLY, OPT_GO, OPT_EXPORT_NAME]);
        // a GO refused for another reason stays an error
        let mut s = [
            &NBDMAGIC.to_be_bytes()[..],
            &IHAVEOPT.to_be_bytes(),
            &3u16.to_be_bytes(),
        ]
        .concat();
        s.extend(optrep(OPT_STRUCTURED_REPLY, REP_ACK, &[]));
        s.extend(optrep(OPT_GO, 0x8000_0006, b"unknown export"));
        assert!(Client::connect(&s[..], io::sink(), "x", &[]).is_err());
    }

    /// Regression (fuzzing): a hostile server overshooting the requested range
    /// panicked on `size - last.0` and could push extents past the export end.
    #[test]
    fn hostile_block_status_is_clipped() {
        let mut s = handshake(1000);
        let mut p = 1u32.to_be_bytes().to_vec();
        for (l, f) in [(600u32, 1u32), (u32::MAX, 0), (u32::MAX, 1)] {
            p.extend(l.to_be_bytes());
            p.extend(f.to_be_bytes());
        }
        s.extend(chunk(REPLY_FLAG_DONE, REPLY_BLOCK_STATUS, 1, &p));
        let mut c = Client::connect(&s[..], io::sink(), "e", &["ctx"]).unwrap();
        assert_eq!(c.block_status("ctx").unwrap(), vec![(0, 600, 1), (600, 400, 0)]);
    }

    /// Regression (fuzzing): a read chunk whose offset wraps the buffer index.
    #[test]
    fn hostile_read_offset_is_an_error() {
        let mut s = handshake(1 << 20);
        let mut p = (u64::MAX - 3).to_be_bytes().to_vec();
        p.extend([1u8; 16]);
        s.extend(chunk(REPLY_FLAG_DONE, REPLY_OFFSET_DATA, 1, &p));
        let mut c = Client::connect(&s[..], io::sink(), "e", &["ctx"]).unwrap();
        let mut buf = [0u8; 64];
        assert_eq!(c.read_at(0, &mut buf).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn flagged_merges_adjacent() {
        let ext = [(0, 100, 0), (100, 1, 1), (101, 299, 0), (400, 100, 1), (500, 100, 3)];
        assert_eq!(super::flagged(&ext, 1), vec![(100, 1), (400, 200)]);
    }
}
