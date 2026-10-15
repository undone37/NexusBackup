//! Minimal read-only NBD server (fixed newstyle, simple replies) for restore
//! and instant recovery. One export, one client per call.

use super::*;

const OPT_EXPORT_NAME: u32 = 1;
const OPT_ABORT: u32 = 2;
const OPT_LIST: u32 = 3;
const OPT_INFO: u32 = 6;
const REP_SERVER: u32 = 2;
const REP_ERR_UNSUP: u32 = 0x8000_0001;
const REP_ERR_INVALID: u32 = 0x8000_0003;
const REP_ERR_UNKNOWN: u32 = 0x8000_0006;
const TFLAG_HAS_FLAGS: u16 = 1;
const TFLAG_READ_ONLY: u16 = 2;
const CMD_WRITE: u16 = 1;
const CMD_FLUSH: u16 = 3;
const EPERM: u32 = 1;
const EINVAL: u32 = 22;
const EIO: u32 = 5;

fn opt_reply(w: &mut impl Write, opt: u32, ty: u32, data: &[u8]) -> io::Result<()> {
    let mut m = Vec::with_capacity(20 + data.len());
    m.extend(REPLY_MAGIC.to_be_bytes());
    m.extend(opt.to_be_bytes());
    m.extend(ty.to_be_bytes());
    m.extend((data.len() as u32).to_be_bytes());
    m.extend(data);
    w.write_all(&m)?;
    w.flush()
}

fn simple_reply(w: &mut impl Write, err: u32, cookie: u64, data: &[u8]) -> io::Result<()> {
    let mut m = Vec::with_capacity(16 + data.len());
    m.extend(SIMPLE_REPLY_MAGIC.to_be_bytes());
    m.extend(err.to_be_bytes());
    m.extend(cookie.to_be_bytes());
    m.extend(data);
    w.write_all(&m)?;
    w.flush()
}

/// Serves `export` (read-only, `size` bytes) until the client disconnects.
/// `read_at` fills a buffer from the backing image (e.g. a fixed index).
pub fn serve(
    mut r: impl Read,
    mut w: impl Write,
    export: &str,
    size: u64,
    mut read_at: impl FnMut(u64, &mut [u8]) -> io::Result<()>,
) -> io::Result<()> {
    let mut hello = Vec::with_capacity(18);
    hello.extend(NBDMAGIC.to_be_bytes());
    hello.extend(IHAVEOPT.to_be_bytes());
    hello.extend((FLAG_FIXED_NEWSTYLE | FLAG_NO_ZEROES).to_be_bytes());
    w.write_all(&hello)?;
    w.flush()?;
    let client_flags = u32_(&mut r)?;
    if client_flags & u32::from(FLAG_FIXED_NEWSTYLE) == 0 {
        return Err(proto("client does not speak fixed newstyle"));
    }
    let tflags = TFLAG_HAS_FLAGS | TFLAG_READ_ONLY;
    let info: Vec<u8> = [
        &INFO_EXPORT.to_be_bytes()[..],
        &size.to_be_bytes(),
        &tflags.to_be_bytes(),
    ]
    .concat();

    // option haggling
    loop {
        if u64_(&mut r)? != IHAVEOPT {
            return Err(proto("bad option magic"));
        }
        let opt = u32_(&mut r)?;
        let len = u32_(&mut r)? as usize;
        if len > 64 << 10 {
            return Err(proto("option too large"));
        }
        let data = bytes(&mut r, len)?;
        match opt {
            OPT_EXPORT_NAME => {
                if data != export.as_bytes() {
                    return Err(proto("unknown export"));
                }
                w.write_all(&[&size.to_be_bytes()[..], &tflags.to_be_bytes()].concat())?;
                w.flush()?;
                break;
            }
            OPT_GO | OPT_INFO => {
                let name_len = data
                    .get(..4)
                    .map(|b| u32::from_be_bytes(b.try_into().unwrap()) as usize);
                let Some(name) = name_len.and_then(|n| data.get(4..4 + n)) else {
                    opt_reply(&mut w, opt, REP_ERR_INVALID, &[])?;
                    continue;
                };
                if name != export.as_bytes() && !name.is_empty() {
                    opt_reply(&mut w, opt, REP_ERR_UNKNOWN, b"unknown export")?;
                    continue;
                }
                opt_reply(&mut w, opt, REP_INFO, &info)?;
                opt_reply(&mut w, opt, REP_ACK, &[])?;
                if opt == OPT_GO {
                    break;
                }
            }
            OPT_LIST => {
                opt_reply(&mut w, opt, REP_SERVER, &with_len(export))?;
                opt_reply(&mut w, opt, REP_ACK, &[])?;
            }
            OPT_ABORT => {
                let _ = opt_reply(&mut w, opt, REP_ACK, &[]);
                return Ok(());
            }
            _ => opt_reply(&mut w, opt, REP_ERR_UNSUP, &[])?,
        }
    }

    // transmission
    let mut buf = Vec::new();
    loop {
        let magic = match u32_(&mut r) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        if magic != REQUEST_MAGIC {
            return Err(proto("bad request magic"));
        }
        let _flags = u16_(&mut r)?;
        let ty = u16_(&mut r)?;
        let cookie = u64_(&mut r)?;
        let off = u64_(&mut r)?;
        let len = u32_(&mut r)?;
        match ty {
            CMD_READ => {
                if len > MAX_REQUEST || off.checked_add(len as u64).is_none_or(|e| e > size) {
                    simple_reply(&mut w, EINVAL, cookie, &[])?;
                    continue;
                }
                buf.resize(len as usize, 0);
                match read_at(off, &mut buf) {
                    Ok(()) => simple_reply(&mut w, 0, cookie, &buf)?,
                    Err(e) => {
                        eprintln!("nbd server: read {off}+{len}: {e}");
                        simple_reply(&mut w, EIO, cookie, &[])?;
                    }
                }
            }
            CMD_WRITE => {
                if len > MAX_REQUEST {
                    return Err(proto("write too large"));
                }
                io::copy(&mut (&mut r).take(len as u64), &mut io::sink())?; // discard payload
                simple_reply(&mut w, EPERM, cookie, &[])?;
            }
            CMD_FLUSH => simple_reply(&mut w, 0, cookie, &[])?,
            CMD_DISC => return Ok(()),
            _ => simple_reply(&mut w, EINVAL, cookie, &[])?,
        }
    }
}
