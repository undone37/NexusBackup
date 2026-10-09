//! Strict reader for the content stream of the forced command `read`: GNU tar
//! `--format=posix --no-recursion --xattrs --xattrs-include='*'` of exactly
//! the requested regular files and directories.
//!
//! Only what that command produces is accepted (threat model T12-like: the
//! device is not trusted): ustar headers with valid checksums, regular files,
//! directories, one local PAX header (`x`, ≤ 1 MiB) per member carrying
//! `path`, `size` and `SCHILY.xattr.*`, global PAX headers (`g`, ignored).
//! Links, devices, GNU long names, sparse files and base-256 numbers are
//! refused; memory per member is bounded.

use anyhow::{bail, Context, Result};
use std::io::{self, Read};

pub const BLOCK: usize = 512;
pub const MAX_PAX: u64 = 1 << 20;
pub const MAX_GLOBAL_PAX: u64 = 64 << 10;
pub const MAX_XATTRS: usize = 1024;
pub const MAX_XATTR_NAME: usize = 255;
pub const MAX_XATTR_VALUE: usize = 64 << 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub kind: Kind,
    /// relative, validated, without a trailing `/`
    pub path: Vec<u8>,
    pub size: u64,
    pub xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

pub struct Reader<R: Read> {
    r: R,
    /// unread data bytes of the current member + its padding
    remaining: u64,
    pad: u64,
    done: bool,
    /// bytes consumed from `r`
    pub bytes: u64,
}

fn octal(f: &[u8]) -> Result<u64> {
    let s = f.iter().position(|b| *b != b' ').unwrap_or(f.len());
    let f = &f[s..];
    let end = f.iter().position(|b| *b == 0 || *b == b' ').unwrap_or(f.len());
    let (digits, rest) = f.split_at(end);
    if digits.is_empty() || !digits.iter().all(|c| (b'0'..=b'7').contains(c)) {
        bail!("bad octal field");
    }
    if !rest.iter().all(|b| *b == 0 || *b == b' ') {
        bail!("bad octal field");
    }
    digits
        .iter()
        .try_fold(0u64, |a, c| a.checked_mul(8)?.checked_add(u64::from(c - b'0')))
        .context("octal field overflow")
}

fn cstr(f: &[u8]) -> &[u8] {
    &f[..f.iter().position(|b| *b == 0).unwrap_or(f.len())]
}

#[derive(Default)]
struct Pax {
    path: Option<Vec<u8>>,
    size: Option<u64>,
    xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

/// `<len> <key>=<value>\n` records.
fn parse_pax(mut d: &[u8], global: bool) -> Result<Pax> {
    let mut p = Pax::default();
    while !d.is_empty() {
        let sp = d.iter().take(21).position(|b| *b == b' ').context("bad pax record")?;
        let len: usize = std::str::from_utf8(&d[..sp])?.parse().context("bad pax length")?;
        if len <= sp + 1 || len > d.len() || d[len - 1] != b'\n' || d[0] == b'0' {
            bail!("bad pax record");
        }
        let rec = &d[sp + 1..len - 1];
        d = &d[len..];
        let eq = rec.iter().position(|b| *b == b'=').context("bad pax record")?;
        let (k, v) = (&rec[..eq], &rec[eq + 1..]);
        if global {
            continue; // global headers carry nothing we use
        }
        if let Some(name) = k.strip_prefix(b"SCHILY.xattr.") {
            if name.is_empty() || name.len() > MAX_XATTR_NAME || name.contains(&0) || v.len() > MAX_XATTR_VALUE {
                bail!("bad xattr in pax header");
            }
            if p.xattrs.len() >= MAX_XATTRS {
                bail!("too many xattrs");
            }
            if p.xattrs.iter().any(|(n, _)| n == name) {
                bail!("duplicate xattr");
            }
            p.xattrs.push((name.to_vec(), v.to_vec()));
        } else if k == b"path" {
            p.path = Some(v.to_vec());
        } else if k == b"size" {
            if v.is_empty() || v.len() > 20 || !v.iter().all(u8::is_ascii_digit) {
                bail!("bad pax size");
            }
            p.size = Some(std::str::from_utf8(v)?.parse()?);
        } else if k.starts_with(b"GNU.sparse") || k == b"linkpath" {
            bail!("unsupported pax key");
        }
        // mtime/atime/ctime/uid/gid/uname/gname/hdrcharset/…: the walk is authoritative
    }
    Ok(p)
}

impl<R: Read> Reader<R> {
    pub fn new(r: R) -> Self {
        Reader {
            r,
            remaining: 0,
            pad: 0,
            done: false,
            bytes: 0,
        }
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        self.r.read_exact(buf).context("tar stream truncated")?;
        self.bytes += buf.len() as u64;
        Ok(())
    }

    fn skip(&mut self, n: u64) -> Result<()> {
        let got = io::copy(&mut (&mut self.r).take(n), &mut io::sink())?;
        self.bytes += got;
        if got != n {
            bail!("tar stream truncated");
        }
        Ok(())
    }

    fn header(&mut self) -> Result<Option<[u8; BLOCK]>> {
        let mut h = [0u8; BLOCK];
        self.read_exact(&mut h)?;
        if h.iter().all(|b| *b == 0) {
            return Ok(None);
        }
        let stored = octal(&h[148..156])?;
        let sum: u64 = h
            .iter()
            .enumerate()
            .map(|(i, b)| if (148..156).contains(&i) { 32 } else { u64::from(*b) })
            .sum();
        if stored != sum {
            bail!("tar header checksum mismatch");
        }
        if &h[257..263] != b"ustar\0" || &h[263..265] != b"00" {
            bail!("not a POSIX ustar header");
        }
        Ok(Some(h))
    }

    fn read_ext(&mut self, size: u64, max: u64) -> Result<Vec<u8>> {
        if size > max {
            bail!("pax header too large");
        }
        let mut d = vec![0u8; size as usize];
        self.read_exact(&mut d)?;
        self.skip(size.next_multiple_of(BLOCK as u64) - size)?;
        Ok(d)
    }

    /// Next member (after skipping what is left of the previous one), or None at the end marker.
    pub fn next_member(&mut self) -> Result<Option<Member>> {
        if self.done {
            return Ok(None);
        }
        let left = self.remaining + self.pad;
        self.remaining = 0;
        self.pad = 0;
        self.skip(left)?;
        let mut pax: Option<Pax> = None;
        loop {
            let Some(h) = self.header()? else {
                self.done = true;
                if pax.is_some() {
                    bail!("pax header without a member");
                }
                return Ok(None);
            };
            let size = octal(&h[124..136])?;
            match h[156] {
                b'g' => {
                    let d = self.read_ext(size, MAX_GLOBAL_PAX)?;
                    parse_pax(&d, true)?;
                }
                b'x' => {
                    if pax.is_some() {
                        bail!("two pax headers in a row");
                    }
                    let d = self.read_ext(size, MAX_PAX)?;
                    pax = Some(parse_pax(&d, false)?);
                }
                t @ (b'0' | 0 | b'5') => {
                    let p = pax.take().unwrap_or_default();
                    let kind = if t == b'5' { Kind::Dir } else { Kind::File };
                    let mut path = match p.path {
                        Some(path) => path,
                        None => {
                            let (name, prefix) = (cstr(&h[0..100]), cstr(&h[345..500]));
                            if prefix.is_empty() {
                                name.to_vec()
                            } else {
                                [prefix, b"/", name].concat()
                            }
                        }
                    };
                    if kind == Kind::Dir && path.ends_with(b"/") {
                        path.pop();
                    }
                    if !crate::valid_rel_path(&path) {
                        bail!("invalid member path");
                    }
                    let size = p.size.unwrap_or(size);
                    if kind == Kind::Dir && size != 0 {
                        bail!("directory with data");
                    }
                    self.remaining = size;
                    self.pad = size.next_multiple_of(BLOCK as u64) - size;
                    return Ok(Some(Member {
                        kind,
                        path,
                        size,
                        xattrs: p.xattrs,
                    }));
                }
                t => bail!("unsupported tar member type {:?}", t as char),
            }
        }
    }

    /// Data of the current member (exactly `size` bytes; short = error).
    pub fn data(&mut self) -> Data<'_, R> {
        Data { t: self }
    }

    /// Consumes everything after the end marker (GNU tar pads to 10 KiB records);
    /// at most `max` bytes, which must all be zero.
    pub fn finish(&mut self, max: u64) -> Result<()> {
        if !self.done {
            bail!("tar stream not at its end");
        }
        let mut buf = [0u8; 8192];
        let mut total = 0u64;
        loop {
            let n = self.r.read(&mut buf)?;
            if n == 0 {
                return Ok(());
            }
            total += n as u64;
            self.bytes += n as u64;
            if total > max || buf[..n].iter().any(|b| *b != 0) {
                bail!("trailing data after the tar end marker");
            }
        }
    }
}

pub struct Data<'a, R: Read> {
    t: &'a mut Reader<R>,
}

impl<R: Read> Read for Data<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.t.remaining == 0 {
            return Ok(0);
        }
        let n = (buf.len() as u64).min(self.t.remaining) as usize;
        let got = self.t.r.read(&mut buf[..n])?;
        if got == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "tar member truncated"));
        }
        self.t.remaining -= got as u64;
        self.t.bytes += got as u64;
        Ok(got)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Minimal ustar writer for tests (and the fuzz seed corpus).
    pub fn header(name: &[u8], typ: u8, size: u64) -> [u8; BLOCK] {
        let mut h = [0u8; BLOCK];
        h[..name.len()].copy_from_slice(name);
        h[100..107].copy_from_slice(b"0000644");
        h[108..115].copy_from_slice(b"0000000");
        h[116..123].copy_from_slice(b"0000000");
        h[124..135].copy_from_slice(format!("{size:011o}").as_bytes());
        h[136..147].copy_from_slice(b"00000000000");
        h[156] = typ;
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].copy_from_slice(b"        ");
        let sum: u64 = h.iter().map(|b| u64::from(*b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        h
    }

    pub fn pax(records: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (k, v) in records {
            let body = k.len() + v.len() + 3; // ' ' '=' '\n'
            let mut len = body + 1;
            while len.to_string().len() + body != len {
                len += 1;
            }
            out.extend_from_slice(format!("{len} ").as_bytes());
            out.extend_from_slice(k);
            out.push(b'=');
            out.extend_from_slice(v);
            out.push(b'\n');
        }
        out
    }

    pub fn member(out: &mut Vec<u8>, name: &[u8], typ: u8, data: &[u8], recs: &[(&[u8], &[u8])]) {
        if !recs.is_empty() {
            let p = pax(recs);
            out.extend_from_slice(&header(b"PaxHeaders/x", b'x', p.len() as u64));
            out.extend_from_slice(&p);
            out.resize(out.len().next_multiple_of(BLOCK), 0);
        }
        out.extend_from_slice(&header(name, typ, data.len() as u64));
        out.extend_from_slice(data);
        out.resize(out.len().next_multiple_of(BLOCK), 0);
    }

    pub fn end(out: &mut Vec<u8>) {
        out.resize(out.len() + 2 * BLOCK, 0);
        out.resize(out.len().next_multiple_of(10240), 0);
    }

    fn read_all(s: &[u8]) -> Result<Vec<(Member, Vec<u8>)>> {
        let mut r = Reader::new(s);
        let mut out = Vec::new();
        while let Some(m) = r.next_member()? {
            let mut d = Vec::new();
            r.data().read_to_end(&mut d)?;
            out.push((m, d));
        }
        r.finish(1 << 20)?;
        assert_eq!(r.bytes, s.len() as u64);
        Ok(out)
    }

    #[test]
    fn reads_gnu_posix_members() {
        let mut s = Vec::new();
        let long = vec![b'l'; 300];
        let longpath = [&b"d/"[..], &long].concat();
        let g = pax(&[(b"comment", b"global")]);
        s.extend_from_slice(&header(b"pax_global_header", b'g', g.len() as u64));
        s.extend_from_slice(&g);
        s.resize(s.len().next_multiple_of(BLOCK), 0);
        member(
            &mut s,
            b"d/",
            b'5',
            b"",
            &[(b"SCHILY.xattr.system.posix_acl_default", b"\x02\0\0\0\n=")],
        );
        member(
            &mut s,
            b"d/a",
            b'0',
            b"hello",
            &[(b"SCHILY.xattr.user.c", b"v"), (b"mtime", b"1.5")],
        );
        member(&mut s, b"ignored-name", b'0', &[7u8; 1000], &[(b"path", &longpath)]);
        member(&mut s, b"d/empty", 0, b"", &[]);
        end(&mut s);
        let m = read_all(&s).unwrap();
        assert_eq!(m.len(), 4);
        assert_eq!((m[0].0.kind, m[0].0.path.as_slice()), (Kind::Dir, &b"d"[..]));
        assert_eq!(m[0].0.xattrs[0].1, b"\x02\0\0\0\n=");
        assert_eq!(m[1].1, b"hello");
        assert_eq!(m[1].0.xattrs, vec![(b"user.c".to_vec(), b"v".to_vec())]);
        assert_eq!(m[2].0.path, longpath);
        assert_eq!(m[2].1.len(), 1000);
        assert_eq!(m[3].0.size, 0);
    }

    #[test]
    fn skips_unread_data() {
        let mut s = Vec::new();
        member(&mut s, b"a", b'0', &[1u8; 700], &[]);
        member(&mut s, b"b", b'0', b"x", &[]);
        end(&mut s);
        let mut r = Reader::new(&s[..]);
        assert_eq!(r.next_member().unwrap().unwrap().path, b"a");
        let mut d = [0u8; 10];
        r.data().read_exact(&mut d).unwrap();
        assert_eq!(r.next_member().unwrap().unwrap().path, b"b");
        assert!(r.next_member().unwrap().is_none());
        r.finish(1 << 20).unwrap();
    }

    #[test]
    fn refuses_hostile_streams() {
        let bad: Vec<Vec<u8>> = vec![
            {
                let mut s = Vec::new();
                member(&mut s, b"../etc/passwd", b'0', b"x", &[]);
                s
            },
            {
                let mut s = Vec::new();
                member(&mut s, b"a", b'2', b"", &[]); // symlink
                s
            },
            {
                let mut s = Vec::new();
                member(&mut s, b"a", b'1', b"", &[]); // hard link
                s
            },
            {
                let mut s = Vec::new();
                member(&mut s, b"a", b'L', b"x", &[]); // GNU long name
                s
            },
            {
                let mut s = Vec::new();
                member(&mut s, b"a", b'0', b"x", &[(b"path", b"/etc/shadow")]);
                s
            },
            {
                let mut s = Vec::new();
                member(&mut s, b"a", b'0', b"x", &[(b"GNU.sparse.map", b"0,1")]);
                s
            },
            {
                let mut s = Vec::new();
                member(&mut s, b"a", b'0', b"x", &[(b"SCHILY.xattr.", b"x")]);
                s
            },
            {
                let mut s = Vec::new();
                member(
                    &mut s,
                    b"a",
                    b'0',
                    b"x",
                    &[(b"SCHILY.xattr.u", b"1"), (b"SCHILY.xattr.u", b"2")],
                );
                s
            },
            {
                let mut s = Vec::new();
                member(&mut s, b"a", b'0', b"x", &[(b"size", b"999999")]); // pax size beyond the stream
                s
            },
            {
                let mut s = Vec::new();
                member(&mut s, b"d", b'5', b"data", &[]);
                s
            },
            {
                let mut s = Vec::new();
                member(&mut s, b"a", b'0', b"x", &[]);
                s[148] ^= 1; // checksum
                s
            },
            {
                let mut s = header(b"PaxHeaders/x", b'x', 2 << 20).to_vec();
                s.resize(s.len() + (2 << 20), b'1');
                s
            },
            {
                let mut s = header(b"PaxHeaders/x", b'x', 10).to_vec();
                s.extend_from_slice(b"99 path=a\n");
                s.resize(1024, 0);
                s
            },
            {
                let mut s = Vec::new();
                member(&mut s, b"a", b'0', b"x", &[]);
                s.truncate(600); // data truncated
                s
            },
            {
                let mut s = Vec::new();
                member(&mut s, b"a", b'0', b"x", &[]);
                end(&mut s);
                s.extend_from_slice(b"junk"); // trailing data
                s
            },
            {
                let mut s = Vec::new();
                member(&mut s, b"a", b'0', b"x", &[]); // no end marker
                s
            },
        ];
        for (i, s) in bad.iter().enumerate() {
            assert!(read_all(s).is_err(), "case {i}");
        }
        assert!(octal(b"0000012\0").unwrap() == 10 && octal(b"  12 ").unwrap() == 10);
        assert!(octal(b"\x80\0\0\0").is_err() && octal(b"").is_err() && octal(b"1 2").is_err());
        assert!(octal(b"7777777777777777777777").is_err());
    }
}
