//! Parser for the metadata walk of a snapshot (forced command `walk`):
//! GNU find `-mindepth 1 -printf` with one record per entry,
//! ```text
//! %y %m %U %G %s %T@ %C@ %i %n \0 %P \0 %l \0
//! type mode uid gid size mtime ctime inode nlink NUL path NUL link-target NUL
//! ```
//! in pre-order (a directory before its contents). Times are
//! `<secs>.<10 digits>`. Paths are relative to the snapshot root, raw bytes.

use anyhow::{bail, Context, Result};
use chunkstore::TreeKind;
use std::io::BufRead;

/// Entries per dataset (all are held in memory, like agent backups).
pub const MAX_ENTRIES: usize = 50_000_000;

#[derive(Debug, Clone, PartialEq)]
pub struct WalkEntry {
    pub kind: TreeKind,
    /// type bits | permission bits (incl. setuid/setgid/sticky)
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    /// ZFS object number: stable across renames
    pub inode: u64,
    pub nlink: u64,
    pub path: Vec<u8>,
    /// symlinks only
    pub link: Option<Vec<u8>>,
}

fn kind_of(y: &[u8]) -> Result<(TreeKind, u32)> {
    Ok(match y {
        b"f" => (TreeKind::File, libc::S_IFREG),
        b"d" => (TreeKind::Dir, libc::S_IFDIR),
        b"l" => (TreeKind::Symlink, libc::S_IFLNK),
        b"b" => (TreeKind::Device, libc::S_IFBLK),
        b"c" => (TreeKind::Device, libc::S_IFCHR),
        b"p" => (TreeKind::Fifo, libc::S_IFIFO),
        b"s" => (TreeKind::Socket, libc::S_IFSOCK),
        _ => bail!("unknown file type"),
    })
}

fn num<T: std::str::FromStr>(f: &[u8]) -> Result<T> {
    if f.is_empty() || f.len() > 20 || !f.iter().all(u8::is_ascii_digit) {
        bail!("bad number");
    }
    std::str::from_utf8(f)?.parse().ok().context("bad number")
}

/// `1791569435.3639793240` / `-5.5000000000` → nanoseconds.
pub fn parse_time(f: &[u8]) -> Result<i64> {
    let (neg, f) = match f.strip_prefix(b"-") {
        Some(r) => (true, r),
        None => (false, f),
    };
    let (s, frac) = match f.iter().position(|b| *b == b'.') {
        Some(i) => (&f[..i], &f[i + 1..]),
        None => (f, &b""[..]),
    };
    if frac.len() > 10 || !frac.iter().all(u8::is_ascii_digit) {
        bail!("bad time");
    }
    let secs: i64 = num(s)?;
    let mut ns: i64 = 0;
    for i in 0..9 {
        ns = ns * 10 + i64::from(frac.get(i).map_or(0, |d| d - b'0'));
    }
    let t = secs
        .checked_mul(1_000_000_000)
        .and_then(|v| v.checked_add(ns))
        .context("time out of range")?;
    Ok(if neg { -t } else { t })
}

fn field<'a, R: BufRead>(r: &mut R, buf: &'a mut Vec<u8>, max: usize) -> Result<Option<&'a [u8]>> {
    buf.clear();
    let n = std::io::Read::take(&mut *r, max as u64 + 1).read_until(0, buf)?;
    if n == 0 {
        return Ok(None);
    }
    if buf.pop() != Some(0) {
        bail!("walk record truncated or too long");
    }
    Ok(Some(buf))
}

/// Parses one record; `Ok(None)` at a clean end of input.
pub fn next(r: &mut impl BufRead) -> Result<Option<WalkEntry>> {
    let mut b = Vec::new();
    let Some(head) = field(r, &mut b, 256)? else {
        return Ok(None);
    };
    let f: Vec<&[u8]> = head.split(|c| *c == b' ').collect();
    let [y, m, u, g, s, mt, ct, i, n] = f.as_slice() else {
        bail!("walk record: expected 9 fields");
    };
    let (kind, ftype) = kind_of(y)?;
    if m.is_empty() || m.len() > 4 || !m.iter().all(|c| (b'0'..=b'7').contains(c)) {
        bail!("bad mode");
    }
    let perm = m.iter().fold(0u32, |a, c| a * 8 + u32::from(c - b'0'));
    let mut e = WalkEntry {
        kind,
        mode: ftype | perm,
        uid: num(u)?,
        gid: num(g)?,
        size: num(s)?,
        mtime_ns: parse_time(mt)?,
        ctime_ns: parse_time(ct)?,
        inode: num(i)?,
        nlink: num(n)?,
        path: Vec::new(),
        link: None,
    };
    let mut pb = Vec::new();
    e.path = field(r, &mut pb, crate::MAX_PATH)?
        .context("walk record truncated")?
        .to_vec();
    if !crate::valid_rel_path(&e.path) {
        bail!("invalid path in walk");
    }
    let link = field(r, &mut pb, crate::MAX_PATH)?.context("walk record truncated")?;
    match (&e.kind, link.is_empty()) {
        (TreeKind::Symlink, false) => e.link = Some(link.to_vec()),
        (TreeKind::Symlink, true) => bail!("symlink without target"),
        (_, true) => {}
        (_, false) => bail!("link target on a non-symlink"),
    }
    Ok(Some(e))
}

/// Reads all records; enforces unique paths, pre-order (every parent is an
/// earlier directory) and [`MAX_ENTRIES`].
pub fn read_all(r: &mut impl BufRead) -> Result<Vec<WalkEntry>> {
    let mut out: Vec<WalkEntry> = Vec::new();
    let mut seen: std::collections::HashMap<Vec<u8>, bool> = std::collections::HashMap::new(); // path -> is_dir
    while let Some(e) = next(r).with_context(|| format!("walk entry {}", out.len() + 1))? {
        if out.len() >= MAX_ENTRIES {
            bail!("more than {MAX_ENTRIES} entries");
        }
        if let Some(i) = e.path.iter().rposition(|b| *b == b'/') {
            if seen.get(&e.path[..i]) != Some(&true) {
                bail!("walk: parent of an entry is not an earlier directory");
            }
        }
        if seen.insert(e.path.clone(), e.kind == TreeKind::Dir).is_some() {
            bail!("walk: duplicate path");
        }
        out.push(e);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(head: &str, path: &[u8], link: &[u8]) -> Vec<u8> {
        let mut v = head.as_bytes().to_vec();
        v.push(0);
        v.extend_from_slice(path);
        v.push(0);
        v.extend_from_slice(link);
        v.push(0);
        v
    }

    #[test]
    fn parses_records() {
        let mut s = Vec::new();
        s.extend(rec(
            "d 700 1234 1234 3 1791569435.3639793240 1791569435.3719793460 132 2",
            b"secret",
            b"",
        ));
        s.extend(rec(
            "f 4755 0 0 10 981173106.1234567890 1791569435.3759793580 385 1",
            b"secret/k\ney",
            b"",
        ));
        s.extend(rec("l 777 0 0 1 -5.5000000000 1 9 1", b"lnk", b"/"));
        s.extend(rec("p 644 0 0 0 1 1 10 1", b"fifo", b""));
        let w = read_all(&mut &s[..]).unwrap();
        assert_eq!(w.len(), 4);
        assert_eq!(w[0].kind, TreeKind::Dir);
        assert_eq!(w[0].mode, libc::S_IFDIR | 0o700);
        assert_eq!(w[1].mode, libc::S_IFREG | 0o4755);
        assert_eq!(w[1].mtime_ns, 981_173_106_123_456_789);
        assert_eq!(w[1].path, b"secret/k\ney");
        assert_eq!(w[1].inode, 385);
        assert_eq!(w[2].link.as_deref(), Some(&b"/"[..]));
        assert_eq!(w[2].mtime_ns, -5_500_000_000);
        assert_eq!(w[3].kind, TreeKind::Fifo);
        assert!(read_all(&mut &b""[..]).unwrap().is_empty());
        assert_eq!(parse_time(b"7").unwrap(), 7_000_000_000);
    }

    #[test]
    fn refuses_hostile_records() {
        let ok = "f 644 0 0 1 1.0 1.0 5 1";
        for (head, path, link) in [
            ("x 644 0 0 1 1.0 1.0 5 1", &b"a"[..], &b""[..]),
            ("f 644 0 0 1 1.0 1.0 5", b"a", b""),
            ("f 644 0 0 1 1.0 1.0 5 1 9", b"a", b""),
            ("f 8644 0 0 1 1.0 1.0 5 1", b"a", b""),
            ("f 644 -1 0 1 1.0 1.0 5 1", b"a", b""),
            ("f 644 0 0 99999999999999999999999 1.0 1.0 5 1", b"a", b""),
            ("f 644 0 0 1 1.00000000000 1.0 5 1", b"a", b""),
            ("f 644 0 0 1 99999999999.0 1.0 5 1", b"a", b""),
            ("f 644 0 0 1 1.x 1.0 5 1", b"a", b""),
            (ok, b"../etc", b""),
            (ok, b"/abs", b""),
            (ok, b"a//b", b""),
            (ok, b"", b""),
            (ok, b"a", b"target-on-file"),
            ("l 777 0 0 1 1.0 1.0 5 1", b"a", b""),
        ] {
            let s = rec(head, path, link);
            assert!(read_all(&mut &s[..]).is_err(), "{head} {path:?}");
        }
        // missing parent / duplicates / parent is a file / truncation
        let mut s = rec(ok, b"a/b", b"");
        assert!(read_all(&mut &s[..]).is_err());
        s = [rec(ok, b"a", b""), rec(ok, b"a", b"")].concat();
        assert!(read_all(&mut &s[..]).is_err());
        s = [rec(ok, b"a", b""), rec(ok, b"a/b", b"")].concat();
        assert!(read_all(&mut &s[..]).is_err());
        s = rec(ok, b"a", b"");
        s.pop();
        assert!(read_all(&mut &s[..]).is_err());
        let long = rec(ok, &vec![b'a'; 5000], b"");
        assert!(read_all(&mut &long[..]).is_err());
        let longhead = rec(&"9".repeat(300), b"a", b"");
        assert!(read_all(&mut &longhead[..]).is_err());
    }
}
