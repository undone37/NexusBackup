//! Parser for `zfs diff -FH <ds>@<from> <ds>@<to>` (OpenZFS 2.x, libzfs_diff.c).
//!
//! One change per line, tab separated, paths prefixed with the dataset's
//! mount point:
//! ```text
//! +  F  /mnt/tank/a/new           added
//! -  F  /mnt/tank/a/gone          removed
//! M  /  /mnt/tank/a/dir           modified (content, metadata, entries)
//! R  F  /mnt/tank/a/old  /mnt/tank/a/new    renamed (object kept)
//! M  F  /mnt/tank/a/file  (+1)    link count changed (one name only)
//! ```
//! Bytes outside `0x21..=0x7e` and `\` are written as `\` + 4 octal digits
//! (`\0040` = space). Renames of a hard-linked object can show up as `M` of
//! another of its names, and a renamed directory is one `R` line (its content
//! is not listed): the tree builder therefore matches files by object number
//! (inode), and this module only answers "which objects may have changed".

use anyhow::{bail, Context, Result};

/// Output bigger than this is refused (hostile or absurd).
pub const MAX_OUTPUT: usize = 1 << 30;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Change {
    Added(Vec<u8>),
    Removed(Vec<u8>),
    Modified(Vec<u8>),
    Renamed {
        from: Vec<u8>,
        to: Vec<u8>,
    },
    /// link count of the object changed by `delta`; `path` is one of its names
    Links {
        path: Vec<u8>,
        delta: i64,
    },
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Line {
    /// `F`, `/`, `@`, `|`, `=`, `B`, `C`, `>`, `P`, `?`
    pub ftype: u8,
    pub change: Change,
}

impl Line {
    /// Path in the *to* snapshot whose object may have changed (None for removals).
    /// Empty = the dataset root directory.
    pub fn changed_path(&self) -> Option<&[u8]> {
        match &self.change {
            Change::Added(p) | Change::Modified(p) | Change::Links { path: p, .. } => Some(p),
            Change::Renamed { to, .. } => Some(to),
            Change::Removed(_) => None,
        }
    }
}

/// `\NNNN` (4 octal digits, value ≤ 0o377) → byte; any other `\` is an error.
pub fn unescape(s: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'\\' {
            let d = s.get(i + 1..i + 5).context("truncated escape")?;
            if !d.iter().all(|c| (b'0'..=b'7').contains(c)) {
                bail!("invalid escape");
            }
            let v = d.iter().fold(0u32, |a, c| a * 8 + u32::from(c - b'0'));
            out.push(u8::try_from(v).ok().context("escape out of range")?);
            i += 5;
        } else {
            // zfs escapes everything outside 0x21..=0x7e: raw controls/space mean a broken line
            if !(0x21..=0x7e).contains(&s[i]) {
                bail!("unescaped byte 0x{:02x}", s[i]);
            }
            out.push(s[i]);
            i += 1;
        }
    }
    Ok(out)
}

/// Absolute path from zfs → path relative to the mount point (empty = root).
fn relative(abs: &[u8], mountpoint: &[u8]) -> Result<Vec<u8>> {
    let mp = mountpoint.strip_suffix(b"/").unwrap_or(mountpoint);
    let rest = abs.strip_prefix(mp).context("path outside the dataset")?;
    // the root directory is reported as `<mountpoint>/`
    if rest.is_empty() || rest == b"/" {
        return Ok(Vec::new());
    }
    let rel = rest.strip_prefix(b"/").context("path outside the dataset")?;
    if !crate::valid_rel_path(rel) {
        bail!("invalid path");
    }
    Ok(rel.to_vec())
}

fn path(field: &[u8], mountpoint: &[u8]) -> Result<Vec<u8>> {
    relative(&unescape(field)?, mountpoint)
}

/// Parses the whole `zfs diff -FH` output. `mountpoint` is the dataset's
/// mount point as reported by the API (validated absolute path).
pub fn parse(out: &[u8], mountpoint: &[u8]) -> Result<Vec<Line>> {
    if out.len() > MAX_OUTPUT {
        bail!("zfs diff output too large");
    }
    if !mountpoint.starts_with(b"/") {
        bail!("mount point must be absolute");
    }
    let mut lines = Vec::new();
    let body = out.strip_suffix(b"\n").unwrap_or(out);
    if body.is_empty() {
        return Ok(lines);
    }
    for (n, l) in body.split(|b| *b == b'\n').enumerate() {
        let parse_line = || -> Result<Line> {
            let f: Vec<&[u8]> = l.split(|b| *b == b'\t').collect();
            let ftype = match f.get(1) {
                Some([t]) if b"F/@|=BC>P?".contains(t) => *t,
                _ => bail!("bad file type"),
            };
            let change = match (f[0], f.len()) {
                (b"+", 3) => Change::Added(path(f[2], mountpoint)?),
                (b"-", 3) => Change::Removed(path(f[2], mountpoint)?),
                (b"M", 3) => Change::Modified(path(f[2], mountpoint)?),
                (b"M", 4) => {
                    let d = f[3]
                        .strip_prefix(b"(")
                        .and_then(|d| d.strip_suffix(b")"))
                        .context("bad link delta")?;
                    let d = std::str::from_utf8(d)?;
                    if !(d.starts_with('+') || d.starts_with('-')) || d.len() > 12 {
                        bail!("bad link delta");
                    }
                    Change::Links {
                        path: path(f[2], mountpoint)?,
                        delta: d.parse()?,
                    }
                }
                (b"R", 4) => Change::Renamed {
                    from: path(f[2], mountpoint)?,
                    to: path(f[3], mountpoint)?,
                },
                _ => bail!("unknown change"),
            };
            Ok(Line { ftype, change })
        };
        lines.push(parse_line().with_context(|| format!("zfs diff line {}", n + 1))?);
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    #[test]
    fn parses_all_change_kinds() {
        let out = b"M\tF\t/mnt/tank/data/hl/a\n\
M\t/\t/mnt/tank/data/docs\n\
+\tF\t/mnt/tank/data/docs/sp\\0040ace\n\
-\tF\t/mnt/tank/data/docs/gone\n\
R\tF\t/mnt/tank/data/docs/readme.txt\t/mnt/tank/data/docs/README.txt\n\
R\t/\t/mnt/tank/data/many\t/mnt/tank/data/renamed-many\n\
M\tF\t/mnt/tank/data/docs/new.txt\t(+1)\n\
M\tF\t/mnt/tank/data/x\t(-2)\n\
M\t/\t/mnt/tank/data/\n\
+\tF\t/mnt/tank/data/docs/Gr\\0303\\0274\\0303\\0237e\n\
+\tF\t/mnt/tank/data/docs/new\\0012line\n\
+\tF\t/mnt/tank/data/docs/back\\0134slash\n\
+\t@\t/mnt/tank/data/links/t\\0011ab\n";
        let l = parse(out, b"/mnt/tank/data").unwrap();
        assert_eq!(l.len(), 13);
        assert_eq!(l[0].change, Change::Modified(p("hl/a")));
        assert_eq!(l[1].ftype, b'/');
        assert_eq!(l[2].change, Change::Added(p("docs/sp ace")));
        assert_eq!(l[3].change, Change::Removed(p("docs/gone")));
        assert_eq!(l[3].changed_path(), None);
        assert_eq!(
            l[4].change,
            Change::Renamed {
                from: p("docs/readme.txt"),
                to: p("docs/README.txt")
            }
        );
        assert_eq!(l[5].changed_path(), Some(&b"renamed-many"[..]));
        assert_eq!(
            l[6].change,
            Change::Links {
                path: p("docs/new.txt"),
                delta: 1
            }
        );
        assert_eq!(
            l[7].change,
            Change::Links {
                path: p("x"),
                delta: -2
            }
        );
        assert_eq!(l[8].change, Change::Modified(Vec::new()));
        assert_eq!(l[9].change, Change::Added("docs/Grüße".as_bytes().to_vec()));
        assert_eq!(l[10].change, Change::Added(p("docs/new\nline")));
        assert_eq!(l[11].change, Change::Added(p("docs/back\\slash")));
        assert_eq!(l[12].ftype, b'@');
        assert!(parse(b"", b"/mnt/x").unwrap().is_empty());
        // trailing slash on the mount point is tolerated
        assert_eq!(
            parse(b"+\tF\t/mnt/x/a\n", b"/mnt/x/").unwrap()[0].change,
            Change::Added(p("a"))
        );
    }

    #[test]
    fn refuses_hostile_lines() {
        let mp = b"/mnt/tank/data";
        for bad in [
            &b"+\tF\t/mnt/tank/other/x\n"[..],          // outside the dataset
            b"+\tF\t/mnt/tank/datax/x\n",               // prefix trick
            b"+\tF\t/mnt/tank/data/../etc/shadow\n",    // traversal
            b"+\tF\t/mnt/tank/data/a\\0057..\\0057b\n", // escaped "/../"
            b"+\tF\t/mnt/tank/data//a\n",               // empty component
            b"+\tF\t/mnt/tank/data/a\\0000b\n",         // NUL
            b"+\tF\t/mnt/tank/data/a b\n",              // unescaped space
            b"+\tF\t/mnt/tank/data/a\\9999\n",          // bad escape
            b"+\tF\t/mnt/tank/data/a\\0400\n",          // > 0xff
            b"+\tF\t/mnt/tank/data/a\\003\n",           // truncated escape
            b"*\tF\t/mnt/tank/data/a\n",                // unknown change
            b"+\tX\t/mnt/tank/data/a\n",                // unknown type
            b"+\tF\n",                                  // missing path
            b"R\tF\t/mnt/tank/data/a\n",                // rename without target
            b"M\tF\t/mnt/tank/data/a\t+1\n",            // bad delta
            b"M\tF\t/mnt/tank/data/a\t(1)\n",           // unsigned delta
            b"+\tF\t/mnt/tank/data/a\textra\n",         // extra field
            b"+\tF\trelative\n",
        ] {
            assert!(parse(bad, mp).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        let long = format!("+\tF\t/mnt/tank/data/{}\n", "a".repeat(5000));
        assert!(parse(long.as_bytes(), mp).is_err());
        assert!(parse(b"+\tF\t/a\n", b"relative").is_err());
    }
}
