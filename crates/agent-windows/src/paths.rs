//! Path and name mapping between Windows and the protocol (pure, tested on Linux).
//!
//! - Host paths `C:\Users\alice` are named `/C/Users/alice` towards the appliance
//!   (`Prepare.paths`, restore targets, `Volume.mountpoint`), because the appliance only
//!   accepts absolute `/` paths. `Entry.path` is that without the leading `/`:
//!   `C/Users/alice` (drive letter upper case, components separated by `/`).
//! - Names are UTF-16 on NTFS/ReFS and may contain unpaired surrogates; entry bytes are
//!   WTF-8 (UTF-8 for every valid name, the generalised encoding for the rest), so every
//!   name round-trips exactly.
//! - Alternate data streams are entries named `<file>:<stream>` (see `meta.rs`).

use std::fmt;

/// UTF-16 → WTF-8 (unpaired surrogates encoded as 3-byte sequences).
pub fn utf16_to_wtf8(w: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(w.len());
    let mut i = 0;
    while i < w.len() {
        let u = w[i] as u32;
        let cp = if (0xD800..0xDC00).contains(&u) && i + 1 < w.len() && (0xDC00..0xE000).contains(&(w[i + 1] as u32)) {
            i += 1;
            0x10000 + ((u - 0xD800) << 10) + (w[i] as u32 - 0xDC00)
        } else {
            u
        };
        i += 1;
        match cp {
            0..=0x7F => out.push(cp as u8),
            0x80..=0x7FF => out.extend([0xC0 | (cp >> 6) as u8, 0x80 | (cp & 0x3F) as u8]),
            0x800..=0xFFFF => out.extend([
                0xE0 | (cp >> 12) as u8,
                0x80 | ((cp >> 6) & 0x3F) as u8,
                0x80 | (cp & 0x3F) as u8,
            ]),
            _ => out.extend([
                0xF0 | (cp >> 18) as u8,
                0x80 | ((cp >> 12) & 0x3F) as u8,
                0x80 | ((cp >> 6) & 0x3F) as u8,
                0x80 | (cp & 0x3F) as u8,
            ]),
        }
    }
    out
}

/// WTF-8 → UTF-16. `None` for malformed input (including a surrogate pair encoded as
/// two 3-byte sequences, which WTF-8 forbids, so the mapping stays bijective).
pub fn wtf8_to_utf16(b: &[u8]) -> Option<Vec<u16>> {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let mut prev_lead = false;
    while i < b.len() {
        let c0 = b[i] as u32;
        let (cp, n) = match c0 {
            0x00..=0x7F => (c0, 1),
            0xC2..=0xDF => (((c0 & 0x1F) << 6) | cont(b, i + 1)?, 2),
            0xE0..=0xEF => {
                let cp = ((c0 & 0x0F) << 12) | (cont(b, i + 1)? << 6) | cont(b, i + 2)?;
                if cp < 0x800 {
                    return None;
                }
                (cp, 3)
            }
            0xF0..=0xF4 => {
                let cp = ((c0 & 0x07) << 18) | (cont(b, i + 1)? << 12) | (cont(b, i + 2)? << 6) | cont(b, i + 3)?;
                if !(0x10000..=0x10FFFF).contains(&cp) {
                    return None;
                }
                (cp, 4)
            }
            _ => return None,
        };
        i += n;
        if cp >= 0x10000 {
            let v = cp - 0x10000;
            out.push(0xD800 + (v >> 10) as u16);
            out.push(0xDC00 + (v & 0x3FF) as u16);
            prev_lead = false;
        } else {
            if (0xDC00..0xE000).contains(&cp) && prev_lead {
                return None; // would have to be a 4-byte sequence
            }
            prev_lead = (0xD800..0xDC00).contains(&cp);
            out.push(cp as u16);
        }
    }
    Some(out)
}

fn cont(b: &[u8], i: usize) -> Option<u32> {
    let c = *b.get(i)?;
    (c & 0xC0 == 0x80).then_some((c & 0x3F) as u32)
}

/// An absolute local path on a drive letter: `C:\a\b` = drive `C`, components `a`, `b`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WinPath {
    pub drive: u8,
    pub comps: Vec<String>,
}

impl fmt::Display for WinPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.win32())
    }
}

impl WinPath {
    /// Accepts `/C/Users/x`, `/c`, `C:\Users\x`, `C:/Users/x`, `\\?\C:\Users\x`.
    /// `.` components are dropped; `..`, UNC paths, device paths and invalid names are
    /// refused.
    pub fn parse(p: &str) -> Result<WinPath, String> {
        let bad = || format!("path {p:?} is not an absolute local path (C:\\... or /C/...)");
        let s = p.strip_prefix(r"\\?\").unwrap_or(p);
        let (drive, rest) = if let Some(r) = s.strip_prefix('/') {
            let mut it = r.splitn(2, '/');
            let d = it.next().unwrap_or_default();
            if d.len() != 1 {
                return Err(bad());
            }
            (d.as_bytes()[0], it.next().unwrap_or_default())
        } else {
            let b = s.as_bytes();
            if b.len() < 2 || b[1] != b':' || (b.len() > 2 && b[2] != b'\\' && b[2] != b'/') {
                return Err(bad());
            }
            (b[0], &s[2.min(s.len())..])
        };
        if !drive.is_ascii_alphabetic() {
            return Err(bad());
        }
        let mut comps = vec![];
        for c in rest.split(['/', '\\']) {
            match c {
                "" | "." => {}
                ".." => return Err(format!("path {p:?} contains ..")),
                c => {
                    check_name(c.as_bytes()).map_err(|e| format!("path {p:?}: {e}"))?;
                    comps.push(c.to_string());
                }
            }
        }
        Ok(WinPath {
            drive: drive.to_ascii_uppercase(),
            comps,
        })
    }

    /// `C:\a\b` (`C:\` for the drive root)
    pub fn win32(&self) -> String {
        let mut s = format!("{}:\\", self.drive as char);
        s.push_str(&self.comps.join("\\"));
        s
    }

    /// `\\?\C:\a\b` (no MAX_PATH limit, no name normalisation)
    pub fn verbatim(&self) -> String {
        format!(r"\\?\{}", self.win32())
    }

    /// `/C/a/b`, the appliance-facing absolute form
    pub fn slash(&self) -> String {
        format!("/{}", String::from_utf8_lossy(&self.entry_path()))
    }

    /// `C/a/b`, the `Entry.path` of this path
    pub fn entry_path(&self) -> Vec<u8> {
        let mut out = vec![self.drive];
        for c in &self.comps {
            out.push(b'/');
            out.extend_from_slice(c.as_bytes());
        }
        out
    }

    pub fn join(&self, name: &str) -> WinPath {
        let mut p = self.clone();
        p.comps.push(name.to_string());
        p
    }

    /// Case-insensitive prefix test on whole components (NTFS default).
    pub fn starts_with(&self, other: &WinPath) -> bool {
        self.drive == other.drive
            && self.comps.len() >= other.comps.len()
            && self.comps.iter().zip(&other.comps).all(|(a, b)| eq_ignore_case(a, b))
    }

    /// Components below `prefix` (which must be a prefix).
    pub fn strip_prefix(&self, prefix: &WinPath) -> Option<&[String]> {
        self.starts_with(prefix).then(|| &self.comps[prefix.comps.len()..])
    }
}

/// Simple case folding (`to_uppercase` per char) — what NTFS's upcase table does for
/// practically all names.
pub fn eq_ignore_case(a: &str, b: &str) -> bool {
    a.chars()
        .flat_map(char::to_uppercase)
        .eq(b.chars().flat_map(char::to_uppercase))
}

const RESERVED: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2",
    "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// A name the restore may create with the Win32 API: valid WTF-8, 1..=255 UTF-16
/// units, no `< > : " / \ | ? *` or control characters, no trailing space or dot, not
/// `.`/`..`, not a reserved device name (also with an extension, `NUL.txt`).
pub fn check_name(name: &[u8]) -> Result<(), String> {
    let shown = String::from_utf8_lossy(name);
    let w = wtf8_to_utf16(name).ok_or_else(|| format!("{shown:?}: not valid WTF-8"))?;
    if w.is_empty() || w.len() > 255 {
        return Err(format!("{shown:?}: name length must be 1 to 255"));
    }
    if name == b"." || name == b".." {
        return Err(format!("{shown:?}: not a name"));
    }
    if let Some(c) = w
        .iter()
        .find(|c| **c < 0x20 || (**c < 0x80 && b"<>:\"/\\|?*".contains(&(**c as u8))))
    {
        return Err(format!("{shown:?}: character {c:#x} is not allowed"));
    }
    if name.ends_with(b" ") || name.ends_with(b".") {
        return Err(format!("{shown:?}: trailing space or dot"));
    }
    let stem = shown
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end()
        .to_ascii_uppercase();
    if RESERVED.contains(&stem.as_str()) {
        return Err(format!("{shown:?}: reserved device name"));
    }
    Ok(())
}

/// Validate an entry path for a restore on Windows; returns (components, stream).
/// With `ads` (the entry carries the `win.ads` marker) the last component must be
/// `<name>:<stream>`; otherwise no `:` may appear anywhere (a `:` would silently create
/// an alternate data stream).
/// (validated components incl. the base name, stream name)
pub type EntryParts<'a> = (Vec<&'a [u8]>, Option<&'a [u8]>);

pub fn check_entry_path(path: &[u8], ads: bool) -> Result<EntryParts<'_>, String> {
    let mut comps = agent_core::restore::components(path).map_err(|e| e.to_string())?;
    let mut stream = None;
    if ads {
        let last = comps.pop().expect("non-empty");
        let i = last
            .iter()
            .position(|b| *b == b':')
            .ok_or("alternate data stream entry without ':'")?;
        let (base, s) = (&last[..i], &last[i + 1..]);
        check_stream_name(s)?;
        comps.push(base);
        stream = Some(s);
    }
    for c in &comps {
        check_name(c)?;
    }
    Ok((comps, stream))
}

/// Stream names: 1..=255 UTF-16 units, no `:`, `/`, `\`, NUL.
pub fn check_stream_name(s: &[u8]) -> Result<(), String> {
    let w = wtf8_to_utf16(s).ok_or("stream name is not valid WTF-8")?;
    if w.is_empty()
        || w.len() > 255
        || w.iter()
            .any(|c| [0, b':' as u16, b'/' as u16, b'\\' as u16].contains(c))
    {
        return Err(format!("invalid stream name {:?}", String::from_utf8_lossy(s)));
    }
    Ok(())
}

/// Exclude patterns as typed for Windows: `C:\Users\*\AppData\Local\Temp` or
/// `/C/Users/...` become `/C/Users/*/AppData/Local/Temp`; name patterns (`*.tmp`) stay.
/// They are matched case-insensitively against `/` + entry path.
pub fn normalize_exclude(p: &str) -> String {
    let t = p.trim();
    let b = t.as_bytes();
    if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        return format!("/{}{}", b[0].to_ascii_uppercase() as char, t[2..].replace('\\', "/"));
    }
    t.replace('\\', "/")
}

/// Is `path` (a final path from `GetFinalPathNameByHandleW`, any prefix form) the
/// directory `root` or below it? Case-insensitive, on whole components.
pub fn is_beneath(path: &str, root: &str) -> bool {
    fn norm(s: &str) -> Vec<String> {
        let s = s
            .strip_prefix(r"\\?\UNC\")
            .map(|r| format!(r"\\{r}"))
            .unwrap_or_else(|| s.strip_prefix(r"\\?\").unwrap_or(s).to_string());
        s.split(['\\', '/'])
            .filter(|c| !c.is_empty())
            .map(|c| c.chars().flat_map(char::to_uppercase).collect())
            .collect()
    }
    let (p, r) = (norm(path), norm(root));
    !r.is_empty() && p.len() >= r.len() && p[..r.len()] == r[..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wtf8_roundtrip_including_unpaired_surrogates() {
        let cases: Vec<Vec<u16>> = vec![
            "plain.txt".encode_utf16().collect(),
            "Grüße €".encode_utf16().collect(),
            "𠀋 supplementary".encode_utf16().collect(),
            vec![0xD800],                 // lone lead
            vec![b'a' as u16, 0xDC00],    // lone trail
            vec![0xDC00, 0xD800],         // reversed pair = two lone surrogates
            vec![0xD83D, 0xDE00, 0xD800], // pair + lone lead at the end
        ];
        for w in cases {
            let b = utf16_to_wtf8(&w);
            assert_eq!(wtf8_to_utf16(&b).unwrap(), w, "{w:x?}");
        }
        assert_eq!(
            utf16_to_wtf8(&"Grüße".encode_utf16().collect::<Vec<_>>()),
            "Grüße".as_bytes()
        );
        assert_eq!(utf16_to_wtf8(&[0xD800]), vec![0xED, 0xA0, 0x80]);
        // surrogate pair spelled as two 3-byte sequences is not WTF-8
        assert!(wtf8_to_utf16(&[0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80]).is_none());
        for bad in [
            &[0xC0, 0x80][..],
            &[0xE0, 0x80, 0x80],
            &[0xF5, 0x80, 0x80, 0x80],
            &[0x80],
            &[0xE2, 0x82],
        ] {
            assert!(wtf8_to_utf16(bad).is_none(), "{bad:x?}");
        }
    }

    #[test]
    fn parses_and_formats_paths() {
        for (input, entry) in [
            ("C:\\Users\\alice", "C/Users/alice"),
            ("c:/Users/alice/", "C/Users/alice"),
            ("/D/data/./x", "D/data/x"),
            ("/e", "E"),
            ("E:\\", "E"),
            (r"\\?\C:\Program Files\App", "C/Program Files/App"),
        ] {
            let p = WinPath::parse(input).unwrap();
            assert_eq!(p.entry_path(), entry.as_bytes(), "{input}");
        }
        let p = WinPath::parse("/C/Users/alice").unwrap();
        assert_eq!(p.win32(), r"C:\Users\alice");
        assert_eq!(p.verbatim(), r"\\?\C:\Users\alice");
        assert_eq!(p.slash(), "/C/Users/alice");
        assert_eq!(WinPath::parse("/C").unwrap().win32(), r"C:\");
        for bad in [
            "relative\\x",
            "C:relative",
            "/CC/x",
            "/1/x",
            r"\\server\share\x",
            r"\\?\UNC\server\share",
            r"\\.\PhysicalDrive0",
            "C:\\a\\..\\Windows",
            "C:\\a\\b:stream",
            "C:\\NUL",
            "",
        ] {
            assert!(WinPath::parse(bad).is_err(), "{bad}");
        }
        let root = WinPath::parse("C:\\Data").unwrap();
        let sub = WinPath::parse("c:\\DATA\\x\\y").unwrap();
        assert!(sub.starts_with(&root));
        assert_eq!(sub.strip_prefix(&root).unwrap(), ["x".to_string(), "y".to_string()]);
        assert!(!WinPath::parse("C:\\Database").unwrap().starts_with(&root));
        assert!(!WinPath::parse("D:\\Data").unwrap().starts_with(&root));
    }

    #[test]
    fn name_rules() {
        for ok in ["a", "file.txt", "Grüße", ".hidden", "a b", "LPT10", "console", "x.y.z"] {
            assert!(check_name(ok.as_bytes()).is_ok(), "{ok}");
        }
        for bad in [
            "", ".", "..", "a:b", "a/b", "a\\b", "a*", "q?", "<x>", "a|b", "\"", "tab\t", "trail.", "trail ", "CON",
            "nul.txt", "Com1", "lpt9.log", "AUX ",
        ] {
            assert!(check_name(bad.as_bytes()).is_err(), "{bad}");
        }
        assert!(check_name(&[0xFF]).is_err());
        assert!(check_name("x".repeat(256).as_bytes()).is_err());
        assert!(check_name("x".repeat(255).as_bytes()).is_ok());
    }

    #[test]
    fn entry_paths_and_streams() {
        let (c, s) = check_entry_path(b"C/Users/a.txt", false).unwrap();
        assert_eq!(c.len(), 3);
        assert!(s.is_none());
        assert!(
            check_entry_path(b"C/Users/a.txt:Zone.Identifier", false).is_err(),
            "':' only for ADS"
        );
        let (c, s) = check_entry_path(b"C/Users/a.txt:Zone.Identifier", true).unwrap();
        assert_eq!(c.last().unwrap(), b"a.txt");
        assert_eq!(s.unwrap(), b"Zone.Identifier");
        assert!(
            check_entry_path(b"C/dir:s/a.txt", true).is_err(),
            "stream only on the last component"
        );
        assert!(check_entry_path(b"C/a.txt:", true).is_err());
        assert!(check_entry_path(b"C/a.txt:x:y", true).is_err());
        assert!(check_entry_path(b"C/a.txt", true).is_err());
        assert!(check_entry_path(b"C/../x", false).is_err());
        assert!(check_entry_path(b"C/x/NUL", false).is_err());
    }

    #[test]
    fn excludes_and_beneath() {
        assert_eq!(
            normalize_exclude(r"c:\Users\*\AppData\Local\Temp"),
            "/C/Users/*/AppData/Local/Temp"
        );
        assert_eq!(normalize_exclude("*.tmp"), "*.tmp");
        assert_eq!(normalize_exclude("/C/pagefile.sys"), "/C/pagefile.sys");
        assert!(is_beneath(r"\\?\C:\Restore\a\b", r"C:\restore"));
        assert!(is_beneath(r"\\?\C:\Restore", r"\\?\C:\Restore\"));
        assert!(!is_beneath(r"\\?\C:\Restore2\a", r"C:\Restore"));
        assert!(!is_beneath(r"\\?\C:\Windows\System32", r"C:\Restore"));
        assert!(!is_beneath(r"\\?\C:\x", ""));
    }
}
