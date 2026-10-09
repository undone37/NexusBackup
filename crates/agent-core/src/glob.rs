//! Exclude patterns (shell-style, byte based).
//!
//! - `*` matches within one path component, `?` one byte, `**` any number of components.
//! - A pattern containing `/` is matched against the whole absolute host path
//!   (a leading `/` is optional; `/var/cache/**` or `/home/*/.cache`).
//! - A pattern without `/` is matched against the file name alone (`*.tmp`, `lost+found`).
//!
//! An excluded directory is not descended into.

#[derive(Clone, Debug, Default)]
pub struct Excludes {
    pats: Vec<(Vec<u8>, bool)>, // (pattern, anchored on the full path)
    /// ASCII case-insensitive matching (Windows file systems)
    fold: bool,
}

impl Excludes {
    pub fn new(patterns: &[String]) -> Excludes {
        let pats = patterns
            .iter()
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .map(|p| {
                if p.contains('/') {
                    let p = p.trim_end_matches('/');
                    let p = if p.starts_with('/') {
                        p.to_string()
                    } else {
                        format!("/{p}")
                    };
                    (p.into_bytes(), true)
                } else {
                    (p.as_bytes().to_vec(), false)
                }
            })
            .collect();
        Excludes { pats, fold: false }
    }

    /// Same patterns, matched ASCII case-insensitively (NTFS/ReFS names).
    pub fn new_case_insensitive(patterns: &[String]) -> Excludes {
        let mut e = Excludes::new(patterns);
        for (p, _) in &mut e.pats {
            p.make_ascii_lowercase();
        }
        e.fold = true;
        e
    }

    /// `abs` is the absolute host path (starting with `/`).
    pub fn matches(&self, abs: &[u8]) -> bool {
        if self.fold {
            let lower = abs.to_ascii_lowercase();
            return self.matches_exact(&lower);
        }
        self.matches_exact(abs)
    }

    fn matches_exact(&self, abs: &[u8]) -> bool {
        let name = abs.rsplit(|b| *b == b'/').next().unwrap_or(abs);
        self.pats
            .iter()
            .any(|(p, anchored)| if *anchored { glob(p, abs) } else { glob(p, name) })
    }
}

/// Iterative-backtracking glob over bytes.
fn glob(p: &[u8], s: &[u8]) -> bool {
    if p.is_empty() {
        return s.is_empty();
    }
    if p.starts_with(b"**") {
        let after = &p[2..];
        if after.is_empty() {
            return true;
        }
        // `**/x`: zero or more whole components, then `x` at a component start
        if let Some(rest) = after.strip_prefix(b"/") {
            return (0..=s.len())
                .filter(|&i| i == 0 || s[i - 1] == b'/')
                .any(|i| glob(rest, &s[i..]));
        }
        return (0..=s.len()).any(|i| glob(after, &s[i..]));
    }
    match p[0] {
        b'*' => (0..=s.len())
            .take_while(|&i| i == 0 || s[i - 1] != b'/')
            .any(|i| glob(&p[1..], &s[i..])),
        b'?' => !s.is_empty() && s[0] != b'/' && glob(&p[1..], &s[1..]),
        c => !s.is_empty() && s[0] == c && glob(&p[1..], &s[1..]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclude_patterns() {
        let e = Excludes::new(&[
            "*.tmp".into(),
            "/var/cache/**".into(),
            "home/*/.cache".into(),
            "lost+found".into(),
            "/srv/**/node_modules".into(),
        ]);
        assert!(e.matches(b"/tmp/a.tmp"));
        assert!(e.matches(b"/data/x/y.tmp"));
        assert!(!e.matches(b"/data/x/y.tmpx"));
        assert!(e.matches(b"/var/cache/apt"));
        assert!(e.matches(b"/var/cache/apt/archives/x.deb"));
        assert!(!e.matches(b"/var/cachex"));
        assert!(e.matches(b"/home/alice/.cache"));
        assert!(!e.matches(b"/home/alice/sub/.cache"), "* does not cross /");
        assert!(e.matches(b"/lost+found"));
        assert!(e.matches(b"/srv/node_modules"));
        assert!(e.matches(b"/srv/a/b/node_modules"));
        assert!(!e.matches(b"/srv/a/b/node_modules2"));
        assert!(!e.matches(b"/srv/a/xnode_modules"));
        assert!(!Excludes::new(&[]).matches(b"/x"));
        assert!(!e.matches(b"/TMP/A.TMP"), "case-sensitive by default");
        let w = Excludes::new_case_insensitive(&["*.TMP".into(), "/C/Users/*/AppData/Local/Temp".into()]);
        assert!(w.matches(b"/C/x/a.tmp"));
        assert!(w.matches(b"/c/users/Alice/appdata/local/TEMP"));
        assert!(!w.matches(b"/C/Users/Alice/AppData/Local/Templates"));
    }
}
