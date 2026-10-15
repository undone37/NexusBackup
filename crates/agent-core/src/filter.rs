//! File selection shared by the agents and the NAS connector (docs/agent-protocol.md
//! "Filters"): glob excludes ([`Excludes`]), regex excludes and include roots.
//!
//! - An entry matched by a glob or a regex is skipped (a directory is not descended).
//! - Include roots (absolute paths, no patterns): if any are set, an entry is taken
//!   only inside one of them; the directories leading to a root are kept (so the
//!   tree is complete) but nothing else in them.
//! - Exclusion wins: an excluded directory is skipped even if it leads to, or is,
//!   an include root.
//!
//! Paths are absolute host paths with `/` separators (`/C/Users/…` on Windows).

use crate::glob::Excludes;
use regex::bytes::{RegexSet, RegexSetBuilder};

/// Nested file systems never backed up when crossing mounts: pseudo, in-memory,
/// container overlay, read-only image and network file systems.
pub const DEFAULT_SKIP_FSTYPES: &[&str] = &[
    "proc",
    "sysfs",
    "devtmpfs",
    "devpts",
    "tmpfs",
    "ramfs",
    "overlay",
    "squashfs",
    "iso9660",
    "nfs",
    "nfs4",
    "cifs",
    "smb3",
    "fuse",
    "fuse.sshfs",
    "fuse.gvfsd-fuse",
    "autofs",
    "cgroup",
    "cgroup2",
    "debugfs",
    "tracefs",
    "securityfs",
    "pstore",
    "bpf",
    "configfs",
    "fusectl",
    "mqueue",
    "hugetlbfs",
    "binfmt_misc",
    "efivarfs",
    "rpc_pipefs",
    "nsfs",
];

/// Is `fstype` skipped (`list` empty = [`DEFAULT_SKIP_FSTYPES`])?
pub fn skip_fstype(list: &[String], fstype: &str) -> bool {
    if list.is_empty() {
        DEFAULT_SKIP_FSTYPES.contains(&fstype)
    } else {
        list.iter().any(|t| t == fstype)
    }
}

/// What to do with an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Visit {
    /// not backed up, not descended
    Skip,
    /// a directory leading to an include root: kept and descended, its other
    /// children are filtered (meaningless for non-directories: skip them)
    Pass,
    /// backed up (and descended)
    Take,
}

#[derive(Debug, Default)]
pub struct Filter {
    globs: Excludes,
    regex: Option<RegexSet>,
    include: Vec<Vec<u8>>,
    /// ASCII case-insensitive (Windows)
    fold: bool,
}

/// Size limit of the compiled regexes (a hostile or careless pattern must not eat memory).
const REGEX_SIZE: usize = 1 << 20;

fn build_regex(patterns: &[String], fold: bool) -> Result<Option<RegexSet>, String> {
    let pats: Vec<&str> = patterns.iter().map(|p| p.trim()).filter(|p| !p.is_empty()).collect();
    if pats.is_empty() {
        return Ok(None);
    }
    RegexSetBuilder::new(pats)
        .case_insensitive(fold)
        .size_limit(REGEX_SIZE)
        .dfa_size_limit(REGEX_SIZE)
        .build()
        .map(Some)
        .map_err(|e| format!("regex exclude: {e}"))
}

/// Validates regex excludes (API input) the way the agents compile them.
pub fn check_regex(patterns: &[String]) -> Result<(), String> {
    for p in patterns {
        build_regex(std::slice::from_ref(p), false).map_err(|e| format!("{p:?}: {e}"))?;
    }
    Ok(())
}

/// `p` is `root` or below it (component-wise).
fn under(p: &[u8], root: &[u8]) -> bool {
    root == b"/" || (p.starts_with(root) && (p.len() == root.len() || p[root.len()] == b'/'))
}

impl Filter {
    /// `globs` is the platform's glob matcher; `include` are absolute roots already
    /// in the scan's path form (the caller normalises Windows paths).
    pub fn new(globs: Excludes, include: &[String], regex: &[String], fold: bool) -> Result<Filter, String> {
        let include = include
            .iter()
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .map(|p| {
                if !p.starts_with('/') {
                    return Err(format!("include {p:?}: absolute path required"));
                }
                let p = if p == "/" { p } else { p.trim_end_matches('/') };
                let mut b = p.as_bytes().to_vec();
                if fold {
                    b.make_ascii_lowercase();
                }
                Ok(b)
            })
            .collect::<Result<_, _>>()?;
        Ok(Filter {
            globs,
            regex: build_regex(regex, fold)?,
            include,
            fold,
        })
    }

    /// Glob excludes only (old `Prepare`, tests).
    pub fn globs(globs: Excludes) -> Filter {
        Filter {
            globs,
            ..Default::default()
        }
    }

    /// Matched by a glob or a regex exclude.
    pub fn excluded(&self, abs: &[u8]) -> bool {
        self.globs.matches(abs) || self.regex.as_ref().is_some_and(|r| r.is_match(abs))
    }

    pub fn has_include(&self) -> bool {
        !self.include.is_empty()
    }

    pub fn visit(&self, abs: &[u8]) -> Visit {
        if self.excluded(abs) {
            return Visit::Skip;
        }
        if self.include.is_empty() {
            return Visit::Take;
        }
        let lower;
        let p = if self.fold {
            lower = abs.to_ascii_lowercase();
            &lower[..]
        } else {
            abs
        };
        if self.include.iter().any(|r| under(p, r)) {
            Visit::Take
        } else if self.include.iter().any(|r| under(r, p)) {
            Visit::Pass
        } else {
            Visit::Skip
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(globs: &[&str], include: &[&str], regex: &[&str]) -> Filter {
        let s = |v: &[&str]| v.iter().map(std::string::ToString::to_string).collect::<Vec<_>>();
        Filter::new(Excludes::new(&s(globs)), &s(include), &s(regex), false).unwrap()
    }

    #[test]
    fn include_roots_regex_and_precedence() {
        let x = f(
            &["*.tmp"],
            &["/home/alice", "/srv/data/"],
            &[r"/cache(/|$)", r"\.(bak|old)$"],
        );
        assert_eq!(x.visit(b"/home"), Visit::Pass, "leads to a root");
        assert_eq!(x.visit(b"/home/alice"), Visit::Take);
        assert_eq!(x.visit(b"/home/alice/doc.txt"), Visit::Take);
        assert_eq!(x.visit(b"/home/alicex"), Visit::Skip, "component-wise");
        assert_eq!(x.visit(b"/home/bob"), Visit::Skip);
        assert_eq!(x.visit(b"/srv"), Visit::Pass);
        assert_eq!(x.visit(b"/srv/data/x"), Visit::Take, "trailing / of a root ignored");
        assert_eq!(x.visit(b"/etc"), Visit::Skip);
        // exclusion wins over include
        assert_eq!(x.visit(b"/home/alice/a.tmp"), Visit::Skip, "glob");
        assert_eq!(x.visit(b"/home/alice/cache"), Visit::Skip, "regex dir");
        assert_eq!(x.visit(b"/home/alice/cache/y"), Visit::Skip);
        assert_eq!(x.visit(b"/home/alice/cachex"), Visit::Take);
        assert_eq!(x.visit(b"/home/alice/db.bak"), Visit::Skip);
        assert_eq!(x.visit(b"/home/alice/db.bak2"), Visit::Take);
        // no include: everything not excluded
        let y = f(&[], &[], &["^/var/log/"]);
        assert_eq!(y.visit(b"/var/log"), Visit::Take);
        assert_eq!(y.visit(b"/var/log/syslog"), Visit::Skip);
        assert_eq!(y.visit(b"/etc/passwd"), Visit::Take);
        let all = f(&[], &["/"], &[]);
        assert_eq!(all.visit(b"/anything"), Visit::Take);
        // Windows: case-insensitive include and regex
        let w = Filter::new(
            Excludes::new_case_insensitive(&[]),
            &["/C/Users/Alice".into()],
            &[r"\.PST$".into()],
            true,
        )
        .unwrap();
        assert_eq!(w.visit(b"/c/users/alice/x"), Visit::Take);
        assert_eq!(w.visit(b"/C/USERS"), Visit::Pass);
        assert_eq!(w.visit(b"/C/Users/Alice/mail.pst"), Visit::Skip);
    }

    #[test]
    fn invalid_input_is_refused() {
        assert!(Filter::new(Excludes::default(), &["relative".into()], &[], false).is_err());
        assert!(Filter::new(Excludes::default(), &[], &["(".into()], false).is_err());
        assert!(check_regex(&["a+".into(), "[".into()]).is_err());
        assert!(check_regex(&[r"^/tmp/.*\.swp$".into()]).is_ok());
        // a pattern whose compiled form exceeds the size limit
        assert!(check_regex(&["(\\w{100}){100}".into()]).is_err());
    }

    #[test]
    fn fstype_skip_list() {
        assert!(skip_fstype(&[], "tmpfs"));
        assert!(skip_fstype(&[], "nfs4"));
        assert!(!skip_fstype(&[], "ext4"));
        assert!(
            !skip_fstype(&["nfs".into()], "tmpfs"),
            "an explicit list replaces the default"
        );
        assert!(skip_fstype(&["nfs".into()], "nfs"));
    }
}
