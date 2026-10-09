//! Restore path confinement (algorithm pure and tested on a simulated namespace; the
//! Windows implementation of [`Namespace`] is in `win/restore.rs`).
//!
//! Every directory below the restore target is opened one component at a time with
//! `FILE_FLAG_OPEN_REPARSE_POINT` (the component itself is opened, never what it
//! points to) and checked: a reparse point (symlink, junction, mount point) or a
//! non-directory in the path ends the operation. The handles of the whole chain stay
//! open without `FILE_SHARE_DELETE`, so no verified directory can be renamed, removed
//! or replaced by a junction while the entry is written; the final object is opened
//! the same way and its final path is checked to lie below the target.

/// What a component turned out to be (opened without following it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Node {
    Dir,
    File,
    /// symlink, junction, volume mount point, or any other reparse point
    Reparse,
}

pub trait Namespace {
    type Handle;
    /// The restore target itself.
    fn root(&mut self) -> std::io::Result<Self::Handle>;
    /// Open `name` inside `parent` without following it; `Ok(None)` if it does not exist.
    fn open(&mut self, parent: &Self::Handle, name: &[u8]) -> std::io::Result<Option<(Self::Handle, Node)>>;
    /// Create directory `name` inside `parent` (fails if it exists).
    fn mkdir(&mut self, parent: &Self::Handle, name: &[u8]) -> std::io::Result<()>;
}

fn refuse(msg: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, msg)
}

/// Open the directory chain `root/comps[0]/.../comps[n-1]`, optionally creating
/// missing directories. Returns all handles (root first) — keep them alive while the
/// final component is used.
pub fn open_dirs<N: Namespace>(ns: &mut N, comps: &[&[u8]], create: bool) -> std::io::Result<Vec<N::Handle>> {
    let mut chain = vec![ns.root()?];
    for (i, c) in comps.iter().enumerate() {
        let shown = || String::from_utf8_lossy(&comps[..=i].join(&b'/')).into_owned();
        let parent = chain.last().expect("root");
        let opened = match ns.open(parent, c)? {
            None if create => {
                ns.mkdir(parent, c)?;
                ns.open(parent, c)?
            }
            r => r,
        };
        match opened {
            Some((h, Node::Dir)) => chain.push(h),
            Some((_, Node::Reparse)) => {
                return Err(refuse(format!("{}: reparse point in the path (not followed)", shown())))
            }
            Some((_, Node::File)) => return Err(refuse(format!("{}: not a directory", shown()))),
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("{}: missing", shown()),
                ))
            }
        }
    }
    Ok(chain)
}

#[cfg(test)]
pub mod sim {
    //! A simulated case-insensitive namespace with directories, files and junctions.
    use super::*;
    use std::collections::BTreeMap;
    use std::io;

    #[derive(Default)]
    pub struct Sim {
        /// upper-cased full path (`/`-joined, "" = root) → kind and junction target
        pub nodes: BTreeMap<String, (Node, Option<String>)>,
        pub held: Vec<String>,
    }

    impl Sim {
        pub fn new() -> Sim {
            let mut s = Sim::default();
            s.nodes.insert(String::new(), (Node::Dir, None));
            s
        }
        pub fn add(&mut self, path: &str, n: Node, target: Option<&str>) {
            self.nodes
                .insert(path.to_uppercase(), (n, target.map(str::to_uppercase)));
        }
        fn key(parent: &str, name: &[u8]) -> String {
            let n = String::from_utf8_lossy(name).to_uppercase();
            if parent.is_empty() {
                n
            } else {
                format!("{parent}/{n}")
            }
        }
    }

    impl Namespace for Sim {
        type Handle = String;
        fn root(&mut self) -> io::Result<String> {
            Ok(String::new())
        }
        fn open(&mut self, parent: &String, name: &[u8]) -> io::Result<Option<(String, Node)>> {
            let k = Sim::key(parent, name);
            Ok(self.nodes.get(&k).map(|(n, _)| {
                self.held.push(k.clone());
                (k.clone(), *n)
            }))
        }
        fn mkdir(&mut self, parent: &String, name: &[u8]) -> io::Result<()> {
            let k = Sim::key(parent, name);
            if self.nodes.contains_key(&k) {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            self.nodes.insert(k, (Node::Dir, None));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::sim::Sim;
    use super::*;

    #[test]
    fn walks_creates_and_refuses_reparse_points() {
        let mut ns = Sim::new();
        ns.add("a", Node::Dir, None);
        ns.add("a/junction", Node::Reparse, Some("C:/Windows"));
        ns.add("a/file", Node::File, None);
        // existing chain, case-insensitive
        let chain = open_dirs(&mut ns, &[b"A"], false).unwrap();
        assert_eq!(chain, vec!["".to_string(), "A".to_string()]);
        // missing dirs are created only on request
        assert!(open_dirs(&mut ns, &[b"a", b"new", b"deeper"], false).is_err());
        let chain = open_dirs(&mut ns, &[b"a", b"new", b"deeper"], true).unwrap();
        assert_eq!(chain.len(), 4);
        assert!(ns.nodes.contains_key("A/NEW/DEEPER"));
        // a junction anywhere in the path is never traversed
        let e = open_dirs(&mut ns, &[b"a", b"junction", b"System32"], true).unwrap_err();
        assert!(e.to_string().contains("reparse point"), "{e}");
        assert!(
            !ns.nodes.keys().any(|k| k.starts_with("A/JUNCTION/")),
            "nothing created behind it"
        );
        let e = open_dirs(&mut ns, &[b"a", b"JUNCTION"], false).unwrap_err();
        assert!(e.to_string().contains("reparse point"));
        // a file in the way
        let e = open_dirs(&mut ns, &[b"a", b"file", b"x"], true).unwrap_err();
        assert!(e.to_string().contains("not a directory"));
    }

    #[test]
    fn race_planted_junction_after_mkdir_is_caught() {
        /// mkdir succeeds, but before the re-open an attacker swaps in a junction
        struct Racy(Sim);
        impl Namespace for Racy {
            type Handle = String;
            fn root(&mut self) -> std::io::Result<String> {
                self.0.root()
            }
            fn open(&mut self, p: &String, n: &[u8]) -> std::io::Result<Option<(String, Node)>> {
                self.0.open(p, n)
            }
            fn mkdir(&mut self, p: &String, n: &[u8]) -> std::io::Result<()> {
                self.0.mkdir(p, n)?;
                let k = if p.is_empty() {
                    String::from_utf8_lossy(n).to_uppercase()
                } else {
                    format!("{p}/{}", String::from_utf8_lossy(n).to_uppercase())
                };
                self.0.nodes.insert(k, (Node::Reparse, Some("C:/".into())));
                Ok(())
            }
        }
        let mut ns = Racy(Sim::new());
        assert!(open_dirs(&mut ns, &[b"x", b"y"], true).is_err());
    }
}
