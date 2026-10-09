//! File restore from hostile tar streams (a container's tar, or the restore
//! micro-VM agent after a guest-kernel compromise): listing and extraction into
//! tar/zip must not panic, and the produced download must never contain a
//! path that escapes the extraction directory on the user's machine.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pve::files::{self, Format};
use std::io::{Read, Seek};
use std::path::{Component, Path, PathBuf};

fn safe(p: &Path) -> bool {
    p.components()
        .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
}

/// No entry may live below an earlier symlink entry (write-through-symlink on extraction).
fn below_link(links: &[PathBuf], p: &Path) -> bool {
    links.iter().any(|l| p != l && p.starts_with(l))
}

fuzz_target!(|data: &[u8]| {
    for dir in ["", "etc", "/a/b/"] {
        let _ = files::list(data, dir);
    }
    let sel = [String::new()];

    let mut f = tempfile::tempfile_in("/dev/shm").unwrap();
    if files::extract(data, &sel, Format::Tar, f.try_clone().unwrap()).is_ok() {
        f.rewind().unwrap();
        let mut a = tar::Archive::new(&mut f);
        let mut links = Vec::new();
        for e in a.entries().unwrap() {
            let Ok(e) = e else { break };
            let p = e.path().unwrap().into_owned();
            assert!(safe(&p), "unsafe tar path {p:?}");
            assert!(!below_link(&links, &p), "{p:?} below a symlink");
            if e.header().entry_type() == tar::EntryType::Symlink {
                links.push(p.clone());
            }
            if e.header().entry_type() == tar::EntryType::Link {
                if let Ok(Some(l)) = e.link_name() {
                    assert!(safe(&l), "unsafe hardlink target {l:?}");
                }
            }
        }
    }

    let mut f = tempfile::tempfile_in("/dev/shm").unwrap();
    if files::extract(data, &sel, Format::Zip, f.try_clone().unwrap()).is_ok() {
        f.rewind().unwrap();
        let mut z = zip::ZipArchive::new(f).unwrap();
        let mut links = Vec::new();
        for i in 0..z.len() {
            let mut e = z.by_index(i).unwrap();
            let p = e.enclosed_name();
            assert!(p.is_some(), "unsafe zip name {:?}", e.name());
            let p = p.unwrap();
            assert!(!below_link(&links, &p), "{p:?} below a symlink");
            if e.is_symlink() {
                links.push(p);
            }
            let mut sink = Vec::new();
            let _ = e.read_to_end(&mut sink);
        }
    }
});
