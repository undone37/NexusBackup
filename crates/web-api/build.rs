//! Embeds the built SPA (`web/dist`, or `$NEXUS_WEB_DIST`) into the binary.
//! If the directory does not exist yet the asset table is empty and the
//! server answers client routes with a small placeholder page.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(root, &p, out);
        } else if p.is_file() {
            let rel = p.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            out.push((rel, p.canonicalize().unwrap()));
        }
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=NEXUS_WEB_DIST");
    let dist = std::env::var_os("NEXUS_WEB_DIST")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../web/dist"));
    // a missing path makes cargo re-run this script on every build, so the
    // assets are picked up as soon as the SPA build lands
    println!("cargo:rerun-if-changed={}", dist.display());
    let mut files = Vec::new();
    walk(&dist, &dist, &mut files);
    files.sort();
    let mut src = String::from("pub static ASSETS: &[(&str, &[u8])] = &[\n");
    for (rel, abs) in &files {
        writeln!(src, "    ({rel:?}, include_bytes!({:?})),", abs.to_string_lossy()).unwrap();
    }
    src.push_str("];\n");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("assets.rs");
    std::fs::write(out, src).unwrap();
}
