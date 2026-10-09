//! Writes seed inputs for `hostile_box` and `pack_parse`: a real (small)
//! upload into an in-memory box, serialized in the MemBox input format.
//! `cargo run --example mkseed -- <corpus root>`

use chunkstore::{Options, Store};
use offsite::target::{self, Target};
use offsite_fuzz::{keys, MemBox};
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(std::env::args().nth(1).expect("corpus root"));
    let d = tempfile::tempdir().unwrap();
    let store = Store::open(
        d.path().join("store"),
        keys(),
        Options {
            min_lock_secs: 0,
            gc_grace_secs: 0,
            ..Default::default()
        },
    )
    .unwrap();
    for t in 1..=3u64 {
        let img: Vec<u8> = (0..4096u32).map(|i| (i * t as u32 / 7) as u8).collect();
        let idx = store.store_image(&img[..], 1024).unwrap();
        let (files, _) = store.store_file(&b"etc/hostname\n"[..]).unwrap();
        let cfg = chunkstore::Index::Dynamic {
            entries: vec![chunkstore::FileEntry {
                path: "qemu-server.conf".into(),
                mode: 0o640,
                size: 13,
                mtime: 0,
                chunks: files,
            }],
        };
        store
            .commit_snapshot("vm-100", t * 1000, &[("drive-scsi0", idx), ("config", cfg)])
            .unwrap();
    }
    let remote = MemBox::default();
    let mut tg = Target::open(&store, &remote, d.path().join("state"), target::Options::default()).unwrap();
    tg.upload().unwrap();
    let files: Vec<(String, Vec<u8>)> = remote
        .files
        .lock()
        .unwrap()
        .iter()
        .map(|(p, (d, _))| (p.clone(), d.clone()))
        .collect();
    std::fs::create_dir_all(out.join("hostile_box")).unwrap();
    std::fs::create_dir_all(out.join("pack_parse")).unwrap();
    std::fs::write(out.join("hostile_box/upload3"), MemBox::encode(&files)).unwrap();
    std::fs::write(
        out.join("hostile_box/upload1"),
        MemBox::encode(&files[..files.len().min(4)]),
    )
    .unwrap();
    for (i, (p, d)) in files.iter().enumerate() {
        if p.ends_with(".pack") {
            std::fs::write(out.join(format!("pack_parse/pack{i}")), d).unwrap();
        }
    }
    eprintln!("{} files", files.len());
}
