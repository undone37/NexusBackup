//! The parent decoding what a compromised helper sends: entry batches must be
//! rejected or yield relative paths without `.`/`..`/empty components, owners
//! of the allowed characters and hashes only on files.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut r = data;
    while let Ok((tag, p)) = fsindex::proto::read_frame(&mut r) {
        match tag {
            b'E' => {
                let mut out = Vec::new();
                if fsindex::proto::decode_entries(&p, &mut out).is_ok() {
                    for e in out {
                        assert!(!e.path.starts_with('/'));
                        assert!(e.path.split('/').all(|c| !c.is_empty() && c != "." && c != ".."));
                        assert!(e.owner.as_deref().is_none_or(fsindex::valid_owner));
                        assert!(e.sha256.is_none() || e.kind == fsindex::KIND_FILE);
                    }
                }
            }
            b'B' | b'Z' => {
                let _ = serde_json_free(&p);
            }
            _ => {}
        }
    }
});

fn serde_json_free(p: &[u8]) -> bool {
    fsindex::proto::parse_volume(p).is_ok()
}
