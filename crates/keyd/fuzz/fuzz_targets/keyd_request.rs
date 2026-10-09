//! keyd socket protocol: request lines (`<tenant>`, `ensure <tenant>`,
//! `escrow <tenant>`) as read from the socket (at most 128 bytes), and the
//! client-side escrow answer decoder. Invariants: no panic, nothing created
//! outside `tenants/<valid name>/`, DEK answers are whole 36-byte records,
//! escrow answers decode to wrapped files only.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::fs;
use std::path::Path;

fn valid(t: &str) -> bool {
    !t.is_empty()
        && t.len() <= 64
        && !t.starts_with('.')
        && t.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn check_tree(dir: &Path) {
    for e in fs::read_dir(dir).unwrap() {
        let n = e.unwrap().file_name().into_string().unwrap();
        assert!(
            ["kek.local", "kek.recovery", "tenants"].contains(&n.as_str()),
            "unexpected {n}"
        );
    }
    for e in fs::read_dir(dir.join("tenants")).unwrap() {
        let n = e.unwrap().file_name().into_string().unwrap();
        assert!(valid(&n), "tenant dir {n:?}");
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = keyd::parse_escrow(data);

    let d = tempfile::tempdir_in("/dev/shm").unwrap();
    keyd::init(d.path()).unwrap();
    keyd::create_tenant(d.path(), "acme").unwrap();
    // the server reads one line of at most 128 bytes as UTF-8
    let raw = &data[..data.len().min(128)];
    let raw = raw.split_inclusive(|b| *b == b'\n').next().unwrap_or_default();
    let Ok(line) = std::str::from_utf8(raw) else { return };
    match keyd::answer(d.path(), line) {
        Ok(out) => {
            let l = line.trim_end_matches('\n');
            if let Some(t) = l.strip_prefix("escrow ") {
                assert!(valid(t));
                let files = keyd::parse_escrow(&out).unwrap();
                assert!(files
                    .iter()
                    .all(|(n, _)| n == "kek.recovery" || n.starts_with(&format!("tenants/{t}/dek."))));
            } else {
                assert!(!out.is_empty() && out.len() % 36 == 0);
            }
        }
        Err(_) => {}
    }
    check_tree(d.path());
});
