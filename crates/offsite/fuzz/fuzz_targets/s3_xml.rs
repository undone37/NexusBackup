//! S3 answers from a hostile endpoint: the XML reader, the ListObjectsV2 and
//! `<Error>` parsers, and the date parser for Object Lock headers. Every input
//! must give a value or an error, never a panic, and listed names must be
//! plain path components.
#![no_main]

use libfuzzer_sys::fuzz_target;
use offsite::{s3, xml};

fuzz_target!(|data: &[u8]| {
    let _ = xml::parse(data);
    // first byte selects the prefix the listing is relative to
    let prefix = match data.first().map(|b| b % 3) {
        Some(0) => "",
        Some(1) => "t1/",
        _ => "t1/packs/ab/",
    };
    if let Ok((files, dirs, next)) = s3::parse_list(data, prefix) {
        for (n, _) in &files {
            assert!(!n.is_empty() && !n.contains('/'));
        }
        for d in &dirs {
            assert!(!d.is_empty() && !d.contains('/'));
        }
        assert!(next.is_none_or(|t| !t.is_empty()));
    }
    let e = s3::parse_error(u16::from(data.first().copied().unwrap_or(0)) + 300, data);
    assert!(e.code.len() <= 800 && e.message.chars().count() <= 200);
    let _ = e.into_io();
    if let Ok(s) = std::str::from_utf8(data) {
        if let Some(t) = s3::parse_iso(s) {
            assert_eq!(s3::parse_iso(&s3::iso_date(t)), Some(t));
        }
    }
});
