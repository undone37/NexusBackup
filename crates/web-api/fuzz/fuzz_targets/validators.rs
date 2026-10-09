//! web-api input validators: no panics, and accepted values keep the
//! properties other components rely on (names are safe path components,
//! source refs are `vm-`/`ct-` + vmid, guest paths are absolute without
//! control characters, schedules parse in the scheduler).
#![no_main]

use libfuzzer_sys::fuzz_target;
use web_api::validate;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let s = s.as_ref();
    if validate::name(s, "n").is_ok() {
        assert!(!s.is_empty() && s.len() <= 64 && !s.starts_with('.'));
        assert!(!s.contains('/') && s != "." && s != "..");
    }
    if validate::schedule(s).is_ok() {
        assert!(s.starts_with("daily ") || s.starts_with("hourly "));
        assert!(s.is_ascii() && s.len() <= 11);
    }
    if validate::source_ref(s).is_ok() {
        let n: u32 = s[3..].parse().unwrap();
        assert!((100..=999_999_999).contains(&n));
        assert!(s.starts_with("vm-") || s.starts_with("ct-"));
    }
    if validate::guest_path(s).is_ok() {
        assert!(s.starts_with('/') && !s.chars().any(char::is_control));
    }
    if validate::host(s).is_ok() {
        assert!(!s.starts_with('-') && !s.contains(' ') && !s.contains('/'));
    }
    let _ = validate::text(s, "t", 100);
    let _ = validate::role(s);
    if let Ok(g) = serde_json::from_slice::<validate::Gfs>(data) {
        let _ = g.check();
        assert!(!g.lowered_by(&g));
    }
});
