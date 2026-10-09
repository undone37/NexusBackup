//! The mount helper's input (nexus-nasmount runs as root with CAP_SYS_ADMIN):
//! whatever a (compromised) connector sends, the request parser must not panic,
//! everything it accepts must pass the option builder, re-encode to an equal
//! request, and produce only fixed option names with values free of NUL/control
//! characters; the mount attributes are always the read-only/nosuid/nodev/
//! noexec/nosymfollow set. The connector-side answer parser gets the same bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nas::opts::{self, Param, ATTRS};
use nas::proto::{parse_response, Request};

const KEYS: &[&str] = &[
    "ro", "source", "vers", "addr", "proto", "port", "mountvers", "mountproto", "mountport", "nolock", "sec", "soft",
    "timeo", "retrans", "nosharecache", "ip", "sign", "seal", "username", "domain", "password", "cruid", "noperm",
    "backupuid", "echo_interval", "nobrl", "nosharesock", "nolease",
];

fuzz_target!(|data: &[u8]| {
    let _ = parse_response(data);
    let Ok(r) = Request::parse(data) else {
        return;
    };
    let again = Request::parse(&r.encode().expect("accepted requests encode")).expect("round trip");
    assert!(again == r);
    let m = opts::build(&r, 1000).expect("accepted requests build");
    assert_eq!(m.attrs, ATTRS);
    assert!(matches!(m.fstype, "nfs" | "nfs4" | "cifs"));
    assert_eq!(m.params.first(), Some(&Param::Flag("ro")));
    for p in &m.params {
        let (k, v) = match p {
            Param::Flag(k) => (*k, ""),
            Param::Str(k, v) => (*k, v.as_str()),
        };
        assert!(KEYS.contains(&k), "{k}");
        assert!(!v.contains('\0'));
        if k != "password" {
            assert!(!v.chars().any(char::is_control), "{k}");
        }
    }
});
