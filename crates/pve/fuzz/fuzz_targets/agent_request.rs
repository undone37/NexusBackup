//! Guest side of the restore micro-VM protocol: request parsing and path
//! validation in the agent (restore-vm/agent, included by path). Invariant: a
//! path is only ever mapped to a mountpoint plus plain components (no `.`,
//! `..`, empty or NUL), so `openat2(RESOLVE_IN_ROOT)` gets a relative path.
#![no_main]

#[allow(dead_code, unused_imports, unused_macros)]
#[path = "../../../../restore-vm/agent/src/main.rs"]
mod agent;

use libfuzzer_sys::fuzz_target;

fn mps() -> Vec<String> {
    ["/vda1", "/lvm/vg0-root", "/zfs/tank", "/zfs/tank+data"]
        .map(String::from)
        .to_vec()
}

fn check(path: &str) {
    match agent::resolve(path, &mps()) {
        Ok(agent::Target::Fs(mp, rel)) => {
            assert!(mps().contains(&mp));
            for c in &rel {
                assert!(
                    !c.is_empty() && c != "." && c != ".." && !c.contains('/') && !c.contains('\0'),
                    "{c:?}"
                );
            }
        }
        Ok(agent::Target::Virtual(comps)) => {
            assert!(comps.iter().all(|c| !c.is_empty() && c != "." && c != ".."));
        }
        Err(_) => {}
    }
}

fuzz_target!(|data: &[u8]| {
    for line in data.split(|b| *b == b'\n') {
        match serde_json::from_slice::<agent::Req>(line) {
            Ok(agent::Req::Ls { path }) => check(&path),
            Ok(agent::Req::Tar { paths }) => paths.iter().for_each(|p| check(p)),
            _ => {}
        }
    }
    check(&String::from_utf8_lossy(data));

    // framing round trip: agent writer -> appliance reader, uneven write sizes
    let mut fw = agent::Frames {
        w: Vec::new(),
        buf: Vec::new(),
    };
    let mut rest = data;
    while !rest.is_empty() {
        let k = (rest[0] as usize % 17 + 1).min(rest.len());
        std::io::Write::write_all(&mut fw, &rest[..k]).unwrap();
        rest = &rest[k..];
    }
    let wire = fw.finish().unwrap();
    let (mut r, mut left, mut done, mut out, mut buf) = (&wire[..], 0u32, false, Vec::new(), [0u8; 11]);
    loop {
        let n = pve::restorevm::read_frame(&mut r, &mut left, &mut done, &mut buf).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    assert_eq!(out, data);
    assert!(r.is_empty());
});
