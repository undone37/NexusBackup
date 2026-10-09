//! Checks the cross-compiled artifact of `build.sh` (on demand, after
//! `crates/agent-windows/build.sh --test-key` and signing it with the TEST key:
//! `COSIGN_KEY=release/testkey/TEST-cosign.key COSIGN_PASSWORD=nexus-test-key
//!  release/sign.sh sign-blob target/agent-dist/windows/nexus-agent.exe{,.sig}`):
//!
//!   cargo test -p agent-windows --test dist -- --ignored

use std::path::Path;

#[test]
#[ignore = "needs target/agent-dist/windows from build.sh"]
fn built_exe_is_pe_x64_carries_its_version_and_verifies_with_the_test_key() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/agent-dist/windows");
    let exe = std::fs::read(dir.join("nexus-agent.exe")).expect("run build.sh first");
    assert!(nexus_agent_windows::update::is_pe_x64(&exe));
    assert_eq!(
        agent_core::update::embedded_version(&exe).unwrap(),
        env!("CARGO_PKG_VERSION")
    );
    assert!(exe.len() < agent_proto::MAX_FRAME - 4096, "fits one update frame");
    let sig = std::fs::read(dir.join("nexus-agent.exe.sig")).expect("sign it with the TEST key");
    let key =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../release/testkey/TEST-cosign.pub"))
            .unwrap();
    let keys = vec![("TEST".to_string(), agent_core::update::parse_public_key(&key).unwrap())];
    assert_eq!(agent_core::update::verify(&exe, &sig, &keys).unwrap(), "TEST");
    // the update path accepts it as a newer version
    let (k, v) = agent_core::update::check_candidate(
        env!("CARGO_PKG_VERSION"),
        &exe,
        &sig,
        &keys,
        "0.0.1",
        nexus_agent_windows::update::is_pe_x64,
    )
    .unwrap();
    assert_eq!((k.as_str(), v.as_str()), ("TEST", env!("CARGO_PKG_VERSION")));
}
