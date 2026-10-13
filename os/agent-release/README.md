# Agent releases shipped with the appliance image

`os/Containerfile` copies this directory to `/usr/share/nexus/agent/` (Phase 27,
docs/agent-update-plan.md "Release store"). It is empty in git; the release process
puts the signed release of the agents here before the image is built:

    release/packages.sh                       # target/packages/agent-release/<version>/
    release/sign.sh sign-agent-release target/packages/agent-release/<version>
    release/verify.sh --agent-release target/packages/agent-release/<version>
    cp -a target/packages/agent-release/<version> os/agent-release/

Lab builds use `release/packages.sh --test-key` and sign with the TEST key
(`COSIGN_KEY=release/testkey/TEST-cosign.key COSIGN_PASSWORD=nexus-test-key`). The
appliance verifies every `manifest.json` against its pinned keys
(`/etc/pki/nexus/cosign/*.pub`) and never offers an unsigned release. Version directories
are ignored by git (`.gitignore`); this README is removed from the image.
