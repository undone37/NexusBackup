# Release signing key: generation, custody, rotation

The appliance accepts an OS image only if it carries a cosign signature from a key
pinned in `/etc/pki/nexus/cosign/` (`/etc/containers/policy.json`, docs/release.md).
Whoever holds that private key can push code that runs as root on every appliance.
Treat it like a CA root key.

## Roles

- **Key custodians (2 people):** generate the key together, each holds one of the two
  escrow sets, and both must be present to use the key (four-eyes).
- **Release manager:** one of the custodians. Runs `release/sign.sh`.

## What you need

- An **offline machine**: a laptop that never has networking during the ceremony (Wi-Fi
  hardware switch off or removed, no cable). Boot a live system that has podman
  (e.g. a Fedora live USB). Use the same machine for every signing.
- The cosign image, carried over on removable media. On an online machine:
  `podman pull "$COSIGN_IMAGE"` (pinned by digest in `release/config.env`) and then
  `podman save -o cosign.tar "$COSIGN_IMAGE"`. On the offline machine run
  `podman load -i cosign.tar` and compare the digest with `release/config.env`.
- Two new encrypted USB sticks (LUKS) for the escrow copies, plus paper for the
  passphrase.

## Generation (offline machine, both custodians present)

```sh
mkdir -m 700 /tmp/key && cd /tmp/key
# Passphrase: at least 7 Diceware words (or 24+ random characters), generated on the
# offline machine. It is never typed on a networked machine.
podman run --rm -it --user 0 --network none -v .:/k:Z -w /k "$COSIGN_IMAGE" generate-key-pair
mv cosign.key nexus-release-2026a.key
mv cosign.pub nexus-release-2026a.pub
openssl pkey -pubin -in nexus-release-2026a.pub -outform DER | sha256sum   # fingerprint, write it down
```

The key is ECDSA P-256. The private key file is encrypted with the passphrase
(scrypt + NaCl secretbox).

Name keys `nexus-release-<year><letter>.pub`. File names must not contain `TEST`,
because `inject-keys.sh` refuses them.

## Custody

- Copy the encrypted `*.key` onto **both** USB sticks. Custodian A keeps set 1 and
  custodian B keeps set 2, in safes at **two different sites**.
- Write the passphrase on paper twice and seal each copy in an envelope. Each envelope
  goes to a safe that does **not** hold the key copy of the same custodian (A's
  envelope sits with B's stick, and the other way round). A single stolen safe then
  never yields key and passphrase together.
- Then wipe `/tmp/key` (tmpfs on a live system: power off).
- Once a year, both custodians check that both sticks still decrypt
  (`cosign public-key --key ...` on the offline machine, then compare the fingerprint).
- **HSM option:** a PKCS#11 token (e.g. YubiKey PIV, Nitrokey HSM) keeps the key
  non-exportable. The official cosign image is built without PKCS#11 support, so you
  need a cosign build with `-tags pkcs11key` (`COSIGN_IMAGE` and `COSIGN_PKCS11_RUN`
  in `release/sign.sh`). Escrow then means two tokens holding the same key, or a
  documented re-keying procedure (the rotation below), because a lost token cannot
  be recovered.

## Publishing the public key

Add `nexus-release-2026a.pub` to `release/keys/` in a pull request that the other
custodian approves, with the fingerprint in the PR description. The release workflow
(`release/inject-keys.sh`) pins exactly the files in `release/keys/` and removes the
TEST key. Every release's `release-metadata.json` lists the sha256 of the pinned key
files.

## Signing

See docs/release.md ("Release"). With the air-gapped variant, only the small payload
JSON and the signature file cross the air gap. Before signing, compare the digest in
the payload with the one CI printed.

## Rotation

Appliances can only learn a new key from an image signed by a key they already trust.
Keys therefore roll over through one overlapping release.

1. **Generate** key B as above. Add `release/keys/nexus-release-<year>b.pub` next to
   the current key A (two files; `inject-keys.sh` allows at most two).
2. **Release N** pins A + B and is **signed with A**.
3. **Every release after that is signed with both A and B** (run `sign.sh` twice,
   once per key; containers/image accepts an image if *any* attached signature
   verifies with a pinned key, as `release/test-local.sh` case G shows). Appliances
   still on N-1 or older, which trust only A, can then still update. Keep doing this
   until every appliance runs N or later (check the `nexus-update` status in the
   fleet, or ask support).
4. **Then** sign with B only. A later release pins only B. Retire A: both custodians
   physically destroy both sticks and the paper, and record this.

Planned rotation: every 2 years, and whenever a custodian leaves.

**Compromise of the active key.** An attacker with the key can sign images that
appliances accept. Mitigations:
- Keep a **standby key** permanently pinned next to the active one (always two keys
  in `release/keys/`), stored at different sites from the active key. If the active
  key is compromised, ship an emergency release signed with the standby key that pins
  only the standby key plus a fresh standby. Appliances that update before the
  attacker reaches them stop trusting the compromised key.
- Appliances fetch only from `NEXUS_IMAGE_REPO`. An attacker also needs write access
  to that repository, or must redirect the appliance's DNS/TLS, so the GitHub
  organisation and its tokens are part of the trust base.
- Appliances that already installed a malicious image cannot be repaired remotely.
  Reinstall from trusted media.

## Development TEST key

`release/testkey/TEST-cosign.key` (passphrase `nexus-test-key`) and the pinned
`os/etc/pki/nexus/cosign/TEST-KEY-DO-NOT-SHIP.pub` exist for local and lab
builds only. They are public. `release/check-trust.sh --release` and the release
workflow fail if a release image would still contain them.
