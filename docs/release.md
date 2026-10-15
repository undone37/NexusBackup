# Releases, signed updates and rollback (plan.md 12.1, Phase 6)

Decisions (plan.md §2): releases are **signed with cosign using an offline key**. The
appliance pins the public key, and nothing depends on a transparency log or other
sigstore service. **Updates are signed bootc images on ghcr.io**, fetched over HTTPS
through an explicit nftables allow rule.

```
 tag vX.Y.Z ──► CI (release.yml): build, bootc lint, push :vX.Y.Z, SBOM, draft release
                  │ prints ghcr.io/undone37/nexusbackup@sha256:D   (NOT signed)
                  ▼
 release manager: release/sign.sh (offline key) ─► verify.sh --policy ─► promote.sh D stable
                  │                                           (:stable now names D)
                  ▼
 appliance: nexus-update.timer ─► bootc upgrade --download-only (policy.json: signature
            from the pinned key or reject) ─► staged, not applied
            maintenance window / admin "apply" ─► reboot into D
            greenboot: nexus-health red ─► reboot (max 3) ─► bootc rollback ─► previous image
```

## What the appliance trusts

| File (in the image) | Content |
|---|---|
| `/etc/containers/policy.json` | `default: reject`. Exactly one scope: `docker` / `ghcr.io/undone37/nexusbackup` → `sigstoreSigned`, `keyPaths` = pinned keys, `signedIdentity: matchRepository`. No `insecureAcceptAnything` anywhere, no Rekor/Fulcio |
| `/etc/containers/registries.d/nexus-appliance.yaml` | `use-sigstore-attachments: true` for that repository: signatures are read from the cosign tag `sha256-<digest>.sig` in the same registry |
| `/etc/pki/nexus/cosign/*.pub` | Pinned cosign public key(s): one, or two during a rotation (release/keygen.md). Development trees pin `TEST-KEY-DO-NOT-SHIP.pub` |
| `/etc/nexus/update.conf` | `NEXUS_IMAGE_REPO`, channel tag, default maintenance window, egress mode |

So the appliance accepts an OS image only if it comes from that one repository **and**
carries a cosign signature by a pinned key **over that exact manifest digest**. It
rejects everything else from every registry. The appliance runs no other containers.

- **Single constant for the repository:** `NEXUS_IMAGE_REPO` in `release/config.env`.
  The four places that name it (config.env, policy.json, registries.d,
  update.conf) are kept equal by `release/check-trust.sh`. A fork builds with
  `--build-arg NEXUS_IMAGE_REPO=...`, and the Containerfile rewrites the three
  `/etc` files.
- **Why `matchRepository`, not `matchRepoDigestOrExact`:** cosign v2 writes the
  bare repository (no tag) as the signed identity, so the exact match fails for
  `bootc upgrade` by tag (verified in `release/test-local.sh`). The signature still
  binds the manifest digest (case F: a signature replayed onto another digest is
  rejected). With matchRepository, any image our key signed for this repository
  is acceptable under any tag. That allows a *downgrade* to an older signed
  release if someone moves the tag. `nexus-update` therefore refuses to apply an
  image whose `org.opencontainers.image.version` is lower than the booted one,
  unless an admin forces it.
- **cosign v2, not v3:** containers/image (podman, skopeo, bootc) verifies the classic
  simple-signing payload in the `.sig` tag. cosign v3 defaults to the new bundle
  format stored as OCI referrers. The image is pinned by digest in `release/config.env`.

### How bootc applies the policy (AlmaLinux 10.2, bootc 1.16.4)

bootc fetches through `skopeo experimental-image-proxy` (containers/image), but the
deployment's origin decides whether the policy is consulted:

| `bootc status` → `spec.image.signature` | Origin | Fetch |
|---|---|---|
| `insecure` | `ostree-unverified-registry:` (default after `bootc install` / `bootc switch`) | proxy runs with `--insecure-policy`, **policy.json ignored** |
| `containerPolicy` | `ostree-image-signed:docker://` (after `--enforce-container-sigpolicy`) | policy.json enforced. bootc also refuses a `default: insecureAcceptAnything` policy |

`bootc upgrade` keeps the origin's mode. So the signed mode must be set once, and
it then holds for every later upgrade:

- at install time: `bootc install to-disk --enforce-container-sigpolicy --target-imgref ghcr.io/undone37/nexusbackup:stable ...`, or
- afterwards: `bootc switch --enforce-container-sigpolicy ghcr.io/undone37/nexusbackup:stable`.

`nexus-update stage` checks this every time. If the spec image is not
`NEXUS_IMAGE_REPO:NEXUS_UPDATE_TAG` with signature `containerPolicy`, it runs the
`switch --enforce-container-sigpolicy` (whose fetch is then already verified) instead
of an upgrade. A freshly installed appliance therefore moves to the enforced origin
on its first update check.

## Release (release manager)

Prerequisites: `release/keys/*.pub` holds the real public key(s) (release/keygen.md).
podman is the only host tool needed, plus `jq`/`openssl` for check-trust.
`podman login ghcr.io` (the auth file is mounted read-only into the tool containers).

1. `git tag -s vX.Y.Z && git push origin vX.Y.Z`. Then `release.yml`:
   - runs the update-agent/health-check unit tests,
   - `release/inject-keys.sh` replaces the TEST key with `release/keys/*.pub` and runs
     `check-trust.sh --release`,
   - builds `os/Containerfile` with `NEXUS_VERSION`/`NEXUS_IMAGE_REPO`, runs
     `bootc container lint`, and checks that the image's policy.json and keys equal the
     tree and that no TEST key is left,
   - pushes **only** `:vX.Y.Z` (never the channel tag) and records the digest,
   - creates an SPDX SBOM with syft (container), attaches it to the digest as an OCI
     referrer (oras) and uploads it with `release-metadata.json` (digest, commit,
     base image digest, pinned key hashes; no provenance attestation) to a
     **draft** GitHub release whose notes list the commits since the previous tag,
   - then, in the same workflow, scans the image for CVEs (`cve`) and builds the agent packages (`packages`),
   - **does not sign.**

   When it succeeded, `iso.yml` builds the installer ISO and the rescue ISO, and its `assets` job checks that every
   file of the release is attached (ISOs with checksums, SBOM, metadata, CVE report, SHA256SUMS, .deb/.rpm/.msi, the
   agent release tar). Sign only after that job is green. A tag does not run `ci.yml`: tag a commit that passed CI on
   main.
2. Sign the digest from the draft/job summary with the offline key:
   ```sh
   # key machine with registry access:
   COSIGN_KEY=/media/escrow/nexus-release-2026a.key release/sign.sh sign ghcr.io/undone37/nexusbackup@sha256:D
   # or fully air-gapped (only payload.json and payload.sig cross the gap):
   release/sign.sh payload ghcr.io/undone37/nexusbackup@sha256:D payload.json        # online
   COSIGN_KEY=... release/sign.sh sign-payload payload.json payload.sig                 # offline, --network none
   release/sign.sh attach ghcr.io/undone37/nexusbackup@sha256:D payload.json payload.sig  # online
   ```
   Everything runs with `--tlog-upload=false`. `sign.sh` accepts only `IMAGE@sha256:`
   references in `NEXUS_IMAGE_REPO`. A PKCS#11 token works via `COSIGN_PKCS11_URI` (needs
   a cosign build with PKCS#11, see sign.sh).
3. Run steps 3 and 4 in a checkout of the release tag with the release keys pinned
   (`git worktree add --detach ../rel vX && cd ../rel && release/inject-keys.sh`). A plain
   checkout pins the development TEST key, so verify.sh there fails with "not signed by
   TEST-KEY-DO-NOT-SHIP.pub".
   `release/verify.sh --policy ghcr.io/undone37/nexusbackup@sha256:D` runs cosign
   verify against the pinned keys without a tlog, then fetches through skopeo with the
   appliance's own policy.json and registries.d, which is exactly the check bootc makes.
4. `release/promote.sh ghcr.io/undone37/nexusbackup@sha256:D stable` verifies again,
   then points `:stable` at the digest (skopeo, `--preserve-digests`, copied under the
   appliance policy, so an unsigned digest cannot be promoted). Appliances pick it up at
   their next check. Publish the draft release once the package signatures (step 6) are attached.
5. The `iso` workflow (`.github/workflows/iso.yml`) starts when the release workflow succeeds: it builds
   `nexusbackup-<version>-x86_64.iso` with bootc-image-builder (`anaconda-iso`, config `release/iso/config.toml`)
   around the release digest from `release-metadata.json` and uploads it with a `.sha256` to the release. For an
   existing release: `gh workflow run iso.yml -f tag=vX.Y.Z`. The ISO embeds the image (no signature inside); the
   installed system switches to signature enforcement on its first update check. Check an ISO before publishing
   with `lab/appliance/iso-test.sh <iso>` (unattended UEFI install in QEMU, then a screenshot of the first-boot
   wizard).

6. The `packages` job of `release.yml` (after the image job) builds the agent packages with
   `release/packages.sh` (nexus-agent `.deb`/`.rpm` for x86_64 and aarch64, the Windows
   MSI, `SHA256SUMS`; rootless podman only: Rust image, nfpm, Fedora msitools; release keys
   from `release/keys/`), checks them with `release/test-packages.sh` (install/remove in
   debian:13, almalinux:10, fedora; lintian/rpmlint errors fail; MSI tables) and uploads them
   to the draft. CI does not sign them. Sign on the key machine (offline, `--network none`,
   the passphrase is asked once), verify, upload the signatures:
   ```sh
   gh release download vX.Y.Z -D pkgs -p '*.deb' -p '*.rpm' -p '*.msi' -p SHA256SUMS
   COSIGN_KEY=... release/sign.sh sign-blobs pkgs     # checks SHA256SUMS, writes <file>.sig + SHA256SUMS.sig
   release/verify.sh --blobs pkgs                    # every file + SHA256SUMS, against release/keys/*.pub
   gh release upload vX.Y.Z pkgs/*.sig
   ```
   Users check a download with `sha256sum -c --ignore-missing SHA256SUMS` and
   `cosign verify-blob --key <release key>.pub --signature <file>.sig --insecure-ignore-tlog=true <file>`.
   No native package signatures (GPG for apt/dnf, Authenticode for the MSI): there is no
   package repository and no code-signing certificate yet (plan.md §2).

   **Agent release for the appliance** (Phase 27, docs/agent-update-plan.md): the packages job
   also attaches `nexus-agent-release-<v>.tar` (the release tree: `<v>/manifest.json` and the
   binaries, packages and bundles per OS/arch). Sign it on the key machine and attach the
   signed tar; the next image build ships it (`os/agent-release/` → `/usr/share/nexus/agent/`),
   admins can also upload it in Agents → Updates:
   ```sh
   gh release download vX.Y.Z -p 'nexus-agent-release-*.tar' && tar -xf nexus-agent-release-<v>.tar
   COSIGN_KEY=... release/sign.sh sign-agent-release <v>   # checks manifest.json, writes <artifact>.sig + manifest.json.sig
   release/verify.sh --agent-release <v>                  # against release/keys/*.pub
   gh release upload vX.Y.Z nexus-agent-release-<v>-signed.tar
   ```
   Agents of every install type are updated in-band from it (deb with deb, rpm with rpm, MSI
   with MSI, bundles by binary swap); `self_update = off` on a host refuses that.

`release/test-local.sh` runs this whole chain against a throwaway `registry:2` on
127.0.0.1 with the TEST key and a freshly generated untrusted key.

### CVE scan and CIS report (Phase 21d)

- The `cve` job of `release.yml` (after the image job) runs `release/cve-scan.sh
  registry:<image@digest> out`: grype from its pinned image (`GRYPE_IMAGE` in
  `release/config.env`, by digest) in rootless podman with the podman login as registry
  credential; its vulnerability DB is cached in the podman volume `nexus-grype-db` (delete
  it with `podman volume rm nexus-grype-db`; it is downloaded again). Output:
  `grype.txt` (table), `grype.json` (all matches) and `grype-blocking.txt`. Both reports are
  uploaded as the `cve-report` artifact and attached to the draft release as
  `cve-report.txt` / `cve-report.json`; the job summary lists the blocking findings.
- **Gate:** a **critical** CVE whose package has a **fixed version** fails the job. Do not
  publish the draft then: tag a new patch release. The build pulls the base image with
  `--pull=always`, so a rebuild picks up the fixed package. Critical CVEs without a fix and
  all lower severities are in the report but do not fail the release. Review them before
  publishing.
- **CIS report (informational):** the image job runs `release/cis-report.sh
  localhost/nexus-os:release out/cis`. A throw-away container of the image installs
  `openscap-scanner` + `scap-security-guide` and evaluates the CIS server level 1 profile
  (`cis-report.html`, `cis-results.xml`, uploaded as the `cis-report` artifact). The image is
  not changed (`podman run --rm`). Rules about the kernel, boot loader, mounts and running
  services cannot be judged in a container, so the report never fails the workflow. Use it
  as a review aid.
- **Weekly re-scan:** `.github/workflows/cve.yml` scans the published channel tag
  (`:stable`, or any tag via `gh workflow run cve.yml -f tag=vX.Y.Z`) every Monday, because
  new CVEs are published after a release. It does not build anything. CI does not scan on
  every main push: that would need a full image build per push.
- Locally: `release/cve-scan.sh registry:ghcr.io/undone37/nexusbackup:vX.Y.Z out` (after
  `podman login ghcr.io`). The grype container cannot see the host's podman storage. To scan
  an image that was not pushed, save it into the output directory first:
  `podman save --format oci-archive -o out/img.tar localhost/nexus-os:dev &&
  release/cve-scan.sh oci-archive:/out/img.tar out`.
- Nothing is installed on the runner: both tools run in containers, as syft, oras and
  cosign do.

## Updates on the appliance (`nexus-update`)

Units (in `/usr/lib/systemd/system`, enabled by preset `05-nexus-update.preset`):
`nexus-update.timer` (every 15 min, 10 min after boot) and `nexus-update.path`
(immediately on a control-plane request) start `nexus-update.service`, which runs
`/usr/libexec/nexus/nexus-update tick` as root. The stock `bootc-fetch-apply-updates.timer`
(it runs `bootc upgrade --apply`, rebooting at any time), `rpm-ostreed-automatic.timer`
and `podman-auto-update.timer` are disabled by preset. The first two are also masked
in `/etc`.

A tick:
1. consumes a pending request,
2. if the last check is older than `NEXUS_UPDATE_CHECK_HOURS` (24) or `stage` was
   requested: opens egress, runs `bootc upgrade --download-only` (or the enforcing
   `switch`, see above), closes egress. A **download-only** deployment is *not*
   applied by an unplanned reboot or power loss,
3. if an admin requested `apply`, or the maintenance window is open, an update is
   staged and nothing inhibits it: records the digest as `applying` and runs
   `bootc upgrade --from-downloaded --apply` (reboot),
4. writes `status.json`.

Pre-update checks (Phase 14b): before step 2 fetches and before step 3 reboots (once per
tick), `nexus-update` runs `/usr/libexec/nexus/nexus-diag checks` (`NEXUS_UPDATE_DIAG`,
`off` skips). If a check with `status: fail` and `severity >= 3` comes back, the step is
refused: `last_result` = `refused: pre-update checks failed: <id>: <detail>; …`,
`status.json` `checks` = `{time, blocking: [{id, title, severity, detail, manual}]}`, the api
view `status: "blocked"` with `blocked` = that list. The tick still exits 0 (a failed unit
would itself fail the `systemd.failed` check). Rollback is never gated. When nexus-diag
cannot run (exit ≠ 0, bad JSON, missing), the update proceeds and `checks.error` records why:
a broken checker must not block the update that fixes it. The console `stage`/`apply`
commands run the same checks. Checks and their severities: manual/15 "The checks".

Egress: outbound traffic is default-deny (os/nftables.conf). With
`NEXUS_UPDATE_EGRESS=nft`, the addresses of `ghcr.io` and
`pkg-containers.githubusercontent.com` (blob CDN) are resolved (union of 3 lookups)
and added to `inet nexus allowed_out_v4/v6` as `addr . tcp . 443` for the duration of
the fetch only. `nft create` is used, so elements that already existed are left alone
on cleanup. DNS must be allowed (`dns_servers_*`, set by first boot).

Console (root): `nexus-update status | stage | apply | rollback | tick`.

### Interface for web-api / scheduler (not implemented in the UI yet)

Directory `/var/lib/nexus/update/` (tmpfiles: `2770 root:nexus-catalog`, so web-api
and scheduler can write and root reads):

| File | Writer | Meaning |
|---|---|---|
| `request` | web-api | one word: `stage` (check + download now), `apply` (reboot into the staged update now; ignores window and inhibit, and also applies a digest that was rolled back before or an older version), `rollback` (`bootc rollback` + reboot). Consumed at once by `nexus-update.path`. Should be quorum-gated in the control plane |
| `window` | web-api | overrides the default window: `<days> HH:MM <minutes>` in UTC, days = `daily` or `Mon,Thu,...`, or `off` (only admin apply). Invalid content → default window + log |
| `inhibit` | scheduler | while present and touched within the last 6 h, window applies are postponed (touch it while jobs run, delete afterwards). A stale file stops blocking after 6 h |
| `status.json` | root (0640) | `booted`/`staged`/`rollback` {image, digest, version, signature, download_only}, `spec_signature`, `channel`, `window`, `in_window`, `inhibited`, `last_check`, `last_result` {time, request, result}, `applying`, `failed_digests`, `checks` (pre-update checks, above), `api` (the web view) |

Control files are read with `O_NOFOLLOW`, as regular files only and at most 256
bytes. Unknown words are logged and dropped. Open: the web-api and scheduler units
need `ReadWritePaths=/var/lib/nexus/update` (ProtectSystem=strict).

## Rollback (health-check gated)

greenboot (greenboot-rs 0.16.3 from AlmaLinux 10 AppStream, bootc-aware) provides
the boot counting and rollback. `greenboot-default-health-checks` is **not**
installed, because its DNS/repository checks would fail behind the default-deny
firewall.

- After an update (`ConditionNeedsUpdate`), `greenboot-set-rollback-trigger` arms
  the rollback. GRUB (`08_greenboot.cfg`, installed by bootupd at install time)
  counts down `boot_counter` in `/boot/grub2/grubenv`.
- `greenboot-healthcheck.service` (before `boot-complete.target`) runs
  `/usr/lib/greenboot/check/required.d/50-nexus-health.sh` →
  `/usr/libexec/nexus/nexus-health`:
  - **disk:** `/var/lib/nexus`, `/var` ≥ 1 GiB and ≥ 2 % free; `/boot` ≥ 100 MiB,
  - after first-boot setup (`/var/lib/nexus/setup-done`) also: **units**
    (nexus-keyd, nexus-web-api, nexus-scheduler: those that are enabled must be
    active, waiting up to 300 s), **keyd** (socket accepts), **web-api**
    (`https://127.0.0.1:8443/health` → 200 `{"ok":true}`, TLS pinned to
    `/etc/nexus/tls/cert.pem`), **catalog** (read-only `PRAGMA integrity_check` and a
    full audit hash-chain verification, the same algorithm as `catalog::verify_audit`;
    tested against hashes written by the Rust crate).
- Red → greenboot reboots. After `GREENBOOT_MAX_BOOT_ATTEMPTS=3` red boots of the new
  deployment it runs `bootc rollback` and reboots into the previous image. Without
  an armed trigger (no update happened) a red boot means "manual intervention", and
  there is no reboot loop.
- On the next tick, `nexus-update` sees that it is not running the digest it applied.
  It adds that digest to `failed_digests` and will not apply it again automatically
  (the channel tag still points to it until a fixed release is promoted).

Caveats:
- A red boot caused by something an update cannot fix (a full disk, a corrupt
  catalog) after an update costs up to 3 reboots and then a rollback. On the old
  image the failure stays red without reboots, so check `journalctl -u
  greenboot-healthcheck`.
- **Catalog schema migrations must survive a rollback.** The new image's services run
  before the health verdict. A migration that the previous release cannot open makes
  the rollback fail too. Rule: migrations stay backward compatible for one release
  (old binaries ignore new columns/tables); destructive cleanups run one release later.
  Example v4 (Linux agents): new table `agents`, and `sources` rebuilt with the same
  columns, ids and constraints but a wider `kind` CHECK (SQLite cannot alter a CHECK).
  An older release skips the migration (`user_version` 4 > its last), reads `sources`
  unchanged and fails jobs of `linux` sources as unsupported. Test:
  `catalog::tests::migration_v4_keeps_pve_sources`. v5 (TrueNAS) and v6 (NFS/SMB shares)
  rebuild `sources` the same way (`migration_v6_adds_share_sources`). v7 (appliance
  replication, docs/replication.md) is purely additive and runs after v6: tables
  `replication_peers`, `replication_sources` and the nullable column `snapshots.origin`;
  `sources` keeps v6's kind CHECK (pve, linux, truenas, nfs, smb). The v6 release skips
  migration 7 (`user_version` 7 > 6), its `sources`/`snapshots` queries (and snapshot
  inserts without `origin`) keep working, and it never reads the new tables. Test:
  `catalog::tests::migration_v7_adds_replication` (a v6 catalog with share sources and
  snapshots migrates, rows/ids/references survive, then reopened as v6).
- Appliances installed before greenboot was in the image have no `08_greenboot.cfg` in
  `/boot` until `bootupctl update`. 1.0 ships greenboot from the first install.

## Lab test procedure (VM, A1's environment)

Unit level (no root): `python3 -m unittest discover -s os/greenboot/tests -v` (44 tests:
health checks incl. a TLS server, catalog corruption and chain tampering; update agent
against fake bootc/nft/systemctl: origin switch, download-only, window across midnight,
inhibit, requests, symlinked or unknown requests, rollback detection, downgrade guard,
egress open/close order). Signing chain: `release/test-local.sh`.

In a VM (rootless QEMU, user networking; the host is `10.0.2.2`):
1. Run a registry on the host: `podman run -d -p 5055:5000 docker.io/library/registry:2`.
   The signed identity is the repository *name*, so host and VM must use the same name:
   `R=nexus-lab-registry:5055/nexusbackup/appliance`. In the VM that name resolves to
   10.0.2.2. On the host the tools get
   `NEXUS_TOOL_ARGS=--add-host=nexus-lab-registry:127.0.0.1`.
   Build v1 with `--build-arg NEXUS_IMAGE_REPO=$R --build-arg NEXUS_VERSION=0.0.1` and
   these lab-only files: `/etc/hosts` entry `10.0.2.2 nexus-lab-registry`,
   `/etc/containers/registries.conf.d/lab.conf` (`[[registry]]
   location="nexus-lab-registry:5055"` + `insecure=true`) and `NEXUS_UPDATE_EGRESS=none` in
   update.conf, unless the lab fills the nft sets. Push via `127.0.0.1:5055/...` (same
   storage). Then run
   `NEXUS_IMAGE_REPO=$R NEXUS_ALLOW_HTTP=1 NEXUS_TOOL_ARGS=… COSIGN_KEY=release/testkey/TEST-cosign.key release/sign.sh sign $R@sha256:…`
   (passphrase `nexus-test-key`) and `release/promote.sh $R@sha256:… stable` with the same
   variables. Install the VM from the image.
2. `bootc status`: signature `insecure`. `systemctl start nexus-update.service` →
   journal "switching origin … (signature enforced)", `bootc status --json` spec signature
   `containerPolicy`. Reboot.
3. **Unsigned update rejected:** push an unsigned v2 and point `:stable` at it with
   `skopeo copy --insecure-policy`. `nexus-update stage` → `A signature was required`,
   nothing staged.
4. **Signed update, staged only:** sign and promote v2 (0.0.2).
   `echo stage > /var/lib/nexus/update/request` → staged, `download_only: true`.
   Power-cycle the VM: still on v1. `echo apply > …/request` → reboots into v2.
   `journalctl -u greenboot-healthcheck` GREEN, `grub2-editenv list` → `boot_success=1`.
5. **Window:** `echo "daily HH:MM 30" > …/window` (a few minutes ahead, UTC) with v3
   staged → reboot inside the window. Touch `inhibit` first → no reboot.
6. **Rollback:** v4 = v3 + `/usr/lib/greenboot/check/required.d/00-fail.sh` (`exit 1`),
   signed and promoted. Apply → 3 red boots → greenboot `bootc rollback` → v3 booted,
   `bootc status` rollback = v4. The next tick → `failed_digests` contains v4. The window
   does not re-apply it. A real-service variant: `systemctl mask nexus-web-api` in v4.
7. **Downgrade guard:** promote v2 again → staged, but the window apply refuses
   ("older than the booted one"). Admin `apply` would force it.
