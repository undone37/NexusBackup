# Threat Model (v0.2)

Scope: the appliance, its sources and the offsite tier, as described in `plan.md`.
v0.2 (2026-10-09): updated after the internal security review
(`docs/security-review.md`); T12/T13 added, mitigations point to code, residual
risks reflect the current implementation. External test scope: `docs/pentest-scope.md`.

## Assets
1. Backup data and indexes (confidentiality, integrity, availability).
2. Tenant DEKs, appliance KEK, recovery key.
3. Credentials the appliance holds for sources and Storage Boxes (tier-0).
4. Retention guarantees (locks, compliance clock, quorum, audit log).
5. Root on the protected PVE nodes (the node plugin runs as root).

## Adversaries and mitigations

| # | Adversary / scenario | Goal | Mitigations | Residual risk |
|---|---|---|---|---|
| T1 | Ransomware on a source (PVE node, server) | Destroy or encrypt backups | Pull model: sources hold no appliance credentials and the appliance has no inbound data port; SSH `restrict`/forced command with strict argument regexes (`pve-plugin/helper`). | Encrypted data gets backed up; detect via change-rate anomaly alerts (later). |
| T2 | Compromised admin account | Delete backups, shorten retention, stop offsite | Locks only extendable (`Store::extend_lock`/`delete_snapshot`); quorum for destructive/weakening actions incl. group moves, tenant offsite changes, privileged account changes; stale approvals refused; write-only secrets do not follow endpoint changes; TOTP; hash-chained audit log; RBAC matrix test. | Two colluding roles; admin can still stop *future* backups (remove guests from groups, break source config) — detected by the lag/failed-job alerts, not prevented; own password/TOTP reset without re-authentication. |
| T3 | System time manipulation (`date`, rogue NTP) | Expire locks early | Compliance clock with bounded forward slew (ADR-011), non-finite values refused; NTS for chrony. | +1 % drift; deleting the clock file (uid `nexus-chunkstore` or root) re-trusts system time once; TPM NV counter later. |
| T4 | Storage provider / Storage Box compromise (passive) | Read or fingerprint data | Per-tenant keyed chunk IDs, AEAD on everything (AAD binds tenant + context), meaningless file names. | Traffic and size analysis (compression before encryption leaks sizes). |
| T5 | Storage Box deletion (by a compromised appliance) | Destroy the offsite copy | Box snapshots set up in the Hetzner console (no API key on the appliance); offsite inventory monitoring. S3 targets: Object Lock in compliance mode on every pack, snapshot file and key escrow file (until the snapshot's offsite lock), credentials without `DeleteObjectVersion`/bucket changes, deletes only add markers (docs/s3-offsite.md). | Storage Box: ~6-week detection window. S3: unlocked data only for the lifecycle delay; lock extension to absurd dates (cost); provider without real compliance semantics. |
| T6 | Compromised appliance (root) | Reach the whole infrastructure | Least-privilege source credentials, separate management network, SELinux domains, no interactive root, nftables egress allow-list. | Source data readable within scope (inherent to the pull model); root on PVE nodes via restore (T13). Several services share one uid today (review H-3). |
| T7 | Disk / hardware theft | Read data | Chunk AEAD; LUKS2 + TPM **deferred**. | KEK is a plain 0600 file (review H-1): disk theft = all tenant data. Cold-boot attack. |
| T8 | Bit rot / tampered chunks | Silent corruption | AEAD tag + keyed-hash re-check on every read; rolling verify; offsite sampled verify. | Corruption is detected, not repaired, without a second copy. |
| T9 | Crash / power loss during a write | Corrupt store | Commit protocol (ADR-012), GC aborts on an unreadable manifest/index, grace period. | Backups longer than the grace period. |
| T10 | Malicious agent / NBD / SFTP peer, malicious guest content | Exploit parsers, plant files on the user's machine | Rust, cargo-fuzz targets for every network-facing parser (`crates/*/fuzz`, `lab/fuzz/run.sh`), mTLS for agents (later), restore micro-VM for foreign file systems, file-restore downloads drop `..`/NUL names and entries below symlinks. | Kernel NBD/FS bugs (confined to the micro-VM, but QEMU shares the scheduler uid today); restored disks are parsed by the node kernel (`/dev/nbdX`); unbounded tar long names / NBD extent lists (memory DoS of one job). |
| T11 | Path traversal via source / index names | Write outside the store | `check_name` allows only `[A-Za-z0-9._-]` without a leading dot; offsite listings validated the same way (pack ids = 32 hex). | — |
| T12 | Malicious Storage Box (active: crafted listings, packs, footers, extra files) | Crash DR/verify, plant data, cause local data loss | Every pack index / manifest / index authenticated before use, only files named by the authenticated manifest are kept, foreign names reported as unknown, footers range-checked, downloads bounded by the recorded pack size; fuzz target `hostile_box` asserts no local loss and no writes outside the state dir. | Denial of DR / offsite (the box can delete anyway, T5); memory DoS via huge manifests. |
| T13 | Stolen appliance SSH key (helper user `nexusbackup`) or compromised appliance → PVE node | Root on the node | Forced command + `restrict`, root-owned `authorized_keys`; sticky rendezvous and state dirs; root writes only into root-owned dirs with `O_EXCL|O_NOFOLLOW`; restore drops `lxc.*`/`args`/`hookscript` keys from catalog configs; CT staging dir must be a private root-owned dir. | Helper can still DoS jobs (predictable names) and read the live NBD export it is given; restored guest disks touch the node kernel (`/dev/nbdX`, udev, LVM autoactivation); no `from=` restriction in `authorized_keys` by default. |

| T14 | Replication (docs/replication.md): compromised secondary, compromised primary, network attacker between them, stolen peer certificate | Read other tenants, destroy the replicated copy, obtain DEKs | Secondary pulls (primary holds no credentials for it); mTLS with certificates of the primary's own replication CA, fingerprint re-checked per request (revocation immediate), tenant scope per peer enforced by web-api and replicad; peer API only on the replication ALPN; replicad reads stores read-only, has no keys/network; DEKs only sealed to the secondary keyd's X25519 key after a second quorum approval naming that key; enrollment = one-time code + pinned primary certificate + TLS-exporter-bound proofs (MITM test); every received object verified before import, manifest last; secondary never deletes because the primary did. | A compromised secondary reads its scoped tenants (inherent). A compromised web-api on the primary could ask replicad for any tenant's *sealed* objects. A malicious primary can stop serving or serve garbage (failed sync + alert) and push newer DEK versions for its own tenants. Listing reveals source names and times of scoped tenants. Same uid for replicad and the scheduler (H-3): MAC is the boundary. |

## Process isolation (plan §4.2) — state after review

| Rule | Status |
|---|---|
| web-api never touches chunks or keys | ✓ (own uid `nexus-webapi`, no keyd access). It can read/write the catalog, but source/offsite secrets only as `sealed:v1:` blobs sealed to the scheduler key (it holds only the public key). TOTP seeds are encrypted with the web-api's own key (review H-2 fixed). Residual: root and the scheduler uid can open source secrets; the web-api uid can decrypt TOTP seeds. |
| connectors have no key material | ✗ `nexus-pve` / `nexus-offsite` open the chunk store in-process with DEKs from keyd (accepted deviation, see state.md) |
| chunkstore is the only process with DEKs | ✗ scheduler, nexus-pve, nexus-offsite hold DEKs (same uid `nexus-chunkstore`); now non-dumpable |
| offsite sees only encrypted data | ✗ same as above |
| keyd is the only process with TPM access | ✓ (TPM not used yet) |
| replication: web-api never touches chunks or keys | ✓ the peer endpoint forwards to `nexus-replicad` (read-only stores, no keys, no network, own SELinux domain); the web-api crate links only the protocol types (test `web_api_never_opens_store_files`). DEK exports leave keyd only sealed to a secondary keyd. |
| per-service user, sandbox, SELinux domain | partial: scheduler + QEMU without own user/domain; see `docs/security-review.md` §2 |

## Open items
- TPM sealing of the KEK / LUKS2 (deferred by decision) — biggest residual risk (T7).
- Split the `nexus-chunkstore` uid: scheduler, nexus-pve, nexus-offsite, restore-VM QEMU each with own user + SELinux domain; keyd ACL per uid.
- Anchor the audit chain off-box (journal forwarding, HMAC/checkpoints).
- Insider at the hosting provider combined with an appliance compromise.
