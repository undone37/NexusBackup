# Architecture Decision Records

Each record: context → decision → consequences. Full rationale in `plan.md` §2.
Status of all records below: **Accepted (2026-10-08)**.

## ADR-001 Own chunk store in Rust
- **Context:** Borg is a client-only CLI tool with single-writer locking and an unstable 2.0 format; PBS is AGPL and Proxmox-specific.
- **Decision:** Build our own chunk store (`crates/chunkstore`); PBS crates may be reused (see ADR-010).
- **Consequences:** We own the on-disk format and its compatibility.

## ADR-002 Rust for data plane and control plane
- **Decision:** Rust only in the core; Perl only for the PVE on-node plugin.
- **Consequences:** Memory safety, C-level throughput; longer compile times, smaller hiring pool.

## ADR-003 Pull model
- **Decision:** The appliance initiates every connection; one inbound port (management).
- **Consequences:** Sources cannot reach backups; the appliance becomes a tier-0 asset (see threat model).

## ADR-004 SELinux, bootc image-based OS
- **Decision:** AlmaLinux/CentOS Stream bootc image, SELinux enforcing, one domain per service.

## ADR-005 SQLite (WAL) catalog
- **Decision:** Catalog holds sources, policies, snapshots, jobs, users. File metadata stays in dynamic indexes.

## ADR-006 Mark-and-sweep GC with grace period
- **Decision:** No reference counting. Dedup hits bump chunk mtime; sweep deletes only unmarked chunks older than the grace period (default 24 h), re-checked under a lock. Any unreadable manifest/index aborts GC. Deleting more than 20 % of chunks requires quorum approval.
- **Consequences:** A backup must commit within the grace period.

## ADR-007 Chunking
- **Decision:** Fixed 4 MiB chunks for block devices (dirty-bitmap aligned); FastCDC 128 KiB / 512 KiB / 4 MiB for files.

## ADR-008 Keyed chunk IDs, no cross-tenant dedup
- **Decision:** Chunk ID = BLAKE3 keyed hash with a key derived from the tenant DEK and key version.
- **Consequences:** The storage provider cannot fingerprint known files. A DEK rotation means new chunks do not dedup against chunks from before the rotation.

## ADR-009 XChaCha20-Poly1305, envelope keys, dedup → compress → encrypt
- **Decision:** One sealed blob format for chunks, indexes and manifests: `NXB1 | flags | key_version | 24-byte nonce | ciphertext+tag`, zstd before encryption (only if smaller). AAD binds header, tenant and context (chunk ID / index path). DEK is wrapped by the KEK (TPM) and the KEK by the offline recovery key.
- **Consequences:** No nonce-exhaustion limits per key; every read is a full integrity check.

## ADR-010 License AGPL-3.0
- **Decision:** AGPL-3.0-only for the whole repository.
- **Consequences:** PBS / Proxmox crates can be reused; modified network deployments must publish their source.

## ADR-011 Compliance clock
- **Decision:** Retention locks use a clock that advances with the monotonic clock, is persisted, and slews forward toward system time by at most 0.1 % of elapsed time (calibration knob `clock_slew`, `chunkstore::clock::DEFAULT_SLEW`). Backward jumps are ignored.
- **Consequences:** Manipulating system time cannot expire locks early (at most +0.1 %, ≈ 20 min over a 14-day lock); after downtime locks last longer, never shorter. Upgrade path: TPM NV counter as a hardware anchor.
- **Change (Phase 18, 2026-10-12):** the slew was 1 % (≈ 3.4 h over 14 days); lowered to 0.1 % after the Cohesity comparison (≈ 10 min / 14 days there). The clock only advances while a process holds it: the scheduler now keeps every tenant's clock open (one shared instance per store and process) instead of each short-lived job re-reading the persisted value, which lost the time between jobs. A lag after downtime catches up 10× slower than before (1 h of downtime ≈ 6 weeks); this only lengthens locks. The scheduler raises `clock_skew` (warning > 60 s, critical > 10 min) when system time jumps while it runs or moves back, info for a lag found at start; nexus-diag check `time.compliance`.

## ADR-012 Commit protocol
- **Decision:** Chunk files are written as tmp + fsync + rename. At commit, chunk directories are fsynced, then indexes, then the manifest (atomic rename). A snapshot exists if and only if its manifest exists.
- **Consequences:** kill -9 / power loss leaves only orphan chunks and tmp files, which GC removes (covered by the `survives_kill_9` test).

## ADR-013 Boot menu password derived from the recovery key
- **Decision (Phase 18, 2026-10-12):** GRUB's superuser password (editing entries, the GRUB command line) is derived from the recovery key (HMAC-SHA256 with the label `nexus-grub-password-v1`, 20 letters; `crates/setup/src/grub.rs`), not generated and shown separately. Boot entries stay unrestricted; rescue mode masked, sulogin never forced, no initramfs shell.
- **Consequences:** No second secret to store; whoever holds the recovery key computes the password (`nexus-setup grub-password` or a Python one-liner, also off the appliance). The recovery key already opens all data and the console gate, so the derivation adds no new power to it. Rotating the GRUB password means rotating the recovery key (not available yet). HMAC instead of HKDF: the same construction for a uniformly random 32-byte key, and reproducible with Python's standard library.
