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
- **Insert path (2026-10):** the caller's thread reads the source in order; each chunk goes through a bounded queue to
  `chunk_workers` threads (`Options::chunk_workers`, 0 = `NEXUS_CHUNK_WORKERS` or min(cores, 8)) that merge
  partly dirty image chunks with the previous chunk, compute the keyed ID, dedup-check, compress, seal and write
  (`chunkstore/src/pipeline.rs`). Results are put back in chunk order, so the index is the same for any worker
  count. At most ~2 × workers + 1 chunks are in flight; the first error stops the reader and is returned. Used by
  `store_image*`, `store_file*` (files of more than one chunk) and the agent chunk transfer
  (`Store::insert_chunks_parallel`). Two workers storing the same chunk race safely: unique temp files
  (`create_new`), the rename under the chunk lock decides, the loser drops its copy and counts nothing.

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

## ADR-014 Hybrid post-quantum sealing of long-lived key material (X25519 + ML-KEM-768)
- **Context (Phase 30, docs/netbackup-comparison.md Tier 2):** three kinds of secrets rest outside the appliance under
  a public key for years: the tenant recovery escrow (`tenant-escrow.*`, offsite), replication DEK exports (stored on
  the primary, fetched by the secondary) and configuration bundles (offsite). They were X25519 sealed boxes
  (crypto_box). A copy harvested from an offsite provider today could be opened once X25519 falls to a quantum
  computer ("harvest now, decrypt later"). Chunk data is not affected: XChaCha20-Poly1305 with 256-bit keys keeps
  ~128 bits against Grover.
- **Decision:** a hybrid KEM in keyd (`crates/keyd/src/hybrid.rs`): X25519 **and** ML-KEM-768 (FIPS 203), the key is
  `BLAKE3 derive_key("NexusBackup 2026 hybrid seal X25519+ML-KEM-768 v2", x25519 shared | ML-KEM shared | ephemeral
  public | recipient X25519 public | ML-KEM ciphertext)`, payload XChaCha20-Poly1305 with a 24-byte random nonce and
  `label | header` as AAD; format `NXHYB2\0\0 | ephemeral X25519 public (32) | ML-KEM ciphertext (1088) | nonce |
  AEAD` (a version in the magic). Like X-Wing, the combiner binds both shared secrets to the ciphertext and the
  recipient, so the box stays closed while either primitive holds. The recipient's ML-KEM key pair is derived from the
  existing 32-byte X25519 secret (`BLAKE3 derive_key(<use> ml-kem-768 v1, secret)` → 64-byte seed `d | z`), so no new
  secret has to be stored, escrowed or typed: a tenant recovery key stays 16 groups of 4 hex digits.
- **Implementation:** RustCrypto `ml-kem` 0.3 (pure Rust, Apache-2.0 OR MIT, FIPS 203 final; already in the tree
  through `russh`'s `mlkem768x25519` key exchange, so `cargo deny` and the lockfile see no new crate) and
  `curve25519-dalek` 4 for the raw X25519 DH. Encapsulation uses `encapsulate_deterministic` with 32 bytes from the
  OS RNG (the `hazmat` feature; `ml-kem` 0.3 wants a `rand_core` 0.10 RNG, the workspace has 0.8). Public keys from
  the wire are validated (FIPS 203 modulus check); an all-zero X25519 shared secret is refused.
- **Where:** tenant recovery escrow (new keys; `tenant-recovery.pub` = X25519 | ML-KEM-768 encapsulation key, the
  web-api derives the ML-KEM half when it shows the key, `catalog::tenant_key::pq_public`), replication DEK exports
  (the secondary sends its hybrid key at enrollment, `keyd_pub_pq`; keyd `replica-pubkey-pq`, `export-for-pq`),
  configuration bundles (`NXCFGB2\0`, keyd publishes the hybrid key in `config-backup.pub`). Each use has its own
  label and seed context.
- **Compatibility:** every opener reads both formats (no magic = X25519 box of earlier releases). Tenant recovery
  keys set before keep their X25519-only escrow until they are replaced (the ML-KEM half needs the secret, which the
  appliance does not keep); peers enrolled before keep X25519-only exports until they enroll again; a secondary
  enrolling at a primary of an earlier release retries without the hybrid key. Bundles and escrow files written by
  this release need this release (or later) to open.
- **Not covered:** TLS (agents, replication, edge, web UI) stays X25519 until the rustls provider in use (`ring`)
  offers the X25519MLKEM768 group; `aws-lc-rs` would bring a C dependency (plan §2 pure-Rust preference; open question
  7 of the NetBackup comparison, proposal taken). On-appliance seals (catalog credentials sealed to the scheduler,
  TOTP seeds) stay as they are: they never leave the appliance. SSH to PVE/TrueNAS nodes already negotiates
  `mlkem768x25519-sha256` where both sides offer it (russh).
- **Consequences:** ~1.2 KiB more per sealed box (escrow file, export, bundle), ~1.2 KiB public keys (catalog setting,
  replication peer row); key generation and sealing take well under a millisecond.