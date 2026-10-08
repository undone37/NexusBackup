# Project State

_Last updated: 2026-10-08_

## Decisions (see plan.md §2, docs/adr.md)
- License AGPL-3.0 · AEAD XChaCha20-Poly1305 · git + GitHub Actions
- Session scope: Phase 0 + Phase 1 chunk store core (toward M1)

## Done
- [x] Questions answered, recorded in plan.md
- [x] git repo (branch `main`, **nothing committed yet**), Cargo workspace, LICENSE (AGPL-3.0), rustfmt.toml
- [x] CI `.github/workflows/ci.yml`: fmt, clippy `-D warnings`, tests, cargo-audit
- [x] `docs/adr.md` (ADR-001…012), `docs/threat-model.md` (T1…T11)
- [x] `crates/chunkstore`
  - `crypto.rs`: keyed BLAKE3 chunk IDs, sealed blob format (zstd + XChaCha20-Poly1305, AAD = header|tenant|context), DEK versions/rotation, key wrap/unwrap
  - `clock.rs`: compliance clock (monotonic, ≤1 % forward slew, ignores backward jumps, persisted)
  - `store.rs`: one file per chunk, fixed + dynamic index, FastCDC file chunking, manifests, commit protocol, retention locks (extend-only, delete blocked), mark-and-sweep GC (grace period, quorum valve at 20 %, abort on unreadable metadata), verify (missing + corrupt, selectable subset), keyring check, name validation
- [x] Tests: 13 passing (`cargo test`), including `survives_kill_9` (6× SIGKILL during writes, then restore + GC + verify); clippy clean

## M1 status
Chunk store ingests and restores synthetic block and file data with dedup, encryption, GC and locks, and survives kill -9 tests. **Still missing for M1:** `keyd` (TPM), power-loss simulation (beyond kill -9).

## Next
- [ ] Initial commit (waiting for user OK)
- [ ] `keyd`: TPM sealing of KEK (tss-esapi, test with swtpm), recovery-key first-boot flow, Unix socket to chunkstore
- [ ] Power-loss test (e.g. dm-flakey or QEMU VM hard reset)
- [ ] Incremental fixed index from a dirty bitmap (needed in Phase 2)
- [ ] OS image skeleton (bootc Containerfile, SELinux, LUKS/TPM)

## Deferred (with reason)
- Bloom filter / separate dedup index: the filesystem path is the local dedup index; add when stat lookups become the bottleneck
- Single global chunk lock: per-prefix locks if contention shows
- Fsync per new chunk file (dir fsync is batched at commit): batch file syncs if HDD throughput suffers
- GFS retention classification: belongs to the scheduler (Phase 5)
- Offsite/verify status: catalog, not the immutable manifest
