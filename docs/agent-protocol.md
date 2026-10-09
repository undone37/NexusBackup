# Agent Protocol — Contract (Phase 7, Linux agent; Windows agent reuses it)

Status: v1 (2026-10-09). Plan §7.2/§7.3, §13. Decisions: agent never connects out (pull model), mTLS with an
appliance-run CA + one-time enrollment token, agent sends **plain BLAKE3** chunk hashes, the appliance maps
them to keyed chunk IDs in a local index that never leaves the appliance.

## Transport
- Agent `nexus-agent` listens on TCP **7444** (configurable), TLS 1.3 only (rustls), ALPN `nexus-agent/1`.
- After enrollment: **mutual TLS**. The agent presents its certificate (issued by the appliance CA); it accepts
  only client certificates issued by the same CA with the extended key usage clientAuth and
  `CN=nexus-appliance:<appliance-id>`. The appliance verifies the agent cert against its CA and the expected
  agent id (`CN=nexus-agent:<agent-id>`); hostnames are not used for trust.
- Framing: `u32 BE length | postcard(Message)`; max frame 8 MiB (chunk data ≤ 4 MiB + header). One request at a
  time per connection except the chunk-data stream described below. Either side closes on a malformed frame.

## Enrollment (no agent → appliance connection, no TOFU)
1. Admin creates the agent in the UI (tenant, name, host, port) → appliance creates a one-time **token**
   (128 bit, base32, 24 h, stored as sha256) and shows the install command.
2. On the host: `nexus-agent init --token <T>` writes `/etc/nexus-agent/token` (0600, sha256 only) and a
   fresh key pair; the service listens with a **self-signed** certificate in *enrollment mode*.
3. The appliance connects (TLS without cert validation, but TLS 1.3 only) and both sides prove knowledge of
   the token bound to *this* TLS session:
   `proof = HMAC-SHA256(key = token, msg = role || TLS-exporter("nexus-agent enroll", 32 bytes))`,
   `role` = `"appliance"` / `"agent"`. A man in the middle has a different exporter on each leg and cannot
   relay the proofs. The appliance sends its proof first; the agent answers with its proof and a CSR
   (`Enroll` / `EnrollReply`).
4. The appliance signs the CSR (agent id in CN, serverAuth), returns the agent cert + CA cert
   (`EnrollDone`); the agent stores them, deletes the token and switches to mTLS mode. Tokens are single use
   on both sides; 5 failed proofs → the agent stays locked until `nexus-agent init` is run again.

## Messages (crate `agent-proto`)
| Appliance → agent | Agent → appliance | Purpose |
|---|---|---|
| `Hello { version }` | `HelloReply { version, agent_id, os, kernel, hostname, agent_version, caps }` | version check (major must match) |
| `ListVolumes` | `Volumes { list: [Volume { mountpoint, device, fstype, snapshot: Lvm/Zfs/Btrfs/None }] }` | what can be snapshotted |
| `Prepare { job, paths, excludes, hooks: bool }` | `Prepared { job, snapshots: [SnapshotInfo], consistent: bool, hook_log }` | run local pre-hooks (DB dumps), create snapshots |
| `Scan { job, base: Option<BaseRef> }` | stream of `Entries { batch: [Entry] }` …, then `ScanDone { stats }` | walk the snapshot; chunk changed files with FastCDC (128/512/4096 KiB) and hash chunks with plain BLAKE3 |
| `Want { job, hashes: [Hash] }` | stream of `Chunk { hash, data }` …, then `WantDone` | appliance asks only for chunks it does not have |
| `Release { job, success }` | `Released { job, hook_log }` | drop snapshots, run post-hooks, on success commit the agent's metadata cache for `base` |
| `RestoreBegin { job, target, overwrite: Never/IfOlder/Always, confirm }` | `RestoreReady` / `Error` | restore to a path; `confirm` = token the admin typed in the UI, echoed in the agent's journal |
| `RestoreEntries { batch }`, `RestoreChunk { hash, data }`, `RestoreEnd` | `RestoreDone { stats }` | write files below `target` only (no `..`, no following symlinks: `openat2(RESOLVE_BENEATH)`) |
| `Update { version, binary, signature }` | `UpdateDone` / `Error` | self-update; signature = cosign blob signature with the pinned release key |
| — | `Error { code, message }` | any request may fail |

`Entry { path (bytes, relative to the volume root), kind (File/Dir/Symlink/Hardlink/Device/Fifo/Socket), mode,
uid, gid, size, mtime_ns, ctime_ns, inode, link_target, xattrs: [(name, value)], chunks: [(Hash, len)],
unchanged: bool, inconsistent: bool }`. With `base`, files whose (size, mtime_ns, ctime_ns, inode) match the
agent's metadata cache are sent with `unchanged = true` and the cached chunk list, without reading them.
`inconsistent = true` marks files that changed while read in fallback mode (no snapshot).

## Security properties (must hold)
- The appliance **cannot execute arbitrary commands** on the host: hooks are configured only locally in
  `/etc/nexus-agent/hooks.d/` (root-owned, 0700); the appliance can only ask "run the configured hooks".
- Data-modifying operations: only restore-to-path with a UI confirmation token, and signed self-update.
- The agent holds **no tenant key material**; it learns nothing about other hosts' data. Chunk data on the
  wire is protected by TLS; at rest on the appliance by the normal sealed chunk format.
- Plain BLAKE3 hashes are stored only in the appliance's local mapping index (`<store>/agent-map.db`), never
  offsite. The appliance verifies every received chunk: `blake3(data) == hash` before mapping/inserting.
- Limits: frame size, entries per batch (≤ 10 000), path length (≤ 4096), xattr size (≤ 64 KiB), chunk size
  (≤ 4 MiB); violations close the connection.

## Appliance side
- Source kind `linux` (catalog migration): config `{agent_id, host, port, paths, excludes, hooks}`; enrollment
  state per agent (`agents` table: id, tenant, name, host, port, cert fingerprint, enrolled_at, token_hash,
  token_expires, last_seen, version).
- Snapshot index: new `Index::Tree { entries }` (postcard variant appended → old data still decodes) holding
  the full `Entry` metadata with keyed chunk IDs; source name `host-<agent_id>`.
- Job kinds: `backup` (group guests = agent ids), `restore_files` {source, time, paths, target, overwrite,
  confirm}, `agent_update` {agent_id}.
