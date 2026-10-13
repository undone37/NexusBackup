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
- Source kind `linux` (catalog v4): config `{agent_id, paths, excludes, hooks}` (endpoint and trust live in
  the agent row); per agent the `agents` table: id (16 hex, random), tenant, name, host, port, cert_sha256,
  enrolled_at, token_hash, token_expires, last_seen, version, os. A group of a linux source has
  `guests = [agent_id]`.
- Snapshot index: new `Index::Tree { entries }` (postcard variant appended → old data still decodes) holding
  the full `Entry` metadata with keyed chunk IDs; source name `host-<agent_id>`, index name `tree`.
- Job kinds: `backup` ({group_id} or {agent_id}), `restore_files` {source, time, paths, target, overwrite,
  confirm, agent_id} (source: any file snapshot of the tenant, see "Restore from any file snapshot"),
  `agent_update` {agent_id}, `agent_enroll` {agent_id}; endpoints and RBAC in docs/control-plane.md.

### Clarifications (appliance implementation, crate `agent-conn`, CLI `nexus-agentctl`)
These pin down points the message table leaves open; an agent must behave as described.
- **Token digest.** Both sides keep only `token_digest(token)` = lowercase hex SHA-256 of the trimmed token
  (`agent_proto::token_digest`), and that hex string is the `token` argument of `enroll_proof` (HMAC key).
  The appliance stores it sealed to the scheduler (`agents.token_hash` = `sealed:v1:…`, location
  `agent/<id>/token@<host>:<port>`, so a changed endpoint voids it) and clears it after enrollment.
- **Exporter**: `export_keying_material(32 bytes, label "nexus-agent enroll", context = none)`.
- **Enrollment connection**: TLS 1.3 + ALPN `nexus-agent/1`; the appliance accepts any agent certificate but
  checks the handshake signature, and offers its client certificate (an agent in enrollment mode may ignore
  it). `EnrollDone` has no answer: the appliance closes, then confirms with an mTLS `Hello` (retries 60 s).
  The fingerprint is recorded as soon as `EnrollDone` was sent (the agent has consumed its token).
- **Certificates.** Appliance CA: ECDSA P-256, `<state_dir>/agent-ca/` (`ca.key`, `client.key` 0600; created
  on first use under a lock), path length 0. Appliance client cert `CN=nexus-appliance:<appliance-id>`, EKU
  clientAuth. Agent cert: only the CSR's (self-signature-checked) public key is used; subject
  `CN=nexus-agent:<agent-id>`, EKU serverAuth, KU digitalSignature, 10 years, no SAN. The appliance verifies
  the chain to its CA, EKU serverAuth, the CN, and pins the SHA-256 of the cert recorded at enrollment
  (re-issuing needs a new token + enrollment). `HelloReply.agent_id` must equal the expected id.
- **Paths.** `Entry.path` is the path relative to the host's `/` (the volume mountpoint prefix included, not
  relative to a snapshot mount), components separated by `/`, never empty, `.`, `..`, no NUL; the root itself
  may be sent as `""`/`"."` and is ignored. `paths` in `Prepare` and restore requests are absolute.
- **Entries checked by the appliance** (violation = backup fails, nothing committed): each path once; regular
  files: chunk lengths sum to `size`, no empty chunk; other kinds carry no chunks; symlinks have a target;
  hard-link targets are valid relative paths; one hash has one length across all entries.
- **Base.** `Scan.base` = time of the newest committed `host-<agent_id>` snapshot in the appliance store (or
  none). The agent compares against the metadata cache it committed at its last `Release{success: true}`.
- **Want.** The appliance requests every hash that is not in its mapping index *or* whose mapped chunk is
  missing in the store (GC) — including hashes of `unchanged` files, so an agent must be able to deliver those
  (re-read the file). ≤ 10 000 hashes per `Want`, sorted; the agent answers with exactly the requested chunks
  (any order, each once) and `WantDone`. Unrequested, duplicate, wrong-length or hash-mismatching chunks fail
  the backup. Mapped chunks are touched against a concurrent GC before they are reused.
- **Release** is sent with `success: true` only after the snapshot commit; on any earlier failure with
  `success: false` (chunk messages still in flight are skipped while waiting for `Released`).
- **Mapping index** `<store>/agent-map.db` (SQLite, 0600, `plain → keyed, len`): written only for verified
  chunks, never uploaded offsite; losing it costs one full transfer, never correctness.
- **Restore.** After `RestoreReady` the appliance sends batches of ≤ 1000 entries; after each
  `RestoreEntries` it sends one `RestoreChunk` per chunk of that batch's regular files in entry order and
  chunk order (repeated chunks are sent again), so files can be written sequentially; then `RestoreEnd`.
  Selected paths include all parent directories (with their recorded metadata). `confirm` is the target
  agent's *name* as typed by the user (the web-api refuses anything else); `RestoreDone.stats.errors` non-empty
  fails the job. Entry chunk lists carry plain hashes (mapping index, or recomputed). A batch also ends
  before it would carry more than 100 000 chunk references (frame limit).
- **Restore from any file snapshot (Phase 15b).** The source of a restore is any file-tree snapshot of the
  tenant: `host-<agent>` (index `tree`), `nas-<source>-<dataset>` and `share-<source>` (index `tree`),
  `plugin-…` (index `files`, plus its streams below `.nexus-streams/` exactly as in the file browser), and
  VM/CT files: `nexus-pve files|ct-files <vmid> <time> get <downloads>/restore-<job>-<rand>.tar <paths>`
  (restore micro-VM / CT tar stream) writes the selection as a tar, and `nexus-agentctl restore` with
  `restore.tar` turns it into the same entry/chunk stream (`agent_conn::tarbridge`: pass 1 builds the
  entries, file data cut into 4 MiB pieces with plain BLAKE3, pass 2 re-reads the tar for each batch's data;
  regular files, directories, symlinks, hard links within the archive, FIFOs and long names; devices,
  sockets, `..` names and entries below a symlink are skipped; sparse files arrive fully allocated; the tar
  has no xattrs). The staging tar is removed by `nexus-agentctl` (and by the scheduler if the job fails).
- **Restore to another host** (target agent ≠ the snapshot's `host-<agent>`; always for nas/share/plugin/VM/CT
  sources): the appliance adapts the entries, the protocol is unchanged (works with older agents):
  `uid`/`gid` = `0xFFFFFFFF` (= -1 for `fchown`: the agent's restore user stays the owner; Windows ignores
  them), setuid/setgid/sticky bits cleared, device nodes and sockets (and FIFOs for Windows agents) skipped, xattrs kept only if the target
  can store them (`user.*` on agents with the `xattrs` capability, `win.*` on agents with `win-sd`; POSIX/NFSv4
  ACLs, `security.*` labels and `trusted.*` of the other machine are dropped), alternate data streams
  (`win.ads`) only onto Windows agents. Skipped entries and xattrs are counted in the job log
  (`restore to another host: skipped …`), not reported as errors.
- **Update.** The update directory (`/usr/share/nexus/agent`) holds `nexus-agent`, `nexus-agent.sig`,
  `nexus-agent.version`; the whole binary travels in one frame, so it must stay below 8 MiB (open: chunked
  update for bigger binaries). After `UpdateDone` the appliance reconnects (≤ 120 s) and expects the new
  version in `HelloReply`.
- **Downloads** from tree snapshots need no agent: `nexus-agentctl files <agent> <time> ls|get` (same JSON
  and tar/zip formats as VM/CT files; tar keeps owners, modes, mtimes, links, devices and xattrs as PAX
  `SCHILY.xattr.*`).
- **Consistency.** `Prepared.consistent = false` or entries with `inconsistent` → the backup is committed and
  the scheduler raises a `backup_inconsistent` warning.

## v1.1 (additive, 2026-10-09: Windows agent)
Old peers are unaffected: postcard enum tags of v1 did not move (new variants are
appended; checked by `agent-proto` tests), and v1.1 messages are only sent when the
peer announced them.
- `SnapshotKind::Vss` (appended): Windows Volume Shadow Copy (`Volumes`, `Prepared.snapshots`).
- `Writers { job }` (appliance → agent, after `Prepared`, only if `HelloReply.caps`
  contains `"vss-writers"`) → `WritersReport { job, writers: [VssWriter { name, class_id,
  instance, participated, state, failure, application }] }`: which VSS writers took part
  in the job's snapshot (`participated` = not excluded by `vss_exclude_writers`;
  `failure` = HRESULT text if the writer failed; `application` = SQL Server / Exchange /
  AD writer). The same information is always in `Prepared.hook_log` as text.
  **Open (appliance):** `agent-conn` does not request `Writers` yet; the job log shows
  the `hook_log` summary, and `consistent = false` already raises `backup_inconsistent`
  when an application writer failed.
- Windows path and metadata conventions (`Entry.path` = `C/Users/x`, request paths
  `/C/Users/x`, xattrs `win.sd`, `win.attrs`, `win.created`, `win.reparse`, `win.ads`,
  ADS as entries `<path>:<stream>`): docs/agent-windows.md.
- Shared implementation: both agents use `crates/agent-core` (session state machine,
  enrollment, chunking, cache, restore stream, update checks); the agent metadata cache
  is format 2 (adds per-volume change-journal marks; format 1 still loads).

## v1.2 — LZ4 on the wire (additive, 2026-10-10)
- The agent advertises capability `lz4` in `HelloReply.caps` (all agents built on `agent-core`).
- The appliance then asks with `WantLz4 { job, hashes }` instead of `Want`. For each chunk the agent tries one
  LZ4 block compression (`lz4_flex`, pure Rust, one extra buffer of ≤ 4 MiB at a time) and sends
  `ChunkLz4 { hash, raw_len, data }` if that saves at least 10 %, else the usual `Chunk` (already compressed or
  encrypted data costs only the attempt).
- Restore: the appliance sends `RestoreChunkLz4 { hash, raw_len, data }` the same way if the agent advertised `lz4`.
- Receivers decompress with the output size fixed by `raw_len` (frame check: `raw_len` and `data` ≤ MAX_CHUNK), then
  verify the BLAKE3 hash of the decompressed data as before. A `ChunkLz4` that was not asked for is refused.
- Old peers never see the new messages (variants appended; negotiation by capability). Storage is unaffected: chunks are
  stored zstd-compressed and sealed exactly as before.

## v1.3 — filters, limits, certificate renewal (additive, Phase 15e/f)
Old peers are unaffected: the variants are appended after `RestoreChunkLz4` (tags 31–35, checked by
`agent-proto` tests; an old appliance's `Prepare` decodes unchanged) and are only sent when the agent announced them.
All agents built on `agent-core` announce both capabilities.

- **Capability `prepare2`** → the appliance sends `PrepareEx { job, paths, excludes, hooks, filters, limits }`
  instead of `Prepare` (answered with `Prepared` as before):
  - `Filters { include, exclude_regex, cross_mounts, skip_fstypes }` (limits: ≤ 256 entries each, ≤ 4096 bytes each).
    The agent compiles them once (`agent_core::filter`, regex size limit 1 MiB) and refuses invalid ones with
    `Error 400` before anything is snapshotted. Selection rules ("Filters"): an entry matched by a glob or a regex
    (absolute host path, `/`-separated; Windows `/C/…`, case-insensitive) is skipped and not descended; with
    include roots, only entries inside a root are taken and the directories leading to a root are kept but filtered;
    **exclusion wins** over inclusion. `cross_mounts` (Linux): data file systems mounted below the requested paths
    become roots of their own (own snapshot), except types in `skip_fstypes` (empty = the default list in
    `agent_core::filter::DEFAULT_SKIP_FSTYPES`) and except mounts at or below an excluded directory; skipped network
    and data file systems are named in `Prepared.hook_log`. The NAS connector applies the same `Filter` to share
    paths (`/` = share root).
  - `Limits { bwlimit, nice }`: `bwlimit` bytes/s is a token bucket (one second of burst) on the chunk data the agent
    sends for `Want`/`WantLz4` (wire bytes); `nice` 1–19 lowers the session thread's priority for the rest of the
    connection, only ever downwards (Linux: `setpriority` on the thread to max(current, nice) — the unit already runs
    with `Nice=10` and best-effort 7 — and from 15 on `ioprio_set` idle class, inherited by hooks; Windows:
    `THREAD_MODE_BACKGROUND_BEGIN`). The agent reports what it did in `Prepared.hook_log`.
  - Agents without `prepare2` get `Prepare` with the globs only; `nexus-agentctl` logs "this agent version ignores …"
    for every non-empty filter / limit.
- **Capability `cert-renew`** → certificate renewal over the established mTLS session:
  `RenewCert` → the agent generates a **new** key pair (kept in memory) and answers `RenewCsr { csr_pem }`; the
  appliance signs it exactly like at enrollment (same CN `nexus-agent:<id>`, serverAuth, same CA, 10 years) and
  prints `renew-issued {json}` (the scheduler stores the fingerprint as `agents.cert_sha256_next`, a second accepted
  pin); then `RenewDone { cert_pem, ca_pem }` → the agent checks that the certificate is for its new key, names its
  id and is signed by the CA it **already trusts** (a different CA is refused), writes `agent.key.new` and
  `agent.crt.new` (the certificate last marks a complete pair), renames key then certificate, switches new
  connections to the new identity and answers `RenewOk`. A crash during the swap is rolled forward (certificate
  present) or back (only the key) at the next start (`config::finish_identity_swap`). The appliance confirms with a
  session pinned to the new fingerprint only (`renewed {json}`).
- Every mTLS session prints `agent-cert {"agent_id", "cert_sha256", "not_before", "not_after"}` for the certificate
  the agent presented: the scheduler keeps `agents.cert_issued` / `cert_expires` current and promotes
  `cert_sha256_next` when the agent presents it (renewal interrupted after the swap). Automatic renewal: when less
  than 30 days or 10 % of the lifetime are left (job `agent_renew`, `auto: true`; a failed one is retried after a
  day); "Renew certificate now" queues the same job. Audit `agent.cert_renewed`; the `cert_expiry:agent:<id>` alert
  is resolved.
- **Re-enrollment** keeps the agent id: a new token for an existing agent (`POST /agents/{id}/token`), `nexus-agent
  init` on the host, the usual enrollment; the scheduler replaces the pin and clears the renewal state.

## v1.4 — endpoint status (additive, Phase 24a)
Appended after `RenewOk` (tags 36–39, checked by `agent-proto` tests); sent only to agents announcing **capability
`poll`** (all agents built on `agent-core`). Older agents keep working: the appliance only opens the session and
says `Hello` (reachability, version, OS).

- `SessionSummary { summary, status }` → `SummaryAck { job }`: after a backup or file restore of the agent the
  scheduler stores one `Summary { job, kind: Backup|Restore, started, ended, result: Success|Warning|Failed|Cancelled,
  read_bytes, transferred_bytes, new_bytes, warnings, first_error, snapshot_time, log_tail }` (catalog
  `agent_sessions`; `log_tail` = the agent's part of the job log, ≤ 200 lines of ≤ 1 KiB) and delivers it with the
  next poll session (oldest first, ≤ 20 per session) until acknowledged. The agent keeps the newest 100 (by end
  time, one per job) in `<state>/ui-state.json` (root only).
- `Poll { status, ack }` → `PollReply { requests, power, policy_version, busy }`: every 2 minutes per enrolled agent
  of an active tenant (`nexus-agentctl <cfg> poll`, one process for all due agents, ≤ 8 sessions at once, 20 s I/O
  timeout; backoff 4, 8, 15 minutes while unreachable). `status = ApplianceStatus { appliance, now, next_run,
  ui_policy: UiPolicy { accent, header, hide_backup_now, hide_tray }, policy_version }` (also part of every
  `SessionSummary`). `requests` = "back up now" requests queued by local users (`BackupRequest { id ≤ 64 hex,
  queued_at }`, ≤ 16); the agent keeps each until an `ack` names it (or 7 days), so a scheduler restart between
  queueing and acknowledging repeats it — the scheduler deduplicates by id (jobs carry `request_id`). `power =
  PowerState { on_battery, battery_percent, metered, network_name }` (each optional = unknown). `busy` = a backup
  session is active on the agent.
- Limits (receiver-checked): `log_tail` ≤ 200 lines, lines and `first_error` ≤ 1024 bytes, `appliance` / `header` ≤
  256 bytes, `accent` ≤ 16, `ack` / `requests` ≤ 16 entries with ids ≤ 64 bytes, `network_name` ≤ 256 bytes.
- Output of `nexus-agentctl … poll`: one line `poll {"agent_id", "ok", "error"?, "info", "poll", "delivered":
  [job…], "requests": [{id, queued_at}], "power", "policy_version", "busy"}` per agent (request ids other than hex
  are dropped). The scheduler records `agents.reachable / last_poll / last_seen / poll_failures / power /
  ui_policy_seen`, marks summaries delivered, queues one backup per group of the agent for a new request
  (`requested_by = agent:<id>`, params `{group_id, guests: [id], request_id}`; at most one per 10 minutes; audit
  `agent.request_backup` with actor `agent:<id>`) and acknowledges it in the next poll. Laptop policies
  (`agents.laptop`) and missed runs: docs/endpoint-ui.md.

Local side (agent ↔ endpoint UIs): crate `agent-ui-proto`, docs/endpoint-ui.md "Local IPC". Nothing on the local
socket reaches the appliance except the requests above; it cannot change configuration, start a restore or read
backup data.

## v1.5 — fleet enrollment (additive, Phase 24d)
Pre-installed agents (GPO / Intune / Ansible) are initialised with a reusable, time-limited **fleet secret**
instead of a per-host token; the appliance finds them by scanning admin-defined address ranges. Appended variants
(tags 40–41, after v1.4's 36–39). No capability: the messages are sent in enrollment
mode, before any `Hello`: `FleetProbe { fleet_id, proof }`, `FleetInfo { proof, hostname, os, agent_version }`.

- Secret `nxf1.<fleet id: 16 hex>.<26 base32>`, created by an admin (expiry ≤ 30 days, optional maximum number of
  uses, optional `auto_accept`, agent port, ranges: IPv4 CIDR /22../32, IPv6 /118../128, addresses, host names;
  ≤ 32 entries, ≤ 4096 addresses), shown once. The appliance keeps `token_digest(secret)` sealed to the scheduler
  (`fleets.secret_hash`, location `fleet/<id>`). The fleet id is not secret: it only lets an agent tell fleets apart.
- Agent: `nexus-agent init --fleet-secret -` (stdin), MSI `FLEETSECRET=…` (custom action, `MsiHiddenProperties`),
  or a package deployment's `/etc/nexus-agent/fleet-secret` (adopted and deleted at the next start; the unit starts
  when it exists). The agent stores the digest as `token` plus the fleet id (`fleet`) and is in enrollment mode
  ("awaiting fleet enrollment"). `init --fleet-secret` refuses an enrolled agent (re-enrollment needs a token).
- Scan (`nexus-agentctl fleet-scan`, job `fleet_scan`, every 15 minutes per usable fleet, at most 8 connections at
  a time and 20 per second, 2 s timeout, only the fleet port; the firewall allows exactly these addresses and port
  while the fleet is usable): enrollment-mode TLS as above, then `FleetProbe` with
  `proof = HMAC(digest, "fleet-appliance" || exporter)`. The agent answers `Error 401` without counting a failed
  proof when it is not in this fleet (token-initialised agents included; agents before v1.5 cannot decode the
  message and close the connection); a wrong proof for its own fleet counts like a failed enrollment proof (lock
  after 5). Otherwise it answers `FleetInfo` with `proof = HMAC(digest, "fleet-agent" || exporter)` and its host
  info — never before the appliance proved the secret, and the secret itself never crosses the wire. Distinct roles
  keep probe proofs from passing as enrollment proofs. Output: `fleet-agent {"host","port","hostname","os","version"}`
  (control characters stripped, 128 characters each).
- Candidates (`fleet_candidates`, unique per fleet + endpoint, a decision sticks across scans) are accepted by an
  admin or tenant admin of the fleet's tenant, or automatically (`auto_accept`): agent row (host = scanned address,
  `agents.fleet_id`), a linux source + protection group copied from the template group of the first matching
  hostname rule (else the fleet's default group), job `agent_enroll {agent_id, fleet_id}`, one use counted. That job
  is the normal enrollment with the fleet digest in place of the token digest (revoked or expired fleets enroll
  nobody; the use limit only gates new acceptances). Audit `fleet.create`, `fleet.revoke`, `fleet.accept`,
  `fleet.auto_accept`, `fleet.reject`.
- Trust: anyone holding the secret can run an agent that waits for acceptance (docs/threat-model.md); expiry,
  maximum uses, the scanned ranges, manual acceptance by default and revocation bound that.
