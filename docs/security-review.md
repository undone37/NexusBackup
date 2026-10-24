# Internal Security Review (Phase 6)

Date: 2026-10-09 · Basis: `main` at 322084d (M5) plus the fixes listed here.
Scope: plan.md §3.3, §4.2, §13, §14; `docs/threat-model.md` (updated to v0.2),
`docs/control-plane.md`, `docs/pve-connector.md`, the Rust workspace, the PVE
plugin and `os/`. The external test is scoped in `docs/pentest-scope.md`.

Method: fuzzing of every network-facing parser (§1), a threat-by-threat
walk-through mapping each mitigation to code (§2), focused reviews (§3), and
supply-chain checks (§5). Findings are classified critical / high / medium /
low / info. Critical and high findings were fixed where that was possible
without design changes; each fix is a separate commit with a regression test.
The rest are listed with recommendations (§4).

**Summary**
- No critical findings.
- **6 high:**
  - 4 fixed: H-F1 zip slip in file-restore downloads; H-F2 and H-F3, two root-on-node paths in the PVE plugin; H-2 plaintext secrets in the catalog (fixed after the review, see §4).
  - 2 open design items, both already known deferrals: H-1 file-based KEK; H-3 one uid shared by scheduler, CLIs and QEMU.
- **Medium:** 12 fixed (M-5 after the review), 6 open.
- Fuzzing found 5 distinct crash classes and 1 logic flaw. All are fixed with regression tests.

---

## 1. Fuzzing

### 1.1 Targets

The targets are cargo-fuzz (libFuzzer) crates under `crates/<crate>/fuzz/`. Each crate has its own workspace, so the main workspace stays on stable.

| Crate / target | Input = attacker | Invariants checked (besides "no panic") |
|---|---|---|
| `nbd/nbd_client` | Everything a hostile NBD server (PVE node, SSH stdio) sends. Selector byte for meta contexts. | Block-status extents stay inside the export. Reads and seeks are safe. |
| `nbd/nbd_server` | Everything a hostile NBD client (node during restore / IR) sends. | Never reads outside the export. |
| `chunkstore/sealed_open` | Arbitrary sealed blobs (box, disk). | Random input never authenticates. Honest blobs round-trip. Any bit flip or context change is rejected. Key wrap round-trip. |
| `chunkstore/meta_decode` | postcard `Manifest` / `Index` / `FileEntry` bytes. | Decode → encode → decode is stable. |
| `offsite/pack_parse` | Pack bytes from the box, **plus** authentic packs whose sealed index plaintext comes from the fuzzer. | `parse` only returns entries inside the pack. Footer and id handling. |
| `offsite/hostile_box` | A whole in-memory Storage Box (listings, sizes that lie, packs, manifests, indexes, extra files), against a store that has a local snapshot. Runs `rebuild_from_remote`, `check_inventory`, `verify_sample`, `restore`, `gc`. | The local snapshot survives. Nothing is written outside `store/` and `state/{packs,snapshots}`. |
| `pve/ct_records` | Container record stream (`C`/`D`/`E`) from a node / CT, into a fresh store. | Never more payload than input. |
| `pve/tar_files` | Tar stream from a hostile CT or restore VM, run through `files::list` and `files::extract` to tar and zip. | The download contains no `..`, absolute or NUL names, no unsafe hard-link targets, and no entry below a symlink entry. |
| `pve/agent_frames` | Appliance side of the micro-VM protocol: tar frames + JSON response lines. | Frame sizes are bounded. Responses parse safely. |
| `pve/agent_request` | Guest-side agent (`restore-vm/agent`, included by path): request lines, path resolution, framing writer. | Resolved paths are mountpoint + plain components only. Framing round-trips. |
| `keyd/keyd_request` | keyd socket request lines (`<t>`, `ensure <t>`, `escrow <t>`, ≤128 bytes) against a fresh keyd dir, plus the escrow-answer decoder. | Nothing is created outside `tenants/<valid>/`. DEK answers are whole 36-byte records. Escrow only returns `kek.recovery` + this tenant's DEKs. |
| `web-api/validators` | Name / schedule / source / path / host / role / GFS validators. | Accepted values keep the properties the other components rely on. |
| `web-api/api_router` | The whole axum router: method × path × body × {anonymous, admin, SO, operator, tenant_user, scoped operator}. | No 5xx. Anonymous callers never get past auth on `/api/v1`. The audit chain verifies. |
| `replication/hostile_primary` | Everything a hostile primary sends to a secondary: HTTP/1.1 heads, Content-Length and chunked bodies on one keep-alive connection, the JSON answers, the chunk frames (docs/replication.md). | Bodies stay within the requested limit; frames return only the requested id and at most `MAX_CHUNK` bytes. |

### 1.2 How to run

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
lab/fuzz/run.sh [SECONDS=600] [PARALLEL=4] [crate:target ...]
# e.g. lab/fuzz/run.sh 1200 7                  # all 13 targets, 20 min each, 7 at a time
#      lab/fuzz/run.sh 300 1 offsite:hostile_box
#      SANITIZER=address lab/fuzz/run.sh 600 2 # with ASan (slower, ~3x memory)
```

- **Seeds:** `lab/fuzz/mkseeds.py` writes protocol-shaped seeds (from the tests and specs) to `crates/<c>/fuzz/seeds/<t>`. The offsite seeds come from a real upload (`crates/offsite/fuzz/examples/mkseed.rs`).
- **Corpora:** they grow in `crates/<c>/fuzz/corpus/<t>` (git-ignored).
- **Crashes and logs:** crashes land in `crates/<c>/fuzz/artifacts/<t>`, logs in `target/fuzz-logs/<t>.log`.
- **Reproducing a crash:** `cd crates/<c> && cargo +nightly fuzz run -s none <t> fuzz/artifacts/<t>/crash-…`.
- **Build flags:** the default build has debug assertions and overflow checks but no ASan (`-s none`). The fuzzed code contains no `unsafe`, and the build machine had little free memory.
- **CI recommendation:** a nightly job running `lab/fuzz/run.sh 300 2` with ASan, keeping the corpora as artefacts.

### 1.3 Results

The campaign on 2026-10-09 had three parts:
- smoke rounds of 20 s and 60 s per target;
- a main run of 20 min per target (13 targets, 7 in parallel on 16 threads);
- re-runs after the fixes.

The main run used the final code, with all fixes applied: 13 targets × 20 min, about 4.3 CPU-hours in total. No crash, leak or OOM remains.

| Target | Execs (20 min) | Target | Execs (20 min) |
|---|---|---|---|
| nbd_client | 103.1 M | ct_records | 2.6 M |
| nbd_server | 25.9 M | tar_files | 6.5 M |
| sealed_open | 13.2 M | agent_frames | 17.3 M |
| meta_decode | 124.3 M | agent_request | 10.2 M |
| pack_parse | 18.2 M | keyd_request | 12.4 M |
| hostile_box | 1.7 M | validators | 182.2 M |
| api_router | 36.9 M | | |

Total: about 555 M executions.

One run hit 4 simultaneous "timeouts" (keyd_request, api_router, agent_request, tar_files) while the machine was stalled by a parallel workspace build:
- each artefact re-executes in ≤1 ms;
- all 4 targets were re-run for the full 20 min with `TIMEOUT=60`, cleanly;
- their numbers above are from that re-run.

**Crashes found and fixed.** Each fix is a separate commit with a regression test.

| # | Target | Crash | Impact | Fix (commit) |
|---|---|---|---|---|
| 1 | nbd_client | `size - last.0` underflow and unbounded extents when a server overshoots the block-status range; `at + len` overflow on a read chunk offset | A hostile node aborts the backup job. In release builds the overflow wraps, so extents beyond the export could reach `store_image_extents`. | Clip extents to the requested range; `checked_add` (7dcd4ed) |
| 2 | pack_parse / hostile_box | `remote_path` slices `&id[..2]` on foreign names in a box listing; `size - FOOTER - ilen` underflow on a lying footer | A malicious box crashes `check` and `dr` | Pack ids must be 32 hex in their own prefix dir, footers are range-checked and capped (2beeae3) |
| 3 | tar_files | `../../etc/cron.d/x`, `lnk -> /etc` + `lnk/passwd`, and hard links to `../` were copied into the user's tar/zip download (**H-F1**, zip slip) | A compromised CT or restore VM plants files outside the extraction dir on the admin's machine | `files::Guard` drops them (fa0354a) |
| 4 | agent_frames | `v["ok"]` IndexMut on a non-object agent response | A compromised agent crashes nexus-pve | `parse_response` requires an object (60bb445) |
| 5 | tar_files (2nd round) | NUL bytes in GNU long names reached zip names | Extractors truncate the name | Dropped (63ad430) |
| 6 | hostile_box (review of the target) | `rebuild_from_remote` copied every `*.idx` listed next to a manifest into the local state, unauthenticated | A box makes local restores fail and pollutes the state | Only the indexes named by the authenticated manifest are kept, and each is verified (2beeae3) |

---

## 2. Threat walk-through (T1–T13) and process isolation

Code references are to this repository. "Gap" lists what is missing or only partly true.

**T1 – ransomware on a source**
- Pull model: there is no inbound data port, and the node never connects to the appliance (`pve-plugin/PVE/Storage/Custom/NexusBackupPlugin.pm` header).
- The node helper only runs an allow-listed command set, with anchored regexes per argument and no shell (`pve-plugin/helper`, dispatch at the end, regexes at the top). `authorized_keys` uses `restrict,command=` and is owned by root (`pve-plugin/build-deb.sh`).
- **Gap:** there is no change-rate anomaly alert yet (planned).

**T2 – compromised admin**
- Locks are enforced in the store: `Store::extend_lock` only grows, and `delete_snapshot` refuses while the compliance clock is before `lock_until` (`crates/chunkstore/src/store.rs`).
- Quorum (`crates/web-api/src/quorum.rs`, `resources.rs`) covers:
  - every delete;
  - weakening a policy, including moving a group to a weaker policy;
  - **changing an existing tenant offsite target** (new);
  - privileged account creation, re-enable, demote, disable-last and credential resets.
- Approvals of objects that changed after the request are refused (new). The GC valve is at 20 % (`Store::gc`, scheduler quorum).
- Approvals are optional (plan §2, 2026-10-10; `crates/web-api/src/approvals.rs`, catalog v9 `settings.approvals_enabled`):
  - approvers are admins and security officers, never the requester;
  - enabling is immediate; disabling is a quorum request `approvals.disable` (requester + one other approver);
  - with approvals enabled, a user change that would leave fewer than two possible approvers (enabled, activated admins / security officers) is refused, and enabling needs a second possible approver (no deadlock);
  - disabled: gated actions execute directly, audited with `"approvals": "disabled"`; a GC over the valve waits for an explicit admin confirmation (`POST /gc/approve-large`, honoured by the scheduler only while approvals are still disabled); replication DEK exports run on the admin's request (the scheduler accepts a self-decided export only while approvals are disabled).
- Self-enrollment (`crates/web-api/src/activation.rs`): admins create accounts without credentials and get a one-time activation code (128 bit, 72 h, SHA-256 digest stored). For admin / security officer accounts with approvals enabled the code is split: part 1 to the requesting admin, part 2 to the approver; neither alone activates. An account waiting for activation with a code one admin knows cannot be promoted / enabled as privileged while approvals are enabled.
- The audit chain is in `crates/catalog/src/lib.rs`. The RBAC matrix and audit completeness are checked by the test `rbac_matrix_and_audit_completeness`.
- **Gaps:**
  - M-6: an admin can stop *future* backups by removing guests or breaking a source. There is no quorum for this; it is only detected by the failed-job and lag alerts.
  - ~~M-5~~ fixed: every password / TOTP change (own or another user's) needs the actor's current password and a fresh TOTP code.
  - M-1: the audit chain is not anchored off-box.
  - **Accepted residual (user decision 2026-10-10):** with approvals disabled — the default for a single administrator — one admin can weaken policies, delete configuration, confirm a large GC and export DEKs to a replication peer. Retention locks still protect existing snapshots; everything is audited; the dashboard recommends enabling approvals once two people could approve. Accounts created while approvals were off were provisioned by one admin.

**T3 – time manipulation**
- `crates/chunkstore/src/clock.rs`: bounded forward slew, backward jumps ignored, persisted, and **non-finite values refused** (new). chrony is NTS-only with `minsources 2` (`os/chrony.conf`).
- **Gap (M-3):** a deleted clock file trusts system time again once.

**T4 – passive box compromise**
- Keyed BLAKE3 chunk ids (`crypto.rs` `TenantKey::from_dek` with derive-key contexts `NexusBackup 2026 chunk-id v1` / `aead v1`).
- XChaCha20-Poly1305 with random 192-bit nonces. The AAD is the header, tenant, NUL and context (`chunk id` / `manifest:<src>/<t>` / `index:<src>/<t>/<name>` / `pack:<id>`). Pack file names are random.
- **Residual (info):** compressing before encrypting leaks sizes.

**T5 – box deletion**
- Box snapshots are external. Inventory monitoring is in `Target::check_inventory`, and foreign names are now reported as unknown.

**T6 – compromised appliance**
- PVE TLS is pinned to the cluster CA (`crates/pve/src/api.rs`). SSH host keys are pinned with `StrictHostKeyChecking=yes` (`backup.rs`). The offsite host key is pinned, with no TOFU (`offsite/src/sftp.rs`).
- nftables default-deny in and out (`os/nftables.conf`). sshd is disabled and root is locked (`os/Containerfile`, preset).
- **Gaps:**
  - H-2 (fixed): source/offsite secrets are sealed to the scheduler, TOTP seeds encrypted with a web-api key; residual risk in §4.
  - H-3: shared uid.
  - M-2: the egress sets are never populated.
  - M-7: the lab PVE token is broader than needed.

**T7 – theft**
- **Gap (H-1):** the KEK is a 0600 file (`crates/keyd/src/lib.rs` `seal`). TPM and LUKS are deferred by decision, so disk theft exposes everything.

**T8 – tampering / bit rot**
- `Keyring::open_chunk` re-derives the keyed hash on every read. `Store::verify`, `Target::verify_sample`, and `insert_chunk_raw` all verify before accepting.

**T9 – crash**
- Commit protocol and `syncfs` at open. Tested by `survives_kill_9` and the power-loss test.

**T10 – malicious peers and content**
- Fuzzing (§1). The micro-VM has no NIC, uses `-sandbox`, has read-only disks, and the agent uses `openat2(RESOLVE_IN_ROOT)` (`restore-vm/agent`). Download sanitizing is new.
- **Gaps:**
  - H-3: QEMU runs as the scheduler uid.
  - M-4: restored disks are parsed by the node kernel.
  - L-2: memory DoS.

**T11 – names**
- `check_name` in the store. `validate::name` in the API. `safe_name` / `valid_id` for box listings (new).

**T12 – active malicious box**
- Every artefact is authenticated before use. Only manifest-named indexes are kept. Listings are validated. Fuzzed by `hostile_box`.

**T13 – helper key or appliance → node root**
- New:
  - the state dir is sticky;
  - root task-log writes are hardened;
  - root-only config keys are dropped on restore;
  - the CT staging dir is validated.
- **Gaps:** M-4; and L-8: DoS via predictable names, no `from=`, no taint mode in the helper.

### Process isolation (plan §4.2)

| Process | User | Sandbox (unit in `os/systemd/`) | SELinux domain | Holds DEKs | Notes |
|---|---|---|---|---|---|
| nexus-web-api | nexus-webapi (+nexus-catalog) | strict, NoNewPrivileges, empty caps, @system-service ~@privileged ~@resources, MDWE, LimitCORE=0, SocketBindAllow 8443 | `nexus_webapi_t` | TOTP key | can read and write the whole catalog, but source/offsite secrets only as `sealed:v1:` blobs it cannot open (H-2 fixed) |
| nexus-scheduler | **nexus-chunkstore** (+nexus-catalog) | strict, NoNewPrivileges, empty caps, @system-service only, no MDWE (QEMU TCG), /dev/kvm | **none** | **yes** (in-process stores) | spawns nexus-pve, nexus-offsite and QEMU under the same uid (H-3) |
| nexus-pve / nexus-offsite | same as scheduler (children) | inherited | none | yes | now non-dumpable (9fba584) |
| restore-VM QEMU | same as scheduler | inherited + QEMU `-sandbox on,…` + no NIC | none | no (but same uid as DEK holders) | H-3 |
| nexus-keyd | nexus-keyd | strict, PrivateNetwork, IPAddressDeny=any, AF_UNIX only, full syscall filter, MDWE | `nexus_keyd_t` | KEK + DEKs | peer-uid check, non-dumpable, mlockall |
| nexus-chunkstore (unit) | nexus-chunkstore | as keyd | `nexus_chunkstore_t` | — | unit exists; the service binary is not split out yet |
| nexus-setup | root | strict, NoNewPrivileges, no caps bound, no syscall filter | none | recovery key (transient) | L-4 |

---

## 3. Focused reviews

### 3.1 Authentication, sessions, CSRF (`crates/web-api/src/auth.rs`)

**Good:**
- argon2id with a minimum of 12 characters. Unknown users get a dummy hash, so timing does not reveal them.
- TOTP ±1 step; each step is consumed atomically, so a code cannot be replayed.
- Rate limit of 5 failures per user and per IP in 15 min, followed by a 15 min lockout. Failures are audited.
- 256-bit session tokens, stored as sha256. The cookie is HttpOnly, Secure, SameSite=Strict.
- Idle and absolute expiry are enforced on every request. Disabled users are rejected on every request. User updates end the user's sessions.
- CSRF token per session, compared in constant time, required on all non-GET requests. JSON-only bodies. CSP without `unsafe-*`, `frame-ancestors 'none'`, HSTS, nosniff.

**Findings:**
- L-1: the lockout is per user name, so anyone can lock an admin out for 15 min (accepted, documented).
- M-5 (fixed): credential changes did not need the current password. Now `PUT /users/{id}` with `password` or `reset_totp` (own account only) or `new_activation` (another account) requires `current_password` + `current_totp` of the acting user, with the login checks (replay, rate limiter, audit `auth.reauth_failed`).
- Self-enrollment (2026-10-10): `POST /auth/activate/begin|complete` (no session, like login). Wrong, expired or unknown codes answer the same 401, are audited (`auth.activate_failed`) and count toward the login limiter per user and per IP. The code is checked again at `complete`; password, cleared activation and consumed TOTP step are written in one conditional UPDATE (code and TOTP replays fail). The new TOTP seed is shown only to the person activating. A pending account has no valid password hash, so it cannot log in, and its sessions are refused.

### 3.2 RBAC matrix vs. implementation

The new test `rbac_matrix_and_audit_completeness` (`crates/web-api/tests/api.rs`) drives every route as anonymous, admin, security_officer, operator and tenant_user against the matrix in `docs/control-plane.md`:
- allowed roles never get 401 or 403;
- every other role gets exactly 403;
- anonymous callers get 401;
- every successful non-GET call appends an audit entry.

The implementation matched the matrix. The gaps found were in *scoping*: tenant-scoped admins (fixed, see 3.3).

### 3.3 Quorum bypass attempts

| Attempt | Result |
|---|---|
| Weakening by PUT with partial fields | Not possible: PUT bodies are complete (`deny_unknown_fields`, all fields required), and the comparison is per GFS field plus offsite. |
| Weakening via a group move to a weaker policy | Gated (existing). |
| Weakening via a new weak policy + group move | Gated (the move is compared). |
| Disabling offsite via the tenant config (`offsite: {}` or another box) | **Was possible.** Now gated: `tenant.update`, a first setup stays direct (a18c526). |
| Approval race: request a small change, then change the object directly, then approve | **Approval applied the stale snapshot**, so the reviewed diff ≠ the effect. Now 409 when the object ≠ `old` (a18c526). |
| Exfiltrating the write-only PVE token by changing host/CA while keeping the secret | **Was possible.** The secret must now be re-entered when the endpoint changes (a18c526). |
| Tenant-scoped admin writing across tenants / clearing its own scope | **Was possible** (the API accepted `tenant` on any role). Privileged roles can no longer be scoped (a18c526). |
| `tenant: null` on PUT /users | Deserialized as "keep" (functional bug). Fixed. |
| User role change while an enable request is pending | The approver now always sees the resulting role. |
| Approving your own request; renaming to bypass | Refused (by name); names are immutable and there is no user deletion. |
| GC > 20 % | The scheduler raises a quorum (existing); with approvals disabled it waits for an explicit, audited admin confirmation instead of running silently. |
| Admin creates a privileged account and activates it themselves (sock puppet approver) | Prevented while approvals are enabled: the requester gets only part 1 of the activation code, the approver part 2. |
| Admin issues an operator's code, activates it, then requests promotion | Promotion of an account still waiting with an admin-known code is refused (409); after the person activated, the approver must verify the person (out of band). |
| Disabling approvals, then acting alone | Disabling is itself a quorum request needing a second approver. |
| Disabling / demoting approvers until only the requester is left | Refused with approvals enabled (fewer than two possible approvers). |
| Forging a confirmed GC through `POST /jobs` | `gc` params are `deny_unknown_fields` without `approved`/`confirmed_by`; the scheduler ignores `confirmed_by` while approvals are enabled. |

### 3.4 Audit completeness

Every mutating endpoint audits; this is now covered by the test.
- The audit hash is a length-prefixed sha256 chain with append-only triggers (`crates/catalog/src/lib.rs`).
- **Open (M-1):** any process with catalog write access (web-api, scheduler, root) can drop the triggers and recompute the chain. Nothing anchors it off-box: the journal echo has no details, and there is no rsyslog/TLS config in `os/` yet.
- **Open (L-3):** a config change and its audit entry are not in one transaction.

### 3.5 Secrets handling

**Good:**
- Job configs go to `/run/nexus-scheduler/job-<id>/` (0700 dir, files 0600 `create_new`). They are removed after the job and wiped at startup (`crates/scheduler/src/run.rs`, `lib.rs`).
- No secrets in argv.
- The token secret is write-only in the API, and quorum params are redacted.
- Setup never writes the recovery key or the TOTP secret.
- The TLS key is 0600, the metrics token is 0640 root:nexus-webapi.
- `LimitCORE=0` on all units.
- keyd: non-dumpable, mlockall, zeroized keys. `Keyring`/`TenantKey` are zeroized on drop.

**Fixed:**
- Inline `key_pem` / PEM private keys in opaque blobs were accepted, and therefore readable via GET and the audit log (4c8099d).
- The DEK-holding processes were dumpable (9fba584).
- H-2: PVE token secrets and TOTP seeds were in plaintext in the catalog (1042aaf, `crates/catalog/src/secret.rs`).

**Open:**
- L-6: `nexus-offsite dr` keeps the recovery key and DEKs in non-zeroized buffers, and the PVE auth header is not marked sensitive.
- L-7: job logs carry raw remote error text and are readable by tenant users.

### 3.6 Cryptography

- **Nonces:** XChaCha20-Poly1305 with 24-byte random nonces from `OsRng`, for every seal and every key wrap, so there is no nonce-reuse risk at backup volumes.
- **AAD:**
  - for blobs: the 9-byte header (magic, flags, key version), the tenant, a NUL, then the context;
  - for key wraps: the label (`tenant-dek:<t>:v<n>`, `kek-recovery`).
  Swapping blobs between tenants, chunks, snapshots, index names or packs fails authentication; this is tested in `crypto.rs` tests, `pack.rs`, and the `sealed_open` fuzzer.
- **Key derivation:** BLAKE3 `derive_key` with distinct contexts for the chunk-id key and the AEAD key, so one DEK yields two independent keys.
- **Keyed hash:** chunk ids are keyed per tenant and DEK version, so ids cannot be confirmed across tenants. After a rotation there is no dedup against old chunks; this is documented.
- **Decompression:** zstd is decoded only after authentication, so a decompression bomb would need the key.
- **Compliance clock:** see T3. The clock file is protected only by file permissions; a TPM NV counter is planned.
- **Recovery key:** 256-bit, shown once, re-entry check at setup.
- **Info:** compression before encryption leaks sizes (T4 residual).

### 3.7 SSH forced-command helper and PVE plugin root actions (`pve-plugin/`)

**Good:**
- `SSH_ORIGINAL_COMMAND` is split without a shell and capped at 2048 bytes. Arity is exact and every argument is matched against an anchored `\z` regex. Socket paths are derived, never taken from input. The helper runs as the dedicated `nexusbackup` user (password `*`), and `.ssh`/`authorized_keys` are owned by root.
- The IR overlay backing JSON is built with an encoder from regex-checked volnames, under root-owned 0700 dirs that are verified with lstat. `qemu-img -u` and all other commands run via list-form `system`/`open`. There is no eval-string, backticks or 2-arg open.
- The plugin runs under `perl -T` in API workers; the earlier taint bug is fixed and tested.

**Fixed (e76d279):**
- **H-F2:** `backup_handle_log_file` wrote root's task-log copy through a `logs/` dir and `*.log.tmp` name that the helper user could swap for symlinks (the state dir was 0770, not sticky). That gave root-level overwrite plus chgrp of arbitrary files. Fixed with:
  - a sticky state dir (existing installs are fixed up);
  - a root-owned `logs/` that must not be group-writable;
  - `O_EXCL|O_NOFOLLOW` plus fchown/fchmod.
- **H-F3:** guest configs from `index.json` (written by the helper on the appliance's behalf) were handed to PVE unchanged, so `lxc.hook.*`, `args:` or `hookscript:` gave command execution as root on restore. These keys are now dropped with a task-log warning.
- **M-F:** the CT restore staging dir in `/var/tmp` was only checked with `-d`, so a local user could pre-create it or a symlink and redirect root's tar extraction. It must now be a root-owned 0700 real directory.

**Open:** M-4, L-8, L-12 (§4).

### 3.8 Restore micro-VM isolation

**Good:**
- QEMU has no NIC, no default devices, `-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny`, read-only NBD disks, and a 0700 work dir.
- It gets PDEATHSIG and RLIMIT_CORE=0.
- The agent is PID 1 with no network, mounts read-only without journal replay, and confines paths with `openat2(RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS)`.
- The appliance side bounds responses (256 MiB) and frames (16 MiB). It now refuses non-object responses and sanitizes the resulting downloads.

**Open (H-3):** a QEMU escape lands in uid `nexus-chunkstore` without an SELinux domain. From there it can reach the keyd socket (every tenant's DEKs), all stores and the clock files. Run QEMU as its own user in a transient unit with its own domain (svirt-like), keeping DeviceAllow to /dev/kvm only.

### 3.9 Offsite remote trust

A malicious Storage Box (T12) can deny service, as it always could by deleting data. It can no longer:
- crash `check` or `dr`;
- plant unauthenticated index files;
- make the appliance accept foreign data.

Local data loss is excluded by construction:
- the offsite code never deletes local store data;
- the local store accepts only verified chunks and authenticated manifests/indexes.

The `hostile_box` fuzzer asserts this.

**Open (L-2):** no size cap on manifest/index downloads during DR (memory DoS); `LocalDir::get` allocates the requested length.

### 3.10 Appliance replication (Phase 8, docs/replication.md)

Reviewed with the implementation (2026-10-10):
- **Port 8443 surface.** Client certificates are requested only when the ClientHello offers
  `nexus-replication/1` (rustls `Acceptor`, config chosen by ALPN); browsers never get a
  CertificateRequest. Peer connections reach only `/replication/v1/*` (middleware), ordinary
  connections never reach it (403). Chain validation is not trusted alone: every request
  re-checks the fingerprint in `replication_peers` (state `enrolled`) — revocation works on open
  keep-alive connections (test `tenant_scope_revocation_and_connection_kinds`).
- **Isolation.** The web-api crate depends on the replication crate without the `daemons`
  feature, so it cannot link the chunk store or the keyd client (test asserts the manifest; the
  image builds `-p replication` in a separate cargo invocation so features do not unify). Data
  comes from nexus-replicad: read-only store access (SELinux neverallow on writes, systemd
  `ProtectSystem=strict`), no keyd (neverallow connectto + `InaccessiblePaths=`), no network
  (`PrivateNetwork=yes`). Accepted: replicad trusts the web-api for the peer identity it forwards
  (a compromised web-api gets ciphertext of any tenant, no keys).
- **Enrollment.** Token 128 bit, single use, valid 24 h after the quorum approval, digest sealed to
  replicad (the web-api cannot open it), 5 failed proofs void it. The secondary pins the primary
  certificate before sending anything; proofs bind the TLS exporter of each leg (MITM test).
  The CSR contributes only its public key; the secondary checks that the issued certificate
  carries its key and CN.
- **Keys.** DEKs leave keyd only as a sealed box to the secondary keyd's X25519 key, only for an
  approved `replication.key_export` request (second person, names the keyd key fingerprint),
  executed by the scheduler, which re-checks peer state, key and scope. The secondary keyd binds
  imported tenants to the primary's certificate fingerprint (`origin`), refuses tenants with local
  keys, differing key versions and local rotation. Accepted: keyd trusts its caller uid for the
  quorum check (that uid holds DEKs anyway, T6/H-3).
- **Hostile primary.** Everything is verified before it is written (`decode_manifest`/`decode_index`,
  `insert_chunk_raw` = AEAD + keyed hash); the manifest is committed last; the secondary never deletes
  because the primary did; sizes are bounded (files 256 MiB, chunks 4 MiB + header, listing 64 MiB,
  HTTP heads 16 KiB). Test `tampered_chunk_is_not_imported`.
- Fuzz target `replication/hostile_primary` covers the secondary's HTTP/1.1 client and the chunk
  frames (§1.1).
- **Open (L-4):** no per-peer bandwidth limit on the primary (concurrency is limited to 8 requests
  per peer; the secondary has `bwlimit`).

---

## 4. Findings

### Fixed in this review

| ID | Sev | Finding | Commit |
|---|---|---|---|
| H-F1 | high | Zip slip / write-through-symlink entries in file-restore downloads (compromised CT or restore VM → files on the user's machine) | fa0354a, 63ad430 |
| H-F2 | high | PVE plugin: root task-log write through helper-controlled symlinks (helper user → root on the node) | e76d279 |
| H-F3 | high | PVE plugin: root-only guest config keys from the catalog applied on restore (appliance/helper → root on the node) | e76d279 |
| M-F1 | medium | NBD client overflow / unbounded extents from a hostile node | 7dcd4ed |
| M-F2 | medium | Offsite: hostile listings/footers crash inventory/DR; unauthenticated `*.idx` copied into the state | 2beeae3 |
| M-F3 | medium | Quorum TOCTOU: approval applied a stale snapshot | a18c526 |
| M-F4 | medium | Tenant offsite target change/removal not quorum-gated | a18c526 |
| M-F5 | medium | Write-only PVE token followed host/CA changes (exfiltration by admin) | a18c526 |
| M-F6 | medium | Tenant-scoped admin/SO accounts (cross-tenant writes, self-unscoping) | a18c526 |
| M-F7 | medium | Inline SSH private keys accepted in opaque blobs, returned by GET and audit | 4c8099d |
| M-F8 | medium | Compliance clock file `inf`/`NaN` accepted (all locks expire) | 885ef56 |
| M-F9 | medium | DEK-holding processes dumpable / ptrace-able by the same uid (incl. QEMU) | 9fba584 |
| M-F10 | medium | CT restore staging dir in `/var/tmp` not ownership-checked (local user → root on the node) | e76d279 |
| M-F11 | medium | Offsite `verify_sample` downloaded an unbounded size; SFTP range overflow | 2beeae3 |
| H-2 | high | Catalog held PVE token secrets and TOTP seeds in plaintext (web-api RCE → every PVE token and TOTP seed). See "H-2 design" below. | 1042aaf |
| M-5 | medium | Own password/TOTP change without re-authentication (a hijacked session becomes persistent) | 1042aaf |
| L-F1 | low | Non-object agent response panicked nexus-pve | 60bb445 |
| L-F2 | low | `tenant: null` did not clear a user's tenant scope | a18c526 |
| L-F3 | low | keyd: no write timeout on the single-threaded socket loop | 8bd8755 |
| L-F4 | low | Agent: an unreadable package marker (ACL, scanner lock) counted as "no package", so an MSI/.deb/.rpm install could take a binary swap behind its package manager (lab #67) | 868d18a8 |

### Open — recommendations

| ID | Sev | Finding | Recommendation |
|---|---|---|---|
| H-1 | high | KEK stored as a plain 0600 file (`keyd::seal`); no LUKS. Disk theft = all data. *Accepted deferral (user decision 2026-10-08/09).* | TPM2 sealing to PCRs + LUKS2 before production. Until then keep appliance disks in controlled locations and keep the KEK out of images and backups. |
| H-3 | high | scheduler, nexus-pve, nexus-offsite and restore-VM QEMU share uid `nexus-chunkstore` and have no SELinux domain. keyd hands DEKs to that uid. Narrowed 2026-10-21 (Phase 39 S4): nexus-index (same uid, primary group `nexus-index`) only fetches keyrings; keyd refuses it everything that creates, exports, imports or changes keys (test `read_only_group_only_fetches_keyrings`). | Separate users (`nexus-scheduler`, `nexus-pve`, `nexus-offsite`, `nexus-restorevm`). QEMU in a transient unit (PrivateNetwork, DeviceAllow=/dev/kvm) with its own domain. keyd ACL per uid. Domain transitions in `os/selinux`. |
| M-1 | medium | Audit chain unkeyed and not anchored off-box. The journal echo lacks details. No log forwarding config. | HMAC chain with a keyd key or signed checkpoints. Journal/rsyslog TLS forwarding in the image. Single audit writer. Include the head hash in each offsite upload. |
| M-2 | medium | nftables egress sets are never populated (no code writes them). The firewall blocks DNS/NTS/PVE/SFTP, which invites flushing it. | Root helper or setup generates the sets from the catalog and chrony config (Phase 6 "nftables automation"). |
| M-3 | medium | Deleting the clock file makes the store trust system time once. | Fail closed when snapshots exist and the clock is missing, or seed from the newest manifest. Give the clock file its own owner. TPM NV counter later. |
| M-4 | medium | VM restore attaches guest-controlled disk content to the node kernel (`/dev/nbdX`): partition parsing, udev/blkid, LVM autoactivation. | `nbd max_part=0`, LVM `global_filter` reject `/dev/nbd*`, udev rule to skip probing. Better: a userspace NBD source for `qemu-img` if PVE allows. |
| M-6 | medium | An admin can stop *future* protection without a quorum: remove guests from groups, break source config, change schedules. | Quorum for removing guests or deleting coverage, or at least a "coverage reduced" alert to the SO. |
| M-7 | medium | Lab PVE token has lab-wide roles. Least-privilege role set not defined. | Define and document the minimal PVE privileges (VM.Backup, Datastore.Allocate*, Sys.Audit on nodes, SDN for restore) and test with them. |
| L-1 | low | Per-user login lockout lets anyone lock out a known admin for 15 min. | Accepted. Optionally exempt known-good IPs or add a progressive delay instead. |
| L-2 | low | Memory DoS by hostile peers: tar GNU long names (tar crate reads them fully), many tiny NBD extents, unbounded manifest/index downloads in DR, `LocalDir::get` length. | Per-job `MemoryMax=` (transient units, see H-3); caps for metadata downloads. |
| L-3 | low | Config change and audit entry are not one transaction. | Write both in one SQLite transaction. |
| L-4 | low | `nexus-setup.service` is root with no capability bound and no syscall filter. | `CapabilityBoundingSet` (CHOWN, FOWNER, DAC_OVERRIDE, NET_ADMIN), `SystemCallFilter=@system-service`. |
| L-5 | low | SELinux policy incomplete (catalog/TLS labels missing, no scheduler domain). Enforcing would break it, inviting permissive. | Finish labels and domains before release; add a `neverallow` for web-api → keyd socket. |
| L-6 | low | `nexus-offsite dr` keeps the recovery key and DEKs in plain buffers. PVE auth header not marked sensitive. | `Zeroizing`, `HeaderValue::set_sensitive`. |
| L-7 | low | Job logs (readable by tenant users) contain raw ssh/PVE error text. | Cap/scrub; tenant users see a summary only. |
| L-8 | low | PVE helper: predictable rendezvous names allow job DoS. No `from=` in `authorized_keys`. Helper not under `perl -T`. `ir-serve` without a session limit. | Random names; document `from="<appliance>"`; `-T`; session timeouts. |
| L-9 | low | Escrow dir `/var/lib/nexus/escrow` not writable by the scheduler unit (ProtectSystem=strict), so escrow refresh silently fails. | Add it to the unit's StateDirectory/ReadWritePaths (os/ owner). |
| L-10 | low | Key paths (node SSH key, box key) are arbitrary admin-chosen paths. Nothing provisions `/etc/nexus/ssh`. | Generate keys in setup under a fixed 0700 dir; reject paths outside it. |
| L-11 | low | CT restore extracts the appliance tar as real root with `--xattrs-include=*` and an unbounded size. | Extract inside the target userns; restrict xattrs; check free space. |
| I-1 | info | Compression before encryption leaks chunk sizes to the box. | Accepted (T4 residual); optional padding buckets. |
| I-2 | info | `os/Containerfile` does not install `nexus-scheduler.service`. `os/README.md` claims `PrivateUsers=yes` for web-api. `docs/pve-connector.md` says 0770 for dirs that are 1770. | Fix in the respective owners' trees. |

---


### H-2 design (fixed)

- **Source / offsite credentials** (`token_secret`, `key_pem` anywhere in `sources.config` / `tenants.offsite`) are sealed to the scheduler: libsodium `crypto_box_seal` (X25519 + XSalsa20-Poly1305, crate `crypto_box`), stored as `sealed:v1:<base64>`. The scheduler owns the private key (`/var/lib/nexus/scheduler/secrets.key`, 0600, created on first start, audit `secret.key_create`) and publishes the public key (`/var/lib/nexus/catalog/secrets.pub`, 0640, group `nexus-catalog`). The web-api seals on write and refuses secret writes with 503 while the public key is missing. It cannot decrypt.
- **Binding:** the sealed plaintext is `location NUL secret`, and the location is checked on open. The location is `source/<id>` or `tenant/<name>/offsite`, plus the JSON pointer of the field, plus a digest of the endpoint fields next to it (`host`, `port`, `connect_addr`, `ca_pem`, `token_id`, `user`, `host_key`). A blob copied to another source or field does not open. Neither does a token whose source was pointed at another host or CA directly in the catalog.
- The scheduler opens secrets only in memory while generating the 0600 job config. Legacy plaintext values are sealed at scheduler startup (audit `secret.migrate`, per row, field pointers only).
- **TOTP seeds** use XChaCha20-Poly1305 with a web-api-only key (`/var/lib/nexus/webapi/totp.key`, 0600 `nexus-webapi`, created by nexus-setup). The AAD is the user name. Seeds are stored as `enc:v1:<base64>`, including the `totp_secret` of pending `user.update` quorum params. Legacy plaintext seeds keep working and are encrypted at web-api startup (audit `secret.migrate`). The web-api creates a missing key itself only while no encrypted seed exists.
- **Residual risk:**
  - Root, or anything running as the scheduler uid (`nexus-chunkstore`: scheduler, nexus-pve, nexus-offsite, restore-VM QEMU; see H-3), can read `secrets.key` and decrypt every source/offsite secret.
  - The web-api uid can decrypt every TOTP seed. A web-api RCE still yields second factors, but no longer PVE tokens or SSH keys.
  - A catalog writer (web-api RCE) can still delete or replace sealed secrets (denial of backups) and rewrite unsealed config such as storage and nodes. It can also seal its *own* token for an attacker endpoint. That only sends the attacker's own credential to the attacker.
  - The catalog stays writable by both uids (audit chain: M-1).

## 5. Supply chain

- **`cargo audit`** (RustSec DB of 2026-10-09, 406 crates): **0 vulnerabilities**. 4 warnings:
  - `atomic-polyfill` unmaintained (via postcard/heapless);
  - `paste` unmaintained (proc-macro via ratatui);
  - two `lru` 0.12 unsoundness advisories (RUSTSEC-2026-0002, -0253) via ratatui.

  All warnings are reachable only from the first-boot console TUI (`crates/setup`) and get no untrusted input. Recommendation: bump ratatui when a release with lru ≥ 0.16 is available.
- **Desktop agent GUI (Phase 24, `crates/agent-gui`):** iced (tiny-skia software renderer, no GPU stack) and
  tray-icon with its pure-Rust StatusNotifierItem backend (ksni, licence Unlicense, allowed in `deny.toml`) instead of
  GTK. `ttf-parser` (via cosmic-text/fontdb) is unmaintained (RUSTSEC-2026-0192, ignored in `deny.toml`): it parses
  only the fonts installed on the user's desktop, the GUI receives no network input (local agent socket/pipe only).
- **Review 2026-10-20 (cargo audit, 5 warnings, 0 vulnerabilities):**
  - `lru` 0.16 unsound (RUSTSEC-2026-0253: `LruCache::pop` leaves dangling list nodes if a key's `Drop` panics). On
    the appliance it came from tantivy (file index): **fixed** by tantivy 0.27 (lru 0.18.5; same index format 7, so
    existing indexes stay readable). Left only in the desktop GUI via cryoglyph (iced's glyph cache): plain value keys
    whose `Drop` cannot panic, so the unsound path is not reachable; goes with the next iced release.
  - `zvariant`, `zbus_names`, `zvariant_derive` unmaintained (RUSTSEC-2026-0370/0371/0372): merged into zbus 6 as
    modules, no flaw. Via zbus 5 in tray-icon and iced_winit, desktop GUI only (D-Bus to the local session bus); goes
    with the releases of those on zbus 6.
  - All five are in `deny.toml` with these reasons; none reaches the appliance.
- **Review 2026-10-21 (for 0.2.0-alpha, cargo audit 2 warnings, 0 vulnerabilities):**
  - zbus 5 stack (RUSTSEC-2026-0370/0371/0372): **fixed**. The Linux desktop GUI now speaks D-Bus itself on zbus 6
    (`crates/agent-gui/src/sni.rs`: StatusNotifierItem, dbusmenu, notifications, the portal's dark-mode setting)
    instead of ksni, notify-rust and iced's mundy, which are all still on zbus 5. tray-icon and notify-rust remain
    for Windows only; test `crates/agent-gui/tests/sni.rs` on a private session bus.
  - `lru` 0.16.4 (RUSTSEC-2026-0253): in `Cargo.lock` only. cryoglyph belongs to iced_wgpu, which is never built
    (software renderer); Cargo locks optional dependencies named by weak `dep?/feature` features. Not in any binary.
  - `ttf-parser` unmaintained (RUSTSEC-2026-0192, no patched version): the font parser of iced 0.14 (fontdb,
    cosmic-text), reading only the fonts installed on the desktop. No iced release without it yet (iced master
    still pins cosmic-text from git); goes with the next iced release.
  - Appliance image CVE scan: `dnf upgrade` in the image build (the base image lagged the AlmaLinux security
    updates: kernel, openssl, python3, pcre2, bubblewrap, rpcbind) and the unused flatpak-session-helper removed.
    Still open upstream: podman/skopeo built with Go 1.26.7 (x/net, grpc, podman module findings; fixes need an
    AlmaLinux rebuild, none published on 2026-10-21; podman is a bootc dependency the appliance never runs,
    skopeo is run by bootc only for the signed update pull) and kernel fixes RHEL published before AlmaLinux.
- **Time servers configurable (2026-10-21, Settings → Time):** a new write path to the clock (threat model T3). Gated
  by approval `time.servers` (security officer with approvals on), audited, admin only, never tenant-scoped; plain NTP
  only with the explicit `allow_ntp` opt-in (chrony `authselectmode prefer`, `time.nts` warns, the approver sees
  `plain_ntp`). The root helper `nexus-time` runs without network in `nexus_time_t`, which the policy grants no capability (the bounding set keeps `CAP_DAC_OVERRIDE` for chronyc in `chronyc_t`, as for nexus-diag); only it may
  write the sources file (neverallow); the chronyd restart happens in the unit's ExecStartPost, not in the domain.
  Tests: `crates/web-api/tests/timesync.rs` (RBAC, refusals, approval before the request file),
  `os/greenboot/tests/test_nexus_time.py`. Found on the way: `time.nts` read the wrong chronyc column and always
  warned (fixed, fixtures now real chrony 4.8 output).
- **bootc in install_t (2026-10-21, `os/selinux/nexus.te`):** nexus-update (unconfined_service_t) now transitions
  bootc, ostree and rpm-ostree (`install_exec_t`) into `install_t`, the domain the stock bootc and rpm-ostree units
  use. That widens what the update path may do by `mac_admin` (labels the loaded policy does not know), which an
  update that adds SELinux types needs. The trust decision stays with the signature policy (`policy.json`, release
  keys pinned) and nexus-update's checks; only root services in unconfined_service_t could exec bootc before and
  after. nexus-update.service no longer sets NoNewPrivileges: no_new_privs refused bootc's own transitions (mount_t
  and others; the stock units do not set it either); it is root in unconfined_service_t either way. Lab (VM 201):
  an offline update from 0.0.11 to an image with a type unknown to the running policy imported, booted and labelled
  the file; 0.0.13 and 0.0.14 installed the same way.
- **Risk signal thresholds and the API token network rule (2026-10-21, Phase 39 S2):** the numbers of the risk rules
  became a setting, which is a way to blunt detection: every change is gated (`settings.risk`), out-of-range values
  are refused, an unreadable stored value falls back to the defaults (never weaker by accident), and a loosening
  change counts toward the weakening burst itself. New rule: an API token used from a network it was not used from
  before marks the account (a stolen token used elsewhere stops changing anything until a person clears it). Tests:
  `crates/web-api/tests/tokens.rs` `token_from_a_new_network`, `risk.rs` unit tests.
- **Post-quantum TLS key exchange (2026-10-21, Phase 39 S5):** the hybrid X25519MLKEM768 is preferred on every TLS
  endpoint of ours (crate `tls-pq`). Own code in a cryptographic path, so: the hybrid only adds to X25519 (both
  secrets go into the TLS key schedule, the session is as strong as the stronger half), share lengths are checked
  before parsing, the client's encapsulation key is validated (FIPS 203 modulus check), and the wire format is
  checked against OpenSSL 3.5 in both directions (tests in `crates/tls-pq`). A peer without the group falls back to
  X25519.
- **`cargo deny check`** with the new `deny.toml`: advisories / bans / licenses / sources **ok**.
  - **Licenses:** only permissive or weak-copyleft licenses compatible with AGPL-3.0.
  - **Sources:** crates.io only, no git dependencies.
  - The advisories above are ignored with documented reasons.
  - Recommendation: add `cargo deny check` to CI next to `cargo audit`.
- **`npm audit`** (web/, 5 exact-pinned devDependencies, nothing shipped except the built bundle): **0 vulnerabilities**.
- **Fuzz toolchain:** nightly + cargo-fuzz are build-time only and not part of the image.

---

## 6. Re-running this review

- `cargo test` (includes `rbac_matrix_and_audit_completeness` and the regression tests named in §4).
- `prove pve-plugin/t`.
- `lab/fuzz/run.sh 600 4`.
- `cargo audit && cargo deny check`.
- `cd web && npm audit`.
