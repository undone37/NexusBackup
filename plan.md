# Open-Source Enterprise Backup Appliance — Project Plan

**Version:** 1.0 (initial consolidated plan)
**Date:** 2026-10-08
**Status:** Draft for review

---

## 1. Vision and Goals

Build an open-source, enterprise-grade backup suite modelled on Cohesity: a hardened, self-contained backup appliance that pulls data from all sources, stores everything deduplicated as forever-full snapshots, and replicates encrypted copies to an offsite tier.

### 1.1 Design principles

1. **Forever full.** Every backup is a complete, immutable snapshot. Physically only new chunks are stored.
2. **Global deduplication per tenant.** All sources of a tenant deduplicate against each other. No deduplication across tenants (by design, for isolation).
3. **Pull model.** The appliance initiates every connection. No source ever connects to the appliance. The appliance can therefore be operated fully encapsulated behind a default-deny firewall with a single inbound port (management UI/API).
4. **Hardened by default.** Image-based OS, SELinux enforcing, full-disk encryption bound to TPM and Secure Boot, no interactive root, retention locks that nobody can shorten, four-eyes principle for destructive actions.
5. **Policy-driven, not job-driven.** Protection groups receive an SLA policy (frequency, retention, offsite). Admins define the goal, not individual runs.
6. **Self-describing offsite copies.** Every offsite copy can be restored with nothing but the storage credentials and the recovery key — without the original appliance.
7. **Single language in the core.** Rust for data plane and control plane.
8. **No code or components originating from Veeam.** (Explicit project constraint; e.g. no blksnap-based snapshotting.)

### 1.2 Non-goals (initial scope)

- Scale-out / multi-node clustering (design for it, do not build it in phase 1).
- Windows block-level CBT (file-level with VSS + USN journal only).
- NAS block-level or snapshot-based backup (file-level only).
- S3/object storage as offsite tier (Hetzner Storage Box first; S3 is a later backend implementation).
- Microsoft 365 (last phase, see roadmap; built as a plugin).
- Long-term legal archiving (GoBD / HGB / AO retention of up to 10 years is the job of an archive/DMS, not of the backup system; this must be communicated to customers).

---

## 2. Key Decisions and Rationale

| Decision | Choice | Rationale |
|---|---|---|
| Storage engine | **Own chunk store in Rust** | Borg was evaluated and rejected: client-only CLI tool, no server component or API, single-writer repository locking, Borg 2.0 still in beta (2.0.0b23, Aug 2026) with a format incompatible to 1.x. Teaching Borg dirty bitmaps would effectively mean re-implementing the PBS fixed index. |
| Language | **Rust** (data plane and control plane) | Memory safety without GC pauses, C-level throughput for hashing/compression/encryption, mature crates (`tokio`, `blake3`, `zstd`, `fastcdc`, RustCrypto/`ring`, `axum`). Proven for this exact task by Proxmox Backup Server. Trade-offs: compile times, smaller hiring pool. |
| Direction of connections | **Pull** (appliance → sources) | Sources never hold credentials to the appliance. A compromised hypervisor or server cannot reach the backups. |
| Reference model | **Cohesity** | Single storage for all workloads, snapshot-based forever-full, SLA policies, instant mount, quorum for destructive actions. |
| MAC system | **SELinux** (not AppArmor) | Type enforcement confines every service into its own domain; root processes are still restricted by policy. AppArmor is path-based and easier to bypass. |
| Base OS | **Image-based RHEL clone with bootc** (AlmaLinux / CentOS Stream) | Signed container image, read-only `/usr`, atomic A/B updates, automatic rollback. |
| Offsite tier (phase 1) | **Hetzner Storage Box, one box per tenant** | Cheap, EU-located, SFTP/rsync, automated snapshots. Per-tenant box solves the 10-connection limit, improves isolation, enables per-customer billing. |
| Offsite retention | **Identical to local retention** (Phase 30: by default; a target may keep *longer*, never shorter) | Customer requirement; the same restore points must be available offsite. Phase 30 (second offsite target, docs/netbackup-comparison.md decision 5): each offsite target can have its own retention, applied as the larger of it and the policies' per class. |
| Catalog database | **SQLite (WAL mode)** | Single-node appliance; robust, serverless, trivially backed up. |
| Garbage collection | **Mark-and-sweep** (not reference counting) | Reference counters corrupt easily on crashes; a wrong counter means data loss. |
| VM chunking | **Fixed-size chunks aligned to dirty bitmaps** | Maps dirty-bitmap regions directly to chunks; enables random access for instant recovery and single-file restore. |
| File chunking | **Content-defined chunking (FastCDC)** | Insert/shift-resistant deduplication for file data. |
| Chunk identifiers | **Keyed hash (BLAKE3 keyed mode, per-tenant key)** | Prevents the storage provider from confirming the presence of known files (fingerprinting attacks). Implies no cross-tenant dedup. |
| Encryption | **AEAD per chunk: XChaCha20-Poly1305** (decided 2026-10-08), envelope key model | Per-tenant DEK wrapped by a KEK held in the TPM and escrowed as an offline recovery key. 192-bit random nonces have no practical collision risk at billions of chunks (AES-GCM's 96-bit nonce would limit chunks per key); fast without AES-NI; pure Rust (RustCrypto). |
| Data path order | **Dedup → compress → encrypt** | Any other order destroys deduplication. |
| License | **AGPL-3.0** (decided 2026-10-08) | Allows reuse of AGPL Proxmox / PBS crates; network clause fits an appliance that may be offered as a service. |
| VCS / CI | **git + GitHub Actions** (decided 2026-10-08) | CI runs fmt, clippy, tests and cargo-audit. |
| PVE support | **PVE 9.x only** (decided 2026-10-08) | One API version to track; 8.4 not targeted. |
| PVE NBD transport | **NBD piped over SSH stdio via forced command** (decided 2026-10-08) | `restrict`ed key without any forwarding; `permitopen` cannot limit Unix-socket forwards. |
| PVE test lab | **Nested PVE 9 VM in QEMU on the dev machine** (decided 2026-10-08) | No host installs; reproducible lab scripts. |
| Instant recovery | **qcow2 overlay on the node, backing = appliance NBD export over SSH; then live `qm disk move`** (decided 2026-10-09) | PVE refuses provider live-restore; writes stay local on the node; appliance stays read-only. |
| Restore micro-VM | **Debian 13 kernel + initramfs, including ZFS** (decided 2026-10-09) | Appliance (RHEL-family) kernel lacks ntfs3/ZFS; ZFS (CDDL) is a separate component inside the micro-VM, not linked into AGPL code. |
| File restore delivery (Phase 3) | **CLI download as tar/zip** (decided 2026-10-09) | Web UI download follows in Phase 5. |
| Offsite test target (Phase 4) | **Local OpenSSH SFTP container mimicking Storage Box limits first**; real Storage Box later for a final run (decided 2026-10-09) | Fast, repeatable tests; no credentials needed during development. |
| SFTP client | **Pure Rust: russh + russh-sftp** (decided 2026-10-09) | No C dependencies; host-key pinning, range reads, parallel connections under our control. |
| Web UI (Phase 5) | **Svelte 5 + Vite SPA in TypeScript** (decided 2026-10-09) on the REST API | Small bundles, no inline scripts (strict CSP). |
| Web UI dependencies | **Committed lockfile, `npm ci --ignore-scripts`, minimal deps; built assets embedded in the web-api binary** (decided 2026-10-09) | Supply-chain hygiene; no Node in the appliance image. |
| MFA (Phase 5) | **TOTP only at first** (decided 2026-10-09) | WebAuthn follows later. |
| First boot (Phase 5) | **Console TUI** (decided 2026-10-09) | Management API unreachable until setup is done; no default credentials. |
| Disk encryption (Phase 6) | **Deferred together with TPM** (decided 2026-10-09) | Data stays AEAD-encrypted per chunk on disk; LUKS2 + TPM unlock come later. |
| Release signing (Phase 6) | **cosign with an offline key** (decided 2026-10-09) | Appliance pins the public key; no dependency on external transparency services. |
| Update source (Phase 6) | **Signed bootc images on ghcr.io** (decided 2026-10-09) | Pulled over HTTPS via an explicit nftables allow rule. |
| Phase 7 order | **Linux agent → Windows agent → TrueNAS → NAS (NFS/SMB)** (decided 2026-10-09) | Agents share most code (protocol, chunking, enrollment). |
| Agent dedup hashing (Phase 7) | **Agents send plain BLAKE3 chunk hashes; the appliance maps them to keyed chunk IDs in a local index** (decided 2026-10-09) | Source hosts never hold tenant key material; the unkeyed hashes never leave the appliance (not offsite). |
| TrueNAS data path (Phase 7) | **ZFS snapshot via TrueNAS API, changed files streamed from `.zfs/snapshot` over a restricted SSH user (forced command)** (decided 2026-10-09) | No mounts on the appliance; nothing installed on TrueNAS beyond a key. |
| TrueNAS privilege model (Phase 7) | **SSH user `nexusbackup` runs find/tar/realpath/zfs via passwordless sudo; the forced command is the security boundary** (accepted 2026-10-09) | Reading NAS data needs root (modes, NFSv4 ACLs); same trust level as the PVE helper. Snapshots named `nexus-<source>-<time>`; restore download-only in v1. |
| Work order after Phase 7 TrueNAS | **Continue the plan order (NAS → Phase 8 → Phase 9 plugin system → Phase 10 end-user manual → Phase 11 M365); production hardening later** (decided 2026-10-09; plugin phase inserted 2026-10-10) | User decision; production gaps listed in state.md. |
| NAS read access (Phase 7) | **Documented server-side models: NFS read-only export to the appliance with `all_squash,anonuid=0,anongid=0`; SMB dedicated backup account (Backup Operators / Samba `admin users`)** (decided 2026-10-10) | Full read access without agents on the NAS. |
| SMB Kerberos (Phase 7) | **Dropped from v1** (decided 2026-10-10) | NTLMSSP with signed + encrypted SMB3 only; Kerberos later with an AD lab. |
| Missing NAS snapshot alerts (Phase 7) | **Warn once per source; afterwards a status badge; always alert when files actually changed during the read** (decided 2026-10-10) | Avoid alert fatigue. |
| S3 test target (Phase 8) | **Local MinIO (Object Lock compliance) for development; real provider for a final run later** (decided 2026-10-09) | No credentials needed during development. |
| S3 client (Phase 8) | **Minimal own SigV4 client** (decided 2026-10-09) | Only the calls we need; few deps; fuzzable. |
| Appliance replication (Phase 8) | **Secondary pulls via a replication endpoint on the primary's management port 8443, mTLS with an enrolled secondary's client cert** (decided 2026-10-09) | No new inbound port; serves sealed data read-only; primary holds no credentials for the secondary. |
| Approval system (quorum) | **Optional.** Off by default when the appliance has a single user; enabling needs no approval; disabling needs the requester **plus one other approver**; approvers are **admins and security officers** (never the requester); when users are added later approvals stay off and the UI recommends enabling them (decided 2026-10-10) | Small installations stay usable; disabling the safety net still needs four eyes. Retention locks stay enforced regardless. |
| User onboarding | **Self-enrollment at first sign-in**: the admin creates the account and gets a one-time activation code; the user sets their own password and authenticator (decided 2026-10-10) | The admin never learns another user's credentials (otherwise approvals are meaningless). |
| Replication approvals (Phase 8) | **Two quorum approvals: create peer, then key export naming the secondary keyd fingerprint** (decided 2026-10-10) | Approver sees exactly which machine receives the keys. |
| Replicated tenants (Phase 8) | **Read-only copies on the secondary: no local backups** (decided 2026-10-10) | Unambiguous key origin and retention. |
| nexus-replicad identity (Phase 8) | **Runs as nexus-chunkstore, read-only enforced by its SELinux domain** (decided 2026-10-10) | Revisit with the planned uid split (review H-3). |
| Plugin runtime (Phase 9) | **Signed executables spawned as sandboxed processes (own systemd sandbox + SELinux domain) speaking a versioned protocol; Rust SDK** (decided 2026-10-10) | Plugins may use native libraries (libpq, VMware, NetApp). |
| Plugin trust (Phase 9) | **Project release key accepted; further publisher keys trusted per appliance by an admin with quorum** (decided 2026-10-10) | Third-party and own plugins without opening the door to unsigned code. |
| Plugin scope (Phase 9) | **Reference plugin PostgreSQL; TrueNAS connector ported to the SDK; restore API covers download, restore to original/alternate target, application-specific restore and mount/instant access** (decided 2026-10-10) | M9 proof with a real database and a real port. |
| End-user manual (Phase 10) | **English; screenshots from a seeded demo appliance captured by a headless-browser script** (decided 2026-10-10) | Matches the UI; reproducible per release; no real hostnames/IPs/secrets. |
| M365 testing (Phase 11) | **Local Microsoft Graph mock for development; final run against a real M365 developer/test tenant provided later** (decided 2026-10-11) | No tenant credentials needed during development. |
| M365 scope (Phase 11) | **Exchange mailboxes (mail, calendar, contacts), OneDrive, SharePoint sites (document libraries), Teams (channel messages + team files)** (decided 2026-10-11) | Full first release; Teams messages need Microsoft's protected/metered export APIs (tenant approval). |
| M365 authentication (Phase 11) | **Entra app registration, application permissions, certificate credential; private key stored as a sealed source secret; no client secrets** (decided 2026-10-11) | No expiring bearer secret. |
| M365 restores (Phase 11) | **Download, restore to original (new folder, no overwrite by default), restore to another user/site** (decided 2026-10-11) | Covers leaver scenarios. |
| UI redesign (Phase 12) | **Enterprise console look: dark navy icon sidebar, light card-based content, dense tables, status colors; dark mode (follows the OS, manual toggle)** (decided 2026-10-11) | User: current UI not professional enough. |
| Management dashboard (Phase 12) | **KPIs + charts for protection & SLA (protected/unprotected, RPO compliance, last good backup age), job success trends (7/30 days, failures by source type), capacity & efficiency (used/free, growth + forecast to full, dedup/compression), offsite & replication (lag, lock coverage, restore tests)** (decided 2026-10-11) | Management needs KPIs at a glance. |
| OIDC (Phase 12) | **Generic OIDC (Entra ID, Keycloak, Okta, Authentik, …) in addition to local auth; IdP groups/claims mapped to appliance roles and tenants; MFA enforced by the IdP; local accounts remain as break-glass** (decided 2026-10-11) | Central identity management. |
| Phase 12 order | **After Phase 11 (M365)** (decided 2026-10-11) | |
| OIDC user provisioning (Phase 12) | **Just-in-time on first login**: role + tenants from the group/claim mapping, refreshed at every login; no matching mapping = access denied; IdP + mappings configured by admins in the UI (decided 2026-10-11) | No manual account sync. |
| Branding (Phase 12) | **Name "NexusBackup", simple geometric SVG logo mark, navy + teal palette** (decided 2026-10-11) | Neutral; replaceable (one SVG + CSS variables). |
| UI dependencies (Phase 12) | **Hand-written SVG charts (no chart library); small npm UI deps allowed (e.g. icon set)** (decided 2026-10-11) | Small bundle, strict CSP. |
| Release 0.0.1-alpha | **After Phase 12: push main, CI green, push tag `v0.0.1-alpha` → CI draft release; maintainer signs the digest (release/sign.sh), then the draft is published** (decided 2026-10-11) | Signing needs the maintainer's passphrase. |
| Visibility | **GitHub repo and ghcr.io package stay private until the maintainer decides otherwise (more testing first)** (decided 2026-10-12) | Releases are for testing only; appliances need a read-only pull credential for updates. |
| Phases 13–19 scope | **All Cohesity "worth copying" items, Tiers 1–3 (docs/cohesity-comparison.md)** (decided 2026-10-12) | Close operational gaps; feature parity where it fits the pull/security model. |
| Failover of replicated tenants | **Still no promotion: a secondary never takes over; DR = rebuild a primary from the secondary or offsite** (reconfirmed 2026-10-12) | Keeps the one-way trust model of replication. |
| Emergency console root access (Phase 14) | **tty2 gate: approved one-time code (`console.unlock`, ≤ 8 h) or the recovery key; time-limited shell; audit + critical alert** (decided 2026-10-12) | Closes the "no root shell" gap without sshd or a known root password. |
| Audit/alert forwarding (Phase 14) | **Syslog over TLS (RFC 5424/5425) and HTTPS JSON, both; audit entries carry seq + hash; daily anchor record** (decided 2026-10-12) | SIEM integration; anchors the hash chain off the box. |
| Orphaned snapshots (Phase 13) | **Pruned with the default GFS (setting `orphan_gfs`); never-locked-only delete via approval** (decided 2026-10-12) | Store must not grow forever. |
| Orphan sweep / manual delete details (13a) | **Sweep runs at the start of the daily `gc` job; replicated tenants skipped; manual delete only for local, unlocked, non-replicated snapshots (offsite copies follow offsite retention); `orphan_gfs` has no UI yet** (decided 2026-10-12) | Same run frees the chunks; a deleted replica would be re-fetched. |
| Storage accounting (13d/e) | **Figures from per-snapshot `nexus-stats` of locally kept snapshots; a chunk counts for its first writer (Stored = lower bound; measured store size stays authoritative); source in several groups → lowest group id; quotas soft (alerts 80/100 %, never block); anomaly settings: stricter applies at once, weaker/off needs approval (`settings.anomaly`)** (decided 2026-10-12) | Honest, cheap figures without rescanning the store. |
| Alert lifecycle (13f) | **Alerts keyed; repeat while open bumps count; ack = seen (still open), resolve = closed (by people with a note, or automatically on the success path, audited); reminders for open unacked alerts every 24 h, severity rise re-delivered; changed-files inconsistency alerts still warn again after an ack (2026-10-10 decision kept); rules with tenants match only those tenants; webhook header values write-only** (decided 2026-10-12) | Less noise, clear state, routing per team. |
| Auto-protect (13c) | **Inventory refreshed by an `inventory` job per source (default hourly; PVE needs VM.Audit); auto groups (`all`/`tags`, exclude wins) protect nothing until the first refresh and never fall back to "whole source"; plugin protocol v1.5 adds a separate `TaggedGuests` message (postcard is not self-describing, old plugins keep working); M365 Entra-group tags deferred to 17a (needs GroupMember.Read.All)** (decided 2026-10-12) | New guests protected without manual edits; wire compatibility. |
| Run control (13b) | **Schedules (every Nh, weekdays, monthly) in the group's time zone (chrono-tz); retries only for failed guests, `job_failed` after the last attempt; adding a blackout window = weakening (approval), removing not; retries not held by blackout, none while paused; pause/maintenance via API for operators, UI admin-only; retention/GC/verify not interrupted by cancel (after the current step); replication schedules stay UTC** (decided 2026-10-12) | Fewer false alarms, controllable runs. |
| Reports (14e) | **Shared crate `crates/reports` (dashboard, Storage page and reports use the same code); CSV RFC 4180, no BOM, formula-injection guard; protection/storage show the current state, SLA breaches from snapshot + job history; scheduled reports weekly/monthly only (no hourly), via the alerts SMTP server** (decided 2026-10-12) | One source of truth for figures. |
| Diagnostics (14b) | **Root helper `nexus-diag` (path unit, own SELinux domain, no network); 15 checks; checks: admin + SO, bundles/downloads: admin; checker fails open, only failed checks with severity ≥ 3 block an update (rollback never gated); no smartmontools in the image (SMART check skips)** (decided 2026-10-12) | Support without a shell; safe updates. |
| Console gate details (14c) | **Code fetched once by POST (CSRF cannot burn it); recovery key works even with approvals on (it is the break-glass path); binary `/usr/libexec/nexus/nexus-console-gate`; shell via `systemd-run --scope` with RuntimeMaxSec, `unconfined_t` only through the gate; no per-command audit inside the shell** (decided 2026-10-12) | Emergency access that is time-boxed and loud. |
| File index (Phase 15, moved from 18) | **Per-tenant index, written at snapshot commit, sealed with the tenant key and stored in the tenant's store (no file names in plaintext in the catalog); removed with the snapshot** (decided 2026-10-12) | Find a file to restore without knowing which snapshot holds it. |
| Forwarding details (14a) | **Outbox table (triggers on alerts/jobs) + audit by seq; at-least-once, never skips; weakening a sink (disable, remove, new destination, CA/pin/headers) needs approval, adding one does not; a new destination receives the audit history from seq 1; TLS trust = CA, exact cert or SHA-256 pin (no insecure mode); structured-data PEN 32473 is the documentation placeholder until a real enterprise number is assigned** (decided 2026-10-12) | SIEM gets a gap-free, verifiable trail. |
| API tokens / certificate details (14d2) | **Token creation needs password + TOTP (OIDC: session ≤ 15 min); max 20 per user; allow-list of token routes (closed by default); imported web cert in a separate `web.pem` while replication ALPN keeps the self-signed identity cert (existing pins never break); cert install admin-only without approval (audited); no ACME client** (decided 2026-10-12) | Automation without weakening four-eyes; own PKI without breaking replication. |
| Firewall in the UI (Phase 16) | **Inbound only: per-service source restrictions (8443, replication, SSH/others if added); outbound stays automatic default-deny; changes need approval** (decided 2026-10-12) | Restrict admin access without weakening the egress model. |
| Disk layout (Phase 16) | **mdadm + XFS for data/metadata tiers, configured in the UI (create on empty disks, spare, replace/rebuild, grow); system disks only shown (mirrored at install); SMART in the UI + `disk` alerts** (decided 2026-10-12) | In-kernel, mature, SELinux-friendly; no out-of-tree modules in the signed image. |
| Order after Phase 15 | **Hardware + firewall = Phase 16, after file search (Phase 15); former 16–18 become 17–19** (decided 2026-10-12) | User priority. |
| Agent packages (Phase 20) | **Linux agent as .deb + .rpm, Windows agent as .exe installer, built by the release workflow and attached to every release; last phase** (decided 2026-10-12) | Easy installation on sources. |
| Legal hold details (15c) | **Holds in the catalog (`legal_holds` with history), not store locks (those can only grow); admins cannot set, only request release; replication: advisory on the secondary, applied by its SO** (decided 2026-10-12) | Releasable protection with four eyes. |
| File index details (15g) | **One sealed `names` file per snapshot (written at commit, gone with the snapshot); search runs in the scheduler with the tenant key; only local snapshots; offsite/replica copies get it via the daily backfill; viewers/SOs cannot search (like files_list); measured 100 × 200k names in < 2 s** (decided 2026-10-12) | Simple, crash-safe, fast enough without a global index. |
| Restore to a host (15b) | **Any file snapshot (host/nas/share/plugin with download, vm/ct via micro-VM tar) into an agent of the same tenant; on another host: owner = agent restore user, no setuid/devices, only user.* / win.* xattrs** (decided 2026-10-12) | Ends download-only restores safely. |
| Restore options / consistency (15a/d) | **Default name `<name>-restore`; replace-original via approval, never deletes the original, rollback on any failure, not cancellable mid-swap; consistency levels application/crash/inconsistent/unknown (stopped guests = application); policy require_consistency off/warn/fail, relaxing needs approval** (decided 2026-10-12) | Safer restores, honest restore points. |
| Inbound firewall details (16c) | **Service registry: `web` 8443 (UI, API, metrics and replication share the TLS listener → restricted together), `icmp` off by default, `ssh` listed as not running; setting `inbound` (migrates `mgmt_allow`); every change via approval `firewall.inbound`, lock-out guard for `web`; blocked attempts from nft dynamic sets; console reset `nexus-setup reset-firewall`** (decided 2026-10-12) | Restrict admin access without a TLS-blind per-path illusion. |
| Disks details (16a/b) | **Root helper `nexus-disks` (timer + path unit, own SELinux domain, no network); smartmontools + mdadm in the image (smartd off); data array only on empty disks while the store is empty (no store migration); metadata tier deferred (would move the live catalog); arrays by md UUID, disks by serial; rescan/self-test without approval, layout changes with approval + typed serials** (decided 2026-10-12) | Safe hardware management without a shell. |
| Additional Cohesity docs (2026-10-12) | **Urgent small items done immediately (GRUB lock, fleecing space guard, clock skew, Splunk HEC preset + alert category); the rest planned as Phases 21–23 after Phase 20** (decided 2026-10-12, recommended path) | Safety first; feature work keeps the agreed phase order. |
| Tenant recovery key (17e) | **256-bit key as X25519 secret, appliance keeps only the public key, every DEK version sealed (crypto_box sealed box) into `tenant-escrow.<kid>.<v>`; show-once after approval; DR via `nexus-offsite dr --tenant-key` (key on stdin) only for that tenant; after tenant DR offsite goes to a new target/prefix** (decided 2026-10-12) | MSP customers recover their own data without the appliance-wide key. |
| M365 throughput / cross-tenant (18a2) | **Up to 9 app registrations per source (each guest pinned to an app by hash, 429 → next free app); chats opt-in (metered API), download only; cross-tenant restore only into a source of the same appliance tenant (admins too); manifest flag `target_source` (plugin contract v1.6)** (decided 2026-10-12) | First full backups of large tenants in days, tenant migrations. |
| Offsite in the UI (17d) | **Fetch-back protection = store lock extended by 7 days (no new flag); attach = approval without key, then the requester submits the recovery key once (sealed to the scheduler, 0600 one-time file, keyd re-wraps under the new KEK, never stored/logged); attached tenants keep the old appliance escrow on the target (key rotation would break it, documented); attach with a per-tenant key not in the UI yet** (decided 2026-10-12) | DR without the console. |
| Vault mode / tenant deactivation (17c/f) | **Vault mode: preconditions (secondary only, all tenants replicated, no peers, approvals on, web allow-list set) checked on request and approval; restores/downloads via `vault.restore` approval (browsing stays direct); switching off = approved request + `nexus-setup vault-disable` with the recovery key at the console (web-api never becomes a recovery-key oracle). Tenant deactivation needs approval (backups stop), reactivation direct; retention/GC/verify keep running; one info alert** (decided 2026-10-12) | One stolen admin account cannot read out or weaken the vault copy. |
| M365 robustness (18a1) | **Item/folder failures → job ok with warnings (plugin contract v1.7 `Warnings`), the next run refetches them; still fatal: 401, mass failures, broken downloads; unlicensed users and team sites excluded from all/tags groups unless selected; Recoverable Items (Deletions); private/shared channel files; M365 group guests (conversations + calendar download-only — no app permission to write them; group calendar reads likely refused on real tenants)** (decided 2026-10-12) | One bad item no longer costs a whole mailbox's restore point. |
| Urgent hardening (2026-10-12) | **GRUB password derived from the recovery key (HMAC-SHA256 label `nexus-grub-password-v1`, keyboard-layout-safe alphabet; ADR-013), boot entries unrestricted, rescue masked, emergency refuses locked root, `rd.shell=0 rd.emergency=reboot`; fleecing guard per PVE source (skip < 15 % / 20 GiB, stop < 5 %); compliance clock slew 0.1 % and kept running by the scheduler; `clock_skew` warning/critical only for jumps or a clock ahead, a lag after downtime is info; Splunk HEC format + alert `category`** (decided 2026-10-12) | Close the console bypass; protect production VMs during backups; trustworthy lock time. |
| Windows / close vault (17a/b) | **One window type (pause > limit > base; a limit window replaces the base rate); weakening judged at every boundary over 8 days (a time-zone change usually counts); window changes apply from the next job; "Close vault (pause pulling now)" per replication source is distinct from vault mode; closing is direct for admin/SO, reopening needs approval** (decided 2026-10-12) | Short exposure of the secondary; no WAN saturation. |
| PostgreSQL 1.2.0 (18b) | **`every Nm` schedules (5–30); `Gfs.recent` hours keep-all class adds no lock beyond the 14-day commit lock; generic `snapshots.meta` (plugin contract v1.8 `SnapshotMeta`, catalog only); marker transaction per run so an idle server can be recovered to the run's time; HA via `hosts`, primary chosen per operation, old slot after failover dropped by the admin** (decided 2026-10-12) | Point-in-time RPO in minutes. |
| Self-hosted CI runner (2026-10-12) | **All workflows on `runs-on: self-hosted` (Actions minutes limit); if the runner lacks tools, only report it — all gates run locally before every push** (decided 2026-10-12) | Private repo on paid minutes. |
| Release 0.1.0-alpha (2026-10-12) | **After the final VM labs pass: push tag `v0.1.0-alpha` → draft release (image + ISO); maintainer signs, then publish** (decided 2026-10-12) | Same procedure as 0.0.1-alpha. |
| Scope while the maintainer is away (2026-10-12) | **Phases 19, 20, then 21–23, each with labs** (decided 2026-10-12) | |
| Windows agent installer (Phase 20) | **MSI (WiX), suited for GPO/Intune; .deb/.rpm/.msi get SHA256SUMS + cosign blob signatures at release time (no GPG/Authenticode keys yet)** (decided 2026-10-12) | Enterprise deployment. |
| Endpoint UIs (Phase 24) | **Linux TUI + Windows/Linux desktop GUI showing the last backup sessions (pushed by the appliance after each backup), next run, appliance reachability; "Back up now" is a local request picked up by an appliance poll of every agent (agent still never connects out); roaming laptops only on LAN/VPN (retry when reachable, UI shows "not reachable since"); GUI in Rust + iced with a tray icon (shared Windows/Linux), talking to the local agent service over a socket/named pipe; no end-user self-service restore (restores stay admin-only on the appliance)** (decided 2026-10-12, user request; style inspired by Veeam Agent for Linux/Windows) | End users see protection status on their machine. |
| Endpoint UI details (Phase 24a–c) | **Session summaries are delivered by the 2-minute poll session (not inside the backup session); backoff 4/8/15 min while unreachable; laptop options (min battery, skip metered, run missed, retry window) per agent, not per group; a group whose agents are all skipped is recorded as a cancelled job without alert; the appliance enforces its own 10-minute request limit as well as the agent's; socket `/run/nexus-agent/ui.sock` root:nexus-agent-ui 0660 in a 0711 runtime dir, Windows pipe with interactive users read/write-data only; Linux tray via ksni (pure Rust, GNOME needs the AppIndicator extension; since 2026-10-21 our own StatusNotifierItem on zbus 6, ksni stayed on the unmaintained zbus 5); Windows GUI autostart via HKLM Run key; desktop package `nexus-agent-desktop` (glibc ≥ 2.31)** (decided 2026-10-13, recommended path) | No new outbound connection from endpoints; small dependency footprint. |
| Fleet enrollment (Phase 24d) | **Admin-created fleet secrets (expiry ≤ 30 days, optional max uses, ranges ≤ 4096 addresses, template group, hostname rules), no approval (like tokens); mutual HMAC proofs bound to the TLS session, the secret never crosses the wire; found agents are accepted by an admin/tenant admin or auto-accept (refused in vault mode); each accepted agent gets its own copy of the template source+group; the use limit only blocks new acceptances; fleets are immutable (revoke + recreate); CSV bulk enrollment ≤ 500 rows, all-or-nothing** (decided 2026-10-13, recommended path) | Mass deployment via GPO/Intune/Ansible without per-host tokens in deployment configs. |
| Ransomware signals (Phase 21a) | **Anomaly flags are columns on the snapshot; restore and legal-hold dialogs default to the newest clean snapshot; a security officer clears a flag with a note (no approval, audited, alert stays); file-level signals: known ransom-note names (built-in list + admin patterns; removing a pattern needs approval) and mass renames (≥ 50 files and ≥ 10 % deleted with ≥ half as many new files with unseen extensions, constants); snapshot diff as a read-only job, 200 paths per page; secure restore (YARA) left to 21e** (decided 2026-10-13, recommended path) | Earlier detection, safer default restore point. |
| Passkeys (Phase 21c) | **WebAuthn as a second factor next to TOTP (password always required; no username-less sign-in); ES256/EdDSA verified with ring, attestation none (synced passkeys allowed), no webauthn-rs (OpenSSL); RP ID setting (empty = served host name, no passkeys by IP address); "require passkeys for admins/security officers" applies at once but is refused if the acting admin has none; turning it off or changing the RP ID needs approval; TOTP stays mandatory at activation; SSO accounts out of scope; challenges in memory** (decided 2026-10-13, recommended path) | Phishing-resistant MFA for privileged roles. |
| Bare-metal recovery / P2V (Phase 19a) | **Linux agents record the machine layout with every backup (`.nexus-system/layout.json`); a rescue ISO (hybrid BIOS+UEFI, built in CI, unsigned → Secure Boot off) boots `nexus-agent rescue`, enrolls with a one-time token (check-in carries only a lookup hash), recreates partitions/LVM/file systems with original UUIDs, restores, reinstalls the boot loader with a generic initramfs; P2V creates a PVE VM with a config disk for unattended recovery; LUKS/md/ZFS are not recreated; agent protocol v1.6 (capabilities `layout`, `rescue`); the agent unit drops `ProtectKernelModules` (it hid /usr/lib/modules from backups; module loading stays blocked by capabilities + seccomp)** (decided 2026-10-13, recommended path) | Restore a whole Linux machine without a manual reinstall. |
| Incident mode and posture (Phase 21b) | **Security officer enters incident mode at once (holds, pauses groups, ends other sessions, deletes API tokens, critical alert); leaving always needs a second person, even with approvals off; holds stay after leaving (each released by its own approval); posture checks are pass/warn only and never block updates (`offsite_lock` passes only for S3 Object Lock, dormant admins default 90 days); `max_sessions` (default 5, oldest dropped) and `dek_rotation_days` (default 365, info alert, rotation stays a console keyd command) are admin settings without approval** (decided 2026-10-13, recommended path) | One-click containment; visible security drift. |
| CVE scan and chunk repair (Phase 21d) | **grype (pinned by digest, in a container, nothing installed on the runner) scans every release image and fails on critical CVEs with a fix; the weekly `cve.yml` rescans `:stable` (no scan per main push: it would need a full image build); OpenSCAP CIS L1 report informational only. Verify moves corrupt chunks aside and lists them; a damaged snapshot is never used as an incremental base (PVE full read, agent without cache) or uploaded offsite; `chunk_repair` (admin) fetches chunks from offsite packs or, on a secondary, from the primary inside its window, and is queued automatically after new damage; a primary cannot repair from its secondary (it serves no data)** (decided 2026-10-13, recommended path) | Known-vulnerable images blocked; bit rot healed without a new full backup. |
| Malware scan and Entra ID (Phase 21e) | **YARA scan with the yara CLI inside the restore micro-VM (yara-x failed cargo deny: wasmtime advisories, unmaintained bincode, rsa); admin-uploaded rules only (≤ 50 files, 1 MiB), no feed; VM disks mounted in the VM, file trees streamed as tar; limits 64 MiB/file, 60 s/file, 4 h/scan, one scan at a time; a hit flags the snapshot (21a flag) and raises a critical `malware` alert; restore option "scan first" = refuse or link down (VM/CT), the scheduler holds the restore until a verdict, a timeout counts as a hit; no automatic scan after each backup yet. Entra ID objects as M365 guest type `e.directory` (opt-in, JSON per object, export only, no restore to Entra)** (decided 2026-10-13, recommended path) | Secure restore without network access during the scan. |
| Recovery assurance (Phase 25) | **Restore tests boot VMs from instant-recovery overlays (never moved), containers by full restore, networks down or on an admin-named isolated bridge, `nxtest-` names / VMIDs from 990000, checks via guest agent (running, agent ping, listening ports, custom command), always destroyed; scheduled per protection group every N days, one guest at a time; recovery plans = waves with delays, target node/storage, test bridge, network map, per-guest checks; daily readiness check 05:30 UTC; test runs isolated through all waves; Execute = full restores under the original VMIDs, needs approval `recovery_plan.execute`, stops at a failed wave; DR report as HTML; severities: test/readiness warning, failed execution critical** (decided 2026-10-13, recommended path) | Proven restorability instead of assumed. |
| Network configuration (Phase 22a) | **Root helper `nexus-net` writes NetworkManager keyfiles + `nmcli reload/up` (smallest SELinux policy, rollback = restore old files); its applied config is the source of truth for egress binding; bonds/VLAN/MTU/routes, at most one interface per role (management, data, replication), only management has a gateway; changes need approval, a management change rolls back unless confirmed within 120 s (survives reboot); data, offsite and replication egress bound to role interfaces (others unbound, unconfigured role = any interface); inbound not interface-bound (residual risk T46); MTU probe in the helper, diag only reads it** (decided 2026-10-13, recommended path) | Separate backup networks without a shell on the appliance. |
| PVE/NAS operations (Phase 22b) | **Per-source cap limits parallel guests (backups of one source already run one at a time) plus per-PVE-storage caps; read-limit windows can only limit, never pause (a paused read stalls a backup and fills fleecing storage; use blackout windows); restore priority (admin/operator, 1–24 h, renewable, auto-expiry, no approval) holds scheduled backups, GC, verify, indexing, offsite, replication; a changed vmgenid/SMBIOS UUID restarts the chain with a full read and raises `vmid_reused`; NAS split creates new sources and keeps the original; TrueNAS can back up from existing periodic snapshots; instant disk recovery attaches one snapshot disk to a protected VM of the same tenant (tenant users may request it; approval in vault mode). Not built: removable-disk offsite, online store migration, small-chunk packing, PSI backoff** (decided 2026-10-13, recommended path) | Protect production during backups and DR. |
| Service-provider operations (Phase 23a) | **Monthly usage export per tenant (CSV, UI, scheduled e-mail; downloads audited); per-tenant OIDC IdP (`tenant_idps`, tenant roles only, changes need approval, login picks the IdP by e-mail domain or tenant name — reveals whether a domain is a customer, residual risk T47); onboarding wizard; restore point simulator in the policy dialog and in retention-weakening approvals (retention logic split into `crates/retention`); keep-until backups up to 10 years, approval beyond `keep_until_max_days` (90), raising that limit needs approval; `/api/openapi.json` kept in sync with the token allow-list by a test; `nexusctl` CLI on API tokens (not packaged yet)** (decided 2026-10-13, recommended path) | Running the appliance for several customers. |
| Edge proxy (Phase 26) | **`nexus-edge` on its own hardened bootc VM: public mTLS agent port 443, control port 7445 dialled by the appliance; it pairs and relays the end-to-end TLS session between appliance and agent (relayed bytes are TLS records, no keys or data on the edge), per-IP/per-cert rate limits and a connection cap, signed updates pushed by the appliance; agents get `edge`/`edge_sha256` via protocol v1.7 (SetEdge) and keep an outbound rendezvous; the appliance dials direct first, then via the edge; edge targets are firewall role `data`; edge image CI build, edge OS updates and edge HA are open** (decided 2026-10-13, recommended path) | "Back up now" from anywhere without exposing the appliance. |
| MySQL/MariaDB and Windows workloads (Phase 23b) | **Signed plugin `mysql`: logical dumps over SSH or TLS, physical backups with mariadb-backup/XtraBackup plus binlog (incremental), PITR into a new directory to a time/position, recoverable range in snapshot meta, system databases never offered; Galera/Group Replication primary selection not supported. Windows workloads documentation only (no Windows lab): AD DC restore runbook (VM-GenerationID, USN rollback, authoritative restore), SQL Server/Exchange guidance (VSS copy mode never truncates logs; use native log backups). Open: MSSQL log chain/PITR, Exchange full-VSS, Hyper-V host-level, Windows BMR, arm64 agents** (decided 2026-10-13, recommended path) | Most-requested database after PostgreSQL. |
| Veeam B&R comparison (2026-10-12) | **Configuration backup now (DR blocker); restore tests + recovery plans as Phase 25; the rest placed into Phases 21–24 (docs/veeam-comparison.md)** (decided 2026-10-12, recommended path) | |
| Configuration backup (2026-10-13) | **Daily sealed bundle (catalog copy, totp/secrets keys, agent CA, replication keys, SSH keys, TLS identity) sealed to a key pair derived from the KEK so only the recovery key opens it; uploaded to every tenant offsite target (`config/<appliance-id>/`, 14 daily + 12 monthly, Object Lock respected); restore via `nexus-setup restore-config` / wizard key b; tenant data keys come back from the offsite escrow (`config_rekey`, keyd accepts only keys unwrapping under its KEK); the first-boot wizard gets network + CAP_NET_ADMIN to fetch the bundle (outbound opened for that one target); plugin binaries are not in the bundle (re-upload)** (decided 2026-10-13, recommended path) | Closes the DR gap "appliance configuration is lost with the appliance". |
| Edge proxy (Phase 26) | **Separate single VM (DMZ or client network), internet-facing threat model, managed by the appliance which connects out to it; relay only (end-to-end TLS appliance↔agent); built as a separate later phase after Phase 25** (decided 2026-10-12) | Roaming laptops without VPN, without inbound connections to the appliance. |
| Agent packages (Phase 20) | **nfpm (pinned image) for .deb/.rpm x86_64 + aarch64 (static musl), wixl (msitools) for the MSI — everything in rootless podman; the unit/service is installed but only enabled after `init --token -`; MSI carries no token property (tokens are one-time, MSI properties end up in logs/GPO); package-installed agents refuse self-update unless `self_update = on` (package manager owns updates); cosign blob signatures only** (decided 2026-10-13) | Clean enterprise deployment. |
| Legal hold (Phase 15) | **Set by the security officer alone (adds protection); release needs approval; advisory to secondaries** (decided 2026-10-12) | Incident tool beyond retention locks. |
| API tokens (Phase 14) | **Scoped read/operator, expiring, hashed; can never approve, change settings/users/tokens or download** (decided 2026-10-12) | Automation without weakening four-eyes. |
| Vault mode (Phase 17) | **One-way profile for secondaries; switching off needs approval + recovery key** (decided 2026-10-12) | Protects the vault copy against one stolen admin account. |
| Mail export (Phase 19) | **mbox / .eml tree first, then a PST writer** (decided 2026-10-12) | PST writing is large; open formats cover most needs. |
| Mail export details (Phase 19c) | **Conversion runs as a plugin `export` op with no network access and without the source's secrets (contract v1.9); PST is Unicode, mail only, split at `pst_max_gb` (default 20 GiB); exported mails are marked read; categories/flags/read state are not exported (Graph MIME lacks them); attached messages become .eml attachments; non-mail items are copied as stored** (decided 2026-10-13, recommended path) | Smallest correct PST; Outlook import still to be lab-verified. |
| Tenant admin (Phase 19b) | **`tenant_admin` manages its tenant's users, sources and groups with policies the admin assigned (policy tiers as templates); may create sources (threat model T30); no offsite, keys, retention cuts or approvals. "View as tenant" = role intersection, read-only, visible in the tenant's audit; downloads and token creation are off while impersonating. Tenants get an immutable uid; deleted tenants leave a tombstone forever (names cannot be reused, crypto bindings stay name-bound); replication checks the uid** (decided 2026-10-13, recommended path) | Service-provider operation without giving customers appliance admin rights. |
| NAS shares (Phase 7) | **Kernel NFS/SMB mounts, read-only, in a private mount namespace by a small privileged helper with its own SELinux domain** (decided 2026-10-09) | Mature, fast clients; isolation via namespace + SELinux. |
| Windows testing (Phase 7) | **Build + unit tests only, no Windows test VMs for now** (decided 2026-10-09) | Real Windows testing later; plan's test matrix for Windows is deferred. |
| Agent trust (Phase 7) | **Appliance-run private CA + one-time enrollment token**, agent pins appliance cert (decided 2026-10-09) | Agent never connects out; mTLS only. |
| Windows build (Phase 7) | **Cross-compile in a podman container (mingw-w64)** (decided 2026-10-09) | No host installs. |
| Penetration test (Phase 6) | **Internal security review + scope document; external test commissioned by the project owner** (decided 2026-10-09) | Plan requirement kept; external test before first production tenant. |
| Agent updates (Phase 27) | **Signed agent releases ship with the appliance image (or signed upload); package installs updated with their own package type (deb/rpm/MSI); `self_update = off` on the host always wins; downgrades only as an approved rollback; manual rollouts by default, automatic per tenant/group optional** (decided 2026-10-14, maintainer: "finish the tasks and phases"; docs/agent-update-plan.md) | The appliance chooses which signed release goes where but can never create one; package databases stay truthful. |
| File index (Phase 31) | **Embedded Tantivy in a `nexus-index` service with sealed segments; per-snapshot sealed name indexes remain the source of truth; guest file systems parsed read-only by a sandboxed helper without keys (`nexus-fsindex`); micro-VM stays the fallback; no OpenSearch/Meilisearch** (decided 2026-10-14; docs/file-index-v2-plan.md) | No extra network service on a hardened box; names stay encrypted at rest; Cohesity's kernel-mount indexing hangs on crash-consistent XFS. |
| Commvault Tier 1 (Phase 28) | **Scheduled YARA scans per group with a clean/hit/unscanned state per snapshot, IOC hash hunting over per-file SHA-256 in the name index, tenant lockdown (incident mode per tenant), new-device sign-in alert** (decided 2026-10-14; docs/commvault-comparison.md) | Restore-latest-clean and IOC response without restores; MSP incidents stay per customer. |
| NetBackup Tier 1 (Phase 29) | **Periodic full read with a change-tracking drift alert, approval for restoring malware-flagged snapshots to production, scan back to the last clean snapshot, incident-mode freezes, deterministic privileged-activity risk signals** (decided 2026-10-14; docs/netbackup-comparison.md) | Catches silently broken change tracking; ransomware restores without reinfection. |

---

## 3. Requirements

### 3.1 Functional

- **Sources (phase order):** Proxmox VE (VMs and LXC), TrueNAS Community (ZFS snapshots), Linux physical servers (agent), NAS shares via NFS/SMB (file-level), Windows physical servers (agent, VSS, file-level), Microsoft 365 (last).
- **Backup modes:** incremental-forever with full logical snapshots; VM backups use dirty bitmaps; file backups use change detection (ZFS diff, btrfs find-new, NTFS/ReFS USN journal, metadata cache for NAS).
- **Restore modes:** full VM/host restore, single-file restore from VM images and from file backups, instant recovery (VM boots directly from the backup over NBD), restore directly from the offsite tier, disaster-recovery restore without the original appliance.
- **Retention (GFS):** 14 daily, 4 weekly, 6 monthly, 2 yearly; period-based semantics ("last backup of each of the last N periods that have backups"); identical retention local and offsite; configurable per policy and per target.
- **Multi-tenancy:** up to 5 tenants per appliance initially; cryptographic separation per tenant; tenant-scoped RBAC.
- **Offsite:** encrypted, deduplicated, incremental upload of pack files to one Hetzner Storage Box per tenant; bandwidth limits and schedules; resumable uploads; independent verification; offsite inventory monitoring.
- **Replication to a second appliance (later):** the secondary appliance pulls from the primary; the primary holds no credentials for the secondary.

### 3.2 Non-functional

- Data set: 5 tenants × 1–2 TB raw (5–10 TB total), growing.
- Daily backup window must comfortably hold the daily delta (~2 % change rate assumed; measure in production).
- Throughput target: initial full of 10 TB within one weekend on local network; daily increments of 100–200 GB raw within a few hours.
- Steady-state capacity after two years (full GFS retention): ~18–20 TB for 10 TB raw → appliance sized for ~40 TB usable.
- Appliance must survive a single disk failure in any tier without data loss (RAID6 / RAIDZ2 for data, mirrors for metadata and OS).

### 3.3 Security

- Only one inbound port (management UI/API). Everything else outbound, allow-listed per configured source/target.
- Full-disk encryption, TPM-sealed, Secure Boot measured.
- Retention locks enforced in the storage layer; locks can only be extended, never shortened.
- Tamper-resistant compliance clock, independent from system time.
- Four-eyes (quorum) approval for destructive or weakening actions — optional (off for single-user appliances; disabling needs two people).
- Hash-chained audit log, forwarded to an external syslog/SIEM.
- MFA (WebAuthn or TOTP) for all interactive accounts; OIDC later.
- No interactive root; emergency access only via local console.
- Least-privilege credentials for every source (scoped PVE API tokens, SSH keys with `restrict`, forced commands, `permitopen`).

---

## 4. System Architecture

### 4.1 Component overview

The appliance consists of three layers. Every box runs as its own OS process with its own system user and its own SELinux domain, sandboxed by systemd.

**Control plane**
- `web-api` — Web UI and REST API (`axum`), authentication, RBAC, quorum workflows.
- `scheduler` — policy engine, job scheduling, retention computation, protection groups.
- `catalog` — SQLite catalog (sources, policies, snapshots, jobs, users), audit log writer, metrics endpoint.

**Data plane**
- `connectors` — one worker type per source class: Proxmox, Linux agent, Windows agent, NAS, TrueNAS, (M365 later).
- `chunkstore` — dedup index, chunk storage, compression, encryption, verify, garbage collection, retention locks, compliance clock.
- `offsite` — pack builder and uploader (SFTP to Storage Box), offsite inventory, offsite verification.
- `restore` — NBD server for instant recovery, file-level restore service, restore micro-VM for single-file restore from images.

**Base**
- `keyd` — the only process talking to the TPM; unwraps tenant keys and hands them to `chunkstore` over a local Unix socket; keys exist only in memory.
- OS — bootc image, SELinux enforcing, LUKS2, nftables, chrony with NTS.

### 4.2 Process isolation rules

- `web-api` never touches chunks or keys; it only calls `scheduler`/`catalog`/`restore` over local sockets.
- `connectors` have no key material; they hand plaintext data to `chunkstore` over a local socket (or run chunking themselves and submit chunks + IDs).
- `chunkstore` is the only process with tenant DEKs in memory.
- `offsite` only ever sees encrypted packs and encrypted indexes.
- `keyd` is the only process with TPM access.
- Every service: dedicated user, `ProtectSystem=strict`, `NoNewPrivileges=yes`, `SystemCallFilter`, private `/tmp`, own network namespace where possible, SELinux domain with explicit transitions only.

### 4.3 Storage abstraction (Rust traits)

```text
trait ChunkBackend  // local: one file per chunk (fast random access, simple GC)
trait PackBackend   // remote: chunks packed into 32–64 MiB pack files
                    // implementations: StorageBoxSftp (phase 1), S3 (later), Tape (later)
```

The local chunk store and the remote pack store share the same chunk IDs, encryption and index formats. Only the physical layout differs.

---

## 5. Chunk Store Design

### 5.1 Data path

```text
source bytes → chunking → keyed hash (chunk ID) → dedup lookup
            → [new chunk] compress (zstd) → encrypt (AEAD) → write
            → append chunk ID to snapshot index
```

### 5.2 Chunking

| Data type | Method | Default parameters | Notes |
|---|---|---|---|
| VM disks / block devices | Fixed-size, offset-aligned | 4 MiB (evaluate 1 MiB) | Aligns with QEMU dirty bitmaps; VMs from the same template dedup well because blocks are aligned. |
| Files (agents, NAS, TrueNAS) | FastCDC | avg 512 KiB, min 128 KiB, max 4 MiB | Content-defined boundaries survive inserts/shifts. Very small files = one chunk each. |

Chunk sizes are configurable per datastore. At this project's scale (~10 M chunks) the dedup index is tiny (~0.5 GB), so chunk sizes can be chosen for dedup quality rather than RAM.

Known limitation: the same file inside a VM image and in a file-level backup does not dedup against each other (different chunk boundaries). Accepted; common to all systems of this design.

### 5.3 Index structures

- **Dedup index:** chunk ID → location (local path / pack + offset), uncompressed size, compressed size. Held on NVMe; Bloom filter in RAM answers "is this chunk new?" without disk access.
- **Fixed index:** ordered list of chunk IDs for a block device; chunk N covers offset `N × chunk_size`. Enables O(1) offset lookup for NBD/instant recovery.
- **Dynamic index:** stream of (path, metadata, chunk list) entries for file trees. Includes a metadata cache (path, size, mtime, inode → chunk list) so unchanged files are never re-read on the next run.
- **Snapshot manifest:** tenant, source, type, timestamp, index references, retention classification (daily/weekly/monthly/yearly flags), lock-until timestamp, offsite status, verify status.

All indexes are encrypted with the tenant DEK before being written to disk or offsite.

### 5.4 Garbage collection (mark-and-sweep)

1. Walk every snapshot manifest and index that is still retained → mark referenced chunk IDs (snapshots under retention lock are always marked).
2. Chunks not marked are candidates; they are deleted only after a **grace period** (e.g. 24 h) so that running backups which already referenced a chunk but have not yet committed their index cannot lose it.
3. GC runs are logged and metered; a GC that would delete more than a configurable share of the store requires quorum approval (safety valve against catastrophic policy errors).

Offsite GC: whole packs are deleted when all chunks are dead; partially dead packs are re-packed only above a threshold (e.g. 50 % dead). Packs are grouped at upload time by protection group and retention class so they tend to expire together. Yearly snapshots pin chunks for two years, so occasional repacking is unavoidable — acceptable on a Storage Box (no egress cost, only time and connections).

### 5.5 Retention locks and compliance clock

- Every snapshot receives a lock on creation for at least the minimum retention (14 days).
- When the retention engine classifies a snapshot as weekly/monthly/yearly, its lock is **extended** accordingly (4 weeks / 6 months / 2 years).
- Locks can only be extended. Shortening or deleting a locked snapshot is impossible through any API, including for administrators.
- The chunk store maintains its own **compliance clock** based on a monotonic clock, persisted frequently; it accepts only small corrections from system time. A manipulated NTP server or `date` command cannot expire locks early.
- Local and offsite enforce locks independently.

### 5.6 Verification

- Every chunk carries its own authenticated tag (AEAD) and keyed hash; reads always verify.
- Scheduled verify jobs re-read a configurable fraction of chunks per week (full verification over N weeks).
- Offsite: sampled verification (download random packs, decrypt, verify hashes) to detect bit rot, misconfiguration and key problems early.

---

## 6. Encryption and Key Management

### 6.1 Envelope model

```text
Recovery key (offline, paper/HSM/external KMS)
        │ wraps
Appliance KEK (sealed in TPM, bound to Secure Boot + image measurement)
        │ wraps
Tenant DEK (one per tenant; used for chunk ID keying, chunk AEAD, index encryption)
```

- Chunk IDs: BLAKE3 keyed hash with a tenant-specific key derived from the DEK.
- Chunk payload: XChaCha20-Poly1305, random 192-bit nonce per chunk, chunk ID and tenant ID as associated data.
- Indexes, manifests and the catalog copy for offsite: encrypted with the tenant DEK.
- Hetzner (or any storage provider) sees neither content nor meaningful file names.

### 6.2 Key lifecycle

- Recovery key is generated during first boot, shown exactly once, and the wizard requires partial re-entry to prove it was recorded.
- Tenant DEKs can be rotated (new chunks use the new key; old chunks remain readable via key versioning in the manifest).
- Loss scenario: new hardware + recovery key + offsite credentials = full restore. This path is tested as part of DR drills.

---

## 7. Source Connectors

### 7.1 Proxmox VE (first source)

**Integration basis:** the official Proxmox VE Backup Provider API (available since PVE 8.4). Proxmox ships an example Borg provider plugin (`src/PVE/BackupProvider/Plugin/Borg.pm` in `pve-storage`) that serves as a developer guideline — it is explicitly not supported for production but documents the API end to end. A backup provider consists of two parts:

1. A **storage plugin** (`PVE::Storage::Custom::*`, Perl) for front-end integration (storage.cfg config, listing/deleting backups via UI/API/CLI, feature flag "has backup provider", `APIVERSION`/`APIAGE`).
2. A **backup provider plugin** (`PVE::BackupProvider::Plugin::Base`) with separate hooks for VMs and containers for backup and restore. API docs live as POD inside `Base.pm`.

**Inverting the push API into a pull flow (all connections originate from the appliance):**

1. Appliance calls the PVE API (port 8006) with a least-privilege token (`VM.Backup`, `VM.Audit` on the required paths) to start the backup job for the provider storage.
2. The on-node plugin makes **no outbound connections**. It lets PVE prepare the snapshot and the NBD export (with dirty bitmap information) and then waits.
3. The appliance opens an SSH session to the node; a forced-command helper connects to the local NBD Unix socket and pipes it over the session's stdin/stdout (no SSH forwarding at all, decided 2026-10-08). The appliance reads only the dirty blocks, building the new fixed index.
4. Plugin signals completion; PVE finalizes the job and keeps the task log.

Dirty bitmaps are managed by PVE; the appliance only consumes them. Note: bitmaps are lost on VM/host restart; the next backup then reads the full disk but still transfers only changed chunks.

**Implementation findings (Phase 2, details in `docs/pve-connector.md` and `docs/pve-backup-provider-api.md`):**
- Provider VM backups require **fleecing** on a local thin storage of the node (`nexus-fleecing-storage`); VM templates cannot be backed up this way.
- The exports are snapshot-access: only dirty areas are readable. The appliance reads dirty byte extents and completes partly dirty chunks from the previous snapshot.
- QEMU commits the bitmap as soon as `backup_vm` returns, before vzdump's post-steps, so the appliance commits its snapshot **before** releasing `backup_vm`, and keeps it even if vzdump later reports failure. Retention is appliance-only: the node plugin never prunes or deletes.
- Nodes must answer listing/config queries offline: the appliance pushes an `index.json` catalog to every node after each run.
- PVE API workers run Perl in taint mode; all plugin input from files must be untainted.
- Full VM restore: PVE only accepts a file/block device as source, so the node attaches the appliance's NBD export (served over the SSH session) to `/dev/nbdX` with its own `qemu-nbd`. Live restore is refused by PVE for providers.
- Token privileges (lab, to be minimized): VM.Backup, Datastore.AllocateSpace on backup + fleecing storage, SDN.Use on the bridge zone for restore.

**SSH hardening on nodes:** dedicated user, key restricted in `authorized_keys` with `restrict` (no forwarding of any kind), forced command that only offers: read job status, pipe a named NBD export of the current job, signal completion. (`permitopen` cannot restrict Unix-socket forwarding, hence stdio piping instead of `ssh -L`.)

**Instant recovery:** the appliance's NBD server is exposed on the node over the SSH session (helper relay to a local socket, as for full restore — no `ssh -R`, the key stays `restrict`ed); the VM starts from that disk, data is migrated to PVE storage in the background. Direction of the TCP connection remains appliance → node. **Open for Phase 3:** PVE refuses provider live-restore, so the VM must be started from the attached device by other means (e.g. a temporary VM config on `/dev/nbdX` + `qm disk move`).

**Containers (LXC):** file-level via the provider API directory mechanism: the node streams the container directory as one tar stream (keeps owners, ACLs, xattrs, device nodes, hardlinks) through the SSH helper; the appliance chunks the stream with FastCDC into a dynamic index (same model as PBS pxar). Restore streams it back; the node extracts into a staging directory (`directory` restore mechanism, unprivileged only).

**Deliverable:** `.deb` package for the on-node plugin, built with `dpkg-deb`; supports **PVE 9.x only** (decided 2026-10-08; 8.4 is not targeted).

### 7.2 Linux agent (physical servers)

- Static Rust binary (musl target), one binary for all distributions.
- Listens on a port; accepts **only mTLS** connections presenting the appliance certificate. Never connects out.
- Snapshot providers: LVM thin/thick, ZFS, btrfs. Change detection: `zfs diff`, `btrfs subvolume find-new`; otherwise metadata cache.
- **Fallback without snapshot capability** (plain ext4/XFS on a partition): read files live, flag files that changed during read as "inconsistent", run database dump hooks (PostgreSQL, MySQL/MariaDB, etc.). Snapshot status is shown prominently in the UI per host.
- Chunking runs **on the agent**: the appliance connects, the agent reports chunk IDs, the appliance requests only the missing chunks (bandwidth-efficient for remote sites).
- Agent is remotely updateable from the appliance (signed binaries).

### 7.3 Windows agent (physical servers)

- Rust, cross-compiled; VSS via COM (`windows` crate). File-level only; no CBT driver.
- Change detection via **NTFS/ReFS USN journal** (built into the file system, no driver).
- Application consistency via VSS writers (SQL Server, Exchange, AD) — otherwise databases are only crash-consistent; the UI must show which writers participated.
- Minimum supported version: **Windows Server 2016** (2012 R2 out of support since Oct 2023). Supported: 2016/2019/2022/2025.
- Same mTLS listen model and agent-side chunking as Linux.

### 7.4 NAS (NFS / SMB shares)

- Appliance mounts shares read-only (kernel NFS/CIFS client) and scans them.
- Metadata cache (path, size, mtime, inode → chunk list) so unchanged files are never re-read.
- Parallelized scan is critical for shares with millions of files.
- No consistent point-in-time without NAS-side snapshots; documented limitation.

### 7.5 TrueNAS Community (ZFS)

- Appliance creates a ZFS snapshot via the TrueNAS JSON-RPC API (API key with SNAPSHOT_WRITE/SNAPSHOT_DELETE/DATASET_READ), determines changes with `zfs diff` against the previous snapshot and reads changed files from `.zfs/snapshot/…` over a restricted SSH user (forced command; tools via sudo — see `docs/truenas-connector.md`).
- The last backed-up snapshot is kept on TrueNAS as reference for the next run.
- `zfs send` streams were considered and rejected (poor fit with dedup and forever-full).

### 7.6 Microsoft 365 (last phase)

- Graph API; separate data models for Exchange, SharePoint, OneDrive, Teams; throttling handling. Planned as its own project phase after everything else is stable.

---

## 8. Restore

| Mode | Mechanism |
|---|---|
| Full VM restore | Write disks back over SSH tunnel + NBD or via the provider API restore hooks. |
| Instant recovery | Reverse SSH tunnel exposes appliance NBD server on the node; VM boots immediately; background migration to PVE storage. Optional NVMe cache tier on the appliance for acceptable latency. |
| Single-file restore from VM images | Image is exposed as a virtual block device from the fixed index and mounted inside a small, isolated **restore micro-VM** on the appliance (drivers for NTFS, ext4, XFS, LVM, ZFS). Foreign file systems are never mounted on the appliance host itself. |
| File-level restore | Directly from dynamic indexes; to original host via agent, to NAS, or as download. |
| Restore from offsite | SFTP range reads into pack files; only required chunks are fetched. |
| Disaster recovery | Fresh appliance (or CLI tool) + recovery key + Storage Box credentials rebuilds catalog, indexes and data for a tenant. |

---

## 9. Offsite Tier — Hetzner Storage Box

### 9.1 Facts that drive the design

- Protocols: FTP(S), SFTP, SCP, Samba/CIFS, WebDAV, rsync over SSH, BorgBackup.
- **10 concurrent connections per box**, 100 sub-accounts, 30–40 snapshots depending on size (automated snapshots available).
- Largest standard plan BX41 = 20 TB; smaller plans 1/5/10 TB; upgrade/downgrade without data loss.
- No object lock; no server-side processes.

### 9.2 Design

- **One Storage Box per tenant.** Independent connection limits, isolation, per-tenant snapshots, per-customer billing, independent sizing (1 TB raw → ~2 TB stored → 5 TB box; 2 TB raw → ~4 TB stored → 10 TB box). The appliance warns at 75 % usage.
- **Pack files** of 32–64 MiB with a pack index; uploaded over ~4 parallel SFTP connections (reserve connections for restore/verify). Packs grouped by protection group and retention class.
- **Appliance-side intelligence.** The box is "dumb": the appliance keeps a local inventory of what is offsite and performs dedup decisions itself, but also stores encrypted indexes, manifests and a catalog copy on the box so the copy is self-describing.
- **Append-only behaviour.** The appliance never overwrites existing files; deletions happen only through delayed GC.
- **Box snapshots as the immutability layer.** Automated snapshots are configured in the Hetzner console — the appliance has no Hetzner API credentials and therefore cannot delete them. Suggested schedule: 14 daily + 4 weekly (18 snapshots). This yields roughly six weeks to detect an attack on the offsite copy before deleted data becomes unrecoverable. Snapshot overhead ≈ 5–10 % per tenant (data deleted by GC stays allocated until snapshots expire; bursts after repacking).
- **Independent offsite monitoring.** The appliance regularly compares box contents with the expected catalog and alerts immediately (email + webhook, external channel) when packs or snapshots disappear unexpectedly.
- **Retention is computed independently** on both sides from snapshot timestamps with the same policy. Local deletions are never blindly propagated; locks apply separately.
- **Snapshot status in the UI:** a snapshot is "fully protected" only when it is present and verified both locally and offsite.
- **Initial seeding plan:** 6 TB take ~14 h at 1 Gbit/s, ~1 week at 100 Mbit/s; seed tenants sequentially so each reaches a complete offsite copy quickly; afterwards daily uploads are ~60–120 GB.
- **Migration between boxes** is supported: copy packs, verify, switch.

### 9.3 Later backends

S3-compatible object storage (Object Lock compliance mode, separate account, write-only credentials, hot tier for indexes + cold tier for packs) and a second appliance (pull-based replication) are additional `PackBackend` implementations; the pack format does not change.

---

## 10. Retention and Policy Engine

- **Policy model:** protection group → policy {schedule, retention per target, offsite targets, bandwidth window}. Retention is configurable separately per target even though the initial requirement is identical retention.
- **GFS schema:** 14 daily, 4 weekly, 6 monthly, 2 yearly.
- **Semantics:** period-based, as in PBS / `borg prune`: "14 daily" keeps the last backup of each of the last 14 days *that have a backup*. A snapshot may be daily, weekly, monthly and yearly at once; the union is kept. If backups stop for weeks, old restore points are not silently pruned.
- **Lock lifecycle:** minimum lock 14 days; extended automatically on classification; never shortened.

### 10.1 Capacity model (assumptions: ~2 % daily change, dedup + compression ≈ 0.6× of raw)

| Component | 5 TB raw | 10 TB raw |
|---|---|---|
| Base (first full, dedup + compressed) | ~3 TB | ~6 TB |
| 14 daily | ~0.8 TB | ~1.7 TB |
| 4 weekly | ~0.8 TB | ~1.6 TB |
| 6 monthly | ~2.5–3 TB | ~5–6 TB |
| 2 yearly | ~2–2.5 TB | ~4–5 TB |
| **Steady state (reached after 2 years)** | **~9–10 TB** | **~18–20 TB** |

Monthly and yearly restore points dominate capacity. Real change rates must be measured in the first months and the model corrected.

---

## 11. Control Plane

### 11.1 API and UI

- REST API with `axum`; the Web UI consumes the same API (everything the UI can do is scriptable).
- Authentication: local accounts with TOTP (WebAuthn later, decided 2026-10-09); OIDC later.
- Session hardening, rate limiting, CSRF protection, strict CSP.

### 11.2 Roles (initial RBAC)

| Role | Capabilities |
|---|---|
| Administrator | Configure appliance, sources, policies; cannot shorten retention or delete locked snapshots. |
| Security Officer | Approves quorum actions; manages recovery keys and lock policies. |
| Operator | Runs backups and restores. |
| Tenant User | Sees only own tenant; can trigger restores (optional customer self-service). |

**Quorum:** shortening retention, deleting protection groups, mass-deleting snapshots, disabling offsite, large GC runs require approval by a second role (Security Officer).

### 11.3 Catalog, audit, monitoring

- Catalog: SQLite (WAL) — sources, policies, snapshots, jobs, users, offsite inventory. Encrypted copy written to each tenant's Storage Box after every run.
- Audit log: hash-chained entries (each entry includes the hash of the previous one); forwarded via syslog/TLS to an external SIEM.
- Monitoring: Prometheus `/metrics`; alerts by email and webhook for failed jobs, lagging offsite copies, capacity thresholds, verify failures, offsite inventory anomalies, clock anomalies, failed login bursts.

---

## 12. Appliance OS, Hardening and Hardware

### 12.1 OS image

- bootc-based image from AlmaLinux / CentOS Stream; built in CI as a signed OCI image; read-only `/usr`; A/B updates with health-check-gated automatic rollback (greenboot-style).
- SELinux enforcing with a project-specific policy module; every service in its own domain.
- systemd sandboxing for every unit (see 4.2).
- No interactive root; emergency access via local console only; SSH server disabled by default (optional, key-only, management interface only, break-glass with quorum).
- chrony with NTS; compliance clock in `chunkstore`.
- nftables default deny inbound (except management port) and default deny outbound (except allow-listed sources and offsite targets; rules generated automatically when sources are configured).

### 12.2 Disk layout and encryption

| Tier | Devices | Purpose |
|---|---|---|
| System | 2× small SSD, mirror | bootc image, A/B slots |
| Metadata | 2× NVMe, mirror | dedup index, snapshot indexes, catalog, Bloom filter persistence |
| Data | 6–8× HDD, RAID6 / RAIDZ2 | chunks (one file per chunk) |
| Optional | NVMe | instant-recovery cache |

All tiers LUKS2-encrypted; unlocked via TPM 2.0 bound to Secure Boot state and image measurement; recovery passphrase escrowed offline. File system for the data tier: XFS on mdraid preferred (chunk store already checksums everything; ZFS is CoW-on-CoW), decided by performance tests.

### 12.3 Hardware sizing (5 tenants, 5–10 TB raw, full GFS)

- CPU: 8–16 cores.
- RAM: 32–64 GB.
- Metadata: 2× NVMe (≥ 1 TB) mirror.
- Data: 6× 12 TB in RAID6 ≈ 48 TB nominal, ~40 TB usable → ~30–40 % headroom over the 2-year steady state.
- Network: separate NICs for management, backup and offsite (at least two, ideally three).
- TPM 2.0, Secure Boot capable firmware.

### 12.4 Networking

| Interface | Direction | Purpose |
|---|---|---|
| Management | inbound (only port) | Web UI / API |
| Backup | outbound only | PVE API 8006 + SSH 22, agents (mTLS port), NFS/SMB mounts, TrueNAS API/SSH |
| Offsite | outbound only | SFTP to Storage Boxes |

### 12.5 First boot

Console TUI wizard: network → admin account + MFA → recovery key (shown once, partial re-entry required) → disk initialization → Web UI becomes reachable.

---

## 13. Security Considerations of the Pull Model

The appliance holds credentials to every source and therefore becomes a **tier-0 asset**. A compromised source cannot reach the backups, but a compromised appliance could reach the entire infrastructure. Mitigations are part of the concept, not optional:

- Least privilege per source (scoped PVE tokens, SSH `restrict` + forced command + `permitopen`, mTLS client certs for agents, read-only NAS mounts, restricted TrueNAS user).
- Strictly separated management network, MFA, no root, quorum, hash-chained audit log, external alerting.
- Agents accept connections only from the appliance certificate; agents expose no data-modifying operations beyond restore-to-path with explicit confirmation.

---

## 14. Testing Strategy

- **Unit and property tests** for chunking (boundary stability under inserts/shifts), index formats, GC marking, lock logic, compliance clock.
- **Crash-consistency tests** for the chunk store (kill -9 / power-loss simulation during write, index commit, GC).
- **Integration lab:** a Proxmox cluster running the test matrix as VMs, backed up by a test appliance (exercises the PVE integration at the same time).
- **Test matrix:** Windows Server 2016/2019/2022/2025; Debian, Ubuntu LTS, RHEL clones — each with and without LVM/ZFS/btrfs; PVE 9.x; TrueNAS Community current release; NFS and SMB shares with millions of small files.
- **Restore drills:** full VM, instant recovery, single-file from NTFS/ext4/XFS/LVM images, file-level to host, restore from offsite, **DR restore on fresh hardware with recovery key only**.
- **Security tests:** SELinux policy coverage (audit2allow review, no permissive domains), systemd sandbox audit, external penetration test before first production tenant, fuzzing of network-facing parsers (agent protocol, NBD, SFTP client).
- **Performance tests:** initial full of 10 TB, daily deltas, GC runtime, instant-recovery latency with and without NVMe cache, offsite upload with 4 connections.

---

## 15. Roadmap and Milestones

Order is driven by dependencies: the chunk store first, then the key model (hard to change later), then the first real source.

**Current development scope (decided 2026-10-08):** Phase 0 (repository, CI, ADRs, threat model) plus the Phase 1 chunk store core, working toward milestone M1.

### Phase 0 — Foundations (weeks 1–4)
- Repository structure, CI (Rust toolchain, clippy, cargo-audit, image build pipeline).
- Architecture decision records for the decisions in section 2.
- Threat model document.
- OS image skeleton (bootc, SELinux enforcing with permissive-free baseline, LUKS/TPM enrolment) can start in parallel.

### Phase 1 — Chunk store and key service (months 2–4)
- On-disk chunk format, dedup index + Bloom filter, fixed and dynamic indexes, manifests.
- Compression and AEAD pipeline; keyed chunk IDs.
- `keyd` with TPM sealing, recovery key, tenant DEKs, key versioning.
- Mark-and-sweep GC with grace period; retention locks; compliance clock.
- Verify jobs. Crash-consistency test suite.
- **Milestone M1:** chunk store ingests and restores synthetic block and file data with dedup, encryption, GC and locks, surviving crash tests.

### Phase 2 — Proxmox connector (months 4–7)
- On-node storage + backup provider plugin (Perl, `.deb` package).
- Pull orchestration: PVE API job trigger, SSH tunnel to NBD socket, dirty-bitmap consumption into fixed index; LXC file-level backup.
- Full VM restore.
- **Milestone M2:** scheduled, incremental-forever backups of a PVE cluster with full restore.

### Phase 3 — Restore features (months 7–9)
- NBD server, instant recovery via reverse SSH tunnel, background migration.
- Restore micro-VM for single-file restore from images (NTFS/ext4/XFS/LVM/ZFS).
- File-level restore service.
- **Milestone M3:** instant recovery and single-file restore demonstrated on the test matrix.

### Phase 4 — Offsite (months 9–11)
- Pack format and pack index; `PackBackend` trait; Storage Box SFTP implementation.
- Per-tenant box mapping, upload scheduler with connection budget, bandwidth windows, resumable uploads.
- Offsite inventory, sampled verification, inventory anomaly alerting, independent retention/lock enforcement, restore-from-offsite.
- DR tool: rebuild tenant from box + recovery key.
- **Milestone M4:** every snapshot shows local ✓ / offsite ✓; DR drill from a Storage Box succeeds on fresh hardware.

### Phase 5 — Control plane and UI (months 10–13, overlaps phase 4)
- REST API, Web UI, MFA, RBAC, quorum workflows.
- Policy engine with GFS retention and per-target retention.
- Catalog, hash-chained audit log, syslog forwarding, Prometheus metrics, alerting.
- First-boot TUI wizard.
- **Milestone M5:** appliance operable end to end without shell access.

### Phase 6 — Hardened appliance release (months 12–14)
- Final SELinux policy, systemd sandboxing audit, nftables automation, A/B update channel with rollback, signed releases.
- External penetration test; fixes.
- **Milestone M6:** "1.0" appliance image; first production tenant on Proxmox.

### Phase 7 — Additional sources (months 14–20)
- TrueNAS connector (ZFS snapshots).
- Linux agent (LVM/ZFS/btrfs snapshots, fallback mode, DB hooks, agent-side chunking, remote update).
- NAS connector (NFS/SMB file-level, metadata cache, parallel scan).
- Windows agent (VSS, USN journal, VSS writers; Server 2016+).
- **Milestone M7:** all phase-1 source classes supported with the full test matrix passing.

### Phase 8 — Replication and S3 (months 20–24)
- Second-appliance pull replication.
- S3 `PackBackend` with Object Lock, hot/cold tiering.
- Scale-out groundwork (no multi-node yet).

### Phase 9 — Plugin system (after phase 8; added 2026-10-10 by user request)
- Goal: extend the appliance with **new data sources and restore functions without changing the core**, e.g. NetApp
  (ONTAP SVM / vserver) backup, VMware ESXi / vCenter, PostgreSQL (logical and PITR), later Microsoft 365.
- A plugin provides: source type (config schema for UI/API validation, secrets marked for sealing), backup (produce
  snapshots into the chunk store through a stable, versioned SDK: file trees → `Index::Tree`, block devices → fixed
  index, application data streams), change detection / incremental state, restore functions (download, restore to
  target, application-specific restore, optional instant/mount), firewall endpoints, schedule/retention hooks, UI
  metadata (forms, snapshot browser columns), health checks and alerts.
- Must keep the security model: plugins never get tenant keys or catalog access directly; they run as spawned job
  processes in their own sandbox (uid/SELinux domain/systemd sandboxing) and talk to the core through a narrow API;
  plugins are signed (same offline release key or a separate plugin signing key) and versioned; the existing
  connectors (PVE, agents, TrueNAS, NAS) should become plugins on the same SDK where practical (dogfooding).
- Deliverables: plugin SDK crate + protocol, plugin manifest + packaging + signature verification, plugin manager
  (install/upgrade/disable via UI with quorum), sandbox, reference plugins (at least one new source, e.g. PostgreSQL),
  documentation for third-party plugin authors.
- **Milestone M9:** a new source type (e.g. PostgreSQL) installed as a signed plugin, backed up, restored and shown in the
  UI without core changes; one existing connector ported to the SDK.

### Phase 10 — End-user documentation (after phase 9; added 2026-10-10 by user request)
- New folder `manual/` with a complete end-user manual in Markdown for administrators, security officers, operators
  and tenant users: concepts (forever-full, dedup, retention/GFS, locks, quorum, offsite, replication), installation
  and first boot, every page of the web interface with **screenshots**, sources (PVE, Linux/Windows agents, TrueNAS,
  NFS/SMB, plugins), policies and groups, restores (full, instant recovery, file restore, restore to path), offsite
  targets (Storage Box, S3), replication, users/roles/MFA, approvals, audit, alerts, updates, disaster recovery
  with the recovery key, troubleshooting and FAQ.
- Screenshots are produced reproducibly by a script driving the real web UI (headless browser against the lab or
  a seeded demo backend), so they can be regenerated for every release.
- **Milestone M10:** manual complete, reviewed against the UI, screenshots regenerated from the current build.

### Phase 11 — Microsoft 365 (after phase 10)
- Separate project: Graph API connectors for Exchange, SharePoint, OneDrive, Teams — built as a plugin on the Phase 9 SDK.

### Phase 12 — Professional UI, management dashboard, OIDC (after phase 11; added 2026-10-11 by user request)
- Redesign of the web UI in an enterprise-console style (icon sidebar, cards, dense tables), dark mode (OS preference + toggle).
- Management dashboard with KPIs and charts: protection & SLA, job success trends, capacity & efficiency (incl. forecast),
  offsite & replication; backed by an aggregated metrics API (no client-side full scans).
- OIDC login (authorization code + PKCE) next to local accounts; group/claim → role/tenant mapping; local break-glass admins.
- Manual screenshots regenerated (Phase 10 script); docs/control-plane.md + threat model updated for OIDC.

### Phase 13 — Operations core (after 0.0.1-alpha; added 2026-10-12 by user request, Cohesity comparison)
- Orphaned-snapshot retention + approved snapshot delete; run control (retries, pause/maintenance, blackout windows,
  runtime SLA, richer schedules with time zones, cancel running jobs, back up selected/failed guests);
  auto-protect (guest inventory, `all`/tag/pool modes with exclusions); storage accounting (dedup/compression,
  per tenant/group, growth) + soft quotas; change-rate anomaly alert; alert lifecycle (resolve, auto-resolve,
  hints) + notification rules and webhook templates.

### Phase 14 — Security and operations
- Audit/alert forwarding (syslog TLS + HTTPS JSON, anchor), audit filters + CSV; diagnostics bundle + self-checks
  (also before updates); emergency console root access; viewer role, download privilege, session list/revoke,
  configurable timeouts, API tokens, web certificate import (CSR on the appliance) + expiry alerts, login banner,
  management IP allow-list; scheduled CSV/HTML reports. Release 0.1.0-alpha afterwards.

### Phase 15 — Restore and protection
- **File search (moved here from Phase 19 on 2026-10-12 by user request):** per-tenant file index, built at
  snapshot commit, sealed with the tenant key in the tenant's store; search by name/wildcard across snapshots,
  results lead straight to download / restore; VM-disk indexing opt-in per group.
- Restore options (link down, power-on, name, multi-guest, replace original safely); restore into hosts through an
  agent for any file snapshot; legal hold; consistency per snapshot; disk/file selection; agent cert renewal,
  re-registration, throttling; parallel guests per group.

### Phase 16 — Hardware and inbound firewall in the web UI (after Phase 15; added 2026-10-12 by user request)
- Disks: inventory of all disks (model, serial, size, role), SMART attributes and self-test results in the UI
  (smartmontools in the image), `disk` alerts for failing/degraded disks (SMART health, pending/reallocated sectors,
  temperature, md array degraded / rebuilding).
- Disk layout: mdadm (RAID1/5/6/10) + XFS for the data and metadata tiers, configured in the UI: create an array
  on empty disks, add a hot spare, replace a failed disk (rebuild with progress), grow; system disks are mirrored
  at install and only shown. Destructive steps need approval + typed confirmation; disks with data are refused.
- Inbound firewall: per-service source restrictions (web port 8443, replication, SSH or other services if ever
  added) edited in the UI; generalises the 14d management allow-list; outbound stays automatic (default-deny);
  every change needs approval; console reset against lock-out.

### Phase 17 — Offsite, replication, vault, tenants
- Time windows (bandwidth/pause) for offsite and replication, replication sync window + "close vault now", vault
  profile, offsite browse/restore in the UI + attach an offsite copy, optional per-tenant recovery key, tenant
  deactivation.

### Phase 18 — Workloads
- M365: per-item failures as warnings, unlicensed users, Recoverable Items, private channels, group mailboxes,
  several app registrations, chats (download only), cross-tenant restore, app registration helper.
  PostgreSQL: WAL-only frequent runs, recoverable range, start after restore, tablespace remap, LSN targets, HA.

### Phase 19 — Tier 3
- (file search moved to Phase 15) M365 item metadata search; Linux bare-metal recovery / P2V via rescue ISO;
  tenant-admin role; mbox/eml then PST export. Not planned: failover (decision above).

### Phase 20 — Agent packages on the release page (added 2026-10-12 by user request)
- Linux agent as `.deb` and `.rpm` (static musl binary, systemd unit, user, hardening, postinst enrollment hint;
  amd64 + arm64 if the build allows), Windows agent as an MSI (WiX) installer (service registration,
  firewall-free: the agent never listens publicly beyond its mTLS port as today, uninstaller); all built by the
  release workflow, checksummed and attached to the GitHub release next to the ISO; package signatures with the
  release key (cosign blob signatures; rpm/deb native signing documented); install docs in the manual.

### Phase 21 — Security and ransomware follow-ups (added 2026-10-12 from additional Cohesity docs)
- Flag anomalous snapshots (restore/hold default to latest clean), file-level change signals + snapshot diff from the
  name index, trend sparklines, incident mode, security posture checks, WebAuthn/passkeys, CVE scan of the image in
  CI, bit-rot repair from offsite/replica, DEK rotation reminder, session cap, BMC/separation-of-duties docs, opt-in
  YARA scan in the restore microVM, Entra ID objects (export). (docs/cohesity-comparison.md "Additional …")

### Phase 22 — Network, PVE and NAS operations
- Network interfaces (bond, VLAN, MTU, routes) + interface-bound egress, path-MTU check, VM-deployment guidance,
  per-source/per-storage concurrency caps, read rate limits + PSI backoff, restore-priority switch, VM identity per
  snapshot, NAS sizing/split/skipped-files CSV/overlap warning, TrueNAS existing-snapshot mode, local small-chunk packing.

### Phase 23 — Service-provider operations and new workloads
- Usage/billing export, per-tenant IdP, impersonation rules, policy tiers, onboarding wizard, immutable tenant IDs,
  site-VPN pattern, interim-backup DR runbook; MSSQL (log chain, PITR), MySQL/MariaDB plugin, Exchange full-VSS mode,
  AD runbook, Hyper-V host-level, Windows BMR (now Phase 37), Windows client + arm64 agents.

### Phase 24 — Endpoint UIs for the agents (added 2026-10-12 by user request)
- Linux agent TUI (`nexus-agent tui`, Veeam-Agent-for-Linux style: status, last sessions with result/duration/
  transferred, next run, "Back up now" request); Windows tray + window (Veeam-Agent-for-Windows style timeline of
  sessions); new Linux desktop GUI agent package (tray + window, same iced codebase). Appliance: session summaries
  pushed to the agent after each backup; lightweight poll of enrolled agents for queued requests and reachability;
  laptop handling (reachability-based retry, "last seen"). No self-service restore.

### Phase 25 — Recovery assurance (added 2026-10-12 from the Veeam B&R comparison)
- SureBackup-style automated restore tests in an isolated PVE network (boot, guest-agent ping, port checks), recovery
  plans with daily readiness checks and DR reports; plus the Veeam items placed into Phases 21–24
  (docs/veeam-comparison.md). Configuration backup is done immediately (DR blocker).

### Phase 26 — Edge proxy for roaming agents (added 2026-10-12 by user request)
- `nexus-edge`: a separate single bootc VM, hosted by the customer in a DMZ or the client network, internet-facing
  hardened (only the agent port; mTLS before anything else; rate limits; no admin UI on the public port). The appliance
  connects out to the proxy (enrolled with a one-time token, pushes its config, receives health/logs, updates it) and
  keeps a control tunnel; laptop agents connect out to the proxy with their agent certificate; the appliance opens the
  normal backup/restore session to the agent through the proxy, TLS end to end (pinned certs) — the proxy only
  forwards bytes, holds no keys or data. "Back up now" from the endpoint UI starts within seconds from anywhere.
  Compromise of the proxy: denial of service + connection metadata, no data, no path to the appliance.

### Phase 27 — Agent updates pushed from the appliance (proposed 2026-10-13 by user request)
- Signed agent releases ship with each appliance image (or are uploaded, signature-checked); per-OS/arch artifact
  selection; package installs updated with their own package type (deb/rpm/MSI, GUI included), bundles by binary
  swap with a start watchdog; chunked transfer; per-agent update state; rollouts with waves, canary, failure
  threshold, busy/window handling; optional automatic mode; rollback only with approval; installer downloads from
  the appliance. Details and proposed decisions: `docs/agent-update-plan.md`.
- **Implemented 2026-10-14 (27a, 27b, 27c)**; contract and deviations: `docs/agent-update-plan.md` "Implementation".
  Catalog v41, protocol v1.8, threat model T57–T59, alert kinds `agent_update_failed` / `rollout_paused`, quorum
  action `agent.rollback`. Deviations and decisions taken during implementation:
  - Host facts (`arch`, `install`, `gui`) travel as `HelloReply.caps` entries (`arch=…`, `install=…`, `gui=…`), not as
    new `HelloReply` fields: a postcard struct variant cannot grow without breaking the decoding of older agents.
  - Rollback marker: instead of a signed marker per version pair, each agent build carries a compiled-in
    `ROLLBACK_FLOOR` (part of the signed binary); an approved rollback may go down to it, never below. MSI installs
    cannot be rolled back in-band (Windows Installer refuses downgrades).
  - Start watchdog: checked by the agent binary at the start of `run` (Linux and Windows), not by an `ExecStartPre`
    shell snippet; the unit stays shell-free and the binary is signed and verified before the swap.
  - Package-install results: no wrapper process; the agent settles a pending install itself (new version listening =
    ok; the transient unit's `Result`/exit status and journal tail, or the MSI verbose log, = failed; 30 min timeout).
  - Agents keep the single-frame `Update` for v1.7 and older; package-installed agents refuse it (no binary swap under
    a package manager). Without any signed release in the store the scheduler still uses the legacy update directory.
  - Windows (UTC) for rollout maintenance windows; group policy blackout windows are honoured per agent; the failure
    share counts only from 5 finished agents (the count threshold and a failed canary pause at once).
  - Image builds ship the newest signed agent release attached to a GitHub release
    (`nexus-agent-release-<v>-signed.tar`, signed offline with `release/sign.sh sign-agent-release`); CI cannot sign,
    so a release's own agent tree reaches the image with the next build (or by upload).
  - Agent tags (`agents.tags`, `PUT /agents/{id}/tags`) were added for the "tag" rollout scope.

### Phase 28+ — Commvault-inspired items (proposed 2026-10-13)
- Tier 1 (scheduled threat scans, IOC hash hunting, tenant lockdown, new-device sign-in notice) as Phase 28, Tier 2 as Phase 29; details and open questions: `docs/commvault-comparison.md`.
- NetBackup-inspired items (proposed 2026-10-13): Tier 1 (scheduled full read with change-tracking drift check,
  approval for restoring malware-flagged snapshots to production, scan back to the last clean snapshot, incident-mode
  freezes, privileged-activity risk signals) with Phase 29, Tier 2 as Phase 30; details: `docs/netbackup-comparison.md`.

### Phase 28 — Commvault Tier 1 (implemented 2026-10-14)
Scheduled threat scans with a per-snapshot verdict and recovery calendar, IOC hash hunting over per-file SHA-256 in
the sealed name index, tenant lockdown, new-device sign-in notice (catalog v43, threat model T62–T63, alert kinds
`scan_hit`, `hash_hunt_hit`, `tenant_lockdown`, `login_new_device`, approval `tenant.lockdown.lift`). Details:
docs/malware-scan.md "Scheduled scans", docs/file-index.md "File hashes", docs/control-plane.md "Tenant lockdown" /
"New-device sign-in", docs/agent-protocol.md "v1.8 notes — file hashes". Deviations from the proposal
(docs/commvault-comparison.md) and decisions taken on the way:
- **Scan schedule** is the policy schedule grammar per group (UI: off / daily at / custom), not a fixed "daily latest"
  switch; only the newest local snapshot of each source without a verdict is scanned. "After each backup" is not
  offered (open question 4: the queue might never drain). Scans on request keep raising `malware`; only scheduled
  scans raise `scan_hit`. A snapshot already scanned is not scanned again when the rules change (rescan on request).
- **Verdict** is a catalog column `snapshots.scan_state` (newest scan), backfilled from `snapshot_scans`; a hit whose
  anomaly flag a security officer cleared still shows red in the calendar but counts as clean for "latest clean".
- **File hashes:** SHA-256 only (open question 2). Name index v2 is a new sealing context (`names2:`); indexes without
  hashes stay v1, so the previous release reads them; after a rollback v2 indexes are unreadable for search there
  (accepted). Hashes come from the reader (agents with `file-hash`, NAS/TrueNAS/plugin connectors), else carried over
  from the previous snapshot by identical chunk list, else read back from the store (old agents, first run after
  switching on: no forced full read on the source). Containers are hashed in the `file_index` job (with
  `index_files`); **VM disks are not hashed** (open question 3: later, opt-in; done in 31c for NTFS, ext4, XFS, the rest Phase 39 C1). Hash cache in the store: about
  100 bytes per file of one backup.
- **Agent protocol:** `ScanHashed`/`EntryHashes` appended as tags 49/50 behind capability `file-hash`, documented in
  the v1.8 notes without a version change. The v1.8 agent-update messages (Phase 27) must be ordered after or before
  them consistently when both are merged (both unreleased; the `agent-proto` tests pin the tags).
- **Hunt:** appliance-wide lists (admins, security officers), hunts per tenant (admins, operators, security officers,
  tenant admins); in-process in the scheduler like the file search, 30 minute budget, at most 2000 file versions.
  Hits flag up to 500 snapshots (newest first) and raise one `hash_hunt_hit` per tenant. Results through the jobs
  API (`hash_hunt` job result); no separate results table.
- **Tenant lockdown** goes beyond the proposal: the tenant's accounts cannot sign in while it lasts (password,
  passkey, OIDC, tokens), and agent updates/renewals and changes of its tenant settings are refused as well. Scans,
  hunts, restores to new targets and downloads stay allowed. Entering: security officers **and** admins
  (appliance-wide), re-authenticated; lifting always needs a second person.
- **New-device notice:** device = browser family + OS from the user agent and the /24 (IPv4) or /48 (IPv6) prefix;
  the account's first sign-in is the baseline (no alert); at most 50 devices per account. The mail to the account goes
  through the alert SMTP server on the alert's first delivery only (not reminders); the address comes from **My
  account** or the OIDC `email` claim (unless `email_verified` is false). Changing group options needs no approval
  (detection, not protection; audited).

### Phase 29 — NetBackup Tier 1 (implemented 2026-10-14)
Scheduled full read with a change-tracking drift check, approval for restoring flagged snapshots to production, scan
back to the last clean snapshot, incident-mode freezes, privileged-activity risk signals with step-up (catalog v44,
threat model T64–T65, alert kinds `change_tracking`, `user_risk`, approval actions `restore.infected`,
`incident.freeze.lift`). Details: docs/control-plane.md "Full read", "Restores of flagged snapshots", "Incident
freezes", "Risk signals and step-up"; docs/malware-scan.md "Scan back"; connector docs "Full read (Phase 29)".
Deviations from the proposal (docs/netbackup-comparison.md) and decisions taken on the way:
- **Full read** is a group setting (`PUT /groups/{id}/full-read`, null = default by source kind: Proxmox VE 90 days,
  agents/NAS/TrueNAS 30, plugins none), not a policy field; no approval (detection, audited). On by default
  (open question 2), first due staggered over the interval by a hash of the source name, skipped during restore
  priority, only for sources that already have a snapshot. PVE keeps reusing the dirty bitmap and reads the whole disk
  (so the bitmap's report can be compared) instead of dropping it; containers are not covered (they read everything).
  Agents need no protocol change (a Scan without base skips the metadata cache and the USN journal); the drift rule for
  files is "same size, mtime, ctime and inode, different content". `change_tracking` is critical (proposal: warning),
  as the task decided.
- **Restore of flagged snapshots:** flagged = any uncleared anomaly flag (YARA hit, hash-hunt hit, change-rate flag)
  or an uncleared `scan_state = hit`; the proposal named only the YARA flag. Production = over or next to the original
  with the network up, instant recovery with links up, instant disk, files into the original paths (`target` "/") or
  overwriting, plugin restores. One `restore.infected` request also covers a replace (no second `restore.replace`).
  With approvals disabled administrators only (open question 3 proposed security officers, who cannot start jobs).
  Downloads of flagged snapshots are for administrators only (Phase 39 S3, 2026-10-20). Jobs queued by recovery
  plans or the vault are re-checked by the scheduler and fail without the approval. BMR/P2V of a flagged snapshot are refused (Phase 39 S3).
- **Scan back** is driven by the scheduler (one ordinary `snapshot_scan` per snapshot with `--stop-on-match`, so every
  scan has its own job and `snapshot_scans` row) instead of one long connector run; `nexus-pve scan-back` exists as a
  manual CLI. Default 30 snapshots, one hour per snapshot; hits found by it are flagged without alerts. No bisect.
  `stop_on_match` is not on by default for scan-first restores (an older restore VM image would refuse the field).
- **Freezes:** appliance-wide (configuration, deletions, restores to production) when entering incident mode; per
  tenant lockdown deletions and restores only (its configuration is refused by the lockdown anyway). The configuration
  freeze is an allow-list middleware (sign-in, own account, incident/lockdown, approvals, disabling accounts, ending
  sessions, alerts, holds, pausing, jobs, scans, hunts, search, diagnostics); updates are frozen too (open question 4:
  not even OS updates with approval; lift the freeze first). Lifting freezes early: `incident.freeze.lift`, always a
  second person; leaving incident mode / lifting the lockdown ends them as well.
- **Risk signals:** four rules (unusual sign-in hour UTC +-1 h after 10 sign-ins in 90 days; 5 weakening requests per
  hour; 10 delete requests per hour; downloads over max(10 x daily median, 1 GiB) in 24 h); the "first API token use
  from a new network" rule is not done. Thresholds are constants, not settings (both Phase 39 S2). The mark lasts 24 h; marked sessions
  get 428 on their first change until `POST /auth/step-up`; tokens of a marked account cannot write; security
  officers and admins list and clear marks (not their own).

### Phase 30 — NetBackup Tier 2 (implemented 2026-10-14)
Backup-duration and dedup-rate anomalies, just-in-time role elevation, instant rollback of a PVE VM, hybrid
post-quantum key wrapping, a second offsite copy with its own retention (catalog v45, threat model T66–T69).
Deviations from the proposal (docs/netbackup-comparison.md "Tier 2") and decisions taken on the way:
- **Anomalies:** the dedup rate is new data / data **read** (not unique / logical, which is the change rate divided
  by the size); agents now report what they read from their disks as `read`. Duration = snapshot time to commit
  (`nexus-stats` `secs`). Sensitivity per source (`low`/`medium`/`high`, default medium) scales all three rules;
  lowering it is the approval `anomaly.sensitivity`. Duration alone raises a warning, everything else critical; all
  findings flag the snapshot and share the `anomaly` alert kind and key.
- **Role elevation:** per session (not per account): other sessions and API tokens keep the standing role. Only
  appliance-wide **local** operators and viewers can hold an eligible role (single sign-on accounts get their role from
  the IdP mapping); granting it is the approval `user.update` like granting the role. The approval for each elevation
  (`role.elevate`) is a setting, off by default (the proposal: "optionally"); switching it off is itself an approval.
  The passkey policy of the eligible role applies to the elevation. Possible approvers stay the standing admins and
  security officers. Posture check `posture.standing_admins` warns above two standing admins (break-glass + one).
- **Instant rollback** (open question 6 had no proposal; the maintainer's task decided "a new helper write
  command"): an option of replace original, approval `restore.replace`. The helper stays unprivileged and only
  forwards to a new socket-activated **root service** on the node (`pve-plugin/rollback`): it writes only disks of a
  VM that is stopped, tagged `nexus-rollback` through the API and locked `rollback` by itself, through qemu-nbd with
  the storage's format (no `sudo`, no paths from the appliance). The VM's "current dirty bitmap" is read by a
  pre-rollback incremental backup of the paused VM (which also keeps the old state in the store, instead of a PVE
  snapshot); the VM's configuration is not rolled back. Fallback to the full replace when the VM is stopped, its
  identity or disk layout changed, or a bitmap cannot be reused.
- **Post-quantum** (open question 7, proposal taken: keyd hybrid wrapping first, TLS later: Phase 39 S5): ADR-014. RustCrypto
  `ml-kem` (already in the tree through russh) rather than another implementation; the ML-KEM keys are derived from
  the existing X25519 secrets, so a tenant recovery key stays one secret (24 BIP39 words since ADR-015). Existing tenant recovery keys and
  replication peers stay X25519-only until replaced or enrolled again (the appliance cannot derive their ML-KEM half).
- **Second offsite target** (decision 5, proposal taken; plan §2 updated): `tenants.offsite.second` with its own
  remote, lock and `gfs`, set with `PUT /tenants/{name}/offsite2`; per class the larger of the policies' and the
  target's value (identical by default, longer only). One offsite job per target, own upload state, copy status per
  target (`snapshots.offsite2`), inventory and `offsite_lag` alerts per target, gc/verify on both, browse/fetch per
  target. No per-policy offsite GFS. Configuration backups still go to the first target only (Phase 39 O1).

### Phase 31 — Guest file index without the restore micro-VM (proposed 2026-10-13 by user request)
- VM/CT disk file systems (GPT/MBR, LVM2, NTFS, ext4, FAT; XFS/btrfs/LDM later) parsed read-only by a sandboxed
  helper without keys (`nexus-fsindex`), incremental per changed metadata chunk; one search index per tenant in an
  embedded Tantivy service (`nexus-index`) with sealed segments, file-version model (first seen / gone), instant
  search API and UI with version timeline; the sealed per-snapshot name indexes stay the source of truth; the micro-VM
  stays the fallback. OpenSearch and Meilisearch considered and not recommended. Details: `docs/file-index-v2-plan.md`.
- **Implemented 31a + 31b (2026-10-14).** Crates `fsindex` (nexus-fsindex helper + parent side), `fileindex`
  (nexus-index service), `index-proto`; catalog v42; threat model T60, T61; alerts `index_backlog`, `index_space`;
  audit `file.search`, `group.index_rules`, `file.index_rebuild`. Deviations from docs/file-index-v2-plan.md:
  - Per-chunk metadata cache at **volume** granularity: a volume is reused (no parse) when every chunk id its last
    parse read is unchanged; finer (per directory) reuse needs parsers without internal caches (the ext4/NTFS/FAT
    crates cache blocks), deferred to 31c.
  - ext4: the crate `ext4-view` applies the jbd2 journal in memory (read-only, nothing written); NTFS `$LogFile`
    and FAT/exFAT are not replayed and a dirty volume is marked "crash-consistent". XFS, btrfs and ZFS are listed
    through the restore micro-VM when its image is installed (fallback inside the same job) instead of being only
    reported; md RAID, LDM, Storage Spaces, LVM thin/cache/VDO/RAID5, BitLocker, LUKS, ReFS are reported per volume.
  - Panics of the third-party parser crates are contained per volume (catch_unwind; the volume is `failed`), and
    their fuzz targets count hangs, memory blowups and aborts, not panics (`ntfs` turns a short read into a panic,
    `fatfs` has debug overflow asserts). Own parsers (partition tables, LVM, exFAT, protocol) must not panic.
  - Guest paths: the name index keeps the file browser's paths (`vda1/…`) so open/download/restore stay unchanged;
    the mount mapping lives in the sealed per-snapshot report `fsindex` and the search index shows guest paths
    (`/home/…`, `C:/Users/…`, label or `vol<N>`).
  - `index_files` is on by default for **new** Proxmox VE groups; existing groups keep their setting (no lab
    measurement of the per-snapshot cost on the PVE lab host yet: decision 4 asks for one first).
  - nexus-index runs as `nexus-chunkstore` (keyd hands keyrings to one uid) with its own SELinux domain and group
    `nexus-index` for the socket; one-uid split of keyd stays an open item (threat model; Phase 39 S4).
  - Snapshot deletion does not cancel a running `file_index` job (the job fails on the missing snapshot; the next
    sync drops the versions). The nightly compare is the periodic sync (every 10 min) comparing the index payload with
    the stores; rebuild per source on any difference other than appended snapshots.
  - Owner/SID filters, XFS walker, LVM thin, btrfs, LDM, Windows drive letters from the SYSTEM hive, per-directory
    reuse, content hashes: done in 31c. Lab runs on the PVE lab host: Phase 39 L11 (compared against the micro-VM on
    the restore-vm fixtures instead).
- **Implemented 31c (2026-10-14/15).** Per-directory reuse (NTFS, XFS); drive letters from the SYSTEM hive (own regf
  parser); XFS and single-device btrfs walkers (own parsers; the micro-VM fallback only for ZFS and multi-device
  btrfs); LVM thin volumes (dm-thin metadata); Windows dynamic disks (LDM, simple/spanned/mirrored); owners (NTFS
  SIDs, `uid:gid`; name index v3; returned with search hits); content hashes of VM disk files (NTFS, ext4, XFS) for
  groups with `file_hashes`. Deviations from docs/file-index-v2-plan.md:
  - btrfs has no per-directory records (copy-on-write rewrites the path to the root on every change); ext4 neither
    (crate cache); both are reused per volume.
  - Owners are stored and returned, not yet filterable (the search filter needs a web-api parameter and the UI); SIDs
    and uids are not resolved to names (Phase 39 C2).
  - Dynamic volumes get their own browse paths (`ldm/<name>`); the micro-VM cannot open them, restores go through the
    Windows agent. GPT dynamic disks follow libldm's layout, not yet checked against a Windows-made disk (Phase 39 C3).
  - Hashes: btrfs, FAT and exFAT files stay unhashed; NTFS compressed / encrypted / deduplicated files too (Phase 39 C1).
  - No new catalog migration was needed.

### Phase 33 — Commvault Tier 2 (2026-10-14)
The Tier 2 items of `docs/commvault-comparison.md` (never scheduled before; the comparison proposed them as
"Phase 29", which became the NetBackup Tier 1). Order: PSA ticketing, tenant-side approvers, multi-appliance
overview, synthetic restore, M365 compliance search / cases, VMware transport spike. Catalog v46, threat model
T70–T75. Decisions and deviations:
- **PSA ticketing** (implemented): alert rule channel `psa` for HaloPSA, ConnectWise PSA and Autotask, one ticket
  per (rule, alert key), an internal note on repeats (at most hourly) and at once on escalation or re-raise, a note
  and the closed status on resolve; own scheduler thread (every 60 s), `psa_tickets` / `psa_state`, alert `psa`
  after 15 minutes of failures, egress allow-list, secret sealed to rule + API URL + token URL. Deviation: OAuth2
  client credentials only for HaloPSA; ConnectWise PSA (API member keys, Basic auth + `clientId`) and Autotask (API
  user headers) do not offer a client-credentials grant for integrations, so their native schemes are used. No
  ticket templates (fixed summary and description). Alerts already open when a rule is added get tickets too
  (rate-limited to 50 operations per rule and minute). Details: docs/control-plane.md "PSA ticketing".
- **Tenant-side approvers** (implemented): opt-in per tenant (admin or the tenant's own admin, immediate; off =
  approval `tenant.approvers.disable`, gated itself); gated: snapshot delete, hold release, weakening group /
  policy changes (policy: every tenant with a group on it), group delete, tenant update / disable / delete, replication
  key export. The provider's approval and the tenant's in any order; refusal final (open question 5); 24 h wait per
  account after becoming tenant admin, activation or re-enabling (SQL trigger on `users`), `tenant_approver` alert
  during the wait. Decisions taken: the 24 h wait applies to tenant-side approvers only (appliance approvers already
  have split activation codes; applying it there would block fresh installations for a day); with approvals disabled
  gated requests still wait for the tenant; a tenant admin's own request counts as the tenant's consent;
  impersonating sessions never decide; source/agent/policy deletion are not gated (refused while in use, no data
  effect). Details: docs/control-plane.md "Tenant-side approvers".
- **Multi-appliance overview** (implemented): `nexusctl fleet` (open question 7: CLI and a static HTML report, no web
  service): per appliance its own read token from a file (mode 0600) or environment variable, never inline;
  `/auth/me` now reports the token's scope and anything but `read` is refused; dashboard, open alerts, failed jobs
  of the last N hours; parallel, unreachable appliances listed; `--html` (no scripts, escaped, 0600), `--json`,
  `--check` (exit 2 for monitoring). No figures from `crates/reports` (the dashboard JSON has them already).
- **Synthetic (clean-file) restore** (implemented): job `synthetic_restore` for `host-`/`nas-`/`share-`
  snapshots; the scheduler decides per file from the sealed name indexes (YARA matches of each snapshot's newest scan,
  IOC lists, ransom-note names, mass-rename output recomputed per step with the 21a rules), walking back up to 30
  (1..=100) snapshots; files a mass rename deleted come back from before it; the CSV goes next to the downloads;
  `nexus-agentctl synthetic` composes (`chunkstore::synthetic`) and writes tar/zip or restores to an agent.
  Decisions taken: a version with the content of a YARA/hash-flagged version (size + mtime or SHA-256) is flagged in
  older snapshots too; a scan listing fewer matches than it found distrusts its whole snapshot; unscanned snapshots
  count as clean (reported as `from_unscanned`; the UI recommends scanning back first); rename output = dominant new
  extension or a deleted name plus an extension (an unrelated new file type in the same snapshot is kept); host
  restores of a flagged snapshot to production keep needing `restore.infected` (conservative: unknown malware may
  remain); not for VM/CT disks, plugins or M365 (no per-file versions without a per-snapshot file index walk).
- **M365 compliance search and cases** (implemented as cases on the name index; the Phase 19 item metadata search
  still does not exist: Phase 39 C4): `cases` / `case_snapshots`, criteria = name pattern + source prefix (default
  `plugin-m365-`) + snapshot range, search = `file_search` with `case_id` (new `source_prefix` filter), holds by
  security officers on the matched snapshots, export = one `files_get` per snapshot with the matched items (M365
  mail as eml/mbox/PST), Cases page. Decisions taken: provider roles only (admins, security officers), case audit
  entries not indexed under the tenant (no tip-off), closing a case keeps its holds, exports refused in vault mode and
  capped at 50 snapshots. The item metadata index (sender, recipients) is described as a design in docs/m365.md
  "Compliance search and cases".
- **VMware vSphere source**: not implemented; transport spike document docs/vmware-transport-spike.md (open question
  6 decided: no VDDK in the image; HTTPS datastore reads + `QueryChangedDiskAreas` first, nbdkit with a
  customer-supplied VDDK later if needed; scheduled after the spike ran in a vSphere lab: Phase 39 C5).

### Phase 34 — Code quality, documentation and repository workflow (added 2026-10-15 by user request)

Goal: the code base reads as if one careful team wrote it, a new contributor (human or agent) finds their way in
without help, and the GitHub side runs with as little manual work and runner load as possible. No new features.

- **34a Clean code:**
  - one pass per crate: dead code, duplicated helpers (for example the two `is_disk_key` in `pve::ir` and
    `pve::rollback`), `#[allow(...)]` that are no longer needed, long functions split where that makes them easier to
    read, consistent error context;
  - lints: workspace `[lints]` table (clippy pedantic subset that fits the code, `unsafe_code` denied outside the
    crates that need it, `missing_docs` on public items of library crates);
  - the same for the web UI (`svelte-check` strict, no unused exports) and the Perl plugin (`perlcritic` at a level
    agreed on first, no new dependency without asking; open: Phase 39 R3).
- **34b Documentation:**
  - every crate gets a crate-level doc comment (purpose, entry points, links to docs/), every public item a doc
    comment; `cargo doc --no-deps` without warnings becomes a CI gate;
  - `docs/` gets an index (what each document is for, which ones are history such as comparisons and plans);
  - stale statements in docs/ and manual/ found while doing so are fixed.
- **34c AGENTS.md:** replaces AGENT.MD, written for coding agents:
  - layout and where to start, build/test commands with their run times, which gates must pass before a commit;
  - house rules (no emojis, no `pkill -f`, ask before installing software, no `npx` for tools not in
    `web/node_modules/.bin`, `cargo fmt --all` before committing, lab rules: which VMs may be touched);
  - conventions (error handling, logging, tests next to the code, state.md updates, commit message style);
  - safety: secrets never in the repo, lab credentials outside the repo, the runner VM is not touched.
- **34d GitHub workflow:**
  - **issues:** issue forms (bug, feature request, lab result), labels, a private security policy (`SECURITY.md`,
    private vulnerability reporting), PR template with the gate checklist;
  - **pre-commit hooks:** a versioned hook script (`.githooks/`, enabled with `git config core.hooksPath`) that runs
    the fast gates (fmt, clippy on changed crates, `svelte-check` and `prettier --check` (via `npx prettier`, allowed 2026-10-15) when web/ changed, `prove` when pve-plugin/
    changed, no secrets / emojis in the diff); documented in AGENTS.md; no pre-commit framework download;
  - **CI:** path filters so a docs-only push does not run Rust tests; cached cargo and npm directories on the
    self-hosted runner; test parallelism limited so the runner (16 GiB) does not run out of memory again; jobs
    split so fmt/clippy fail fast before the long tests; a scheduled weekly run of the slow tests;
  - **release workflow:** one tag starts image, SBOM, CVE scan, packages, ISO and rescue ISO in a defined order;
    the draft release notes are generated from the commits since the last tag; a check that every expected asset is
    attached before the maintainer signs; documented in docs/release.md;
  - **Dependabot** (or a scheduled `cargo update` / `npm outdated` report) for Cargo, npm and GitHub Actions.
- **Verification:** all gates green in CI on the self-hosted runner, a docs-only push skips the heavy jobs, a test tag
  on a fork-like branch produces a complete draft release.

### Phase 35 — CIS AlmaLinux OS 10 Benchmark (added 2026-10-15 by user request)

Source: CIS AlmaLinux OS 10 Benchmark v1.0.0 (maintainer's copy in `tmp/`, not in git: CIS licence; the repository
refers to recommendation numbers and our own short titles only, never to CIS text).

- **35a Gap analysis:** every recommendation of the Level 1 Server profile, and Level 2 where it fits an appliance,
  classified as *applied*, *not applicable* (with the reason, e.g. no GUI, immutable bootc `/usr`, no interactive
  users) or *deviates* (with the reason and the compensating control, e.g. SELinux domains per service, nftables
  default-deny both ways). Result: `docs/cis.md`, one row per recommendation.
- **35b Evidence:** the OpenSCAP report the release workflow already produces (`release/cis-report.sh`, container
  view) plus a scan of a booted appliance VM in the lab (kernel, mounts, services, boot state the container cannot
  show), before and after; numbers in state.md.
- **35c Hardening in `os/`:** the applicable gaps, in the image: sysctl and module blacklists, mount options
  (`/tmp`, `/var/tmp`, `/dev/shm`) and the installer's partition layout, sshd and PAM / password policy for the
  break-glass and console accounts, auditd rules, file permissions, crypto policy, banners, journald/rsyslog,
  disabled services. Every change keeps greenboot, signed updates, the restore micro-VM (KVM), the agents' and the
  PVE connector's SSH paths and the full lab green.
- **35d Gate:** the CIS report becomes a CI/release gate for the rules marked *applied* (a regression fails the
  release); deviations stay documented.
- **Verification:** appliance lab (install from the ISO, setup, PVE backup and restore test on VM 101, update and
  rollback) with the hardened image; lab scan score before/after.

### Phase 36 — Offline (air-gapped) appliance updates (added 2026-10-15 by user request)

Goal: an appliance without any route to ghcr.io updates from a file an admin uploads in the web UI, with the same
guarantees as an online update: only images signed with a pinned release key, no downgrade without force, pre-update
checks, maintenance window, greenboot rollback, audit entry. Agent releases come along (they are in the image).

- **36a Update bundle (release side):** the release workflow attaches `nexusbackup-<v>-update.tar`: the image as an
  OCI archive plus its cosign signature (the simple-signing payload and signature the registry holds in the `.sig`
  tag), `release-metadata.json` and a manifest with SHA-256 sums. Signed like the other blobs (`release/sign.sh
  sign-blobs`). GitHub limits assets to 2 GiB; if the archive is larger, the bundle is split into numbered parts.
- **36b Verification and import (appliance side), decided by a spike first:**
  - *A: local mirror.* The bundle is loaded into a registry that only listens on the appliance's loopback; a
    `registries.conf` mirror for `ghcr.io/undone37/nexusbackup` points there, so `bootc upgrade` and `policy.json`
    (signature from the mirror's `.sig` tag, `matchRepository` on the original name) stay exactly as online. Needs a
    registry binary in the image.
  - *B: own check, then oci-archive.* The appliance verifies the signature itself (ECDSA P-256 over the
    simple-signing payload, pinned keys, digest match) and switches with `bootc switch --transport oci-archive`;
    needs a signed-origin story for the next online update and a policy scope for that transport.
  - The spike decides on: does bootc enforce the policy for the chosen path, does a later online update still work,
    disk space (the archive plus the staged deployment), and the downgrade rule (`org.opencontainers.image.version`).
- **36c Web UI and API:** Settings, Updates gets "Upload update": chunked, resumable upload (sizes of 1-2 GB through
  the browser), progress, then verification result (version, digest, key, release notes from the metadata) before
  anything is staged. "Apply" follows the existing flow (pre-update checks, now or in the maintenance window,
  approval if the update policy requires it). The upload is refused unless the signature verifies; a failed check
  leaves the running system untouched and deletes the file. Also via `nexusctl update upload <bundle>` and from a
  USB stick at the console (`nexus-setup`), for sites without a browser path to the appliance.
- **36d Scope and limits:** only the appliance image (OS + services + bundled agent release + restore micro-VM).
  Plugins already install from uploaded signed bundles (Phase 9). The PVE node plugin (.deb) stays a manual install
  on the nodes, with the .deb downloadable from the appliance's installer page.
- **Verification:** lab appliance with egress blocked (nftables), update from the uploaded bundle to a newer signed
  build, rollback by greenboot after a broken build, refusal of an unsigned, re-signed-with-another-key, truncated
  and older bundle; then an online update afterwards still works.
- **Decision (spike, 2026-10-20): B.** No registry binary in the image (AlmaLinux 10 ships none) rules out A.
  nexus-update verifies the cosign simple-signing payload itself (openssl, keys pinned in policy.json, repository
  identity, manifest digest, version label), then `bootc switch --transport oci` from a root-only directory, the
  one path policy.json accepts for that transport (`check-trust.sh` allows exactly it). Same origin on the next
  bundle: `bootc upgrade`. **Done 2026-10-20** for 36a (release/update-bundle.sh), 36b, 36c (upload API + UI);
  lab on the appliance VM: see state.md. Open: parts above 2 GiB, `nexusctl update upload`, USB at the console,
  the greenboot rollback after a broken build and an online update after an offline one (lab).

### Phase 37 — Windows bare-metal recovery (added 2026-10-20 by user request)

Goal: a Windows Server or Windows 11 machine backed up by the Windows agent can be rebuilt on empty disks: same
machine after a disk loss, new hardware, or as a Proxmox VE VM (P2V), like Linux BMR (Phase 19a, `docs/bmr.md`).
Until now the Windows agent backs up files (VSS, USN incrementals), and BMR was listed as open (Phase 23b).

- **37a Layout:** the agent records the machine layout with every backup (`GetLayout`, as on Linux): disks, GPT/MBR,
  partitions with type GUIDs (EFI system, MSR, recovery, basic data), volume GUIDs and disk signatures, file systems,
  BitLocker state per volume, firmware (UEFI/BIOS), Secure Boot state, BCD store location, network interfaces.
  Dynamic disks and Storage Spaces are detected and reported as unsupported for BMR.
- **37b Volume images:** the system-relevant volumes (EFI system, MSR, Windows, recovery) are backed up as images
  read from the VSS shadow copy, only blocks in use (`FSCTL_GET_VOLUME_BITMAP`), chunked and deduplicated like VM
  disks. Incrementals at first by re-reading and deduplicating (no kernel driver); changed block tracking is a
  follow-up (Phase 38). BitLocker volumes are read in plain text from the shadow copy; the restore says so.
- **37c Recovery media, decided by a spike first:**
  - *A: the existing Linux rescue ISO* recreates the partition table, writes the volume images, keeps disk and
    partition GUIDs so the BCD entries stay valid, and resizes the Windows volume (ntfs3/ntfsresize) when the new
    disk is larger. No Windows licensing question.
  - *B: a WinPE-based medium* built by the customer with the Windows ADK (WinPE may not be redistributed) carrying
    the Windows agent's rescue mode; needed for driver injection on dissimilar hardware (DISM) and BCD repair
    (`bcdboot`).
  - The spike decides on: boot after restore to the same and to different hardware, UEFI and BIOS, Secure Boot,
    BitLocker re-enable, and how much of B is unavoidable. A may be enough for same hardware and P2V.
- **37d P2V:** "Restore as PVE VM" for Windows: UEFI/OVMF or SeaBIOS as recorded, vTPM, VirtIO drivers injected
  (or the VM starts on SATA/e1000 first, then the VirtIO drivers are installed), the network configured.
- **37e Limits:** domain controllers follow the AD restore runbook (VM-GenerationID, non-authoritative by default);
  dynamic disks, Storage Spaces and Windows clusters are out of scope at first.
- **Verification:** VM 101 is never written to: lab restores of an isolated copy of VM 101 onto blank disks (same
  firmware) and as a P2V VM; Windows boots, the guest agent answers, the data is identical (hash list), BitLocker
  state as recorded. Then a test on physical hardware.

### Phase 38 — Standalone agents with Veeam Agent parity (added 2026-10-20 by user request)

Goal: the Linux and Windows agents also run **without the appliance**, for small companies without a large server
infrastructure: backups to a local or USB disk, NFS, SMB, SFTP or S3, scheduled and triggered on the client,
application-aware backups and restores controlled from the client. The target is feature parity with the commercial
Veeam Agent for Microsoft Windows and Veeam Agent for Linux (both editions, not only the free one). Everything stays
in this repository and uses the same crates as the appliance; the agents get their own version line inside it.

- **38a Comparison first:** `docs/veeam-agent-comparison.md`, from Veeam's current documentation: backup modes,
  targets, schedules and triggers, application-aware processing, restores, recovery media, management (standalone,
  managed), security, limits. Each feature: has / partial / missing here, with effort. It fixes the scope of 38b-38j;
  the list below is the starting point, not the result.
- **38b Two modes, one agent:** *managed* (today: the appliance pulls, its policies apply) and *standalone* (the
  agent schedules and writes itself). A standalone agent can later be attached to an appliance without a new full
  backup (38i).
- **38c Local repository, same format as the appliance:** the chunk store (`crates/chunkstore`: deduplication,
  zstd, XChaCha20-Poly1305) on a local disk, a USB disk (rotation, "backup when the disk is connected"), NFS, SMB,
  SFTP and S3 (Object Lock for immutability, as for offsite). Local key with the 24-word recovery key (ADR-015);
  retention locks where the target can enforce them; GFS retention (`crates/retention`); health check and compaction
  (GC, verify) scheduled by the agent.
- **38d Backup modes:** entire computer and volume level (images as in Phase 37, BMR-capable), file level (today's
  file backups). Changed block tracking for images: Linux blksnap/LVM/btrfs snapshots, Windows a CBT filter driver
  (needs a Microsoft-signed kernel driver: decide in 38a whether that is in scope or re-read plus deduplication stays).
- **38e Schedules and triggers:** daily/periodic schedules, backup at lock/log off, when the target becomes available,
  on idle, not on battery, retries, bandwidth limit, "back up now" from the tray, CLI and TUI.
- **38f Application-aware processing:** Windows VSS writers with log truncation as an option (SQL Server, Exchange,
  SharePoint, Active Directory), SQL Server transaction log backups, Oracle (RMAN or archive logs), and the existing
  MySQL/MariaDB and PostgreSQL plugins run locally; pre/post scripts.
- **38g Restores from the client:** files and folders (desktop UI, with versions and search), volumes, whole
  machine (recovery media of Phase 19a and 37), application items (databases to a point in time, AD objects as far
  as 38a decides), export of a machine backup as VHDX/qcow2.
- **38h UI and CLI:** the desktop agent UI (`crates/agent-gui`) and the TUI get job configuration, target setup,
  restore wizards and a status/notification history; a scriptable CLI (`nexus-agent job|backup|restore ...`);
  e-mail notification in standalone mode.
- **38i Growing into the appliance:** an appliance imports a standalone repository (or reads it on the share) and
  takes the agent over as managed; policies can be pushed to standalone agents later.
- **38j Packaging:** the same signed packages (.deb, .rpm, .msi) with standalone mode chosen at install or later;
  agent releases keep the release key and the self-update rules (Phase 27).
- **Order:** 38a, then 38b + 38c (repository and modes), 38e, 38d with Phase 37, 38f, 38g, 38h, 38i.
- **Verification:** lab matrix from `lab/README.md` (Linux distributions) and VM 101 copies for Windows: backup to
  each target type, triggers, application-aware backup and point-in-time restore, BMR from a standalone repository,
  attach of a standalone repository to an appliance, recovery with only the 24 words and the target.

### Phase 39 — Open items (consolidated 2026-10-20 by user request)

The small open points that were scattered over Phases 0–34 and the state log. Each lives here only; the earlier
sections keep their decisions and point here. Larger planned work stays in Phases 35–38. IDs are for references from
state.md and commits.

**Security**
- S1 Offline key ceremony with a standby key; rotate away from the alpha key before the first beta
  (0.0.1-alpha release).
- S2 **Done 2026-10-21:** risk signals: the "API token from a new network" rule (/24, /48; `token_networks`,
  catalog v47); thresholds as the gated setting `risk` (Settings → Security; loosening counts as weakening)
  (Phase 29).
- S3 **Done 2026-10-20:** flagged snapshots: BMR/P2V refused (409, scheduler re-check; no approval route, the flag is
  cleared first); downloads administrators only (security officers start no jobs) (Phase 29).
- S4 Split keyd's single key uid so nexus-index does not run as `nexus-chunkstore` (Phase 31, threat model).
- S5 Post-quantum TLS (hybrid key exchange for the web and replication endpoints); keyd wrapping is done
  (Phase 30, ADR-014).
- S6 Moved to Phase 40 (maintainer decision 2026-10-20).
- S7 **Done 2026-10-21:** time servers whose NTS key exchange negotiates NTP servers at other addresses
  (nts.netnod.se): nexus-time writes chronyd's NTP associations (address and port, netnod uses 4123) to
  /run/nexus-time/addresses, nft-sync allows them outbound (UDP) (lab 2026-10-21).

**Sources and connectors**
- C1 VM disk file hashes for btrfs, FAT and exFAT (NTFS, ext4, XFS done); NTFS compressed / encrypted / deduplicated
  files unhashed (Phase 28, 31c). MD5/SHA-1 IOC lists: decided SHA-256 only for now.
- C2 File search: owner filter (web-api parameter + UI); SID and uid resolved to names (31c).
- C3 Windows dynamic disks: GPT dynamic disks checked against a Windows-made disk; micro-VM restore from dynamic
  volumes (31c).
- C4 M365 item metadata search (sender, recipients) for cases: plugin contract change, design in docs/m365.md
  (Phase 19, 33).
- C5 VMware vSphere: moved to Phase 41 (2026-10-21).
- C6 Instant rollback for containers (Phase 30).
- C7 Progress lines for nexus-nas and the plugin host (today log only) (Phase 31 lab notes).
- C8 `ntfs` 0.4.0 (file index) pins binrw 0.11.3, which Rust 1.99 reports as future-incompatible (unnamed `...`
  argument, private extern crate re-export; rust-lang/rust#145544, #127909). ntfs master replaced binrw with zerocopy
  (2026-01) but is unreleased: move to ntfs 0.5 when it is published (2026-10-21).

**Storage and offsite**
- O1 Configuration backups to the second offsite target as well (today the first only) (Phase 30).

**Web UI**
- U1 In-depth review of the Plugins, Hardware, Quorum and Search pages (UI polish 2026-10-14).

**Release and CI**
- R1 Maintainer: sign and publish the v0.1.0-alpha draft (digest sha256:176c25e7...) (Release 0.1.0-alpha).
- R2 CVE gate for final releases (2026-10-20): `toolbox` removed from the image. Reviewed exceptions
  (`release/cve-exceptions.json`, 90-day review) cover all 19 critical kernel findings of the restore micro-VM: 6 by
  Debian tracker evidence (2 not affected, 4 fixed in 6.12.100 to 6.12.111), 13 by reachability (maintainer decision:
  config option per subsystem from Debian's 6.12.111 config; the VM has no NIC; the initrd's 36-module closure holds
  none of ksmbd, sctp, rdma_rxe, mlx5, qla2xxx, netfs). **Still blocking a final release:** the podman/skopeo Go
  findings (grpc, x/net, Go stdlib; AlmaLinux 10 has no newer build) (Release 0.1.0-alpha).
- R6 Spike: our own minimal kernel for the restore micro-VM (no networking, only the needed drivers and file systems,
  a current LTS series so grype sees the fixes): CI build time, ZFS against the LTS, rebuild cadence per stable
  release; then decide whether to replace Debian's kernel (maintainer question 2026-10-20).
- R3 **Done 2026-10-20:** perlcritic severity 4 ("stern") over the plugin, helper and rollback, in CI (`plugin`) and
  the pre-push hook; `.perlcriticrc` excludes octal modes and `use constant`, inline exceptions name their reason
  (PVE storage API `return undef`, process-wide `%SIG`/`%ENV`, streamed tar pipes) (Phase 34a).
- R4 **Done 2026-10-20:** Dependabot runs at night (02:00 Europe/Berlin, actions 03:00 monthly) (Phase 34d).
- R5 **Done 2026-10-20 (maintainer):** private vulnerability reporting and Dependabot alerts enabled (Phase 34d).

**Labs and tests** (lab rules: `lab/README.md`, Windows only on copies of VM 101)
- L1 Real Hetzner Storage Box: rename-no-overwrite, extensions, WAN throughput (Phase 4).
- L2 Appliance VM scripts not run since Phases 13–18: `disks.sh` (EXTRA_DISKS=5 NVME=1), `grub-lock.sh`, m5-api
  `firewall` step, `forwarding.sh` rerun, `offsite-fetch`, `config-restore.sh`, `console-gate.sh`, PG 1.2.0 bundle,
  vault mode, ui-smoke.
- L3 Installation on physical hardware (none tested; manual chapter 2) and a multi-node PVE cluster (manual chapter 4).
- L4 Windows: desktop GUI checked by the maintainer (icon, palette), MSI major upgrade with a bumped version, the
  appliance on pve-test backing up the Windows VMs through PVE (Phase 24, 27).
- L5 Restore test of VM 101 on pve-test: pipelined reads byte-exact and timed on a full run.
- L6 Linux agent updates: `lab/linux/e2e.sh <vm> agent agent_deb update_deb`, `.rpm` on alma-xfs, desktop package
  with the GUI running, bundle swap + watchdog on deb-plain, arm64 on the emulated aarch64 VM, edge-connected laptop
  updated on reconnect (Phase 27).
- L7 Windows agent updates: MSI update with the GUI running (service stays enrolled), msiexec outside the service's
  job object, MSI 1603 log parsing, watchdog revert of a manual install, rollback refused for MSI (Phase 27).
- L8 Appliance image with a signed agent release (os/agent-release) booted; SELinux of the upload dir
  (`nexus_agent_release_t`) and of nexus-agentctl reading /etc/pki/nexus/cosign under enforcing (Phase 27).
- L9 Scheduled scan and hash hunt with real Linux and Windows agents; lockdown with a tenant admin session;
  new-device mail through the lab SMTP sink (Phase 28).
- L10 Full read against the PVE host (bitmap reuse with a real VM), scan back in the real restore VM, step-up with a
  passkey in the browser (Phase 29).
- L11 File index: Debian LVM + XFS guest; XFS / btrfs / LVM thin / LDM on real guests; index time with the LRU cache
  on the Windows member server; several groups at once (needs a second PVE node); per-snapshot cost of `index_files`
  on by default (decision 4 of docs/file-index-v2-plan.md) (Phase 31).
- L12 Instant rollback on a PVE host with a running VM: `restore ... --replace --rollback` on LVM-thin, ZFS, dir
  qcow2 and RBD, the root service's socket unit after installing the .deb, rolled-back disk compared with
  `nexus-pve dump`; risk of a pre-rollback backup of a paused Windows guest without guest-agent freeze (Phase 30).
- L13 Two real offsite targets (Storage Box + S3 with Object Lock) for one tenant: uploads, longer monthly retention
  on the second, listing, fetch and DR (`nexus-setup` attach) from the second (Phase 30).
- L14 PSA ticketing against HaloPSA, ConnectWise and Autotask sandboxes (needs vendor test instances) (Phase 33).
- L15 `nexusctl fleet` against two appliance VMs over HTTPS with their own CAs (Phase 33).
- L16 Clean-file restore of a real agent / share snapshot after a simulated ransomware run (rename + YARA rule),
  download and to host (Phase 33).
- L17 M365 case over a real test tenant backup with a PST export (Phase 33).
- L18 Instant recovery with disk move of a TPM VM (TPM state fix, 2026-10-15).
- L19 First boot with the 24-word recovery key screen on a real console, 80x25 (ADR-015).

### Phase 40 — Disk encryption with LUKS2 and TPM, NVMe metadata tier (added 2026-10-20)

Split out of Phase 39 (S6) as its own phase. The plan §12.2 disk layout without its missing parts:
- LUKS2 on the data array and the metadata disks, unlocked by the TPM (systemd-cryptenroll, PCR policy over firmware,
  Secure Boot state and the bootc deployment), with the recovery key (24 words, ADR-015) as the fallback keyslot.
- What happens on a bootc update or a firmware update (PCR changes: re-enrolment before the reboot, greenboot check),
  on a replaced disk (array rebuild into a new LUKS device) and on new hardware (recovery key, then re-enrolment).
- The NVMe metadata tier: catalog and chunk indexes on a mirrored NVMe pair, the data array for packs only.
- Virtual appliances: vTPM limits (manual chapter 2), and what the setup wizard offers without a TPM.
- Lab: appliance VM with vTPM and Secure Boot on pve-test; unlock, update, rollback, disk replacement, recovery.
Not started.

### Phase 41 — VMware ESXi and vCenter backups as plugins (added 2026-10-21 by user request)

VM backups from VMware vSphere 7 and 8 as signed, sandboxed plugins (Phase 9), the main audience being SMBs moving
from VMware to Proxmox VE. Takes over Phase 39 C5 and builds on docs/vmware-transport-spike.md (transport decision:
no VDDK in the image; HTTPS datastore reads with `QueryChangedDiskAreas` first, nbdkit with a customer-supplied VDDK
only if the spike shows it is needed).
- Plugins: `vmware-esxi` (standalone hosts) and `vmware-vcenter` (inventory, clusters, VMs that move between hosts),
  both on one shared vSphere client library in the SDK (session, snapshot, CBT, datastore reads); the host keeps the
  chunking, encryption and keys as for every plugin. Egress only to the declared ESXi / vCenter addresses.
- Spike first, in a lab: nested ESXi 7.0U3 and 8.0U3 on pve-test (ISOs present), a vCenter appliance (VCSA ISO and
  evaluation licences still to be supplied by the maintainer). Measure datastore read throughput per stream and with
  parallel ranges, CBT behaviour after snapshot consolidation and storage vMotion, vSAN/vVols reachability.
- Backup: snapshot with quiescing through VMware Tools (VSS on Windows guests, fallback crash-consistent with an
  alert), CBT incrementals into one fixed index per disk, scheduled full read against CBT drift (Phase 29), VM
  configuration (vmx, hardware version, NICs, firmware, vTPM state where readable) in the snapshot, file index on
  the disk images (Phase 31), malware scan and restore tests as for PVE VMs.
- Restore: to Proxmox VE (VM conversion: disk bus, NIC model, firmware, VirtIO drivers note for Windows guests),
  file-level restore and downloads; back to ESXi / vCenter as a later step.
- Requirements and limits to document: licensed ESXi (the free hypervisor's API is read-only, so no snapshots), a
  least-privilege vCenter role, CBT enabled per VM by the plugin, which datastore types work (VMFS, NFS; vSAN and
  vVols per the spike result).
- UI, manual chapter, compatibility matrix rows, docs/plugin-system.md entry; lab e2e like `lab/truenas/e2e.sh`.
Not started.

Timelines assume a small dedicated team (2–4 engineers); adjust to actual staffing.

---

## 16. Risks and Open Questions

| Risk / question | Impact | Mitigation / decision needed |
|---|---|---|
| Proxmox Backup Provider API changes between PVE releases | Connector breakage | Track `pve-devel`; pin `APIVERSION`/`APIAGE`; integration tests against PVE 9.x (only supported version). |
| Dirty bitmap loss after VM/host restart | Full re-read (not full transfer) | Document; monitor backup duration; nothing further needed. |
| Linux hosts without snapshot capability | Inconsistent file backups | Fallback mode with explicit UI status; DB dump hooks; recommend LVM for new installs. |
| Windows application consistency | Crash-consistent DBs if writers are missing | VSS writer participation shown per job; alerts if expected writers are absent. |
| Storage Box has no object lock | Offsite copy deletable by a compromised appliance | Box snapshots managed outside the appliance; inventory monitoring; ~6-week detection window; consider S3 Object Lock as second offsite later. |
| Yearly snapshots pin chunks inside offsite packs | Repacking cost | Retention-class pack grouping; repack threshold; acceptable on Storage Box. |
| Capacity model uncertainty (change rate) | Under-sized appliance or boxes | Measure in first months; 30–40 % headroom; boxes resizable without data loss. |
| Rust hiring pool | Staffing | Keep core small; clear module boundaries; good documentation. |
| Team size and licensing model (AGPL vs. others, commercial support?) | Affects reuse of AGPL code (e.g. PBS crates) and go-to-market | **Decided 2026-10-08: AGPL-3.0.** Commercial support model and team size still open. |
| Instant-recovery latency on HDD tier | Poor user experience | Optional NVMe cache tier; measure in phase 3. |
| Catalog growth with millions of NAS files | SQLite performance | Keep file metadata in dynamic indexes, not in the catalog; catalog stores only snapshots/jobs. |
| Anomaly alert false positives (Phase 13) | Alert fatigue, ignored real attacks | Conservative defaults (3× median, 1 GiB floor), thresholds in settings, per-source history; tune with real data. |
| Tenant-admin scope creep (Phase 19) | Privilege escalation across tenants | Explicit allow-list of actions; RBAC matrix tests; no offsite/keys/approvals. |
| PST writer complexity (Phase 19) | Large effort, format bugs | Ship mbox/eml first; PST mail-only; validate with libpff/Outlook. |
| Legal retention expectations (GoBD/HGB) | Customer misunderstanding | Document clearly that backup ≠ archive. |

---

## 17. Glossary

- **Chunk:** unit of deduplication; identified by a keyed BLAKE3 hash.
- **Fixed index:** chunk list for a block device at fixed offsets.
- **Dynamic index:** chunk lists for a file tree with metadata.
- **Pack:** 32–64 MiB container of encrypted chunks used on remote storage.
- **DEK / KEK:** data-encryption key (per tenant) / key-encryption key (appliance, TPM-sealed).
- **GFS:** grandfather-father-son retention (daily/weekly/monthly/yearly).
- **Retention lock:** storage-layer guarantee that a snapshot cannot be deleted before a given time.
- **Compliance clock:** tamper-resistant clock used solely for retention locks.
- **Quorum:** second-person approval for destructive or weakening actions.
- **Pull model:** the appliance initiates all network connections to sources and targets.