# Plugin System — Contract (Phase 9)

Status: v1 (2026-10-10), implementation notes v1.1 (2026-10-10, see "Implementation (v1.1)" at the end), additive
v1.2 (2026-10-10, TrueNAS + PostgreSQL plugins, see "v1.2" at the end), additive v1.3 (2026-10-11, Microsoft 365
plugin, see "v1.3" at the end), additive v1.4 (2026-10-11, restores per snapshot kind, see "v1.4" at the end), additive v1.5 (2026-10-12, tagged guests, see "v1.5"), additive v1.6 (2026-10-12, snapshot metadata and endpoint host lists, see "v1.6"). Decisions (plan.md §2): plugins are **signed executables run as sandboxed processes**
speaking a **versioned protocol**, with a **Rust SDK**; trust = **project release key + publisher keys an admin adds
with quorum**; reference plugin **PostgreSQL**; the **TrueNAS** connector is ported to the SDK; the restore API covers
**download, restore to original/alternate target, application-specific restore and mount/instant access**.

## Trust split (the core rule)
A plugin is **untrusted code**. It talks to its source system with the source's credentials and streams data to the
appliance; it never sees tenant keys, the chunk store, the catalog or other tenants.

```text
 scheduler ── spawns ── nexus-pluginhost (trusted: store + keyring, domain nexus_pluginhost_t)
                             │  stdin/stdout, framed protocol (crate plugin-proto)
                             └── spawns ── plugin binary (untrusted: domain nexus_plugin_t, own sandbox)
                                               └── network: only the endpoints its source config declares
```
`nexus-pluginhost` does everything security-relevant: FastCDC chunking, hashing, sealing, dedup, index building,
commit (manifest last), retention, downloads. It validates every message (limits, paths, sizes) like agent-conn
validates agents.

## Package (bundle)
`<id>-<version>.nxplugin` = tar with:
- `manifest.json` — see below;
- `bin/plugin` — the executable (static preferred; dynamically linked against the appliance image's libraries is allowed);
- `assets/` — optional (icons, docs);
- detached signature `<bundle>.sig` — cosign blob signature over the bundle's SHA-256 (same format as agent updates).

```json
{
  "id": "postgresql",                     // [a-z0-9-]{2,32}; source kinds become "plugin:<id>"
  "name": "PostgreSQL", "version": "1.0.0", "publisher": "nexusbackup",
  "api": 1,                               // plugin protocol major version
  "kinds": [{
    "kind": "postgresql",                 // -> source kind "plugin:postgresql"
    "title": "PostgreSQL server",
    "config_schema": { ... },             // JSON-Schema subset (type/object/properties/required/enum/min/max/pattern/format)
    "secret_fields": ["password", "tls_key"],
    "endpoints": [{"host": "/host", "port": "/port", "default_port": 5432, "proto": "tcp"}],   // JSON pointers into the config -> firewall allow-list
    "guests": {"title": "Databases", "list": true},     // groups select guests (here: databases); list via ListGuests
    "backup": {"incremental": true, "consistent": "application"},
    "restores": [
      {"id": "download", "title": "Download (tar/zip)"},                                  // generic, done by the host
      {"id": "to_target", "title": "Restore to server", "params_schema": { ... }},
      {"id": "pitr", "title": "Point-in-time restore", "params_schema": { ... }, "app_specific": true},
      {"id": "mount", "title": "Mount read-only", "params_schema": { ... }}
    ]
  }],
  "sandbox": {"network": "endpoints", "tmp_mb": 1024, "memory_mb": 1024, "cpu_quota": 200}
}
```

## Trust and lifecycle
- Verification on install/upgrade: signature against the trusted keys (project release key(s) from the image +
  publisher keys in the catalog), manifest `api` supported, `id` not taken by another publisher, version strictly newer on
  upgrade.
- Install, upgrade, disable, remove and **adding/removing a publisher key** are quorum-gated (four-eyes) and audited.
  Remove is refused while sources of its kinds exist.
- Installed at `/var/lib/nexus/plugins/<id>/<version>/` (root-owned, read-only for the runtime, SELinux
  `nexus_plugin_exec_t` for the binary); `current` points at the active version.

## Protocol (crate `plugin-proto`, framing like agent-proto: `u32 BE len | postcard`, max 8 MiB)
Host → plugin first: `Init { api, job, kind, op, config (secrets opened), params, base: Option<BaseInfo>, state: Option<Vec<u8>> }`.
`op` ∈ `Validate`, `ListGuests`, `Backup`, `Restore`, `Mount`.

| op | plugin → host | host → plugin |
|---|---|---|
| Validate | `Valid` / `Invalid { field, message }` (connectivity + permission check) | — |
| ListGuests | `Guests { list: [Guest { id, title, size? }] }` | — |
| Backup | `Item` stream: `FileBegin { path, meta }` → `Data { bytes }`* → `FileEnd`; `Unchanged { path, meta }` (reuse from base); `Stream { name }` → `Data`* → `StreamEnd` (application streams, e.g. dumps, WAL); then `Done { state, consistent, summary }` | `BaseQuery { paths }` → `BaseInfo` answers (previous entry metadata) on demand |
| Restore (`to_target`, app-specific) | `NeedFiles { paths }` / `NeedStreams { names }`, `Progress`, `Done` | `FileBegin/Data/FileEnd`, `Stream/Data/StreamEnd` of the selected snapshot content |
| Mount | `MountReady { info }`, keeps running until `Unmount` | `ReadFile { path, offset, len }` answers / NBD socket fd for fixed indexes |
Every op may end in `Error { code, message }`. `Log { level, text }` may be sent at any time (shown in the job log;
escaped by the host). The host enforces limits: path ≤ 4096 bytes and relative, no `..`; metadata sizes; stream names
`[A-Za-z0-9._/-]{1,255}`; `Data` frames ≤ 4 MiB; total size per file/stream as announced or open-ended; time limits per op.

Snapshot layout: files → `Index::Tree` named `files`; streams → one `Index::Dynamic` named `streams` (one entry per
stream); the plugin's `state` blob (≤ 1 MiB, opaque, e.g. last WAL LSN) is stored as a sealed extra file of the
snapshot and returned in the next `Init`. Source name `plugin-<id>-<source>` (+ `-<guest>` per guest).

## Sandbox
- Spawned by `nexus-pluginhost` via a hardened exec: new user namespace or the dedicated uid `nexus-plugin`,
  no new privileges, seccomp (`@system-service` minus `@privileged @mount @module @raw-io`), private /tmp (size limit),
  read-only root, no access to `/var/lib/nexus` except its own install dir, RLIMIT_AS/CPU, `PR_SET_PDEATHSIG`.
- SELinux `nexus_plugin_t`: exec only from `nexus_plugin_exec_t`, network only TCP connect (ports per manifest are
  enforced by nftables: the scheduler adds the manifest-declared endpoints of each configured source), no access to
  any nexus data type, keys, catalog, sockets except its stdio.
- Plugins never get privileged helpers in v1.

## SDK (crate `plugin-sdk`, Rust)
Typed manifest, `Plugin` trait (`validate`, `list_guests`, `backup(&mut Sink)`, `restore(&mut Source, …)`, `mount(…)`),
streaming helpers (file walker emitting `FileBegin/Data/FileEnd`, `Unchanged` against `BaseInfo`), state blob helpers,
a test harness (`plugin_sdk::testing::Host`) that runs a plugin in-process against a temp store, and `nexus-plugin
pack|sign|verify` tooling.

## Appliance integration
- Catalog migration v8: `plugins` (id, version, publisher, sha256, manifest JSON, state, installed_at),
  `plugin_keys` (publisher, public key, added_by, added_at), `sources.kind` accepts `plugin:<id-kind>` (rebuild of the CHECK).
- web-api: `/api/v1/plugins` (list, upload → quorum, enable/disable/remove → quorum), `/api/v1/plugin-keys`
  (quorum), source forms generated from `config_schema` (secret fields write-only and sealed), restore actions from
  `restores[]` with `params_schema`.
- scheduler: job kinds `plugin_backup`, `plugin_restore`, `plugin_mount`, `plugin_validate`, `plugin_guests` run
  `nexus-pluginhost`; retention/offsite/replication treat plugin snapshots like any other. A backup job backs up
  its guests one after the other, or up to `parallel` at once (job config key, group `parallel_guests` 1..=8,
  Phase 15f): one sandboxed plugin process and one store handle per guest, the `result {json}` line lists the
  guests in their configured order.
- UI: Plugins page (install with signature details, publisher keys), dynamic source forms, restore dialogs.

## Milestone M9
The PostgreSQL plugin (logical dumps per database + base backup + WAL for point-in-time restore) is installed as a
signed bundle, configured, backed up on a schedule, restored to an alternate server and point-in-time restored, all in
the UI without core changes; the TrueNAS connector runs as a plugin on the same SDK with its existing lab passing.

## Implementation (v1.1) — clarifications and additive changes
Built in crates `plugin-host` (`nexus-pluginhost`), `plugin-manager` (`nexus-plugin-install`), `plugin-sdk`
(+ `nexus-plugin` packaging CLI), `plugins/example-files`; author guide: docs/plugin-sdk.md.

**Manifest (stricter `Manifest::validate`, additive for authors):** plugin `id` must not have an empty or all-digit
`-` component (so `plugin-<id>-<source>[-<guest>]` parses unambiguously: the first all-digit component is the source
id); `publisher` is `[a-z0-9-]{2,32}` (`nexusbackup` = project keys only); kinds unique; restore ids
`[a-z0-9_-]{2,32}`, unique per kind, `params_schema` an object; every `secret_fields` entry must be a property of
`config_schema` (top-level). `sandbox.network`: `endpoints` (default) or `none`. Guest ids (ListGuests, groups):
`[A-Za-z0-9._-]{1,64}`, not starting with `.`/`-` (invalid ones are dropped by the host).

**Bundle crate feature:** `plugin-proto` feature `bundle` (reader/packer, P-256 signature verify/sign, key parsing).
Reading is strict (only `manifest.json`, `bin/plugin` (ELF), `assets/…`; regular files and dirs; no `..`, no
duplicates; ≤ 128 MiB). The signature is verified over the bundle bytes (= cosign `sign-blob` of the file).

**Trust and installation:** project keys are `/etc/pki/nexus/plugin-keys/*.pub` (lab images: the release TEST key;
`release/inject-keys.sh` puts the release key there). The publisher of the signing key must equal the manifest's
`publisher`; an id belongs to the first publisher that installed it; versions must be strictly newer than every
installed/approved one; a kind may only be provided by one plugin id. The web-api verifies, stages
`<sha256>.nxplugin` + `.sig` in `/var/lib/nexus/plugins-staging` and records the row `pending`; approval
(`plugin.install`) repeats the checks (`approved`) and touches `.trigger`; `nexus-plugin-install` (user
`nexus-plugins`, not the plugin runtime uid; SELinux `nexus_plugininstall_t`, the only domain that may write
`nexus_plugin_data_t`/`nexus_plugin_exec_t`) re-verifies against the catalog record, unpacks to
`<id>/.<version>.tmp/` → `<id>/<version>/` (dirs 0555, files 0444, `bin/plugin` 0555), marks it `installed` +
`current` and maintains the `<id>/current` symlink. `current` itself lives in the catalog (`plugin.activate` switches
it). Disable (quorum) sets `enabled = 0`: jobs of its sources fail before starting; enable is a direct admin action.

**Sandbox (as built):** the plugin runs as the job uid (`nexus-chunkstore`: the scheduler and its jobs have no
privilege to switch uid, and the scheduler unit's `RestrictNamespaces=yes` forbids user namespaces — a user + IPC
namespace is used where available, e.g. development hosts). The boundaries are SELinux `nexus_plugin_t` (entered
only via `nexus_plugin_exec_t`, no nexus data types, no Unix sockets of nexus domains), **Landlock** (required: read +
exec of the install dir, `/usr`, `/lib*`, `/bin`, `/sbin`; read of a few `/etc` files and the CA stores; rw of
`/dev/null|zero|urandom` and the private tmp dir; TCP connect only to the endpoint ports of the source config + 53, no
TCP bind; signals and abstract Unix sockets scoped to the sandbox — Landlock ABI ≥ 6, the appliance kernel has it),
a **seccomp allowlist** (`socket()` only AF_INET/AF_INET6/AF_NETLINK-route; no ptrace, mount, namespaces, bpf,
keyctl, modules, io_uring, set*id …), `NO_NEW_PRIVS`, `PR_SET_PDEATHSIG`, own process group, rlimits (`RLIMIT_DATA` =
`memory_mb`, `RLIMIT_AS` = 4× (≥ 4 GiB), `RLIMIT_FSIZE` = `tmp_mb`, `RLIMIT_CPU` = op time limit, `RLIMIT_NOFILE`
1024, no core), nice 10, a cleared environment (`PATH`, `HOME`=`TMPDIR`=tmp dir, `LANG`, `NEXUS_PLUGIN_JOB`) and a
private tmp dir whose size is accounted (above `tmp_mb` the plugin is killed). `cpu_quota` is not enforced in v1 (no
cgroup delegation to the scheduler). The binary is executed via `execveat` of the descriptor whose SHA-256 was
checked against the catalog (no path race); `manifest.json` must equal the catalog's copy. The appliance's nftables
allow-list is global (TCP only), so manifest UDP endpoints are not opened.

**Protocol rules the host enforces (in addition to `plugin_proto::check`):**
- Backup: `FileBegin` → `Data`* → `FileEnd`; data only for regular files and exactly `meta.size` bytes (the SDK pads
  / truncates files that change while read and reports `consistent = false`); non-regular entries store size 0;
  symlinks need a target; hard links name a regular file sent earlier; paths unique and not below the reserved
  `.nexus-streams/`; `Unchanged` only for a path of the base snapshot whose type, mode, uid, gid, mtime, link target
  (and size for files) match — the chunks are taken from the base entry and touched for GC; `Stream` names unique;
  `Done` only between items. Any violation, an invalid frame, EOF before `Done`, the idle limit (900 s between
  messages; validate/guests 120 s) or the op limit (24 h) kills the plugin's process group; nothing is committed.
- `BaseQuery`: at most 1 MiB of paths; answered with exactly one `BaseEntries` (found paths only; xattrs are dropped
  if the answer would not fit one frame).
- `Done.state` (≤ 1 MiB) is stored as index `state` (one dynamic entry, sealed chunks) and returned as
  `Init.state` of the next backup, and of restore/mount of that snapshot. Devices are stored without `rdev`.
- Restore: `Init.params` = `{"restore", "params", "guest"?, "snapshot": {"source","time"}, "streams": [{"name","size"}],
  "top": [top-level names], "files": n}`; `NeedFiles` paths name entries or subtrees; unknown paths/streams are skipped;
  each answer ends with `NeedDone`. `download` never reaches a plugin: it is `files_list`/`files_get` (files + streams
  below `.nexus-streams/<name>`).
- Mount: after `MountReady` the plugin may stay quiet until the mount time (job param `minutes`, ≤ 24 h) ends, then
  the host sends `Unmount` and expects `Done` within 120 s; `ReadFile` of a missing / non-regular file is answered with
  `Error { code: 2 }`. The NBD socket for fixed indexes is not implemented in v1 (plugins snapshots have no fixed index).
- Log/Progress/stderr of the plugin are escaped (control characters), truncated, prefixed (`plugin[level]: `,
  `plugin stderr: `) and capped at 4 MiB / 1 MiB per job, so they can never forge the host's parseable lines
  (`committed <source>/<time> …`, `inconsistent <source>/<time>: …`, `summary …`, `result {json}`, `restored {json}`,
  `mount-ready {json}`, `unmounted {json}`).

**Appliance:** job kinds and API as listed in docs/control-plane.md; a backup with `consistent = false` raises
`backup_inconsistent` once per snapshot source; `restores[].params_schema` values end up in `jobs.params` (visible to
operators) — restore parameters must not carry secrets in v1 (use source secrets).

## v1.2 — additive changes for the TrueNAS and PostgreSQL plugins (2026-10-10)
Found while porting the TrueNAS connector (`plugins/truenas`, docs/truenas-connector.md §9); protocol and API
version unchanged (`api: 1`), older plugins are unaffected.
- **Backup `Init.params` carries `source_id`** (`{"guest", "source_id"}`; SDK `Ctx::source_id()`): the appliance's
  id of the source, stable and unique per appliance. A plugin that creates objects on the source system (TrueNAS:
  ZFS snapshots `nexus-<source>-<time>`) names them with it, so two sources on the same system — or a plugin source
  next to a built-in one — never touch each other's objects. (Previous-snapshot references need no new capability:
  the plugin keeps its own reference in the `state` blob, which is returned with the base snapshot.)
- **The SSH client may run in the sandbox:** SELinux `can_exec(nexus_plugin_t, ssh_exec_t)` (it already ran the
  image's other tools in-domain). Nothing else changes: `ssh` inherits Landlock (TCP connect only to the endpoint
  ports; key and `known_hosts` must live in the plugin's tmp dir; `/etc/ssh` is not readable, so the system
  `ssh_config` is skipped), the seccomp allowlist (no AF_UNIX: no agent; glibc's NSS falls back to `/etc/passwd`)
  and the rlimits. Tested by `plugins/truenas/tests/plugin.rs` (the binary in the real sandbox against a local
  unprivileged sshd).
- **Endpoint ports from the source config** are now one function (`KindSpec::tcp_ports(config)` in `plugin-proto`,
  wrapped by `plugin_host::endpoint_ports` for `sandbox.network`) used by `nexus-pluginhost` and the SDK's test harness; `testing::Host` previously opened only the manifest's
  `default_port`s, so plugins whose test servers listen on other ports could not be tested in the sandbox.
- Hint for plugin authors (no change): the host drops the xattrs of a whole `BaseEntries` answer that would not fit
  one frame; plugins that rely on base xattrs (TrueNAS: unchanged directories) query small batches.
- Optional endpoints (e.g. an alternate restore server, an SSH restore host) are a pattern: declare them, they
  open only when configured.

**PostgreSQL reference plugin (M9, `plugins/postgresql`):** guests = databases (logical dumps, stream `<db>.sql`),
no guest = the whole cluster (base backup + WAL as files: `data/`, `wal/<segment>`; incrementals re-reference
`data/` and earlier WAL via `Unchanged` from a front-coded path list in the state blob, so every snapshot is
self-contained for point-in-time restore). Pure-Rust wire protocol client instead of `pg_dump`/`pg_basebackup`
(not in the image, and they must match the server's major version); restores to targets declared as optional
endpoints of the source (alternate PostgreSQL server; SSH restore host for the PITR data directory). Details and
limits: plugins/postgresql/README.md. No other contract change.

## v1.3 — additive changes for the Microsoft 365 plugin (2026-10-11)
Found while building `plugins/m365` (docs/m365.md); protocol and API version unchanged (`api: 1`). Plugins built
for v1.2 run unchanged; a plugin that uses `BaseList` needs a v1.3 host (the appliance ships host and SDK together).
- **Fixed endpoint hosts:** an endpoint may name `"default_host"` — used when the config has no (or an empty)
  value at its `host` pointer. So a cloud API (`graph.microsoft.com`, `login.microsoftonline.com`) is opened
  without a form field the admin must fill, while the pointed-to config field can still override it (national
  clouds, test setups). `Manifest::validate` accepts DNS names only (no IP literals, no wildcards, at least two
  labels). One function resolves endpoints for both the firewall and the sandbox: `KindSpec::tcp_targets(config)`
  (host from the config, else `default_host`; port from the config, else `default_port`; endpoints without a host
  are skipped), `KindSpec::tcp_ports` = its ports (the Landlock allow-list), used by the scheduler's allow-list
  (replacing its own copy) and by `nexus-pluginhost`/the SDK harness. Behaviour change for v1.2 manifests: an
  endpoint whose host field is present but empty no longer opens its port. The web UI shows `default_host` in the
  plugin details.
- **`BaseList { after }` (plugin → host, backup only):** the base snapshot's entries in path order (bytes) after
  `after` (from the start if absent), answered with one `BaseEntries` page as large as fits one frame with full
  metadata incl. xattrs (≤ `MAX_BATCH` entries; at least one); an empty page ends the listing; without a base the
  answer is empty. The variant is appended to `Message`, so existing variants keep their wire index. SDK:
  `Sink::base_list()` returns the whole base. Use: plugins that rebuild their previous view of the source from the
  base snapshot instead of the 1 MiB state blob — the M365 plugin keeps each item's Graph id in an xattr and finds
  previous path/version per id, so per-item lists of large mailboxes and drives never go into the state blob (only
  the Graph delta links do). Tested: `crates/plugin-host/tests/host.rs` (test plugin pages through the base),
  `plugins/m365/tests/m365.rs`.
- **SDK, restores:** when a `Source::files`/`streams` callback fails, the SDK reads the rest of the host's answer
  (until `NeedDone`) before returning the error, so the host receives the plugin's `Error` (shown in the job log)
  instead of failing on a closed pipe. No host change.

## v1.5 — tagged guests (2026-10-12, Phase 13c auto-protect)
Additive; `api: 1` unchanged. New struct `TaggedGuest {id, title, size, tags}` and the appended message
`TaggedGuests { list }` (plugin → host, answer to `ListGuests`; older variants keep their wire index, a v1.4
`Guests` frame is byte for byte unchanged). Postcard is not self-describing, so a field could not be added to
`Guest` itself. SDK: `Plugin::list_tagged_guests` (default: `list_guests` without tags); the SDK sends `Guests` when
no guest has a tag, so such plugins keep running on a v1.4 host, and `TaggedGuests` otherwise (needs a v1.5 host).
Limits: 64 tags per guest, 128 bytes each (`check`); the host keeps only printable, trimmed tags and returns them in
`{"guests": [{id, title, size, tags}]}`. The scheduler stores them in the guest inventory (docs/control-plane.md
"Inventory"); groups of mode `tags` select on them. Microsoft 365 emits `type:user|site|team` and `license:none`
(users without `assignedLicenses`, read with the existing User.Read.All); Entra group tags (`group:<name>`) would
need GroupMember.Read.All and are left for 17a. Tested: `crates/plugin-proto` (wire compatibility, limits),
`plugins/m365/tests/m365.rs` (tags).

## v1.6 — restore into another source; lists of objects in configs (2026-10-12, Phase 18a)
Manifest and job parameters only; protocol and `api: 1` unchanged.
- **`target_source: true`** on a restore spec: the restore may run with the config (credentials, endpoints) of
  **another source of the same kind and appliance tenant**. Job `plugin_restore` takes `target_source_id` next to
  `params`. The web-api refuses it for restores without the flag, for sources of other tenants (also for admins:
  sources and their secrets belong to one tenant) or kinds, and for mounts; the scheduler checks tenant, kind and
  flag again, opens the target's sealed secrets and passes `restore.target {source_id, config}` to
  `nexus-pluginhost`, which refuses a target for a restore without the flag (an older web-api cannot bypass it),
  runs the plugin with the target's config (its endpoints open the sandbox ports) and adds `target_source_id` to
  the restore's init params. Snapshot and store stay those of the original source. UI: a **Target source** select
  in the restore dialog (sources of the snapshot's tenant and kind). Use: Microsoft 365 `to_other` into another
  M365 tenant (docs/m365.md). Tested: `crates/web-api/tests/plugins.rs`, `crates/plugin-host` (unit + host test),
  `plugins/m365/tests/apps_chats.rs`.
- **Lists of objects** in `config_schema`: a property `{"type": "array", "items": {"type": "object", "properties":
  {…scalars…}, "required": […]}}` (M365 `apps`). The web-api validates every item like an object (unknown
  properties refused). `secret_fields` names apply inside the items as well (sealed at `/apps/<i>/<field>`,
  returned as `<field>_set` per item, kept on update when the item's other fields are unchanged at the same
  position; a moved or new item must bring its secrets again). The form renders such lists as repeatable groups.

## v1.4 — restores per snapshot kind (2026-10-11, docs/phase12-contract.md §6)
Manifest only; protocol and API version unchanged (`api: 1`). A restore spec may name `"applies_to"`: `"guest"`
(offered only on snapshots of one guest, `plugin-<p>-<sid>-<guest>`), `"source"` (only on whole-source snapshots,
`plugin-<p>-<sid>`) or `"any"` (default; also when the field is absent, so v1.3 manifests behave as before).
`Manifest::validate` refuses other values. Enforced twice: the web-api refuses a `plugin_restore` job whose
snapshot kind does not match (400), and `nexus-pluginhost restore` refuses it before the plugin starts (an older
web-api cannot bypass it). `GET /plugins` returns the manifest as signed, so the UI reads `applies_to` from there
and offers a restore only where it applies. PostgreSQL: `to_target` (a database dump) = `guest`, `pitr` (base backup
+ WAL of the cluster) = `source`. A v1.3 host ignores the field (it would offer and run both restores everywhere,
failing inside the plugin as before). Tested: `crates/plugin-proto` (validation, shipped PostgreSQL manifest),
`crates/web-api/tests/plugins.rs` (refusal at the API).

## v1.6 — snapshot metadata, endpoint host lists (2026-10-12, Phase 18b PostgreSQL)
Additive; `api: 1` unchanged.
- **`SnapshotMeta { json }`** (plugin → host, backup only, at most once, before `Done`; appended variant, older
  variants keep their wire index): a JSON object of at most 16 KiB (`check` refuses anything else) that the
  appliance keeps with the snapshot. SDK: `Sink::snapshot_meta(&Value)`. The host returns it as `meta` per snapshot
  in its `result {json}` line (`backup::Report::meta`); the scheduler stores it in `snapshots.meta` (catalog v23,
  docs/control-plane.md) and `GET /snapshots` returns it. Generic: the web UI interprets known keys only —
  `recoverable: {from_time, to_time, from_lsn, to_lsn, timeline}` bounds the point-in-time target of a restore
  that has a `target_time` parameter (range box + time picker; a target outside it is refused in the form).
  A plugin that sends it needs a v1.6 host (a v1.5 host stops it with "unexpected message").
- **Endpoint host lists:** an endpoint's `host` pointer may name an array of strings; each item is `host` or
  `host:port` (`[v6]:port`, bare IPv6), the port of an item without one comes from the endpoint's port field
  (`plugin_proto::split_host_port`). `KindSpec::tcp_targets` returns one target per item, so the firewall and the
  Landlock port list cover every server. PostgreSQL uses it for `hosts` (HA). A v1.5 host ignores array values
  (only `host` opens).
- PostgreSQL plugin 1.2.0 (plugins/postgresql/README.md): WAL-only frequent runs with a recovery marker commit,
  the recoverable range as snapshot metadata, recovery to an LSN or a named restore point, tablespace remapping,
  start after restore, primary selection among several servers. Tested: `crates/plugin-proto` (wire index, limits,
  host lists), `crates/plugin-host/tests/host.rs` (metadata in the report, twice = violation),
  `crates/scheduler` (result → `snapshots.meta`), `plugins/postgresql/tests/pg.rs` (real PostgreSQL 14 and 17).
