# Plugin System — Contract (Phase 9)

Status: v1 (2026-10-10). Decisions (plan.md §2): plugins are **signed executables run as sandboxed processes**
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
  `nexus-pluginhost`; retention/offsite/replication treat plugin snapshots like any other.
- UI: Plugins page (install with signature details, publisher keys), dynamic source forms, restore dialogs.

## Milestone M9
The PostgreSQL plugin (logical dumps per database + base backup + WAL for point-in-time restore) is installed as a
signed bundle, configured, backed up on a schedule, restored to an alternate server and point-in-time restored, all in
the UI without core changes; the TrueNAS connector runs as a plugin on the same SDK with its existing lab passing.
