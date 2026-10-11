# Writing NexusBackup plugins (Rust SDK)

A plugin adds a source type (and its restore functions) to the appliance without changing the core. It is a
signed executable that the appliance starts in a sandbox for each operation and talks to over stdin/stdout. The
binding contract is docs/plugin-system.md; this guide shows how to build one with crate `plugin-sdk`. The complete
example is `plugins/example-files` (backs up a local directory, restores it into a directory); `plugins/truenas`
is a real connector (API client + `ssh` in the sandbox, guests, incremental via the state blob, docs/truenas-connector.md §9);
`plugins/m365` is a cloud connector (HTTPS API with fixed default hosts, certificate auth, delta queries, `base_list`,
a mock server in its tests, docs/m365.md).

## What a plugin does — and what it never sees

| The plugin | The appliance (`nexus-pluginhost`) |
|---|---|
| connects to its source system with the source's credentials (from its config) | starts the plugin in its sandbox, checks the installed binary |
| lists guests (databases, VMs …), validates connectivity | chunks, deduplicates, encrypts, stores, commits snapshots |
| sends files (path + metadata + bytes), says *unchanged* for files it can prove unchanged, sends application streams (dumps, logs) | validates every message; reuses data for *unchanged* files only from its own base snapshot |
| restores: asks for files/streams and writes them to the target system | serves the requested snapshot content; generic download (tar/zip) without the plugin |

A plugin never gets tenant keys, the chunk store, the catalog or other tenants' data, and it cannot reach the
appliance's own services. Treat everything you receive as the data of exactly one source of one tenant.

## Project layout

```text
my-plugin/
  Cargo.toml          [dependencies] plugin-sdk = …   [dev-dependencies] plugin-sdk = { …, features = ["testing"] }
  manifest.json       id, version, kinds (config schema, secrets, endpoints, guests, restores), sandbox limits
  src/main.rs         impl plugin_sdk::Plugin; fn main() { plugin_sdk::run(MyPlugin) }
  tests/roundtrip.rs  plugin_sdk::testing::Host against the real host code
```

## The manifest

```json
{
  "id": "postgresql", "name": "PostgreSQL", "version": "1.0.0", "publisher": "acme", "api": 1,
  "kinds": [{
    "kind": "postgresql", "title": "PostgreSQL server",
    "config_schema": {"type": "object", "required": ["host", "user", "password"], "properties": {
      "host": {"type": "string", "format": "hostname", "title": "Server"},
      "port": {"type": "integer", "format": "port", "default": 5432},
      "user": {"type": "string", "pattern": "^[a-z_][a-z0-9_]*$"},
      "password": {"type": "string", "format": "password"},
      "sslmode": {"type": "string", "enum": ["require", "verify-full"]}}},
    "secret_fields": ["password"],
    "endpoints": [{"host": "/host", "port": "/port", "default_port": 5432, "proto": "tcp"}],
    "guests": {"title": "Databases", "list": true},
    "restores": [
      {"id": "download", "title": "Download (tar/zip)"},
      {"id": "to_target", "title": "Restore to server", "params_schema": {"type": "object", "required": ["database"],
        "properties": {"database": {"type": "string", "pattern": "^[a-z0-9_]+$"}}}}
    ]
  }],
  "sandbox": {"network": "endpoints", "tmp_mb": 1024, "memory_mb": 1024}
}
```

Rules (checked by `nexus-plugin pack` and again by the appliance):
- `id`: `[a-z0-9-]{2,32}`, no all-digit `-` component (`pg-15` is not allowed). The id belongs to the first publisher
  that installs it. `version`: `MAJOR.MINOR.PATCH`, every upload strictly newer. `publisher` must be the publisher of
  the signing key (the appliance admin binds your key to this name).
- `config_schema` — the subset the UI renders and the web-api validates: an object with `properties` and `required`;
  property types `string` (`enum`, `pattern`, `minLength`/`maxLength`, `format`: `hostname`, `port`, `password`),
  `integer` (`minimum`/`maximum`, `format: port`), `boolean`, `array` of strings. Unknown properties are refused.
- `secret_fields`: top-level properties that are write-only and sealed at rest; your plugin receives them in clear in
  `ctx.config` (memory only — never log them).
- `endpoints`: JSON pointers into the config. They open the appliance firewall (TCP) for this source and are the
  only TCP ports your process can connect to (plus DNS). `"default_host"` (v1.3) names a fixed DNS host used when
  the config field is empty (cloud APIs: `{"host": "/graph_host", "default_host": "graph.microsoft.com",
  "default_port": 443, "proto": "tcp"}`). `sandbox.network: "none"` = no network.
- `guests`: `{"title", "list": true}` if a group selects guests; implement `list_guests`. Every guest gets its own
  snapshot (`plugin-<id>-<source>-<guest>`); guest ids are `[A-Za-z0-9._-]{1,64}`.
- `restores`: `download` is mandatory and done by the appliance (files + your streams below `.nexus-streams/`).
  Others (`[a-z0-9_-]`) call your `restore` with `ctx.params["restore"]` = the id; their `params_schema` drives the
  restore dialog. An entry with id `mount` enables the mount operation. Restore parameters are visible in the job
  list: never ask for passwords there.

## The `Plugin` trait

```rust
use plugin_sdk::*;

struct Pg;

impl Plugin for Pg {
    fn validate(&mut self, ctx: &Ctx) -> Result<Validation> {
        // connect with ctx.config, check permissions
        Ok(Validation::Invalid { field: "password".into(), message: "authentication failed".into() })
    }
    fn list_guests(&mut self, ctx: &Ctx) -> Result<Vec<Guest>> {
        Ok(vec![Guest { id: "app".into(), title: "app (12 GB)".into(), size: Some(12 << 30) }])
    }
    fn backup(&mut self, ctx: &Ctx, sink: &mut Sink) -> Result<BackupResult> {
        let db = ctx.guest().unwrap_or("postgres");
        let mut s = sink.stream(&format!("{db}/dump.sql"))?;   // write_all(&mut s, …) as you produce it
        // … pg_dump into s …
        s.finish()?;
        Ok(BackupResult { state: Some(b"lsn=0/16B3748".to_vec()), consistent: true, summary: "1 dump".into() })
    }
    fn restore(&mut self, ctx: &Ctx, src: &mut Source) -> Result<String> {
        let db = ctx.params["params"]["database"].as_str().unwrap_or_default();
        src.streams(&[format!("{db}/dump.sql")], |_name, data| { /* psql < data */ Ok(()) })?;
        Ok(format!("restored into {db}"))
    }
}

fn main() { plugin_sdk::run(Pg) }
```

- `Ctx`: `kind`, `op`, `config` (secrets opened), `params` (backup: `{"guest", "source_id"}`; restore/mount: see
  contract), `source_id()` (to name objects you create on the source system),
  `base_time` + `state` (your state blob of the previous snapshot / of the restored snapshot), `log`/`info`/`warn`,
  `progress`. Logs are escaped and shown in the job log.
- Errors: return `Err(...)`; `plugin_sdk::error(code, msg)` sets the protocol error code. The job fails, nothing is
  committed.
- `consistent`: say `false` if you could not get a consistent view (no snapshot, live files). The appliance shows it
  per snapshot and warns once per source.
- `state`: ≤ 1 MiB, opaque, stored encrypted with the snapshot (e.g. last WAL position, change tokens).

### Sending data (`Sink`)
- `sink.file(path, meta, &mut reader)` — exactly `meta.size` bytes are sent; if the reader returns less/more (file
  changed while read) the SDK pads/cuts and marks the backup not consistent.
- `sink.entry(path, meta)` — directories, symlinks (`link_target`), fifos, hard links (`Kind::Hardlink`,
  `link_target` = an earlier regular file's path).
- `sink.unchanged(path, meta)` — the file is identical to the base snapshot. The host checks type, mode, owner,
  mtime, link target and size against **its own** base entry and reuses its data; a wrong claim fails the backup
  (it never takes chunk ids from you).
- `sink.base(&paths)` — metadata of these paths in the base snapshot (to decide `unchanged`).
- `sink.base_list()` — every entry of the base snapshot in path order with full metadata (v1.3). Keep your own ids
  in xattrs and rebuild your previous view from it instead of storing item lists in the 1 MiB state blob
  (`plugins/m365`).
- `sink.walk_dir(root, &WalkOptions { excludes, xattrs })` — a local directory tree with all of the above
  (deterministic order, hard links, xattrs, glob excludes, unchanged by size+mtime+ctime+inode+mode+owner).
- `sink.stream(name)` — application data (`[A-Za-z0-9._/-]`, unique); bounded 1 MiB buffer; `finish()`.

Paths are relative, `/`-separated bytes without `.`/`..`, unique, ≤ 4096 bytes; `.nexus-streams/` is reserved.

### Restoring (`Source`)
- `src.files(&paths, |item, data| …)` — entries at/below the paths (`ctx.params["top"]` lists the top level).
  If the callback returns an error, the SDK drains the rest of the answer and then returns it, so your error
  message reaches the job log.
- `src.streams(&names, |name, data| …)` — `ctx.params["streams"]` lists the snapshot's streams.
- `src.restore_tree(&paths, target_dir, &RestoreOptions { overwrite, owners, xattrs })` — safe local restore
  (component-wise `openat` with `O_NOFOLLOW`, exclusive create, metadata, hard links, directory times last).

### Mount (`Mount`)
`m.ready(info)` (shown to the user), `m.read_file(path, offset, len)` on demand, `m.wait_unmount()`; the host ends
the mount after the requested minutes.

## The sandbox — what your process can do
Your plugin runs as an unprivileged process: read-only access to its install dir and the system libraries/tools
under `/usr`, a private writable `$TMPDIR` (= `$HOME`, limited to `sandbox.tmp_mb`), TCP connections only to the
ports of your endpoints (+ DNS), no TCP listening, no Unix sockets, no access to other processes, memory limited to
`sandbox.memory_mb`, a cleared environment. Dynamically linked binaries must work with the appliance image's
libraries (AlmaLinux 10, glibc 2.39); a static (musl) build is the safe choice. External tools (`pg_dump`, `ssh`)
can be executed if the image ships them; they inherit the sandbox (`ssh`: key and `known_hosts` in `$TMPDIR`, pass
them with `-i` / `-o UserKnownHostsFile=`, no agent). Anything else fails with `EACCES`/`EPERM` — design for it, do not work around it.

Time limits: 24 h per operation, 15 min without any message (send `progress` during long silent phases).

## Testing
```rust
use plugin_sdk::testing::Host;
let mut h = Host::binary("manifest.json".as_ref(), env!("CARGO_BIN_EXE_my-plugin").as_ref(), "mykind")?;
h.read_paths.push(test_data_dir);              // sandbox exceptions for local test data
let b = h.backup(&serde_json::json!({...}), Some("guest1"))?;      // real host code, temp chunk store
let r = h.restore(&cfg, &b.source, b.time, "to_target", serde_json::json!({...}))?;
```
`Host::binary` runs your real binary in the real sandbox (Landlock + seccomp; no root needed; TCP to the endpoint
ports the config resolves, as on the appliance);
`Host::in_process(manifest, kind, || MyPlugin)` runs it on a thread for quick logic tests. `h.log()` shows the job
log, `h.snapshot()` / `h.store()` give access to what was committed. The sandbox opens the TCP ports of your
endpoints as resolved in the config you pass (as on the appliance), so local test servers work. See
`plugins/example-files/tests/roundtrip.rs` and `plugins/truenas/tests/plugin.rs` (mock API server over wss, local
sshd), and `plugins/postgresql/tests/pg.rs` (a real server in podman).

## Packaging and signing
```sh
cargo build --release --target x86_64-unknown-linux-musl
nexus-plugin pack manifest.json target/x86_64-unknown-linux-musl/release/my-plugin my-plugin-1.0.0.nxplugin [assets/]
nexus-plugin keygen acme                      # once: acme.key (keep offline) + acme.pub
nexus-plugin sign my-plugin-1.0.0.nxplugin acme.key          # -> my-plugin-1.0.0.nxplugin.sig
nexus-plugin verify my-plugin-1.0.0.nxplugin my-plugin-1.0.0.nxplugin.sig acme.pub
nexus-plugin inspect my-plugin-1.0.0.nxplugin
```
The signature format is cosign's `sign-blob` output, so `cosign sign-blob --key cosign.key bundle` works too; project
plugins are signed with the release key via `release/sign.sh sign-blob <bundle> <bundle>.sig`.

Installing on an appliance: an admin adds your public key under Plugins → Publisher keys (a security officer
approves), then uploads bundle + signature (another approval). The appliance shows publisher, signing key, digests,
kinds, endpoints and sandbox limits before the approval.
