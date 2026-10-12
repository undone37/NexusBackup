# Microsoft 365 plugin (Phase 11)

Backs up a Microsoft 365 tenant through Microsoft Graph with an Entra app registration (application permissions,
certificate credential — no client secret). Source kind `plugin:m365`. Design, Entra setup (permissions per
workload, certificate upload), limits and the open real-tenant run: [docs/m365.md](../../docs/m365.md).

| Guest | Snapshot `plugin-m365-<source>-<guest>` | Restores |
|---|---|---|
| `u.<user id>` | `mail/…/*.eml`, `calendar/…/*.ics`, `contacts/…/*.vcf`, `onedrive/…`, `chats/*.json+.html` (opt-in) | download; to the original or another user (new folder; also in another M365 tenant) |
| `s.<site>` | `libraries/<library>/…` | download; to the original or another site (new folder) |
| `t.<team id>` | `files/…`, `channels/<channel>/*.json` | download; to the original or another team (new folder, migration-mode channels) |

Incremental: Graph delta queries for mail folders and drives (delta links in the state blob), complete listings
for calendars and contacts, the Teams export API by modification time for channel messages; the previous
snapshot is read back with `BaseList` (contract v1.3), unchanged items go out as `Unchanged`.

Code: `src/auth.rs` (certificate credential, client assertion), `src/graph.rs` (HTTP client: tokens, retries,
paging, ranged downloads, uploads), `src/backup.rs`, `src/chats.rs` (1:1/group chats), `src/restore.rs`, `src/format.rs` (names, times, iCalendar,
vCard). Tests: `cargo test -p m365-plugin` against the Graph mock in `tests/mock/` (also runnable for development:
`cargo run -p m365-plugin --example graph_mock`). The key and certificate in `tests/data/` are test fixtures only.

App registration helpers (run on an admin machine, never on the appliance): `tools/register-app.sh` (Azure CLI)
and `tools/register-app.ps1` (PowerShell, Microsoft.Graph module), see docs/m365.md. Several app registrations
(`apps`) are used round-robin with failover when one is throttled.

Bundle: `PLUGIN=m365 lab/appliance/plugins.sh bundle` (or `nexus-plugin pack manifest.json <binary> …`, see
docs/plugin-sdk.md).
