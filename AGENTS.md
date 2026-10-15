# AGENTS.md

Instructions for coding agents (and humans) working on this repository. Read this first; `README.md` says what the
product is, [`plan.md`](plan.md) why it is built this way, [`state.md`](state.md) where it stands.

## Ground rules

- **Ask before installing software** on the development machine or a lab host (packages, global npm/cargo tools,
  containers that are not already used by a script). `npx` only for tools in `web/node_modules/.bin`; prettier is
  pinned there.
- **No emojis** anywhere: code, UI strings, docs, test data, commit messages. The pre-commit hook refuses them.
- **No secrets in the repository.** Lab credentials live in `~/nexus-lab/` (never committed). Test keys in the tree
  are marked as such (`release/testkey/`, `TEST-KEY-DO-NOT-SHIP`).
- **Stop processes by PID**, never with `pkill -f` / `killall` (a pattern can hit unrelated processes).
- **Keep `state.md` current**: tick what is done, add what is open, record lab results with numbers and dates.
  Decisions go to `plan.md` (§2 decision table or the phase section).
- **The repository stays private** until the maintainer says otherwise; images on ghcr.io too.
- Prefer the smallest change that works and matches the surrounding code. No new dependency for what a few lines do.

## Layout

| Path | What |
|---|---|
| `crates/chunkstore`, `keyd`, `catalog` | data plane core: chunk store (crypto, locks, GC), key service, SQLite catalog + audit |
| `crates/web-api`, `web/` | REST API (axum, `openapi.json`) and the Svelte 5 UI; `web/mock/` is the mock backend for UI work |
| `crates/scheduler` | policies, job runner (spawns the connector binaries), alerts, firewall sync |
| `crates/pve`, `pve-plugin/` | Proxmox VE connector and the Perl node plugin (storage plugin, backup provider, SSH helper) |
| `crates/agent-*` | agent protocol, Linux/Windows agents, desktop UI, appliance side (`agent-conn`) |
| `crates/fsindex` | read-only guest file system parsers for the file index (NTFS, ext4, XFS, btrfs, FAT, LVM, LDM) |
| `crates/offsite`, `replication`, `nas`, `truenas`, `plugin-*`, `plugins/` | other connectors and the plugin system |
| `os/` | bootc Containerfile, systemd units, SELinux policy, nftables, greenboot checks |
| `release/` | packaging, signing (offline key), verification, promotion |
| `docs/` | contracts and designs (`docs/pve-connector.md`, `docs/adr.md`, ...); comparisons are background reading |
| `manual/` | user manual; screenshots from `manual/tools/screenshots.mjs` against the mock backend |
| `lab/` | reproducible labs (`lab/README.md`); `lab/pvehost/` drives the real PVE lab host |

Where to start for a change: the user-facing behaviour is described in `manual/`, the wire contracts in `docs/`, the
job kinds in `crates/scheduler` and `crates/web-api/src/jobs.rs`.

## Setup

```sh
git config core.hooksPath .githooks             # pre-commit (seconds) and pre-push (about a minute)
git config blame.ignoreRevsFile .git-blame-ignore-revs
(cd web && npm ci --ignore-scripts)              # svelte-check, prettier, vite
```

## Gates before every commit

| Change in | Run |
|---|---|
| Rust | `cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`, `cargo test -p <crate>` (CI runs `cargo test --all`) |
| `web/` | `cd web && npm run format && npm run check && npm run build` |
| `pve-plugin/` | `prove pve-plugin/t` (about 30 s, taint mode like PVE's workers) |
| `os/`, `release/` | `python3 -m unittest discover -s os/greenboot/tests`, `release/check-trust.sh` |
| UI visible change | regenerate the affected manual screenshots (`node manual/tools/screenshots.mjs`, see the script header) |

The hooks run the fast part automatically; `--no-verify` skips them only for a deliberate exception (for example a
test key). After pushing, check the CI run (`gh run list -L 3`) and fix a red run before anything else. CI runs only
the jobs whose files changed (`.github/workflows/ci.yml`, job `changes`). CI runs the tests with cargo-nextest (all test binaries in parallel, `.config/nextest.toml`) and the container-based MySQL, PostgreSQL and Keycloak suites in a separate `testbox` job; locally `cargo test` is fine.

## Conventions

- **Rust:** `anyhow` errors with `.context("...")` naming what failed (no `thiserror` in the tree). Unit tests
  in the same file (`#[cfg(test)] mod tests`), integration tests in `crates/<crate>/tests/`. Doc comments on public
  items say what and why, not how. Mark deliberate simplifications with a comment naming the limit.
- **Connectors** are separate binaries started by the scheduler with a JSON config file; they print progress lines
  the scheduler parses (`@<unix time>`, `progress ...`, `result ...`). Keep that format stable.
- **Web UI:** Svelte 5 runes, strings in `web/src/lib/i18n.ts`, API types in `web/src/lib/types.ts`; every new API
  call also gets a mock in `web/mock/api.ts`. Show the user state and next steps: link jobs, explain waits and errors.
- **Database:** catalog migrations are append-only (`SCHEMA_Vnn` in `crates/catalog`); never edit a released one.
- **Security-relevant changes** (auth, approvals, locks, crypto, firewall, update policy) get a test that fails
  without the change, and a line in `docs/security-review.md` if they close or open a finding.
- **Commits:** one topic per commit, imperative summary that says what changed and why, details in the body. Run
  `cargo fmt --all` first. Push to `main` directly; tags only on a commit that passed CI.

## Labs

- Lab hosts, credentials and VM lists: `lab/README.md` and `~/nexus-lab/` (outside the repository).
- On the PVE lab host (`10.2.34.200`) only VMs with ID 200 and above are ours to create and destroy. VMs 100 to 103
  belong to the maintainer: Windows tests use **VM 101 only** and never write to its disks (restore tests run on
  isolated copies). **VM 103 is the CI runner: do not touch it**; if the runner is offline, report it.
- Keep `~/nexus-lab/pvehost/appliance/root/secrets.env` when cleaning up a lab.
- Record every lab run in `state.md`: date, commit, what ran, the numbers, what failed.

## Releases

`docs/release.md`. In short: tag `vX.Y.Z[-pre]` on a green main commit; `release.yml` builds and pushes the image,
SBOM, CVE scan and agent packages into a draft; `iso.yml` adds the ISOs and checks the asset list. The maintainer
signs with the offline key (`release/sign.sh`) and publishes. CI never holds the signing key.
