# Plan: pushing agent updates from the appliance (Phase 27)

Status: proposed 2026-10-13, decided and implemented 2026-10-14 (see "Implementation" at the end; "Where we are
today" describes the state before Phase 27). Scope: Linux agent (bundle, `.deb`, `.rpm`; x86_64 + aarch64),
Windows agent (MSI, manual install), and the desktop GUI that ships with them.

## Where we are today

- In-band self-update exists (`agent_update` job, `nexus-agentctl update`, protocol `Update`/`UpdateDone`):
  the appliance sends one signed binary; the agent checks the cosign signature against its pinned release keys,
  refuses downgrades and same versions, swaps the binary (`.prev` kept) and restarts (exit 75 / SCM restart).
  Verified in the labs on Linux (bundle) and on Windows Server 2022 (refusal of MSI installs).
- Gaps:
  1. One update directory per appliance with fixed file names: no per-OS / per-arch selection, `HelloReply` has
     no architecture.
  2. The appliance image ships no agent releases (`/usr/share/nexus/agent` is empty in production).
  3. Package installs (deb/rpm/MSI, the recommended install path) refuse in-band updates: updating them means
     apt/dnf/GPO/Intune outside the appliance.
  4. One protocol frame (8 MiB) per update.
  5. Manual, one agent at a time: no bulk update, no rollout waves, no automatic mode, no state per agent.
  6. The desktop GUI (`nexus-agent-gui`) is never updated in-band.
  7. No installer download from the appliance.

## Decisions (proposed, to be recorded in plan.md §2)

| Decision | Choice | Rationale |
|---|---|---|
| Where releases come from | **With the appliance OS update** (each image carries the matching agent release), plus **signed upload** in the UI for out-of-band releases; no internet fetch by the appliance | Egress stays closed; the appliance and its agents move together; air-gapped sites work. |
| Who can make an update | **Only the offline release key** (cosign, as today); the agent verifies against its pinned keys | A compromised appliance or admin account cannot push code to every server: it can only choose *which signed release* and *when*. |
| Package installs | **Updated with their own package type**: deb with deb, rpm with rpm, MSI with MSI; never a binary swap under a package manager | The package database stays truthful; uninstall/upgrade by apt/dnf/GPO keeps working. |
| Local veto | `self_update = off` in `agent.conf` **always wins**; default becomes `auto` (allowed for the package type the agent was installed with) | The server owner keeps control; managed-by-GPO sites keep their process. |
| Downgrades | Refused, except an explicit **rollback** to a signed older release, which needs **approval (quorum)** | Downgrade to a vulnerable release is an attack. |
| Default mode | **Manual** (admin starts a rollout); **automatic** optional per tenant/group with maintenance window + canary | Predictable for MSPs; no surprise restarts. |

## Design

### 27a. Releases, protocol, single-agent push of packages

- **Release store** on the appliance: `/usr/share/nexus/agent/<version>/` from the image (read-only) and
  `/var/lib/nexus/agent-releases/<version>/` for uploads. Per version a signed `manifest.json`
  (version, protocol, min appliance, artifacts with sha256 and size) and the artifacts:
  `linux-x86_64/nexus-agent` (bundle binary), `linux-aarch64/…`, `windows-x64/nexus-agent.exe`, the packages
  (`.deb`, `.rpm` per arch, `.msi`, the desktop packages) and their `.sig`. The release workflow produces this
  tree; `os/Containerfile` copies it into the image (closes gap 2). Upload: Agents → Updates → Upload release
  (tar), verified against the pinned release keys before it is accepted.
- **Protocol v1.8**: `HelloReply` gains `arch` (`x86_64|aarch64`), `install` (`bundle|deb|rpm|msi|manual`) and
  `gui_version` (if installed). Chunked transfer `UpdateBegin{kind, version, size, sha256, signature}` /
  `UpdateChunk` / `UpdateCommit` replaces the single frame (gap 4; old agents keep `Update`).
- **Agent side** (agent-core + platform):
  - bundle / manual: as today (binary swap, `.prev`, restart), plus a **start watchdog**: a new binary that does
    not reach "listening" twice in a row is swapped back to `.prev` (Linux: `ExecStartPre` check of a crash
    counter; Windows: counter in `%ProgramData%\NexusAgent\state`, checked at service start).
  - deb/rpm: the verified package is installed by a **transient systemd unit** (`systemd-run --unit
    nexus-agent-update -- apt-get install -y ./x.deb` / `dnf install -y ./x.rpm`, desktop package in the same
    transaction when installed) so the upgrade survives the agent's own restart; result in
    `/var/lib/nexus-agent/update-state.json`, reported on the next `Hello`.
  - MSI: `msiexec /i x.msi /qn /l*v <state>\update-msi.log` started **detached** from the service (outside its
    job object) so it can stop and replace the service; the MSI's major upgrade keeps the enrollment; result +
    log tail reported on the next `Hello`. The MSI carries the GUI, so Windows GUI updates come for free (gap 6).
- **Appliance**: `agent_update` picks the artifact by `os`/`arch`/`install` from the release store (gap 1);
  per-agent state in the catalog (migration): `agents.update_target`, `update_state`
  (`pending|sending|installing|ok|failed|rolled_back`), `update_error`, `update_attempts`, `update_at`.
- **Installer downloads** (gap 7): Agents → Add agent offers the matching installer from the release store
  through the existing download-token mechanism, with its sha256.

### 27b. Rollouts

- Agents → **Updates** tab: available releases (signature state, notes), agents per version, "outdated"
  filter (below the appliance's recommended version) and "unsupported" (below the minimum protocol).
- **Rollout** = target version + scope (all, tenant, protection group, OS, tag, selected agents) + waves
  (canary n agents or %, then the rest after a soak time) + concurrency cap + failure threshold (pause the
  rollout after k failures or x %). Pause / resume / cancel; audited (`agent.rollout.*`).
- Scheduler: a rollout poller queues `agent_update` jobs per wave, skips agents with running jobs (busy is
  retried, not failed), honours blackout windows, and treats a missing reconnect with the new version within
  10 min as failed. Laptops and edge-connected agents are updated on their next poll session (v1.4 poll /
  edge rendezvous), so offline machines catch up when they appear.
- Alerts: `agent_update_failed` (per agent, auto-resolved by a later success), `rollout_paused`.

### 27c. Automatic mode and rollback

- Per tenant / group: `updates: manual | automatic` with a maintenance window (shared window type from 16a)
  and the canary settings. A new release arriving with an appliance update then rolls out by itself.
- Rollback: rollout to an older signed release, approval required (quorum action `agent.rollback`).

## Security notes (threat model rows T57+)

- The appliance chooses *which* signed release goes *where*; it can never create one. Agents refuse unsigned,
  foreign-key, older (without rollback marker signed for that version pair) and wrong-platform artifacts.
- Updates run as root/SYSTEM by design; the agent installs only the verified file it received, by path, with a
  fixed command line (no shell, no appliance-supplied arguments).
- Abuse case: mass restart of agents during backups — mitigated by busy checks, waves, windows, audit.

## Tests and labs

- Unit: artifact selection, state machine, waves and failure threshold, chunked transfer, watchdog revert,
  downgrade/rollback rules, package-command construction (no shell).
- Labs: `lab/linux` (bundle on deb-plain, `.deb` on deb-lvm, `.rpm` on alma-xfs, desktop package with the GUI
  running), `lab/windows` (MSI on Server 2022 and Windows 11 with the GUI running, service stays enrolled,
  `.prev`/MSI rollback), an edge-connected laptop updated on reconnect, kill during update, arm64 in the
  emulated aarch64 VM on the PVE lab host.
- Manual: chapter 13 (agent updates), 16/17 (update sections), screenshots of the Updates tab.

## Order and size

27a (protocol, release store, package installs, one agent) → 27b (rollouts + UI) → 27c (automatic, rollback).
27a is the largest part; 27b/27c reuse the scheduler's poller, approval and window code.

## Implementation (Phase 27, 2026-10-14)

Status: implemented (27a, 27b, 27c). This section is the contract between the agents, `nexus-agentctl`, the
scheduler, the web-api and the web UI; deviations from the proposal above are marked **Deviation**.

### Protocol v1.8 (crate `agent-proto`, docs/agent-protocol.md "v1.8")

- **Capability `update2`**: the agent understands the chunked update messages below. Agents without it (v1.7 and
  older) still get the single-frame `Update` (binary swap, at most 8 MiB) as before.
- **Host facts.** **Deviation:** `HelloReply` is a postcard struct variant; new fields would make every v1.8
  appliance fail to decode the `HelloReply` of an older agent. The facts therefore travel as capabilities in
  `HelloReply.caps`: `arch=x86_64|aarch64`, `install=bundle|deb|rpm|msi|manual` and `gui=<version>` (only when the
  desktop UI is installed). `agent_proto::release::HostFacts::from_caps` parses them; the appliance shows them as
  `arch`, `install`, `gui_version`.
- **Messages** (appended after `EdgeSet` = 48):

  | Tag | Message | Direction | Answer |
  |---|---|---|---|
  | 49 | `UpdateBegin { kind, name, size, sha256, signature, manifest, manifest_sig, rollback }` | appliance to agent | `UpdateReady` or `Error` |
  | 50 | `UpdateReady` | agent to appliance | |
  | 51 | `UpdateChunk { data }` (at most 4 MiB) | appliance to agent | none (stream) |
  | 52 | `UpdateCommit { apply }` | appliance to agent | `UpdateStaged` (`apply = false`), `UpdateDone` or `Error` |
  | 53 | `UpdateStaged` | agent to appliance | |
  | 54 | `UpdateStatus` | appliance to agent | `UpdateState { json }` |
  | 55 | `UpdateState { json }` (at most 16 KiB) | agent to appliance | |

  `kind` is the artifact kind of the manifest (`binary`, `deb`, `rpm`, `msi`, `desktop-deb`, `desktop-rpm`), `name`
  its manifest name, `signature` the cosign blob signature of the artifact, `manifest` + `manifest_sig` the signed
  release manifest it belongs to. Several artifacts are staged with `apply = false` (desktop package in the same
  transaction), the last one is committed with `apply = true`. Limits: artifact 512 MiB, signature 64 KiB,
  manifest 256 KiB, name 200 bytes.
- **Agent checks** (`agent_core::update`), in this order: `self_update = off` refuses everything; busy (jobs or a
  restore running) answers `Error 409`; the kind must match the install type (`bundle`/`manual`: `binary`; `deb`:
  `deb` + `desktop-deb`; `rpm`: `rpm` + `desktop-rpm`; `msi`: `msi`; never a binary swap under a package manager);
  the manifest signature verifies with a pinned release key; the artifact is listed in it with this `name`, `kind`,
  OS and architecture, size and SHA-256; the artifact's own signature verifies; the manifest version is strictly
  newer than the running one, or, with `rollback`, older but not below the agent's compiled-in `ROLLBACK_FLOOR`
  (**Deviation:** instead of a per-pair rollback marker; the floor is part of the signed binary, so a compromised
  appliance cannot roll an agent back below what its release allows). A `binary` must also carry the same embedded
  version marker and be a native executable.
- **Installing.** `binary`: swap (`.prev` kept) and restart, as before. `deb`/`rpm`: `systemd-run
  --unit=nexus-agent-update … /usr/bin/apt-get install -y <files>` (rpm: `dnf install -y`, rollback `dnf downgrade
  -y`, fallback `rpm -U [--oldpackage]`), no shell, only the absolute paths of the staged files. `msi`:
  `msiexec.exe /i <file> /qn /norestart /l*v <state>\update-msi.log`, started detached (breakaway from the
  service's job object). State: `<state>/update-pending.json` while an install runs, `<state>/update-state.json`
  with `{state: installing|ok|failed|rolled_back, kind, from, to, at, error, log}` afterwards (the answer to
  `UpdateStatus`).
- **Start probe** (binary swaps, #120): before the swap the running agent runs the staged, signature-checked binary
  with `version` (30 s); it must exit 0 and name the expected version, else the update fails and nothing is
  swapped. This catches every binary that never reaches its own code (loader or libc mismatch, CPU features, a
  truncated file that still carries the marker), on Linux and Windows alike.
- **Start watchdog** (binary swaps): `update-pending.json` counts starts; the agent removes it once it listens. The
  third start without reaching "listening" swaps `.prev` back, records `rolled_back` and restarts.
  **Deviation:** the counter is checked by the agent binary at the very start of `run` (Linux and Windows), not by
  an `ExecStartPre` shell snippet: the binary is signed and verified before the swap, so the realistic failures
  (panic during start-up, a listener that cannot bind, an incompatible configuration) are caught, and the unit
  keeps no shell.

### Release store

- `/usr/share/nexus/agent/<version>/` (from the image, read-only) and `/var/lib/nexus/agent-releases/<version>/`
  (uploads). Per version `manifest.json` + `manifest.json.sig` and the artifacts (each with `<name>.sig`).
- `manifest.json`: `{format: 1, version, protocol: "1.8", min_appliance, released, notes, artifacts: [{name, kind,
  os, arch, version, size, sha256}]}`; `name` is a relative path (`linux-x86_64/nexus-agent`,
  `linux-x86_64/nexus-agent_0.2.0_amd64.deb`, `windows-x64/nexus-agent-0.2.0-x64.msi`, ...). Download-only kinds:
  `bundle` (the install bundle `.tar.gz`), `exe` (Windows `nexus-agent.exe`).
- The appliance verifies every manifest against its pinned keys (`/etc/pki/nexus/cosign/*.pub`); unsigned or
  foreign releases are listed with `signed: false` and an error and are never offered or sent.
- Produced by `release/packages.sh` (`target/packages/agent-release/<version>/` and
  `nexus-agent-release-<version>.tar`), signed offline by `release/sign.sh sign-agent-release <dir>`, shipped in
  the image from `os/agent-release/` (lab: signed with the TEST key).

### nexus-agentctl `update`

Config `update: {release_dir, version, rollback}` (the old `update_dir` still works). Lines: `agent-info {...,
arch, install, gui_version}`, `update-plan {"from","to","install","artifacts":[...],"mode":"chunked|legacy"}`,
`update-sent {"to"}`, `update-state {...}` (the agent's state after reconnecting) and finally `update-result
{"agent_id","state":"ok|failed|rolled_back|busy","version","error"}`. The reconnect check waits up to 10 min
(package installs) or 2 min (binary swaps).

### Catalog v41

- `agents`: `arch`, `install`, `gui_version`, `caps` (JSON array), `tags` (JSON array, default `[]`),
  `update_target`, `update_state` (`pending|sending|installing|ok|failed|rolled_back`), `update_error`,
  `update_attempts`, `update_at`.
- `agent_rollouts (id, version, scope JSON, canary, canary_pct, soak_minutes, concurrency, max_failures,
  max_failure_pct, windows JSON, rollback, automatic, state, reason, wave, wave_done_at, quorum_id, created,
  created_by, finished)`; `state` one of `pending_approval|running|paused|cancelled|done|rejected`.
- `agent_rollout_items (rollout_id, agent_id, tenant, wave, state, job_id, attempts, error, from_version,
  updated)`; `state` one of `waiting|queued|running|ok|failed|skipped|cancelled`.
- `agent_update_settings (tenant, group_id (0 = whole tenant), mode manual|automatic, windows JSON, canary,
  soak_minutes, updated, updated_by)`.
- `agent_downloads (token, version, artifact, requested_by, created, expires)`.

### Web API

| Method + path | Roles | Body / answer |
|---|---|---|
| `GET /agent-releases` | all | `{recommended, releases: [{version, source: image\|upload, signed, key, error, protocol, min_appliance, released, notes, artifacts: [{name, kind, os, arch, version, size, sha256}]}]}` |
| `POST /agent-releases` | admin | body: the release as tar (`application/x-tar`, at most 512 MiB) answers 201 `{version}`; audited `agent.release.upload` |
| `DELETE /agent-releases/{version}` | admin | uploaded releases only; audited `agent.release.delete` |
| `POST /agent-releases/{version}/download` | admin, tenant_admin (with the download right) | `{artifact}` answers `{token, url, name, size, sha256, expires}`; `GET /downloads/{token}` serves the file (1 h) |
| `PUT /agents/{id}/tags` | admin, tenant_admin | `{tags: [...]}` (at most 16, `[a-z0-9_.-]{1,32}`) |
| `GET /agent-rollouts` | admin, security_officer, operator, viewer | `[{id, version, scope, canary, canary_pct, soak_minutes, concurrency, max_failures, max_failure_pct, windows, rollback, automatic, state, reason, wave, quorum_id, created, created_by, finished, counts: {total, waiting, queued, running, ok, failed, skipped, cancelled}}]` |
| `GET /agent-rollouts/{id}` | same | the rollout + `items: [{agent_id, name, tenant, wave, state, job_id, attempts, error, from_version, version, updated}]` |
| `POST /agent-rollouts` | admin | `{version, scope: {tenant?, group_id?, os?, tag?, agents?}, canary?, canary_pct?, soak_minutes?, concurrency?, max_failures?, max_failure_pct?, windows?, rollback?}` answers 201 the rollout; a rollback is gated (`agent.rollback`): 202 `{quorum_id, id}` with approvals on |
| `POST /agent-rollouts/{id}/pause`, `/resume`, `/cancel` | admin | audited `agent.rollout.pause`, `.resume`, `.cancel` |
| `GET /agent-update-settings` | admin, security_officer, operator, viewer | `[{tenant, group_id, mode, windows, canary, soak_minutes, updated, updated_by}]` |
| `PUT /agent-update-settings` | admin | `{tenant, group_id?, mode, windows?, canary?, soak_minutes?}`; audited `agent.update_settings` |

Defaults: `canary` 1, `soak_minutes` 60, `concurrency` 5, `max_failures` 3, `max_failure_pct` 20, `windows` `[]`
(any time). Windows use the blackout window type (`{days, from, to}`, UTC). Agent rows gain `arch, install,
gui_version, protocol` ("1.8" with `update2`, else "1.7"), `tags, update_target, update_state, update_error,
update_attempts, update_at`. The job `agent_update` takes `{agent_id, version?}` (default: the recommended
release; never older than the running version).

### Scheduler

Every tick: rollouts in `running` queue `agent_update` jobs for `waiting` items of the current wave (wave 0 =
canary, wave 1 = the rest after all canaries finished plus the soak time), at most `concurrency` at a time, only
inside one of the rollout's windows (if any), never for agents that are busy (a queued or running job for the
agent), unreachable (picked up when they are back) or inside an active blackout window of one of their groups'
policies. A busy answer from the agent puts the item back to `waiting`. The failure threshold (`max_failures` or
`max_failure_pct` of the finished items) or a failed canary pauses the rollout (`rollout_paused`, warning). A
failed item raises `agent_update_failed:<agent>` (warning), resolved by a later successful update. A rollback
rollout starts only when its quorum request (`agent.rollback`) is executed; rejected or expired: `rejected`.
Automatic mode: every 10 min, for each `agent_update_settings` row with `automatic`, outdated enrolled agents of
the scope get one automatic rollout per (scope, recommended version).
