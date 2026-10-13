# Plan: pushing agent updates from the appliance (Phase 27)

Status: proposed 2026-10-13, not started. Scope: Linux agent (bundle, `.deb`, `.rpm`; x86_64 + aarch64),
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
