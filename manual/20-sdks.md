# 20 SDKs (Python and PowerShell)

Scripts and integrations that work with NexusBackup from Python or PowerShell use the official SDKs instead of raw
HTTP calls. Both talk to the same REST API as the web interface and `nexusctl`, so every action goes through the same
roles, approvals and audit log.

> **Status:** Covered by unit tests against local stub servers (including TLS with a self-signed certificate);
> not run against an appliance yet. Nothing is published to PyPI or the PowerShell Gallery: install from a checkout
> of the repository. Developer details (design, sync check, versioning, releasing): `sdk/README.md` in the
> repository.

| | Python | PowerShell |
|---|---|---|
| Name | package `nexusbackup` (`sdk/python`) | module `NexusBackup` (`sdk/powershell`) |
| Needs | Python 3.10 or later, nothing else | PowerShell 7.2 or later (Windows, Linux, macOS) |
| Install | `pip install ./sdk/python` | `Import-Module ./sdk/powershell/NexusBackup` |
| Help | docstrings, `help(nexusbackup.Client)` | `Get-Help <cmdlet> -Full` |

## Signing in

- **API token** (`nxt_...`, [09 Users and access](09-users-and-access.md#api-tokens)): for scheduled scripts,
  monitoring and integrations. A **read** token only reads; an **operator** token also starts and cancels jobs,
  pauses and resumes groups, sets maintenance mode, acknowledges alerts and syncs replication; a **backup** token
  reads and starts backups only. A token acts at most as an operator, whatever the account's role, and never
  approves anything. The SDKs refuse what tokens cannot reach before sending anything.
- **As a person**, with name, password and the current TOTP code: for deciding approval requests, exporting the
  audit log as CSV and the restore point simulator. The session is ended when the script is done. A TOTP code is
  accepted once. Accounts under the passkey policy and single sign-on accounts cannot sign in this way: they use the
  web interface, and scripts use an API token. An account marked by a risk signal must step up in the web interface
  before its sessions may change anything ([09 Users and access](09-users-and-access.md#risk-signals-and-step-up)).

Both read the same environment variables as `nexusctl`: `NEXUS_URL`, `NEXUS_TOKEN`, `NEXUS_CA`, and also
`NEXUS_FINGERPRINT`.

```python
from nexusbackup import Client
c = Client.from_env()                                     # token
with Client.login(url, "alice", password, totp="123456", fingerprint=fp) as sec:
    sec.approve(12)
```

```powershell
Connect-NexusBackup                                       # token from the environment
Connect-NexusBackup -Url https://192.0.2.10:8443 -Credential alice -Totp 123456 -CertificateFingerprint $fp
```

## The appliance's certificate

A new appliance serves a **self-signed** web certificate ([02 Installation](02-installation.md)). The SDKs never
skip the check silently; choose one:

| Choice | Python | PowerShell | Checks |
|---|---|---|---|
| A certificate from a CA your systems trust | (default) | (default) | chain and name |
| Your private CA, or the appliance's own certificate as PEM | `ca_file=` | `-CaCertificatePath` | chain to that CA and name |
| The certificate's SHA-256 fingerprint | `fingerprint=` | `-CertificateFingerprint` | only that exact certificate |

Pinning the fingerprint is the choice when the appliance is reached by an address its certificate does not name.
Read the fingerprint on the appliance (**Settings → Certificate**, or the summary of the `nexus-setup` wizard), or
let the SDK show what a server presents and compare it with that before pinning it:

```sh
python3 -m nexusbackup fingerprint https://192.0.2.10:8443
```

```powershell
Get-NexusBackupServerFingerprint -Url https://192.0.2.10:8443
```

After the certificate is replaced (a renewal, an imported CA-signed one), the pinned fingerprint no longer matches
and the SDKs refuse to connect until it is updated.

## Jobs and approvals

Backups, restores, verifications and the other long-running actions are **jobs**. The workflow methods and cmdlets
that start one wait until it has finished (up to an hour by default, or without a limit) and return an outcome:

| Outcome | Meaning |
|---|---|
| `done` | the job finished successfully; the outcome carries the job with its log |
| `approval_pending` | the request needs approval ([10 Approvals and audit](10-approvals-and-audit.md#what-needs-approval)), for example a lock beyond the allowed days or a restore in vault mode: a second person decides; the outcome carries the approval request id. The SDKs do not wait for that |
| `pending` | not waited for (`wait=False`, `-NoWait`); the job id can be waited for later |
| `ok` | the action took effect at once (no job) |

A failed or cancelled job raises an error with the reason (the job's error, or the last line of its log); a job
still running when the wait ends raises a timeout error and goes on running on the appliance. API errors carry the
appliance's message (a backup of a group that already has one queued, for example, is a conflict).

```python
out = c.backup_group(3)                                   # waits for the backup job
print(out.state, out.job_id)
```

```powershell
Backup-NexusBackupGroup -Id 3 -FailedOnly
Get-NexusBackupApprovalRequest -Pending | Approve-NexusBackupRequest    # as a person; asks for confirmation
```

## What the SDKs cover

- **Every operation** of the API description (`https://<appliance>/api/openapi.json`,
  [09 Users and access](09-users-and-access.md#api-tokens)): Python `client.api.<operation>()`, PowerShell
  `Invoke-NexusBackupApi <operationId>` (`Get-NexusBackupOperation` lists them). That is what API tokens may reach,
  plus sign-in, approval decisions, the audit CSV and the restore point simulator. Settings, users, plugins,
  restores with downloads and the other functions of the web interface are not part of it.
- **Workflows:** jobs (list, show, start, back up a group now, cancel, wait), protection groups (pause, resume),
  sources, snapshots, the file search (all pages), alerts (list, acknowledge), approval requests (list, approve,
  reject), the audit log (all pages, the SIEM pull by sequence number, CSV), monthly usage (also CSV), the dashboard,
  the API version check.

Examples in the repository: `sdk/python/examples/` and `sdk/powershell/examples/` (back up a group with an operator
token and list the new snapshots; read-only reporting and an audit pull with a read token).

## Versions

The SDKs' major version is the API version (`1` for `/api/v1`); `check_compatibility()` and
`Get-NexusBackupApiVersion` compare it with the appliance.
