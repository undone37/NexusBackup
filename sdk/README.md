# NexusBackup SDKs

Official clients of the NexusBackup REST API (`/api/v1`, described in
[`crates/web-api/openapi.json`](../crates/web-api/openapi.json)) for scripts and integrations (issue #181):

| SDK | Path | Needs | Install (from this repository) |
|---|---|---|---|
| Python package `nexusbackup` (distribution `nexusbackup-sdk`) | [`python/`](python/) | Python 3.10+, no dependencies | `pip install ./sdk/python` |
| PowerShell module `NexusBackup` | [`powershell/`](powershell/) | PowerShell 7.2+ (Windows, Linux, macOS) | `Import-Module ./sdk/powershell/NexusBackup` |

Both cover the same ground:

- **Every operation** of the API description: Python `client.api.<operation_id in snake case>(...)`, PowerShell
  `Invoke-NexusBackupApi <operationId>` (47 operations). The description is what API tokens may reach
  (`crates/web-api/src/tokens.rs`, checked by `crates/web-api/src/openapi.rs`), plus the billing export and the
  few operations a script needs as a person: sign-in and sign-out, deciding approval requests, the audit log as
  CSV, the restore point simulator. The rest of the web UI's API (settings, users, plugins, restores with
  downloads, ...) is not described and not in the SDKs. Bodies and answers are JSON (dicts / PSCustomObjects)
  as the description documents them.
- **Authentication:** an API token (`nxt_...`; scope read, operator or backup; at most operator) or a person's
  session (name, password, TOTP code; the `nx_session` cookie and `X-CSRF-Token` handled; sign-out at the end).
  Operations marked `x-token: false` are refused before sending when only a token is configured.
- **TLS for self-signed appliances:** the system trust store, a private CA or the appliance's certificate as the
  only trust anchor (name checked), or a **pinned SHA-256 fingerprint** (no name or chain check: for an appliance
  reached by an address its certificate does not name). A helper shows a server's fingerprint for trust on first
  use; compare it with Settings -> Certificate before pinning.
- **Errors** carry the API's `{"error": "..."}` text and the status (Python: `NotFoundError`, `ConflictError`, ...;
  PowerShell: `NexusBackup.ApiException` with `StatusCode` and `ApiError`).
- **Jobs:** starting a job answers 202 with its `id`; the workflow methods/cmdlets wait (default one hour; no limit
  with `timeout=None` / `-TimeoutSec 0`) by polling `GET /jobs/{id}`, and return an outcome: `done` (the job
  finished `ok`), `approval_pending` (the request needs approval: `quorum_id`, decided by a second person, not
  waited for), `pending` (not waited), `ok` (no job). Failed and cancelled jobs raise with the reason (the
  result's error or the last log line), a timeout raises too (the job goes on running).
- **Paging** of the audit log (`after`/`before` by seq, the SIEM pull) and of the file search (`next` cursor).
  **CSV** downloads of the audit log (a person's session) and the billing export.
- **Workflows:** jobs (list, show, start, back up a group now, cancel, wait), protection groups (list, pause,
  resume), sources, snapshots, file search, alerts (list, acknowledge), approval requests (list, approve,
  reject), audit log, usage, dashboard, API version check.

Examples: [`python/examples/`](python/examples/), [`powershell/examples/`](powershell/examples/). Manual chapter:
[20 SDKs](../manual/20-sdks.md). `nexusctl` (the Rust command-line client, `crates/nexusctl`) reads the same
environment variables (`NEXUS_URL`, `NEXUS_TOKEN`, `NEXUS_CA`; the SDKs also `NEXUS_FINGERPRINT`).

## How they are built

The operation table of both SDKs is **generated** from `openapi.json` by [`codegen.py`](codegen.py) (standard
library only): `python/src/nexusbackup/_operations.py` (one typed method per operation) and
`powershell/NexusBackup/Operations.ps1` (the table behind `Invoke-NexusBackupApi`). Everything else (transport,
authentication, TLS, errors, waiting for jobs, paging, the workflow layer) is a small hand-written core per
language. The design follows the NexusStor SDKs (same layout, same TLS and error handling), so a script that
manages both products reads alike.

Why not an off-the-shelf generator: the description is hand-maintained and its bodies are mostly free-form
objects (`Object`, `List`), so generated model classes would add little and change with every feature; and
generated PowerShell clients send with `Invoke-RestMethod`, which in PowerShell 7 can only use the system trust
store or skip every check: no private CA, no pinned fingerprint, which self-signed appliances need. The module
therefore sends through an `HttpClient` whose certificate check is compiled with Add-Type
(`powershell/NexusBackup/NexusBackup.cs`). Every operation has an `operationId` (a web-api test keeps them present,
unique and lowerCamelCase), so any third-party generator gets stable names too.

## Keeping them in sync

| Check | Fails when |
|---|---|
| `python3 sdk/codegen.py --check` | the committed tables differ from what `openapi.json` gives (run `python3 sdk/codegen.py`) |
| `cargo test -p web-api openapi` | an operation has no `operationId` or one is used twice; an operation documented for tokens is not on the allow-list, or one marked `x-token: false` is on it |
| `sdk/python/tests/test_sync.py`, Pester `operations` | an operation is missing, has another method, path or token flag, or the version major is not the API version |

`sdk/check.sh` runs all SDK checks (sync, pytest, Pester when a local `pwsh` has Pester 5); `sdk/check.sh
--container` adds Python 3.10 with ruff and mypy (strict), and Pester with PSScriptAnalyzer in the
`mcr.microsoft.com/powershell` container when the local `pwsh` has no Pester. The pre-push hook runs
`sdk/check.sh` when `sdk/` or `openapi.json` changes; CI runs `sdk/check.sh --container` (job `sdk` in
`.github/workflows/ci.yml`, on GitHub's runner with its `pwsh`).

## Versioning and compatibility

The SDK version is `MAJOR.MINOR.PATCH` with **MAJOR = the API version** (`info.version` of `openapi.json`, the `v1`
in `/api/v1`). The intent is that the API only grows within one version (new operations and fields) and an SDK
minor release adds them; while NexusBackup is not production-ready this is not guaranteed.
`Client.check_compatibility()` / `Get-NexusBackupApiVersion` compare with the appliance's `GET /openapi.json`.

| SDK | API | NexusBackup releases |
|---|---|---|
| 1.x | 1 (`/api/v1`) | every release so far (the SDKs only describe endpoints the appliance already had; nothing is published yet) |

An operation the appliance does not know yet (an older appliance) answers 404. Use an SDK whose minor version is
not newer than the appliance's API features you rely on; older SDKs keep working with newer appliances of the same
API version.

## Releasing (not done)

Nothing is published: PyPI and the PowerShell Gallery are public and the project is not production-ready. There is
no automatic publishing step anywhere. When it is time, by hand:

1. Set the version in `python/pyproject.toml`, `python/src/nexusbackup/__init__.py` and
   `powershell/NexusBackup/NexusBackup.psd1` (the tests check that the three agree with the API version).
2. `sdk/check.sh --container`.
3. Python: `python3 -m build sdk/python` and `twine upload dist/*` (a PyPI account and token for `nexusbackup-sdk`).
4. PowerShell: `Publish-Module -Path sdk/powershell/NexusBackup -NuGetApiKey ...` (a Gallery account and key).
5. Tag the commit `sdk-v<version>`.

## Status

Covered by unit tests against a local stub (Python: HTTP and HTTPS stubs on 127.0.0.1, including real TLS with a
self-signed certificate, on the runner's Python and on 3.10; PowerShell: Pester with the HTTP call mocked and the
certificate check tested with in-memory certificates, in CI). Not yet run against an appliance. Passkey sign-in
(WebAuthn) and single sign-on are not supported: those accounts use the web UI, scripts use API tokens. A session
of an account marked by a risk signal must step up in the web UI before it may change anything (the API answers
403).
