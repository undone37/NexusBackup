# NexusBackup PowerShell module

Cmdlets for the NexusBackup appliance REST API (`/api/v1`), PowerShell 7.2+ on Windows, Linux and macOS (Windows
PowerShell 5.1 is not supported: the certificate checks need .NET 6). Overview, design and versioning:
[`sdk/README.md`](../README.md).

```powershell
Import-Module ./sdk/powershell/NexusBackup    # from a checkout; nothing is published to the PowerShell Gallery yet
Get-Command -Module NexusBackup
Get-Help Connect-NexusBackup -Full
```

## Connecting

```powershell
# API token (My account -> API tokens; scope Read only, Operator or Backup)
$token = Read-Host -AsSecureString 'API token'
Connect-NexusBackup -Url https://backup.example.com:8443 -Token $token -CaCertificatePath ./nexus-ca.pem

# a person (what tokens never do: approve, the audit CSV, the restore point simulator)
$fp = Get-NexusBackupServerFingerprint -Url https://192.0.2.10:8443     # compare with Settings -> Certificate
Connect-NexusBackup -Url https://192.0.2.10:8443 -Credential alice -Totp 123456 -CertificateFingerprint $fp
...
Disconnect-NexusBackup
```

Without parameters `Connect-NexusBackup` reads `NEXUS_URL`, `NEXUS_TOKEN`, `NEXUS_CA` (as `nexusctl`) and
`NEXUS_FINGERPRINT`. TLS: the system trust store by default; `-CaCertificatePath` trusts only that CA or the
appliance's self-signed certificate (its name must match the URL); `-CertificateFingerprint` pins the certificate's
SHA-256 and skips the name and chain checks; `-SkipCertificateCheck` checks nothing. Every cmdlet takes
`-Connection` (from `Connect-NexusBackup -PassThru`) for more than one appliance.

## Cmdlets

| Area | Cmdlets |
|---|---|
| Connection | `Connect-NexusBackup`, `Disconnect-NexusBackup`, `Get-NexusBackupServerFingerprint`, `Get-NexusBackupApiVersion` |
| Any operation | `Invoke-NexusBackupApi`, `Get-NexusBackupOperation` |
| Jobs | `Get-NexusBackupJob`, `Start-NexusBackupJob`, `Backup-NexusBackupGroup`, `Wait-NexusBackupJob`, `Stop-NexusBackupJob` (cancel) |
| Groups and sources | `Get-NexusBackupGroup`, `Suspend-NexusBackupGroup` (pause), `Resume-NexusBackupGroup`, `Get-NexusBackupSource` |
| Data | `Get-NexusBackupSnapshot`, `Find-NexusBackupFile` (file search, all pages) |
| Alerts | `Get-NexusBackupAlert`, `Confirm-NexusBackupAlert` (acknowledge) |
| Approvals | `Get-NexusBackupApprovalRequest`, `Approve-NexusBackupRequest`, `Deny-NexusBackupRequest` |
| Audit and usage | `Get-NexusBackupAuditLog`, `Export-NexusBackupAuditLog` (CSV, a person's session), `Get-NexusBackupUsage`, `Get-NexusBackupDashboard` |

Actions that start a job wait until it has finished (`-TimeoutSec`, default 3600; 0 = no limit) unless `-NoWait`,
and return a `NexusBackup.Outcome`: `State` done (with `Job`, its `GET /jobs/{id}` answer), approval_pending (the
request needs approval: `QuorumId`, decided by a second person), pending (with `-NoWait`: `JobId`) or ok. Changing
cmdlets support `-WhatIf`; cancelling and approving ask for confirmation (`-Confirm:$false` in scripts).

```powershell
Backup-NexusBackupGroup -Id 3 -FailedOnly
Get-NexusBackupGroup | Where-Object name -eq web | Backup-NexusBackupGroup -KeepUntil (Get-Date).AddDays(90)
Start-NexusBackupJob -Kind verify -Tenant acme -Parameters @{ source = 'vm-100' } -NoWait | Wait-NexusBackupJob -TimeoutSec 0
Get-NexusBackupJob -State failed -Limit 20 | Format-Table id, kind, tenant, finished
Suspend-NexusBackupGroup -Id 3 -Until (Get-Date).AddHours(4)
Find-NexusBackupFile -Query invoice -Tenant acme -Extension pdf | Select-Object source, path
Get-NexusBackupAlert | Confirm-NexusBackupAlert -Note 'known, ticket 4711'
Get-NexusBackupAuditLog -Action job. -From (Get-Date).AddDays(-1) | Format-Table seq, actor, action, target
Get-NexusBackupUsage -Month 2026-10 -OutFile ./usage-2026-10.csv
```

Every operation of the API description, by its `operationId` (tab completion; `Get-NexusBackupOperation` lists them):

```powershell
Invoke-NexusBackupApi getSourceInventory -PathParameters @{ id = 4 }
Invoke-NexusBackupApi listAuditEntries -Query @{ actor = 'alice'; limit = 50 }
Wait-NexusBackupJob -InputObject (Invoke-NexusBackupApi createJob -Body @{ kind = 'offsite'; tenant = 'acme'; params = @{} })
```

## Errors

API errors are terminating errors with a `NexusBackup.ApiException` (`StatusCode`, `ApiError` = the API's `error`
text) and a matching category (404 ObjectNotFound, 403 PermissionDenied, ...). Also `NexusBackup.TlsException`,
`NexusBackup.SessionRequiredException` (an operation tokens cannot reach), `NexusBackup.JobFailedException` (failed
or cancelled, with `JobId`, `State` and `Reason`) and `NexusBackup.WaitTimeoutException`.

```powershell
try { Get-NexusBackupJob -Id 99 } catch [NexusBackup.ApiException] { $_.Exception.StatusCode; $_.Exception.ApiError }
```

## Tests

`sdk/check.sh` runs the Pester tests with a local `pwsh` that has Pester 5, `sdk/check.sh --container` in the
`mcr.microsoft.com/powershell` container (with PSScriptAnalyzer) when it has not; CI runs them on every change of
`sdk/` or `openapi.json`. Example: [`examples/BackupGroup.ps1`](examples/BackupGroup.ps1) (back up a group with an
operator token and list the new snapshots).
