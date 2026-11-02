<#
.SYNOPSIS
Backs up a protection group now, waits for the job, then lists the group's newest snapshots.
.DESCRIPTION
Uses an operator API token (My account -> API tokens, scope Operator or Backup), from -Token or NEXUS_TOKEN.
With -KeepUntil beyond the allowed days the request needs approval: the script names the approval request and
stops.
.EXAMPLE
$fp = Get-NexusBackupServerFingerprint -Url https://192.0.2.10:8443   # compare with Settings -> Certificate
./BackupGroup.ps1 -Url https://192.0.2.10:8443 -Fingerprint $fp -Group web
#>
[CmdletBinding()]
param(
    [string] $Url = $env:NEXUS_URL,
    [securestring] $Token,
    [string] $Fingerprint,
    [string] $CaCertificatePath,
    [Parameter(Mandatory)] [string] $Group,
    [switch] $FailedOnly,
    [Nullable[datetime]] $KeepUntil,
    [double] $TimeoutSec = 14400
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../NexusBackup/NexusBackup.psd1')

$connect = @{ Url = $Url }
if ($Token) { $connect.Token = $Token }
if ($Fingerprint) { $connect.CertificateFingerprint = $Fingerprint }
if ($CaCertificatePath) { $connect.CaCertificatePath = $CaCertificatePath }
Connect-NexusBackup @connect

$v = Get-NexusBackupApiVersion
if (-not $v.Compatible) { Write-Warning "appliance API $($v.ApplianceVersion), module for $($v.ModuleApiVersion)" }

$g = Get-NexusBackupGroup | Where-Object { $_.name -eq $Group -or "$($_.id)" -eq $Group } | Select-Object -First 1
if (-not $g) { throw "no protection group '$Group'" }
"backing up $($g.name) (tenant $($g.tenant)) ..."
try {
    $backup = @{ Id = $g.id; Tenant = $g.tenant; FailedOnly = $FailedOnly; TimeoutSec = $TimeoutSec }
    if ($KeepUntil) { $backup.KeepUntil = $KeepUntil }
    $out = Backup-NexusBackupGroup @backup
} catch [NexusBackup.JobFailedException] {
    "job $($_.Exception.JobId) $($_.Exception.State): $($_.Exception.Reason)"
    exit 1
}
if ($out.State -eq 'approval_pending') {
    "the request needs approval: approval request $($out.QuorumId) (Approvals in the web UI)"
    exit 0
}
"job $($out.JobId): $($out.Job.state)"
Get-NexusBackupSnapshot -Tenant $g.tenant |
    Where-Object { $_.time -ge $out.Job.started } |
    Select-Object -First 10 label, source, time, size, lock_until |
    Format-Table -AutoSize
