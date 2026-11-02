# Cmdlets of the common workflows, built on Invoke-NexusBackupApi (Core.ps1). Actions that start a job wait
# until it has finished unless -NoWait and return a NexusBackup.Outcome. Dot-sourced by NexusBackup.psm1.

function Remove-NexusBackupEmptyQuery {
    param([System.Collections.IDictionary] $Query)
    foreach ($k in @($Query.Keys)) { if ($null -eq $Query[$k] -or "$($Query[$k])" -eq '') { $Query.Remove($k) } }
    $Query
}

function Get-NexusBackupJob {
    <#
    .SYNOPSIS
    Lists jobs (newest first), or shows one with its log.
    .DESCRIPTION
    State is queued, running, ok, failed or cancelled; a running job has progress (percent, bytes, rate, eta).
    Tenant-scoped accounts see their own tenant's jobs only.
    .EXAMPLE
    Get-NexusBackupJob -State failed -Limit 20 | Format-Table id, kind, tenant, finished
    .EXAMPLE
    (Get-NexusBackupJob -Id 4711).log
    #>
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName, ParameterSetName = 'Id')] [Alias('JobId')] [long] $Id,
        [Parameter(ParameterSetName = 'List')] [ValidateSet('queued', 'running', 'ok', 'failed', 'cancelled')] [string] $State,
        [Parameter(ParameterSetName = 'List')] [string] $Kind,
        [Parameter(ParameterSetName = 'List')] [string] $Tenant,
        [Parameter(ParameterSetName = 'List')] [ValidateRange(1, 1000)] [int] $Limit = 100,
        [PSTypeName('NexusBackup.Connection')] [object] $Connection
    )
    process {
        if ($PSCmdlet.ParameterSetName -eq 'Id') {
            Invoke-NexusBackupApi getJob -PathParameters @{ id = $Id } -Connection $Connection
        } else {
            $q = Remove-NexusBackupEmptyQuery ([ordered]@{ state = $State; kind = $Kind; tenant = $Tenant; limit = $Limit })
            Invoke-NexusBackupApi listJobs -Query $q -Connection $Connection
        }
    }
}

function Start-NexusBackupJob {
    <#
    .SYNOPSIS
    Starts a job (operator scope) and waits until it has finished.
    .DESCRIPTION
    -Kind as POST /jobs takes it (backup, restore, verify, offsite, retention, ...), -Parameters per kind. Some
    requests need approval (a lock beyond the allowed days, restores in vault mode): then the outcome is
    approval_pending with a QuorumId. With -NoWait the outcome is pending with the JobId.
    .EXAMPLE
    Start-NexusBackupJob -Kind verify -Tenant acme -Parameters @{ source = 'vm-100' }
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType('NexusBackup.Outcome')]
    param(
        [Parameter(Mandatory, Position = 0)] [string] $Kind,
        [Parameter(Mandatory, Position = 1)] [string] $Tenant,
        [System.Collections.IDictionary] $Parameters = @{},
        [switch] $NoWait,
        [ValidateRange(0, 604800)] [double] $TimeoutSec = 3600,
        [PSTypeName('NexusBackup.Connection')] [object] $Connection
    )
    if ($PSCmdlet.ShouldProcess("tenant $Tenant", "Start a $Kind job")) {
        $c = Get-NexusBackupConnection $Connection
        $a = Invoke-NexusBackupApi createJob -Body @{ kind = $Kind; tenant = $Tenant; params = $Parameters } -Connection $c
        $jid = if ($null -eq (Get-NexusBackupProperty $a 'quorum_id')) { Get-NexusBackupProperty $a 'id' } else { $null }
        Resolve-NexusBackupAnswer -Connection $c -Answer $a -JobId $jid -NoWait:$NoWait -TimeoutSec $TimeoutSec
    }
}

function Backup-NexusBackupGroup {
    <#
    .SYNOPSIS
    Backs up a protection group now and waits until the backup job has finished.
    .DESCRIPTION
    -Guest backs up only these members, -FailedOnly only the members whose last backup failed. -KeepUntil
    locks the new snapshots until then (beyond the allowed days the request needs approval). The tenant is
    the group's (read from the groups when -Tenant is not given).
    .EXAMPLE
    Backup-NexusBackupGroup -Id 3
    .EXAMPLE
    Get-NexusBackupGroup | Where-Object name -eq web | Backup-NexusBackupGroup -FailedOnly -NoWait
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType('NexusBackup.Outcome')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)] [Alias('GroupId')] [long] $Id,
        [Parameter(ValueFromPipelineByPropertyName)] [string] $Tenant,
        [object[]] $Guest,
        [switch] $FailedOnly,
        [Nullable[datetime]] $KeepUntil,
        [switch] $NoWait,
        [ValidateRange(0, 604800)] [double] $TimeoutSec = 3600,
        [PSTypeName('NexusBackup.Connection')] [object] $Connection
    )
    process {
        $c = Get-NexusBackupConnection $Connection
        $t = $Tenant
        if (-not $t) {
            $g = @(Invoke-NexusBackupApi listGroups -Connection $c | Where-Object { $_.id -eq $Id })
            if ($g.Count -eq 0) { throw [System.ArgumentException]::new("no protection group $Id") }
            $t = [string]$g[0].tenant
        }
        $p = [ordered]@{ group_id = $Id }
        if ($Guest) { $p['guests'] = @($Guest) }
        if ($FailedOnly) { $p['failed_only'] = $true }
        if ($KeepUntil) { $p['keep_until'] = ConvertTo-NexusBackupUnixTime $KeepUntil }
        if ($PSCmdlet.ShouldProcess("group $Id (tenant $t)", 'Back up now')) {
            $a = Invoke-NexusBackupApi createJob -Body @{ kind = 'backup'; tenant = $t; params = $p } -Connection $c
            $jid = if ($null -eq (Get-NexusBackupProperty $a 'quorum_id')) { Get-NexusBackupProperty $a 'id' } else { $null }
            Resolve-NexusBackupAnswer -Connection $c -Answer $a -JobId $jid -NoWait:$NoWait -TimeoutSec $TimeoutSec
        }
    }
}

function Stop-NexusBackupJob {
    <#
    .SYNOPSIS
    Cancels a queued or running job.
    .EXAMPLE
    Get-NexusBackupJob -State running -Kind offsite | Stop-NexusBackupJob
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)] [Alias('JobId')] [long] $Id,
        [PSTypeName('NexusBackup.Connection')] [object] $Connection
    )
    process {
        if ($PSCmdlet.ShouldProcess("job $Id", 'Cancel')) {
            Invoke-NexusBackupApi cancelJob -PathParameters @{ id = $Id } -Connection $Connection
        }
    }
}

function Get-NexusBackupSource {
    <#
    .SYNOPSIS
    Lists the sources (PVE, agents, NAS, TrueNAS, VMware, plugins); secrets are never included.
    .EXAMPLE
    Get-NexusBackupSource | Format-Table id, kind, name, tenant
    #>
    [CmdletBinding()]
    param([PSTypeName('NexusBackup.Connection')] [object] $Connection)
    Invoke-NexusBackupApi listSources -Connection $Connection
}

function Get-NexusBackupGroup {
    <#
    .SYNOPSIS
    Lists the protection groups with their last and next backup.
    .EXAMPLE
    Get-NexusBackupGroup | Format-Table id, name, tenant, next_backup
    #>
    [CmdletBinding()]
    param([PSTypeName('NexusBackup.Connection')] [object] $Connection)
    Invoke-NexusBackupApi listGroups -Connection $Connection
}

function Suspend-NexusBackupGroup {
    <#
    .SYNOPSIS
    Pauses a protection group's schedule, until a time or indefinitely.
    .EXAMPLE
    Suspend-NexusBackupGroup -Id 3 -Until (Get-Date).AddHours(4)
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)] [Alias('GroupId')] [long] $Id,
        [Nullable[datetime]] $Until,
        [PSTypeName('NexusBackup.Connection')] [object] $Connection
    )
    process {
        $what = if ($Until) { "Pause until $Until" } else { 'Pause indefinitely' }
        if ($PSCmdlet.ShouldProcess("group $Id", $what)) {
            Invoke-NexusBackupApi pauseGroup -PathParameters @{ id = $Id } -Body @{ until = ConvertTo-NexusBackupUnixTime $Until } -Connection $Connection
        }
    }
}

function Resume-NexusBackupGroup {
    <#
    .SYNOPSIS
    Resumes a paused protection group.
    .EXAMPLE
    Resume-NexusBackupGroup -Id 3
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)] [Alias('GroupId')] [long] $Id,
        [PSTypeName('NexusBackup.Connection')] [object] $Connection
    )
    process {
        if ($PSCmdlet.ShouldProcess("group $Id", 'Resume')) {
            Invoke-NexusBackupApi resumeGroup -PathParameters @{ id = $Id } -Connection $Connection
        }
    }
}

function Get-NexusBackupSnapshot {
    <#
    .SYNOPSIS
    Lists snapshots: local and offsite copies, lock, verification, legal holds.
    .EXAMPLE
    Get-NexusBackupSnapshot -Tenant acme -Source vm-100 | Select-Object -Last 5
    #>
    [CmdletBinding()]
    param(
        [string] $Tenant,
        [string] $Source,
        [switch] $Held,
        [PSTypeName('NexusBackup.Connection')] [object] $Connection
    )
    $q = Remove-NexusBackupEmptyQuery ([ordered]@{ tenant = $Tenant; source = $Source; held = if ($Held) { $true } else { $null } })
    Invoke-NexusBackupApi listSnapshots -Query $q -Connection $Connection
}

function Find-NexusBackupFile {
    <#
    .SYNOPSIS
    Finds files in all indexed snapshots (one result per file with its versions), all pages.
    .EXAMPLE
    Find-NexusBackupFile -Query report.docx -Tenant acme | Select-Object source, path, @{ n = 'versions'; e = { $_.versions.Count } }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)] [string] $Query,
        [string] $Tenant,
        [string] $Source,
        [Nullable[long]] $Group,
        [ValidateSet('file', 'dir', 'symlink', 'other')] [string] $Kind,
        [string] $Extension,
        [ValidateSet('only', 'exclude')] [string] $Deleted,
        [ValidateRange(1, 1000)] [int] $PageSize = 200,
        [PSTypeName('NexusBackup.Connection')] [object] $Connection
    )
    $c = Get-NexusBackupConnection $Connection
    $cursor = $null
    while ($true) {
        $q = Remove-NexusBackupEmptyQuery ([ordered]@{
                q = $Query; tenant = $Tenant; source = $Source; group = $Group; kind = $Kind; ext = $Extension
                deleted = $Deleted; limit = $PageSize; cursor = $cursor
            })
        $page = Invoke-NexusBackupApi searchFiles -Query $q -Connection $c
        @(Get-NexusBackupProperty $page 'hits' | Where-Object { $null -ne $_ })
        $cursor = Get-NexusBackupProperty $page 'next'
        if (-not $cursor) { return }
    }
}

function Get-NexusBackupAlert {
    <#
    .SYNOPSIS
    Lists the alerts (open ones by default).
    .EXAMPLE
    Get-NexusBackupAlert | Where-Object severity -eq critical
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('open', 'resolved', 'all')] [string] $State = 'open',
        [string] $Category,
        [PSTypeName('NexusBackup.Connection')] [object] $Connection
    )
    $q = Remove-NexusBackupEmptyQuery ([ordered]@{ state = $State; category = $Category })
    Invoke-NexusBackupApi listAlerts -Query $q -Connection $Connection
}

function Confirm-NexusBackupAlert {
    <#
    .SYNOPSIS
    Acknowledges an alert, with an optional note.
    .EXAMPLE
    Get-NexusBackupAlert -Category backup | Confirm-NexusBackupAlert -Note 'known, ticket 4711'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)] [Alias('AlertId')] [long] $Id,
        [string] $Note,
        [PSTypeName('NexusBackup.Connection')] [object] $Connection
    )
    process {
        if ($PSCmdlet.ShouldProcess("alert $Id", 'Acknowledge')) {
            $body = if ($Note) { @{ note = $Note } } else { @{} }
            Invoke-NexusBackupApi acknowledgeAlert -PathParameters @{ id = $Id } -Body $body -Connection $Connection
        }
    }
}

function Get-NexusBackupApprovalRequest {
    <#
    .SYNOPSIS
    Lists the approval requests (pending ones with -Pending).
    .EXAMPLE
    Get-NexusBackupApprovalRequest -Pending
    #>
    [CmdletBinding()]
    param([switch] $Pending, [PSTypeName('NexusBackup.Connection')] [object] $Connection)
    $q = if ($Pending) { @{ state = 'pending' } } else { @{} }
    Invoke-NexusBackupApi listApprovalRequests -Query $q -Connection $Connection
}

function Approve-NexusBackupRequest {
    <#
    .SYNOPSIS
    Approves and carries out another person's request (a person's session: administrator, security officer or
    the tenant's approver).
    .DESCRIPTION
    State done once carried out (and, when the request starts a job, once that job has finished; -NoWait
    returns pending with the JobId), approval_pending while tenant approvers still have to decide.
    .EXAMPLE
    Approve-NexusBackupRequest -Id 12
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType('NexusBackup.Outcome')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)] [Alias('QuorumId')] [long] $Id,
        [switch] $NoWait,
        [ValidateRange(0, 604800)] [double] $TimeoutSec = 3600,
        [PSTypeName('NexusBackup.Connection')] [object] $Connection
    )
    process {
        if ($PSCmdlet.ShouldProcess("approval request $Id", 'Approve and carry out')) {
            $c = Get-NexusBackupConnection $Connection
            $a = Invoke-NexusBackupApi approveRequest -PathParameters @{ id = $Id } -Connection $c
            if ((Get-NexusBackupProperty $a 'state') -eq 'pending') {
                return New-NexusBackupOutcome -State approval_pending -QuorumId $Id -Response $a
            }
            $out = Resolve-NexusBackupAnswer -Connection $c -Answer $a -NoWait:$NoWait -TimeoutSec $TimeoutSec
            if ($out.State -eq 'ok') { $out = New-NexusBackupOutcome -State done -QuorumId $Id -Response $a }
            $out
        }
    }
}

function Deny-NexusBackupRequest {
    <#
    .SYNOPSIS
    Rejects another person's request (a person's session).
    .EXAMPLE
    Deny-NexusBackupRequest -Id 12
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)] [Alias('QuorumId')] [long] $Id,
        [PSTypeName('NexusBackup.Connection')] [object] $Connection
    )
    process {
        if ($PSCmdlet.ShouldProcess("approval request $Id", 'Reject')) {
            Invoke-NexusBackupApi rejectRequest -PathParameters @{ id = $Id } -Connection $Connection
        }
    }
}

function Get-NexusBackupAuditLog {
    <#
    .SYNOPSIS
    Reads the audit log, all matching entries page by page (oldest first, or -NewestFirst).
    .DESCRIPTION
    Filters: -Actor (exact), -Action (prefix), -Target (substring), -From/-To (times), -Tenant. Stop early
    with Select-Object -First. For a SIEM pull, -After the last seq seen.
    .EXAMPLE
    Get-NexusBackupAuditLog -Action job. -From (Get-Date).AddDays(-1)
    .EXAMPLE
    Get-NexusBackupAuditLog -NewestFirst | Select-Object -First 20
    #>
    [CmdletBinding()]
    param(
        [string] $Actor,
        [string] $Action,
        [string] $Target,
        [Nullable[datetime]] $From,
        [Nullable[datetime]] $To,
        [string] $Tenant,
        [Nullable[long]] $After,
        [switch] $NewestFirst,
        [ValidateRange(1, 1000)] [int] $PageSize = 500,
        [PSTypeName('NexusBackup.Connection')] [object] $Connection
    )
    $c = Get-NexusBackupConnection $Connection
    $cursorKey = if ($NewestFirst) { 'before' } else { 'after' }
    $cursor = if ($NewestFirst) { $null } else { $After }
    while ($true) {
        $q = Remove-NexusBackupEmptyQuery ([ordered]@{
                limit = $PageSize; order = if ($NewestFirst) { 'desc' } else { 'asc' }
                actor = $Actor; action = $Action; target = $Target; tenant = $Tenant
                from = ConvertTo-NexusBackupUnixTime $From; to = ConvertTo-NexusBackupUnixTime $To
            })
        if ($null -ne $cursor) { $q[$cursorKey] = $cursor }
        $page = @(Invoke-NexusBackupApi listAuditEntries -Query $q -Connection $c)
        $page
        if ($page.Count -lt $PageSize) { return }
        $cursor = $page[-1].seq
    }
}

function Export-NexusBackupAuditLog {
    <#
    .SYNOPSIS
    Saves the audit log as CSV (every matching entry oldest first, with the hash chain columns; a person's
    session).
    .EXAMPLE
    Export-NexusBackupAuditLog -Path ./audit.csv -From (Get-Date).AddDays(-30)
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0)] [string] $Path,
        [string] $Actor,
        [string] $Action,
        [string] $Target,
        [Nullable[datetime]] $From,
        [Nullable[datetime]] $To,
        [string] $Tenant,
        [PSTypeName('NexusBackup.Connection')] [object] $Connection
    )
    $q = Remove-NexusBackupEmptyQuery ([ordered]@{
            actor = $Actor; action = $Action; target = $Target; tenant = $Tenant
            from = ConvertTo-NexusBackupUnixTime $From; to = ConvertTo-NexusBackupUnixTime $To
        })
    if ($PSCmdlet.ShouldProcess($Path, 'Write the audit log')) {
        Invoke-NexusBackupApi exportAuditCsv -Query $q -OutFile $Path -TimeoutSec 600 -Connection $Connection
    }
}

function Get-NexusBackupUsage {
    <#
    .SYNOPSIS
    Shows the monthly usage per tenant (billing), or saves it as CSV with -OutFile.
    .EXAMPLE
    (Get-NexusBackupUsage -Month 2026-10).tenants | Format-Table tenant, objects, stored_peak
    .EXAMPLE
    Get-NexusBackupUsage -Month 2026-10 -OutFile ./usage-2026-10.csv
    #>
    [CmdletBinding()]
    param(
        [ValidatePattern('^\d{4}-\d{2}$')] [string] $Month,
        [string] $Tenant,
        [string] $OutFile,
        [PSTypeName('NexusBackup.Connection')] [object] $Connection
    )
    $q = Remove-NexusBackupEmptyQuery ([ordered]@{ month = $Month; tenant = $Tenant })
    if ($OutFile) {
        $q['format'] = 'csv'
        Invoke-NexusBackupApi getUsage -Query $q -OutFile $OutFile -Connection $Connection
    } else {
        Invoke-NexusBackupApi getUsage -Query $q -Connection $Connection
    }
}

function Get-NexusBackupDashboard {
    <#
    .SYNOPSIS
    Shows the dashboard key figures (protection, RPO, capacity, jobs).
    .EXAMPLE
    Get-NexusBackupDashboard
    #>
    [CmdletBinding()]
    param([PSTypeName('NexusBackup.Connection')] [object] $Connection)
    Invoke-NexusBackupApi getDashboard -Connection $Connection
}
