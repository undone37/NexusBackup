@{
    RootModule           = 'NexusBackup.psm1'
    # major = the API version (info.version of crates/web-api/openapi.json); see sdk/README.md
    ModuleVersion        = '1.0.0'
    GUID                 = '17d106f7-05d2-4c7d-8c1d-3494140652e4'
    Author               = 'NexusBackup contributors'
    CompanyName          = 'NexusBackup'
    Copyright            = '(c) NexusBackup contributors. AGPL-3.0-only.'
    Description          = 'PowerShell module for the NexusBackup appliance REST API: jobs, protection groups, sources, snapshots, file search, alerts, approvals, audit log, usage.'
    PowerShellVersion    = '7.2'
    CompatiblePSEditions = @('Core')
    FunctionsToExport    = @(
        'Approve-NexusBackupRequest'
        'Backup-NexusBackupGroup'
        'Confirm-NexusBackupAlert'
        'Connect-NexusBackup'
        'Deny-NexusBackupRequest'
        'Disconnect-NexusBackup'
        'Export-NexusBackupAuditLog'
        'Find-NexusBackupFile'
        'Get-NexusBackupAlert'
        'Get-NexusBackupApiVersion'
        'Get-NexusBackupApprovalRequest'
        'Get-NexusBackupAuditLog'
        'Get-NexusBackupDashboard'
        'Get-NexusBackupGroup'
        'Get-NexusBackupJob'
        'Get-NexusBackupOperation'
        'Get-NexusBackupServerFingerprint'
        'Get-NexusBackupSnapshot'
        'Get-NexusBackupSource'
        'Get-NexusBackupUsage'
        'Invoke-NexusBackupApi'
        'Resume-NexusBackupGroup'
        'Start-NexusBackupJob'
        'Stop-NexusBackupJob'
        'Suspend-NexusBackupGroup'
        'Wait-NexusBackupJob'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags       = @('NexusBackup', 'Backup', 'Proxmox', 'Restore', 'REST')
            LicenseUri = 'https://www.gnu.org/licenses/agpl-3.0.html'
        }
    }
}
