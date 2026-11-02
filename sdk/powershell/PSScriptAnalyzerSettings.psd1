@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Invoke-NexusBackupHttp and the other helpers are private (not exported); the exported change cmdlets
        # support ShouldProcess
        'PSUseShouldProcessForStateChangingFunctions'
    )
}
