# NexusBackup PowerShell module: the REST API of the NexusBackup appliance (/api/v1).
#
#   Operations.ps1   generated from crates/web-api/openapi.json (sdk/codegen.py): every operation by operationId
#   Core.ps1         connection, authentication, TLS, requests, errors, jobs (Invoke-NexusBackupApi)
#   Cmdlets.ps1      the cmdlets of the common workflows, built on Invoke-NexusBackupApi
#   NexusBackup.cs   exception types and the certificate check (Add-Type)

Set-StrictMode -Version 3.0

if (-not ('NexusBackup.CertificateValidator' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'NexusBackup.cs')
}

. (Join-Path $PSScriptRoot 'Operations.ps1')
. (Join-Path $PSScriptRoot 'Core.ps1')
. (Join-Path $PSScriptRoot 'Cmdlets.ps1')

$script:DefaultConnection = $null

Register-ArgumentCompleter -CommandName Invoke-NexusBackupApi, Get-NexusBackupOperation -ParameterName OperationId -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete)
    $null = $commandName, $parameterName
    $script:NexusBackupOperations.Keys | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $script:NexusBackupOperations[$_].Summary)
    }
}
