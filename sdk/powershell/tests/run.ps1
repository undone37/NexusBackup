# Runs the Pester tests and PSScriptAnalyzer on the module. Exit code 0 = all passed.
# Used by sdk/check.sh (locally when Pester 5 is installed, else in the mcr.microsoft.com/powershell container) and
# by CI (job sdk, with -Install: the pinned Pester and PSScriptAnalyzer from the PowerShell Gallery).
param([switch] $Install)
$ErrorActionPreference = 'Stop'
$PSStyle.OutputRendering = 'PlainText'

if ($Install) {
    # pinned: what the gate ran with (PSScriptAnalyzer 1.24 needs PowerShell 7.4.6)
    Set-PSRepository PSGallery -InstallationPolicy Trusted
    Install-Module Pester -RequiredVersion 5.7.1 -Scope CurrentUser -Force -SkipPublisherCheck
    Install-Module PSScriptAnalyzer -RequiredVersion 1.23.0 -Scope CurrentUser -Force
}

$sdk = Split-Path -Parent $PSScriptRoot
Import-Module Pester -MinimumVersion 5.3

$cfg = New-PesterConfiguration
$cfg.Run.Path = Join-Path $PSScriptRoot 'NexusBackup.Tests.ps1'
$cfg.Run.Exit = $false
$cfg.Run.PassThru = $true
$cfg.Output.Verbosity = 'Normal'
$result = Invoke-Pester -Configuration $cfg
$failed = $result.FailedCount -gt 0 -or $result.Result -ne 'Passed'

if (Get-Module -ListAvailable PSScriptAnalyzer) {
    $settings = Join-Path $sdk 'PSScriptAnalyzerSettings.psd1'
    $issues = Invoke-ScriptAnalyzer -Path (Join-Path $sdk 'NexusBackup') -Recurse -Settings $settings
    if ($issues) {
        $issues | Format-Table -AutoSize RuleName, Severity, ScriptName, Line, Message | Out-String -Width 200 | Write-Host
        $failed = $true
    } else {
        Write-Host 'PSScriptAnalyzer: no findings'
    }
} else {
    Write-Host 'PSScriptAnalyzer not installed: lint skipped'
}
exit ([int]$failed)
