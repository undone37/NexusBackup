<#
.SYNOPSIS
Registers an Entra ID app for the NexusBackup Microsoft 365 plugin (docs/m365.md
"Entra ID setup") with the Microsoft Graph PowerShell SDK: app registration,
self-signed certificate (or your own), the Microsoft Graph application permissions
the plugin needs and admin consent. Prints the values for the source form.

.DESCRIPTION
Run it on an admin workstation (PowerShell 7.3 or later, module Microsoft.Graph:
Install-Module Microsoft.Graph -Scope CurrentUser), as a Global Administrator or
Privileged Role Administrator. Never on the appliance: the appliance has no
outbound access to these APIs and must not hold admin credentials.
Several apps (source field "Further app registrations"): run it once per app with
different names.

.EXAMPLE
./register-app.ps1 -TenantId contoso.onmicrosoft.com -Chats
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $TenantId,
    [string] $Name = 'NexusBackup M365',
    [string] $Out = "./nexus-m365-$(Get-Date -Format yyyyMMdd-HHmmss)",
    [int] $Days = 730,
    # your own certificate and unencrypted key (PEM) instead of a new self-signed one
    [string] $CertFile,
    [string] $KeyFile,
    # read permissions only (no restores into Microsoft 365)
    [switch] $BackupOnly,
    # ChannelMessage.Read.All (protected API: Microsoft must approve)
    [switch] $TeamsMessages,
    # Chat.Read.All + Chat.ReadBasic.All (protected, metered API)
    [switch] $Chats,
    # Device.Read.All + Application.Read.All (source option "Entra ID directory objects";
    # groups and members use Group.Read.All)
    [switch] $Entra
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Graph = '00000003-0000-0000-c000-000000000000'

if ($PSVersionTable.PSVersion -lt [version]'7.3') { throw 'PowerShell 7.3 or later is required' }
if ([bool]$CertFile -ne [bool]$KeyFile) { throw '-CertFile and -KeyFile go together' }

# Application permissions (docs/m365.md, "API permissions")
$perms = if ($BackupOnly) {
    @('User.Read.All', 'Mail.Read', 'Calendars.Read', 'Contacts.Read', 'Sites.Read.All', 'Files.Read.All',
      'Team.ReadBasic.All', 'Channel.ReadBasic.All', 'Group.Read.All')
} else {
    @('User.Read.All', 'Mail.ReadWrite', 'Calendars.ReadWrite', 'Contacts.ReadWrite', 'Sites.ReadWrite.All',
      'Files.ReadWrite.All', 'Team.ReadBasic.All', 'Channel.ReadBasic.All', 'Group.Read.All')
}
if ($TeamsMessages) {
    $perms += 'ChannelMessage.Read.All'
    if (-not $BackupOnly) { $perms += @('Teamwork.Migrate.All', 'Channel.Create') }
}
if ($Chats) { $perms += @('Chat.Read.All', 'Chat.ReadBasic.All') }
if ($Entra) { $perms += @('Device.Read.All', 'Application.Read.All') }

New-Item -ItemType Directory -Force -Path $Out | Out-Null
if (-not $IsWindows) { chmod 700 $Out }
if ($CertFile) {
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile($CertFile, $KeyFile)
    $certPem = Get-Content -Raw $CertFile
    $keyPem = Get-Content -Raw $KeyFile
} else {
    $rsa = [System.Security.Cryptography.RSA]::Create(3072)
    $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        "CN=$Name", $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $now = [DateTimeOffset]::UtcNow
    $cert = $req.CreateSelfSigned($now.AddDays(-1), $now.AddDays($Days))
    $certPem = $cert.ExportCertificatePem() + "`n"
    $keyPem = $rsa.ExportPkcs8PrivateKeyPem() + "`n"
}
$certPath = Join-Path $Out 'app.crt'
$keyPath = Join-Path $Out 'app.key'
$pemPath = Join-Path $Out 'app.pem'
Set-Content -NoNewline -Path $certPath -Value $certPem
Set-Content -NoNewline -Path $keyPath -Value $keyPem
Set-Content -NoNewline -Path $pemPath -Value ($certPem + $keyPem)
if (-not $IsWindows) { chmod 600 $keyPath $pemPath }

Import-Module Microsoft.Graph.Applications
Connect-MgGraph -TenantId $TenantId -NoWelcome -Scopes @(
    'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'Sites.Read.All')
$tenant = (Get-MgContext).TenantId

$graphSp = Get-MgServicePrincipal -Filter "appId eq '$Graph'"
$roles = foreach ($p in $perms) {
    $r = $graphSp.AppRoles | Where-Object { $_.Value -eq $p -and $_.AllowedMemberTypes -contains 'Application' }
    if (-not $r) { throw "Microsoft Graph has no application permission $p" }
    $r
}

Write-Host "Creating the app registration `"$Name`" in tenant $tenant ..."
$app = New-MgApplication -DisplayName $Name -SignInAudience AzureADMyOrg `
    -KeyCredentials @(@{ Type = 'AsymmetricX509Cert'; Usage = 'Verify'; Key = $cert.RawData; DisplayName = "CN=$Name" }) `
    -RequiredResourceAccess @(@{ ResourceAppId = $Graph; ResourceAccess = @($roles | ForEach-Object { @{ Id = $_.Id; Type = 'Role' } }) })
$sp = New-MgServicePrincipal -AppId $app.AppId

Write-Host "Granting $($perms.Count) Microsoft Graph application permissions (admin consent) ..."
foreach ($r in $roles) {
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id `
        -ResourceId $graphSp.Id -AppRoleId $r.Id | Out-Null
}

$spHost = $null
try { $spHost = (Invoke-MgGraphRequest -Method GET -Uri 'v1.0/sites/root?$select=siteCollection').siteCollection.hostname } catch { }
$odHost = if ($spHost) { $spHost -replace '^([^.]+)\.', '$1-my.' } else { $null }
$thumb = $cert.Thumbprint

Write-Host @"

Done. Values for the source (Configuration -> Sources -> Microsoft 365 tenant):

  Tenant ID ............ $tenant
  Client ID ............ $($app.AppId)
  Certificate .......... $certPath
  Private key .......... $keyPath
  (both in one file, for "Further app registrations": $pemPath)
  SharePoint host ...... $(if ($spHost) { $spHost } else { '<tenant>.sharepoint.com (look it up in the SharePoint admin center)' })
  OneDrive host ........ $odHost
  Thumbprint (SHA-1) ... $thumb  (validation logs it)

Permissions: $($perms -join ' ')
"@
if ($TeamsMessages -or $Chats) {
    Write-Host 'Protected APIs: request access at https://aka.ms/teamsgraph/requestaccess (model B also needs an Azure subscription linked to the app).'
}
Write-Host "Paste the certificate and key into the source, then delete $Out (the appliance keeps them sealed)."
