#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.3' }
# Pester tests of the NexusBackup module. The network is mocked at Invoke-NexusBackupHttp, the module's only
# network call (it uses an HttpClient, not Invoke-RestMethod, for the certificate checks; see NexusBackup.cs).

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $root 'NexusBackup/NexusBackup.psd1') -Force
    $script:Spec = Get-Content -Raw (Join-Path $root '../../crates/web-api/openapi.json') | ConvertFrom-Json -AsHashtable
    $script:Token = ConvertTo-SecureString ('nxt_0123abcd_' + ('0' * 64)) -AsPlainText -Force  # not a real token

    function Resp {
        param([int] $Status = 200, $Body = $null, [string] $ContentType = 'application/json', [hashtable] $Headers = @{})
        $bytes = if ($Body -is [byte[]]) { $Body }
        elseif ($null -eq $Body) { [byte[]]@() }
        elseif ($ContentType -ne 'application/json') { [System.Text.Encoding]::UTF8.GetBytes([string]$Body) }
        else { [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Body -Depth 20 -Compress)) }
        [pscustomobject]@{ StatusCode = $Status; ContentType = $ContentType; Headers = $Headers; Bytes = $bytes }
    }

    # Routes: "METHOD /path" -> a list of answers, in turn (the last repeats). Calls are recorded.
    function Set-Route([string] $Key, [object[]] $Answers) { $script:Routes[$Key] = [System.Collections.Generic.List[object]]$Answers }
    function Use-Stub {
        $script:Routes = @{}
        $script:Calls = [System.Collections.Generic.List[object]]::new()
        Mock -ModuleName NexusBackup Invoke-NexusBackupHttp {
            $u = [uri]$Uri
            $path = $u.AbsolutePath -replace '^/api/v1', ''
            $script:Calls.Add([pscustomobject]@{
                    Method = $Method; Path = $path; Query = $u.Query; Headers = $Headers
                    Body = if ($Body) { $Body | ConvertFrom-Json -AsHashtable } else { $null }
                })
            $answers = $script:Routes["$Method $path"]
            if (-not $answers) { return Resp 404 @{ error = "no route $Method $path" } }
            $a = $answers[0]
            if ($answers.Count -gt 1) { $answers.RemoveAt(0) }
            $a
        }
        Mock -ModuleName NexusBackup Start-Sleep {}
    }
    function Connect-Token { Connect-NexusBackup -Url 'https://backup.example.com:8443' -Token $script:Token -CertificateFingerprint ('AB' * 32) }
    function Job([long] $Id, [string] $State, [hashtable] $Extra = @{}) {
        $j = @{ id = $Id; kind = 'backup'; tenant = 'acme'; state = $State; params = @{ group_id = 3 }; log = '' }
        foreach ($k in $Extra.Keys) { $j[$k] = $Extra[$k] }
        $j
    }
}

Describe 'module' {
    It 'exports cmdlets with help: synopsis and an example' {
        $cmds = Get-Command -Module NexusBackup
        $cmds.Count | Should -BeGreaterThan 20
        foreach ($c in $cmds) {
            $h = Get-Help $c.Name -Full
            $h.Synopsis | Should -Not -BeNullOrEmpty -Because $c.Name
            $h.Synopsis | Should -Not -BeLike "$($c.Name)*" -Because "$($c.Name) has comment-based help"
            @($h.examples.example).Count | Should -BeGreaterThan 0 -Because "$($c.Name) has an example"
        }
    }

    It 'exports what the manifest lists' {
        $listed = (Import-PowerShellDataFile (Join-Path (Split-Path -Parent $PSScriptRoot) 'NexusBackup/NexusBackup.psd1')).FunctionsToExport
        @((Get-Command -Module NexusBackup).Name | Sort-Object) | Should -Be @($listed | Sort-Object)
    }

    It 'uses approved verbs' {
        $approved = (Get-Verb).Verb
        foreach ($c in Get-Command -Module NexusBackup) { $c.Verb | Should -BeIn $approved }
    }

    It 'asks before cancelling and approving' {
        foreach ($n in 'Stop-NexusBackupJob', 'Approve-NexusBackupRequest') {
            (Get-Command $n).Parameters.Keys | Should -Contain 'WhatIf'
            (Get-Command $n).ScriptBlock.Attributes.Where({ $_ -is [System.Management.Automation.CmdletBindingAttribute] }).ConfirmImpact | Should -Be 'High'
        }
    }
}

Describe 'operations' {
    It 'cover every operation of openapi.json' {
        $ops = Get-NexusBackupOperation
        $inSpec = @{}
        foreach ($p in $script:Spec.paths.Keys) {
            $item = $script:Spec.paths[$p]
            foreach ($m in 'get', 'put', 'post', 'delete', 'patch') {
                if (-not $item.ContainsKey($m)) { continue }
                $token = -not ($item[$m].ContainsKey('x-token') -and $item[$m]['x-token'] -eq $false)
                $inSpec[$item[$m].operationId] = [pscustomobject]@{ Method = $m.ToUpper(); Path = $p; Token = $token }
            }
        }
        @($ops.OperationId | Sort-Object) | Should -Be @($inSpec.Keys | Sort-Object)
        foreach ($o in $ops) {
            $o.Method | Should -Be $inSpec[$o.OperationId].Method
            $o.Path | Should -Be $inSpec[$o.OperationId].Path
            $o.Token | Should -Be $inSpec[$o.OperationId].Token -Because $o.OperationId
        }
    }

    It 'version major is the API version' {
        $v = (Import-PowerShellDataFile (Join-Path (Split-Path -Parent $PSScriptRoot) 'NexusBackup/NexusBackup.psd1')).ModuleVersion
        $v.Split('.')[0] | Should -Be $script:Spec.info.version
    }
}

Describe 'connecting' {
    BeforeEach { Use-Stub }

    It 'sends the token as a bearer header' {
        Connect-Token
        Set-Route 'GET /dashboard' (Resp 200 @{ protected = 12 })
        (Get-NexusBackupDashboard).protected | Should -Be 12
        $script:Calls[0].Headers['Authorization'] | Should -Be ('Bearer nxt_0123abcd_' + ('0' * 64))
        $script:Calls[0].Headers.ContainsKey('Cookie') | Should -BeFalse
    }

    It 'checks the URL and the token' {
        { Connect-NexusBackup -Url 'http://backup.example.com' -Token $script:Token } | Should -Throw '*only for localhost*'
        $bad = ConvertTo-SecureString 'secret' -AsPlainText -Force
        { Connect-NexusBackup -Url 'https://backup.example.com' -Token $bad } | Should -Throw '*nxt_*'
        { Connect-NexusBackup -Url 'https://backup.example.com' -Token $script:Token -CertificateFingerprint 'AB:CD' } | Should -Throw '*64 hex*'
    }

    It 'signs in as a person: cookie, CSRF on changes, sign-out' {
        Set-Route 'POST /auth/login' (Resp 200 @{ user = @{ name = 'alice' }; csrf = 'c0ffee' } -Headers @{ 'Set-Cookie' = @('nx_session=s3ss; HttpOnly; Secure') })
        Set-Route 'GET /quorum' (Resp 200 @(@{ id = 12; state = 'pending' }))
        Set-Route 'POST /quorum/12/approve' (Resp 200 @{ id = 12; state = 'executed' })
        Set-Route 'POST /auth/logout' (Resp 200 @{ ok = $true })
        $cred = [pscredential]::new('alice', (ConvertTo-SecureString 'pw' -AsPlainText -Force))
        $c = Connect-NexusBackup -Url 'https://backup.example.com:8443' -Credential $cred -Totp '123456' -PassThru -SkipCertificateCheck
        $c.User | Should -Be 'alice'
        (Get-NexusBackupApprovalRequest -Pending).id | Should -Be 12
        $out = Approve-NexusBackupRequest -Id 12 -Confirm:$false
        Disconnect-NexusBackup
        $login, $get, $approve, $logout = $script:Calls
        $login.Body.name | Should -Be 'alice'
        $login.Body.password | Should -Be 'pw'
        $login.Body.totp | Should -Be '123456'
        $get.Query | Should -Be '?state=pending'
        $get.Headers['Cookie'] | Should -Be 'nx_session=s3ss'
        $get.Headers.ContainsKey('X-CSRF-Token') | Should -BeFalse
        $approve.Headers['X-CSRF-Token'] | Should -Be 'c0ffee'
        $logout.Path | Should -Be '/auth/logout'
        $out.State | Should -Be 'done'
        $out.QuorumId | Should -Be 12
        { Get-NexusBackupDashboard } | Should -Throw '*not connected*'
    }

    It 'reports a failed sign-in with the API message' {
        Set-Route 'POST /auth/login' (Resp 401 @{ error = 'invalid credentials' })
        $cred = [pscredential]::new('alice', (ConvertTo-SecureString 'bad' -AsPlainText -Force))
        { Connect-NexusBackup -Url 'https://backup.example.com' -Credential $cred } | Should -Throw '*invalid credentials*'
    }
}

Describe 'requests and errors' {
    BeforeEach { Use-Stub; Connect-Token }

    It 'throws ApiException with the API error text' {
        Set-Route 'GET /jobs/99' (Resp 404 @{ error = 'not found' })
        $err = $null
        try { Get-NexusBackupJob -Id 99 } catch { $err = $_ }
        $err.Exception | Should -BeOfType ([NexusBackup.ApiException])
        $err.Exception.StatusCode | Should -Be 404
        $err.Exception.ApiError | Should -Be 'not found'
        $err.CategoryInfo.Category | Should -Be 'ObjectNotFound'
    }

    It 'refuses session-only operations with a token before sending' {
        { Approve-NexusBackupRequest -Id 12 -Confirm:$false } | Should -Throw -ExceptionType ([NexusBackup.SessionRequiredException])
        { Export-NexusBackupAuditLog -Path (Join-Path $TestDrive 'a.csv') } | Should -Throw -ExceptionType ([NexusBackup.SessionRequiredException])
        $script:Calls.Count | Should -Be 0
    }

    It 'escapes path parameters and checks query names' {
        Set-Route 'GET /sources/a%2Fb/inventory' (Resp 200 @{ guests = @() })
        $null = Invoke-NexusBackupApi getSourceInventory -PathParameters @{ id = 'a/b' }
        $script:Calls.Count | Should -Be 1
        { Invoke-NexusBackupApi listAuditEntries -Query @{ acter = 'x' } } | Should -Throw "*no query parameter 'acter'*"
        { Invoke-NexusBackupApi getJob } | Should -Throw "*path parameter 'id'*"
        { Invoke-NexusBackupApi createJob } | Should -Throw '*-Body is required*'
    }

    It 'waits for a job until it has finished' {
        Set-Route 'POST /jobs' (Resp 202 @{ id = 41 })
        Set-Route 'GET /jobs/41' @((Resp 200 (Job 41 'queued')), (Resp 200 (Job 41 'running')), (Resp 200 (Job 41 'ok')))
        $out = Start-NexusBackupJob -Kind verify -Tenant acme -Parameters @{ source = 'vm-100' }
        $out.State | Should -Be 'done'
        $out.Done | Should -BeTrue
        $out.JobId | Should -Be 41
        $out.Job.state | Should -Be 'ok'
        $script:Calls[0].Body.kind | Should -Be 'verify'
        $script:Calls[0].Body.params.source | Should -Be 'vm-100'
        @($script:Calls | Where-Object Path -eq '/jobs/41').Count | Should -Be 3
    }

    It 'throws JobFailedException with the last log line' {
        Set-Route 'POST /jobs' (Resp 202 @{ id = 42 })
        Set-Route 'GET /jobs/42' (Resp 200 (Job 42 'failed' @{ log = "[pve] connecting`n[pve] guest 100 is locked`n" }))
        $err = $null
        try { Start-NexusBackupJob backup acme -Parameters @{ group_id = 3 } } catch { $err = $_ }
        $err.Exception | Should -BeOfType ([NexusBackup.JobFailedException])
        $err.Exception.State | Should -Be 'failed'
        $err.Exception.JobId | Should -Be 42
        $err.Exception.Message | Should -Be 'job 42 (backup) failed: [pve] guest 100 is locked'
    }

    It 'prefers the result error' {
        Set-Route 'GET /jobs/5' (Resp 200 (Job 5 'cancelled' @{ result = @{ error = 'cancelled by alice' } }))
        { Wait-NexusBackupJob -Id 5 } | Should -Throw '*cancelled by alice*'
    }

    It 'times out and does not wait with -NoWait' {
        Set-Route 'POST /jobs' (Resp 202 @{ id = 43 })
        Set-Route 'GET /jobs/43' (Resp 200 (Job 43 'running'))
        { Start-NexusBackupJob backup acme -TimeoutSec 0.001 } | Should -Throw -ExceptionType ([NexusBackup.WaitTimeoutException])
        $out = Start-NexusBackupJob backup acme -NoWait
        $out.State | Should -Be 'pending'
        $out.JobId | Should -Be 43
    }

    It 'returns approval_pending for a request that needs approval' {
        Set-Route 'POST /jobs' (Resp 202 @{ quorum_id = 9 })
        $out = Start-NexusBackupJob backup acme -Parameters @{ group_id = 3; keep_until = 1798761600 }
        $out.State | Should -Be 'approval_pending'
        $out.QuorumId | Should -Be 9
        $script:Calls.Count | Should -Be 1
    }

    It 'waits for raw answers and piped jobs' {
        Set-Route 'POST /jobs' (Resp 202 @{ id = 44 })
        Set-Route 'GET /jobs/44' (Resp 200 (Job 44 'ok'))
        Set-Route 'GET /jobs' (Resp 200 @((Job 44 'running')))
        $a = Invoke-NexusBackupApi createJob -Body @{ kind = 'verify'; tenant = 'acme'; params = @{} }
        (Wait-NexusBackupJob -InputObject $a).State | Should -Be 'done'
        (Get-NexusBackupJob -State running | Wait-NexusBackupJob).JobId | Should -Be 44
        (Wait-NexusBackupJob -InputObject @{ ok = $true }).State | Should -Be 'ok'
    }

    It 'sends nothing with -WhatIf' {
        Backup-NexusBackupGroup -Id 3 -Tenant acme -WhatIf
        Suspend-NexusBackupGroup -Id 3 -WhatIf
        Stop-NexusBackupJob -Id 1 -WhatIf
        $script:Calls.Count | Should -Be 0
    }
}

Describe 'groups, alerts, files' {
    BeforeEach { Use-Stub; Connect-Token }

    It 'backs up a group with the tenant read from the groups' {
        Set-Route 'GET /groups' (Resp 200 @(@{ id = 3; tenant = 'acme'; name = 'web' }))
        Set-Route 'POST /jobs' (Resp 202 @{ id = 45 })
        Set-Route 'GET /jobs/45' (Resp 200 (Job 45 'ok'))
        $until = [datetime]::new(2027, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
        (Backup-NexusBackupGroup -Id 3 -FailedOnly -KeepUntil $until -Confirm:$false).State | Should -Be 'done'
        $post = ($script:Calls | Where-Object Method -eq 'POST')[0].Body
        $post.tenant | Should -Be 'acme'
        $post.kind | Should -Be 'backup'
        $post.params.group_id | Should -Be 3
        $post.params.failed_only | Should -BeTrue
        $post.params.keep_until | Should -Be 1798761600
        { Backup-NexusBackupGroup -Id 4 } | Should -Throw '*no protection group 4*'
    }

    It 'pipes groups into a backup' {
        Set-Route 'GET /groups' (Resp 200 @(@{ id = 3; tenant = 'acme'; name = 'web' }))
        Set-Route 'POST /jobs' (Resp 202 @{ id = 46 })
        $out = Get-NexusBackupGroup | Backup-NexusBackupGroup -NoWait
        $out.JobId | Should -Be 46
        @($script:Calls | Where-Object Path -eq '/groups').Count | Should -Be 1
    }

    It 'pauses with or without a time and acknowledges with a note' {
        Set-Route 'POST /groups/3/pause' (Resp 200 @{ ok = $true })
        Set-Route 'POST /alerts/5/ack' (Resp 200 @{ ok = $true })
        $null = Suspend-NexusBackupGroup -Id 3
        $null = Suspend-NexusBackupGroup -Id 3 -Until ([datetime]::new(2027, 1, 1, 0, 0, 0, [DateTimeKind]::Utc))
        $null = Confirm-NexusBackupAlert -Id 5 -Note 'known, ticket 4711'
        $script:Calls[0].Body.ContainsKey('until') | Should -BeTrue
        $script:Calls[0].Body.until | Should -BeNullOrEmpty
        $script:Calls[1].Body.until | Should -Be 1798761600
        $script:Calls[2].Body.note | Should -Be 'known, ticket 4711'
    }

    It 'follows the file search cursor' {
        Set-Route 'GET /files/search' @(
            (Resp 200 @{ hits = @(@{ path = '/etc/hosts' }); next = 'c2' }),
            (Resp 200 @{ hits = @(@{ path = '/etc/hostname' }); next = $null }))
        (Find-NexusBackupFile host -Source vm-100).path | Should -Be @('/etc/hosts', '/etc/hostname')
        $script:Calls[0].Query | Should -Be '?q=host&source=vm-100&limit=200'
        $script:Calls[1].Query | Should -BeLike '*cursor=c2*'
    }
}

Describe 'logs and usage' {
    BeforeEach { Use-Stub; Connect-Token }

    It 'pages the audit log by seq' {
        Set-Route 'GET /audit' @((Resp 200 @(@{ seq = 1 }, @{ seq = 2 })), (Resp 200 @(@{ seq = 3 })))
        (Get-NexusBackupAuditLog -PageSize 2 -Actor alice).seq | Should -Be @(1, 2, 3)
        $script:Calls[0].Query | Should -Be '?limit=2&order=asc&actor=alice'
        $script:Calls[1].Query | Should -BeLike '*after=2*'
    }

    It 'pages the audit log newest first' {
        Set-Route 'GET /audit' @((Resp 200 @(@{ seq = 9 }, @{ seq = 8 })), (Resp 200 @()))
        (Get-NexusBackupAuditLog -PageSize 2 -NewestFirst).seq | Should -Be @(9, 8)
        $script:Calls[1].Query | Should -BeLike '*order=desc*before=8*'
    }

    It 'saves CSV downloads' {
        Set-Route 'GET /usage' (Resp 200 "month,tenant`n2026-10,acme`n" -ContentType 'text/csv')
        Get-NexusBackupUsage -Month 2026-10 -OutFile (Join-Path $TestDrive 'usage.csv')
        Get-Content -Raw (Join-Path $TestDrive 'usage.csv') | Should -BeLike 'month,tenant*acme*'
        $script:Calls[0].Query | Should -Be '?month=2026-10&format=csv'
    }

    It 'exports the audit log as a person' {
        Set-Route 'POST /auth/login' (Resp 200 @{ user = @{ name = 'sec' }; csrf = 'x' } -Headers @{ 'Set-Cookie' = @('nx_session=s; HttpOnly') })
        Set-Route 'GET /audit.csv' (Resp 200 "seq,ts,actor`n1,2,alice`n" -ContentType 'text/csv; charset=utf-8')
        $cred = [pscredential]::new('sec', (ConvertTo-SecureString 'pw' -AsPlainText -Force))
        Connect-NexusBackup -Url 'https://backup.example.com' -Credential $cred -SkipCertificateCheck
        Export-NexusBackupAuditLog -Path (Join-Path $TestDrive 'audit.csv') -Actor alice
        Get-Content -Raw (Join-Path $TestDrive 'audit.csv') | Should -BeLike 'seq,ts,actor*alice*'
        $script:Calls[1].Query | Should -Be '?actor=alice'
    }
}

Describe 'certificate checks' {
    BeforeAll {
        $key = [System.Security.Cryptography.ECDsa]::Create()
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=localhost', $key, 'SHA256')
        $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
        $san.AddDnsName('localhost')
        $req.CertificateExtensions.Add($san.Build())
        $now = [DateTimeOffset]::UtcNow
        $script:Cert = $req.CreateSelfSigned($now.AddMinutes(-5), $now.AddDays(2))
        $hex = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($script:Cert.RawData))
        $script:Fp = ($hex -split '(..)' | Where-Object { $_ }) -join ':'
        $script:Roots = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new($script:Cert)
        $script:None = [System.Net.Security.SslPolicyErrors]::None
        $script:Chain = [System.Net.Security.SslPolicyErrors]::RemoteCertificateChainErrors
        $script:Name = [System.Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch
    }

    It 'formats fingerprints as the appliance shows them' {
        [NexusBackup.CertificateValidator]::Fingerprint($script:Cert) | Should -Be $script:Fp
    }

    It 'accepts the pinned certificate whatever its name and chain' {
        $v = [NexusBackup.CertificateValidator]::new($script:Fp, $null, $false)
        $v.Validate($script:Cert, $null, ($script:Chain -bor $script:Name)) | Should -BeTrue
        $v = [NexusBackup.CertificateValidator]::new($script:Fp.Replace(':', '').ToLower(), $null, $false)
        $v.Validate($script:Cert, $null, $script:Chain) | Should -BeTrue
    }

    It 'refuses another certificate when pinned' {
        $v = [NexusBackup.CertificateValidator]::new(('00' * 32), $null, $false)
        $v.Validate($script:Cert, $null, $script:None) | Should -BeFalse
        $v.LastError | Should -BeLike '*does not match the pinned one*'
    }

    It 'trusts a given CA (the self-signed certificate) but checks the name' {
        $v = [NexusBackup.CertificateValidator]::new($null, $script:Roots, $false)
        $v.Validate($script:Cert, $null, $script:Chain) | Should -BeTrue
        $v.Validate($script:Cert, $null, ($script:Chain -bor $script:Name)) | Should -BeFalse
        $v.LastError | Should -BeLike '*does not name this host*'
    }

    It 'refuses an untrusted certificate by default and with another CA' {
        $v = [NexusBackup.CertificateValidator]::new($null, $null, $false)
        $v.Validate($script:Cert, $null, $script:Chain) | Should -BeFalse
        $v.LastError | Should -BeLike '*not trusted*'
        $other = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=other', [System.Security.Cryptography.ECDsa]::Create(), 'SHA256')
        $otherCert = $other.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddDays(1))
        $v = [NexusBackup.CertificateValidator]::new($null, [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new($otherCert), $false)
        $v.Validate($script:Cert, $null, $script:Chain) | Should -BeFalse
    }

    It 'checks nothing with -SkipCertificateCheck' {
        [NexusBackup.CertificateValidator]::new($null, $null, $true).Validate($script:Cert, $null, $script:Chain) | Should -BeTrue
    }
}
