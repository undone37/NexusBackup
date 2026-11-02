# Connection, authentication, TLS, requests, errors and waiting for jobs. Dot-sourced by NexusBackup.psm1.

$script:SessionCookie = 'nx_session'
$script:ModuleVersion = '1.0.0'

function Invoke-NexusBackupHttp {
    # The module's only network call: one HTTP exchange with the connection's HttpClient (certificate check in
    # NexusBackup.cs). The tests mock this function.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $Connection,
        [Parameter(Mandatory)] [string] $Method,
        [Parameter(Mandatory)] [string] $Uri,
        [hashtable] $Headers = @{},
        [AllowNull()] [string] $Body,
        [int] $TimeoutSec = 0
    )
    $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::new($Method), $Uri)
    foreach ($k in $Headers.Keys) {
        [void]$req.Headers.TryAddWithoutValidation($k, [string]$Headers[$k])
    }
    if (-not [string]::IsNullOrEmpty($Body)) {
        $req.Content = [System.Net.Http.StringContent]::new($Body, [System.Text.Encoding]::UTF8, 'application/json')
    }
    $seconds = if ($TimeoutSec -gt 0) { $TimeoutSec } else { $Connection.TimeoutSec }
    $cts = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds($seconds))
    $Connection.Validator.Reset()
    try {
        $resp = $Connection.HttpClient.SendAsync($req, $cts.Token).GetAwaiter().GetResult()
    } catch {
        $e = $_.Exception
        while ($e -is [System.Management.Automation.MethodInvocationException] -and $e.InnerException) { $e = $e.InnerException }
        $req.Dispose()
        $why = $Connection.Validator.LastError
        if ($why) { throw [NexusBackup.TlsException]::new("$($Connection.Url): $why", $e) }
        if ($e -is [System.OperationCanceledException]) {
            throw [NexusBackup.NexusBackupException]::new("$Method $Uri : no answer within $seconds s", $e)
        }
        throw [NexusBackup.NexusBackupException]::new("$($Connection.Url): $($e.Message)", $e)
    } finally {
        $cts.Dispose()
    }
    try {
        $headers = @{}
        foreach ($h in $resp.Headers) { $headers[$h.Key] = @($h.Value) }
        foreach ($h in $resp.Content.Headers) { $headers[$h.Key] = @($h.Value) }
        [pscustomobject]@{
            StatusCode  = [int]$resp.StatusCode
            ContentType = [string]$resp.Content.Headers.ContentType
            Headers     = $headers
            Bytes       = $resp.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
        }
    } finally {
        $resp.Dispose()
        $req.Dispose()
    }
}

function ConvertFrom-NexusBackupContent {
    # JSON -> objects (arrays kept as arrays), text/* -> string, anything else -> byte[]
    param([Parameter(Mandatory)] [object] $Response)
    $ct = ([string]$Response.ContentType).Split(';')[0].Trim().ToLowerInvariant()
    $bytes = [byte[]]$Response.Bytes
    if ($ct -eq 'application/json' -or $ct.EndsWith('+json')) {
        if ($null -eq $bytes -or $bytes.Length -eq 0) { return $null }
        $v = ConvertFrom-Json -InputObject ([System.Text.Encoding]::UTF8.GetString($bytes)) -Depth 100 -NoEnumerate
        if ($v -is [array]) { return , $v }
        return $v
    }
    if ($ct.StartsWith('text/')) {
        return [System.Text.Encoding]::UTF8.GetString($bytes)
    }
    if (-not $ct -and ($null -eq $bytes -or $bytes.Length -eq 0)) { return $null }
    return , $bytes
}

function Get-NexusBackupConnection {
    # The -Connection given, else the one of the last Connect-NexusBackup.
    param([object] $Connection)
    if ($Connection) { return $Connection }
    if ($script:DefaultConnection) { return $script:DefaultConnection }
    throw [NexusBackup.NexusBackupException]::new('not connected: run Connect-NexusBackup first (or pass -Connection)')
}

function ConvertTo-NexusBackupQueryString {
    param([System.Collections.IDictionary] $Query)
    $parts = foreach ($k in $Query.Keys) {
        $v = $Query[$k]
        if ($null -eq $v) { continue }
        if ($v -is [bool]) { $v = if ($v) { 'true' } else { 'false' } }
        elseif ($v -is [datetime]) { $v = [DateTimeOffset]::new($v.ToUniversalTime()).ToUnixTimeSeconds() }
        '{0}={1}' -f [uri]::EscapeDataString([string]$k), [uri]::EscapeDataString([string]$v)
    }
    if ($parts) { '?' + ($parts -join '&') } else { '' }
}

function Send-NexusBackupRequest {
    # One request below /api/v1 with the connection's credentials; returns @{ Response; Value } or throws an
    # ErrorRecord with a NexusBackup.ApiException (the API's {"error"} text).
    param(
        [Parameter(Mandatory)] [object] $Connection,
        [Parameter(Mandatory)] [string] $Method,
        [Parameter(Mandatory)] [string] $Path,
        [System.Collections.IDictionary] $Query = @{},
        [object] $Body,
        [int] $TimeoutSec = 0
    )
    $headers = @{
        'Accept'     = 'application/json'
        'User-Agent' = "nexusbackup-powershell/$script:ModuleVersion"
    }
    if ($Connection.Cookie) {
        $headers['Cookie'] = "$script:SessionCookie=$($Connection.Cookie)"
        if ($Method -ne 'GET' -and $Connection.Csrf) { $headers['X-CSRF-Token'] = $Connection.Csrf }
    } elseif ($Connection.Token) {
        $headers['Authorization'] = 'Bearer ' + [System.Net.NetworkCredential]::new('', $Connection.Token).Password
    }
    $json = $null
    if ($null -ne $Body) {
        $json = if ($Body -is [string]) { $Body } else { ConvertTo-Json -InputObject $Body -Depth 100 -Compress }
    }
    $uri = $Connection.BaseUri + '/api/v1' + $Path + (ConvertTo-NexusBackupQueryString $Query)
    $r = Invoke-NexusBackupHttp -Connection $Connection -Method $Method -Uri $uri -Headers $headers -Body $json -TimeoutSec $TimeoutSec
    $value = ConvertFrom-NexusBackupContent -Response $r
    if ($r.StatusCode -ge 400) {
        $msg = $null
        if ($value -is [System.Management.Automation.PSCustomObject] -and $value.PSObject.Properties['error']) { $msg = [string]$value.error }
        elseif ($value -is [string] -and $value) { $msg = $value }
        if (-not $msg) { $msg = "HTTP $($r.StatusCode)" }
        $ex = [NexusBackup.ApiException]::new($r.StatusCode, $msg, $Method, $Path, $value)
        $category = switch ($r.StatusCode) {
            400 { 'InvalidArgument' }
            401 { 'AuthenticationError' }
            403 { 'PermissionDenied' }
            404 { 'ObjectNotFound' }
            409 { 'InvalidOperation' }
            429 { 'LimitsExceeded' }
            default { 'InvalidResult' }
        }
        throw [System.Management.Automation.ErrorRecord]::new($ex, "NexusBackup.Http$($r.StatusCode)", $category, "$Method $Path")
    }
    [pscustomobject]@{ Response = $r; Value = $value }
}

function New-NexusBackupOutcome {
    param([string] $State, [object] $JobId, [object] $QuorumId, [object] $Response, [object] $Job)
    [pscustomobject]@{
        PSTypeName = 'NexusBackup.Outcome'
        State      = $State
        Done       = $State -in 'done', 'ok'
        JobId      = $JobId
        QuorumId   = $QuorumId
        Response   = $Response
        Job        = $Job
    }
}

function Get-NexusBackupProperty {
    param([object] $Object, [string] $Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { return $Object[$Name] }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { $p.Value } else { $null }
}

function Get-NexusBackupJobReason {
    # Why a job failed: result.error, else the last line of its log.
    param([object] $Job)
    $err = Get-NexusBackupProperty (Get-NexusBackupProperty $Job 'result') 'error'
    if ($err -is [string] -and $err) { return $err }
    $lines = @(([string](Get-NexusBackupProperty $Job 'log')) -split "`r?`n" | Where-Object { $_.Trim() })
    if ($lines.Count -gt 0) { return $lines[-1].Trim() }
    'no reason given'
}

function Wait-NexusBackupJobId {
    # Polls GET /jobs/{id} until the job has finished; TimeoutSec 0 = no limit.
    param([object] $Connection, [long] $JobId, [double] $TimeoutSec, [int] $IntervalMs, [object] $Response)
    $deadline = if ($TimeoutSec -gt 0) { [DateTime]::UtcNow.AddSeconds($TimeoutSec) } else { [DateTime]::MaxValue }
    while ($true) {
        $job = (Send-NexusBackupRequest -Connection $Connection -Method GET -Path "/jobs/$JobId").Value
        $state = [string](Get-NexusBackupProperty $job 'state')
        if ($state -eq 'ok') {
            return New-NexusBackupOutcome -State done -JobId $JobId -Response $Response -Job $job
        }
        if ($state -in 'failed', 'cancelled') {
            $ex = [NexusBackup.JobFailedException]::new($JobId, [string](Get-NexusBackupProperty $job 'kind'), $state, (Get-NexusBackupJobReason $job), $job)
            throw [System.Management.Automation.ErrorRecord]::new($ex, "NexusBackup.Job.$state", 'InvalidResult', $JobId)
        }
        if ([DateTime]::UtcNow.AddMilliseconds($IntervalMs) -gt $deadline) {
            $ex = [NexusBackup.WaitTimeoutException]::new($JobId, $state, $TimeoutSec, $job)
            throw [System.Management.Automation.ErrorRecord]::new($ex, 'NexusBackup.Job.Timeout', 'OperationTimeout', $JobId)
        }
        Start-Sleep -Milliseconds $IntervalMs
    }
}

function Resolve-NexusBackupAnswer {
    # The answer to an action -> an outcome: waits for its job (-JobId, else the answer's job_id) unless -NoWait;
    # a quorum_id (the action needs approval) is returned as approval_pending, never waited for.
    param(
        [object] $Connection,
        [AllowNull()] [object] $Answer,
        [object] $JobId,
        [switch] $NoWait,
        [double] $TimeoutSec = 3600,
        [int] $IntervalMs = 3000
    )
    if ($null -eq $Answer -or $Answer -is [string] -or $Answer -is [array] -or $Answer -is [byte[]]) {
        return New-NexusBackupOutcome -State ok -Response $Answer
    }
    $quorum = Get-NexusBackupProperty $Answer 'quorum_id'
    if ($null -ne $quorum -and (Get-NexusBackupProperty $Answer 'approvals') -ne 'disabled') {
        return New-NexusBackupOutcome -State approval_pending -QuorumId $quorum -Response $Answer
    }
    if ($null -eq $JobId) { $JobId = Get-NexusBackupProperty $Answer 'job_id' }
    if ($null -ne $JobId) {
        if ($NoWait) { return New-NexusBackupOutcome -State pending -JobId ([long]$JobId) -Response $Answer }
        return Wait-NexusBackupJobId -Connection $Connection -JobId ([long]$JobId) -TimeoutSec $TimeoutSec -IntervalMs $IntervalMs -Response $Answer
    }
    New-NexusBackupOutcome -State ok -Response $Answer
}

function ConvertTo-NexusBackupUnixTime {
    param([object] $Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return [DateTimeOffset]::new($Value.ToUniversalTime()).ToUnixTimeSeconds() }
    if ($Value -is [DateTimeOffset]) { return $Value.ToUnixTimeSeconds() }
    [long]$Value
}

function Connect-NexusBackup {
    <#
    .SYNOPSIS
    Connects to a NexusBackup appliance with an API token or as a person (password and TOTP code).
    .DESCRIPTION
    The connection becomes the default of the other cmdlets (or pass it with -Connection; -PassThru returns it).

    API token (My account -> API tokens, nxt_...; scope read, operator or backup): acts at most as an operator
    and reaches only the operations of the API description not marked session only. For those (approving,
    the audit CSV, the restore point simulator), connect with -Credential and -Totp: a session like the web
    UI's, ended by Disconnect-NexusBackup. Accounts under the passkey policy and single sign-on accounts cannot
    sign in here: use the web UI.

    TLS: the system trust store by default; -CaCertificatePath trusts only the given CA or the appliance's
    self-signed certificate (the name in it must match the URL's host); -CertificateFingerprint pins the
    certificate's SHA-256 instead (no name or chain check: for the self-signed certificate reached by an
    address it does not name; see Get-NexusBackupServerFingerprint); -SkipCertificateCheck checks nothing.

    Defaults from the environment as nexusctl: NEXUS_URL, NEXUS_TOKEN, NEXUS_CA, and NEXUS_FINGERPRINT.
    .PARAMETER Url
    The management URL, https://host[:port] (http:// only for localhost).
    .PARAMETER Token
    The API token as a SecureString (default: NEXUS_TOKEN).
    .PARAMETER Credential
    User name and password of a person; with -Totp, the current code of the account's authenticator.
    .EXAMPLE
    $token = Read-Host -AsSecureString 'API token'
    Connect-NexusBackup -Url https://backup.example.com:8443 -Token $token -CaCertificatePath ./nexusbackup-ca.pem
    .EXAMPLE
    Connect-NexusBackup -Url https://192.0.2.10:8443 -Credential alice -Totp 123456 -CertificateFingerprint 'AB:CD:...'
    #>
    [CmdletBinding(DefaultParameterSetName = 'Token')]
    [OutputType('NexusBackup.Connection')]
    param(
        [string] $Url = $env:NEXUS_URL,
        [Parameter(ParameterSetName = 'Token')] [securestring] $Token,
        [Parameter(Mandatory, ParameterSetName = 'Session')] [pscredential] [System.Management.Automation.Credential()] $Credential,
        [Parameter(ParameterSetName = 'Session')] [string] $Totp,
        [string] $CaCertificatePath = $env:NEXUS_CA,
        [string] $CertificateFingerprint = $env:NEXUS_FINGERPRINT,
        [switch] $SkipCertificateCheck,
        [ValidateRange(1, 3600)] [int] $TimeoutSec = 60,
        [switch] $PassThru
    )
    if (-not $Url) { throw [System.ArgumentException]::new('-Url (or NEXUS_URL) is required') }
    $u = $null
    if (-not [uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$u) -or $u.Scheme -notin 'https', 'http') {
        throw [System.ArgumentException]::new("-Url: https://host[:port], not '$Url'")
    }
    if ($u.Scheme -eq 'http' -and $u.Host -notin 'localhost', '127.0.0.1', '[::1]') {
        throw [System.ArgumentException]::new('-Url: https:// (http:// only for localhost)')
    }
    if ($PSCmdlet.ParameterSetName -eq 'Token') {
        if (-not $Token -and $env:NEXUS_TOKEN) { $Token = [System.Net.NetworkCredential]::new('', $env:NEXUS_TOKEN).SecurePassword }
        if (-not $Token) { throw [System.ArgumentException]::new('-Token (or NEXUS_TOKEN) or -Credential is required') }
        if (-not [System.Net.NetworkCredential]::new('', $Token).Password.StartsWith('nxt_')) {
            throw [System.ArgumentException]::new('-Token: an API token (nxt_...), created under My account -> API tokens')
        }
    }
    $roots = $null
    if ($CaCertificatePath -and -not $CertificateFingerprint -and -not $SkipCertificateCheck) {
        $roots = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $roots.ImportFromPemFile($PSCmdlet.GetUnresolvedProviderPathFromPSPath($CaCertificatePath))
    }
    $validator = [NexusBackup.CertificateValidator]::new($CertificateFingerprint, $roots, [bool]$SkipCertificateCheck)
    $http = [System.Net.Http.HttpClient]::new($validator.CreateHandler(), $true)
    $http.Timeout = [System.Threading.Timeout]::InfiniteTimeSpan
    $conn = [pscustomobject]@{
        PSTypeName = 'NexusBackup.Connection'
        Url        = $Url
        BaseUri    = $u.GetLeftPart([UriPartial]::Authority) + $u.AbsolutePath.TrimEnd('/')
        User       = $null
        Token      = if ($PSCmdlet.ParameterSetName -eq 'Token') { $Token } else { $null }
        Cookie     = $null
        Csrf       = $null
        Session    = $null
        TimeoutSec = $TimeoutSec
        HttpClient = $http
        Validator  = $validator
    }
    if ($PSCmdlet.ParameterSetName -eq 'Session') {
        $body = [ordered]@{ name = $Credential.UserName; password = $Credential.GetNetworkCredential().Password }
        if ($Totp) { $body['totp'] = $Totp }
        $r = Send-NexusBackupRequest -Connection $conn -Method POST -Path '/auth/login' -Body $body
        $cookie = $null
        foreach ($line in @($r.Response.Headers['Set-Cookie'])) {
            if ($line -and $line.StartsWith("$script:SessionCookie=")) {
                $cookie = $line.Split(';')[0].Substring($script:SessionCookie.Length + 1)
            }
        }
        if (-not $cookie) { throw [NexusBackup.NexusBackupException]::new('sign-in: no session cookie in the answer') }
        $csrf = Get-NexusBackupProperty $r.Value 'csrf'
        if (-not $csrf) { throw [NexusBackup.NexusBackupException]::new('sign-in: no CSRF token in the answer') }
        $conn.Cookie = $cookie
        $conn.Csrf = $csrf
        $conn.Session = $r.Value
        $conn.User = $Credential.UserName
    }
    $script:DefaultConnection = $conn
    if ($PassThru) { $conn }
}

function Disconnect-NexusBackup {
    <#
    .SYNOPSIS
    Ends the session of a person (POST /auth/logout) and forgets the connection.
    .EXAMPLE
    Disconnect-NexusBackup
    #>
    [CmdletBinding()]
    param([PSTypeName('NexusBackup.Connection')] [object] $Connection)
    $c = Get-NexusBackupConnection $Connection
    try {
        if ($c.Cookie) { $null = Send-NexusBackupRequest -Connection $c -Method POST -Path '/auth/logout' -Body @{} }
    } finally {
        $c.Cookie = $null
        $c.Csrf = $null
        $c.HttpClient.Dispose()
        if ($script:DefaultConnection -eq $c) { $script:DefaultConnection = $null }
    }
}

function Get-NexusBackupServerFingerprint {
    <#
    .SYNOPSIS
    Shows the SHA-256 fingerprint of the certificate an appliance presents, without checking it.
    .DESCRIPTION
    For trust on first use: compare it with the fingerprint shown on the appliance (web UI: Settings ->
    Certificate) before passing it to Connect-NexusBackup -CertificateFingerprint. On its own it proves nothing.
    .EXAMPLE
    Get-NexusBackupServerFingerprint -Url https://192.0.2.10:8443
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Url, [int] $TimeoutSec = 10)
    $u = [uri]$Url
    if ($u.Scheme -ne 'https') { throw [System.ArgumentException]::new('-Url: https://host[:port]') }
    [NexusBackup.CertificateValidator]::GetServerFingerprint($u.Host, $u.Port, $TimeoutSec * 1000)
}

function Invoke-NexusBackupApi {
    <#
    .SYNOPSIS
    Calls any operation of the NexusBackup REST API by its operationId.
    .DESCRIPTION
    The operations are generated from the API description (Get-NexusBackupOperation lists them; tab completion
    on -OperationId). Answers come back decoded: JSON as objects (lists one by one), CSV as a string,
    downloads as bytes (or written to -OutFile). Starting a job answers {id}, a request that needs approval
    {quorum_id}: see Wait-NexusBackupJob. Errors are terminating, with a NexusBackup.ApiException carrying the
    API's message.
    .PARAMETER PathParameters
    Values of the {placeholders} in the path, e.g. @{ id = 4711 }.
    .PARAMETER Query
    Query parameters, e.g. @{ actor = 'alice'; limit = 100 } (datetime values become unix seconds).
    .PARAMETER Body
    The JSON body: a hashtable, an object or a JSON string.
    .EXAMPLE
    Invoke-NexusBackupApi getDashboard
    .EXAMPLE
    Invoke-NexusBackupApi createJob -Body @{ kind = 'verify'; tenant = 'acme'; params = @{} } | Wait-NexusBackupJob
    .EXAMPLE
    Invoke-NexusBackupApi getUsage -Query @{ month = '2026-10'; format = 'csv' } -OutFile ./usage-2026-10.csv
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)] [string] $OperationId,
        [hashtable] $PathParameters = @{},
        [System.Collections.IDictionary] $Query = @{},
        [object] $Body,
        [string] $OutFile,
        [int] $TimeoutSec = 0,
        [PSTypeName('NexusBackup.Connection')] [object] $Connection
    )
    $op = $script:NexusBackupOperations[$OperationId]
    if (-not $op) {
        throw [System.ArgumentException]::new("unknown operationId '$OperationId'; see Get-NexusBackupOperation")
    }
    $c = Get-NexusBackupConnection $Connection
    if ($op.Auth -and -not $op.Token -and -not $c.Cookie) {
        throw [NexusBackup.SessionRequiredException]::new(
            "$OperationId ($($op.Method) $($op.Path)) is not reachable with an API token: Connect-NexusBackup -Credential")
    }
    $path = $op.Path
    foreach ($p in $op.PathParameters) {
        $v = $PathParameters[$p]
        if ($null -eq $v -or "$v" -eq '') { throw [System.ArgumentException]::new("${OperationId}: path parameter '$p' is required") }
        $path = $path.Replace("{$p}", [uri]::EscapeDataString([string]$v))
    }
    foreach ($k in $Query.Keys) {
        if ($k -notin $op.QueryParameters) {
            throw [System.ArgumentException]::new("${OperationId}: no query parameter '$k' (has: $($op.QueryParameters -join ', '))")
        }
    }
    if ($null -eq $Body) {
        if ($op.Body -eq 'required') { throw [System.ArgumentException]::new("${OperationId}: -Body is required") }
        if ($op.Method -in 'POST', 'PUT') { $Body = @{} }
    }
    $r = Send-NexusBackupRequest -Connection $c -Method $op.Method -Path $path -Query $Query -Body $Body -TimeoutSec $TimeoutSec
    if ($OutFile) {
        $target = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($OutFile)
        [System.IO.File]::WriteAllBytes($target, [byte[]]$r.Response.Bytes)
        return
    }
    Write-Output $r.Value
}

function Get-NexusBackupOperation {
    <#
    .SYNOPSIS
    Lists the operations of the API description that Invoke-NexusBackupApi can call.
    .EXAMPLE
    Get-NexusBackupOperation | Where-Object Path -like '/jobs*' | Format-Table OperationId, Method, Path, Token
    #>
    [CmdletBinding()]
    param([Parameter(Position = 0)] [string] $OperationId = '*')
    foreach ($k in $script:NexusBackupOperations.Keys) {
        if ($k -notlike $OperationId) { continue }
        $o = $script:NexusBackupOperations[$k]
        [pscustomobject]@{
            PSTypeName      = 'NexusBackup.Operation'
            OperationId     = $k
            Method          = $o.Method
            Path            = $o.Path
            PathParameters  = $o.PathParameters
            QueryParameters = $o.QueryParameters
            Body            = $o.Body
            Token           = $o.Token
            Summary         = $o.Summary
        }
    }
}

function Wait-NexusBackupJob {
    <#
    .SYNOPSIS
    Waits until a job has finished and returns its outcome.
    .DESCRIPTION
    Takes a job id (or a job by pipeline: Get-NexusBackupJob output has Id), or the answer of an action from
    Invoke-NexusBackupApi (-InputObject: {id} of POST /jobs, {job_id} of an approval, {quorum_id}). Outcomes
    (State): done (the job finished ok; Job is GET /jobs/{id} with its log), approval_pending (the action needs
    approval: QuorumId waits for a second person; not waited for), ok (no job). Failed and cancelled jobs throw
    a NexusBackup.JobFailedException, a job still queued or running after -TimeoutSec (0: no limit) a
    NexusBackup.WaitTimeoutException; the job goes on running.
    .EXAMPLE
    Wait-NexusBackupJob -Id 4711 -TimeoutSec 7200
    .EXAMPLE
    Get-NexusBackupJob -State running | Wait-NexusBackupJob
    .EXAMPLE
    Wait-NexusBackupJob -InputObject (Invoke-NexusBackupApi approveRequest -PathParameters @{ id = 12 })
    #>
    [CmdletBinding(DefaultParameterSetName = 'Id')]
    [OutputType('NexusBackup.Outcome')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName, ParameterSetName = 'Id')] [Alias('JobId')] [long] $Id,
        [Parameter(Mandatory, ParameterSetName = 'Answer')] [AllowNull()] [object] $InputObject,
        [ValidateRange(0, 604800)] [double] $TimeoutSec = 3600,
        [ValidateRange(50, 600000)] [int] $IntervalMs = 3000,
        [PSTypeName('NexusBackup.Connection')] [object] $Connection
    )
    process {
        $c = Get-NexusBackupConnection $Connection
        if ($PSCmdlet.ParameterSetName -eq 'Id') {
            Wait-NexusBackupJobId -Connection $c -JobId $Id -TimeoutSec $TimeoutSec -IntervalMs $IntervalMs
        } else {
            $jid = $null
            if ($null -eq (Get-NexusBackupProperty $InputObject 'job_id') -and $null -eq (Get-NexusBackupProperty $InputObject 'quorum_id')) {
                $jid = Get-NexusBackupProperty $InputObject 'id'
                if ($null -ne (Get-NexusBackupProperty $InputObject 'state')) { $jid = $null }  # an approval's {id, state}
            }
            Resolve-NexusBackupAnswer -Connection $c -Answer $InputObject -JobId $jid -TimeoutSec $TimeoutSec -IntervalMs $IntervalMs
        }
    }
}

function Get-NexusBackupApiVersion {
    <#
    .SYNOPSIS
    Shows the appliance's API version and whether this module was generated for it.
    .EXAMPLE
    Get-NexusBackupApiVersion
    #>
    [CmdletBinding()]
    param([PSTypeName('NexusBackup.Connection')] [object] $Connection)
    $doc = Invoke-NexusBackupApi getOpenApi -Connection $Connection
    $v = [string]$doc.info.version
    [pscustomobject]@{
        PSTypeName       = 'NexusBackup.ApiVersion'
        ApplianceVersion = $v
        ModuleApiVersion = $script:NexusBackupApiVersion
        Compatible       = $v -eq $script:NexusBackupApiVersion
    }
}
