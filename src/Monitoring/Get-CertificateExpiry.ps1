#Requires -Version 5.1
<#
.SYNOPSIS
    Reports TLS certificates that are expiring soon, from live endpoints and the local machine store.

.DESCRIPTION
    Connects to each host:port you list, pulls the certificate the server actually presents
    (so it catches a renewed cert that was never bound), and classifies it as OK, Warning,
    Critical, or Expired based on days remaining. Optionally also scans LocalMachine\My.

    Results are returned as objects, can be written to JSON for a dashboard, and anything at
    Warning or worse can be posted to Teams.

.PARAMETER Endpoint
    One or more endpoints as host or host:port. Port defaults to 443.

.PARAMETER WarningDays
    Days remaining at or below which a certificate is Warning. Default 30.

.PARAMETER CriticalDays
    Days remaining at or below which a certificate is Critical. Default 14.

.PARAMETER IncludeLocalStore
    Also check certificates in Cert:\LocalMachine\My that have a private key.

.PARAMETER OutputPath
    Optional path to write results as JSON (for a NOC dashboard tile).

.PARAMETER WebhookUrl
    Optional Teams Workflows webhook. One alert is sent listing every non-OK certificate.

.EXAMPLE
    .\Get-CertificateExpiry.ps1 -Endpoint 'portal.example.com','vpn.example.com:8443' -IncludeLocalStore

.EXAMPLE
    .\Get-CertificateExpiry.ps1 -Endpoint (Get-Content .\endpoints.txt) -OutputPath C:\Monitoring\certs.json `
        -WebhookUrl $env:TEAMS_WEBHOOK
#>
[CmdletBinding()]
param(
    [string[]]$Endpoint,
    [ValidateRange(1, 365)][int]$WarningDays = 30,
    [ValidateRange(0, 365)][int]$CriticalDays = 14,
    [switch]$IncludeLocalStore,
    [string]$OutputPath,
    [string]$WebhookUrl
)

function Get-ExpiryStatus {
    <# Pure classification so it can be unit tested. #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][double]$DaysRemaining,
        [int]$WarningDays = 30,
        [int]$CriticalDays = 14
    )
    if ($DaysRemaining -lt 0) { return 'Expired' }
    if ($DaysRemaining -le $CriticalDays) { return 'Critical' }
    if ($DaysRemaining -le $WarningDays) { return 'Warning' }
    return 'OK'
}

function ConvertTo-EndpointTarget {
    <# Splits "host" or "host:port" into a host and port. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Value)
    $parts = $Value.Trim() -split ':'
    $port = 443
    if ($parts.Count -ge 2 -and $parts[-1] -match '^\d+$') { $port = [int]$parts[-1] }
    [pscustomobject]@{ Host = $parts[0]; Port = $port }
}

function Get-RemoteCertificate {
    <# Returns the certificate a server presents, without trusting or validating it. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [int]$Port = 443,
        [int]$TimeoutMs = 5000
    )
    $tcp = [System.Net.Sockets.TcpClient]::new()
    try {
        $connect = $tcp.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $connect.AsyncWaitHandle.WaitOne($TimeoutMs)) { throw "Timed out connecting to ${ComputerName}:$Port" }
        $tcp.EndConnect($connect)

        # Accept any certificate: the goal is to read it, not to trust it.
        $callback = [System.Net.Security.RemoteCertificateValidationCallback] { param($s, $c, $ch, $e) $true }
        $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false, $callback)
        try {
            $ssl.AuthenticateAsClient($ComputerName)
            return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
        }
        finally { $ssl.Dispose() }
    }
    finally { $tcp.Dispose() }
}

function New-CertResult {
    param($Source, $Target, $Certificate, $Now, $WarningDays, $CriticalDays, $ErrorMessage)
    if ($Certificate) {
        $days = [math]::Round(($Certificate.NotAfter - $Now).TotalDays, 1)
        [pscustomobject]@{
            Source        = $Source
            Target        = $Target
            Subject       = $Certificate.Subject
            Issuer        = $Certificate.Issuer
            NotAfter      = $Certificate.NotAfter
            DaysRemaining = $days
            Thumbprint    = $Certificate.Thumbprint
            Status        = Get-ExpiryStatus -DaysRemaining $days -WarningDays $WarningDays -CriticalDays $CriticalDays
            Error         = $null
        }
    }
    else {
        [pscustomobject]@{
            Source = $Source; Target = $Target; Subject = $null; Issuer = $null; NotAfter = $null
            DaysRemaining = $null; Thumbprint = $null; Status = 'Unreachable'; Error = $ErrorMessage
        }
    }
}

function Invoke-CertificateExpiryCheck {
    if (-not $Endpoint -and -not $IncludeLocalStore) {
        throw 'Specify -Endpoint, -IncludeLocalStore, or both.'
    }
    if ($CriticalDays -gt $WarningDays) { throw '-CriticalDays must be less than or equal to -WarningDays.' }

    $now = Get-Date
    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($item in $Endpoint) {
        $t = ConvertTo-EndpointTarget -Value $item
        $label = "$($t.Host):$($t.Port)"
        try {
            $cert = Get-RemoteCertificate -ComputerName $t.Host -Port $t.Port
            $results.Add((New-CertResult 'Endpoint' $label $cert $now $WarningDays $CriticalDays $null))
        }
        catch {
            $results.Add((New-CertResult 'Endpoint' $label $null $now $WarningDays $CriticalDays $_.Exception.Message))
        }
    }

    if ($IncludeLocalStore) {
        Get-ChildItem Cert:\LocalMachine\My | Where-Object HasPrivateKey | ForEach-Object {
            $results.Add((New-CertResult 'LocalStore' $env:COMPUTERNAME $_ $now $WarningDays $CriticalDays $null))
        }
    }

    if ($OutputPath) {
        [pscustomobject]@{ GeneratedAt = $now; Results = $results } |
            ConvertTo-Json -Depth 4 | Set-Content -Path $OutputPath -Encoding UTF8
    }

    $problems = @($results | Where-Object Status -ne 'OK')
    if ($WebhookUrl -and $problems.Count -gt 0) {
        . "$PSScriptRoot/../Common/Send-TeamsAlert.ps1"
        $severity = if ($problems.Status -contains 'Expired' -or $problems.Status -contains 'Critical') { 'Critical' } else { 'Warning' }
        $facts = [ordered]@{}
        foreach ($p in $problems) {
            $detail = if ($p.Status -eq 'Unreachable') { "Unreachable: $($p.Error)" } else { "$($p.Status), $($p.DaysRemaining) days ($($p.Subject))" }
            $facts["$($p.Source) $($p.Target)"] = $detail
        }
        Send-TeamsAlert -WebhookUrl $WebhookUrl -Severity $severity -Title 'Certificates need attention' `
            -Summary "$($problems.Count) certificate check(s) are not OK." -Facts $facts
    }

    $results | Sort-Object { if ($null -eq $_.DaysRemaining) { -1 } else { $_.DaysRemaining } }
}

# Run only when executed, not when dot-sourced (lets the tests load the functions).
if ($MyInvocation.InvocationName -ne '.') { Invoke-CertificateExpiryCheck }
