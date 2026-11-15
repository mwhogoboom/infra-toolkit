#Requires -Version 5.1
# Needs the ActiveDirectory module (RSAT). It is imported at run time rather than with
# #Requires so the pure functions can be unit tested on machines without RSAT.
<#
.SYNOPSIS
    Read-only Active Directory hygiene audit: stale accounts, risky account flags, privileged
    group membership, orphaned adminCount, delegation, and krbtgt password age.

.DESCRIPTION
    Covers the findings that drive most of a PingCastle score and that are easy to lose track
    of between full assessments. Everything here is read-only; the script never changes AD.

    Produces an HTML summary plus one CSV per finding so each list can be worked as a ticket.

    Checks:
      - Enabled users and computers with no logon in -StaleDays (uses lastLogonTimestamp,
        which replicates, so one DC is enough)
      - Enabled users with PasswordNeverExpires, PasswordNotRequired, reversible encryption,
        or Kerberos pre-authentication disabled
      - Recursive membership of the built-in privileged groups
      - Accounts with adminCount=1 that are no longer in any protected group (orphans keep
        the AdminSDHolder ACL and break delegation of permissions)
      - Non-DC computers and users trusted for unconstrained delegation
      - krbtgt password age

.PARAMETER StaleDays
    Days without a logon before an enabled account is reported as stale. Default 90.

.PARAMETER KrbtgtMaxAgeDays
    krbtgt password age that triggers a finding. Default 180.

.PARAMETER OutputFolder
    Folder for the HTML report and CSVs. Created if missing. Default .\ADHygiene-<date>.

.PARAMETER Server
    Optional domain controller to query.

.EXAMPLE
    .\Get-ADHygieneReport.ps1 -StaleDays 120 -OutputFolder C:\Reports\AD
#>
[CmdletBinding()]
param(
    [ValidateRange(30, 3650)][int]$StaleDays = 90,
    [ValidateRange(30, 3650)][int]$KrbtgtMaxAgeDays = 180,
    [string]$OutputFolder = (Join-Path (Get-Location) "ADHygiene-$(Get-Date -Format yyyyMMdd)"),
    [string]$Server
)

$script:PrivilegedGroups = @(
    'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
    'Account Operators', 'Backup Operators', 'Server Operators', 'Print Operators',
    'DnsAdmins', 'Group Policy Creator Owners'
)

function Test-IsStale {
    <#
        An account is stale if its last logon is older than the threshold. An account that has
        never logged on counts as stale only once it is older than the threshold, so brand-new
        accounts aren't flagged.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Nullable[datetime]]$LastLogon,
        [Parameter(Mandatory)][datetime]$WhenCreated,
        [Parameter(Mandatory)][int]$StaleDays,
        [datetime]$Now = (Get-Date)
    )
    $cutoff = $Now.AddDays(-$StaleDays)
    if ($null -eq $LastLogon) { return $WhenCreated -lt $cutoff }
    return $LastLogon -lt $cutoff
}

function ConvertFrom-LastLogonTimestamp {
    [CmdletBinding()]
    [OutputType([Nullable[datetime]])]
    param($Value)
    if ($null -eq $Value -or [int64]$Value -le 0) { return $null }
    return [datetime]::FromFileTime([int64]$Value)
}

function New-Finding {
    param([string]$Name, [ValidateSet('High', 'Medium', 'Low')][string]$Severity, [string]$Why, [object[]]$Items)
    [pscustomobject]@{ Name = $Name; Severity = $Severity; Why = $Why; Count = @($Items).Count; Items = @($Items) }
}

function ConvertTo-HtmlReport {
    param([object[]]$Findings, [string]$Domain, [datetime]$Generated)
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $rows = foreach ($f in $Findings) {
        $cls = if ($f.Count -eq 0) { 'ok' } else { $f.Severity.ToLower() }
        "<tr class='$cls'><td>$(& $enc $f.Severity)</td><td>$(& $enc $f.Name)</td><td class='n'>$($f.Count)</td><td>$(& $enc $f.Why)</td></tr>"
    }
    @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>AD hygiene: $(& $enc $Domain)</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:2rem;color:#16233A}
table{border-collapse:collapse;width:100%}th,td{padding:.5rem .75rem;border-bottom:1px solid #D5DEE8;text-align:left;vertical-align:top}
th{background:#16233A;color:#fff}.n{text-align:right;font-variant-numeric:tabular-nums}
tr.high td:first-child{color:#B42318;font-weight:700}tr.medium td:first-child{color:#B54708;font-weight:700}
tr.low td:first-child{color:#475467}tr.ok{color:#667085}
</style></head><body>
<h1>Active Directory hygiene report</h1>
<p>Domain: <strong>$(& $enc $Domain)</strong> &middot; Generated $($Generated.ToString('yyyy-MM-dd HH:mm'))</p>
<table><thead><tr><th>Severity</th><th>Finding</th><th class="n">Count</th><th>Why it matters</th></tr></thead>
<tbody>
$($rows -join "`n")
</tbody></table>
<p>Each finding with a count above zero has a matching CSV in this folder.</p>
</body></html>
"@
}

function Invoke-ADHygieneReport {
    Import-Module ActiveDirectory -ErrorAction Stop
    $ad = @{}
    if ($Server) { $ad.Server = $Server }

    $now = Get-Date
    $domain = Get-ADDomain @ad
    $dcNames = @(Get-ADDomainController -Filter * @ad | Select-Object -ExpandProperty Name)

    Write-Verbose 'Reading users and computers'
    $userProps = 'lastLogonTimestamp', 'whenCreated', 'PasswordNeverExpires', 'PasswordNotRequired',
                 'AllowReversiblePasswordEncryption', 'DoesNotRequirePreAuth', 'TrustedForDelegation',
                 'adminCount', 'PasswordLastSet', 'Description'
    $users = @(Get-ADUser -Filter 'Enabled -eq $true' -Properties $userProps @ad)
    $computers = @(Get-ADComputer -Filter 'Enabled -eq $true' -Properties lastLogonTimestamp, whenCreated, TrustedForDelegation, OperatingSystem @ad)

    $userView = { $_ | Select-Object SamAccountName, Name, @{n = 'LastLogon'; e = { ConvertFrom-LastLogonTimestamp $_.lastLogonTimestamp } }, whenCreated, PasswordLastSet, Description }

    $findings = [System.Collections.Generic.List[object]]::new()

    $staleUsers = $users | Where-Object { Test-IsStale -LastLogon (ConvertFrom-LastLogonTimestamp $_.lastLogonTimestamp) -WhenCreated $_.whenCreated -StaleDays $StaleDays -Now $now } | ForEach-Object $userView
    $findings.Add((New-Finding "Stale enabled users (no logon in $StaleDays days)" Medium 'Unused enabled accounts are easy targets for password spraying and are rarely monitored.' $staleUsers))

    $staleComputers = $computers | Where-Object { Test-IsStale -LastLogon (ConvertFrom-LastLogonTimestamp $_.lastLogonTimestamp) -WhenCreated $_.whenCreated -StaleDays $StaleDays -Now $now } |
        Select-Object Name, OperatingSystem, @{n = 'LastLogon'; e = { ConvertFrom-LastLogonTimestamp $_.lastLogonTimestamp } }, whenCreated
    $findings.Add((New-Finding "Stale enabled computers (no logon in $StaleDays days)" Low 'Stale computer accounts clutter inventory and patch reporting and can be reused by an attacker.' $staleComputers))

    $findings.Add((New-Finding 'Password never expires' Medium 'Long-lived passwords on enabled accounts, often service accounts that should be gMSAs.' ($users | Where-Object PasswordNeverExpires | ForEach-Object $userView)))
    $findings.Add((New-Finding 'Password not required' High 'The account can have an empty password.' ($users | Where-Object PasswordNotRequired | ForEach-Object $userView)))
    $findings.Add((New-Finding 'Reversible password encryption' High 'The password is stored in a recoverable form.' ($users | Where-Object AllowReversiblePasswordEncryption | ForEach-Object $userView)))
    $findings.Add((New-Finding 'Kerberos pre-authentication disabled' High 'Allows AS-REP roasting: anyone can request a hash to crack offline.' ($users | Where-Object DoesNotRequirePreAuth | ForEach-Object $userView)))

    Write-Verbose 'Expanding privileged groups'
    $privileged = foreach ($group in $script:PrivilegedGroups) {
        try {
            Get-ADGroupMember -Identity $group -Recursive @ad -ErrorAction Stop |
                Select-Object @{n = 'Group'; e = { $group } }, SamAccountName, Name, objectClass
        }
        catch { Write-Verbose "Skipping group '$group': $($_.Exception.Message)" }
    }
    $findings.Add((New-Finding 'Privileged group members' Medium 'Every member here should be a named, justified admin account. Review against your approved list.' $privileged))

    $privilegedNames = @($privileged | Select-Object -ExpandProperty SamAccountName -Unique)
    $orphans = $users | Where-Object { $_.adminCount -eq 1 -and $_.SamAccountName -notin $privilegedNames -and $_.SamAccountName -ne 'krbtgt' } | ForEach-Object $userView
    $findings.Add((New-Finding 'Orphaned adminCount=1' Low 'Former admins keep the AdminSDHolder ACL, which blocks normal permission inheritance.' $orphans))

    $delegation = @(
        $computers | Where-Object { $_.TrustedForDelegation -and $_.Name -notin $dcNames } | Select-Object @{n = 'Type'; e = { 'Computer' } }, Name
        $users | Where-Object TrustedForDelegation | Select-Object @{n = 'Type'; e = { 'User' } }, Name
    )
    $findings.Add((New-Finding 'Unconstrained delegation (non-DC)' High 'Any account that authenticates to these hosts leaves a reusable TGT behind.' $delegation))

    $krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet @ad
    $krbAge = [math]::Round(($now - $krbtgt.PasswordLastSet).TotalDays)
    $krbItems = if ($krbAge -gt $KrbtgtMaxAgeDays) { @([pscustomobject]@{ Account = 'krbtgt'; PasswordLastSet = $krbtgt.PasswordLastSet; AgeDays = $krbAge }) } else { @() }
    $findings.Add((New-Finding "krbtgt password older than $KrbtgtMaxAgeDays days" Medium "Current age: $krbAge days. Rotate it twice, with replication in between, to invalidate forged tickets." $krbItems))

    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
    foreach ($f in $findings | Where-Object Count -gt 0) {
        $file = ($f.Name -replace '[^A-Za-z0-9]+', '-').Trim('-') + '.csv'
        $f.Items | Export-Csv -Path (Join-Path $OutputFolder $file) -NoTypeInformation -Encoding UTF8
    }
    $order = @{ High = 0; Medium = 1; Low = 2 }
    $sorted = $findings | Sort-Object @{ e = { $order[$_.Severity] } }, @{ e = 'Count'; Descending = $true }
    ConvertTo-HtmlReport -Findings $sorted -Domain $domain.DNSRoot -Generated $now |
        Set-Content -Path (Join-Path $OutputFolder 'index.html') -Encoding UTF8

    Write-Host "Report written to $OutputFolder"
    $sorted | Select-Object Severity, Name, Count
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-ADHygieneReport }
