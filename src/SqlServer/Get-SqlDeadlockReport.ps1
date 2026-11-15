#Requires -Version 5.1
<#
.SYNOPSIS
    Pulls deadlocks from SQL Server's built-in system_health session and turns the deadlock
    XML into a readable table: who was the victim, which apps and logins were involved, which
    objects and indexes they fought over, and the statements they were running.

.DESCRIPTION
    Every SQL Server instance records deadlocks in the system_health Extended Events session
    by default, so there is nothing to enable first. The raw XML is hard to read, though, so
    recurring deadlocks (for example, report refreshes colliding with an import job) often go
    unnoticed until users complain.

    This script reads the system_health .xel files, parses each xml_deadlock_report, and
    returns one row per process involved. Use -Summary to group by the objects involved and see
    which deadlock patterns repeat.

    Read-only. Requires the SqlServer module (Invoke-Sqlcmd) and VIEW SERVER STATE.

.PARAMETER SqlInstance
    Instance to query, for example SQL01 or SQL01\REPORTING.

.PARAMETER Since
    Only return deadlocks after this time. Default: last 7 days.

.PARAMETER Summary
    Group results by the set of objects involved, with counts and first/last seen.

.PARAMETER OutputPath
    Optional CSV path for the detailed rows.

.EXAMPLE
    .\Get-SqlDeadlockReport.ps1 -SqlInstance SQL01 | Format-Table Timestamp, IsVictim, ClientApp, Objects

.EXAMPLE
    .\Get-SqlDeadlockReport.ps1 -SqlInstance SQL01 -Since (Get-Date).AddDays(-30) -Summary
#>
[CmdletBinding()]
param(
    [string]$SqlInstance,
    [datetime]$Since = (Get-Date).AddDays(-7),
    [switch]$Summary,
    [string]$OutputPath
)

$script:DeadlockQuery = @'
SELECT CAST(event_data AS nvarchar(max)) AS event_xml
FROM sys.fn_xe_file_target_read_file('system_health*.xel', NULL, NULL, NULL)
WHERE object_name = 'xml_deadlock_report';
'@

function ConvertFrom-DeadlockEventXml {
    <#
        Parses one xml_deadlock_report event into one object per process. Pure function: takes
        the XML text, touches nothing else, so it is unit tested against a sample event.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][string]$EventXml)
    process {
        [xml]$doc = $EventXml
        $evt = $doc.event
        $timestamp = [datetime]::Parse($evt.timestamp, [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal).ToLocalTime()

        $deadlock = $evt.SelectSingleNode("data[@name='xml_report']/value/deadlock")
        if (-not $deadlock) { return }

        $victims = @($deadlock.SelectNodes('victim-list/victimProcess') | ForEach-Object { $_.id })

        # Resource list: map each owner/waiter process id to the objects and indexes it touched.
        $objectsByProcess = @{}
        foreach ($res in $deadlock.SelectNodes('resource-list/*')) {
            $name = $res.objectname
            if ($res.indexname) { $name = "$name ($($res.indexname))" }
            if (-not $name) { $name = "$($res.LocalName) $($res.dbid):$($res.objid)" }
            foreach ($p in $res.SelectNodes('owner-list/owner | waiter-list/waiter')) {
                if (-not $objectsByProcess.ContainsKey($p.id)) { $objectsByProcess[$p.id] = [System.Collections.Generic.List[string]]::new() }
                if (-not $objectsByProcess[$p.id].Contains($name)) { $objectsByProcess[$p.id].Add($name) }
            }
        }
        $allObjects = ($objectsByProcess.Values | ForEach-Object { $_ } | Sort-Object -Unique) -join '; '

        foreach ($proc in $deadlock.SelectNodes('process-list/process')) {
            $sql = ($proc.inputbuf -replace '\s+', ' ').Trim()
            [pscustomobject]@{
                Timestamp      = $timestamp
                IsVictim       = $victims -contains $proc.id
                Spid           = $proc.spid
                LoginName      = $proc.loginname
                HostName       = $proc.hostname
                ClientApp      = $proc.clientapp
                Isolation      = $proc.isolationlevel
                LockMode       = $proc.lockMode
                WaitResource   = $proc.waitresource
                Objects        = if ($objectsByProcess.ContainsKey($proc.id)) { $objectsByProcess[$proc.id] -join '; ' } else { '' }
                DeadlockObjects = $allObjects
                InputBuffer    = $sql
            }
        }
    }
}

function Get-DeadlockSummary {
    <# Groups detail rows into deadlock patterns. Pure, unit tested. #>
    [CmdletBinding()]
    param([object[]]$Rows)
    # One deadlock = one timestamp + object set; count distinct deadlocks, not processes.
    $events = $Rows | Group-Object { "$($_.Timestamp.ToString('o'))|$($_.DeadlockObjects)" }
    $events | ForEach-Object {
        $first = $_.Group[0]
        [pscustomobject]@{
            Objects    = $first.DeadlockObjects
            Timestamp  = $first.Timestamp
            Apps       = ($_.Group.ClientApp | Sort-Object -Unique) -join '; '
            VictimApp  = ($_.Group | Where-Object IsVictim | Select-Object -First 1).ClientApp
        }
    } | Group-Object Objects | ForEach-Object {
        [pscustomobject]@{
            Objects    = $_.Name
            Deadlocks  = $_.Count
            FirstSeen  = ($_.Group.Timestamp | Measure-Object -Minimum).Minimum
            LastSeen   = ($_.Group.Timestamp | Measure-Object -Maximum).Maximum
            Apps       = ($_.Group.Apps -split '; ' | Sort-Object -Unique) -join '; '
            UsualVictim = ($_.Group.VictimApp | Group-Object | Sort-Object Count -Descending | Select-Object -First 1).Name
        }
    } | Sort-Object Deadlocks -Descending
}

function Invoke-SqlDeadlockReport {
    if (-not $SqlInstance) { throw 'Specify -SqlInstance.' }
    Import-Module SqlServer -ErrorAction Stop

    $rows = Invoke-Sqlcmd -ServerInstance $SqlInstance -Database master -Query $script:DeadlockQuery `
        -MaxCharLength 2147483647 -QueryTimeout 300 -TrustServerCertificate -ErrorAction Stop

    $detail = @($rows | ForEach-Object { ConvertFrom-DeadlockEventXml -EventXml $_.event_xml } |
        Where-Object Timestamp -ge $Since | Sort-Object Timestamp)

    if ($OutputPath) { $detail | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }

    if ($detail.Count -eq 0) {
        Write-Host "No deadlocks recorded on $SqlInstance since $Since. (system_health keeps a rolling window, so very old events age out.)"
        return
    }

    if ($Summary) { Get-DeadlockSummary -Rows $detail } else { $detail }
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-SqlDeadlockReport }
