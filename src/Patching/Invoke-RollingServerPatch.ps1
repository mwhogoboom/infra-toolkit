#Requires -Version 5.1
<#
.SYNOPSIS
    Patches Windows servers one at a time: install updates, reboot if needed, verify the server
    and its critical services come back, then move to the next.

.DESCRIPTION
    Designed for an unattended overnight window run from a scheduled task on a management
    server. Servers are processed in the order given, so list dependencies first (for example
    a SQL server before the app servers that use it) or last, whichever your recovery plan
    prefers.

    For each server:
      1. Pre-check: WinRM reachable.
      2. Install: runs Install-WindowsUpdate from the PSWindowsUpdate module on the target
         through Invoke-WUJob (Windows Update can't be driven directly over a remote session,
         so it runs as a scheduled task as SYSTEM) and waits for it to finish.
      3. Reboot: only if the server reports a pending reboot. Waits for WinRM to come back.
      4. Verify: confirms each -CriticalService is Running, starting it once if it isn't.

    Every step is recorded, a CSV report is written, and a Teams summary can be posted.
    Supports -WhatIf.

    Requirements: PSWindowsUpdate installed on each target server, and admin rights on the
    targets for the account running this script.

.PARAMETER ComputerName
    Servers to patch, in order.

.PARAMETER CriticalService
    Service names that must be Running after the reboot (applies to every server where the
    service exists).

.PARAMETER InstallTimeoutMinutes
    How long to wait for the update job on one server. Default 120.

.PARAMETER RebootTimeoutMinutes
    How long to wait for a server to come back after a reboot. Default 20.

.PARAMETER StopOnFailure
    Stop the run at the first server that fails, instead of continuing. Recommended when
    later servers depend on earlier ones.

.PARAMETER ReportPath
    CSV report path. Default .\PatchRun-<timestamp>.csv

.PARAMETER WebhookUrl
    Optional Teams Workflows webhook for the run summary.

.EXAMPLE
    .\Invoke-RollingServerPatch.ps1 -ComputerName SQL01, APP01, APP02 -CriticalService MSSQLSERVER, W3SVC -WhatIf

.EXAMPLE
    .\Invoke-RollingServerPatch.ps1 -ComputerName (Get-Content .\patch-group-a.txt) -StopOnFailure `
        -WebhookUrl $env:TEAMS_WEBHOOK
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string[]]$ComputerName,
    [string[]]$CriticalService = @(),
    [ValidateRange(5, 600)][int]$InstallTimeoutMinutes = 120,
    [ValidateRange(5, 120)][int]$RebootTimeoutMinutes = 20,
    [switch]$StopOnFailure,
    [string]$ReportPath = (Join-Path (Get-Location) "PatchRun-$(Get-Date -Format yyyyMMdd-HHmm).csv"),
    [string]$WebhookUrl
)

function Get-PatchRunSummary {
    <# Pure roll-up of per-server results, unit tested. #>
    [CmdletBinding()]
    param([object[]]$Results)
    $total = @($Results).Count
    $ok = @($Results | Where-Object Result -eq 'Success').Count
    $failed = @($Results | Where-Object Result -eq 'Failed').Count
    $skipped = @($Results | Where-Object Result -eq 'Skipped').Count
    [pscustomobject]@{
        Total             = $total
        Succeeded         = $ok
        Failed            = $failed
        Skipped           = $skipped
        UpdatesInstalled  = [int](($Results | Measure-Object -Property UpdatesInstalled -Sum).Sum)
        Rebooted          = @($Results | Where-Object Rebooted).Count
        CompliancePercent = if ($total -gt 0) { [math]::Round(($ok / $total) * 100, 1) } else { 0 }
    }
}

function Get-InstalledUpdateCount {
    <# Counts installed-update lines in PSWindowsUpdate's Install-WindowsUpdate output. #>
    [CmdletBinding()]
    [OutputType([int])]
    param([string[]]$LogLine)
    @($LogLine | Where-Object { $_ -match '\bInstalled\b' -and $_ -match 'KB\d{6,8}' }).Count
}

function Wait-ForWinRM {
    param([string]$Server, [int]$TimeoutMinutes)
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    Start-Sleep -Seconds 60   # give the box time to actually go down
    while ((Get-Date) -lt $deadline) {
        try { Test-WSMan -ComputerName $Server -ErrorAction Stop | Out-Null; return $true } catch { Start-Sleep -Seconds 15 }
    }
    return $false
}

function Invoke-PatchOneServer {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Server)

    $r = [ordered]@{
        Server = $Server; Result = 'Failed'; UpdatesInstalled = 0; Rebooted = $false
        Started = Get-Date; Finished = $null; Detail = ''
    }
    $log = 'C:\Windows\Temp\RollingPatch.log'

    try {
        Test-WSMan -ComputerName $Server -ErrorAction Stop | Out-Null

        if (-not $PSCmdlet.ShouldProcess($Server, 'Install updates and reboot if required')) {
            $r.Result = 'Skipped'; $r.Detail = 'WhatIf'
            return [pscustomobject]$r
        }

        # 1) Install as SYSTEM through a scheduled task created by Invoke-WUJob.
        $job = "Import-Module PSWindowsUpdate; Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -Verbose *>&1 | Out-File -FilePath '$log' -Encoding utf8"
        Invoke-WUJob -ComputerName $Server -Script ([scriptblock]::Create($job)) -RunNow -Confirm:$false -ErrorAction Stop | Out-Null

        $deadline = (Get-Date).AddMinutes($InstallTimeoutMinutes)
        do {
            Start-Sleep -Seconds 30
            $state = Invoke-Command -ComputerName $Server -ScriptBlock { (Get-ScheduledTask -TaskName PSWindowsUpdate -ErrorAction SilentlyContinue).State }
        } while ($state -eq 'Running' -and (Get-Date) -lt $deadline)
        if ($state -eq 'Running') { throw "Update job still running after $InstallTimeoutMinutes minutes." }

        $lines = Invoke-Command -ComputerName $Server -ScriptBlock { param($p) if (Test-Path $p) { Get-Content $p } } -ArgumentList $log
        $r.UpdatesInstalled = Get-InstalledUpdateCount -LogLine $lines

        # 2) Reboot only when Windows says it needs one.
        $pending = Invoke-Command -ComputerName $Server -ScriptBlock {
            (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
            (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
        }
        if ($pending) {
            Restart-Computer -ComputerName $Server -Force -ErrorAction Stop
            if (-not (Wait-ForWinRM -Server $Server -TimeoutMinutes $RebootTimeoutMinutes)) {
                throw "Did not come back within $RebootTimeoutMinutes minutes of reboot."
            }
            $r.Rebooted = $true
        }

        # 3) Verify critical services, one start attempt each.
        if ($CriticalService.Count -gt 0) {
            $down = Invoke-Command -ComputerName $Server -ArgumentList (, $CriticalService) -ScriptBlock {
                param($names)
                foreach ($n in $names) {
                    $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
                    if ($svc -and $svc.Status -ne 'Running') {
                        try { Start-Service $n -ErrorAction Stop; Start-Sleep -Seconds 10; $svc.Refresh() } catch { Write-Verbose "Could not start ${n}: $($_.Exception.Message)" }
                        if ($svc.Status -ne 'Running') { $n }
                    }
                }
            }
            if ($down) { throw "Services not running after patching: $($down -join ', ')" }
        }

        $r.Result = 'Success'
        $r.Detail = "$($r.UpdatesInstalled) update(s)" + $(if ($r.Rebooted) { ', rebooted' } else { ', no reboot needed' })
    }
    catch {
        $r.Result = 'Failed'
        $r.Detail = $_.Exception.Message
    }
    finally {
        $r.Finished = Get-Date
    }
    [pscustomobject]$r
}

function Invoke-RollingServerPatch {
    if (-not $ComputerName) { throw 'Specify at least one server with -ComputerName.' }
    if (-not $WhatIfPreference -and -not (Get-Command Invoke-WUJob -ErrorAction SilentlyContinue)) {
        throw 'PSWindowsUpdate is required on this machine (Install-Module PSWindowsUpdate).'
    }

    $results = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $ComputerName.Count; $i++) {
        $server = $ComputerName[$i]
        Write-Verbose "Patching $server"
        $res = Invoke-PatchOneServer -Server $server
        $results.Add($res)
        Write-Host ('{0,-20} {1,-8} {2}' -f $res.Server, $res.Result, $res.Detail)

        if ($res.Result -eq 'Failed' -and $StopOnFailure) {
            for ($j = $i + 1; $j -lt $ComputerName.Count; $j++) {
                $s = $ComputerName[$j]
                $results.Add([pscustomobject]@{ Server = $s; Result = 'Skipped'; UpdatesInstalled = 0; Rebooted = $false; Started = $null; Finished = $null; Detail = "Stopped after $server failed" })
            }
            break
        }
    }

    if (-not $WhatIfPreference) { $results | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8 }
    $summary = Get-PatchRunSummary -Results $results

    if ($WebhookUrl -and -not $WhatIfPreference) {
        . "$PSScriptRoot/../Common/Send-TeamsAlert.ps1"
        $facts = [ordered]@{}
        foreach ($x in $results) { $facts[$x.Server] = "$($x.Result): $($x.Detail)" }
        $severity = if ($summary.Failed -gt 0) { 'Critical' } elseif ($summary.Skipped -gt 0) { 'Warning' } else { 'Info' }
        Send-TeamsAlert -WebhookUrl $WebhookUrl -Severity $severity -Title 'Patch run complete' `
            -Summary "$($summary.Succeeded) of $($summary.Total) servers patched ($($summary.CompliancePercent)%), $($summary.UpdatesInstalled) updates, $($summary.Rebooted) reboots." `
            -Facts $facts
    }

    $summary
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-RollingServerPatch }
