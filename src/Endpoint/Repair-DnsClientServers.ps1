#Requires -Version 5.1
<#
.SYNOPSIS
    Finds network adapters whose DNS servers have been overwritten (for example, left pointing
    at 127.0.0.1 by a web-filtering or VPN agent that crashed or was uninstalled) and puts them
    back to DHCP or to your approved servers.

.DESCRIPTION
    Some endpoint agents redirect DNS by rewriting the adapter's DNS server list to a local
    proxy. If the agent stops, updates badly, or is removed, the machine is left resolving
    against a proxy that isn't there, and the user just sees "no internet."

    This script checks every connected adapter's IPv4 DNS servers against a blocked list
    (default 127.0.0.1 and the 0.0.0.0 placeholder) and, optionally, an approved list:
      - DHCP adapters are reset so DHCP supplies DNS again.
      - Static adapters are set to -ApprovedServer (if you provide it), otherwise only reported.
    It then flushes the resolver cache and logs what it did.

    -RegisterTask installs it as an hourly scheduled task running as SYSTEM, which is how it is
    meant to be deployed (by GPO or your RMM) until the agent issue is fixed for good.

    Supports -WhatIf. Run elevated.

.PARAMETER BlockedServer
    DNS server addresses that should never be configured. Default 127.0.0.1 and 0.0.0.0.

.PARAMETER ApprovedServer
    Optional list of the DNS servers that are allowed. If given, any other server is treated as
    wrong, and static adapters are set to this list.

.PARAMETER LogPath
    Log file. Default C:\ProgramData\DnsRepair\DnsRepair.log

.PARAMETER RegisterTask
    Copy this script to C:\ProgramData\DnsRepair and register an hourly SYSTEM scheduled task
    that runs it with the same -BlockedServer / -ApprovedServer values.

.EXAMPLE
    .\Repair-DnsClientServers.ps1 -WhatIf

.EXAMPLE
    .\Repair-DnsClientServers.ps1 -ApprovedServer 10.0.0.10, 10.0.0.11 -RegisterTask
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string[]]$BlockedServer = @('127.0.0.1', '0.0.0.0'),
    [string[]]$ApprovedServer = @(),
    [string]$LogPath = 'C:\ProgramData\DnsRepair\DnsRepair.log',
    [switch]$RegisterTask
)

function Test-DnsServerList {
    <#
        Returns $null when the list is healthy, otherwise a short reason. Pure, unit tested.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string[]]$Configured,
        [string[]]$Blocked = @('127.0.0.1', '0.0.0.0'),
        [string[]]$Approved = @()
    )
    $Configured = @($Configured | Where-Object { $_ })
    $bad = @($Configured | Where-Object { $_ -in $Blocked })
    if ($bad.Count -gt 0) { return "blocked server(s): $($bad -join ', ')" }
    if ($Approved.Count -gt 0) {
        $unknown = @($Configured | Where-Object { $_ -notin $Approved })
        if ($unknown.Count -gt 0) { return "unapproved server(s): $($unknown -join ', ')" }
    }
    return $null
}

function Write-RepairLog {
    param([string]$Message)
    $line = '{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $Message
    Write-Verbose $line
    if (-not $WhatIfPreference) {
        $dir = Split-Path $LogPath -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Add-Content -Path $LogPath -Value $line -Encoding UTF8
    }
}

function Register-RepairTask {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $installDir = 'C:\ProgramData\DnsRepair'
    $target = Join-Path $installDir 'Repair-DnsClientServers.ps1'
    if ($PSCmdlet.ShouldProcess('Scheduled task DnsClientRepair', 'Register hourly SYSTEM task')) {
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
        Copy-Item -Path $PSCommandPath -Destination $target -Force

        $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$target`" -BlockedServer $($BlockedServer -join ',')"
        if ($ApprovedServer.Count -gt 0) { $argList += " -ApprovedServer $($ApprovedServer -join ',')" }

        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argList
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Hours 1)
        $boot = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -StartWhenAvailable -MultipleInstances IgnoreNew
        Register-ScheduledTask -TaskName 'DnsClientRepair' -TaskPath '\IT\' -Action $action -Trigger $trigger, $boot `
            -Principal $principal -Settings $settings -Force | Out-Null
        Write-Host "Registered \IT\DnsClientRepair (hourly and at startup), running $target"
    }
}

function Invoke-DnsClientRepair {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin -and -not $WhatIfPreference) { throw 'Run this elevated (or as SYSTEM).' }

    if ($RegisterTask) { Register-RepairTask; return }

    $changed = 0
    $adapters = Get-NetAdapter | Where-Object Status -eq 'Up'
    $results = foreach ($nic in $adapters) {
        $servers = @((Get-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4).ServerAddresses)
        $problem = Test-DnsServerList -Configured $servers -Blocked $BlockedServer -Approved $ApprovedServer
        $dhcp = (Get-NetIPInterface -InterfaceIndex $nic.ifIndex -AddressFamily IPv4).Dhcp -eq 'Enabled'
        $action = 'None'

        if ($problem) {
            if ($dhcp) {
                if ($PSCmdlet.ShouldProcess($nic.Name, 'Reset DNS servers to DHCP')) {
                    Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ResetServerAddresses
                    $action = 'Reset to DHCP'; $changed++
                }
                else { $action = 'Would reset to DHCP' }
            }
            elseif ($ApprovedServer.Count -gt 0) {
                if ($PSCmdlet.ShouldProcess($nic.Name, "Set DNS servers to $($ApprovedServer -join ', ')")) {
                    Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses $ApprovedServer
                    $action = 'Set to approved servers'; $changed++
                }
                else { $action = 'Would set to approved servers' }
            }
            else { $action = 'Static adapter, report only (no -ApprovedServer given)' }
            Write-RepairLog "$($nic.Name): $problem. Action: $action"
        }

        [pscustomobject]@{
            Adapter = $nic.Name; Dhcp = $dhcp; DnsServers = $servers -join ', '
            Problem = $problem; Action = $action
        }
    }

    if ($changed -gt 0) {
        Clear-DnsClientCache
        Write-RepairLog "Repaired $changed adapter(s); resolver cache flushed."
    }
    $results
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-DnsClientRepair }
