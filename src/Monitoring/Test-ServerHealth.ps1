#Requires -Version 5.1
<#
.SYNOPSIS
    Quick health sweep of Windows servers: reachability, uptime, disk space, stopped automatic
    services, and pending reboots.

.DESCRIPTION
    Built to run on a schedule from a monitoring server and feed a dashboard. Each server gets
    one CIM session (WinRM), and every check is folded into a single overall status so a
    dashboard tile only has to read one field.

    Stopped services are filtered against a list of automatic services that normally stop on
    their own (delayed start, trigger start), so the check doesn't cry wolf.

.PARAMETER ComputerName
    Servers to check. Defaults to the local machine.

.PARAMETER DiskWarningPercent
    Free space percentage at or below which a volume is Warning. Default 15.

.PARAMETER DiskCriticalPercent
    Free space percentage at or below which a volume is Critical. Default 8.

.PARAMETER IgnoreService
    Extra service names to ignore when looking for stopped automatic services.

.PARAMETER OutputPath
    Optional JSON output path for a dashboard.

.PARAMETER WebhookUrl
    Optional Teams Workflows webhook; one alert summarizing every server that isn't OK.

.EXAMPLE
    .\Test-ServerHealth.ps1 -ComputerName APP01, SQL01, FILE01 | Format-Table

.EXAMPLE
    .\Test-ServerHealth.ps1 -ComputerName (Get-Content .\servers.txt) -OutputPath C:\Monitoring\health.json `
        -WebhookUrl $env:TEAMS_WEBHOOK
#>
[CmdletBinding()]
param(
    [string[]]$ComputerName = $env:COMPUTERNAME,
    [ValidateRange(1, 99)][int]$DiskWarningPercent = 15,
    [ValidateRange(0, 99)][int]$DiskCriticalPercent = 8,
    [string[]]$IgnoreService = @(),
    [string]$OutputPath,
    [string]$WebhookUrl
)

# Automatic services that routinely sit stopped on a healthy server.
$script:DefaultIgnoredServices = @(
    'gupdate', 'gupdatem', 'edgeupdate', 'edgeupdatem', 'MapsBroker', 'RemoteRegistry', 'sppsvc',
    'wuauserv', 'TrustedInstaller', 'BITS', 'tiledatamodelsvc', 'CDPSvc', 'WbioSrvc', 'ShellHWDetection',
    'TieringEngineService', 'UsoSvc', 'InstallService', 'WaaSMedicSvc', 'clr_optimization_v4.0.30319_32',
    'clr_optimization_v4.0.30319_64', 'stisvc', 'DoSvc'
)

function Get-DiskStatus {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][double]$FreePercent,
        [int]$WarningPercent = 15,
        [int]$CriticalPercent = 8
    )
    if ($FreePercent -le $CriticalPercent) { return 'Critical' }
    if ($FreePercent -le $WarningPercent) { return 'Warning' }
    return 'OK'
}

function Get-OverallStatus {
    <# Worst status wins. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string[]]$Status)
    foreach ($level in 'Unreachable', 'Critical', 'Warning') {
        if ($Status -contains $level) { return $level }
    }
    return 'OK'
}

function Test-OneServer {
    param([string]$Server, [string[]]$Ignore)

    $result = [ordered]@{
        Server = $Server; Status = 'OK'; UptimeDays = $null; LastBoot = $null
        PendingReboot = $null; Disks = @(); StoppedServices = @(); Notes = @()
    }

    $session = $null
    try {
        $session = New-CimSession -ComputerName $Server -OperationTimeoutSec 30 -ErrorAction Stop

        $os = Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem -ErrorAction Stop
        $result.LastBoot = $os.LastBootUpTime
        $result.UptimeDays = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)

        $result.Disks = @(Get-CimInstance -CimSession $session -ClassName Win32_LogicalDisk -Filter 'DriveType=3' |
            Where-Object Size -gt 0 | ForEach-Object {
                $pct = [math]::Round(($_.FreeSpace / $_.Size) * 100, 1)
                [pscustomobject]@{
                    Drive       = $_.DeviceID
                    SizeGB      = [math]::Round($_.Size / 1GB, 1)
                    FreeGB      = [math]::Round($_.FreeSpace / 1GB, 1)
                    FreePercent = $pct
                    Status      = Get-DiskStatus -FreePercent $pct -WarningPercent $DiskWarningPercent -CriticalPercent $DiskCriticalPercent
                }
            })

        $result.StoppedServices = @(Get-CimInstance -CimSession $session -ClassName Win32_Service `
                -Filter "StartMode='Auto' AND State<>'Running'" |
            Where-Object { $_.Name -notin $Ignore } |
            Select-Object -ExpandProperty Name)

        # Pending reboot: Component Based Servicing, Windows Update, or pending file renames.
        $hklm = [uint32]2147483650
        $cbs = Invoke-CimMethod -CimSession $session -Namespace root\default -ClassName StdRegProv -MethodName EnumKey `
            -Arguments @{ hDefKey = $hklm; sSubKeyName = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing' }
        $wu = Invoke-CimMethod -CimSession $session -Namespace root\default -ClassName StdRegProv -MethodName EnumKey `
            -Arguments @{ hDefKey = $hklm; sSubKeyName = 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' }
        $pfro = Invoke-CimMethod -CimSession $session -Namespace root\default -ClassName StdRegProv -MethodName GetMultiStringValue `
            -Arguments @{ hDefKey = $hklm; sSubKeyName = 'SYSTEM\CurrentControlSet\Control\Session Manager'; sValueName = 'PendingFileRenameOperations' }
        $result.PendingReboot = ($cbs.sNames -contains 'RebootPending') -or
                                ($wu.sNames -contains 'RebootRequired') -or
                                [bool]$pfro.sValue

        $statuses = @($result.Disks.Status)
        if ($result.StoppedServices.Count -gt 0) {
            $statuses += 'Warning'
            $result.Notes += "Stopped automatic services: $($result.StoppedServices -join ', ')"
        }
        if ($result.PendingReboot) { $result.Notes += 'Reboot pending' }
        $result.Status = Get-OverallStatus -Status $statuses
    }
    catch {
        $result.Status = 'Unreachable'
        $result.Notes += $_.Exception.Message
    }
    finally {
        if ($session) { Remove-CimSession $session }
    }

    [pscustomobject]$result
}

function Invoke-ServerHealthCheck {
    if ($DiskCriticalPercent -gt $DiskWarningPercent) { throw '-DiskCriticalPercent must be less than or equal to -DiskWarningPercent.' }
    $ignore = $script:DefaultIgnoredServices + $IgnoreService

    $results = foreach ($server in $ComputerName) { Test-OneServer -Server $server -Ignore $ignore }

    if ($OutputPath) {
        [pscustomobject]@{ GeneratedAt = Get-Date; Results = @($results) } |
            ConvertTo-Json -Depth 5 | Set-Content -Path $OutputPath -Encoding UTF8
    }

    $problems = @($results | Where-Object Status -ne 'OK')
    if ($WebhookUrl -and $problems.Count -gt 0) {
        . "$PSScriptRoot/../Common/Send-TeamsAlert.ps1"
        $facts = [ordered]@{}
        foreach ($p in $problems) {
            $bad = @($p.Disks | Where-Object Status -ne 'OK' | ForEach-Object { "$($_.Drive) $($_.FreePercent)% free" })
            $facts[$p.Server] = (@("$($p.Status)") + $bad + $p.Notes) -join '; '
        }
        $severity = if ($problems.Status -contains 'Critical' -or $problems.Status -contains 'Unreachable') { 'Critical' } else { 'Warning' }
        Send-TeamsAlert -WebhookUrl $WebhookUrl -Severity $severity -Title 'Server health' `
            -Summary "$($problems.Count) of $(@($results).Count) server(s) need attention." -Facts $facts
    }

    $results
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-ServerHealthCheck }
