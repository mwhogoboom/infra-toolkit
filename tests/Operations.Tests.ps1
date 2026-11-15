BeforeAll {
    . "$PSScriptRoot/../src/Patching/Invoke-RollingServerPatch.ps1"
    . "$PSScriptRoot/../src/Endpoint/Repair-DnsClientServers.ps1"
    . "$PSScriptRoot/../src/SqlServer/Get-SqlDeadlockReport.ps1"
}

Describe 'Get-PatchRunSummary' {
    It 'rolls up results and compliance' {
        $results = @(
            [pscustomobject]@{ Server = 'A'; Result = 'Success'; UpdatesInstalled = 3; Rebooted = $true }
            [pscustomobject]@{ Server = 'B'; Result = 'Success'; UpdatesInstalled = 0; Rebooted = $false }
            [pscustomobject]@{ Server = 'C'; Result = 'Failed'; UpdatesInstalled = 1; Rebooted = $false }
            [pscustomobject]@{ Server = 'D'; Result = 'Skipped'; UpdatesInstalled = 0; Rebooted = $false }
        )
        $s = Get-PatchRunSummary -Results $results
        $s.Total | Should -Be 4
        $s.Succeeded | Should -Be 2
        $s.Failed | Should -Be 1
        $s.Skipped | Should -Be 1
        $s.UpdatesInstalled | Should -Be 4
        $s.Rebooted | Should -Be 1
        $s.CompliancePercent | Should -Be 50
    }
    It 'handles an empty run' {
        (Get-PatchRunSummary -Results @()).CompliancePercent | Should -Be 0
    }
}

Describe 'Get-InstalledUpdateCount' {
    It 'counts only installed KB lines' {
        $log = @(
            'X ComputerName Result     KB          Size  Title'
            '1 SRV01        Accepted   KB5044281   1GB   2026-10 Cumulative Update'
            '3 SRV01        Installed  KB5044281   1GB   2026-10 Cumulative Update'
            '3 SRV01        Installed  KB890830    80MB  Malicious Software Removal Tool'
            '3 SRV01        Failed     KB5043050   30MB  Servicing Stack'
        )
        Get-InstalledUpdateCount -LogLine $log | Should -Be 2
    }
}

Describe 'Test-DnsServerList' {
    It 'is healthy for normal servers' {
        Test-DnsServerList -Configured '10.0.0.10', '10.0.0.11' | Should -BeNullOrEmpty
    }
    It 'flags a loopback left behind by an agent' {
        Test-DnsServerList -Configured '127.0.0.1' | Should -Match 'blocked'
    }
    It 'flags servers outside the approved list' {
        Test-DnsServerList -Configured '10.0.0.10', '8.8.8.8' -Approved '10.0.0.10', '10.0.0.11' | Should -Match '8\.8\.8\.8'
    }
    It 'treats an empty list as healthy (DHCP not yet assigned)' {
        Test-DnsServerList -Configured @() | Should -BeNullOrEmpty
    }
}

Describe 'ConvertFrom-DeadlockEventXml' {
    BeforeAll {
        $xml = Get-Content "$PSScriptRoot/fixtures/deadlock-event.xml" -Raw
        $script:rows = @(ConvertFrom-DeadlockEventXml -EventXml $xml)
    }
    It 'returns one row per process' {
        $rows.Count | Should -Be 2
    }
    It 'identifies the victim' {
        ($rows | Where-Object IsVictim).ClientApp | Should -Be 'Microsoft Office'
        ($rows | Where-Object { -not $_.IsVictim }).ClientApp | Should -Be 'ImportJob'
    }
    It 'maps objects and indexes to each process' {
        $rows[0].DeadlockObjects | Should -Be 'Sales.dbo.OrderLines (IX_OrderLines_OrderID); Sales.dbo.Orders (PK_Orders)'
        ($rows | Where-Object ClientApp -eq 'ImportJob').Objects | Should -Match 'PK_Orders'
    }
    It 'collapses whitespace in the input buffer' {
        ($rows | Where-Object IsVictim).InputBuffer | Should -Be 'SELECT o.OrderID, o.Total FROM dbo.Orders o WHERE o.Region = @p1'
    }
    It 'converts the UTC timestamp to local time' {
        $rows[0].Timestamp | Should -Be ([datetime]'2026-10-28T14:05:12.345Z').ToLocalTime()
    }
}

Describe 'Get-DeadlockSummary' {
    It 'counts distinct deadlocks, not processes' {
        $xml = Get-Content "$PSScriptRoot/fixtures/deadlock-event.xml" -Raw
        $first = @(ConvertFrom-DeadlockEventXml -EventXml $xml)
        $second = @(ConvertFrom-DeadlockEventXml -EventXml ($xml -replace '2026-10-28T14:05:12.345Z', '2026-10-29T09:00:00.000Z'))
        $summary = @(Get-DeadlockSummary -Rows ($first + $second))
        $summary.Count | Should -Be 1
        $summary[0].Deadlocks | Should -Be 2
        $summary[0].UsualVictim | Should -Be 'Microsoft Office'
    }
}
