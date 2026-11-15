BeforeAll {
    . "$PSScriptRoot/../src/Monitoring/Get-CertificateExpiry.ps1"
    . "$PSScriptRoot/../src/Monitoring/Test-ServerHealth.ps1"
    . "$PSScriptRoot/../src/Common/Send-TeamsAlert.ps1"
}

Describe 'Get-ExpiryStatus' {
    It 'returns <Expected> for <Days> days remaining' -TestCases @(
        @{ Days = 120; Expected = 'OK' }
        @{ Days = 31; Expected = 'OK' }
        @{ Days = 30; Expected = 'Warning' }
        @{ Days = 15; Expected = 'Warning' }
        @{ Days = 14; Expected = 'Critical' }
        @{ Days = 0; Expected = 'Critical' }
        @{ Days = -1; Expected = 'Expired' }
    ) {
        Get-ExpiryStatus -DaysRemaining $Days -WarningDays 30 -CriticalDays 14 | Should -Be $Expected
    }
}

Describe 'ConvertTo-EndpointTarget' {
    It 'defaults to port 443' {
        $t = ConvertTo-EndpointTarget -Value 'portal.example.com'
        $t.Host | Should -Be 'portal.example.com'
        $t.Port | Should -Be 443
    }
    It 'reads an explicit port' {
        $t = ConvertTo-EndpointTarget -Value ' vpn.example.com:8443 '
        $t.Host | Should -Be 'vpn.example.com'
        $t.Port | Should -Be 8443
    }
}

Describe 'Get-DiskStatus' {
    It 'returns <Expected> at <Pct>% free' -TestCases @(
        @{ Pct = 50; Expected = 'OK' }
        @{ Pct = 15; Expected = 'Warning' }
        @{ Pct = 8; Expected = 'Critical' }
        @{ Pct = 2.5; Expected = 'Critical' }
    ) {
        Get-DiskStatus -FreePercent $Pct -WarningPercent 15 -CriticalPercent 8 | Should -Be $Expected
    }
}

Describe 'Get-OverallStatus' {
    It 'picks the worst status' {
        Get-OverallStatus -Status 'OK', 'Warning', 'Critical' | Should -Be 'Critical'
        Get-OverallStatus -Status 'OK', 'Warning' | Should -Be 'Warning'
        Get-OverallStatus -Status 'OK' | Should -Be 'OK'
        Get-OverallStatus -Status @() | Should -Be 'OK'
    }
}

Describe 'New-TeamsAlertCard' {
    It 'builds an Adaptive Card with the title, summary, and facts' {
        $card = New-TeamsAlertCard -Title 'Disk low' -Summary 'C: is low' -Severity Critical -Facts ([ordered]@{ Server = 'FILE01'; Free = '5%' })
        $content = $card.attachments[0].content
        $content.type | Should -Be 'AdaptiveCard'
        $content.body[0].text | Should -Be '[Critical] Disk low'
        $content.body[0].color | Should -Be 'Attention'
        $content.body[2].type | Should -Be 'FactSet'
        $content.body[2].facts.Count | Should -Be 2
    }
    It 'serializes to valid JSON' {
        $card = New-TeamsAlertCard -Title 'T' -Summary 'S'
        { $card | ConvertTo-Json -Depth 10 | ConvertFrom-Json } | Should -Not -Throw
    }
}
