BeforeAll {
    . "$PSScriptRoot/../src/ActiveDirectory/Get-ADHygieneReport.ps1"
    $script:Now = [datetime]'2026-11-15T12:00:00'
}

Describe 'Test-IsStale' {
    It 'flags a logon older than the threshold' {
        Test-IsStale -LastLogon $Now.AddDays(-120) -WhenCreated $Now.AddYears(-3) -StaleDays 90 -Now $Now | Should -BeTrue
    }
    It 'does not flag a recent logon' {
        Test-IsStale -LastLogon $Now.AddDays(-10) -WhenCreated $Now.AddYears(-3) -StaleDays 90 -Now $Now | Should -BeFalse
    }
    It 'flags a never-used account once it is older than the threshold' {
        Test-IsStale -LastLogon $null -WhenCreated $Now.AddDays(-200) -StaleDays 90 -Now $Now | Should -BeTrue
    }
    It 'does not flag a brand-new account that has not logged on yet' {
        Test-IsStale -LastLogon $null -WhenCreated $Now.AddDays(-5) -StaleDays 90 -Now $Now | Should -BeFalse
    }
}

Describe 'ConvertFrom-LastLogonTimestamp' {
    It 'returns null for never/zero' {
        ConvertFrom-LastLogonTimestamp $null | Should -BeNullOrEmpty
        ConvertFrom-LastLogonTimestamp 0 | Should -BeNullOrEmpty
    }
    It 'converts a FILETIME' {
        $ft = $Now.ToFileTime()
        ConvertFrom-LastLogonTimestamp $ft | Should -Be $Now
    }
}

Describe 'ConvertTo-HtmlReport' {
    It 'HTML-encodes values and marks empty findings as ok' {
        $findings = @(
            New-Finding -Name 'Test <script>' -Severity High -Why 'a & b' -Items @(1, 2)
            New-Finding -Name 'Clean' -Severity Low -Why 'none' -Items @()
        )
        $html = ConvertTo-HtmlReport -Findings $findings -Domain 'contoso.local' -Generated $Now
        $html | Should -Match 'Test &lt;script&gt;'
        $html | Should -Match 'a &amp; b'
        $html | Should -Match "<tr class='ok'>"
        $html | Should -Match "<tr class='high'>"
    }
}
