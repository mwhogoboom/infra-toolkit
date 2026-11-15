@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # These are operator-facing scripts; console progress lines are intentional.
        'PSAvoidUsingWriteHost',
        # Helper functions build objects, they don't change system state.
        'PSUseShouldProcessForStateChangingFunctions',
        # Plural nouns read naturally for reports (Get-...Report, Repair-DnsClientServers).
        'PSUseSingularNouns',
        # Script-level parameters are consumed by each script's main function, which this
        # rule doesn't follow into, so it reports them as unused.
        'PSReviewUnusedParameter'
    )
    Rules        = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.4')
        }
    }
}
