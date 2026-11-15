#Requires -Version 5.1
<#
.SYNOPSIS
    Posts an alert card to a Microsoft Teams channel through a Workflows (Power Automate) webhook.

.DESCRIPTION
    Shared helper used by the monitoring scripts in this repo. Builds an Adaptive Card with a
    severity-colored title, a short summary, and an optional table of facts, then posts it to a
    Teams "Post to a channel when a webhook request is received" workflow URL.

    The webhook URL is a secret. Pass it in from a SecretManagement vault or an environment
    variable; never hard-code it in a script that lives in source control.

.PARAMETER WebhookUrl
    The Teams Workflows webhook URL.

.PARAMETER Title
    Card title, for example "Certificate expiring".

.PARAMETER Summary
    One or two sentences describing what needs attention.

.PARAMETER Severity
    Info, Warning, or Critical. Controls the title color.

.PARAMETER Facts
    Optional ordered hashtable of label/value pairs shown under the summary.

.EXAMPLE
    . .\src\Common\Send-TeamsAlert.ps1
    Send-TeamsAlert -WebhookUrl $env:TEAMS_WEBHOOK -Title 'Disk space low' -Severity Warning `
        -Summary 'FILE01 C: is below 10% free.' -Facts ([ordered]@{ Server = 'FILE01'; Free = '8.2%' })
#>

function New-TeamsAlertCard {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Summary,
        [ValidateSet('Info', 'Warning', 'Critical')][string]$Severity = 'Info',
        [System.Collections.IDictionary]$Facts
    )

    $color = switch ($Severity) {
        'Critical' { 'Attention' }
        'Warning'  { 'Warning' }
        default    { 'Accent' }
    }

    $body = [System.Collections.Generic.List[object]]::new()
    $body.Add(@{ type = 'TextBlock'; text = "[$Severity] $Title"; weight = 'Bolder'; size = 'Medium'; color = $color; wrap = $true })
    $body.Add(@{ type = 'TextBlock'; text = $Summary; wrap = $true })

    if ($Facts -and $Facts.Count -gt 0) {
        $factList = foreach ($key in $Facts.Keys) { @{ title = [string]$key; value = [string]$Facts[$key] } }
        $body.Add(@{ type = 'FactSet'; facts = @($factList) })
    }

    $body.Add(@{ type = 'TextBlock'; text = "Sent $(Get-Date -Format 'yyyy-MM-dd HH:mm') from $env:COMPUTERNAME"; isSubtle = $true; size = 'Small'; wrap = $true })

    return @{
        type        = 'message'
        attachments = @(
            @{
                contentType = 'application/vnd.microsoft.card.adaptive'
                content     = @{
                    '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'
                    type      = 'AdaptiveCard'
                    version   = '1.4'
                    body      = $body.ToArray()
                }
            }
        )
    }
}

function Send-TeamsAlert {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][ValidatePattern('^https://')][string]$WebhookUrl,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Summary,
        [ValidateSet('Info', 'Warning', 'Critical')][string]$Severity = 'Info',
        [System.Collections.IDictionary]$Facts
    )

    $card = New-TeamsAlertCard -Title $Title -Summary $Summary -Severity $Severity -Facts $Facts
    $json = $card | ConvertTo-Json -Depth 10

    if ($PSCmdlet.ShouldProcess('Teams webhook', "Post '$Title'")) {
        try {
            Invoke-RestMethod -Uri $WebhookUrl -Method Post -ContentType 'application/json; charset=utf-8' `
                -Body ([System.Text.Encoding]::UTF8.GetBytes($json)) -TimeoutSec 30 | Out-Null
        }
        catch {
            Write-Warning "Teams alert '$Title' failed to send: $($_.Exception.Message)"
        }
    }
}
