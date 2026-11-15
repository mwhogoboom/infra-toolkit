# infra-toolkit

PowerShell tools for running a Windows infrastructure with a small team: monitoring that tells you what broke before users do, read-only security audits, and automation for the jobs that otherwise eat a maintenance window.

These are generalized versions of patterns I use running Windows infrastructure for a multi-site organization. Nothing here contains real server names, addresses, or credentials.

[![CI](https://github.com/mwhogoboom/infra-toolkit/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/mwhogoboom/infra-toolkit/actions/workflows/ci.yml)

## Tools

| Script | Area | What it does |
|---|---|---|
| [`Get-ADHygieneReport.ps1`](src/ActiveDirectory/Get-ADHygieneReport.ps1) | Active Directory | Read-only audit of the findings behind most PingCastle risk: stale accounts, password-never-expires, pre-auth disabled, reversible encryption, privileged group membership, orphaned `adminCount`, unconstrained delegation, and krbtgt age. HTML summary plus one CSV per finding. |
| [`Invoke-RollingServerPatch.ps1`](src/Patching/Invoke-RollingServerPatch.ps1) | Patching | Patches servers one at a time in a set order: install updates, reboot only if needed, wait for the server to return, verify critical services, then move on. Optional stop-on-failure, CSV report, Teams summary, and `-WhatIf`. |
| [`Get-SqlDeadlockReport.ps1`](src/SqlServer/Get-SqlDeadlockReport.ps1) | SQL Server | Reads deadlocks from the built-in `system_health` session and turns the XML into a table: victim, apps, logins, objects, indexes, and statements. `-Summary` groups them into repeat patterns. |
| [`Test-ServerHealth.ps1`](src/Monitoring/Test-ServerHealth.ps1) | Monitoring | One CIM session per server: uptime, disk free space, stopped automatic services (with a noise filter), and pending reboot, folded into one status per server. JSON output for a dashboard. |
| [`Get-CertificateExpiry.ps1`](src/Monitoring/Get-CertificateExpiry.ps1) | Monitoring | Checks the certificate each endpoint actually presents (catching renewed certs that were never bound) and the local machine store. OK / Warning / Critical / Expired. |
| [`Repair-DnsClientServers.ps1`](src/Endpoint/Repair-DnsClientServers.ps1) | Endpoint | Finds adapters left pointing at a dead DNS proxy (for example `127.0.0.1` after a filtering agent fails) and resets them to DHCP or approved servers. `-RegisterTask` installs it as an hourly SYSTEM task for fleet-wide self-healing. |
| [`Send-TeamsAlert.ps1`](src/Common/Send-TeamsAlert.ps1) | Shared | Posts severity-colored Adaptive Cards to a Teams Workflows webhook. Used by the monitoring and patching scripts. |

## Quick start

```powershell
git clone https://github.com/mwhogoboom/infra-toolkit.git
cd infra-toolkit

# Every script has full comment-based help
Get-Help .\src\Patching\Invoke-RollingServerPatch.ps1 -Full

# See what a change would do before doing it
.\src\Patching\Invoke-RollingServerPatch.ps1 -ComputerName APP01, APP02 -CriticalService W3SVC -WhatIf
.\src\Endpoint\Repair-DnsClientServers.ps1 -WhatIf

# Read-only reports
.\src\ActiveDirectory\Get-ADHygieneReport.ps1 -StaleDays 90 -OutputFolder C:\Reports\AD
.\src\SqlServer\Get-SqlDeadlockReport.ps1 -SqlInstance SQL01 -Since (Get-Date).AddDays(-30) -Summary
.\src\Monitoring\Test-ServerHealth.ps1 -ComputerName (Get-Content .\servers.txt) -OutputPath C:\Monitoring\health.json
.\src\Monitoring\Get-CertificateExpiry.ps1 -Endpoint portal.example.com, vpn.example.com:8443 -IncludeLocalStore
```

Alerts go to Teams when you pass a webhook. Keep the URL out of source control, for example in an environment variable or a SecretManagement vault:

```powershell
.\src\Monitoring\Test-ServerHealth.ps1 -ComputerName APP01, SQL01 -WebhookUrl $env:TEAMS_WEBHOOK
```

## Design principles

- **Read-only unless the name says otherwise.** Reports (`Get-`, `Test-`) never change anything. Scripts that make changes (`Invoke-`, `Repair-`) support `-WhatIf` and log what they did.
- **One status a dashboard can read.** Monitoring scripts collapse every check into a single worst-wins status and can write JSON for a NOC wall tile.
- **Alert once, with the details.** One Teams card per run that lists everything needing attention, instead of one card per problem.
- **Testable.** Each script keeps its decision logic in small pure functions and only runs its main function when executed, not when dot-sourced. The Pester tests load the functions directly, so they run on any OS without AD, SQL Server, or live servers.
- **Windows PowerShell 5.1 and PowerShell 7 compatible**, because 5.1 is what's on the servers.

## Requirements

| Script | Needs |
|---|---|
| `Get-ADHygieneReport.ps1` | RSAT ActiveDirectory module, domain read access |
| `Invoke-RollingServerPatch.ps1` | [PSWindowsUpdate](https://www.powershellgallery.com/packages/PSWindowsUpdate) on the management machine and targets, admin rights on targets, WinRM |
| `Get-SqlDeadlockReport.ps1` | [SqlServer](https://www.powershellgallery.com/packages/SqlServer) module v22+, `VIEW SERVER STATE` |
| `Test-ServerHealth.ps1` | WinRM (CIM over WS-Man) to each server |
| `Repair-DnsClientServers.ps1` | Run elevated or as SYSTEM |

## Tests

```powershell
Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser
Install-Module PSScriptAnalyzer -Scope CurrentUser

Invoke-ScriptAnalyzer -Path .\src -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
Invoke-Pester .\tests -Output Detailed
```

GitHub Actions runs both on Windows and Linux for every push and pull request.

## Repository layout

```
src/
  ActiveDirectory/   Get-ADHygieneReport.ps1
  Common/            Send-TeamsAlert.ps1
  Endpoint/          Repair-DnsClientServers.ps1
  Monitoring/        Get-CertificateExpiry.ps1, Test-ServerHealth.ps1
  Patching/          Invoke-RollingServerPatch.ps1
  SqlServer/         Get-SqlDeadlockReport.ps1
tests/               Pester tests and a sample deadlock event
.github/workflows/   CI: PSScriptAnalyzer + Pester
```

## About

Built by [Matthew Hogoboom](https://matthogoboom.com), a systems engineer in Wichita, Kansas. Questions and suggestions are welcome through issues.

## License

MIT. See [LICENSE](LICENSE).
