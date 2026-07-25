<#
.SYNOPSIS
    Register (or remove) the netaudit backup job in Windows Task Scheduler.

.EXAMPLE
    # Daily at 02:30, alerts written for the Wazuh agent to pick up
    .\scripts\install-scheduled-task.ps1 -At 02:30 `
        -WazuhFile C:\ProgramData\netaudit\wazuh-netaudit.json

.EXAMPLE
    .\scripts\install-scheduled-task.ps1 -Remove
#>
[CmdletBinding()]
param(
    [string]$TaskName = "netaudit-backup",
    [string]$At = "02:30",
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$WazuhFile = "",
    [string]$WazuhSyslog = "",
    [string]$Tag = "",
    [switch]$Remove
)

$ErrorActionPreference = "Stop"

if ($Remove) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed scheduled task: $TaskName"
    return
}

$wrapper = Join-Path $ProjectRoot "scripts\scheduled-backup.ps1"
if (-not (Test-Path $wrapper)) { throw "Wrapper not found: $wrapper" }

$argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$wrapper`"")
if ($WazuhFile)   { $argList += @("-WazuhFile", "`"$WazuhFile`"") }
if ($WazuhSyslog) { $argList += @("-WazuhSyslog", $WazuhSyslog) }
if ($Tag)         { $argList += @("-Tag", $Tag) }

$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument ($argList -join " ") -WorkingDirectory $ProjectRoot
$trigger = New-ScheduledTaskTrigger -Daily -At $At
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
    -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 2)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings $settings -Description "netaudit config backup + audit (company-internal)" -Force |
    Out-Null

Write-Host "Registered scheduled task '$TaskName' daily at $At"
Write-Host "Run once now:  Start-ScheduledTask -TaskName $TaskName"
Write-Host "Check result:  Get-ScheduledTaskInfo -TaskName $TaskName"
