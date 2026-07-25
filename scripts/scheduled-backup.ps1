<#
.SYNOPSIS
    Windows Task Scheduler wrapper for an unattended netaudit run.

.DESCRIPTION
    Activates the project venv, runs `netaudit run` (backup with retries ->
    audit -> exports -> Wazuh alerts), writes a rotating log, and propagates
    the exit code so Task Scheduler shows the correct last result.

    Exit codes: 0 clean, 1 backup failure, 2 critical/high findings.

.EXAMPLE
    .\scripts\scheduled-backup.ps1 -WazuhFile C:\ProgramData\netaudit\wazuh-netaudit.json
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$WazuhFile = "",
    [string]$WazuhSyslog = "",
    [int]$WazuhSyslogPort = 514,
    [string]$Tag = "",
    [int]$Retries = 2,
    [double]$RetryDelay = 10,
    [string]$LogDir = "",
    [int]$KeepLogs = 30
)

$ErrorActionPreference = "Stop"
Set-Location $ProjectRoot

if (-not $LogDir) { $LogDir = Join-Path $ProjectRoot "logs" }
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$logFile = Join-Path $LogDir ("netaudit-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss"))

# Keep the log directory bounded
Get-ChildItem $LogDir -Filter "netaudit-*.log" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -Skip $KeepLogs |
    Remove-Item -Force -ErrorAction SilentlyContinue

$venvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$python = if (Test-Path $venvPython) { $venvPython } else { "python" }

$runArgs = @("-m", "netaudit.cli", "run", "--retries", $Retries, "--retry-delay", $RetryDelay)
if ($Tag)         { $runArgs += @("--tag", $Tag) }
if ($WazuhFile)   { $runArgs += @("--wazuh-file", $WazuhFile) }
if ($WazuhSyslog) { $runArgs += @("--wazuh-syslog", $WazuhSyslog, "--wazuh-syslog-port", $WazuhSyslogPort) }

# UTF-8 so Rich output does not break on legacy code pages
$env:PYTHONIOENCODING = "utf-8"

"[{0}] netaudit run starting: {1}" -f (Get-Date -Format "s"), ($runArgs -join " ") |
    Tee-Object -FilePath $logFile -Append

& $python @runArgs 2>&1 | Tee-Object -FilePath $logFile -Append
$exitCode = $LASTEXITCODE

switch ($exitCode) {
    0 { $status = "clean" }
    1 { $status = "BACKUP FAILURE" }
    2 { $status = "critical/high findings" }
    default { $status = "unexpected exit $exitCode" }
}
"[{0}] netaudit run finished: {1} (exit {2})" -f (Get-Date -Format "s"), $status, $exitCode |
    Tee-Object -FilePath $logFile -Append

exit $exitCode
