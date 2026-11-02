$ErrorActionPreference = 'Stop'
$exe = Join-Path $PSScriptRoot 'open-cisco-zta.exe'
$logDir = Join-Path $env:LOCALAPPDATA 'open-cisco-zta'
$log = Join-Path $logDir 'run.log'

if (Get-Process -Name open-cisco-zta -ErrorAction SilentlyContinue) {
    Write-Host 'Already running. Use ocz-stop.ps1 to stop it.'
    exit 0
}

New-Item -ItemType Directory -Force $logDir | Out-Null
$inner = "& '$exe' run *> '$log'"
Start-Process powershell -Verb RunAs -WindowStyle Hidden -ArgumentList '-NoProfile', '-Command', $inner

Start-Sleep -Seconds 6
if (Get-Process -Name open-cisco-zta -ErrorAction SilentlyContinue) {
    Write-Host "Started in background. Log: $log"
} else {
    Write-Host "Failed to start. See log: $log"
    exit 1
}
