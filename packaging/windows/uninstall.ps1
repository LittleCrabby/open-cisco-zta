$ErrorActionPreference = 'Stop'
$target = Join-Path $env:LOCALAPPDATA 'Programs\open-cisco-zta'
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$entries = @($userPath -split ';' | Where-Object { $_ -and $_ -ne $target })
[Environment]::SetEnvironmentVariable('Path', ($entries -join ';'), 'User')
if (Test-Path $target) { Remove-Item -Recurse -Force $target }
Write-Host 'Removed. Configuration in %APPDATA% was left untouched.'
