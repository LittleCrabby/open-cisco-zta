$ErrorActionPreference = 'Stop'
$target = Join-Path $env:LOCALAPPDATA 'Programs\open-cisco-zta'
New-Item -ItemType Directory -Force $target | Out-Null
Copy-Item (Join-Path $PSScriptRoot 'open-cisco-zta.exe') $target -Force
foreach ($f in 'wintun.dll', 'ocz-start.ps1', 'ocz-stop.ps1', 'ocz-start.cmd', 'ocz-stop.cmd', 'LICENSE', 'README.md') {
    $src = Join-Path $PSScriptRoot $f
    if (Test-Path $src) { Copy-Item $src $target -Force }
}
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$entries = @($userPath -split ';' | Where-Object { $_ })
if ($entries -notcontains $target) {
    [Environment]::SetEnvironmentVariable('Path', (($entries + $target) -join ';'), 'User')
}
Write-Host "Installed to $target"
Write-Host 'Open a new terminal and run: open-cisco-zta --help'


