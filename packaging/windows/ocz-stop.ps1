$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`""
    if (Get-Process -Name open-cisco-zta -ErrorAction SilentlyContinue) {
        Write-Host 'Still running.'
        exit 1
    }
    Write-Host 'Stopped.'
    exit 0
}

Stop-Process -Name open-cisco-zta -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# The process is killed, so it cannot clean up after itself
Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'open-cisco-zta' } | Remove-DnsClientNrptRule -Force
Get-NetRoute -InterfaceAlias ztna0 -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
Clear-DnsClientCache
