<#
  Manual install for testing (until there is a proper installer).

  1. Download the "TGuard-win-x64" artifact from the Actions tab and extract it.
  2. Open PowerShell as Administrator in that folder.
  3. Run:  powershell -ExecutionPolicy Bypass -File .\Install-TGuard.ps1
     To remove:  .\Install-TGuard.ps1 -Uninstall
#>
param(
    [string]$Source = $PSScriptRoot,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$target = Join-Path $env:ProgramFiles 'TGuard'
$serviceName = 'TGuard'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Please run this script from an elevated (Administrator) PowerShell.' -ForegroundColor Yellow
    exit 1
}

function Remove-TGuard {
    if (Get-Service $serviceName -ErrorAction SilentlyContinue) {
        Stop-Service $serviceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $serviceName | Out-Null
    }
    Get-Process TGuard -ErrorAction SilentlyContinue | Stop-Process -Force
    Remove-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'TGuard' -ErrorAction SilentlyContinue
    if (Test-Path $target) { Remove-Item $target -Recurse -Force }
}

if ($Uninstall) {
    Remove-TGuard
    Write-Host 'TGuard removed. Data and quarantine are kept in C:\ProgramData\TGuard.' -ForegroundColor Green
    exit 0
}

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue) -or -not (dotnet --list-runtimes | Select-String 'Microsoft.WindowsDesktop.App 8\.')) {
    Write-Host '.NET 8 Desktop Runtime is missing. Install it with:  winget install Microsoft.DotNet.DesktopRuntime.8' -ForegroundColor Yellow
    exit 1
}

Remove-TGuard
New-Item -ItemType Directory -Force -Path "$target\service", "$target\app", "$target\cli" | Out-Null
Copy-Item "$Source\service\*" "$target\service" -Recurse -Force
Copy-Item "$Source\app\*" "$target\app" -Recurse -Force
Copy-Item "$Source\cli\*" "$target\cli" -Recurse -Force

# Shared data: SYSTEM and admins can write, users can read.
$data = Join-Path $env:ProgramData 'TGuard'
New-Item -ItemType Directory -Force -Path $data | Out-Null
icacls $data /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null

New-Service -Name $serviceName -BinaryPathName "`"$target\service\TGuard.Service.exe`"" -DisplayName 'TGuard Protection' `
    -Description 'TGuard real-time protection and scans (luis-tavares.pt).' -StartupType Automatic | Out-Null
sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
Start-Service $serviceName

Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'TGuard' -Value "`"$target\app\TGuard.exe`" --tray"
Start-Process "$target\app\TGuard.exe"

Write-Host ''
Write-Host 'TGuard is installed and protecting this PC.' -ForegroundColor Green
Write-Host "  Program: $target"
Write-Host "  Data:    $data"
