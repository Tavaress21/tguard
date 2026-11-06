# End-to-end auto-update test (run by GitHub Actions on Windows):
# installs the current build, serves a signed "99.0.0" from localhost with the test keys,
# asks the service to update and checks that it installed the new version on its own.
$ErrorActionPreference = 'Stop'
$appId = '{CEFAB7AD-A3D3-426B-A093-8AB27FB4FB96}_is1'
$uninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$appId"

function Send-TGuard([string]$cmd) {
    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'TGuard.Service.v1', [System.IO.Pipes.PipeDirection]::InOut)
    $pipe.Connect(10000)
    $w = New-Object System.IO.StreamWriter($pipe); $w.AutoFlush = $true
    $r = New-Object System.IO.StreamReader($pipe)
    $w.WriteLine((@{ cmd = $cmd } | ConvertTo-Json -Compress))
    $line = $r.ReadLine()
    $pipe.Dispose()
    return $line | ConvertFrom-Json
}

function Wait-Service {
    for ($i = 0; $i -lt 60; $i++) {
        $s = Get-Service TGuard -ErrorAction SilentlyContinue
        if ($s -and $s.Status -eq 'Running') { try { if ((Send-TGuard 'status').ok) { return } } catch { } }
        Start-Sleep 2
    }
    throw 'Service did not come up.'
}

# 1) install the current build
$current = Get-ChildItem publish\TGuard-Setup-*.exe | Where-Object Name -notlike '*99.0.0*' | Select-Object -First 1
Start-Process $current.FullName -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART' -Wait
Wait-Service
Write-Host "Installed: $((Get-ItemProperty $uninstallKey).DisplayVersion)"

# 2) build a "newer" installer and publish it with the throwaway test keys
& "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe" /Q /DAppVersion=99.0.0 installer\TGuard.iss
if ($LASTEXITCODE -ne 0) { throw 'Could not build the 99.0.0 installer.' }
$serve = Join-Path $env:TEMP 'tguard-update-server'
Remove-Item $serve -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force (Join-Path $serve 'updates') | Out-Null
$env:TGUARD_RELEASE_KEY = Get-Content tests\TGuard.Tests\keys\test-release.key.pem -Raw
$env:TGUARD_FEEDS_KEY = Get-Content tests\TGuard.Tests\keys\test-feeds.key.pem -Raw
./publish/cli/tguard.exe publish-app publish\TGuard-Setup-99.0.0.exe 99.0.0 (Join-Path $serve 'updates')
./publish/cli/tguard.exe publish-feeds (Join-Path $serve 'updates') server\lists
Remove-Item publish\TGuard-Setup-99.0.0.exe

$server = Start-Process python -ArgumentList '-m', 'http.server', '8765', '--bind', '127.0.0.1', '--directory', $serve -PassThru -WindowStyle Hidden
try {
    Start-Sleep 2

    # 3) point the installed service at the local server (admin-only settings)
    $settingsPath = "$env:ProgramData\TGuard\settings.json"
    $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
    $settings.UpdateUrl = 'http://127.0.0.1:8765/updates/'
    $settings.ExtraUpdateKeys = @((Get-Content tests\TGuard.Tests\keys\test-release.pub.pem -Raw), (Get-Content tests\TGuard.Tests\keys\test-feeds.pub.pem -Raw))
    $settings | ConvertTo-Json -Depth 5 | Set-Content $settingsPath -Encoding utf8
    Restart-Service TGuard
    Wait-Service

    # 4) update now; the service downloads, verifies and runs the installer by itself
    $rep = Send-TGuard 'update.now'
    Write-Host "Update report: $($rep.data | ConvertTo-Json -Compress)"
    if (-not ($rep.data.sources -contains 'TGuard')) { throw 'Signed feeds were not accepted.' }

    $ok = $false
    for ($i = 0; $i -lt 60 -and -not $ok; $i++) {
        Start-Sleep 3
        $ok = (Get-ItemProperty $uninstallKey -ErrorAction SilentlyContinue).DisplayVersion -eq '99.0.0'
    }
    if (-not $ok) {
        Get-Content "$env:ProgramData\TGuard\Logs\update.log" -ErrorAction SilentlyContinue | Select-Object -Last 30
        throw 'The service did not install the new version.'
    }
    Wait-Service
    Write-Host 'Auto-update OK: 99.0.0 installed by the service and protection is running again.'
}
finally {
    Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
    $u = Join-Path $env:ProgramFiles 'TGuard\unins000.exe'
    if (Test-Path $u) { Start-Process $u -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART' -Wait }
}
