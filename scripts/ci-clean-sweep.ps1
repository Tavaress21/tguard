param([string]$Cli, [string[]]$Paths, [string]$Report)

Set-Content $Report "" -Encoding utf8
$hits = New-Object System.Collections.Generic.List[object]
$current = $null

function Flush {
    if ($null -eq $script:current) { return }
    $script:hits.Add($script:current)
    $line = "{0,-10} {1,3}  {2}" -f $script:current.Verdict, $script:current.Score, $script:current.File
    Write-Host $line
    Add-Content $Report $line -Encoding utf8
    foreach ($r in $script:current.Reasons) { Write-Host "               - $r"; Add-Content $Report "               - $r" -Encoding utf8 }
    $script:current = $null
}

foreach ($p in $Paths) {
    if (-not (Test-Path $p)) { continue }
    Write-Host "Scanning $p"
    & $Cli scan $p 2>$null | ForEach-Object {
        if ($_ -match '^\[(MALICIOUS|SUSPICIOUS)\s*\]\s+(\d+)/100\s+(.+)$') {
            Flush
            $script:current = [pscustomobject]@{ Verdict = $Matches[1]; Score = [int]$Matches[2]; File = $Matches[3]; Reasons = New-Object System.Collections.Generic.List[string] }
        }
        elseif ($null -ne $script:current -and $_ -match '^\s+- (.+)$') { $script:current.Reasons.Add($Matches[1]) }
        else {
            Flush
            if ($_ -match 'files scanned') { Write-Host "  $_"; Add-Content $Report "# $p : $_" -Encoding utf8 }
        }
    }
    Flush
}

Write-Host ""
Write-Host "Detections on clean files: $($hits.Count)"
$hits | Group-Object { if ($_.Reasons.Count) { $_.Reasons[0] -replace '\d+', 'N' } else { '-' } } | Sort-Object Count -Descending |
    ForEach-Object { Write-Host ("{0,6}  {1}" -f $_.Count, $_.Name) }
exit 0
