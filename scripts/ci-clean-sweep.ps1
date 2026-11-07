param([string]$Cli, [string[]]$Paths, [string]$Report)

$lines = New-Object System.Collections.Generic.List[string]
foreach ($p in $Paths) {
    if (-not (Test-Path $p)) { continue }
    Write-Host "Scanning $p"
    & $Cli scan $p 2>$null | ForEach-Object { $lines.Add($_) }
}

$hits = @()
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '^\[(MALICIOUS|SUSPICIOUS)\s*\]\s+(\d+)/100\s+(.+)$') {
        $reasons = @()
        $j = $i + 1
        while ($j -lt $lines.Count -and $lines[$j] -match '^\s+- (.+)$') { $reasons += $Matches[1]; $j++ }
        $hits += [pscustomobject]@{ Verdict = $Matches[1]; Score = [int]$Matches[2]; File = $Matches[3]; Reasons = $reasons }
    }
}

$summary = $lines | Where-Object { $_ -match 'files scanned' }
$out = New-Object System.Collections.Generic.List[string]
$out.Add("Totals:")
$summary | ForEach-Object { $out.Add("  $_") }
$out.Add("")
$out.Add("Detections on clean files: $($hits.Count)")
$out.Add("")
$out.Add("By first reason:")
$hits | Group-Object { if ($_.Reasons.Count) { $_.Reasons[0] -replace '\d+', 'N' } else { '-' } } | Sort-Object Count -Descending | ForEach-Object { $out.Add(("{0,6}  {1}" -f $_.Count, $_.Name)) }
$out.Add("")
$out.Add("All detections:")
foreach ($h in $hits | Sort-Object Score -Descending) {
    $out.Add(("{0,-10} {1,3}  {2}" -f $h.Verdict, $h.Score, $h.File))
    foreach ($r in $h.Reasons) { $out.Add("               - $r") }
}
$out | Set-Content $Report -Encoding utf8
Get-Content $Report -TotalCount 120
