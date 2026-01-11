param(
  # Rotmapp till filstrukturen. Scriptet hanterar även "dubbelt uppzippad" struktur:
  # .\network_configs\network_configs\routers osv.
  [string]$Root = ".\network_configs",

  # Var outputs ska hamna
  [string]$OutDir = ".\output"
)

# ----------------------------
# 0) Förberedelser
# ----------------------------

# Skapa output-mappen om den saknas
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# Basdatum enligt uppgiften (för korrekta "senaste 7 dagar")
$now = Get-Date "2024-10-14"
$weekAgo = $now.AddDays(-7)

# Normalisera $Root om du råkat få network_configs/network_configs
# Vi letar efter "routers/logs/switches" i en underkatalog som heter network_configs.
if (Test-Path (Join-Path $Root "network_configs")) {
  $candidate = Join-Path $Root "network_configs"
  if ((Test-Path (Join-Path $candidate "routers")) -and (Test-Path (Join-Path $candidate "logs"))) {
    $Root = $candidate
  }
}

if (-not (Test-Path $Root)) {
  throw "Hittar inte Root: $Root"
}

# ----------------------------
# 1) Inventera filer (.conf/.rules/.log)
# ----------------------------

$allFiles = Get-ChildItem -Path $Root -Recurse -File |
  Where-Object { $_.Extension -in @(".conf", ".rules", ".log") }

# Bygg en snabb lookup för backups (för HasBackup i CSV)
$backupDir = Join-Path $Root "backups"
$backupNames = New-Object System.Collections.Generic.HashSet[string]
if (Test-Path $backupDir) {
  Get-ChildItem -Path $backupDir -Recurse -File | ForEach-Object {
    [void]$backupNames.Add($_.Name)
  }
}

# Inventerings-objekt (för CSV)
$configInventory = foreach ($f in $allFiles | Where-Object { $_.Extension -in @(".conf", ".rules") }) {
  $rel = $f.FullName.Substring($Root.Length)
  if ($rel.StartsWith("\") -or $rel.StartsWith("/")) { $rel = $rel.Substring(1) }

  [pscustomobject]@{
    FileName     = $f.Name
    FullPath     = $f.FullName
    RelativePath = $rel
    SizeKB       = [math]::Round($f.Length / 1KB, 2)
    LastModified = $f.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
    FileType     = $f.Extension.TrimStart(".")
    HasBackup    = $backupNames.Contains($f.Name)
  }
}

$configInventory |
  Sort-Object FileType, FileName |
  Export-Csv -Path (Join-Path $OutDir "config_inventory.csv") -NoTypeInformation -Encoding UTF8

# ----------------------------
# 2) Nyligen ändrade filer (senaste 7 dagar)
# ----------------------------

$recentFiles = $allFiles |
  Where-Object { $_.LastWriteTime -gt $weekAgo } |
  Sort-Object LastWriteTime -Descending

# ----------------------------
# 3) Grupp per filtyp + totalsize
# ----------------------------

$byExtSummary = $allFiles |
  Group-Object Extension |
  Sort-Object Count -Descending |
  ForEach-Object {
    [pscustomobject]@{
      Extension   = $_.Name
      Count       = $_.Count
      TotalSizeMB = [math]::Round( (($_.Group | Measure-Object Length -Sum).Sum / 1MB), 2 )
    }
  }

# ----------------------------
# 4) 5 största loggfiler
# ----------------------------

$largestLogs = Get-ChildItem -Path $Root -Recurse -File -Filter "*.log" |
  Sort-Object Length -Descending |
  Select-Object -First 5 |
  Select-Object Name, FullName,
    @{Name="SizeMB";Expression={[math]::Round($_.Length / 1MB, 2)}},
    LastWriteTime

# ----------------------------
# 5) IP-adresser i .conf (unika)
# ----------------------------

$uniqueIPs = Get-ChildItem -Path $Root -Recurse -File -Filter "*.conf" |
  Select-String -Pattern "\b\d{1,3}(\.\d{1,3}){3}\b" -AllMatches -ErrorAction SilentlyContinue |
  ForEach-Object { $_.Matches.Value } |
  Sort-Object -Unique

$uniqueIPs | Out-File -FilePath (Join-Path $OutDir "unique_ip_addresses.txt") -Encoding UTF8

# ----------------------------
# 6) Loggar: ERROR / FAILED / DENIED per fil
# ----------------------------

$logKeywordCounts = @()
$logFiles = Get-ChildItem -Path $Root -Recurse -File -Filter "*.log"

foreach ($lf in $logFiles) {
  $rel = $lf.FullName.Substring($Root.Length)
  if ($rel.StartsWith("\") -or $rel.StartsWith("/")) { $rel = $rel.Substring(1) }

  $err = (Select-String -Path $lf.FullName -Pattern "ERROR"  -SimpleMatch -ErrorAction SilentlyContinue).Count
  $fal = (Select-String -Path $lf.FullName -Pattern "FAILED" -SimpleMatch -ErrorAction SilentlyContinue).Count
  $den = (Select-String -Path $lf.FullName -Pattern "DENIED" -SimpleMatch -ErrorAction SilentlyContinue).Count

  $logKeywordCounts += [pscustomobject]@{
    FileName     = $lf.Name
    RelativePath = $rel
    ERROR        = $err
    FAILED       = $fal
    DENIED       = $den
  }
}

$logKeywordCounts |
  Sort-Object ERROR -Descending |
  Export-Csv -Path (Join-Path $OutDir "log_keyword_counts.csv") -NoTypeInformation -Encoding UTF8

# ----------------------------
# 7) VG: Funktion – hitta "svaga" konfigurationer
# ----------------------------

function Find-SecurityIssues {
  param([string]$Path)

  $patterns = @(
    "enable password\s+\S+",
    "username\s+\S+\s+password\s+\S+",
    "password\s+\S+",
    "secret\s+\S+",
    "snmp-server community\s+public",
    "snmp-server community\s+private"
  )

  $targets = Get-ChildItem -Path $Path -Recurse -File |
    Where-Object { $_.Extension -in @(".conf", ".rules") }

  $issues = @()

  foreach ($t in $targets) {
    foreach ($p in $patterns) {
      $hits = Select-String -Path $t.FullName -Pattern $p -ErrorAction SilentlyContinue
      foreach ($h in $hits) {
        $rel = $t.FullName.Substring($Path.Length)
        if ($rel.StartsWith("\") -or $rel.StartsWith("/")) { $rel = $rel.Substring(1) }

        $issues += [pscustomobject]@{
          FileName     = $t.Name
          RelativePath = $rel
          Pattern      = $p
          LineNumber   = $h.LineNumber
          Line         = $h.Line.Trim()
        }
      }
    }
  }

  return $issues
}

$securityIssues = Find-SecurityIssues -Path $Root
$securityIssues | Export-Csv -Path (Join-Path $OutDir "security_issues.csv") -NoTypeInformation -Encoding UTF8

# ----------------------------
# 8) VG: Compare-Object mot baseline-router.conf
# ----------------------------

$baselinePath = Join-Path $Root "baseline\baseline-router.conf"
$baselineDeviations = @()

if (Test-Path $baselinePath) {
  $baseline = Get-Content -Path $baselinePath

  $routerDir = Join-Path $Root "routers"
  if (Test-Path $routerDir) {
    $routerConfs = Get-ChildItem -Path $routerDir -File -Filter "*.conf"

    foreach ($rc in $routerConfs) {
      $current = Get-Content -Path $rc.FullName

      # Vad saknas i current jämfört med baseline?
      $diff = Compare-Object -ReferenceObject $baseline -DifferenceObject $current

      $missing = $diff | Where-Object { $_.SideIndicator -eq "<=" }
      if ($missing) {
        $baselineDeviations += [pscustomobject]@{
          RouterConfig   = $rc.Name
          MissingLines   = $missing.Count
        }
      } else {
        $baselineDeviations += [pscustomobject]@{
          RouterConfig   = $rc.Name
          MissingLines   = 0
        }
      }
    }
  }
}

$baselineDeviations |
  Sort-Object MissingLines -Descending |
  Export-Csv -Path (Join-Path $OutDir "baseline_deviations.csv") -NoTypeInformation -Encoding UTF8

# ----------------------------
# 9) Skapa security_audit.txt (sammanfattande rapport)
# ----------------------------

$report = New-Object System.Collections.Generic.List[string]

$report.Add(("=" * 80))
$report.Add(("SECURITY AUDIT REPORT - TechCorp AB").PadLeft(52).PadRight(80))
$report.Add(("=" * 80))
$report.Add("Generated (baseline-date): $($now.ToString('yyyy-MM-dd HH:mm:ss'))")
$report.Add("Audit Root: $Root")
$report.Add("")

$report.Add("FILE INVENTORY")
$report.Add(("-" * 80))
$report.Add("Total files (conf/rules/log): $($allFiles.Count)")
$report.Add("Config files (conf/rules):    $($configInventory.Count)")
$report.Add("Log files (.log):             $((Get-ChildItem -Path $Root -Recurse -File -Filter '*.log').Count)")
$report.Add("Files modified last 7 days:   $($recentFiles.Count)")
$report.Add("")

$report.Add("FILES MODIFIED LAST 7 DAYS")
$report.Add(("-" * 80))
if ($recentFiles.Count -eq 0) {
  $report.Add("None.")
} else {
  foreach ($f in ($recentFiles | Select-Object -First 15)) {
    $report.Add("$($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))  $($f.Name)")
  }
  if ($recentFiles.Count -gt 15) { $report.Add("... (truncated)") }
}
$report.Add("")

$report.Add("FILE TYPES SUMMARY")
$report.Add(("-" * 80))
foreach ($x in $byExtSummary) {
  $report.Add(("{0,-8} count={1,2}  total={2,6} MB" -f $x.Extension, $x.Count, $x.TotalSizeMB))
}
$report.Add("")

$report.Add("TOP 5 LARGEST LOG FILES")
$report.Add(("-" * 80))
if ($largestLogs.Count -eq 0) {
  $report.Add("No log files.")
} else {
  foreach ($l in $largestLogs) {
    $report.Add(("{0,-28} {1,6} MB  {2}" -f $l.Name, $l.SizeMB, $l.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")))
  }
}
$report.Add("")

$report.Add("UNIQUE IP ADDRESSES (from .conf)")
$report.Add(("-" * 80))
if (($uniqueIPs | Measure-Object).Count -eq 0) {
  $report.Add("No IPs found.")
} else {
  $report.Add(($uniqueIPs -join ", "))
}
$report.Add("")

$report.Add("LOG KEYWORDS COUNT (ERROR / FAILED / DENIED)")
$report.Add(("-" * 80))
if ($logKeywordCounts.Count -eq 0) {
  $report.Add("No log files found.")
} else {
  foreach ($r in ($logKeywordCounts | Sort-Object ERROR -Descending)) {
    $report.Add(("{0,-28} ERROR={1,3}  FAILED={2,3}  DENIED={3,3}" -f $r.FileName, $r.ERROR, $r.FAILED, $r.DENIED))
  }
}
$report.Add("")

$report.Add("SECURITY ISSUES (pattern matches)")
$report.Add(("-" * 80))
if ($securityIssues.Count -eq 0) {
  $report.Add("No obvious matches.")
} else {
  $report.Add("Total findings: $($securityIssues.Count)")
  foreach ($i in ($securityIssues | Select-Object -First 20)) {
    $report.Add("$($i.RelativePath):$($i.LineNumber)  [$($i.Pattern)]  $($i.Line)")
  }
  if ($securityIssues.Count -gt 20) { $report.Add("... (truncated)") }
}
$report.Add("")

$report.Add("BASELINE COMPLIANCE (routers)")
$report.Add(("-" * 80))
if (-not (Test-Path $baselinePath)) {
  $report.Add("Baseline not found: $baselinePath")
} elseif ($baselineDeviations.Count -eq 0) {
  $report.Add("No router configs found (or no deviations computed).")
} else {
  foreach ($b in ($baselineDeviations | Sort-Object MissingLines -Descending)) {
    $report.Add(("{0,-20} missing baseline lines: {1}" -f $b.RouterConfig, $b.MissingLines))
  }
}
$report.Add("")

$report.Add(("=" * 80))
$report.Add(("RAPPORT SLUT").PadLeft(44).PadRight(80))
$report.Add(("=" * 80))

$report | Out-File -FilePath (Join-Path $OutDir "security_audit.txt") -Encoding UTF8

Write-Host "OK: Skapade outputs i $OutDir"
Write-Host " - config_inventory.csv"
Write-Host " - log_keyword_counts.csv"
Write-Host " - unique_ip_addresses.txt"
Write-Host " - security_issues.csv"
Write-Host " - baseline_deviations.csv"
Write-Host " - security_audit.txt"
