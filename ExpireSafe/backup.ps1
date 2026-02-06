<#
.SYNOPSIS
    Daily backup for ExpireSafe — SQLite DB + uploads.
    Run via Task Scheduler or manually: powershell -ExecutionPolicy Bypass -File backup.ps1
.NOTES
    Uses the same PERSISTENT_STORAGE_PATH env var the Flask app reads.
    Falls back to the script directory if the env var is unset.
#>
param(
    [int]$RetainDays = 14
)

$ErrorActionPreference = "Stop"

# ---- paths (mirror the Flask app's path logic) ----
$Base = if ($env:PERSISTENT_STORAGE_PATH) { $env:PERSISTENT_STORAGE_PATH } else { $PSScriptRoot }
$DbPath      = Join-Path $Base "instance\expiresafe.db"
$UploadsDir  = Join-Path $Base "uploads"
$BackupDir   = Join-Path $Base "backups"

$Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"

if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }

Write-Host "[backup] $(Get-Date) — starting"

# ---- 1. SQLite safe copy (uses .backup via sqlite3 CLI if available, else file copy) ----
$DbBackup = Join-Path $BackupDir "db_$Timestamp.sqlite"

$sqlite3 = Get-Command sqlite3 -ErrorAction SilentlyContinue
if ($sqlite3) {
    & sqlite3 $DbPath ".backup '$DbBackup'"
    Write-Host "[backup] DB backed up via sqlite3 .backup"
} else {
    # Fallback: straight file copy (safe with WAL mode if app uses busy_timeout)
    Copy-Item -Path $DbPath -Destination $DbBackup -Force
    # Also copy WAL + SHM if they exist so the backup is consistent
    foreach ($ext in "-wal", "-shm") {
        $walPath = "$DbPath$ext"
        if (Test-Path $walPath) { Copy-Item $walPath "$DbBackup$ext" -Force }
    }
    Write-Host "[backup] DB backed up via file copy (sqlite3 CLI not found)"
}

# ---- 2. Compress uploads ----
$UploadsZip = Join-Path $BackupDir "uploads_$Timestamp.zip"
if (Test-Path $UploadsDir) {
    Compress-Archive -Path "$UploadsDir\*" -DestinationPath $UploadsZip -Force
    Write-Host "[backup] Uploads archived: $UploadsZip"
} else {
    Write-Host "[backup] No uploads directory found — skipping"
}

# ---- 3. Prune old backups ----
$Cutoff = (Get-Date).AddDays(-$RetainDays)
Get-ChildItem -Path $BackupDir -File | Where-Object { $_.LastWriteTime -lt $Cutoff } | ForEach-Object {
    Write-Host "[backup] Removing old backup: $($_.Name)"
    Remove-Item $_.FullName -Force
}

Write-Host "[backup] $(Get-Date) — done"
