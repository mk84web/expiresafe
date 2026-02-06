#!/bin/bash
set -e

# Reads paths from PERSISTENT_STORAGE_PATH (same env var the app uses).
# Falls back to /mnt/data if unset.
BASE="${PERSISTENT_STORAGE_PATH:-/mnt/data}"
DB_PATH="$BASE/instance/expiresafe.db"
UPLOADS_DIR="$BASE/uploads"
BACKUP_DIR="$BASE/backups"

TS=$(date +"%Y-%m-%d_%H-%M")

mkdir -p "$BACKUP_DIR"

echo "[backup] $(date) — starting"
sqlite3 "$DB_PATH" ".backup '$BACKUP_DIR/db_$TS.sqlite'"
tar -czf "$BACKUP_DIR/uploads_$TS.tar.gz" -C "$BASE" uploads

# keep last 14 days
find "$BACKUP_DIR" -type f -mtime +14 -delete
echo "[backup] $(date) — done"