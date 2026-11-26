#!/usr/bin/env bash
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-./backups}"
mkdir -p "$BACKUP_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_FILE="${BACKUP_DIR}/lanticell_${STAMP}.sql.gz"

: "${DATABASE_URL:?DATABASE_URL must be set}"

pg_dump "$DATABASE_URL" | gzip -9 > "$OUT_FILE"
echo "Backup written to $OUT_FILE"
