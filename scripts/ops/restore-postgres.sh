#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <backup_file.sql.gz>" >&2
  exit 1
fi

BACKUP_FILE="$1"
: "${TARGET_DATABASE_URL:?TARGET_DATABASE_URL must be set}"

gunzip -c "$BACKUP_FILE" | psql "$TARGET_DATABASE_URL"
echo "Restore completed into TARGET_DATABASE_URL"
