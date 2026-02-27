#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKUP_DIR="$PROJECT_DIR/backups"
ARCHIVE_PATH_IN_CONTAINER="/backups/xdr.archive"

MONGO_TOOLS_CONTAINER="mongo-tools"
DB_NAME="XDR-Db"


mkdir -p "$BACKUP_DIR"

echo "==> 1) docker compose up (se serve)"
cd "$PROJECT_DIR"
# docker compose up -d --build

echo "==> 2) mongodump dal container mongo-tools -> /backups/xdr.archive"
docker exec -t "$MONGO_TOOLS_CONTAINER" mongodump \
  --uri "mongodb://root:example@mongo:27017/$DB_NAME?authSource=admin" \
  --archive="$ARCHIVE_PATH_IN_CONTAINER"

echo "==> 3) mongorestore su Atlas (drop) dal container mongo-tools"
docker exec -t "$MONGO_TOOLS_CONTAINER" mongorestore \
  --uri "$XDR_ATLAS_URI" \
  --archive="$ARCHIVE_PATH_IN_CONTAINER" \
  --drop

echo "Sync completato. Archive su host: $BACKUP_DIR/xdr.archive"
