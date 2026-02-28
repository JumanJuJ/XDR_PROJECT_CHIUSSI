#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKUP_DIR="$PROJECT_DIR/backups"
ARCHIVE_PATH_IN_CONTAINER="/backups/xdr.archive"

MONGO_TOOLS_CONTAINER="mongo-tools"
DB_NAME="XDR-Db"

if [ -f "$PROJECT_DIR/.env" ]; then
  sed -i 's/\r$//' "$PROJECT_DIR/.env" 2>/dev/null || true
  source "$PROJECT_DIR/.env"
  echo "loaded environment from $PROJECT_DIR/.env"
  echo "XDR_ATLAS_URI=${XDR_ATLAS_URI:-<empty>}"
fi

if [ -z "${XDR_ATLAS_URI-}" ]; then
  echo >&2 "error: XDR_ATLAS_URI is not set (export it or put it in $PROJECT_DIR/.env)"
  exit 1
fi

mkdir -p "$BACKUP_DIR"

cd "$PROJECT_DIR"

if ! docker ps --format '{{.Names}}' | grep -q "^${MONGO_TOOLS_CONTAINER}$"; then
  echo "container $MONGO_TOOLS_CONTAINER is not running"
  exit 1
fi

echo "==> 1) mongodump dal container $MONGO_TOOLS_CONTAINER -> /backups/xdr.archive"
docker exec -t "$MONGO_TOOLS_CONTAINER" mongodump \
  --uri "mongodb://root:example@mongo:27017/$DB_NAME?authSource=admin" \
  --archive="$ARCHIVE_PATH_IN_CONTAINER"

echo "==> 2) mongorestore su Atlas (drop) dal container $MONGO_TOOLS_CONTAINER"
docker exec -t "$MONGO_TOOLS_CONTAINER" mongorestore \
  --uri "$XDR_ATLAS_URI" \
  --archive="$ARCHIVE_PATH_IN_CONTAINER" \
  --drop

echo "Sync completato. Archive su host: $BACKUP_DIR/xdr.archive"
