#!/bin/bash
set -e

JSON_PATH="/app/XDR-AgentData/captures"
LOG_PATH="/app/XDR-AgentData/logs"
mkdir -p "$JSON_PATH" "$LOG_PATH"

OUTPUT_JSON="$JSON_PATH/filesystem.json"
OUTPUT_LOG="$LOG_PATH/fileCollection.log"

TARGET_DIRS="/bin /sbin /home /tmp /var/tmp /var/www"

echo "[fileCollection] New snapshot at $(date -u)" >> "$OUTPUT_LOG"
: > "$OUTPUT_JSON"

for DIR in $TARGET_DIRS; do
  if [ -d "$DIR" ]; then
    echo "[fileCollection] Scanning $DIR" >> "$OUTPUT_LOG"

    find "$DIR" -type f -print0 | while IFS= read -r -d '' file; do

      sha=$(sha256sum -- "$file" 2>/dev/null | awk '{print $1}')
      [ -n "$sha" ] || sha=null

      stat --printf \
'{"path":"%n","inode":%i,"size":%s,"mode":"%a","uid":%u,"gid":%g,"mtime":%Y,"sha":' \
"$file" >> "$OUTPUT_JSON"

      if [ "$sha" = "null" ]; then
        echo 'null}' >> "$OUTPUT_JSON"
      else
        printf '"%s"}\n' "$sha" >> "$OUTPUT_JSON"
      fi

    done 2>>"$OUTPUT_LOG"

  else
    echo "[fileCollection] Skipping $DIR (does not exist)" >> "$OUTPUT_LOG"
  fi
done

echo "[fileCollection] Snapshot saved to $OUTPUT_JSON" >> "$OUTPUT_LOG"

