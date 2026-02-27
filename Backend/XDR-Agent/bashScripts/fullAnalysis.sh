#!/bin/bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <sample_file>" >&2
  exit 1
fi

ORIG="$1"
STAGING="/app/XDR-AgentData/staging"
OUT="/app/XDR-AgentData/captures"
NDJSON_OUT="$OUT/static_results.json"

mkdir -p "$STAGING" "$OUT"

if [ ! -e "$ORIG" ]; then
  echo "Error: original file not found: $ORIG" >&2
  exit 1
fi

BASENAME="$(basename "$ORIG")"
COPY="$STAGING/${BASENAME}_$(date +%s)_$$"


cp --preserve=mode,ownership,timestamps "$ORIG" "$COPY" 2>/dev/null || cp "$ORIG" "$COPY"

chmod u+r "$COPY" 2>/dev/null || true

if [ ! -r "$COPY" ]; then
  echo "Error: staged file not readable: $COPY" >&2
  exit 1
fi

# Tool check
need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "Error: $1 not available" >&2; exit 127; }; }
need_cmd file
need_cmd strings
need_cmd sha256sum
need_cmd awk
need_cmd sed
need_cmd grep
need_cmd sort
need_cmd wc
need_cmd tr

REAL_PATH="$(realpath "$ORIG" 2>/dev/null || echo "$ORIG")"
NAME="$(basename "$ORIG")"
TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

SHA256="$(sha256sum "$COPY" | awk '{print $1}')"

FILE_OUTPUT="$(file "$COPY" 2>/dev/null || echo "unknown")"


STRINGS_OUTPUT="$(strings -n 6 "$COPY" 2>/dev/null | head -n 5000 || true)"
STRINGS_COUNT="$(printf "%s\n" "$STRINGS_OUTPUT" | wc -l | tr -d ' ')"

IOC_LINES="$(printf "%s\n" "$STRINGS_OUTPUT" \
  | grep -Eoi 'https?://[^[:space:]"'"'"'<>]+|([0-9]{1,3}\.){3}[0-9]{1,3}' 2>/dev/null || true)"

make_json_array() {
  local first=1
  printf '['
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    line=$(printf '%s' "$line" | sed 's/\\/\\\\/g; s/"/\\"/g')
    if [ $first -eq 1 ]; then first=0; else printf ','; fi
    printf '"%s"' "$line"
  done
  printf ']'
}

URLS_JSON="$(
  printf "%s\n" "$IOC_LINES" \
  | grep -Eoi '^https?://.+' 2>/dev/null \
  | sort -u \
  | make_json_array
)"

IPS_JSON="$(
  printf "%s\n" "$IOC_LINES" \
  | grep -Eo '^([0-9]{1,3}\.){3}[0-9]{1,3}$' 2>/dev/null \
  | sort -u \
  | make_json_array
)"

esc() { echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

REAL_PATH_ESCAPED="$(esc "$REAL_PATH")"
NAME_ESCAPED="$(esc "$NAME")"
FILE_OUTPUT_ESCAPED="$(esc "$FILE_OUTPUT")"
SHA256_ESCAPED="$(esc "$SHA256")"

printf '{"event_type":"static_full","path":"%s","name":"%s","analysis_on":"%s","file_type":"%s","sha256":"%s","strings_count":%s,"urls":%s,"ips":%s,"timestamp":"%s"}\n' \
  "$REAL_PATH_ESCAPED" \
  "$NAME_ESCAPED" \
  "$(esc "$COPY")" \
  "$FILE_OUTPUT_ESCAPED" \
  "$SHA256_ESCAPED" \
  "$STRINGS_COUNT" \
  "$URLS_JSON" \
  "$IPS_JSON" \
  "$TS" \
  > "$NDJSON_OUT"

echo "Appended unified static analysis to: $NDJSON_OUT"
