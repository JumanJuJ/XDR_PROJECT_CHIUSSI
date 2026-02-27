#!/bin/bash
set -e

JSON_PATH="/app/XDR-AgentData/captures"
LOG_PATH="/app/XDR-AgentData/logs"
mkdir -p "$JSON_PATH" "$LOG_PATH"

OUTPUT_JSON="$JSON_PATH/processes.json"
OUTPUT_LOG="$LOG_PATH/processCollection.log"

echo "[processCollection] New snapshot at $(date -u)" >> "$OUTPUT_LOG"
: > "$OUTPUT_JSON"

json_escape() {
  sed -e 's/\\/\\\\/g' \
      -e 's/"/\\"/g' \
      -e $'s/\t/\\\\t/g' \
      -e $'s/\r/\\\\r/g'
}

BOOT_TIME_EPOCH=$(awk '$1=="btime"{print $2}' /proc/stat 2>/dev/null || true)
if [ -z "$BOOT_TIME_EPOCH" ]; then
  UPTIME_SEC=$(awk '{print $1}' /proc/uptime 2>/dev/null | cut -d. -f1)
  NOW_EPOCH=$(date +%s)
  BOOT_TIME_EPOCH=$((NOW_EPOCH - UPTIME_SEC))
fi

CLK_TCK=$(getconf CLK_TCK 2>/dev/null || echo 100)

for procdir in /proc/[0-9]*; do
  pid="${procdir#/proc/}"
  [ -r "$procdir/stat" ] || continue

  exe=$(readlink -f "$procdir/exe" 2>/dev/null || true)
  cwd=$(readlink -f "$procdir/cwd" 2>/dev/null || true)

  cmdline=$(tr '\0' ' ' < "$procdir/cmdline" 2>/dev/null | sed 's/[[:space:]]\+$//' || true)

  statline=$(cat "$procdir/stat" 2>/dev/null || true)
  [ -n "$statline" ] || continue

  comm="${statline#* (}"
  comm="${comm%%) *}"
  after="${statline#*) }"

  state=$(echo "$after" | awk '{print $1}')
  ppid=$(echo "$after"  | awk '{print $2}')
  starttime_ticks=$(echo "$after" | awk '{print $20}')

  if [ -n "$starttime_ticks" ] 2>/dev/null; then
    start_epoch=$(( BOOT_TIME_EPOCH + (starttime_ticks / CLK_TCK) ))
  else
    start_epoch=0
  fi

  uid=$(awk '/^Uid:/{print $2}' "$procdir/status" 2>/dev/null || echo 0)
  gid=$(awk '/^Gid:/{print $2}' "$procdir/status" 2>/dev/null || echo 0)

  vmrss_kb=$(awk '/^VmRSS:/{print $2}' "$procdir/status" 2>/dev/null || echo 0)
  vmsize_kb=$(awk '/^VmSize:/{print $2}' "$procdir/status" 2>/dev/null || echo 0)

  comm_json=$(printf "%s" "$comm"    | tr '\n' ' ' | json_escape)
  exe_json=$(printf "%s" "$exe"      | tr '\n' ' ' | json_escape)
  cwd_json=$(printf "%s" "$cwd"      | tr '\n' ' ' | json_escape)
  cmd_json=$(printf "%s" "$cmdline"  | tr '\n' ' ' | json_escape)

  snap_epoch=$(date -u +%s)

  echo "[processCollection] PID=$pid PPID=${ppid:-0} UID=$uid EXE=$exe COMM=$comm" >> "$OUTPUT_LOG"

  printf '{"ts":%s,"pid":%s,"ppid":%s,"state":"%s","uid":%s,"gid":%s,"start":%s,"comm":"%s","exe":"%s","cwd":"%s","cmdline":"%s","vmrss_kb":%s,"vmsize_kb":%s}\n' \
    "$snap_epoch" "$pid" "${ppid:-0}" "$state" "$uid" "$gid" "$start_epoch" \
    "$comm_json" "$exe_json" "$cwd_json" "$cmd_json" "$vmrss_kb" "$vmsize_kb" \
    >> "$OUTPUT_JSON"

done 2>>"$OUTPUT_LOG"

echo "[processCollection] Snapshot saved to $OUTPUT_JSON" >> "$OUTPUT_LOG"
