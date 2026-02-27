#!/usr/bin/env bash
set -euo pipefail

if [[ "${RUN_REPORTS:-0}" == "1" ]]; then
  echo "[mongo-tools] RUN_REPORTS=1 -> generating reports"
  /bin/bash /tests/createReport.sh
  echo "[mongo-tools] reports done"
else
  echo "[mongo-tools] RUN_REPORTS!=1 -> sleep infinity"
  exec sleep infinity
fi
