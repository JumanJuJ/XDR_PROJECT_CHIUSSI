#!/usr/bin/env bash
set -euo pipefail

echo "[agent] starting..."

TEST_MODE="${TEST_MODE:-0}"

# --- Avvio agent principale ---
dotnet /app/XDR-Agent/XDR-Agent.dll --mode live &

# --- Permessi (best effort) ---
chmod 755 /bin/* || true

# --- Script sempre attivi ---
/app/XDR-AgentData/bashScripts/fileCollection.sh &

# --- Script SOLO in test mode ---
if [[ "$TEST_MODE" == "1" ]]; then
  echo "[agent] TEST_MODE=1 -> running test scripts"

  /app/XDR-AgentData/bashScripts/warningTest.sh &
  /app/XDR-AgentData/bashScripts/localAlerts.sh &
else
  echo "[agent] TEST_MODE!=1 -> skipping test scripts"
fi

# --- Porta mock / test ---
nc -l -p 2375 &

wait
