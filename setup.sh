#!/bin/bash

set -e

echo "[+] BlackNet Build Script"
echo "[+] Ensuring build dependencies..."

sudo apt-get update -qq
sudo apt-get install -y -qq \
    g++ make pkg-config \
    libcurl4-openssl-dev libssl-dev libjsoncpp-dev \
    qtbase5-dev libqt5widgets5 2>/dev/null || true

echo "[+] Building..."
make -j$(nproc)

echo "[+] Done! ./blacknet --help"
