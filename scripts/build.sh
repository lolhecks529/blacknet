#!/bin/bash

# BlackNet DDoS Toolkit - Build Script

echo "[+] Building BlackNet DDoS Toolkit..."

# Check for dependencies
command -v g++ >/dev/null 2>&1 || { echo "[-] g++ not found. Please install g++"; exit 1; }
command -v make >/dev/null 2>&1 || { echo "[-] make not found. Please install make"; exit 1; }

# Check for required libraries
if ! pkg-config --exists libcurl libssl libcrypto; then
    echo "[-] Required libraries not found. Running dependency installer..."
    ./scripts/install_deps.sh
fi

# Build
echo "[+] Compiling source code..."
make -j$(nproc)

if [ $? -eq 0 ]; then
    echo "[+] Build successful!"
    echo "[+] Run: ./blacknet --help"
else
    echo "[-] Build failed!"
    exit 1
fi
