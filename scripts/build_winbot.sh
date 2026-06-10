#!/bin/bash
# Cross-compile bot for Windows

echo "[+] Building bot.exe for Windows..."

if ! command -v x86_64-w64-mingw32-g++ &>/dev/null; then
    echo "[-] MinGW-w64 not found. Install it:"
    echo "    sudo apt install mingw-w64"
    exit 1
fi

x86_64-w64-mingw32-g++ -std=c++17 -O2 -static -o bot.exe bot.cpp -lws2_32
strip bot.exe

if command -v upx &>/dev/null; then
    upx --best bot.exe 2>/dev/null || true
fi

echo "[+] Done: bot.exe"
