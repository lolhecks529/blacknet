#!/bin/sh
# blacknet auto-updater — checks GitHub latest release and installs
# usage: sh update.sh [--auto]

REPO="lolhecks529/blacknet"
BIN="./blacknet"
INSTALL_DIR="/usr/local/bin"
AUTO=0

if [ "$1" = "--auto" ]; then
    AUTO=1
fi

VERSION=$("$BIN" --version 2>/dev/null | grep -oP '[0-9]+\.[0-9]+\.[0-9]+')

if [ -z "$VERSION" ]; then
    VERSION="2.0.0"
fi

LATEST=$(curl -sf "https://api.github.com/repos/$REPO/releases/latest" | \
    grep '"tag_name"' | cut -d'"' -f4)

if [ -z "$LATEST" ]; then
    echo "[-] could not check for updates (no network?)"
    exit 1
fi

echo "[*] current: $VERSION"
echo "[*] latest:  $LATEST"

if [ "$VERSION" = "$LATEST" ]; then
    echo "[+] up to date."
    exit 0
fi

echo "[+] update available: $LATEST"

if [ "$AUTO" -eq 0 ]; then
    printf "install update? [y/N]: "
    read -r ANSWER
    case "$ANSWER" in
        y|Y|yes|YES) ;;
        *) echo "[-] cancelled."; exit 0 ;;
    esac
fi

ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    armv7l|armhf) ARCH="armhf" ;;
    *) echo "[-] unsupported arch: $ARCH"; exit 1 ;;
esac

ASSET="blacknet-linux-${ARCH}"
URL="https://github.com/$REPO/releases/download/$LATEST/$ASSET"

echo "[*] downloading $ASSET ..."

TMPFILE=$(mktemp)
if curl -sfL "$URL" -o "$TMPFILE"; then
    chmod +x "$TMPFILE"

    if [ -w "$INSTALL_DIR" ] 2>/dev/null; then
        mv "$TMPFILE" "$INSTALL_DIR/blacknet"
    else
        sudo mv "$TMPFILE" "$INSTALL_DIR/blacknet"
    fi

    echo "[+] updated to $LATEST"
else
    echo "[-] download failed. trying source build..."
    rm -f "$TMPFILE"

    TMPDIR=$(mktemp -d)
    curl -sfL "https://github.com/$REPO/archive/refs/tags/$LATEST.tar.gz" | tar xz -C "$TMPDIR"
    cd "$TMPDIR/blacknet-$LATEST" || exit 1
    make -j$(nproc) 2>/dev/null
    if [ -f blacknet ]; then
        if [ -w "$INSTALL_DIR" ] 2>/dev/null; then
            cp blacknet "$INSTALL_DIR/blacknet"
        else
            sudo cp blacknet "$INSTALL_DIR/blacknet"
        fi
        echo "[+] updated to $LATEST (built from source)"
    else
        echo "[-] build failed"
        cd /
        rm -rf "$TMPDIR"
        exit 1
    fi
    cd /
    rm -rf "$TMPDIR"
fi
