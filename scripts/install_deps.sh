#!/bin/bash

# BlackNet DDoS Toolkit - Dependency Installer
# For Kali Linux / Debian-based systems

echo "[+] Installing BlackNet DDoS Toolkit Dependencies"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "[-] Please run as root"
    exit 1
fi

# Update system
echo "[+] Updating system packages..."
apt-get update
apt-get upgrade -y

# Install build dependencies
echo "[+] Installing build dependencies..."
apt-get install -y \
    g++ \
    gcc \
    make \
    cmake \
    build-essential \
    pkg-config \
    libcurl4-openssl-dev \
    libssl-dev \
    libpthread-stubs0-dev

# Install optional dependencies
echo "[+] Installing optional dependencies..."
apt-get install -y \
    nmap \
    hping3 \
    netcat \
    tcpdump \
    wireshark \
    iptables \
    net-tools \
    iproute2

# Install development tools
echo "[+] Installing development tools..."
apt-get install -y \
    git \
    vim \
    gdb \
    valgrind \
    strace \
    ltrace

# Install Python dependencies (for optional scripts)
echo "[+] Installing Python dependencies..."
apt-get install -y \
    python3 \
    python3-pip \
    python3-dev

pip3 install \
    requests \
    scapy \
    colorama \
    progressbar2

# Create directories
echo "[+] Creating directories..."
mkdir -p /usr/local/share/blacknet
mkdir -p /var/log/blacknet

# Set permissions
echo "[+] Setting permissions..."
chmod 755 /usr/local/share/blacknet
chmod 755 /var/log/blacknet

# Download additional resources
echo "[+] Downloading additional resources..."
cd /usr/local/share/blacknet

# Download user-agents database
if [ ! -f "useragents.txt" ]; then
    wget -O useragents.txt https://raw.githubusercontent.com/tamimibrahim17/List-of-user-agents/master/Chrome.txt
    wget -O useragents2.txt https://raw.githubusercontent.com/tamimibrahim17/List-of-user-agents/master/Firefox.txt
    cat useragents.txt useragents2.txt > useragents_full.txt
    mv useragents_full.txt useragents.txt
    rm useragents2.txt
fi

# Download proxy lists
if [ ! -f "proxies.txt" ]; then
    wget -O proxies.txt https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt
    wget -O proxies2.txt https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list.txt
    cat proxies.txt proxies2.txt | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' > proxies_combined.txt
    mv proxies_combined.txt proxies.txt
    rm proxies2.txt
fi

# Download subdomain lists
if [ ! -f "subdomains.txt" ]; then
    wget -O subdomains.txt https://raw.githubusercontent.com/rbsec/dnscan/master/subdomains.txt
fi

echo "[+] Dependencies installed successfully!"
echo "[+] You can now build BlackNet with: make"
echo "[+] Or install with: sudo make install"
