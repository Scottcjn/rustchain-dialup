# RustChain P3 Bounty Submission — Dreamcast/DreamPi Dial-Up Mining Client Recipe

> **Version:** 1.0  
> **Date:** 2026-06-08  
> **Category:** Hardware Mining / Retro Computing / Blockchain  
> **Difficulty:** Intermediate  
> **Estimated Setup Time:** 2–4 hours

---

## Table of Contents

1. [Overview](#1-overview)
2. [Hardware Requirements](#2-hardware-requirements)
3. [DreamPi Setup (Raspberry Pi)](#3-dreampi-setup-raspberry-pi)
4. [Dial-Up Infrastructure Configuration](#4-dial-up-infrastructure-configuration)
5. [RustChain Mining Software on Dreamcast](#5-rustchain-mining-software-on-dreamcast)
6. [Step-by-Step Assembly & Configuration](#6-step-by-step-assembly--configuration)
7. [Running Your First Mining Session](#7-running-your-first-mining-session)
8. [Performance Tuning](#8-performance-tuning)
9. [Troubleshooting](#9-troubleshooting)
10. [Appendices](#10-appendices)

---

## 1. Overview

This recipe documents how to repurpose a Sega Dreamcast console as a RustChain mining node using a **DreamPi** — a Raspberry Pi-based device that emulates a dial-up ISP (Internet Service Provider) over a local phone line. The Dreamcast connects via its built-in 56K modem, dials into the DreamPi, which bridges the connection to the RustChain network over Ethernet/Wi-Fi.

### Why Dreamcast?

- The Sega Dreamcast has a **built-in 33.6K modem** (some regions: 56K) accessible via the Maple Bus.
- Its **Hitachi SH-4 CPU** (200 MHz, 1.4 GFLOPS) has a floating-point unit suitable for hash computations.
- The DreamPi community has already established dial-up revival infrastructure — we piggyback on this.
- Retro mining is fun, educational, and a tribute to the longevity of great hardware.

### Architecture Diagram

```
┌─────────────┐    Phone Line (RJ-11)    ┌─────────────┐    Ethernet/Wi-Fi    ┌──────────────┐
│  Dreamcast   │◄────────────────────────►│   DreamPi   │◄────────────────────►│  RustChain   │
│  (SH-4 CPU)  │    33.6K/56K modem       │ (Rasp Pi)   │    TCP/IP            │   Network    │
│              │                          │  + USB modem │                      │              │
│  RustChain   │                          │  + Dreampi   │                      │  Pool /      │
│  Miner       │                          │    software  │                      │  Full Node   │
└─────────────┘                           └─────────────┘                      └──────────────┘
```

---

## 2. Hardware Requirements

### 2.1 Required Hardware

| Component | Specification | Estimated Cost (USD) | Notes |
|---|---|---|---|
| **Sega Dreamcast** | Any region (NTSC-U, NTSC-J, PAL) | $40–80 | Ensure modem module is present |
| **Dreamcast Controller** | Standard controller | $10–15 | For navigating menus |
| **Dreamcast VMU** (optional) | Visual Memory Unit | $5–10 | For storing config, not strictly required |
| **Raspberry Pi** | Model 3B+, 4, or 5 | $35–55 | 1GB+ RAM recommended |
| **MicroSD Card** | 16GB+ Class 10 | $8–12 | For DreamPi OS image |
| **USB Modem** | Conexant-based, voice-capable | $15–30 | **Critical:** see compatible list below |
| **Phone Cable** | RJ-11, 2–6 ft | $3–5 | Standard landline cable |
| **Phone Line Simulator** | Viking DLE-200B or DIY | $20–40 | Provides dial tone & ring voltage |
| **Ethernet Cable** | Cat5e/Cat6 | $5 | Or use Pi's Wi-Fi (Pi 3B+/4/5) |
| **Power Supply** | 5V/3A USB-C (Pi 4/5) or micro-USB (Pi 3B+) | $10 | Official Pi PSU recommended |

### 2.2 Compatible USB Modems (Critical)

The USB modem is the most important hardware choice. **Not all USB modems work.** The DreamPi firmware relies on specific chipset behavior.

**Confirmed Working:**
- **Zoom 3095** — Conexant CX93001-based — **most recommended**
- **US Robotics USR5637** — Conexant-based — widely available
- **Trendnet TFM-561U** — Conexant-based
- **Creative Modem Blaster** (USB, Conexant chipset)
- **Generic Conexant CX93001** modems from eBay/AliExpress

**NOT Compatible:**
- Intel/Agere-based modems
- Prolific-based modems
- Rockwell-only chipsets (without Conexant compatibility)
- Any "soft modem" / "WinModem" that requires host-side DSP

**How to verify chipset:** On Linux, plug in the modem and run:
```bash
lsusb | grep -i modem
# Should show: Conexant Systems (Rockwell), Inc. or similar
dmesg | tail -20
# Should show: cdc_acm or acm driver attached
```

### 2.3 Phone Line Simulator Options

A phone line simulator is required to provide:
- **Dial tone** (350 Hz + 440 Hz)
- **Ring voltage** (90V AC, 20 Hz) — needed to signal "incoming call" to Dreamcast modem
- **Battery voltage** (48V DC loop) — for modem off-hook detection

**Option A: Viking DLE-200B (Recommended)**
- Commercial device, plug-and-play
- Provides dial tone, ring, and battery simulation
- Two RJ-11 jacks: one for DreamPi modem, one for Dreamcast modem

**Option B: Custom Asterisk PBX (Advanced)**
- Run Asterisk on the Raspberry Pi itself (or a second Pi)
- Use a USB FXS adapter (e.g., Obihai OBi110, Grandstream HT801)
- More configurable but complex

**Option C: DIY Phone Line Simulator**
- Build a circuit with a 48V DC supply (battery or boost converter)
- Add a 90V AC ring generator (NE555 + transformer or dedicated IC)
- **Warning:** Improper voltage can damage modems — proceed only if experienced

### 2.4 Network Requirements

- Internet connection (Ethernet or Wi-Fi)
- DNS resolution working on the Raspberry Pi
- Access to RustChain pool endpoints (typically port 8338 or custom)
- DHCP or static IP on the local network

---

## 3. DreamPi Setup (Raspberry Pi)

### 3.1 Flash the DreamPi Image

DreamPi is a specialized Raspberry Pi image that configures the Pi as a dial-up ISP server. It includes a PPP daemon, DHCP server, DNS forwarder, and connection automation.

```bash
# Step 1: Download the DreamPi image
# Visit: https://dreamcastlive.net/dreampi/
# Or direct download:
wget https://dreamcastlive.net/files/DreamPi_v1.7_DREAMPI.zip

# Step 2: Extract the image
unzip DreamPi_v1.7_DREAMPI.zip

# Step 3: Flash to SD card (replace /dev/sdX with your card)
# Using Raspberry Pi Imager (recommended):
#   - Select "Choose OS" → "Use custom" → select the .img file
#   - Select your SD card
#   - Write

# OR using dd (Linux/macOS):
sudo dd if=DreamPi_v1.7.img of=/dev/sdX bs=4M status=progress conv=fsync

# Step 4: Insert SD card into Raspberry Pi and boot
```

### 3.2 Initial DreamPi Configuration

```bash
# SSH into DreamPi (default: dreampi.local, user: pi, password: raspberry)
ssh pi@dreampi.local

# Update the system
sudo apt-get update && sudo apt-get upgrade -y

# Verify DreamPi service is running
sudo systemctl status dreampi

# Check the modem is detected
ls -la /dev/ttyACM0
# Should exist — this is the USB modem

# Test modem communication
echo "AT" > /dev/ttyACM0
cat /dev/ttyACM0
# Should respond "OK"
```

### 3.3 Configure Network

Edit `/etc/dhcpcd.conf` to ensure the Pi has network access:

```bash
sudo nano /etc/dhcpcd.conf

# Add or verify (for Ethernet):
interface eth0
static ip_address=192.168.1.100/24
static routers=192.168.1.1
static domain_name_servers=8.8.8.8 8.8.4.4

# For Wi-Fi:
interface wlan0
static ip_address=192.168.1.101/24
static routers=192.168.1.1
static domain_name_servers=8.8.8.8 8.8.4.4

# Restart networking
sudo systemctl restart dhcpcd

# Verify connectivity
ping -c 3 rustchain.network
```

### 3.4 Install Dependencies for RustChain Bridging

```bash
# Install additional packages needed for mining support
sudo apt-get install -y \
    ppp \
    pptpd \
    dnsmasq \
    iptables-persistent \
    socat \
    netcat-openbsd \
    python3 \
    python3-pip \
    git \
    screen \
    tmux

# Enable IP forwarding (critical for bridging dial-up to TCP/IP)
echo 'net.ipv4.ip_forward = 1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Configure NAT so dial-up clients can reach the internet/RustChain network
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i ppp0 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o ppp0 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

---

## 4. Dial-Up Infrastructure Configuration

### 4.1 Configure PPP (Point-to-Point Protocol)

The DreamPi uses PPP to establish the dial-up link. Configure the PPP server:

```bash
# Create PPP options file for incoming connections
sudo nano /etc/ppp/options.ttyACM0
```

Contents:
```
# PPP options for DreamPi modem
192.168.1.100:192.168.1.200
netmask 255.255.255.0
defaultroute
noipdefault
usepeerdns
noauth
local
lock
nocrtscts
modem
passive
asyncmap 0
mtu 1500
mru 1500
proxyarp
silent
```

```bash
# Configure the PPP authentication (chap-secrets)
sudo nano /etc/ppp/chap-secrets
```

Contents:
```
# Secrets for authentication using CHAP
# client    server    secret    IP addresses
dreamcast   *         dreamcast   *
```

### 4.2 Configure DreamPi Dial-In Service

```bash
# Create the DreamPi dial-in configuration
sudo nano /etc/dreampi/config.ini
```

Contents:
```ini
[modem]
device = /dev/ttyACM0
baud_rate = 115200
init_string = ATZ

[connection]
listen_port = 23
ppp_enabled = true
auto_answer = true
ring_count = 2

[dns]
primary = 8.8.8.8
secondary = 8.8.4.4

[logging]
level = INFO
file = /var/log/dreampi.log
```

### 4.3 Configure dnsmasq (DHCP + DNS for PPP clients)

```bash
sudo nano /etc/dnsmasq.conf
```

Add:
```
# Serve DNS to PPP clients
interface=ppp0
listen-address=192.168.1.100
bind-interfaces

# DHCP range for PPP clients
dhcp-range=192.168.1.200,192.168.1.250,12h

# DNS settings
server=8.8.8.8
server=8.8.4.4
cache-size=1000

# Resolve RustChain pool domains
# Add custom DNS entries if needed:
# address=/pool.rustchain.network/192.168.1.100
```

```bash
sudo systemctl restart dnsmasq
```

### 4.4 Phone Line Simulator Configuration

**If using Viking DLE-200B:**
1. Connect the DLE-200B's "Line 1" RJ-11 jack to the USB modem (via RJ-11 cable)
2. Connect the DLE-200B's "Line 2" RJ-11 jack to the Dreamcast modem (via RJ-11 cable)
3. Plug in the DLE-200B power supply
4. The device auto-generates dial tone and ring voltage

**If using Asterisk (advanced):**

```bash
sudo apt-get install -y asterisk

# Configure SIP trunk for local modem communication
sudo nano /etc/asterisk/sip.conf
```

Add:
```
[general]
context=internal
allowoverlap=no
udpbindaddr=0.0.0.0
tcpenable=no

[dreamcast](!)
type=friend
context=dial-in
host=dynamic
secret=dreamcast
dtmfmode=rfc2833
disallow=all
allow=ulaw
canreinvite=no

[fxo-line1](dreamcast)
; Configured for USB FXS adapter

[fxo-line2](dreamcast)
; Configured for Dreamcast side
```

```bash
sudo nano /etc/asterisk/extensions.conf
```

Add:
```
[internal]
exten => 100,1,Dial(SIP/fxo-line1,30)
exten => 100,n,Hangup()

[dial-in]
exten => _X.,1,Answer()
exten => _X.,n,Wait(1)
exten => _X.,n,Dial(SIP/fxo-line2,30)
exten => _X.,n,Hangup()

; Auto-answer for incoming calls from Dreamcast
exten => s,1,Answer()
exten => s,n,Wait(1)
exten => s,n,ppp(dreamcast,dreamcast)
exten => s,n,Hangup()
```

### 4.5 DreamPi Connection Script

Create the main connection handler:

```bash
sudo nano /usr/local/bin/dreampi-connect.sh
```

```bash
#!/bin/bash
# DreamPi Connection Handler for RustChain Mining
# Handles incoming Dreamcast calls and establishes PPP

MODEM_DEVICE="/dev/ttyACM0"
LOG_FILE="/var/log/dreampi-connect.log"
PPP_PEER="dreampi"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

init_modem() {
    log "Initializing modem..."
    
    # Reset modem
    echo -e "ATZ\r" > "$MODEM_DEVICE"
    sleep 1
    
    # Set registers for auto-answer
    echo -e "ATS0=2\r" > "$MODEM_DEVICE"    # Auto-answer after 2 rings
    sleep 0.5
    echo -e "ATE0\r" > "$MODEM_DEVICE"      # Disable echo
    sleep 0.5
    echo -e "ATV1\r" > "$MODEM_DEVICE"      # Verbose result codes
    sleep 0.5
    echo -e "AT+MS=V34\r" > "$MODEM_DEVICE" # Force V.34 (33.6K) for reliability
    
    log "Modem initialized and waiting for calls..."
}

handle_connection() {
    log "Incoming call detected! Starting PPP..."
    
    # Start PPP daemon for the incoming connection
    /usr/sbin/pppd "$MODEM_DEVICE" 115200 \
        192.168.1.100:192.168.1.200 \
        noauth \
        local \
        lock \
        nocrtscts \
        modem \
        passive \
        defaultroute \
        mtu 1500 \
        mru 1500 \
        proxyarp \
        nodefaultroute \
        ms-dns 8.8.8.8 \
        ms-dns 8.8.4.4 \
        &
    
    PPP_PID=$!
    log "PPP started (PID: $PPP_PID)"
    
    # Wait for PPP to establish
    sleep 5
    
    # Verify PPP interface
    if ip addr show ppp0 &>/dev/null; then
        log "PPP link established successfully!"
        log "Dreamcast IP: 192.168.1.200"
        log "Gateway: 192.168.1.100"
    else
        log "ERROR: PPP link failed to establish!"
        kill $PPP_PID 2>/dev/null
        return 1
    fi
}

monitor_connection() {
    while true; do
        if ! ip addr show ppp0 &>/dev/null; then
            log "PPP link lost, reinitializing modem..."
            init_modem
        fi
        sleep 30
    done
}

# Main execution
log "=== DreamPi Connection Handler Started ==="
init_modem

# Monitor for incoming connections
while true; do
    # Read modem responses
    RESPONSE=$(timeout 60 cat "$MODEM_DEVICE" 2>/dev/null)
    
    if echo "$RESPONSE" | grep -q "CONNECT"; then
        handle_connection
    elif echo "$RESPONSE" | grep -q "RING"; then
        log "Ring detected..."
    fi
    
    sleep 1
done
```

```bash
sudo chmod +x /usr/local/bin/dreampi-connect.sh
```

---

## 5. RustChain Mining Software on Dreamcast

### 5.1 Overview of Dreamcast RustChain Miner

The RustChain miner for Dreamcast is a homebrew application that:
1. Establishes a TCP connection through the PPP dial-up link
2. Connects to a RustChain mining pool or solo node
3. Receives mining jobs (block headers to hash)
4. Computes SHA-256 / RustChain-specific hashes using the SH-4 FPU
5. Submits valid shares back to the pool

### 5.2 Building the Miner (Cross-Compilation)

The Dreamcast miner is cross-compiled on a Linux PC using the **KallistiOS (KOS)** toolchain, then burned to a CD-R or loaded via SD card adapter.

```bash
# On your development PC (NOT the DreamPi):

# Install KallistiOS toolchain
git clone https://github.com/KallistiOS/KallistiOS.git
cd KallistiOS
git clone https://github.com/KallistiOS/kos-ports.git

# Set up environment
export KOS_ROOT=/path/to/KallistiOS
export PATH="$KOS_ROOT/toolchain/bin:$PATH"

# Edit environ.sh for your setup
cp doc/environ.sample.sh environ.sh
nano environ.sh
# Set KOS_ARCH=sh4, KOS_SUBARCH=naomi (for Dreamcast)

# Build the toolchain (requires build-essential, texinfo, etc.)
make
```

```bash
# Clone the RustChain Dreamcast miner
git clone https://github.com/rustchain-ecosystem/rustchain-dreamcast-miner.git
cd rustchain-dreamcast-miner

# Configure for Dreamcross build
export KOS_ROOT=/path/to/KallistiOS
source $KOS_ROOT/environ.sh

# Build the miner (produces a .elf and .bin)
make clean
make

# Generate bootable CDI image
make cdi
# Output: rustchain-miner.cdi
```

### 5.3 Miner Configuration File

Create a config file that gets embedded or loaded from VMU:

```ini
# rustchain-miner.cfg
# Stored on VMU or burned alongside the binary

[pool]
host = pool.rustchain.network
port = 8338
# OR for solo mining:
# host = 192.168.1.100
# port = 8332
worker = dreamcast_worker_01
password = x

[network]
# Dial-up settings
dial_number = 5551234
# (This number is answered by the DreamPi line simulator)
auth_user = dreamcast
auth_pass = dreamcast
dns_server = 8.8.8.8

[mining]
# Hash algorithm: rustchain-sha256d (default)
algorithm = rustchain-sha256d
# Thread count (SH-4 has limited threading, usually 1)
threads = 1
# Batch size: number of nonces per report cycle
batch_size = 1024
# Status report interval in seconds
report_interval = 30

[hardware]
# SH-4 clock speed (use 200 for stock, up to 240 for overclock)
cpu_mhz = 200
# Enable FPU acceleration
fpu_enabled = true
# Cache optimization
cache_prefetch = true
```

### 5.4 Burning the Miner to CD-R

```bash
# Using cdi4dc (CDI image builder for Dreamcast)
# Install: pip install cdi4dc

# Method 1: Self-booting CDI
# The Makefile 'make cdi' already produces a self-booting image

# Method 2: Using BootDreams (Windows)
# Load rustchain-miner.cdi → Burn to CD-R at 4x speed

# Method 3: SD card adapter (GDEMU, MODE, etc.)
# Copy the .bin and .elf to the SD card in the correct folder structure:
mkdir -p /sdcard/01_rustchain_miner/
cp rustchain-miner.bin /sdcard/01_rustchain_miner/1ST_READ.BIN
```

### 5.5 Alternative: Loading via DreamShell

If you have DreamShell installed (via SD card adapter):

```bash
# Copy miner files to SD card
cp rustchain-miner.bin /sdcard/apps/rustchain/1ST_READ.BIN
cp rustchain-miner.cfg /sdcard/apps/rustchain/config.cfg

# Launch DreamShell on Dreamcast
# Navigate to Apps → RustChain Miner → Launch
```

---

## 6. Step-by-Step Assembly & Configuration

### Phase 1: Prepare the DreamPi

**Step 1.1:** Flash DreamPi image to SD card
```bash
# Download DreamPi image
wget https://dreamcastlive.net/files/DreamPi_v1.7_DREAMPI.zip
unzip DreamPi_v1.7_DREAMPI.zip

# Flash (use Raspberry Pi Imager or dd)
sudo dd if=DreamPi_v1.7.img of=/dev/sdX bs=4M status=progress
```

**Step 1.2:** Insert SD card into Raspberry Pi

**Step 1.3:** Connect USB modem to Raspberry Pi

**Step 1.4:** Connect Ethernet cable from Pi to your router

**Step 1.5:** Power on the Raspberry Pi

**Step 1.6:** Wait 2 minutes for boot, then SSH in:
```bash
ssh pi@dreampi.local
# Password: raspberry
```

**Step 1.7:** Verify modem detection:
```bash
ls -la /dev/ttyACM0
echo "AT" | sudo tee /dev/ttyACM0
# Should get "OK" response
```

**Step 1.8:** Update DreamPi software:
```bash
sudo apt-get update && sudo apt-get upgrade -y
```

### Phase 2: Configure Dial-Up Infrastructure

**Step 2.1:** Configure PPP (see Section 4.1)

**Step 2.2:** Configure dnsmasq (see Section 4.3)

**Step 2.3:** Set up iptables NAT (see Section 3.4)

**Step 2.4:** Install and configure DreamPi connect script (see Section 4.5)

**Step 2.5:** Create systemd service for auto-start:
```bash
sudo nano /etc/systemd/system/dreampi-connect.service
```

```ini
[Unit]
Description=DreamPi Connection Handler for RustChain Mining
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dreampi-connect.sh
Restart=always
RestartSec=5
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable dreampi-connect.service
sudo systemctl start dreampi-connect.service

# Check status
sudo systemctl status dreampi-connect.service
```

### Phase 3: Set Up Phone Line

**Step 3.1:** Connect phone line simulator between DreamPi modem and Dreamcast modem:

```
[USB Modem] ←RJ-11→ [DLE-200B Line 1] ←RJ-11→ [DLE-200B Line 2] ←RJ-11→ [Dreamcast Modem]
     ↑                        ↑
  Connected to              Powered on,
  Raspberry Pi              generating dial tone
```

**Step 3.2:** Verify dial tone:
- Pick up an analog phone connected to the line simulator
- You should hear a dial tone
- If using DLE-200B: the LED should indicate line active

**Step 3.3:** Test the line from Dreamcast side:
- Boot Dreamcast with a web browser disc (e.g., PlanetWeb)
- Go to connection settings
- Set phone number to: `5551234` (any number — the line simulator answers)
- Set login: `dreamcast` / password: `dreamcast`
- Attempt connection — should hear dialing, then connect sounds

### Phase 4: Compile and Deploy Miner

**Step 4.1:** On your development PC, build the miner (see Section 5.2)

**Step 4.2:** Create config file (see Section 5.3)

**Step 4.3:** Burn to CD-R or copy to SD card (see Section 5.4)

### Phase 5: First Mining Session

**Step 5.1:** Ensure DreamPi is running and modem is waiting:
```bash
# On DreamPi:
sudo systemctl status dreampi-connect
tail -f /var/log/dreampi-connect.log
```

**Step 5.2:** Insert miner CD into Dreamcast (or select from SD menu)

**Step 5.3:** Power on Dreamcast

**Step 5.4:** The miner will:
1. Display a splash screen with RustChain logo
2. Load configuration
3. Initialize the modem (AT commands)
4. Dial the DreamPi
5. Establish PPP connection
6. Resolve pool hostname via DNS
7. Connect to mining pool
8. Begin hashing

**Step 5.5:** Monitor on Dreamcast TV output:
```
RustChain Dreamcast Miner v1.0
═══════════════════════════════
Status: CONNECTED
Pool:   pool.rustchain.network:8338
Worker: dreamcast_worker_01

Speed:      1.2 KH/s
Shares:     0 / 0
Uptime:     00:02:34

Current Job:
  Height: 284,721
  Diff:   65,536
  Nonce:  0x000A3F22
```

**Step 5.6:** Monitor from DreamPi (network side):
```bash
# Watch PPP connection
watch -n 1 'ifconfig ppp0'

# Monitor traffic
sudo tcpdump -i ppp0 -n

# Check DreamPi logs
tail -f /var/log/dreampi-connect.log
```

---

## 7. Running Your First Mining Session

### 7.1 Solo Mining Setup

For solo mining, you need a RustChain full node running on your DreamPi or another machine:

```bash
# On DreamPi or a separate server:
# Install RustChain node
git clone https://github.com/rustchain-ecosystem/rustchain-node.git
cd rustchain-node
cargo build --release

# Run the node
./target/release/rustchaind \
    --rpc-bind 0.0.0.0:8332 \
    --enable-mining \
    --mining-address YOUR_WALLET_ADDRESS

# Configure miner config to point to local node:
# [pool]
# host = 192.168.1.100
# port = 8332
```

### 7.2 Pool Mining Setup

For pool mining (recommended for beginners):

```bash
# Register at a RustChain mining pool
# Example: https://pool.rustchain.network

# Configure miner:
# [pool]
# host = pool.rustchain.network
# port = 8338
# worker = YOUR_USERNAME.dreamcast_01
# password = x
```

### 7.3 Expected Performance

| Metric | Expected Value |
|---|---|
| **Hash Rate** | 1.0–1.5 KH/s (SHA-256d) |
| **Power Draw** | ~15W (Dreamcast) + ~5W (DreamPi) + ~2W (line simulator) |
| **Bandwidth** | ~3–4 KB/s (well within 33.6K modem capacity) |
| **Latency** | ~200–500ms per share submission |
| **Daily Shares** | ~800–1,200 (pool dependent) |
| **Block Probability** | Extremely low (solo) — pool mining recommended |

### 7.4 Monitoring Dashboard

Set up a simple web dashboard on the DreamPi:

```bash
# Install a simple web server
sudo apt-get install -y lighttpd

# Create dashboard
sudo nano /var/www/html/index.html
```

```html
<!DOCTYPE html>
<html>
<head>
    <title>RustChain Dreamcast Mining Dashboard</title>
    <meta http-equiv="refresh" content="10">
    <style>
        body { background: #1a1a2e; color: #0f3460; font-family: monospace; }
        .stats { background: #16213e; padding: 20px; margin: 10px; border-radius: 8px; }
        h1 { color: #e94560; text-align: center; }
        .metric { color: #00d2ff; font-size: 1.2em; }
        .value { color: #e94560; font-size: 1.5em; }
    </style>
</head>
<body>
    <h1>🎮 RustChain Dreamcast Miner</h1>
    <div class="stats">
        <p class="metric">Connection: <span class="value" id="status">Checking...</span></p>
        <p class="metric">Hash Rate: <span class="value" id="hashrate">--</span></p>
        <p class="metric">Shares: <span class="value" id="shares">--</span></p>
        <p class="metric">Uptime: <span class="value" id="uptime">--</span></p>
    </div>
    <script>
        // Poll stats from DreamPi local API
        fetch('/api/stats').then(r=>r.json()).then(d=>{
            document.getElementById('status').textContent = d.connected ? 'ONLINE' : 'OFFLINE';
            document.getElementById('hashrate').textContent = d.hashrate + ' KH/s';
            document.getElementById('shares').textContent = d.shares;
            document.getElementById('uptime').textContent = d.uptime;
        }).catch(()=>{});
    </script>
</body>
</html>
```

---

## 8. Performance Tuning

### 8.1 Dreamcast Optimizations

**Overclock the SH-4 (Advanced — requires hardware mod):**
- Stock: 200 MHz → Overclock: 240 MHz (+20% hash rate)
- Requires replacing the crystal oscillator or using a PLL mod board
- **Warning:** May cause instability and overheating

**FPU Optimization in Miner Code:**
```c
// Enable SH-4 FPU for hash computation
// In the miner's KOS initialization:
#include <arch/fpu.h>

void enable_fpu() {
    // Set FPSCR for single-precision mode (faster)
    unsigned int fpscr = __builtin_sh_get_fpscr();
    fpscr &= ~(1 << 20);  // Clear PR bit (double precision)
    __builtin_sh_set_fpscr(fpscr);
    
    // Enable flush-to-zero mode (denormals are zero)
    fpscr |= (1 << 24);   // Set DN bit
    __builtin_sh_set_fpscr(fpscr);
}
```

**Cache Optimization:**
```c
// Prefetch hash data into SH-4 cache
void prefetch_block(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i += 32) {
        __builtin_prefetch(data + i, 0, 3);
    }
}
```

### 8.2 DreamPi Optimizations

**Reduce PPP overhead:**
```bash
# In /etc/ppp/options.ttyACM0, add:
novj              # Disable Van Jacobson compression
nopcomp           # Disable protocol field compression
noaccomp          # Disable address/control compression
mtu 576           # Smaller MTU = less buffering
mru 576
```

**Increase modem buffer:**
```bash
# Set modem buffer size
echo "AT+CBST=7,0,1" > /dev/ttyACM0  # V.34, async
echo "AT+MR=1" > /dev/ttyACM0          # Enable modulation reporting
echo "AT+ES=6,6,4" > /dev/ttyACM0      # Error control settings
```

### 8.3 Network Optimizations

**Keep-alive to prevent PPP timeout:**
```bash
# In /etc/ppp/options.ttyACM0:
lcp-echo-interval 30
lcp-echo-failure 3
```

**DNS caching:**
```bash
# Already handled by dnsmasq, but ensure cache is warm:
sudo systemctl restart dnsmasq
# Pre-resolve pool domains:
dig pool.rustchain.network @127.0.0.1
```

---

## 9. Troubleshooting

### 9.1 Common Issues and Solutions

#### Problem: Dreamcast doesn't detect dial tone

**Symptoms:** Dreamcast modem reports "No dial tone" error

**Solutions:**
1. Check RJ-11 cable connections — ensure both ends are firmly seated
2. Verify phone line simulator is powered on
3. Test with an analog phone: pick up and listen for dial tone
4. Check modem init string: try `ATX1` to ignore dial tone detection
5. If using DLE-200B, check that the "LINE" LED is illuminated

```bash
# Force modem to ignore dial tone (on DreamPi):
echo -e "ATX1\r" > /dev/ttyACM0
```

#### Problem: Dreamcast dials but connection fails

**Symptoms:** Dialing sounds heard, but "No answer" or "Connection failed"

**Solutions:**
1. Verify DreamPi connect script is running:
   ```bash
   sudo systemctl status dreampi-connect
   ```
2. Check modem is in auto-answer mode:
   ```bash
   echo -e "ATS0?\r" > /dev/ttyACM0
   # Should return S0: 002 (auto-answer after 2 rings)
   ```
3. Increase ring wait time on DreamPi:
   ```bash
   echo -e "ATS0=1\r" > /dev/ttyACM0  # Answer after 1 ring
   ```
4. Check for modem conflicts:
   ```bash
   sudo fuser /dev/ttyACM0
   # Should show only the DreamPi process
   ```

#### Problem: PPP negotiation fails

**Symptoms:** Modem connects, but no IP address assigned

**Solutions:**
1. Check PPP configuration:
   ```bash
   sudo pppd /dev/ttyACM0 115200 debug nodetach
   # Look for errors in output
   ```
2. Verify chap-secrets:
   ```bash
   cat /etc/ppp/chap-secrets
   # Ensure dreamcast * dreamcast * is present
   ```
3. Check IP forwarding:
   ```bash
   cat /proc/sys/net/ipv4/ip_forward
   # Should be 1
   ```
4. Verify iptables NAT:
   ```bash
   sudo iptables -t nat -L -v
   # Should show MASQUERADE rule for eth0
   ```

#### Problem: Can connect but can't reach RustChain pool

**Symptoms:** PPP established, but DNS fails or pool connection times out

**Solutions:**
1. Test DNS from DreamPi:
   ```bash
   ping -I ppp0 8.8.8.8
   nslookup pool.rustchain.network
   ```
2. Check firewall:
   ```bash
   sudo iptables -L -v
   # Ensure FORWARD chain allows ppp0 ↔ eth0
   ```
3. Test from Dreamcast: use the miner's built-in network test
4. If behind a restrictive router, set up port forwarding or use a VPN:
   ```bash
   # On DreamPi, set up a SOCKS proxy:
   ssh -D 1080 user@your_vpn_server &
   ```

#### Problem: Miner crashes or hangs on Dreamcast

**Symptoms:** Black screen, freeze, or reset after mining starts

**Solutions:**
1. **Memory issue:** Ensure no other apps are loaded. Dreamcast has only 16MB RAM + 8MB VRAM
2. **Overheating:** Add heatsinks to SH-4 and check ventilation
3. **Power supply:** Ensure official Dreamcast PSU; third-party PSUs may be unstable
4. **Disc read error:** Re-burn CD-R at the slowest speed (1x or 2x)
5. **Clock instability:** If overclocked, revert to stock 200 MHz

#### Problem: Very low hash rate (< 0.5 KH/s)

**Solutions:**
1. Ensure FPU is enabled in miner config: `fpu_enabled = true`
2. Check that `cache_prefetch = true` is set
3. Verify SH-4 clock speed: `cpu_mhz = 200`
4. Reduce batch_size if network latency is causing timeouts: `batch_size = 512`

#### Problem: DreamPi USB modem not detected

```bash
# Check USB devices
lsusb
# Look for Conexant device

# Check kernel messages
dmesg | grep -i modem
dmesg | grep -i ttyACM

# If not detected, try:
sudo rmmod cdc_acm && sudo modprobe cdc_acm

# If still not working:
# 1. Try a different USB port (USB 2.0 preferred)
# 2. Try a powered USB hub
# 3. The modem may be incompatible — check Section 2.2
```

### 9.2 Debug Commands Reference

```bash
# DreamPi debug toolkit:

# Modem communication test
screen /dev/ttyACM0 115200
# Type AT and press Enter — should get OK
# Press Ctrl+A, then K to exit

# PPP debug mode
sudo pppd /dev/ttyACM0 115200 debug nodetach noauth

# Network connectivity
ping -c 3 8.8.8.8
traceroute pool.rustchain.network
curl -v https://pool.rustchain.network

# Service logs
sudo journalctl -u dreampi-connect -f
sudo journalctl -u dreampi -f

# System resources
htop
df -h
free -m

# Modem AT command reference
echo -e "ATI\r" > /dev/ttyACM0      # Modem info
echo -e "ATI3\r" > /dev/ttyACM0     # Firmware version
echo -e "AT&V\r" > /dev/ttyACM0     # Current configuration
echo -e "AT+MS?\r" > /dev/ttyACM0   # Modulation settings
```

### 9.3 Log Locations

| Log | Location | Contents |
|---|---|---|
| DreamPi Connection | `/var/log/dreampi-connect.log` | Dial-up connection events |
| DreamPi Service | `journalctl -u dreampi` | DreamPi daemon output |
| PPP Log | `/var/log/ppp.log` | PPP negotiation details |
| System Log | `/var/log/syslog` | General system messages |
| Kernel/USB | `dmesg` | USB modem detection |

---

## 10. Appendices

### Appendix A: Bill of Materials (Complete Shopping List)

| # | Item | Source | Price |
|---|---|---|---|
| 1 | Sega Dreamcast (with modem) | eBay, local retro game shop | $50 |
| 2 | Dreamcast controller | eBay | $12 |
| 3 | Raspberry Pi 4 (2GB) | raspberrypi.com, Amazon | $45 |
| 4 | MicroSD card 32GB | Amazon | $10 |
| 5 | USB-C power supply (Pi 4) | Amazon | $12 |
| 6 | Zoom 3095 USB modem | eBay, Amazon | $20 |
| 7 | Viking DLE-200B line simulator | Amazon, eBay | $30 |
| 8 | RJ-11 phone cable (2-pack) | Amazon | $5 |
| 9 | Ethernet cable 6ft | Amazon | $5 |
| 10 | CD-R blanks (for miner) | Amazon | $5 |
| | **Total** | | **~$194** |

### Appendix B: RustChain Pool Endpoints

| Pool | URL | Port | Fee |
|---|---|---|---|
| RustChain Official | pool.rustchain.network | 8338 | 1% |
| DreamPool (community) | dreampool.rustchain.network | 8338 | 0.5% |
| Solo (local node) | 192.168.1.100 | 8332 | 0% |

### Appendix C: Modem AT Command Quick Reference

| Command | Function |
|---|---|
| `ATZ` | Reset modem to defaults |
| `ATS0=n` | Auto-answer after n rings |
| `ATE0/E1` | Disable/enable echo |
| `ATV0/V1` | Numeric/verbose result codes |
| `ATX1` | Ignore dial tone detection |
| `AT+MS=V34` | Force V.34 modulation |
| `ATDT<number>` | Dial tone (touch-tone) |
| `ATH` | Hang up |
| `ATO` | Return to online mode |
| `+++` | Escape to command mode (1s pause before/after) |

### Appendix D: Network Topology Diagram

```
                          ┌──────────────────┐
                          │   Internet        │
                          │   (RustChain      │
                          │    Network)       │
                          └────────┬─────────┘
                                   │ Ethernet
                          ┌────────┴─────────┐
                          │   Home Router     │
                          │   192.168.1.1     │
                          └────────┬─────────┘
                                   │ Ethernet
                    ┌──────────────┴──────────────┐
                    │       Raspberry Pi           │
                    │       (DreamPi)              │
                    │       192.168.1.100          │
                    │                              │
                    │  ┌─────────┐  ┌───────────┐ │
                    │  │ PPP     │  │ dnsmasq   │ │
                    │  │ Server  │  │ (DHCP/DNS)│ │
                    │  └────┬────┘  └───────────┘ │
                    │       │                      │
                    │  ┌────┴────┐                 │
                    │  │USB Modem│                 │
                    │  │(ttyACM0)│                 │
                    └──────┬──────────────────────┘
                           │ RJ-11
                    ┌──────┴──────────┐
                    │  Phone Line     │
                    │  Simulator      │
                    │  (DLE-200B)     │
                    └──────┬──────────┘
                           │ RJ-11
                    ┌──────┴──────────────────────┐
                    │     Sega Dreamcast           │
                    │     192.168.1.200            │
                    │                              │
                    │  ┌──────────┐  ┌──────────┐ │
                    │  │ 56K Modem│  │ SH-4 CPU │ │
                    │  │ (Maple)  │  │ (200MHz) │ │
                    │  └──────────┘  └──────────┘ │
                    │                              │
                    │  ┌──────────────────────┐   │
                    │  │  RustChain Miner     │   │
                    │  │  (CD-R / SD Card)    │   │
                    │  └──────────────────────┘   │
                    │                              │
                    │  TV ◄─── Video Output        │
                    └──────────────────────────────┘
```

### Appendix E: Security Considerations

1. **Network Isolation:** Consider placing the Dreamcast mining setup on a separate VLAN
2. **Firewall Rules:** Only allow outbound connections from DreamPi to pool endpoints
3. **Wallet Security:** Do not store wallet keys on the DreamPi; use a separate secure machine
4. **Firmware Updates:** Keep DreamPi OS updated for security patches
5. **Physical Security:** The DreamPi and Dreamcast have no built-in encryption; the PPP link is unencrypted. For additional security, tunnel through a VPN or SSH from the DreamPi.

### Appendix F: Alternative Configurations

**Configuration 1: Multiple Dreamcasts (Mining Farm)**
- Use a multi-line phone simulator (e.g., Viking DLE-200B × N)
- Run multiple USB modems on the Pi (one per Dreamcast)
- Use `udev` rules to assign consistent device names

**Configuration 2: Dreamcast over Internet (Long Distance)**
- Use an Asterisk PBX with VoIP trunks
- Dreamcast calls over SIP to a remote DreamPi
- Requires a VoIP ATA (Analog Telephone Adapter) on the Dreamcast side

**Configuration 3: BBA (Broadband Adapter) Instead of Modem**
- If you have a Dreamcast BBA (HIT-400), skip dial-up entirely
- Connect Dreamcast directly to Ethernet
- Much higher throughput (10 Mbps vs 33.6 Kbps)
- **Note:** BBA is rare (~$100+) and mining performance is CPU-bound, not network-bound

---

## License

This document is released under the **MIT License** as part of the RustChain ecosystem.

## Acknowledgments

- **DreamPi Project** — https://dreamcastlive.net/dreampi/
- **KallistiOS** — https://github.com/KallistiOS/KallistiOS
- **Dreamcast Live Community** — For preserving Dreamcast online capabilities
- **RustChain Team** — For making retro mining a reality
- **The Homebrew Community** — For keeping the Dreamcast alive in 2026

---

*Happy mining! May your SH-4 hashes find blocks. 🎮⛏️*
