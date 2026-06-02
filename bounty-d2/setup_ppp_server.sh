#!/bin/bash
#
# ==============================================================================
# Dial-Up Island: Hardened PPP Server Setup (Bounty D2)
# ==============================================================================
#
# This script configures a hardened PPP daemon (pppd) for the RustChain
# dial-up island project. It implements the requirements for bounty D2:
#
#   - PPP server setup using pppd.
#   - Hardened configuration for vintage clients.
#   - MTU set to 576 for maximum compatibility.
#   - TCP MSS clamping to prevent fragmentation issues.
#   - Network isolation for connected clients using iptables.
#
# This script is designed for Debian-based Linux distributions (e.g., 
# Raspberry Pi OS, Debian, Ubuntu). It uses 'apt-get' for package
# management and 'iptables-persistent' for firewall rules.
#
# Wallet: RTC_WALLET_ADDRESS_PLACEHOLDER
# Bounty: D2
#

# --- Configuration ---

# IP address of the server on the PPP link
SERVER_IP="10.99.99.1"

# IP address range to assign to dial-in clients
CLIENT_IP_RANGE="10.99.99.100-200"

# Primary and secondary DNS servers for clients
DNS1="1.1.1.1"
DNS2="1.0.0.1"

# Network interface for the PPP connections (e.g., ppp0, ppp1, ...)
PPP_INTERFACE="ppp+"

# Port for ENiGMA-1/2 BBS (default telnet)
BBS_PORT="8888"
# Port for RustChain miner gateway
MINER_GATEWAY_PORT="3030" # Placeholder

# --- Script Body ---

set -e
trap 'echo "An error occurred. Aborting setup."; exit 1' ERR

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root. Please use sudo." >&2
  exit 1
fi

echo "--- [1/4] Installing required packages ---"
if ! command -v pppd &> /dev/null; then
    echo "pppd not found. Installing ppp..."
    apt-get update
    apt-get install -y ppp
else
    echo "ppp package is already installed."
fi

if ! command -v iptables &> /dev/null; then
    echo "iptables not found. Installing..."
    apt-get update
    apt-get install -y iptables
else
    echo "iptables is already installed."
fi

echo "Installing iptables-persistent to save firewall rules..."
# Pre-seed debconf to avoid interactive prompts
echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
apt-get install -y iptables-persistent

echo "--- [2/4] Configuring PPP daemon (pppd) ---"

# Create main pppd options file
cat << EOF > /etc/ppp/options
# /etc/ppp/options - Global PPP configuration for Dial-Up Island (Bounty D2)

# Use hardware flow control & modem control lines
crtscts
modem
# Lock the serial device
lock

# Set a compatible MTU for vintage systems
mtu 576
mru 576

# Asynchronous Control Character Map. 0 means escape all control characters.
asyncmap 0

# Be a server and answer for hosts on the other side of the link
proxyarp

# Enable LCP echo-requests to detect a dropped link
lcp-echo-interval 30
lcp-echo-failure 4

# DNS Servers for clients
ms-dns ${DNS1}
ms-dns ${DNS2}

# Require authentication. mgetty+login is preferred, but this provides a fallback.
auth
require-chap
# or require-pap

# Log everything for debugging
#debug
#dump
logfile /var/log/pppd.log

# Disable compression protocols; many vintage clients have buggy implementations
nobsdcomp
nodeflate
novj
novjccomp
nopcomp
noaccomp

# Kernel-level PPP debugging.
# Not recommended for continuous production operation due to high log volume
# and potential info exposure. Uncomment for initial setup/troubleshooting.
# kdebug 1
EOF

echo "Created /etc/ppp/options."

# Create a per-tty options file if one doesn't exist. This is how pppd knows
# which IP addresses to assign. mgetty can also pass these on the command line.
if [ ! -f /etc/ppp/options.ttyS0 ]; then
    cat << EOF > /etc/ppp/options.ttyS0
# /etc/ppp/options.ttyS0 - Sample per-line configuration for serial port ttyS0
# Server IP : Client IP Range (or single IP)
${SERVER_IP}:${CLIENT_IP_RANGE}

# Note for multi-line operations (Bounty D11 consideration):
# If configuring multiple serial ports (e.g., ttyS0, ttyS1, etc.),
# each options.ttySx file should typically define a unique client IP range
# to avoid conflicts and allow for proper client separation and logging.
EOF
    echo "Created sample /etc/ppp/options.ttyS0 as an example."
fi

# Setup authentication file securely
CHAP_SECRETS_FILE="/etc/ppp/chap-secrets"
if [ ! -f "${CHAP_SECRETS_FILE}" ] || [ -z "$(grep -v '^\s*#' "${CHAP_SECRETS_FILE}" | head -n 1)" ]; then
    echo ""
    echo "--- Setting up CHAP authentication secrets ---"
    echo "For a hardened setup, a default hardcoded secret is not used."
    echo "Please provide a username and password for the first PPP client."
    echo "This entry will be added to ${CHAP_SECRETS_FILE}."
    
    read -rp "Enter desired username for PPP client: " CHAP_USER
    
    while true; do
        read -rsp "Enter a secure password for '${CHAP_USER}': " CHAP_PASS1
        echo
        read -rsp "Confirm password: " CHAP_PASS2
        echo
        if [ "$CHAP_PASS1" = "$CHAP_PASS2" ]; then
            if [ -z "$CHAP_PASS1" ]; then
                echo "Password cannot be empty. Please try again."
            else
                break
            fi
        else
            echo "Passwords do not match. Please try again."
        fi
    done
    
    # Ensure the directory exists
    mkdir -p "$(dirname "${CHAP_SECRETS_FILE}")"
    
    # Write the new entry, creating the file if it doesn't exist
    if [ ! -f "${CHAP_SECRETS_FILE}" ]; then
        echo "# Secrets for CHAP authentication" > "${CHAP_SECRETS_FILE}"
        echo "# client        server  secret                  IP addresses" >> "${CHAP_SECRETS_FILE}"
    fi
    echo "\"${CHAP_USER}\"         *       \"${CHAP_PASS1}\"               *" >> "${CHAP_SECRETS_FILE}"
    chmod 600 "${CHAP_SECRETS_FILE}" # Secure permissions
    
    echo "Added user '${CHAP_USER}' to ${CHAP_SECRETS_FILE}."
    echo "Remember to manually add more users to ${CHAP_SECRETS_FILE} if needed."
else
    echo "CHAP secrets file ${CHAP_SECRETS_FILE} already exists and contains entries."
    echo "Skipping automatic creation of default user to preserve existing configuration."
    echo "Please manage PPP users manually in ${CHAP_SECRETS_FILE}."
fi


echo "--- [3/4] Configuring network and firewall (iptables) ---"

# Enable IP forwarding
echo "Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 > /dev/null # Suppress output
# Make it persistent
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi

echo "Setting up iptables rules for isolation and MSS clamping..."

# Flush existing FORWARD chain
iptables -F FORWARD

# Set default policy to DROP for FORWARD chain
iptables -P FORWARD DROP

# --- FORWARD Chain Rules ---
# Allow established and related traffic to continue
iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Allow NEW traffic from clients ONLY to specific services
# Allow access to the BBS server
iptables -A FORWARD -i ${PPP_INTERFACE} -p tcp --dport ${BBS_PORT} -j ACCEPT

# Allow access to the Miner Gateway
iptables -A FORWARD -i ${PPP_INTERFACE} -p tcp --dport ${MINER_GATEWAY_PORT} -j ACCEPT

# Allow access to external DNS servers
iptables -A FORWARD -i ${PPP_INTERFACE} -d ${DNS1} -p udp --dport 53 -j ACCEPT
iptables -A FORWARD -i ${PPP_INTERFACE} -d ${DNS2} -p udp --dport 53 -j ACCEPT

# *** CLIENT ISOLATION ***
# Explicitly drop traffic between PPP clients. This rule prevents clients
# from attacking each other.
iptables -A FORWARD -i ${PPP_INTERFACE} -o ${PPP_INTERFACE} -j DROP

# *** MSS CLAMPING ***
# Clamp TCP MSS to a safe value (MTU - 40 bytes) to avoid fragmentation
# on the low-MTU link. 576 - 40 = 536.
iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 536

# Log any other packets that hit the end of the FORWARD chain before
# being implicitly dropped by the default policy.
iptables -A FORWARD -j LOG --log-prefix "FORWARD: About to be dropped by policy: " --log-level 7

echo "Saving iptables rules..."
netfilter-persistent save

echo "--- [4/4] Finalizing ---"
echo "Restarting services..."
systemctl restart netfilter-persistent.service

echo ""
echo "========================================================"
echo "✅ Bounty D2 Setup Complete!"
echo "========================================================"
echo ""
echo "What was done:"
echo "  - ppp and iptables-persistent packages installed/verified."
echo "  - /etc/ppp/options configured for vintage hardware (MTU 576)."
echo "  - CHAP user configured in /etc/ppp/chap-secrets (or notified to manage manually)."
echo "  - IP forwarding enabled."
echo "  - iptables rules loaded and made persistent:"
echo "    - Default FORWARD policy is DROP."
echo "    - Clients are isolated from each other."
echo "    - Clients can only access the BBS (${BBS_PORT}), Miner Gateway (${MINER_GATEWAY_PORT}), and DNS."
echo "    - TCP MSS clamping is active to prevent fragmentation (MSS 536)."
echo "    - Dropped FORWARD packets are logged for debugging/monitoring."
echo ""
echo "Next steps:"
echo "  - Configure mgetty to listen on your serial port(s) and launch"
echo "    pppd for authenticated users (e.g., using 'AutoPPP' in login.config)."
echo "  - If you need more PPP users, manually add them to /etc/ppp/chap-secrets."
echo "  - For debugging PPP kernel issues, temporarily uncomment 'kdebug 1' in /etc/ppp/options."
echo "  - If configuring multiple serial lines, ensure unique IP ranges for each ttySx in /etc/ppp/options.ttySx."
echo ""
