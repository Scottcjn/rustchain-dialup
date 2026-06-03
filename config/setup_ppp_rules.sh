#!/usr/bin/env bash
# Setup script to configure hardened pppd options and network isolation rules.
# Part of Bounties D2 & D3 implementation for RustChain Dial-Up.

set -euo pipefail

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "❌ Error: Please run as root." >&2
  exit 1
fi

WORKSPACE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_DIR="${WORKSPACE_DIR}/config"

echo "=== Hardening PPP & Network Isolation ==="

# 1. Enable IPv4 Forwarding
echo "⚙️ Enabling IPv4 Forwarding..."
sysctl -w net.ipv4.ip_forward=1
# Make it persistent
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi

# 2. Deploy PPP options
echo "⚙️ Deploying pppd configuration..."
mkdir -p /etc/ppp
cp "${CONFIG_DIR}/ppp-options" /etc/ppp/options.ttyACM0
echo "✓ Configured /etc/ppp/options.ttyACM0"

# 3. Deploy and Load nftables Isolation Rules
if ! command -v nft &> /dev/null; then
  echo "⚠️ Warning: nftables is not installed. Installing..."
  if command -v apt-get &> /dev/null; then
    apt-get update && apt-get install -y nftables
  elif command -v yum &> /dev/null; then
    yum install -y nftables
  else
    echo "❌ Error: Cannot install nftables. Please install manually." >&2
    exit 1
  fi
fi

echo "⚙️ Loading nftables ruleset..."
nft -f "${CONFIG_DIR}/nftables.conf"
echo "✓ Isolation rules loaded successfully."

# Save nftables configuration so it persists across reboots
if [ -d /etc/nftables ]; then
  cp "${CONFIG_DIR}/nftables.conf" /etc/nftables.conf
  systemctl enable nftables || true
  echo "✓ nftables persistence configured."
fi

echo "========================================="
echo "✓ Setup Complete. Interfaces matching 'ppp*' will be isolated."
echo "========================================="
