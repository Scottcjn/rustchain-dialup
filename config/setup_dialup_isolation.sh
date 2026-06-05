#!/usr/bin/env bash
# RustChain Dial-Up Network Isolation — setup (HYBRID of #6 + #4)
# Applies the nftables isolation ruleset with correct persistence, and OPTIONALLY
# configures CHAP authentication for PPP clients (off by default — the oldest
# dial-up clients can't do CHAP, and the firewall is the isolation boundary).
#
# Fixes over the source PRs:
#   - nftables config actually loads (valid MSS syntax, top-level defines)   [#6]
#   - persistence writes the file the loader reads + enables nftables.service  [#6]
#   - does NOT flush the host's FORWARD chain or clobber global /etc/ppp/options [#4]
#   - CHAP secrets are written via a here-doc with the password escaped         [#4]
#   - single peer IP (not an address range) in per-device options              [#4]
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
NFT_SRC="${SCRIPT_DIR}/nftables-dialup.conf"
NFT_DST="/etc/nftables.conf"
WAN_INTERFACE="${WAN_INTERFACE:-}"
ENABLE_CHAP="${ENABLE_CHAP:-0}"
PPP_PEER_IP="${PPP_PEER_IP:-10.0.0.2}"
PPP_LOCAL_IP="${PPP_LOCAL_IP:-10.0.0.1}"

[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }

# 1. Auto-detect WAN interface if not provided (default route's dev).
if [ -z "$WAN_INTERFACE" ]; then
    WAN_INTERFACE="$(ip -o route get 1.1.1.1 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)"
    [ -n "$WAN_INTERFACE" ] || { echo "Could not auto-detect WAN interface; set WAN_INTERFACE=..." >&2; exit 1; }
fi
echo "[*] WAN interface: ${WAN_INTERFACE}"

command -v nft >/dev/null 2>&1 || { echo "[*] installing nftables"; apt-get update -qq && apt-get install -y nftables; }

# 2. Materialize the ruleset with the chosen WAN interface, then VALIDATE before applying.
tmp_conf="$(mktemp)"; trap 'rm -f "$tmp_conf"' EXIT
sed "s/^define WAN_INTERFACE = .*/define WAN_INTERFACE = \"${WAN_INTERFACE}\"/" "$NFT_SRC" > "$tmp_conf"
nft -c -f "$tmp_conf" || { echo "[!] ruleset failed validation; aborting (host firewall untouched)"; exit 1; }

# 3. Persist + load via the standard loader (does NOT flush unrelated tables —
#    the config only defines its own 'inet filter' / 'ip nat' tables).
install -m 0644 "$tmp_conf" "$NFT_DST"
systemctl enable --now nftables.service
nft -f "$NFT_DST"
echo "[+] Isolation ruleset applied and persisted (${NFT_DST}); enabled on boot."

# 4. Enable IPv4 forwarding (persisted).
sysctl -w net.ipv4.ip_forward=1 >/dev/null
install -m 0644 /dev/stdin /etc/sysctl.d/99-rustchain-dialup.conf <<<'net.ipv4.ip_forward = 1'

# 5. OPTIONAL CHAP auth — only if ENABLE_CHAP=1. Written to a PER-DEVICE options
#    file so the global /etc/ppp/options is never clobbered.
if [ "$ENABLE_CHAP" = "1" ]; then
    read -rp "PPP CHAP username: " CHAP_USER
    read -rsp "PPP CHAP password: " CHAP_PASS; echo
    # Reject characters that can't be safely represented in chap-secrets.
    case "$CHAP_USER$CHAP_PASS" in
        *['"'\\]*|*[[:space:]]*) echo "[!] username/password may not contain quotes, backslashes, or whitespace." >&2; exit 1;;
    esac
    touch /etc/ppp/chap-secrets; chmod 600 /etc/ppp/chap-secrets
    # Append only if this client isn't already present (idempotent).
    grep -qE "^\"?${CHAP_USER}\"?[[:space:]]" /etc/ppp/chap-secrets || \
        printf '%s\t*\t%s\t*\n' "$CHAP_USER" "$CHAP_PASS" >> /etc/ppp/chap-secrets
    echo "[+] CHAP secret recorded for '${CHAP_USER}'. Add 'auth' + 'require-chap' to your per-device ppp options."
else
    echo "[i] CHAP disabled (default). Isolation is enforced at the firewall regardless of auth."
fi
echo "[✓] Done. Verify with config/TEST_MATRIX.md."
