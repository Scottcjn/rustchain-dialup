#!/usr/bin/env python3
"""
RustChain BBS Door — wallet balance + attestation status + network status panel.

Designed for ENiGMA½ BBS terminal mode. Runs as an external door program:
  - Receives caller context via env vars (USER, BAUD, TERM, etc.)
  - Queries the RustChain node API (same endpoints the gateway uses)
  - Renders an ANSI art panel to stdout (the BBS terminal)
  - Returns to BBS on exit

Stdlib only (urllib, json, os, sys, time). No external dependencies.

Usage:
  python3 rustchain_door.py [--miner-id WALLET] [--node-url URL] [--interactive]

Environment variables (set by ENiGMA½ or the launcher):
  RC_MINER_ID    — wallet/miner ID to display (fallback: --miner-id or prompt)
  RC_NODE_URL    — RustChain node base URL (default: https://rustchain.org)
  RC_GATEWAY_URL — gateway URL for attestation status (optional)

Bounty: D9
Wallet: klowagent
"""
from __future__ import annotations

import json
import os
import ssl
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_NODE_URL = "https://rustchain.org"
VERSION = "1.0.1"

# ANSI escape sequences
ESC = "\x1b["
RESET = f"{ESC}0m"
BOLD = f"{ESC}1m"
DIM = f"{ESC}2m"
UNDERLINE = f"{ESC}4m"
BLINK = f"{ESC}5m"
REVERSE = f"{ESC}7m"

# Colors
BLACK = f"{ESC}30m"
RED = f"{ESC}31m"
GREEN = f"{ESC}32m"
YELLOW = f"{ESC}33m"
BLUE = f"{ESC}34m"
MAGENTA = f"{ESC}35m"
CYAN = f"{ESC}36m"
WHITE = f"{ESC}37m"
BRIGHT_BLACK = f"{ESC}90m"
BRIGHT_RED = f"{ESC}91m"
BRIGHT_GREEN = f"{ESC}92m"
BRIGHT_YELLOW = f"{ESC}93m"
BRIGHT_BLUE = f"{ESC}94m"
BRIGHT_MAGENTA = f"{ESC}95m"
BRIGHT_CYAN = f"{ESC}96m"
BRIGHT_WHITE = f"{ESC}97m"

# Background
BG_BLACK = f"{ESC}40m"
BG_RED = f"{ESC}41m"
BG_GREEN = f"{ESC}42m"
BG_YELLOW = f"{ESC}43m"
BG_BLUE = f"{ESC}44m"
BG_MAGENTA = f"{ESC}45m"
BG_CYAN = f"{ESC}46m"
BG_WHITE = f"{ESC}47m"

# Box-drawing chars (CP437 / Unicode)
BOX_H = "─"
BOX_V = "│"
BOX_TL = "┌"
BOX_TR = "┐"
BOX_BL = "└"
BOX_BR = "┘"
BOX_ML = "├"
BOX_MR = "┤"
BOX_MT = "┬"
BOX_MB = "┴"
BOX_CROSS = "┼"
DIAMOND = "◆"
DOT = "●"
ARROW_R = "►"
ARROW_L = "◄"
STAR = "★"


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only, same pattern as rcgateway.py)
# ---------------------------------------------------------------------------
def _sanitize_url(url: str) -> str:
    """Validate URL scheme — only https:// allowed. Blocks file://, ftp://, etc."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme not in ("https",):
        raise ValueError(f"Blocked URL scheme: {parsed.scheme!r} (only https:// allowed)")
    return url


def _get_json(url: str, timeout: float = 10.0, tls_verify: bool = True) -> tuple[int, dict]:
    """GET a JSON endpoint. Returns (status_code, parsed_json). Only allows https:// URLs."""
    _sanitize_url(url)
    req = urllib.request.Request(url, method="GET")
    ctx = ssl.create_default_context()  # Always verify TLS
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(body) if body else {}
            except json.JSONDecodeError:
                parsed = {"_raw": body}
            return r.status, parsed
    except urllib.error.HTTPError as e:
        return e.code, {"error": str(e)}
    except Exception as e:
        return 0, {"error": str(e)}


# ---------------------------------------------------------------------------
# Data fetching
# ---------------------------------------------------------------------------
class RustChainClient:
    """Queries the same node API endpoints the gateway and miner use."""

    def __init__(self, node_url: str = DEFAULT_NODE_URL, timeout: float = 10.0):
        self.node_url = node_url.rstrip("/")
        self.timeout = timeout

    def health(self) -> dict:
        """Node health — same as rcgateway uses for upstream connectivity."""
        status, data = _get_json(f"{self.node_url}/health", self.timeout)
        return data if status == 200 else {"error": data}

    def epoch(self) -> dict:
        """Current epoch info — slot, epoch number, enrolled miners."""
        status, data = _get_json(f"{self.node_url}/epoch", self.timeout)
        return data if status == 200 else {"error": data}

    def wallet_balance(self, miner_id: str) -> dict:
        """Wallet balance — same endpoint as the miner's balance check."""
        status, data = _get_json(
            f"{self.node_url}/wallet/balance?miner_id={miner_id}", self.timeout
        )
        return data if status == 200 else {"error": data}

    def miners(self) -> list[dict]:
        """Active miners list — for attestation status lookup."""
        status, data = _get_json(f"{self.node_url}/api/miners", self.timeout)
        if status == 200 and isinstance(data, dict):
            return data.get("miners", [])
        return []

    def tokenomics(self) -> dict:
        """Token supply and reference rate."""
        status, data = _get_json(f"{self.node_url}/api/tokenomics", self.timeout)
        return data if status == 200 else {"error": data}

    def find_miner(self, miner_id: str) -> Optional[dict]:
        """Find a specific miner in the active miners list."""
        for m in self.miners():
            if m.get("miner") == miner_id:
                return m
        return None


# ---------------------------------------------------------------------------
# ANSI rendering
# ---------------------------------------------------------------------------
def _pad(text: str, width: int, fill: str = " ") -> str:
    """Pad text to width (accounting for ANSI escape sequences)."""
    # Strip ANSI for length calculation
    import re
    visible = re.sub(r'\x1b\[[0-9;]*m', '', text)
    padding = max(0, width - len(visible))
    return text + (fill * padding)


def _center(text: str, width: int, fill: str = " ") -> str:
    """Center text within width."""
    import re
    visible = re.sub(r'\x1b\[[0-9;]*m', '', text)
    left_pad = max(0, (width - len(visible)) // 2)
    right_pad = max(0, width - len(visible) - left_pad)
    return (fill * left_pad) + text + (fill * right_pad)


def _box_line(content: str, width: int = 60, style: str = "") -> str:
    """Render a single box line with content."""
    padded = _pad(content, width - 4)
    return f"{style}{BOX_V}{RESET} {padded} {style}{BOX_V}{RESET}"


def _box_top(width: int = 60, style: str = "") -> str:
    return f"{style}{BOX_TL}{BOX_H * (width - 2)}{BOX_TR}{RESET}"


def _box_bottom(width: int = 60, style: str = "") -> str:
    return f"{style}{BOX_BL}{BOX_H * (width - 2)}{BOX_BR}{RESET}"


def _box_sep(width: int = 60, style: str = "") -> str:
    return f"{style}{BOX_ML}{BOX_H * (width - 2)}{BOX_MR}{RESET}"


def _progress_bar(value: float, max_val: float, width: int = 20,
                  filled: str = "█", empty: str = "░") -> str:
    """Render a progress bar."""
    if max_val <= 0:
        return empty * width
    ratio = min(1.0, value / max_val)
    filled_count = int(ratio * width)
    return (BRIGHT_GREEN + filled * filled_count +
            BRIGHT_BLACK + empty * (width - filled_count) + RESET)


def render_header(width: int = 60) -> str:
    """Render the RustChain BBS door header."""
    lines = []
    lines.append("")
    lines.append(f"{BRIGHT_CYAN}{BOLD}")
    lines.append(f"  ██████╗ ██╗   ██╗███████╗████████╗ ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗")
    lines.append(f"  ██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██║  ██║██╔══██╗██║████╗  ██║")
    lines.append(f"  ██████╔╝██║   ██║███████╗   ██║   ██║     ███████║███████║██║██╔██╗ ██║")
    lines.append(f"  ██╔══██╗██║   ██║╚════██║   ██║   ██║     ██╔══██║██╔══██║██║██║╚██╗██║")
    lines.append(f"  ██║  ██║╚██████╔╝███████║   ██║   ╚██████╗██║  ██║██║  ██║██║██║ ╚████║")
    lines.append(f"  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝")
    lines.append(f"{RESET}")
    lines.append(f"  {BRIGHT_YELLOW}{BOLD}D E P I N   F O R   V I N T A G E   H A R D W A R E{RESET}")
    lines.append(f"  {DIM}The blockchain where old machines outearn new ones.{RESET}")
    lines.append("")
    return "\n".join(lines)


def _sanitize_terminal(text: str) -> str:
    """Strip ANSI escape sequences and control characters to prevent terminal injection."""
    import re
    text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    return text


def render_balance_panel(client: RustChainClient, miner_id: str, width: int = 60) -> str:
    """Render wallet balance panel."""
    lines = []
    miner_id = _sanitize_terminal(miner_id)
    balance = client.wallet_balance(miner_id)
    tokenomics = client.tokenomics()

    has_error = "error" in balance
    amount_rtc = balance.get("amount_rtc", 0.0)
    ref_rate = tokenomics.get("reference_rate_usd", 0.15)
    usd_value = amount_rtc * ref_rate

    lines.append(_box_top(width, BRIGHT_CYAN))
    lines.append(_box_line(
        f"  {BRIGHT_WHITE}{BOLD}{STAR} WALLET BALANCE{RESET}", width, BRIGHT_CYAN
    ))
    lines.append(_box_sep(width, CYAN))

    if has_error:
        lines.append(_box_line(
            f"  {RED}{DOT} Error: {balance.get('error', 'unknown')}{RESET}", width, CYAN
        ))
    else:
        lines.append(_box_line(
            f"  {WHITE}Miner ID:  {BRIGHT_YELLOW}{BOLD}{miner_id}{RESET}", width, CYAN
        ))
        lines.append(_box_line(
            f"  {WHITE}Balance:   {BRIGHT_GREEN}{BOLD}{amount_rtc:,.4f} RTC{RESET}", width, CYAN
        ))
        lines.append(_box_line(
            f"  {WHITE}USD Ref:   {DIM}${usd_value:,.4f} (@ ${ref_rate}/RTC){RESET}", width, CYAN
        ))

    lines.append(_box_bottom(width, BRIGHT_CYAN))
    return "\n".join(lines)


def render_attestation_panel(client: RustChainClient, miner_id: str, width: int = 60) -> str:
    """Render attestation status panel."""
    lines = []
    miner_id = _sanitize_terminal(miner_id)
    miner = client.find_miner(miner_id)

    lines.append(_box_top(width, BRIGHT_MAGENTA))
    lines.append(_box_line(
        f"  {BRIGHT_WHITE}{BOLD}{STAR} ATTESTATION STATUS{RESET}", width, BRIGHT_MAGENTA
    ))
    lines.append(_box_sep(width, MAGENTA))

    if miner is None:
        lines.append(_box_line(
            f"  {YELLOW}{DOT} Miner not found in active miners list{RESET}", width, MAGENTA
        ))
        lines.append(_box_line(
            f"  {DIM}  Start mining to appear on the network.{RESET}", width, MAGENTA
        ))
    else:
        multiplier = miner.get("antiquity_multiplier", 0.0)
        hw_type = miner.get("hardware_type", "Unknown")
        arch = miner.get("device_arch", "Unknown")
        first_ts = miner.get("first_attest", 0)
        last_ts = miner.get("last_attest", 0)

        # Determine tier color
        if multiplier >= 2.5:
            tier_color = BRIGHT_YELLOW
            tier_name = "ANCIENT"
        elif multiplier >= 2.0:
            tier_color = YELLOW
            tier_name = "LEGENDARY"
        elif multiplier >= 1.5:
            tier_color = BRIGHT_MAGENTA
            tier_name = "EXOTIC"
        elif multiplier >= 1.0:
            tier_color = BRIGHT_GREEN
            tier_name = "MODERN"
        else:
            tier_color = BRIGHT_BLACK
            tier_name = "PENALTY"

        first_dt = datetime.fromtimestamp(first_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M") if first_ts else "N/A"
        last_dt = datetime.fromtimestamp(last_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M") if last_ts else "N/A"

        lines.append(_box_line(
            f"  {WHITE}Hardware:  {BRIGHT_CYAN}{hw_type}{RESET}", width, MAGENTA
        ))
        lines.append(_box_line(
            f"  {WHITE}Arch:      {CYAN}{arch}{RESET}", width, MAGENTA
        ))
        lines.append(_box_line(
            f"  {WHITE}Multiplier:{tier_color} {BOLD}{multiplier}x{RESET} {tier_color}({tier_name}){RESET}", width, MAGENTA
        ))
        lines.append(_box_line(
            f"  {WHITE}First:     {DIM}{first_dt} UTC{RESET}", width, MAGENTA
        ))
        lines.append(_box_line(
            f"  {WHITE}Last:      {DIM}{last_dt} UTC{RESET}", width, MAGENTA
        ))

        # Multiplier bar
        bar = _progress_bar(multiplier, 4.0, width=25)
        lines.append(_box_line(
            f"  {WHITE}Power:     {bar} {multiplier}x{RESET}", width, MAGENTA
        ))

    lines.append(_box_bottom(width, BRIGHT_MAGENTA))
    return "\n".join(lines)


def render_mining_panel(client: RustChainClient, width: int = 60) -> str:
    """Render the 'mine while you read' epoch/network panel."""
    lines = []
    epoch_data = client.epoch()
    health = client.health()
    tokenomics = client.tokenomics()

    has_error = "error" in epoch_data
    node_ok = health.get("ok", False)

    lines.append(_box_top(width, BRIGHT_GREEN))
    lines.append(_box_line(
        f"  {BRIGHT_WHITE}{BOLD}{STAR} NETWORK STATUS{RESET}", width, BRIGHT_GREEN
    ))
    lines.append(_box_sep(width, GREEN))

    # Node status
    if node_ok:
        uptime = health.get("uptime_s", 0)
        uptime_str = f"{uptime // 3600}h {(uptime % 3600) // 60}m"
        version = health.get("version", "unknown")
        lines.append(_box_line(
            f"  {WHITE}Node:      {BRIGHT_GREEN}{DOT} ONLINE{RESET} {DIM}(v{version}, up {uptime_str}){RESET}", width, GREEN
        ))
    else:
        lines.append(_box_line(
            f"  {WHITE}Node:      {RED}{DOT} OFFLINE{RESET}", width, GREEN
        ))

    if has_error:
        lines.append(_box_line(
            f"  {RED}{DOT} Error: {epoch_data.get('error', 'unknown')}{RESET}", width, GREEN
        ))
    else:
        epoch_num = epoch_data.get("epoch", 0)
        slot = epoch_data.get("slot", 0)
        total_slots = epoch_data.get("blocks_per_epoch", 144)
        enrolled = epoch_data.get("enrolled_miners", 0)
        epoch_pot = epoch_data.get("epoch_pot", 0.0)
        total_supply = epoch_data.get("total_supply_rtc", 0)

        # Epoch progress (slot is global, use modulo for epoch-relative position)
        epoch_slot = slot % total_slots if total_slots > 0 else 0
        epoch_pct = (epoch_slot / total_slots * 100) if total_slots > 0 else 0
        bar = _progress_bar(epoch_slot, total_slots, width=25)

        lines.append(_box_line(
            f"  {WHITE}Epoch:     {BRIGHT_YELLOW}{BOLD}#{epoch_num}{RESET}", width, GREEN
        ))
        lines.append(_box_line(
            f"  {WHITE}Slot:      {epoch_slot}/{total_slots} ({epoch_pct:.1f}%){RESET}", width, GREEN
        ))
        lines.append(_box_line(
            f"  {WHITE}Progress:  {bar}{RESET}", width, GREEN
        ))
        lines.append(_box_line(
            f"  {WHITE}Reward:    {BRIGHT_GREEN}{epoch_pot} RTC/epoch{RESET}", width, GREEN
        ))
        lines.append(_box_line(
            f"  {WHITE}Miners:    {BRIGHT_CYAN}{enrolled} active{RESET}", width, GREEN
        ))
        lines.append(_box_line(
            f"  {WHITE}Supply:    {DIM}{total_supply:,.0f} RTC{RESET}", width, GREEN
        ))

        # Live stats from tokenomics
        live = tokenomics.get("live", {})
        if live:
            circulating = live.get("circulating_rtc", 0)
            wallets = live.get("wallets_with_balance", 0)
            lines.append(_box_line(
                f"  {WHITE}Holders:   {BRIGHT_CYAN}{wallets:,} wallets{RESET}", width, GREEN
            ))
            lines.append(_box_line(
                f"  {WHITE}Circulating:{DIM} {circulating:,.0f} RTC{RESET}", width, GREEN
            ))

    lines.append(_box_bottom(width, BRIGHT_GREEN))
    return "\n".join(lines)


def render_footer(width: int = 60) -> str:
    """Render the footer."""
    lines = []
    lines.append("")
    lines.append(f"  {DIM}{'─' * (width - 4)}{RESET}")
    lines.append(f"  {DIM}RustChain BBS Door v{VERSION} │ {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}{RESET}")
    lines.append(f"  {DIM}rustchain.org │ github.com/Scottcjn/Rustchain{RESET}")
    lines.append(f"  {DIM}Press any key to return to BBS...{RESET}")
    lines.append("")
    return "\n".join(lines)


def render_error_screen(error_msg: str, width: int = 60) -> str:
    """Render an error screen."""
    lines = []
    lines.append("")
    lines.append(f"  {RED}{BOLD}╔{'═' * (width - 4)}╗{RESET}")
    lines.append(f"  {RED}{BOLD}║{RESET} {_pad(f'  {RED}{BOLD}ERROR{RESET}', width - 4)} {RED}{BOLD}║{RESET}")
    lines.append(f"  {RED}{BOLD}╠{'═' * (width - 4)}╣{RESET}")
    lines.append(f"  {RED}{BOLD}║{RESET} {_pad(f'  {error_msg}', width - 4)} {RED}{BOLD}║{RESET}")
    lines.append(f"  {RED}{BOLD}╚{'═' * (width - 4)}╝{RESET}")
    lines.append("")
    return "\n".join(lines)


def render_full_screen(client: RustChainClient, miner_id: str, width: int = 60) -> str:
    """Render the full BBS door screen."""
    parts = []
    parts.append(render_header(width))
    parts.append(render_balance_panel(client, miner_id, width))
    parts.append("")
    parts.append(render_attestation_panel(client, miner_id, width))
    parts.append("")
    parts.append(render_mining_panel(client, width))
    parts.append(render_footer(width))
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Interactive mode (for BBS terminal — waits for keypress)
# ---------------------------------------------------------------------------
def interactive_mode(client: RustChainClient, miner_id: str) -> None:
    """Run in interactive BBS mode — render, wait for key, exit."""
    # Clear screen (BBS style)
    sys.stdout.write(f"{ESC}2J{ESC}H")
    sys.stdout.flush()

    # Render
    output = render_full_screen(client, miner_id)
    sys.stdout.write(output)
    sys.stdout.flush()

    # Wait for keypress (BBS expects this)
    try:
        if sys.stdin.isatty():
            sys.stdin.read(1)
        else:
            # Non-interactive (piped) — just render and exit
            pass
    except (EOFError, KeyboardInterrupt):
        pass

    # Clear screen on exit
    sys.stdout.write(f"{ESC}2J{ESC}H")
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: Optional[list[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        description="RustChain BBS Door — wallet + attestation + mining panel"
    )
    ap.add_argument("--miner-id", default=None,
                    help="Wallet/miner ID to display (env: RC_MINER_ID)")
    ap.add_argument("--node-url", default=None,
                    help="RustChain node URL (env: RC_NODE_URL)")
    ap.add_argument("--interactive", "-i", action="store_true",
                    help="Interactive BBS mode (clear screen, wait for key)")
    ap.add_argument("--json", action="store_true",
                    help="Output raw JSON data instead of ANSI")
    ap.add_argument("--width", type=int, default=60,
                    help="Panel width (default: 60)")
    args = ap.parse_args(argv)

    # Resolve config
    miner_id = args.miner_id or os.environ.get("RC_MINER_ID") or ""
    node_url = args.node_url or os.environ.get("RC_NODE_URL") or DEFAULT_NODE_URL

    if not miner_id:
        # Try to read from stdin (ENiGMA½ may pipe it)
        if not sys.stdin.isatty():
            miner_id = sys.stdin.readline().strip()

    if not miner_id:
        sys.stderr.write("Error: --miner-id required (or set RC_MINER_ID)\n")
        return 1

    client = RustChainClient(node_url)

    if args.json:
        # Raw JSON output (for testing / scripting)
        data = {
            "miner_id": miner_id,
            "balance": client.wallet_balance(miner_id),
            "miner": client.find_miner(miner_id),
            "epoch": client.epoch(),
            "health": client.health(),
            "tokenomics": client.tokenomics(),
        }
        print(json.dumps(data, indent=2))
        return 0

    if args.interactive:
        interactive_mode(client, miner_id)
    else:
        # Non-interactive: just print the screen
        print(render_full_screen(client, miner_id, args.width))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())