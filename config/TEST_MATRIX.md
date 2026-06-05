# Dial-Up Isolation — Verification Matrix

> Run these **after** `setup_dialup_isolation.sh` with a client dialed in.
> These are commands to execute and confirm — not pre-marked results. The
> nftables ruleset is validated with `nft -c` at install time before it is
> applied, so a failed ruleset aborts without touching the host firewall.

| # | Goal | Command (from dialed-in client) | Expected |
|---|------|----------------------------------|----------|
| T1 | WAN egress works | `ping -c3 1.1.1.1` | Success (NAT/masquerade via `$WAN_INTERFACE`) |
| T2 | Lab LAN blocked | `ping -c3 192.168.1.5` | Dropped + logged `PPP_FORWARD_BLOCK` |
| T3 | PPP↔PPP blocked | `ping -c3 <other-client-ppp-ip>` | Dropped (forward policy `drop`; no PPP→PPP accept) |
| T4 | Host SSH blocked | `ssh root@10.0.0.1` | Dropped + logged `PPP_INPUT_BLOCK` |
| T5 | Local BBS allowed | `telnet 10.0.0.1 23` (or 2323/2222) | Connects |
| T6 | Miner gateway allowed | `curl -s http://10.0.0.1:8099/attest/challenge` | Reaches the gateway |
| T7 | DNS allowed | `nslookup rustchain.example 10.0.0.1` | Resolves |

**Host-side checks**
- `nft -c -f config/nftables-dialup.conf` → loads with no error (syntax valid).
- `nft list ruleset | grep -A2 'chain forward'` → forward policy is `drop`.
- `systemctl is-enabled nftables.service` → `enabled` (rules survive reboot).
- Other tables on the host (e.g. Docker's) are **unaffected** — this config only
  defines its own `inet filter` and `ip nat` tables.
