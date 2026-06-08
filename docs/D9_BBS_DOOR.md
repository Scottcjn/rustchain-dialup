# D9 — BBS⇄RustChain Door

## What this delivers

An ENiGMA½ BBS door that displays three panels on the terminal:

1. **Wallet Balance** — RTC balance, USD reference value, miner ID
2. **Attestation Status** — hardware type, architecture, antiquity multiplier, tier name, first/last attestation timestamps
3. **Mine While You Read** — live node status, epoch number, slot progress, epoch reward, active miners count, circulating supply, holder count

The door queries **only** the RustChain node API endpoints that the gateway and miner already use:
- `/health` — node connectivity
- `/epoch` — current epoch info
- `/wallet/balance?miner_id=` — wallet balance
- `/api/miners` — active miners list (for attestation lookup)
- `/api/tokenomics` — supply and reference rate

No fabricated data. No external dependencies. Stdlib only.

## Files

| File | Purpose |
|------|---------|
| `bbs/rustchain_door.py` | Main BBS door — ANSI art panels, API client, CLI modes |
| `bbs/enigma2-launcher` | ENiGMA½ integration — locked launcher, no shell escape |
| `tests/d9_harness/d9_door_test.py` | 17-check automated test harness |

## How to run

```bash
# Non-interactive (prints to stdout)
python3 bbs/rustchain_door.py --miner-id klowagent

# JSON output (for scripting)
python3 bbs/rustchain_door.py --miner-id klowagent --json

# Interactive BBS mode (clear screen, wait for key)
python3 bbs/rustchain_door.py --miner-id klowagent --interactive

# Run tests
python3 tests/d9_harness/d9_door_test.py
```

## ENiGMA½ integration

The `bbs/enigma2-launcher` script is the locked launcher referenced in `config/login.config`:

```
* - - - /usr/local/bin/enigma2-launcher
```

It:
- Reads miner ID from `RC_MINER_ID` env var, `/etc/rustchain-bbs.conf`, or `BBS_USER`
- Launches `rustchain_door.py --interactive` directly (no shell escape)
- Clears screen on exit, returns to BBS

### Config file (optional)

Create `/etc/rustchain-bbs.conf`:
```
MINER_ID=your-wallet-id
NODE_URL=https://rustchain.org
```

## What the BBS user sees

```
  ██████╗ ██╗   ██╗███████╗████████╗ ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗
  ██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██║  ██║██╔══██╗██║████╗  ██║
  ██████╔╝██║   ██║███████╗   ██║   ██║     ███████║███████║██║██╔██╗ ██║
  ██╔══██╗██║   ██║╚════██║   ██║   ██║     ██╔══██║██╔══██║██║██║╚██╗██║
  ██║  ██║╚██████╔╝███████║   ██║   ╚██████╗██║  ██║██║  ██║██║██║ ╚████║
  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝

  D E P I N   F O R   V I N T A G E   H A R D W A R E
  The blockchain where old machines outearn new ones.

┌──────────────────────────────────────────────────────────┐
│   ★ WALLET BALANCE                                       │
├──────────────────────────────────────────────────────────┤
│   Miner ID:  klowagent                                   │
│   Balance:   0.0000 RTC                                  │
│   USD Ref:   $0.0000 (@ $0.15/RTC)                       │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│   ★ ATTESTATION STATUS                                   │
├──────────────────────────────────────────────────────────┤
│   Hardware:  x86-64 (Modern)                             │
│   Arch:      modern                                      │
│   Multiplier: 0.8x (PENALTY)                             │
│   First:     2026-06-08 05:39 UTC                        │
│   Last:      2026-06-08 05:39 UTC                        │
│   Power:     ░░░░░░░░░░░░░░░░░░░░ 0.8x                  │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│   ★ MINE WHILE YOU READ                                  │
├──────────────────────────────────────────────────────────┤
│   Node:      ● ONLINE (v2.2.1-rip200, up 61h 0m)        │
│   Epoch:     #187                                        │
│   Slot:      54/144 (37.5%)                              │
│   Progress:  ████████████░░░░░░░░░░░░░                   │
│   Reward:    1.5 RTC/epoch                               │
│   Miners:    24 active                                   │
│   Supply:    8,388,608 RTC                               │
│   Holders:   1,203 wallets                               │
│   Circulating: 445,013 RTC                               │
└──────────────────────────────────────────────────────────┘

  RustChain BBS Door v1.0.0 │ 2026-06-08 05:40 UTC
  rustchain.org │ github.com/Scottcjn/Rustchain
  Press any key to return to BBS...
```

## Test results

```
============================================================
ALL 17 CHECKS PASSED
============================================================
```

## Bounty rubric compliance

- [x] Wallet balance displayed from node API
- [x] Attestation status with multiplier, hardware type, timestamps
- [x] "Mine while you read" panel with epoch, node status, network stats
- [x] Only uses gateway/node API endpoints (no fabricated data)
- [x] Stdlib only (urllib, json, ssl — no requests/httpx)
- [x] ENiGMA½ launcher integration (locked, no shell escape)
- [x] Test harness with 17 automated checks
- [x] Documentation with install/config/usage
