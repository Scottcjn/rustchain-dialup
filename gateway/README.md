# rcgateway — RustChain Dial-Up miner gateway

Phase 4a skeleton (bounty **D5**). The gateway runs on the Pi NAS and is the *modern
transport* half of the [split miner](../docs/MINER_GATEWAY.md): the vintage client
signs locally, the gateway fetches the challenge nonce, relays the signed attestation
to the RustChain node over TLS, and returns the result. **It holds no signing key.**

## Quick start

```bash
# 1) Self-test, no node needed — proves the line protocol + guards end to end:
python3 test_rcgateway.py
#   (or: pytest test_rcgateway.py)

# 2) Run against a real node, bound to one miner on this line:
python3 rcgateway.py \
  --node-url https://50.28.86.131 \
  --listen 10.55.0.1:8090 \
  --allow-miner g4-powerbook-115 \
  --verify-sig -v

# 3) Smoke it by hand with the mock node (no real node):
python3 rcgateway.py --mock-node --allow-miner test -v &
printf 'HELLO test\nCHALLENGE\n' | nc 127.0.0.1 8090   # watch NONCE come back
```

## What it does / doesn't do

- **Does:** fetch `POST /attest/challenge`, relay `POST /attest/submit` over TLS,
  enforce miner allowlist (physical-line binding), challenge-nonce binding, per-miner
  rate limit, and an optional local Ed25519 pre-flight (`--verify-sig`).
- **Doesn't:** hold a key, sign anything, gather hardware evidence, or modify the
  payload. A forged/tampered blob fails verification at the node — the gateway can
  deny service but cannot mint a miner.

## Options

| flag | default | purpose |
|------|---------|---------|
| `--node-url` | `https://50.28.86.131` | RustChain node base URL |
| `--listen host:port` | `127.0.0.1:8090` | where vintage clients connect (set to the PPP-subnet IP) |
| `--allow-miner ID` | *(none)* | bind the line to a miner_id (repeatable). **Omit = open relay, logged loudly.** |
| `--rate-per-min N` | `6` | max attest attempts per miner per minute |
| `--verify-sig` | off | local Ed25519 pre-flight before relay (needs PyNaCl) |
| `--tls-verify` | off | verify the node cert (node ships self-signed) |
| `--mock-node` | off | answer challenge/submit locally for testing |

## Protocol

The vintage-client line protocol is specified in **[protocol.md](protocol.md)** — the
contract a D6 C-client author builds against.

## Dependencies

Core is **stdlib only** (urllib for upstream). `PyNaCl` is optional and only used for
`--verify-sig` and for real signing in the test harness. See `requirements.txt`.

## Status / TODO (toward closing D5 → D6)

- [x] Line protocol + key-free binding guards + mock-node self-test
- [x] Validate against a live node (relayed attestation accepted by node `50.28.86.131`; see `proof_live_node.py`)
- [ ] systemd unit + one instance per physical line (Phase 7 multi-line)
- [ ] Raw-serial / BBS-door transport carrying the same protocol (no PPP required)
- [ ] Reference C vintage client (bounty **D6**) that emits SUBMIT payloads
