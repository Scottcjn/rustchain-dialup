# rcgateway line protocol v1

A line-oriented, newline-delimited ASCII protocol between the **vintage client**
(a tiny C binary on the old machine) and the **gateway** (`rcgateway.py` on the Pi).
Designed so a 386 with no TLS and a hand-written parser can speak it: every message
is one line, UTF-8, `\n`-terminated, verb first.

The gateway side of each call is the modern transport — it fetches the challenge
nonce from the RustChain node, relays the signed attestation over TLS, and returns
the result. **The signing happens entirely on the vintage client.** The gateway holds
no key (see [../docs/MINER_GATEWAY.md](../docs/MINER_GATEWAY.md)).

## Transport

- TCP (over the PPP link) to the gateway's `--listen host:port` (default `127.0.0.1:8090`).
  A future raw-serial/BBS transport will carry the same line protocol unchanged.
- One attestation per connection is the simple case; a connection may loop
  (CHALLENGE→SUBMIT) for repeated attests. Each SUBMIT consumes its nonce.
- Lines are capped at 64 KiB. A signed attestation is a few hundred bytes.

## Messages

```
G->C  RCGW 1 ready                 banner on connect (protocol version 1)

C->G  HELLO <miner_id>             identify; bound against the gateway allowlist
G->C  READY                        accepted   (or: ERR <reason> and the line stays open)

C->G  CHALLENGE                    ask for a fresh nonce
G->C  NONCE <nonce>                gateway fetched POST /attest/challenge for you
                                    (or: ERR upstream challenge failed)

C->G  SUBMIT <compact-json>        the FULL signed attestation, on ONE line
G->C  RESULT <compact-json>        the node's JSON response verbatim
                                    (or: ERR <reason>)

C->G  BYE                          optional; gateway replies BYE and closes
```

### `SUBMIT` payload

The `<compact-json>` is the exact attestation object the client built and signed —
single line, no embedded newlines (canonical JSON has none). It MUST contain at least:

| field | meaning |
|-------|---------|
| `miner_id` | must equal the `HELLO` miner_id (gateway rejects mismatch) |
| `nonce` | must equal the `NONCE` just issued (gateway enforces challenge binding) |
| `report`, `device`, `signals`, `fingerprint` | the evidence (built on the vintage box) |
| `signature` | hex Ed25519 over the **pipe-string** `miner_id\|miner\|nonce\|commitment` (see below) |
| `public_key` | hex Ed25519 public key |
| `signature_type` | must be `"ed25519"` |

### What to sign (ground truth, verified against `origin/main`)

The RustChain node's `/attest/submit` verifies the signature over a **pipe-delimited
string**, NOT canonical JSON:

```
sign_message = f"{miner_id}|{miner}|{nonce}|{commitment}"     # UTF-8 bytes
signature    = ed25519_sign(sign_message, private_key)
```

where `miner` is the **wallet address** (the node's `miner` field == wallet; `miner_id` is the
device id) and `commitment` is what the client puts in `report.commitment` — by convention
`sha256(nonce + wallet + '{"variance_ns":0.0}')`. The node only re-derives the *pipe-string above*
for verification; it reads `commitment` from the report as-is.

This is **far simpler for a vintage client than canonical JSON** — no key-sorting,
no separator rules, just `sprintf`. That's why the C client (bounty D6) targets it.

> ⚠️ **Known upstream mismatch (flagged, not ours to fix here):** the shipped
> `rustchain_linux_miner.py` / `rustchain_windows_miner.py` currently sign the
> *canonical JSON* of the full attestation instead of this pipe-string, so their
> signed attestations fail node verification and fall back to unsigned. The C client
> here deliberately signs what the **node actually verifies**, so it is accepted.
> Forwarding a parsed-and-reserialized object is still signature-safe because the
> signature covers the pipe-string, not the JSON byte layout.

## What the gateway enforces (no key required)

- `HELLO` miner_id ∈ allowlist (`--allow-miner`), i.e. bound to the physical line.
- `SUBMIT.miner_id == HELLO miner_id`.
- `SUBMIT.nonce == ` the nonce the gateway just issued (replay guard).
- `signature_type == "ed25519"` and a non-empty `signature`.
- Per-miner rate limit (`--rate-per-min`).
- Optional local Ed25519 pre-flight (`--verify-sig`) — advisory; the node is authoritative.

The gateway never inspects or fabricates the hardware evidence and never signs. A
tampered or forged blob fails verification at the node.

## Error lines

`ERR <human-readable reason>` — the connection stays open unless the framing itself
is unusable. Known reasons: `say HELLO first`, `miner_id not permitted on this line`,
`request a CHALLENGE first`, `nonce mismatch vs issued CHALLENGE`,
`attestation must be ed25519-signed`, `rate limited`, `upstream challenge failed`,
`upstream submit failed`.

## Example session

```
S: RCGW 1 ready
C: HELLO g4-powerbook-115
S: READY
C: CHALLENGE
S: NONCE 9f3a...c1
C: SUBMIT {"miner_id":"g4-powerbook-115","nonce":"9f3a...c1","device":{...},"report":{...},"signals":{...},"fingerprint":{...},"signature":"...","public_key":"...","signature_type":"ed25519"}
S: RESULT {"ok":true,"weight":2.5,...}
C: BYE
S: BYE
```
