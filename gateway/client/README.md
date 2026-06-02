# vintage_client — RustChain dial-up vintage miner (bounty D6 reference)

The **vintage half** of the split miner ([../../docs/MINER_GATEWAY.md](../../docs/MINER_GATEWAY.md)).
Runs on the *old* machine, speaks the [gateway line protocol](../protocol.md) over TCP, gathers
minimal evidence, and **Ed25519-signs locally** the exact message the RustChain node verifies —
`miner_id|miner|nonce|commitment`. The key never leaves the box.

Small and dependency-light on purpose: C99 + POSIX sockets, no JSON library, vendored SHA-256,
Ed25519 via a swappable backend.

## Build

```bash
make                    # OpenSSL Ed25519 backend (modern + 486-Linux dev box)
make CRYPTO=monocypher  # portable vintage target — drop monocypher.c / monocypher.h here first
```

OpenSSL is fine for a 486 running modern Linux, but it's far too heavy for a 68k/SH-4/PPC. For
genuine vintage targets, cross-compile with the period toolchain and use **Monocypher** (single
portable C file, big-endian-safe, no malloc).

## Run

```bash
./vintage_client --host 10.55.0.1 --port 8090 \
    --miner g4-powerbook-115 --wallet RTCyourwallet --arch G4 --family PowerPC
```

`--seed-hex <64hex>` pins the Ed25519 seed for reproducible test vectors. Omit it on real hardware
and the seed is read from `~/.rustchain_seed` (or generated from `/dev/urandom` and saved).

> ⚠️ The bundled seed generation is best-effort. On a real vintage port, wire `load_or_make_seed()`
> to a proper platform CSPRNG and protect the key file. **This is the highest-value hardening item
> for a production port** — the whole proof-of-antiquity rests on this key staying secret and local.

## Verifying a port (no live node needed)

The crypto is checked against a PyNaCl oracle. Run the client with a fixed seed+nonce against a mock
gateway, then compare to [`attest_sign_reference.py`](attest_sign_reference.py):

```bash
# terminal 1 — mock gateway that verifies the signature like the real node does
python3 ../rcgateway.py --mock-node --verify-sig --allow-miner g4-powerbook-115 --listen 127.0.0.1:8097

# terminal 2 — run the client, then diff its output against the oracle for the SAME nonce
SEED=0123...   # 64 hex
./vintage_client --host 127.0.0.1 --port 8097 --miner g4-powerbook-115 --wallet RTCtest --seed-hex $SEED
python3 attest_sign_reference.py --seed-hex $SEED --miner g4-powerbook-115 --wallet RTCtest --nonce <nonce-from-above>
```

`public_key`, `commitment`, `sign_msg`, and `signature` must match byte-for-byte. The OpenSSL
backend was verified identical to PyNaCl this way; a Monocypher port must reproduce the same vector.

## What the node verifies (ground truth)

```
sign_message = "miner_id|miner|nonce|commitment"          # UTF-8, NOT canonical JSON
commitment   = sha256(nonce + miner + '{"variance_ns":0.0}')  # entropy JSON is fixed-shape ASCII
```

Confirmed against `Scottcjn/Rustchain@origin/main` `node/.../attest/submit`. See
[../protocol.md](../protocol.md) for the upstream-mismatch note (the shipped Python miners sign
canonical JSON instead, which the node rejects — this client signs what the node actually checks).

## Status

- [x] Protocol + commitment + pipe-string signing, OpenSSL backend — **compiles clean, run-verified
      byte-identical to PyNaCl, accepted by `rcgateway --verify-sig`**
- [x] Vendored SHA-256 — verified against Python `hashlib`
- [ ] Monocypher backend — wired via `#ifdef`, **not yet compiled** (needs monocypher.c/.h + a target)
- [ ] Real per-platform CSPRNG + key protection (see warning above)
- [ ] Real hardware evidence collection (currently a minimal fixed-shape stub)
- [ ] Validation against a live RustChain node (closes D5/D6 together)
