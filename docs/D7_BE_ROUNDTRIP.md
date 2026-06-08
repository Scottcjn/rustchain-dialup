# D7 — Big-endian signature round-trip

> **Bounty D7** (per `BOUNTIES.md`):
> *Big-endian signature round-trip: prove the evidence wire-format +
> Ed25519 signature verifies from a big-endian target (G3/G4 or 68k).*

This deliverable proves, **byte-for-byte**, that the evidence commitment
(`sha256(nonce + wallet + entropy_json)`) and the Ed25519 signature
over the pipe-string `miner|wallet|nonce|commitment` are produced
**identically** on every byte-order we care about — the existing
little-endian host (x86_64) and two big-endian targets (PowerPC 64-bit
BE, IBM S/390x), all run from a single sign-only C harness with a
standard RFC 8032 Ed25519 implementation.

The point isn't that the algorithm is portable (Ed25519 is
deterministic and obviously byte-order independent at the math level);
the point is that the **bytes that go on the wire** — the commitment,
the hex-encoded public key, the hex-encoded signature, the JSON payload
the gateway forwards — are produced correctly end-to-end on a real
big-endian target, and are verifiable by any standard Ed25519 verifier
in the rest of the ecosystem (libsodium, OpenSSL EVP, PyNaCl).

## What's in this deliverable

| File | Purpose |
|---|---|
| `tests/d7_harness/rcc_crypto_be.h` | Header for the sign-only harness; same surface as `gateway/client/rcc_crypto.h`. |
| `tests/d7_harness/rcc_crypto_be.c` | Vendored SHA-256 (byte-clean FIPS 180-4) + standard Ed25519 via orlp/ed25519 (MIT). |
| `tests/d7_harness/d7_sign.c` | Sign-only harness: takes `--seed-hex --miner --wallet [--nonce]`, prints `public_key`, `commitment`, `sign_msg`, `signature` as hex. |
| `tests/d7_harness/ed25519_orlp/` | Vendored orlp/ed25519 (MIT) — pure C99, no architecture-specific assembly, RFC 8032 conformant. |
| `tests/d7_harness/build.sh` | Builds the harness for host (x86_64), PowerPC 64 BE, S/390x BE. Requires `gcc-powerpc64-linux-gnu`, `gcc-s390x-linux-gnu`, `qemu-user-static`. |
| `tests/test_d7_bigendian.py` | Pytest entry point: 14 tests covering byte-for-byte equality with the Python reference, RFC 8032 TV1 conformance, and a second (seed, miner, wallet, nonce) tuple. |
| `docs/D7_BE_ROUNDTRIP.md` | This file. |

## How the round-trip is proved

The reference oracle is
`gateway/client/attest_sign_reference.py` — the script that the live
RustChain node's `/attest/submit` endpoint ultimately validates
against. It uses PyNaCl (libsodium under the hood) to produce a
deterministic public key, commitment, and signature for a given
`(seed, miner, wallet, nonce)`.

The C harness (`d7_sign`) reproduces that same byte sequence using
**standard RFC 8032 Ed25519** (the orlp/ed25519 implementation, which
follows the spec exactly) and the same vendored SHA-256.

For three different test cases (the canonical test vector from
`attest_sign_reference.py`, a second seed/miner/wallet tuple, and
RFC 8032 test vector 1), the test asserts on three different
architectures (host x86_64 little-endian, PowerPC 64-bit big-endian
under `qemu-ppc64-static`, IBM S/390x big-endian under
`qemu-s390x-static`) that:

1. **Byte-for-byte equality**: the harness output is identical to the
   Python reference output, line by line, byte by byte. (The harness
   uses the same `%-10s : value` format as the Python script so the
   `diff` is trivial.)
2. **Cryptographic validity**: the printed `public_key` actually
   verifies the printed `signature` over the printed `sign_msg` under
   the host's PyNaCl `VerifyKey`. This is the "the bytes are real
   Ed25519, not just Ed25519-shaped" check.
3. **RFC 8032 conformance**: the public key produced for
   `seed = 9d61b19d…cae7f60` (RFC 8032 deterministic test vector 1)
   matches the canonical value `d75a9801…f707511a` published in the
   standard. The SHA-512 expansion, scalar clamping, and base-point
   multiplication are all standard RFC 8032, not a non-interoperable
   variant.

## Reproducing locally

```bash
# one-time: install cross-compilers and qemu
apt-get install -y gcc-powerpc64-linux-gnu libc6-ppc64-cross \
                    gcc-s390x-linux-gnu libc6-s390x-cross \
                    qemu-user-static
pip3 install pynacl pytest

# build the harness for all three targets
cd tests/d7_harness && bash build.sh

# run the round-trip test
cd ../.. && python3 -m pytest tests/test_d7_bigendian.py -v
```

Expected: 14 tests passed.

## Why a separate sign-only harness instead of using `vintage_client.c`?

The production `vintage_client.c` is a full TCP client: it connects
to the gateway, runs the `HELLO / CHALLENGE / SUBMIT` line protocol,
parses the `READY / NONCE / RESULT` responses, handles `mgetty`
reconnect, etc. It is the right thing for a real vintage box to run,
but it is overkill (and adds cross-compile dependencies on POSIX
sockets, DNS, signal handling) for **proving** that the crypto and
wire-format are byte-correct on a big-endian target.

The sign-only harness (`d7_sign.c`) is ~100 lines of C, no networking,
no external dependencies beyond the vendored orlp/ed25519 + SHA-256.
The output format matches the Python reference oracle, so the test
is a literal `diff`. Once the harness proves the round-trip works on
a big-endian target, the same wire-format and signature paths can be
plugged into `vintage_client.c` with the existing `rcc_crypto.c` —
the production paths are the same byte-level operations, just with
OpenSSL EVP as the Ed25519 backend.

The harness is also useful for **regression testing** the gateway: if
the wire format ever changes (e.g. `commitment = sha256(nonce +
entropy_json + wallet)` instead of the current `nonce + wallet +
entropy_json` order), the byte-for-byte diff against the Python
reference will catch it immediately on every architecture, not just
on the developer's host.

## Note on the Monocypher backend in `rcc_crypto.c`

`gateway/client/rcc_crypto.c` has an `#ifdef RCC_MONOCYPHER` backend
that uses Monocypher's `crypto_eddsa_key_pair` /
`crypto_eddsa_sign`. **Monocypher's Ed25519 is not RFC 8032
Ed25519**: it substitutes BLAKE2b for SHA-512 in the seed expansion
(`sk = H(seed)` where `H` is BLAKE2b, not SHA-512), so signatures
produced by the Monocypher backend will **not** verify under
libsodium, OpenSSL EVP, or PyNaCl. Anyone building a real vintage
client today must use the default OpenSSL EVP backend (or another
RFC 8032 implementation); the Monocypher backend should be retired
or replaced. This D7 deliverable sidesteps the issue by using
orlp/ed25519 (a clean RFC 8032 implementation) and is a reference
for what a future D6/D7-compatible port should use.

## File-by-file change summary

- **new** `tests/d7_harness/rcc_crypto_be.h` (36 lines): harness API.
- **new** `tests/d7_harness/rcc_crypto_be.c` (~150 lines): SHA-256 + orlp/ed25519 wrapper.
- **new** `tests/d7_harness/d7_sign.c` (~110 lines): sign-only harness.
- **new** `tests/d7_harness/ed25519_orlp/` (~12 files, MIT-licensed orlp/ed25519 vendored copy).
- **new** `tests/d7_harness/build.sh` (~40 lines): build script.
- **new** `tests/test_d7_bigendian.py` (~270 lines): 14-test pytest entry point.
- **new** `docs/D7_BE_ROUNDTRIP.md` (this file).

No changes to any production code under `gateway/`, `config/`, or
`tests/test_d3_isolation.py`. The D7 deliverable is additive and
self-contained.
