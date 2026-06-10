#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Reference signer + test-vector oracle for vintage_client.c.

Given the same fixed seed and inputs, this MUST produce the byte-identical
commitment, sign-message, public key, and signature as the C client. Use it to
verify a vintage port's crypto without a live node:

    python3 attest_sign_reference.py \
        --seed-hex 00112233...(64 hex) --miner g4-powerbook-115 --wallet RTCtest

then run the C client with the same --seed-hex / --miner / --wallet and diff the
`public_key`, `commitment`, `sign_msg`, and `signature` lines.

Mirrors the node's verified message exactly: miner_id|miner|nonce|commitment.
Needs PyNaCl (pip install pynacl).
"""
import argparse
import hashlib
import json

from nacl.signing import SigningKey

ENTROPY_JSON = '{"variance_ns":0.0}'  # must match vintage_client.c byte-for-byte


def derive(seed_hex: str, miner: str, wallet: str, nonce: str) -> dict:
    seed = bytes.fromhex(seed_hex)
    assert len(seed) == 32, "seed must be 32 bytes (64 hex)"
    sk = SigningKey(seed)
    pk_hex = sk.verify_key.encode().hex()

    preimage = (nonce + wallet + ENTROPY_JSON).encode("utf-8")
    commitment = hashlib.sha256(preimage).hexdigest()

    sign_msg = f"{miner}|{wallet}|{nonce}|{commitment}"
    signature = sk.sign(sign_msg.encode("utf-8")).signature.hex()
    return {
        "public_key": pk_hex,
        "nonce": nonce,
        "commitment": commitment,
        "sign_msg": sign_msg,
        "signature": signature,
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed-hex", required=True)
    ap.add_argument("--miner", required=True)
    ap.add_argument("--wallet", required=True)
    ap.add_argument("--nonce", default="fixednonce0001",
                    help="fixed nonce for a reproducible vector (live runs use the server's)")
    args = ap.parse_args()
    v = derive(args.seed_hex, args.miner, args.wallet, args.nonce)
    for k in ("public_key", "nonce", "commitment", "sign_msg", "signature"):
        print(f"{k:10} : {v[k]}")
