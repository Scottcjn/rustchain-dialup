#!/usr/bin/env python3
"""
D5 Bounty Proof: Live-node validation for rcgateway.
Relays a real Ed25519-signed attestation to a live RustChain node.
"""
import json
import socket
import threading
import time
import subprocess
import sys
import os

# Ensure we can import nacl
try:
    from nacl.signing import SigningKey
    HAS_NACL = True
except ImportError:
    HAS_NACL = False
    print("Error: PyNaCl not found. Run this in the venv.")
    sys.exit(1)

def build_signed_attestation(miner_id: str, nonce: str, device_type: str = "vintage") -> dict:
    if device_type == "vintage":
        # Use G4 PowerBook to expect 2.5x multiplier per docs
        device = {"family": "PowerPC", "arch": "G4", "model": "PowerBook G4"}
        hostname = "g4-powerbook-115"
        miner_wallet = "RTCtestwallet"
    else:
        # Modern x86
        device = {"family": "x86_64", "arch": "amd64", "model": "Ryzen 9"}
        hostname = "modern-box"
        miner_wallet = "RTCtestwallet_modern"

    import secrets
    att = {
        "miner": miner_wallet,
        "miner_id": miner_id,
        "nonce": nonce,
        "report": {"nonce": nonce, "commitment": secrets.token_hex(8), "entropy_score": 1.0},
        "device": device,
        "signals": {"macs": [f"de:ad:be:ef:d5:{secrets.token_hex(1)}"], "hostname": hostname},
        "fingerprint": {
            "all_passed": True,
            "checks": {
                "cpu_family": True,
                "arch_match": True,
                "bogomips_match": True
            }
        },
    }
    sk = SigningKey.generate()
    payload = json.dumps(att, sort_keys=True, separators=(",", ":")).encode()
    att["signature"] = sk.sign(payload).signature.hex()
    att["public_key"] = sk.verify_key.encode().hex()
    att["signature_type"] = "ed25519"
    return att

def run_proof():
    node_url = "https://50.28.86.131"
    listen_port = 8091
    miner_id = "agent-proof-d5"

    print(f"Starting rcgateway pointing at {node_url}...")
    gateway_proc = subprocess.Popen([
        sys.executable, "gateway/rcgateway.py",
        "--node-url", node_url,
        "--listen", f"127.0.0.1:{listen_port}",
        "--allow-miner", miner_id,
        "--verbose"
    ])

    time.sleep(2)  # Wait for gateway to start

    try:
        print(f"Connecting to gateway at 127.0.0.1:{listen_port}...")
        with socket.create_connection(("127.0.0.1", listen_port), timeout=10) as sock:
            f = sock.makefile("rwb")
            
            banner = f.readline().decode().strip()
            print(f"S: {banner}")
            
            for dtype in ["vintage", "modern"]:
                print(f"\n--- Testing {dtype} device ---")
                f.write(f"HELLO {miner_id}\n".encode())
                f.flush()
                resp = f.readline().decode().strip()
                if resp != "READY":
                    print(f"Failed at HELLO: {resp}")
                    return

                f.write(b"CHALLENGE\n")
                f.flush()
                resp = f.readline().decode().strip()
                if not resp.startswith("NONCE "):
                    print(f"Failed at CHALLENGE: {resp}")
                    return
                
                nonce = resp.split(" ", 1)[1]
                
                print("Signing attestation...")
                att = build_signed_attestation(miner_id, nonce, dtype)
                payload = json.dumps(att, separators=(",", ":"))
                
                f.write(f"SUBMIT {payload}\n".encode())
                f.flush()
                
                resp = f.readline().decode().strip()
                if resp.startswith("RESULT "):
                    result = json.loads(resp.split(" ", 1)[1])
                    print(f"Result for {dtype}:")
                    print(json.dumps(result, indent=2))
                else:
                    print(f"Error for {dtype}: {resp}")
                
                time.sleep(1) # bit of delay between attempts

            f.write(b"BYE\n")
            f.flush()
            print(f"\nS: {f.readline().decode().strip()}")

    finally:
        gateway_proc.terminate()
        gateway_proc.wait()

if __name__ == "__main__":
    run_proof()
