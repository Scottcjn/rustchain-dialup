import socket
import json
import subprocess
import time
from nacl.signing import SigningKey

WALLET = "0x43991A9dC8Ddf492eab6E55685644c2cb9B001D2"
MINER_ID = "g4-powerbook-115"

def build_signed_attestation(miner_id: str, nonce: str, wallet: str) -> dict:
    att = {
        "miner": wallet,
        "miner_id": miner_id,
        "nonce": nonce,
        "report": {"nonce": nonce, "commitment": "deadbeef", "entropy_score": 1.0},
        "device": {"family": "PowerPC", "arch": "G4", "model": "PowerBook G4"},
        "signals": {"macs": ["00:11:22:33:44:55"], "hostname": "test"},
        "fingerprint": {"all_passed": True, "checks": {}},
    }
    sk = SigningKey.generate()
    payload = json.dumps(att, sort_keys=True, separators=(",", ":")).encode()
    att["signature"] = sk.sign(payload).signature.hex()
    att["public_key"] = sk.verify_key.encode().hex()
    att["signature_type"] = "ed25519"
    return att

print("Starting gateway process against LIVE node...")
gateway_proc = subprocess.Popen([
    "python3", "rcgateway.py",
    "--node-url", "https://50.28.86.131",
    "--listen", "127.0.0.1:8090",
    "--allow-miner", MINER_ID,
    "--verify-sig", "-v"
])

time.sleep(2)

try:
    print(f"\nConnecting to gateway to claim bounty D5 with wallet {WALLET}...")
    sock = socket.create_connection(("127.0.0.1", 8090), timeout=5)
    f = sock.makefile("rwb")

    def send_cmd(cmd):
        print(f"> {cmd}")
        f.write((cmd + "\n").encode())
        f.flush()
        resp = f.readline().decode().strip()
        print(f"< {resp}")
        return resp

    resp = f.readline().decode().strip()
    print(f"< {resp}")

    send_cmd(f"HELLO {MINER_ID}")

    nonce_resp = send_cmd("CHALLENGE")
    nonce = nonce_resp.split(" ", 1)[1]

    att = build_signed_attestation(MINER_ID, nonce, WALLET)
    payload = json.dumps(att, separators=(",", ":"))

    result = send_cmd(f"SUBMIT {payload}")
    print("\n--- FINAL RESULT ---")
    print(result)

finally:
    try:
        f.close()
    except Exception:
        pass
    try:
        sock.close()
    except Exception:
        pass
    gateway_proc.terminate()
    gateway_proc.wait()
