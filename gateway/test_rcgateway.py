#!/usr/bin/env python3
"""
End-to-end loopback test for rcgateway — the Phase 4a acceptance harness.

Spins the gateway in --mock-node mode on an ephemeral port, connects a socket
client that walks the line protocol (HELLO -> CHALLENGE -> SUBMIT), and asserts the
node accepts the relayed attestation. Also exercises the gateway's key-free
binding guards (allowlist reject, nonce-mismatch reject).

Runs two ways:
  python3 test_rcgateway.py      # standalone, prints PASS/FAIL, exits nonzero on fail
  pytest test_rcgateway.py       # discovered as test_* functions

If PyNaCl is installed the SUBMIT payload is really Ed25519-signed and the gateway's
--verify-sig pre-flight verifies it; otherwise a stub signature is used and the mock
node accepts it (the real node would verify for real).
"""
from __future__ import annotations

import json
import socket
import threading

from rcgateway import GatewayConfig, GatewayServer

try:
    from nacl.signing import SigningKey
    _NACL = True
except ImportError:
    _NACL = False


# --------------------------------------------------------------------------- #
# Test helpers
# --------------------------------------------------------------------------- #
def build_signed_attestation(miner_id: str, nonce: str) -> dict:
    """Build an attestation matching the real miner's shape, signed if PyNaCl is present."""
    att = {
        "miner": "RTCtestwallet",
        "miner_id": miner_id,
        "nonce": nonce,
        "report": {"nonce": nonce, "commitment": "deadbeef", "entropy_score": 1.0},
        "device": {"family": "PowerPC", "arch": "G4", "model": "PowerBook G4"},
        "signals": {"macs": ["00:11:22:33:44:55"], "hostname": "test"},
        "fingerprint": {"all_passed": True, "checks": {}},
    }
    if _NACL:
        sk = SigningKey.generate()
        # Sign the EXACT message the node verifies: miner_id|miner|nonce|commitment
        msg = "{}|{}|{}|{}".format(
            att["miner_id"], att["miner"], att["nonce"], att["report"]["commitment"]
        ).encode()
        att["signature"] = sk.sign(msg).signature.hex()
        att["public_key"] = sk.verify_key.encode().hex()
    else:
        att["signature"] = "00" * 64
        att["public_key"] = "11" * 32
    att["signature_type"] = "ed25519"
    return att


class _Client:
    """Minimal line-protocol client over a socket (stands in for the C vintage client)."""

    def __init__(self, host: str, port: int):
        self.sock = socket.create_connection((host, port), timeout=5)
        self.f = self.sock.makefile("rwb")

    def recv(self) -> str:
        return self.f.readline().decode().strip()

    def send(self, line: str) -> str:
        self.f.write((line + "\n").encode())
        self.f.flush()
        return self.recv()

    def close(self) -> None:
        try:
            self.f.close()
            self.sock.close()
        except OSError:
            pass


class _Harness:
    """Context manager: a running mock-node gateway on an ephemeral port."""

    def __init__(self, **cfg_overrides):
        base = dict(node_url="http://mock", listen_host="127.0.0.1", listen_port=0,
                    mock_node=True, verify_sig=_NACL, allow_miners=frozenset())
        base.update(cfg_overrides)
        self.cfg = GatewayConfig(**base)

    def __enter__(self):
        self.server = GatewayServer(self.cfg)
        self.host, self.port = self.server.server_address
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def client(self) -> _Client:
        return _Client(self.host, self.port)

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #
def test_happy_path_attestation_accepted():
    miner = "g4-powerbook-115"
    with _Harness(allow_miners=frozenset({miner})) as h:
        c = h.client()
        assert c.recv().startswith("RCGW 1")
        assert c.send(f"HELLO {miner}") == "READY"
        nonce_line = c.send("CHALLENGE")
        assert nonce_line.startswith("NONCE "), nonce_line
        nonce = nonce_line.split(" ", 1)[1]
        att = build_signed_attestation(miner, nonce)
        result = c.send("SUBMIT " + json.dumps(att, separators=(",", ":")))
        assert result.startswith("RESULT "), result
        body = json.loads(result.split(" ", 1)[1])
        assert body.get("ok") is True, body
        c.close()


def test_allowlist_rejects_unknown_miner():
    with _Harness(allow_miners=frozenset({"known-miner"})) as h:
        c = h.client()
        c.recv()
        assert c.send("HELLO some-rando").startswith("ERR"), "unlisted miner must be rejected"
        c.close()


def test_nonce_mismatch_rejected():
    miner = "g5-130"
    with _Harness(allow_miners=frozenset({miner})) as h:
        c = h.client()
        c.recv()
        assert c.send(f"HELLO {miner}") == "READY"
        nonce_line = c.send("CHALLENGE")
        assert nonce_line.startswith("NONCE ")
        att = build_signed_attestation(miner, "not-the-issued-nonce")
        resp = c.send("SUBMIT " + json.dumps(att, separators=(",", ":")))
        assert resp.startswith("ERR") and "nonce" in resp, resp
        c.close()


def test_submit_before_challenge_rejected():
    miner = "x"
    with _Harness(allow_miners=frozenset({miner})) as h:
        c = h.client()
        c.recv()
        c.send(f"HELLO {miner}")
        att = build_signed_attestation(miner, "n")
        resp = c.send("SUBMIT " + json.dumps(att, separators=(",", ":")))
        assert resp.startswith("ERR") and "CHALLENGE" in resp, resp
        c.close()


def test_non_dict_report_does_not_crash():
    """A truthy non-dict `report` must yield a clean ERR, not a dead thread."""
    miner = "weird"
    with _Harness(allow_miners=frozenset({miner})) as h:
        c = h.client()
        c.recv()
        assert c.send(f"HELLO {miner}") == "READY"
        nonce = c.send("CHALLENGE").split(" ", 1)[1]
        att = build_signed_attestation(miner, nonce)
        att["report"] = "not-a-dict"  # malformed
        resp = c.send("SUBMIT " + json.dumps(att, separators=(",", ":")))
        assert resp.startswith("ERR"), resp
        # connection still alive: a follow-up line still gets a response
        assert c.send("CHALLENGE").startswith(("NONCE", "ERR")), "thread died"
        c.close()


def test_canonical_json_signature_is_rejected():
    """A signature over canonical JSON (the shipped-miner bug) must fail preflight."""
    if not _NACL:
        return  # can't forge a real sig without PyNaCl; skip
    miner = "jsonsigner"
    with _Harness(allow_miners=frozenset({miner})) as h:
        c = h.client()
        c.recv()
        c.send(f"HELLO {miner}")
        nonce = c.send("CHALLENGE").split(" ", 1)[1]
        att = build_signed_attestation(miner, nonce)
        # re-sign over canonical JSON instead of the pipe-string
        sk = SigningKey.generate()
        stripped = {k: v for k, v in att.items()
                    if k not in ("signature", "public_key", "signature_type")}
        payload = json.dumps(stripped, sort_keys=True, separators=(",", ":")).encode()
        att["signature"] = sk.sign(payload).signature.hex()
        att["public_key"] = sk.verify_key.encode().hex()
        resp = c.send("SUBMIT " + json.dumps(att, separators=(",", ":")))
        assert resp.startswith("ERR preflight"), resp
        c.close()


def _run_standalone() -> int:
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failed = 0
    print(f"rcgateway loopback tests (PyNaCl signing: {'ON' if _NACL else 'STUB'})")
    print("-" * 60)
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
        except Exception as e:  # noqa: BLE001 - test runner reports any failure
            failed += 1
            print(f"  FAIL  {t.__name__}: {e}")
    print("-" * 60)
    print(f"{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
