#!/usr/bin/env python3
"""
rcgateway — RustChain Dial-Up miner gateway (Phase 4a skeleton).

A vintage client (Dreamcast / 386 / 68k) cannot realistically do TLS, DNS, a
disciplined clock, and an HTTP stack. So it doesn't. The vintage box gathers its
own hardware evidence and Ed25519-SIGNS the attestation LOCALLY, then speaks a
dead-simple plaintext line protocol to THIS gateway over the PPP link. The
gateway does the modern transport — fetch the challenge nonce, TLS to the node,
relay the result — and nothing else.

The security invariant (see ../docs/MINER_GATEWAY.md):
  * The gateway holds NO signing key. It cannot forge a miner.
  * The gateway does NOT alter the signed payload. The node strips the signature
    fields and re-canonicalizes, so relaying the parsed object is signature-safe.
  * The gateway enforces challenge-nonce binding (it issued the nonce), a miner
    allowlist bound to the physical line, and a per-miner rate limit — so one Pi
    can't be used to relay a farm of fake "vintage" identities.

A tampered blob simply fails Ed25519 verification at the node: a malicious or
buggy gateway can deny service, but cannot mint a miner.

Stdlib only for the core (urllib for upstream HTTP/S). PyNaCl is OPTIONAL and
only used for a local pre-flight signature check (--verify-sig); the node remains
authoritative either way.

Protocol: see ./protocol.md.  Run an end-to-end loopback test: python3 test_rcgateway.py
"""
from __future__ import annotations

import argparse
import json
import logging
import secrets
import socketserver
import ssl
import threading
import time
import urllib.request
import urllib.error
from collections import deque
from dataclasses import dataclass
from typing import Optional

LOG = logging.getLogger("rcgateway")

PROTO_VERSION = "1"
MAX_LINE_BYTES = 64 * 1024  # a signed attestation is a few hundred bytes; cap generously

# Optional Ed25519 pre-flight verification (node is authoritative regardless).
try:
    from nacl.signing import VerifyKey  # type: ignore
    _NACL = True
except ImportError:
    _NACL = False


# --------------------------------------------------------------------------- #
# Config + shared state
# --------------------------------------------------------------------------- #
@dataclass
class GatewayConfig:
    node_url: str                       # e.g. https://50.28.86.131
    listen_host: str = "127.0.0.1"
    listen_port: int = 8090
    tls_verify: bool = False            # node uses self-signed certs by default
    timeout: float = 30.0
    allow_miners: frozenset[str] = frozenset()   # empty = allow any (logged)
    rate_per_min: int = 6               # attest attempts per miner per 60s
    verify_sig: bool = False            # local pre-flight Ed25519 check
    mock_node: bool = False             # answer challenge/submit locally (testing)

    def challenge_url(self) -> str:
        return self.node_url.rstrip("/") + "/attest/challenge"

    def submit_url(self) -> str:
        return self.node_url.rstrip("/") + "/attest/submit"


class RateLimiter:
    """Per-miner sliding-window limiter. Thread-safe."""

    def __init__(self, per_min: int):
        self._per_min = per_min
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, miner_id: str) -> bool:
        now = time.time()
        with self._lock:
            dq = self._hits.setdefault(miner_id, deque())
            while dq and now - dq[0] > 60.0:
                dq.popleft()
            if len(dq) >= self._per_min:
                return False
            dq.append(now)
            return True


# --------------------------------------------------------------------------- #
# Upstream node calls (the "fast side": Pi -> node over real Ethernet/TLS)
# --------------------------------------------------------------------------- #
def _post_json(url: str, obj: dict, timeout: float, tls_verify: bool) -> tuple[int, dict]:
    data = json.dumps(obj).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json"},
    )
    ctx = None
    if url.lower().startswith("https"):
        ctx = ssl.create_default_context()
        if not tls_verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        body = r.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(body) if body else {}
        except json.JSONDecodeError:
            parsed = {"_raw": body}
        return r.status, parsed


def fetch_challenge(cfg: GatewayConfig) -> str:
    """Return a fresh attestation nonce. The gateway needs no secret for this."""
    if cfg.mock_node:
        return secrets.token_hex(16)
    status, body = _post_json(cfg.challenge_url(), {}, cfg.timeout, cfg.tls_verify)
    if status != 200:
        raise RuntimeError(f"node challenge HTTP {status}")
    nonce = body.get("nonce")
    if not nonce:
        raise RuntimeError("node challenge returned no nonce")
    return str(nonce)


def submit_attestation(cfg: GatewayConfig, attestation: dict) -> dict:
    """Relay the signed attestation to the node and return its JSON result."""
    if cfg.mock_node:
        return {"ok": True, "mock": True, "miner_id": attestation.get("miner_id")}
    status, body = _post_json(cfg.submit_url(), attestation, cfg.timeout, cfg.tls_verify)
    body.setdefault("_http_status", status)
    return body


# --------------------------------------------------------------------------- #
# Local pre-flight verification (advisory; node is authoritative)
# --------------------------------------------------------------------------- #
def preflight_verify(attestation: dict) -> tuple[bool, str]:
    """Mirror the node's verification: strip sig fields, re-canonicalize, verify.

    Returns (ok, reason). When PyNaCl is absent this is a no-op PASS — the node
    still verifies for real.
    """
    if not _NACL:
        return True, "skipped (no PyNaCl)"
    sig = attestation.get("signature")
    pub = attestation.get("public_key")
    if not sig or not pub:
        return False, "missing signature/public_key"
    stripped = {k: v for k, v in attestation.items()
                if k not in ("signature", "public_key", "signature_type")}
    payload = json.dumps(stripped, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        VerifyKey(bytes.fromhex(pub)).verify(payload, bytes.fromhex(sig))
        return True, "ok"
    except Exception as e:  # noqa: BLE001 - any failure means reject
        return False, f"bad signature: {e}"


# --------------------------------------------------------------------------- #
# Connection handler — the line protocol (see protocol.md)
# --------------------------------------------------------------------------- #
@dataclass
class Session:
    miner_id: Optional[str] = None
    issued_nonce: Optional[str] = None  # the challenge we last handed this conn


class GatewayHandler(socketserver.StreamRequestHandler):
    # injected by the server subclass
    cfg: GatewayConfig
    limiter: RateLimiter

    def _send(self, line: str) -> None:
        self.wfile.write((line + "\n").encode("utf-8"))
        self.wfile.flush()

    def handle(self) -> None:  # noqa: C901 - a small protocol state machine
        peer = self.client_address[0]
        sess = Session()
        self._send(f"RCGW {PROTO_VERSION} ready")
        LOG.info("conn from %s", peer)

        while True:
            raw = self.rfile.readline(MAX_LINE_BYTES)
            if not raw:
                break
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            verb, _, rest = line.partition(" ")
            verb = verb.upper()

            if verb == "HELLO":
                self._do_hello(sess, rest.strip(), peer)
            elif verb == "CHALLENGE":
                self._do_challenge(sess)
            elif verb == "SUBMIT":
                self._do_submit(sess, rest, peer)
            elif verb == "BYE":
                self._send("BYE")
                break
            else:
                self._send("ERR unknown verb")

    def _do_hello(self, sess: Session, miner_id: str, peer: str) -> None:
        if not miner_id:
            self._send("ERR HELLO requires a miner_id")
            return
        if self.cfg.allow_miners and miner_id not in self.cfg.allow_miners:
            LOG.warning("rejected miner_id %r from %s (not in allowlist)", miner_id, peer)
            self._send("ERR miner_id not permitted on this line")
            return
        if not self.cfg.allow_miners:
            LOG.warning("HELLO %r from %s — NO allowlist set (open relay; set --allow-miner)",
                        miner_id, peer)
        sess.miner_id = miner_id
        self._send("READY")

    def _do_challenge(self, sess: Session) -> None:
        if not sess.miner_id:
            self._send("ERR say HELLO first")
            return
        try:
            nonce = fetch_challenge(self.cfg)
        except Exception as e:  # noqa: BLE001 - report upstream failure to client
            LOG.error("challenge fetch failed: %s", e)
            self._send("ERR upstream challenge failed")
            return
        sess.issued_nonce = nonce
        self._send(f"NONCE {nonce}")

    def _do_submit(self, sess: Session, payload: str, peer: str) -> None:
        if not sess.miner_id:
            self._send("ERR say HELLO first")
            return
        if not sess.issued_nonce:
            self._send("ERR request a CHALLENGE first")
            return
        if not self.limiter.allow(sess.miner_id):
            LOG.warning("rate-limited %s", sess.miner_id)
            self._send("ERR rate limited")
            return
        try:
            attestation = json.loads(payload)
        except json.JSONDecodeError:
            self._send("ERR SUBMIT payload is not valid JSON")
            return
        if not isinstance(attestation, dict):
            self._send("ERR SUBMIT payload must be a JSON object")
            return

        # --- binding checks the gateway can enforce WITHOUT any key ---------- #
        if attestation.get("miner_id") != sess.miner_id:
            self._send("ERR miner_id mismatch vs HELLO")
            return
        if attestation.get("nonce") != sess.issued_nonce:
            self._send("ERR nonce mismatch vs issued CHALLENGE")
            return
        if attestation.get("signature_type") != "ed25519" or not attestation.get("signature"):
            self._send("ERR attestation must be ed25519-signed")
            return
        if self.cfg.verify_sig:
            ok, reason = preflight_verify(attestation)
            if not ok:
                LOG.warning("preflight verify failed for %s: %s", sess.miner_id, reason)
                self._send(f"ERR preflight {reason}")
                return

        # --- relay upstream (the gateway does NOT modify content) ------------ #
        try:
            result = submit_attestation(self.cfg, attestation)
        except Exception as e:  # noqa: BLE001 - surface upstream error to client
            LOG.error("submit relay failed for %s: %s", sess.miner_id, e)
            self._send("ERR upstream submit failed")
            return
        # one nonce per attestation: force a fresh CHALLENGE for the next submit
        sess.issued_nonce = None
        LOG.info("relayed attestation for %s -> %s", sess.miner_id, result.get("ok"))
        self._send("RESULT " + json.dumps(result, separators=(",", ":")))


class GatewayServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, cfg: GatewayConfig):
        self.cfg = cfg
        self.limiter = RateLimiter(cfg.rate_per_min)
        handler = type("BoundHandler", (GatewayHandler,),
                       {"cfg": cfg, "limiter": self.limiter})
        super().__init__((cfg.listen_host, cfg.listen_port), handler)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_config(argv: Optional[list[str]] = None) -> GatewayConfig:
    ap = argparse.ArgumentParser(description="RustChain Dial-Up miner gateway")
    ap.add_argument("--node-url", default="https://50.28.86.131",
                    help="RustChain node base URL")
    ap.add_argument("--listen", default="127.0.0.1:8090",
                    help="host:port to accept vintage-client connections")
    ap.add_argument("--tls-verify", action="store_true",
                    help="verify the node's TLS cert (default off: self-signed)")
    ap.add_argument("--timeout", type=float, default=30.0, help="upstream HTTP timeout (s)")
    ap.add_argument("--allow-miner", action="append", default=[], metavar="MINER_ID",
                    help="bind the line to this miner_id (repeatable). "
                         "If omitted, the relay is OPEN — logged loudly.")
    ap.add_argument("--rate-per-min", type=int, default=6,
                    help="max attest attempts per miner per minute")
    ap.add_argument("--verify-sig", action="store_true",
                    help="local Ed25519 pre-flight check before relay (needs PyNaCl)")
    ap.add_argument("--mock-node", action="store_true",
                    help="answer challenge/submit locally for testing (no real node)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    host, _, port = args.listen.partition(":")
    return GatewayConfig(
        node_url=args.node_url,
        listen_host=host or "127.0.0.1",
        listen_port=int(port or 8090),
        tls_verify=args.tls_verify,
        timeout=args.timeout,
        allow_miners=frozenset(args.allow_miner),
        rate_per_min=args.rate_per_min,
        verify_sig=args.verify_sig,
        mock_node=args.mock_node,
    )


def main(argv: Optional[list[str]] = None) -> int:
    cfg = build_config(argv)
    if cfg.verify_sig and not _NACL:
        LOG.warning("--verify-sig set but PyNaCl missing; pre-flight will PASS-through")
    server = GatewayServer(cfg)
    LOG.info("rcgateway listening on %s:%d -> node %s%s%s",
             cfg.listen_host, cfg.listen_port, cfg.node_url,
             "  [MOCK NODE]" if cfg.mock_node else "",
             "" if cfg.allow_miners else "  [OPEN RELAY — set --allow-miner]")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOG.info("shutting down")
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
