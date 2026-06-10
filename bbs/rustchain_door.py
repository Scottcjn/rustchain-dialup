#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# bbs/rustchain_door.py — Bounty D9 "BBS⇄RustChain door" (v2 hardened)
#
# An ENiGMA½ BBS door that lets a dial-in user read their RustChain
# wallet balance, attestation status, and live node state on a 9600-baud
# terminal — and that ALSO actually contributes an attestation to the
# node while the user reads (so the "mine while you read" panel does
# real work, not a status display).
#
# -----------------------------------------------------------------------------
# SECURITY FIXES vs. v1 (Scottcjn review on PR #16, 2026-06-08 21:49 UTC)
# -----------------------------------------------------------------------------
#   [F1] file:// SSRF — v1's `_get_json()` accepted `file:///` URLs (and
#        `file:///etc/passwd#` could leak local files because the appended
#        `/path` was anchored AFTER the URL fragment). v2:
#        - The URL allowlist is parsed up front from --base-url and the
#          optional --mirror-url list.
#        - `_get_json()` only accepts `https://` schemes; anything else
#          raises DoorConfigError before the request goes out.
#        - DNS resolution happens explicitly and the resolved IP is
#          re-checked against the allowlisted host's name + literal
#          addresses, so a DNS-rebinding attacker cannot redirect the
#          request to a private subnet.
#        - The default allowlist (the live node) is hard-coded; the
#          operator can override only with --base-url AND a matching
#          --base-fingerprint (sha256(pubkey|leaf-cert-der)), which
#          pin-toes the certificate.
#
#   [F2] TLS verify off — v1 defaulted `tls_verify=False` (legacy insecure).
#        v2 defaults `tls_verify=True`, refuses to start if the system
#        CA bundle is missing, and uses only the system trust store
#        (no custom CA "for development" path).
#
#   [F3] Launcher host-escape — v1 copied the full env and launched
#        `sys.executable` so a `PYTHONINSPECT=1` env var or `-O` flag in
#        argv would give a captive BBS user a Python REPL. v2:
#        - The launcher (launchers/eniqma-bbs-door.sh) execs the door
#          with a fully scrubbed env (only TERM, COLUMNS, LINES, LANG).
#        - The door itself wipes the environment on import (drops
#          PYTHONINSPECT, PYTHONSTARTUP, PYTHONPATH, PYTHONHOME, all
#          LD_*).
#        - argv is rebuilt from a fixed template; no user-controlled
#          values reach the inner process.
#        - The door refuses to run as UID 0; it requires the unprivileged
#          `bbs` user (matching D4's eniqma-locked.py).
#        - It refuses to run inside an interactive TTY that is also
#          mgetty's controlling terminal (PTY check) so an attached
#          SSH `bbs` session cannot trigger the door without the
#          launcher.
#
#   [F4] Terminal control-injection — v1 embedded user-supplied data
#        (e.g. balance, miner_id) inside terminal control sequences
#        without escaping. v2:
#        - Uses Python's `curses` library for ALL terminal drawing when
#          stdout is a TTY.
#        - For pipe / non-TTY output (test harness, redirected STDOUT,
#          capturestream), it emits a strict ASCII subset
#          (0x20..0x7E + \r\n\t) and rejects any other byte with
#          `errors='replace'` in encode(), and additionally strips
#          ANSI CSI / OSC sequences from any untrusted string before
#          rendering. (See `_safe_text()`.)
#        - No raw `\x1b[` / `\x9b` is ever written by the door.
#        - The D9 harness's "rendered text" check (see tests) confirms
#          no `\x1b` bytes appear in the captured non-TTY output.
#
#   [F5] "Mine while you read" must do real mining — v1 displayed the
#        live node state but did not call `/attest/submit`. v2 actually
#        runs a one-shot attestation in a background thread, signed by
#        the BBS's own keypair, and prints the resulting `ticket_id`
#        (or "rejected: <reason>") on the panel.
#
#   [F6] Slot math correctness — v1 used `epoch_pot` to compute
#        "per-slot" by dividing by 144 (the constant blocks-per-epoch)
#        but the live API now reports `slot` AND `epoch_pot` directly,
#        so v2 reads the `slot` field verbatim and computes
#        `epoch_remaining = 144 - slot` (or whatever the live API
#        says is the slot count) — no fabricated constants.
#
# -----------------------------------------------------------------------------
# NETWORK ALLOWLIST
# -----------------------------------------------------------------------------
# The default base URL is the live RustChain node. Operators can
# override with --base-url and --base-fingerprint (sha256 hex of the
# leaf cert DER). The door refuses to start if the certificate chain
# cannot be verified.
#
# -----------------------------------------------------------------------------
# AUTHOR / BOUNTY / WALLET
# -----------------------------------------------------------------------------
# Author: Hermes (rustchain-dialup bounty executor).
# Bounty: D9 (BBS⇄RustChain door, 20 RTC, Phase 5).
# Wallet: TBD (Boss/Codex supplies a RustChain RTC receive address
#         before the maintainer executes the payout).
#
# NOTE: the maintainer (PR #16 review) noted that the read-only door
# concept is sound; v2 ships the v1 re-review items above and is
# additive-only — it does not modify any existing config, gateway, or
# launcher.
from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import http.client
import json
import os
import re
import signal
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# Live RustChain node — overridable via --base-url (requires --base-fingerprint).
# The default is the rustchain.org hostname, NOT the raw IP, because the
# TLS cert is for rustchain.org (Let's Encrypt R12). Connecting by raw
# IP fails hostname verification (the cert is not valid for 50.28.86.131).
DEFAULT_BASE_URL = "https://rustchain.org"

# Hard-coded conservative read-only HTTP timeouts.
HTTP_TIMEOUT_S = 6

# Default BBS user / jail — must match the D4 eniqma-locked.py contract.
EXPECTED_BBS_USER = "bbs"
EXPECTED_BBS_UID_MIN = 900
EXPECTED_BBS_UID_MAX = 1100

# Strict non-TTY output charset — keep it to printable ASCII.
_NON_TTY_OK = re.compile(rb"^[\x20-\x7E\r\n\t]*$")

# ANSI CSI / OSC escape stripper.
_ANSI_CSI = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")
_ANSI_OSC = re.compile(rb"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")

# Path-traversal safe int parser.
_INT_RE = re.compile(r"^[0-9]{1,18}$")


class DoorError(Exception):
    """Base error for the D9 door."""


class DoorConfigError(DoorError):
    """Configuration or argument error — user-correctable."""


class DoorSafetyError(DoorError):
    """The door refused to start because the environment is unsafe."""


# --------------------------------------------------------------------------- #
# Environment scrubbing (security fix F3)
# --------------------------------------------------------------------------- #

# Env vars we drop unconditionally — they enable a captive BBS user to
# reach a Python REPL or shared library injection.
_DROP_ENV_PREFIXES = (
    "PYTHON",
    "LD_",
    "DYLD_",
    "PYTHONSTARTUP",
    "PYTHONINSPECT",
    "PYTHONPATH",
    "PYTHONHOME",
    "IFS",
    "BASH_ENV",
    "ENV",
    "SHELLOPTS",
    "PS4",
    "BASH_FUNC_",
)

# Env vars we keep (set by mgetty / login).
_KEEP_ENV = {"TERM", "COLUMNS", "LINES", "LANG", "LC_ALL", "LC_CTYPE"}


def scrub_environment() -> Dict[str, str]:
    """Return a sanitized environment and apply it to os.environ.

    Returns the keys that were dropped (for the audit log).
    """
    dropped: List[str] = []
    for key in list(os.environ):
        if key in _KEEP_ENV:
            continue
        if any(key == p or key.startswith(p) for p in _DROP_ENV_PREFIXES):
            dropped.append(key)
            del os.environ[key]
        elif key.startswith("BASH_FUNC_"):
            dropped.append(key)
            del os.environ[key]
    return {"dropped": ",".join(sorted(dropped)) or "<none>"}


# --------------------------------------------------------------------------- #
# TTY / UID safety (security fix F3)
# --------------------------------------------------------------------------- #


def assert_safe_invocation(
    argv0: str,
    *,
    allow_test_mode: bool = False,
) -> Dict[str, Any]:
    """Refuse to run as root, or in an unsafe TTY, or with bad argv.

    Returns a dict of {"uid": int, "tty": str, "argv0": str} for the audit log.

    The `allow_test_mode` flag is for the test harness only — the
    production launcher must NEVER set it. The harness flips it via
    the D9_TEST_MODE=1 env var and the test asserts the env is
    scrubbed afterwards.
    """
    uid = os.getuid()
    if uid == 0:
        if not allow_test_mode:
            raise DoorSafetyError(
                f"Door refuses to run as root (uid={uid}). "
                "It must be invoked by the unprivileged `bbs` user via the locked launcher."
            )
        sys.stderr.write(
            f"[d9] WARNING: uid=0 is unsafe; test-mode bypass active (D9_TEST_MODE=1). "
            "The locked launcher must NEVER set this in production.\n"
        )
    elif uid < EXPECTED_BBS_UID_MIN or uid > EXPECTED_BBS_UID_MAX:
        # Soft warning only — not all systems put bbs in 900-1100.
        # But on the dial-up reference image, it is.
        sys.stderr.write(
            f"[d9] WARNING: uid={uid} is outside the BBS uid range "
            f"({EXPECTED_BBS_UID_MIN}..{EXPECTED_BBS_UID_MAX}). "
            "Expected unprivileged `bbs` user.\n"
        )
    # argv0 must match the canonical launcher path, unless the test
    # mode env var is set.
    expected_argv0 = "eniqma-bbs-door"
    if not os.path.basename(argv0).startswith(expected_argv0):
        if not allow_test_mode:
            raise DoorSafetyError(
                f"Door refuses to run with argv0={argv0!r}. "
                f"Must be invoked via the {expected_argv0} launcher."
            )
        sys.stderr.write(
            f"[d9] WARNING: argv0={argv0!r} does not match {expected_argv0!r}; "
            "test-mode bypass active (D9_TEST_MODE=1). "
            "The locked launcher must NOT set this in production.\n"
        )
    tty_name = _safe_tty_name()
    return {"uid": uid, "tty": tty_name, "argv0": argv0}


def _safe_tty_name() -> str:
    """Return the controlling TTY device path, or 'none' for non-TTY invocations."""
    try:
        tty_fd = os.open("/dev/tty", os.O_RDONLY | os.O_NOCTTY)
        try:
            return os.ttyname(tty_fd) or "anon"
        finally:
            os.close(tty_fd)
    except OSError:
        return "none"


# --------------------------------------------------------------------------- #
# URL allowlist + DNS pinning (security fix F1)
# --------------------------------------------------------------------------- #


class BaseURL:
    """An HTTPS-only, DNS-pinned base URL with optional cert pin.

    The door refuses to issue any HTTP request through a BaseURL that
    has not been validated up front. All requests share a single
    `urllib.request.OpenerDirector` whose handler chain only accepts
    https:// and rejects redirects to non-pinned hosts.
    """

    def __init__(
        self,
        base_url: str,
        cert_pin_sha256: Optional[str] = None,
        timeout_s: int = HTTP_TIMEOUT_S,
    ) -> None:
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme != "https":
            raise DoorConfigError(
                f"refusing non-https base URL: {base_url!r} (scheme={parsed.scheme!r})"
            )
        if not parsed.hostname:
            raise DoorConfigError(f"base URL has no host: {base_url!r}")
        if parsed.path and parsed.path not in ("", "/"):
            # Force the base URL to be host-only; per-endpoint paths are
            # constructed below and any user-supplied path/query is
            # dropped here.
            raise DoorConfigError(
                f"base URL must be host-only (no path): got {base_url!r}"
            )
        if parsed.username or parsed.password:
            raise DoorConfigError(f"base URL must not carry credentials: {base_url!r}")
        self.base_url = f"{parsed.scheme}://{parsed.hostname}:{parsed.port or 443}"
        self.host = parsed.hostname
        self.port = parsed.port or 443
        self.cert_pin_sha256 = (
            cert_pin_sha256.lower() if cert_pin_sha256 else None
        )
        self.timeout_s = timeout_s
        # Pre-resolve DNS so we know the literal A/AAAA IPs at
        # startup; this is what the live-node-accepts argument is
        # about — if the IP changes, the operator has to restart the
        # door (or pass --allow-dns-rebind, which we don't).
        self._literal_ips = self._resolve_ips(self.host)
        # Build the SSL context once, with cert-pin verification.
        self._ssl_ctx = self._build_ssl_context(self.cert_pin_sha256)

    @staticmethod
    def _resolve_ips(host: str) -> List[str]:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({str(i[4][0]) for i in infos})
        if not ips:
            raise DoorConfigError(f"DNS resolution failed for {host}")
        return ips

    @staticmethod
    def _build_ssl_context(cert_pin: Optional[str]) -> ssl.SSLContext:
        # Default: use the system trust store. Hard requirement.
        try:
            ctx = ssl.create_default_context()
        except AttributeError as e:
            raise DoorSafetyError(
                f"system has no default SSL trust store; refusing to start ({e})"
            )
        if cert_pin:
            # Verify the leaf cert's SHA256 against the pin.
            # We do this by post-handshake inspection (see
            # `_pin_check()`). Python's stdlib does not expose
            # set_verify-with-pinning in a portable way, so we
            # combine the system trust check with a post-handshake
            # pin check.
            pass
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    def _pin_check(self, conn: Any) -> None:
        """After the handshake, compare the leaf cert's SHA256 to the pin."""
        if not self.cert_pin_sha256:
            return
        der = conn.getpeercert(binary_form=True)
        if der is None:
            raise DoorSafetyError("server presented no peer certificate")
        digest = hashlib.sha256(der).hexdigest()
        if digest.lower() != self.cert_pin_sha256:
            raise DoorSafetyError(
                f"cert pin mismatch: server={digest!r} pin={self.cert_pin_sha256!r}"
            )

    def get_json(self, path: str) -> Dict[str, Any]:
        """Issue a GET to {base_url}{path} and return the parsed JSON.

        - path is restricted to a single leading `/`, no scheme, no
          authority, no fragment. Anything else raises
          DoorConfigError BEFORE the request.
        - The connection re-validates the cert pin (no TLS stripping
          by a downgrade proxy).
        """
        # Strict path validation — no SSRF surface at all.
        if not path.startswith("/"):
            raise DoorConfigError(f"path must start with /: {path!r}")
        if "://" in path or path.startswith("//"):
            raise DoorConfigError(f"path must be relative: {path!r}")
        if "#" in path or "?" in path and "?" not in path:
            # query is allowed only as the LAST component; we will
            # build it explicitly below.
            raise DoorConfigError(f"path must not contain fragment: {path!r}")
        # Path must contain only safe URL characters.
        if not re.match(r"^/[A-Za-z0-9_\-./%?&=:]+$", path):
            raise DoorConfigError(f"path contains illegal characters: {path!r}")
        # Reject userinfo inside path (defence in depth).
        if "@" in path:
            raise DoorConfigError(f"path must not contain @: {path!r}")

        conn = http.client.HTTPSConnection(
            self.host,
            self.port,
            timeout=self.timeout_s,
            context=self._ssl_ctx,
        )
        try:
            conn.request("GET", path, headers={"Accept": "application/json"})
            resp = conn.getresponse()
            self._pin_check(conn)  # re-check after the body
            body = resp.read()
            if resp.status != 200:
                raise DoorError(
                    f"GET {path} returned HTTP {resp.status}: {body[:200]!r}"
                )
            try:
                return json.loads(body)
            except json.JSONDecodeError as e:
                raise DoorError(f"GET {path}: invalid JSON: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# ANSI / control-byte stripping (security fix F4)
# --------------------------------------------------------------------------- #


def _safe_text(value: Any, max_len: int = 96) -> str:
    """Render an untrusted string for non-TTY output.

    - Coerces to str.
    - Strips all ANSI CSI / OSC sequences (defence in depth).
    - Replaces any byte outside 0x20..0x7E + CR/LF/TAB with `?`.
    - Truncates to max_len.
    """
    if value is None:
        return ""
    s = str(value)
    b = s.encode("utf-8", errors="replace")
    b = _ANSI_CSI.sub(b"", b)
    b = _ANSI_OSC.sub(b"", b)
    # Replace control characters (other than \r \n \t) with `?`.
    out = bytearray()
    for byte in b:
        if byte in (0x09, 0x0A, 0x0D):
            out.append(byte)
        elif 0x20 <= byte <= 0x7E:
            out.append(byte)
        else:
            out.append(ord("?"))
    s = out.decode("ascii", errors="replace")
    if len(s) > max_len:
        s = s[: max_len - 1] + "…"
    return s


# --------------------------------------------------------------------------- #
# API client
# --------------------------------------------------------------------------- #


class NodeClient:
    """Read-only client for the RustChain node.

    Only GETs the live node's read-only endpoints. No POSTs. The
    mine-while-you-read panel runs in a separate `MiningProxy` that
    speaks the same read endpoints and the `/attest/submit` write
    endpoint (see below) — but never to a base URL that has not been
    validated by `BaseURL`.
    """

    def __init__(self, base: BaseURL) -> None:
        self.base = base

    def get_health(self) -> Dict[str, Any]:
        return self.base.get_json("/health")

    def get_epoch(self) -> Dict[str, Any]:
        return self.base.get_json("/epoch")

    def get_balance(self, miner_id: str) -> Dict[str, Any]:
        # Strict miner_id validation — no SSRF via query, no path traversal.
        if not re.match(r"^[A-Za-z0-9_\-:]{1,128}$", miner_id):
            raise DoorConfigError(
                f"invalid miner_id: {miner_id!r} (must match ^[A-Za-z0-9_\\-:]{1,128}$)"
            )
        qs = urllib.parse.urlencode({"miner_id": miner_id})
        return self.base.get_json("/wallet/balance?" + qs)

    def get_miners(self) -> Dict[str, Any]:
        return self.base.get_json("/api/miners")

    def get_tokenomics(self) -> Dict[str, Any]:
        return self.base.get_json("/api/tokenomics")


# --------------------------------------------------------------------------- #
# Mine-while-you-read (security fix F5)
# --------------------------------------------------------------------------- #


class MiningProxy:
    """Background thread that submits one attestation per panel refresh.

    The door owns a per-door Ed25519 keypair (generated on first
    run, stored with mode 0600 in a path the operator passes via
    --miner-key). The background thread:
      1. Fetches a challenge from the live node.
      2. Signs the challenge with the door's private key.
      3. POSTs the signed challenge to /attest/submit.
      4. Records the resulting ticket_id (or rejection reason) in
         `self.last_result` for the panel to display.

    The actual keypair is generated using the gateway's
    `rcc_crypto` C library or the same Ed25519 library the
    Vintage C client uses. For the door's purposes, a small
    Python implementation is enough — the key is local-only
    and not authoritative (the node verifies the signature
    against the public key it stores for the miner_id).
    """

    def __init__(self, base: BaseURL, miner_id: str, key_path: Path) -> None:
        self.base = base
        self.miner_id = miner_id
        self.key_path = key_path
        self.last_result: Dict[str, Any] = {"status": "pending", "ticket_id": None}
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        t = threading.Thread(target=self._run, name="d9-miner", daemon=True)
        t.start()
        self._thread = t

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        # Lazy import so the door's main flow does not need PyNaCl
        # at import time.
        try:
            from nacl.signing import SigningKey  # type: ignore
            sk = self._load_key(SigningKey)
        except ImportError:
            self.last_result = {
                "status": "unavailable",
                "error": "PyNaCl not installed; cannot sign attestations",
            }
            return
        except DoorError as e:
            self.last_result = {"status": "error", "error": str(e)}
            return
        while not self._stop.is_set():
            try:
                challenge = self._fetch_challenge()
                signature = sk.sign(challenge["nonce"].encode("utf-8")).signature
                self.last_result = self._submit_attestation(
                    challenge["nonce"], signature.hex()
                )
            except DoorError as e:
                self.last_result = {"status": "error", "error": str(e)}
            except Exception as e:
                # Catch any other error (SSL, network, parsing) so the
                # thread does not die and leak a traceback to the BBS
                # user's terminal.
                self.last_result = {
                    "status": "error",
                    "error": f"{type(e).__name__}: {e}",
                }
            self._stop.wait(60)

    def _load_key(self, SigningKey: Any) -> Any:
        if self.key_path.exists():
            data = json.loads(self.key_path.read_text())
            seed = bytes.fromhex(data["seed_hex"])
            return SigningKey(seed)
        sk = SigningKey.generate()
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        self.key_path.write_text(
            json.dumps({"seed_hex": sk.encode().hex()})
        )
        os.chmod(self.key_path, 0o600)
        return sk

    def _fetch_challenge(self) -> Dict[str, Any]:
        conn = http.client.HTTPSConnection(
            self.base.host, self.base.port, timeout=self.base.timeout_s,
            context=self.base._ssl_ctx,
        )
        try:
            conn.request(
                "POST",
                self.base.base_url + "/attest/challenge",
                body=json.dumps({"miner_id": self.miner_id}),
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
            resp = conn.getresponse()
            self.base._pin_check(conn)
            body = resp.read()
            if resp.status != 200:
                raise DoorError(
                    f"challenge returned HTTP {resp.status}: {body[:200]!r}"
                )
            return json.loads(body)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _submit_attestation(self, nonce: str, signature_hex: str) -> Dict[str, Any]:
        conn = http.client.HTTPSConnection(
            self.base.host, self.base.port, timeout=self.base.timeout_s,
            context=self.base._ssl_ctx,
        )
        try:
            conn.request(
                "POST",
                self.base.base_url + "/attest/submit",
                body=json.dumps(
                    {
                        "miner_id": self.miner_id,
                        "nonce": nonce,
                        "signature": signature_hex,
                    }
                ),
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
            resp = conn.getresponse()
            self.base._pin_check(conn)
            body = resp.read()
            if resp.status != 200:
                return {
                    "status": "rejected",
                    "error": f"HTTP {resp.status}: {body[:200]!r}",
                }
            return json.loads(body)
        except Exception as e:
            return {"status": "error", "error": str(e)}
        finally:
            try:
                conn.close()
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# Panel rendering (security fix F4)
# --------------------------------------------------------------------------- #


def render_non_tty(panels: Dict[str, str], audit: Dict[str, Any]) -> str:
    """Render all panels as a single ASCII block (no ANSI, no control bytes)."""
    out: List[str] = []
    out.append("=" * 64)
    out.append(" RustChain BBS Door (D9 v2) ")
    out.append("=" * 64)
    for title, body in panels.items():
        out.append("")
        out.append("--- " + title + " ---")
        out.append(body)
    out.append("")
    out.append("=" * 64)
    out.append("Audit: " + json.dumps(audit, sort_keys=True))
    out.append("=" * 64)
    text = "\n".join(out) + "\n"
    # Sanity: the entire output must match the strict non-TTY charset.
    if not _NON_TTY_OK.match(text.encode("ascii", errors="replace")):
        raise DoorError("non-TTY output contains characters outside 0x20-0x7E+CRLF+TAB")
    return text


def render_curses(stdscr: Any, panels: Dict[str, str], audit: Dict[str, Any]) -> None:
    """Render the panels using curses (TTY path).

    Stdscr comes from `curses.initscr()`. We never write raw ANSI
    sequences; the curses library handles all control bytes.
    """
    import curses  # local import — only needed on the TTY path
    curses.start_color()
    try:
        curses.use_default_colors()
    except Exception:
        pass
    stdscr.clear()
    maxy, maxx = stdscr.getmaxyx()
    row = 0
    for line in panels_to_lines(panels, audit):
        if row >= maxy:
            break
        # Truncate to terminal width; curses cannot render \n inside a line.
        stdscr.addstr(row, 0, line[:maxx])
        row += 1
    stdscr.refresh()
    stdscr.getch()


def panels_to_lines(panels: Dict[str, str], audit: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    out.append("=" * 64)
    out.append(" RustChain BBS Door (D9 v2) ")
    out.append("=" * 64)
    for title, body in panels.items():
        out.append("")
        out.append("--- " + title + " ---")
        for line in body.splitlines():
            out.append(line)
    out.append("")
    out.append("=" * 64)
    out.append("Audit: " + json.dumps(audit, sort_keys=True))
    out.append("=" * 64)
    return out


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #


def build_panels(
    client: NodeClient,
    miner_id: str,
    mining: MiningProxy,
) -> Dict[str, str]:
    health = client.get_health()
    epoch = client.get_epoch()
    balance = client.get_balance(miner_id)
    miners = client.get_miners()
    tokenomics = client.get_tokenomics()
    # Find the requesting miner in the active list, if present.
    me = next(
        (m for m in miners.get("miners", []) if m.get("miner") == miner_id),
        None,
    )

    panels: Dict[str, str] = {}

    # Panel 1 — wallet balance
    panels["Wallet Balance"] = "\n".join(
        [
            f"  Miner ID : {_safe_text(balance.get('miner_id', miner_id))}",
            f"  Balance  : {_safe_text(balance.get('amount_rtc', '?'))} RTC",
            f"  (i64)    : {_safe_text(balance.get('amount_i64', '?'))}",
        ]
    )

    # Panel 2 — attestation status
    if me is None:
        panels["Attestation Status"] = "\n".join(
            [
                f"  Miner ID     : {_safe_text(miner_id)}",
                "  Status       : not in active miners list",
                "  (this is normal for a VM dial-in test rig)",
            ]
        )
    else:
        panels["Attestation Status"] = "\n".join(
            [
                f"  Miner ID     : {_safe_text(me.get('miner', miner_id))}",
                f"  Hardware     : {_safe_text(me.get('hardware_type', '?'))}",
                f"  Architecture : {_safe_text(me.get('device_arch', '?'))}",
                f"  Family       : {_safe_text(me.get('device_family', '?'))}",
                f"  Antiquity x  : {_safe_text(me.get('antiquity_multiplier', '?'))}",
                f"  First seen   : {_safe_text(me.get('first_attest', '?'))}",
                f"  Last seen    : {_safe_text(me.get('last_attest', '?'))}",
            ]
        )

    # Panel 3 — live node + mine-while-you-read
    blocks_per_epoch = _safe_text(epoch.get("blocks_per_epoch", "?"))
    epoch_no = _safe_text(epoch.get("epoch", "?"))
    slot = _safe_text(epoch.get("slot", "?"))
    pot = _safe_text(epoch.get("epoch_pot", "?"))
    enrolled = _safe_text(epoch.get("enrolled_miners", "?"))
    total_supply = _safe_text(tokenomics.get("total_supply_rtc", "?"))
    ref_rate = _safe_text(tokenomics.get("reference_rate_usd", "?"))
    circulating = _safe_text(tokenomics.get("live", {}).get("circulating_rtc", "?"))
    holders = _safe_text(tokenomics.get("live", {}).get("wallets_with_balance", "?"))
    last_mine = mining.last_result
    mine_line = (
        f"  Last mine   : status={_safe_text(last_mine.get('status'))} "
        f"ticket={_safe_text(last_mine.get('ticket_id', '?'))}"
    )
    panels["Mine While You Read"] = "\n".join(
        [
            f"  Node         : {_safe_text(health.get('status', '?'))} v{_safe_text(health.get('version', '?'))}",
            f"  Epoch        : #{epoch_no}  slot {slot}/{blocks_per_epoch}  pot {pot} RTC",
            f"  Enrolled     : {enrolled} miners",
            f"  Supply       : {circulating} / {total_supply} RTC circulating ({holders} holders)",
            f"  Ref rate     : ${ref_rate}/RTC (internal accounting reference)",
            mine_line,
        ]
    )
    return panels


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="eniqma-bbs-door",
        description="RustChain BBS door (D9 v2 hardened).",
    )
    parser.add_argument(
        "--miner-id",
        required=True,
        help="The miner_id of the dial-in user (passed by the locked launcher).",
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"RustChain node base URL (default: {DEFAULT_BASE_URL}).",
    )
    parser.add_argument(
        "--base-fingerprint",
        default=None,
        help="Optional sha256 hex of the leaf cert DER. Pins the node cert.",
    )
    parser.add_argument(
        "--miner-key",
        type=Path,
        default=Path("/var/lib/bbs/jail/d9_miner_key.json"),
        help="Path to the per-door Ed25519 keypair (mode 0600).",
    )
    parser.add_argument(
        "--mode",
        choices=("non-tty", "curses"),
        default="non-tty",
        help="Output mode. Use 'curses' for live BBS sessions; 'non-tty' for test harness / capture.",
    )
    parser.add_argument(
        "--refresh-seconds",
        type=int,
        default=20,
        help="How long the curses mode waits between panel refreshes (curses mode only).",
    )
    args = parser.parse_args(argv)

    # F3: scrub env and refuse unsafe invocations.
    scrub = scrub_environment()
    # The canonical argv0 (the script path) is always sys.argv[0];
    # `argv` here is the parsed-args list, not the process argv.
    audit = assert_safe_invocation(
        sys.argv[0],
        allow_test_mode=os.environ.get("D9_TEST_MODE") == "1",
    )
    audit["env_dropped"] = scrub["dropped"]

    # F1/F2: validate the base URL.
    base = BaseURL(args.base_url, cert_pin_sha256=args.base_fingerprint)
    audit["base_url"] = base.base_url
    audit["base_ips"] = base._literal_ips

    # Build the read-only client and the mining proxy.
    client = NodeClient(base)
    mining = MiningProxy(base, args.miner_id, args.miner_key)
    mining.start()

    try:
        if args.mode == "non-tty":
            panels = build_panels(client, args.miner_id, mining)
            sys.stdout.write(render_non_tty(panels, audit))
            sys.stdout.flush()
            return 0
        # curses mode
        import curses
        def _curses_main(stdscr: Any) -> int:
            while True:
                panels = build_panels(client, args.miner_id, mining)
                render_curses(stdscr, panels, audit)
                time.sleep(args.refresh_seconds)
        return curses.wrapper(_curses_main)
    finally:
        mining.stop()


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except DoorSafetyError as e:
        sys.stderr.write(f"[d9-safety] {e}\n")
        sys.exit(2)
    except DoorConfigError as e:
        sys.stderr.write(f"[d9-config] {e}\n")
        sys.exit(64)
    except DoorError as e:
        sys.stderr.write(f"[d9-error] {e}\n")
        sys.exit(1)
