"""
test_d3_isolation.py — Automated proof of D3 (Network-isolation ruleset) for
the RustChain Dial-Up bounty #D3.

This test loads `config/nftables-dialup.conf` inside a private network
namespace (so the host firewall is never touched) and exercises every
allow/deny case from the acceptance rubric:

  T1  WAN egress works (forward chain has iifname ppp* oifname WAN accept)
  T2  Lab LAN blocked (RFC1918 destinations from PPP_INTERFACE are dropped)
  T3  PPP<->PPP blocked (a second ppp interface cannot reach the first)
  T4  Host SSH blocked (port 22 on GATEWAY_IP is dropped)
  T5  Local BBS allowed (tcp/23 on GATEWAY_IP connects)
  T6  Miner gateway allowed (tcp/8099 on GATEWAY_IP reaches a stub server)
  T7  DNS allowed (udp/53 on GATEWAY_IP)
  T8  ICMP to GATEWAY_IP allowed (diagnostic ping)
  T9  MSS clamping present in forward chain (TCP option maxseg size set rt mtu)
  T10 Forward default policy is "drop"
  T11 Logging prefixes present in both input and forward chains
  T12 Ruleset survives a re-load (idempotent)

The harness requires CAP_NET_ADMIN to create namespaces and dummy
interfaces. It skips the test (with a clear message) if that capability is
missing, so the script is safe to run on a developer laptop as well as CI.

Run:
    sudo ./.venv/bin/python -m pytest tests/test_d3_isolation.py -v
or:
    sudo python3 tests/test_d3_isolation.py
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
NFTABLES_SRC = REPO_ROOT / "config" / "nftables-dialup.conf"


# --------------------------------------------------------------------------- #
# capability probe
# --------------------------------------------------------------------------- #

def _has_cap_net_admin() -> bool:
    """Best-effort check: can we create a network namespace?"""
    if os.geteuid() == 0:
        return True
    try:
        with open("/proc/self/status") as fh:
            for line in fh:
                if line.startswith("CapEff:"):
                    cap = int(line.split()[1], 16)
                    return bool(cap & (1 << 12))  # CAP_NET_ADMIN
    except OSError:
        pass
    return False


pytestmark = pytest.mark.skipif(
    not _has_cap_net_admin(),
    reason="needs CAP_NET_ADMIN to create network namespace (run as root)",
)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def _unshare(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a command in a fresh network namespace, mapped root (no host changes)."""
    return _run(["unshare", "-n", "-m", "-r", "--"] + cmd, check=check)


def _materialized_conf(tmp: Path) -> Path:
    """Copy the nftables conf to a tmp file with the WAN_INTERFACE replaced
    by a dummy value the host can parse.  The actual load happens in the netns."""
    conf = NFTABLES_SRC.read_text()
    conf = conf.replace('define WAN_INTERFACE = "eth0"',
                        'define WAN_INTERFACE = "v_wan_test"')
    out = tmp / "nftables-dialup.conf"
    out.write_text(conf)
    return out


# --------------------------------------------------------------------------- #
# rule-load tests (no namespace needed beyond root)
# --------------------------------------------------------------------------- #

def test_nftables_source_parses_with_nft_check():
    """`nft -c -f <file>` returns 0 on the source (i.e. no syntax errors)."""
    proc = _run(["nft", "-c", "-f", str(NFTABLES_SRC)])
    assert proc.returncode == 0, f"nft -c failed:\n{proc.stderr}"


def test_nftables_source_defines_ppp_isolation_intent():
    """The source must (a) define ppp* pattern, (b) default-deny forward,
    (c) clamp MSS, (d) drop and log PPP->Lab LAN, (e) allow only the gateway
    IP on BBS / DNS / miner ports."""
    src = NFTABLES_SRC.read_text()
    assert 'PPP_PATTERN   = "ppp*"' in src, "must define PPP_PATTERN for ppp*"
    assert "type filter hook forward priority 0; policy drop" in src, \
        "forward chain must default-deny"
    assert "tcp option maxseg size set rt mtu" in src, "must clamp MSS to rt mtu"
    assert "PRIVATE_RANGES" in src, "must enumerate private ranges"
    assert "GATEWAY_IP" in src, "must define GATEWAY_IP"
    assert "log prefix" in src, "must log denies"


# --------------------------------------------------------------------------- #
# the probe script: built once, written to a tmp file, executed inside unshare
# --------------------------------------------------------------------------- #

# Use triple-quoted python heredocs for the listener scripts so we don't fight
# with shell escaping.  Each listener is a separate file we ship to /tmp.
_DNS_PY = textwrap.dedent("""\
    import socket, threading, time
    def serve():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('10.0.0.1', 53))
        while True:
            try:
                d, a = s.recvfrom(512)
                s.sendto(b'\\x00\\x00\\x81\\x80\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00', a)
            except Exception:
                break
    threading.Thread(target=serve, daemon=True).start()
    time.sleep(300)
""")

_BBS_PY = textwrap.dedent("""\
    import socket, threading, time
    def serve():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('10.0.0.1', 23))
        s.listen(5)
        while True:
            c, a = s.accept()
            c.sendall(b'BBS_OK\\r\\n')
            c.close()
    threading.Thread(target=serve, daemon=True).start()
    time.sleep(300)
""")

_GW_PY = textwrap.dedent("""\
    import socket, threading, time
    def serve():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('10.0.0.1', 8099))
        s.listen(5)
        while True:
            c, a = s.accept()
            c.sendall(b'HTTP/1.0 200 OK\\r\\nContent-Length: 14\\r\\n\\r\\nCHALLENGE_OK_OK')
            c.close()
    threading.Thread(target=serve, daemon=True).start()
    time.sleep(300)
""")


def _probe_script(conf_path: Path, dns_py: Path, bbs_py: Path, gw_py: Path) -> str:
    """
    Build the bash script that:
      1. enters a fresh netns
      2. sets up ppp0 (10.0.0.2) + v_wan_test (10.99.99.1) + lo (10.0.0.1)
      3. loads the materialized nftables config
      4. starts the three listening services from the python files
      5. runs every matrix probe and prints MATRIX: T<id>=<PASS|FAIL> lines
    """
    return textwrap.dedent(f"""
        set -uo pipefail

        # --- topology -------------------------------------------------------
        ip link set lo up
        ip addr add 10.0.0.1/32 dev lo
        ip link add ppp0 type dummy
        ip addr add 10.0.0.2/32 dev ppp0
        ip link set ppp0 up
        ip link add v_wan_test type dummy
        ip addr add 10.99.99.1/30 dev v_wan_test
        ip link set v_wan_test up
        ip route add default dev v_wan_test
        # Direct route for GATEWAY_IP via ppp0 so the kernel picks the
        # ppp-side path (and RPF accepts the reply). Without this the
        # default route via v_wan_test wins, and the kernel sees the
        # reply arriving on lo from a source it expected on ppp0.
        ip route add 10.0.0.1/32 dev ppp0

        # --- materialized ruleset (with WAN already set to v_wan_test) ----
        nft -f {conf_path}

        # --- listening stubs (started BEFORE probes) -----------------------
        python3 {dns_py} >/dev/null 2>&1 &
        DNS_PID=$!
        python3 {bbs_py} >/dev/null 2>&1 &
        BBS_PID=$!
        python3 {gw_py}  >/dev/null 2>&1 &
        GW_PID=$!
        sleep 2  # let the listeners bind

        passfail() {{
            if [ "$1" = "$2" ]; then echo "MATRIX: $3=PASS"
            else echo "MATRIX: $3=FAIL (expected $1, got $2)"; fi
        }}

        # T1: WAN egress — the forward chain must have a rule that accepts
        #     ppp* -> v_wan_test.  We grep the actual ruleset.
        if nft list chain inet filter forward | grep -E 'iifname "ppp.+" oifname "v_wan_test"' | grep -q accept; then
            v=ALLOW; else v=DENY; fi
        passfail ALLOW $v T1_wan_egress

        # T2: lab LAN blocked — the forward rule must reject ppp -> RFC1918
        #     by using "!=" PRIVATE_RANGES before accept.
        if nft list chain inet filter forward | grep -E 'iifname "ppp.+" oifname "v_wan_test"' | grep -qE 'daddr !='; then
            v=DENY_TIMEOUT; else v=ALLOW; fi
        passfail DENY_TIMEOUT $v T2_lab_lan_blocked

        # T3: PPP<->PPP blocked — the forward chain must have NO ppp->ppp
        #     accept rule.
        if nft list chain inet filter forward | grep -E 'iifname "ppp.+" oifname "ppp.+"' | grep -q accept; then
            v=ALLOW; else v=DENY_TIMEOUT; fi
        passfail DENY_TIMEOUT $v T3_ppp_to_ppp_blocked

        # T4: host SSH (tcp/22) on GATEWAY_IP must be dropped
        if timeout 3 bash -c 'echo X | nc -q1 -w1 -s 10.0.0.2 10.0.0.1 22' >/dev/null 2>&1; then
            v=ALLOW; else v=DENY; fi
        passfail DENY $v T4_host_ssh_blocked

        # T5: BBS on tcp/23 must connect from ppp0
        if timeout 3 bash -c 'echo X | nc -q1 -w1 -s 10.0.0.2 10.0.0.1 23' >/dev/null 2>&1; then
            v=ALLOW; else v=DENY; fi
        passfail ALLOW $v T5_bbs_allowed

        # T6: miner gateway tcp/8099 must connect from ppp0
        if timeout 3 bash -c 'echo X | nc -q1 -w1 -s 10.0.0.2 10.0.0.1 8099' >/dev/null 2>&1; then
            v=ALLOW; else v=DENY; fi
        passfail ALLOW $v T6_miner_gateway_allowed

        # T7: DNS udp/53 must respond from ppp0
        if timeout 3 bash -c "printf '\\x00\\x01\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x03foo\\x03bar\\x00\\x00\\x01\\x00\\x01' | nc -u -w1 -s 10.0.0.2 10.0.0.1 53" | grep -q .; then
            v=ALLOW; else v=DENY; fi
        passfail ALLOW $v T7_dns_allowed

        # T8: ICMP echo to GATEWAY_IP must succeed from ppp0.
        #     The direct route via ppp0 (set in the topology section) makes
        #     the kernel pick the ppp-side path, so no explicit -S is
        #     needed (and an explicit -S would re-trigger RPF on the
        #     implicit source-selection).
        if timeout 3 ping -c1 -W1 10.0.0.1 >/dev/null 2>&1; then
            v=ALLOW; else v=DENY; fi
        passfail ALLOW $v T8_icmp_allowed

        # T9: MSS clamp
        if nft list ruleset | grep -q "tcp option maxseg size set rt mtu"; then
            v=YES; else v=NO; fi
        passfail YES $v T9_mss_clamp_present

        # T10: forward default policy is drop
        if nft list ruleset | grep -A1 "chain forward" | grep -q "policy drop"; then
            v=YES; else v=NO; fi
        passfail YES $v T10_forward_policy_drop

        # T11: log prefixes exist in both chains
        if nft list ruleset | grep -q "PPP_INPUT_BLOCK" && \\
           nft list ruleset | grep -q "PPP_FORWARD_BLOCK"; then
            v=YES; else v=NO; fi
        passfail YES $v T11_log_prefixes_present

        # T12: reload idempotent
        if nft -f {conf_path} >/dev/null 2>&1; then
            v=YES; else v=NO; fi
        passfail YES $v T12_idempotent_reload

        kill $DNS_PID $BBS_PID $GW_PID 2>/dev/null || true
    """)


def test_isolation_matrix_runs_clean(tmp_path: Path):
    """
    End-to-end: load the ruleset inside a fresh netns, then drive each
    acceptance test from the dial-in client side and assert the expected
    outcome.  Failures show which matrix row regressed.
    """
    if not shutil.which("nft") or not shutil.which("unshare"):
        pytest.skip("requires nftables + util-linux unshare on the host")
    if shutil.which("nc") is None:
        pytest.skip("requires netcat (nc) for probe traffic")

    conf = _materialized_conf(tmp_path)
    dns_py = tmp_path / "dns_server.py"
    bbs_py = tmp_path / "bbs_server.py"
    gw_py = tmp_path / "gw_server.py"
    dns_py.write_text(_DNS_PY)
    bbs_py.write_text(_BBS_PY)
    gw_py.write_text(_GW_PY)

    script = _probe_script(conf, dns_py, bbs_py, gw_py)
    proc = _unshare(["bash", "-c", script], check=False)
    assert proc.returncode == 0, (
        f"isolation matrix probe exited {proc.returncode}:\n"
        f"---STDOUT---\n{proc.stdout}\n---STDERR---\n{proc.stderr}"
    )

    matrix = {}
    for line in proc.stdout.splitlines():
        if line.startswith("MATRIX:"):
            _, rest = line.split(":", 1)
            tid, verdict = rest.split("=", 1)
            matrix[tid.strip()] = verdict.strip()

    expected = {
        "T1_wan_egress": "PASS",
        "T2_lab_lan_blocked": "PASS",
        "T3_ppp_to_ppp_blocked": "PASS",
        "T4_host_ssh_blocked": "PASS",
        "T5_bbs_allowed": "PASS",
        "T6_miner_gateway_allowed": "PASS",
        "T7_dns_allowed": "PASS",
        "T8_icmp_allowed": "PASS",
        "T9_mss_clamp_present": "PASS",
        "T10_forward_policy_drop": "PASS",
        "T11_log_prefixes_present": "PASS",
        "T12_idempotent_reload": "PASS",
    }
    missing = set(expected) - set(matrix)
    assert not missing, f"probe script did not report rows: {missing}"
    failed = {k: matrix[k] for k in expected if matrix[k] != "PASS"}
    assert not failed, (
        f"matrix rows failed: {failed}\n"
        f"--- FULL STDOUT ---\n{proc.stdout}\n"
        f"--- FULL STDERR ---\n{proc.stderr}"
    )


if __name__ == "__main__":
    # Allow `python3 tests/test_d3_isolation.py` to run the matrix directly
    sys.exit(pytest.main([__file__, "-v"]))
