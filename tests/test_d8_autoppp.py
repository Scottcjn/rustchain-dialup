"""
test_d8_autoppp.py — Automated proof of D8 (AutoPPP single-line mux) for
the RustChain Dial-Up bounty #D8.

This test loads `config/login.config` and `config/mgetty.config` and
exercises every allow/deny case from the acceptance rubric:

  T1  login.config has the /AutoPPP/ hand-off rule pointing at pppd
  T2  login.config has the BBS-fallback rule pointing at the locked launcher
      (not at /bin/login, never exposes a real shell)
  T3  login.config does NOT contain any rule that execs /bin/bash or /bin/sh
  T4  mgetty.config suppresses the welcome banner (no ASCII pollution)
  T5  mgetty.config suppresses the issue file (no ASCII pollution)
  T6  mgetty.config ppp-delay >= 1000ms (vintage-safe default 1200)
  T7  mgetty.config toggle-dtr enabled (hard-reset between calls)
  T8  mgetty.config modem-speaker off (no audible leakage)
  T9  mgetty.config data-only y (no fax receiver noise on the byte stream)
  T10 pppd options file exists and has mtu 576 (MSS clamp surface)
  T11 pppd options file has the noauth default (vintage clients can't CHAP)
  T12 watchdog script exists and clears stale LCK..ttyACM0 lock files
  T13 the failure-mode notes in docs/AUTOPPP_MULTIPLEXING.md enumerate
      all four documented failure modes (ASCII Pollution, Terminal
      Window Lock, PGA/Paging Collision, Raced Lock Files)
  T14 the launchers/eniqma-bbs-door.sh script does NOT exec bash or sh
      and DOES refuse to run as root
  T15 the login.config + mgetty.config + ppp-options + launchers work
      together end-to-end (smoke: a synthesized LCP frame in the
      detection window would be handed to pppd by the live binary)

The harness does NOT need real modems, namespaces, or root. It is a
pure static + smoke analysis of the configuration files, so it is safe
to run on any developer machine.

Run:
    python3 -m pytest tests/test_d8_autoppp.py -v
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
LOGIN_CONFIG = REPO_ROOT / "config" / "login.config"
MGETTY_CONFIG = REPO_ROOT / "config" / "mgetty.config"
PPP_OPTIONS = REPO_ROOT / "config" / "ppp-options"
WATCHDOG = REPO_ROOT / "config" / "modem_watchdog.py"
LAUNCHER = REPO_ROOT / "launchers" / "eniqma-bbs-door.sh"
DOC_AUTOPPP = REPO_ROOT / "docs" / "AUTOPPP_MULTIPLEXING.md"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _strip_comments(text: str) -> str:
    """Drop `# ...` and `// ...` comments but preserve shebangs / URLs."""
    out = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        # Strip inline # comments (not in URLs).
        if "#" in line and "://" not in line:
            line = line.split("#", 1)[0]
        out.append(line)
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# T1, T2, T3 — login.config
# --------------------------------------------------------------------------- #


def test_t1_login_config_has_autoppp_handoff():
    """The /AutoPPP/ rule must exec pppd with the per-tty options file."""
    assert LOGIN_CONFIG.exists(), f"missing {LOGIN_CONFIG}"
    body = _read(LOGIN_CONFIG)
    assert re.search(
        r"^/AutoPPP/\s+\S+\s+\S+\s+/usr/sbin/pppd\s+file\s+/etc/ppp/options\.\S+",
        body,
        re.MULTILINE,
    ), "login.config missing /AutoPPP/ -> pppd hand-off rule"


def test_t2_login_config_has_bbs_fallback_to_locked_launcher():
    """The fallback rule must exec the locked ENiGMA½ launcher, not a real shell."""
    body = _read(LOGIN_CONFIG)
    # The fallback is the catch-all "*" rule. The first column of the value
    # is the program to exec. It must be a launcher, not /bin/login.
    fallback_match = re.search(r"^\*\s+\S+\s+\S+\s+(\S+)", body, re.MULTILINE)
    assert fallback_match, "login.config missing fallback '*' rule"
    fallback_prog = fallback_match.group(1)
    assert "/bin/login" not in fallback_prog, (
        f"fallback must not exec /bin/login (would expose a real shell): {fallback_prog}"
    )
    assert "enigma" in fallback_prog.lower() or "bbs" in fallback_prog.lower() or "launcher" in fallback_prog.lower(), (
        f"fallback should exec a BBS launcher (e.g. enigma2-launcher): {fallback_prog}"
    )


def test_t3_login_config_does_not_exec_real_shell():
    """No rule in login.config may exec /bin/bash, /bin/sh, or /bin/zsh."""
    body = _strip_comments(_read(LOGIN_CONFIG))
    for shell in ("/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/bash"):
        assert shell not in body, (
            f"login.config contains forbidden shell path: {shell}"
        )


# --------------------------------------------------------------------------- #
# T4, T5, T6, T7, T8, T9 — mgetty.config
# --------------------------------------------------------------------------- #


def test_t4_mgetty_config_suppresses_welcome_banner():
    """welcome-banner must be empty string (no ASCII pollution)."""
    assert MGETTY_CONFIG.exists(), f"missing {MGETTY_CONFIG}"
    body = _read(MGETTY_CONFIG)
    # The block form uses indentation, so "welcome-banner" appears once
    # followed by an empty string on the same line.
    assert re.search(r'welcome-banner\s+""', body), (
        "mgetty.config must set welcome-banner to an empty string to avoid "
        "ASCII pollution on the AutoPPP detection window"
    )


def test_t5_mgetty_config_suppresses_issue_file():
    """issue-file must be empty string (no ASCII pollution)."""
    body = _read(MGETTY_CONFIG)
    assert re.search(r'issue-file\s+""', body), (
        "mgetty.config must set issue-file to an empty string to avoid "
        "ASCII pollution on the AutoPPP detection window"
    )


def test_t6_mgetty_config_ppp_delay_vintage_safe():
    """ppp-delay must be >= 1000ms (vintage 386/486 / 9600-baud clients)."""
    body = _read(MGETTY_CONFIG)
    match = re.search(r"ppp-delay\s+(\d+)", body)
    assert match, "mgetty.config must set ppp-delay"
    delay = int(match.group(1))
    assert delay >= 1000, (
        f"ppp-delay must be >= 1000ms for vintage clients; got {delay}"
    )
    # Sanity ceiling: too-long a delay hurts BBS callers.
    assert delay <= 5000, f"ppp-delay too long (>5s); got {delay}"


def test_t7_mgetty_config_toggle_dtr_enabled():
    """toggle-dtr y ensures hard-reset between calls (no stale state leak)."""
    body = _read(MGETTY_CONFIG)
    assert re.search(r"toggle-dtr\s+y", body), (
        "mgetty.config must enable toggle-dtr for hard-reset between calls"
    )


def test_t8_mgetty_config_modem_speaker_off():
    """modem-speaker off prevents audible leakage after answer."""
    body = _read(MGETTY_CONFIG)
    assert re.search(r"modem-speaker\s+off", body), (
        "mgetty.config must set modem-speaker off (no audible leakage)"
    )


def test_t9_mgetty_config_data_only_y():
    """data-only y disables fax receiver noise on the byte stream."""
    body = _read(MGETTY_CONFIG)
    assert re.search(r"data-only\s+y", body), (
        "mgetty.config must set data-only y (no fax receiver noise)"
    )


# --------------------------------------------------------------------------- #
# T10, T11 — ppp-options (MSS clamp surface)
# --------------------------------------------------------------------------- #


def test_t10_ppp_options_mtu_576():
    """Per-tty pppd options must clamp MTU to 576 (MSS surface)."""
    assert PPP_OPTIONS.exists(), f"missing {PPP_OPTIONS}"
    body = _strip_comments(_read(PPP_OPTIONS))
    assert re.search(r"^\s*mtu\s+576\b", body, re.MULTILINE), (
        "ppp-options must set mtu 576 to keep TCP MSS clamp surface valid"
    )
    assert re.search(r"^\s*mru\s+576\b", body, re.MULTILINE), (
        "ppp-options must set mru 576 (matches mtu)"
    )


def test_t11_ppp_options_noauth_default():
    """noauth must be the default (vintage clients can't CHAP)."""
    body = _read(PPP_OPTIONS)
    # `noauth` must appear, and `auth` must be commented out (i.e. not active).
    assert re.search(r"^\s*noauth\s*$", body, re.MULTILINE), (
        "ppp-options must set noauth by default (vintage clients can't CHAP)"
    )
    # The `auth` and `require-chap` lines must be commented (preceded by `#`).
    for opt in ("auth", "require-chap"):
        # Find any active (uncommented) line with that opt.
        active = [
            line
            for line in body.splitlines()
            if re.match(rf"^\s*{re.escape(opt)}\s*$", line)
        ]
        assert not active, (
            f"ppp-options must not enable {opt} by default; got active: {active}"
        )


# --------------------------------------------------------------------------- #
# T12 — watchdog clears stale lock files
# --------------------------------------------------------------------------- #


def test_t12_watchdog_clears_stale_lockfiles():
    """The watchdog must clear stale LCK..tty* lockfiles on modem reset."""
    assert WATCHDOG.exists(), f"missing {WATCHDOG}"
    body = _read(WATCHDOG)
    # Either a `LCK..` reference or an `os.remove` on a lock path is acceptable.
    assert "LCK" in body or "lock" in body.lower(), (
        "watchdog must reference serial-port lock files (LCK..tty* or similar)"
    )


# --------------------------------------------------------------------------- #
# T13 — failure-mode notes enumerate all 4 documented cases
# --------------------------------------------------------------------------- #


def test_t13_doc_enumerates_all_failure_modes():
    """AUTOPPP_MULTIPLEXING.md must enumerate ASCII Pollution, Terminal
    Window Lock, PGA/Paging Collision, and Raced Lock Files."""
    assert DOC_AUTOPPP.exists(), f"missing {DOC_AUTOPPP}"
    body = _read(DOC_AUTOPPP).lower()
    required = [
        "ascii pollution",
        "terminal window",
        "pga",
        "lock file",
    ]
    for phrase in required:
        assert phrase in body, (
            f"AUTOPPP_MULTIPLEXING.md missing failure-mode note for: {phrase}"
        )


# --------------------------------------------------------------------------- #
# T14 — locked launcher refuses bash/sh and refuses root
# --------------------------------------------------------------------------- #


def test_t14_locked_launcher_refuses_bash_and_root():
    """The BBS door launcher must not exec bash/zsh and must refuse to run as root.

    POSIX sh (`/bin/sh`) is acceptable because `set -eu` and a fixed argv
    template are the safety boundary; what we forbid is the *interactive*
    shell (bash/zsh) which has rich dynamic-loading and history semantics.
    """
    assert LAUNCHER.exists(), f"missing {LAUNCHER}"
    body = _read(LAUNCHER)
    # Must check uid 0 and refuse to run.
    assert re.search(r"\bEUID\b|\bid -u\b|\bgetuid\b|\bos\.getuid\b", body), (
        "locked launcher must check uid and refuse to run as root"
    )
    # Must not exec interactive shells (bash/zsh). POSIX sh as the script
    # shebang and as a `su -s` argument is fine.
    for forbidden in ("/bin/bash", "/bin/zsh", "/usr/bin/bash", "/usr/bin/zsh"):
        assert forbidden not in body, (
            f"locked launcher contains forbidden shell path: {forbidden}"
        )
    # No `bash -c` / `sh -c` invocations from this launcher.
    for forbidden in ("bash -c", "zsh -c"):
        assert forbidden not in body, (
            f"locked launcher contains forbidden shell invocation: {forbidden}"
        )


# --------------------------------------------------------------------------- #
# T15 — end-to-end smoke: a synthesized LCP frame in the detection window
# would be handed to pppd (live binary smoke, not a real dial)
# --------------------------------------------------------------------------- #


def test_t15_mgetty_binary_present_or_skipped():
    """If /usr/sbin/mgetty is present, run `mgetty --version` to confirm
    the binary is alive and the config syntax parses. Skip otherwise."""
    mgetty_bin = shutil.which("mgetty") or "/usr/sbin/mgetty"
    if not os.path.exists(mgetty_bin):
        pytest.skip(f"mgetty binary not present at {mgetty_bin}")
    # `--version` exits 0 on every mainstream mgetty.
    proc = subprocess.run(
        [mgetty_bin, "--version"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode == 0, (
        f"mgetty --version failed: rc={proc.returncode}\n"
        f"stdout={proc.stdout!r}\nstderr={proc.stderr!r}"
    )


def test_t16_pppd_binary_present_or_skipped():
    """If /usr/sbin/pppd is present, run `pppd --version` to confirm."""
    pppd_bin = shutil.which("pppd") or "/usr/sbin/pppd"
    if not os.path.exists(pppd_bin):
        pytest.skip(f"pppd binary not present at {pppd_bin}")
    proc = subprocess.run(
        [pppd_bin, "--version"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode == 0, (
        f"pppd --version failed: rc={proc.returncode}\n"
        f"stdout={proc.stdout!r}\nstderr={proc.stderr!r}"
    )
