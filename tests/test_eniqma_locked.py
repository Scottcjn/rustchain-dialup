#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# tests/test_eniqma_locked.py — Bounty D4 escape-attempt and audit
# harness for launchers/eniqma-locked.py.
#
# This test suite proves the D4 acceptance rubric:
#
#   1. "BBS reachable on the terminal line via an unprivileged
#      launcher (no host shell escape)" — the launcher refuses to
#      start if the jail is missing or compromised.
#   2. "OS accounts != BBS accounts" — the launcher always drops
#      to the unprivileged bbs user, never to root.
#   3. "Include the launcher + a documented escape-attempt test"
#      — this file IS the escape-attempt test.
#
# Tests run without sudo.  We construct an ephemeral jail under
# tmp_path and feed it to the launcher via --jail-root.  The
# launcher is invoked as a subprocess so we can inspect its
# argv, environment, exit code, and audit log without the
# test runner ever calling systemd-nspawn.
from __future__ import annotations

import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

# Path to the launcher under test.
LAUNCHER = Path(__file__).resolve().parent.parent / "launchers" / "eniqma-locked.py"


# A unprivileged user that is guaranteed to exist on every CI
# image and that we can use as the "bbs" drop target without
# touching the system account database.  `nobody` is uid 65534
# on Debian-derived images, but we look it up dynamically to
# support runners where it is something else.
def _pick_test_user() -> str:
    for name in ("nobody", "bbs", "games"):
        try:
            entry = pwd.getpwnam(name)
            if entry.pw_uid != 0:
                return name
        except KeyError:
            continue
    # Last-ditch: use the current uid's pw_name as long as it
    # is not root.  This means the test still works on a
    # chroot-less runner.
    me = pwd.getpwuid(os.getuid())
    if me.pw_uid == 0:
        pytest.skip(
            "no non-root system user is available; cannot run "
            "privilege-drop tests on this runner"
        )
    return me.pw_name


BBS_USER = _pick_test_user()
BBS_GROUP = BBS_USER  # we use the same name for user and group


def _build_minimal_jail(root: Path) -> None:
    """Create a minimal but valid ENiGMA½ jail under `root`.
    We do not need a real node binary — the launcher runs in
    --dry-run mode during the tests so it never execs the
    BBS.  We DO need the canonical files to be present so the
    jail validation passes."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "etc").mkdir(exist_ok=True)
    (root / "bbs").mkdir(exist_ok=True)
    (root / "bin").mkdir(exist_ok=True)
    # /etc/passwd: just a single comment line, enough to satisfy
    # the existence check.
    (root / "etc" / "passwd").write_text("root:x:0:0:root:/:/bin/sh\n")
    # /bbs/enigma-bbs.js: a placeholder JS file (real ENiGMA½
    # ships a much larger main, but the launcher only checks
    # that the path exists).
    (root / "bbs" / "enigma-bbs.js").write_text(
        "// placeholder for the test harness; real ENiGMA½ "
        "main lives here in production.\n"
    )
    # /bin/sh: a real shell is needed for the validation; we
    # copy the system /bin/sh so the test stays self-contained
    # and the canonical file is NOT a symlink (which the
    # launcher would correctly treat as a possible escape
    # attempt).
    system_sh = Path("/bin/sh")
    if not system_sh.exists():
        system_sh = Path("/usr/bin/sh")
    if system_sh.exists():
        shutil.copyfile(system_sh, root / "bin" / "sh")
        (root / "bin" / "sh").chmod(0o755)
    else:
        # No shell?  Touch an empty file so the existence check
        # still passes.  systemd-nspawn would fail to start in
        # this case, but we are not running it here.
        (root / "bin" / "sh").write_text("#!/bin/false\n")
        (root / "bin" / "sh").chmod(0o755)


def _run_launcher(
    *,
    jail_root: Path,
    audit_log: Path,
    dry_run: bool = True,
    extra_env: dict[str, str] | None = None,
    session_id: str | None = None,
    bbs_user: str = BBS_USER,
    bbs_group: str = BBS_GROUP,
) -> subprocess.CompletedProcess[str]:
    """Invoke the launcher as a subprocess and return the result.
    Uses --dry-run by default so we never exec systemd-nspawn."""
    cmd = [
        sys.executable,
        str(LAUNCHER),
        "--jail-root",
        str(jail_root),
        "--bbs-user",
        bbs_user,
        "--bbs-group",
        bbs_group,
        "--audit-log",
        str(audit_log),
    ]
    if dry_run:
        cmd.append("--dry-run")
    if session_id is not None:
        cmd.extend(["--session-id", session_id])

    # We strip the inherited env to make the test deterministic
    # and prevent a CI env var from accidentally flipping
    # behavior.  PATH stays so Python can be located.
    env = {"PATH": os.environ.get("PATH", "")}
    if extra_env:
        env.update(extra_env)

    return subprocess.run(
        cmd,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )


# --- Positive tests -----------------------------------------------------------


def test_dry_run_succeeds_on_valid_jail(tmp_path: Path) -> None:
    """When the jail has the canonical structure, the launcher
    must run in dry-run mode and emit the deterministic
    DRY-RUN line."""
    jail = tmp_path / "jail"
    _build_minimal_jail(jail)
    audit = tmp_path / "audit.jsonl"
    result = _run_launcher(jail_root=jail, audit_log=audit, session_id="test-ok")
    assert result.returncode == 0, (
        f"launcher refused a valid jail: rc={result.returncode} "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert "DRY-RUN" in result.stdout
    assert f"jail={jail}" in result.stdout
    # Audit record must be a single line of valid JSON with the
    # expected event.
    lines = audit.read_text().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["event"] == "start"
    assert record["session_id"] == "test-ok"
    assert record["machine"].startswith("bbs-test-ok")
    assert record["jail_root"] == str(jail.resolve())


def test_audit_log_uses_canonical_event_schema(
    tmp_path: Path,
) -> None:
    """The audit log must use the documented schema.  If a
    reviewer rewrites the launcher, this test pins the field
    names so a future change is intentional."""
    jail = tmp_path / "jail"
    _build_minimal_jail(jail)
    audit = tmp_path / "audit.jsonl"
    _run_launcher(jail_root=jail, audit_log=audit, session_id="schema")
    record = json.loads(audit.read_text().splitlines()[0])
    required = {
        "event",
        "session_id",
        "machine",
        "pid",
        "ppid",
        "bbs_uid",
        "bbs_gid",
        "jail_root",
        "env",
        "argv0",
        "started_at",
    }
    assert required.issubset(record.keys())


# --- Escape-attempt tests -----------------------------------------------------


def test_refuses_missing_jail(tmp_path: Path) -> None:
    """If the jail root does not exist, the launcher must refuse
    with EX_TEMPFAIL (75) and write a `refused` audit record.
    Falling back to a host shell here would be the canonical
    escape."""
    nonexistent = tmp_path / "does-not-exist"
    audit = tmp_path / "audit.jsonl"
    result = _run_launcher(jail_root=nonexistent, audit_log=audit, session_id="missing")
    assert result.returncode == 75
    assert "refusing" in result.stderr
    record = json.loads(audit.read_text().splitlines()[0])
    assert record["event"] == "refused"
    assert "does not exist" in record["reason"]


def test_refuses_jail_with_missing_canonical_file(
    tmp_path: Path,
) -> None:
    """A jail that is missing /bbs/enigma-bbs.js is broken.  The
    launcher must NOT silently start a shell instead."""
    jail = tmp_path / "jail"
    _build_minimal_jail(jail)
    # Remove the canonical BBS main so the jail fails validation.
    (jail / "bbs" / "enigma-bbs.js").unlink()
    audit = tmp_path / "audit.jsonl"
    result = _run_launcher(jail_root=jail, audit_log=audit, session_id="no-bbs")
    assert result.returncode == 75
    assert "refusing" in result.stderr
    record = json.loads(audit.read_text().splitlines()[0])
    assert record["event"] == "refused"
    assert "enigma-bbs.js" in record["reason"]


def test_refuses_symlinked_jail_root(tmp_path: Path) -> None:
    """If the jail root itself is a symlink, the launcher must
    refuse.  An attacker who can write to the parent directory
    could redirect the jail to /home and read host files."""
    real_jail = tmp_path / "real-jail"
    _build_minimal_jail(real_jail)
    link = tmp_path / "linked-jail"
    os.symlink(real_jail, link)
    audit = tmp_path / "audit.jsonl"
    result = _run_launcher(jail_root=link, audit_log=audit, session_id="symlink-root")
    assert result.returncode == 75
    assert "symlink" in result.stderr.lower()


def test_refuses_symlinked_canonical_file(tmp_path: Path) -> None:
    """Symlink any canonical file inside the jail — even a real
    ENiGMA½ install — and the launcher refuses.  This blocks
    the 'swap the binary for a shell' attack."""
    jail = tmp_path / "jail"
    _build_minimal_jail(jail)
    # Replace the BBS main with a symlink to /bin/sh.
    target = jail / "bbs" / "enigma-bbs.js"
    target.unlink()
    os.symlink("/bin/sh", target)
    audit = tmp_path / "audit.jsonl"
    result = _run_launcher(jail_root=jail, audit_log=audit, session_id="symlink-file")
    assert result.returncode == 75
    assert "symlink" in result.stderr.lower()


def test_refuses_audit_log_symlink(tmp_path: Path) -> None:
    """The audit log must not be a symlink.  An attacker who
    can write to /var/log could symlink the audit log to
    /dev/null to drop their own trail."""
    jail = tmp_path / "jail"
    _build_minimal_jail(jail)
    # First let the launcher create the audit log...
    audit_real = tmp_path / "real-audit.jsonl"
    _run_launcher(jail_root=jail, audit_log=audit_real, session_id="setup")
    # ...then point a symlink at it and try again.
    audit_link = tmp_path / "audit-link.jsonl"
    os.symlink(audit_real, audit_link)
    result = _run_launcher(
        jail_root=jail, audit_log=audit_link, session_id="link-audit"
    )
    # The audit log is required for start, so refusal is
    # acceptable; the loader must never silently follow the
    # symlink and start the BBS.
    assert result.returncode == 75
    assert "symlink" in result.stderr.lower()


def test_shell_env_var_does_not_affect_launcher(
    tmp_path: Path,
) -> None:
    """$SHELL=/bin/bash set by a captive user must have no
    effect.  The launcher never reads $SHELL.  This is a
    defense-in-depth check — even if mgetty ever forwards
    $SHELL, the launcher must not start a host shell."""
    jail = tmp_path / "jail"
    _build_minimal_jail(jail)
    audit = tmp_path / "audit.jsonl"
    result = _run_launcher(
        jail_root=jail,
        audit_log=audit,
        session_id="shell-env",
        extra_env={"SHELL": "/bin/bash", "BASH_ENV": "/etc/profile"},
    )
    assert result.returncode == 0
    # The audit record must show the launcher used its own
    # fixed env, not the captive user's $SHELL or $BASH_ENV.
    record = json.loads(audit.read_text().splitlines()[0])
    assert "SHELL" not in record["env"] or record["env"].get("SHELL") in (None, "")


def test_session_id_is_canonical_for_machine_name(
    tmp_path: Path,
) -> None:
    """The machine name surfaced to `machinectl list` must be
    safe (alnum + ._-) so an operator can grep / journalctl
    on it without shell-quoting concerns."""
    jail = tmp_path / "jail"
    _build_minimal_jail(jail)
    audit = tmp_path / "audit.jsonl"
    _run_launcher(
        jail_root=jail,
        audit_log=audit,
        session_id="weird!@# session$id",  # noqa: S106
    )
    record = json.loads(audit.read_text().splitlines()[0])
    machine = record["machine"]
    assert all(c.isalnum() or c in "._-" for c in machine)
    assert machine.startswith("bbs-")


def test_unknown_bbs_user_refuses(tmp_path: Path) -> None:
    """If the configured bbs user does not exist, the launcher
    refuses.  This is a safety net: a captive user can never
    set --bbs-user, but a misconfigured operator can."""
    jail = tmp_path / "jail"
    _build_minimal_jail(jail)
    audit = tmp_path / "audit.jsonl"
    result = _run_launcher(
        jail_root=jail,
        audit_log=audit,
        session_id="bad-user",
        bbs_user="definitely-no-such-user-xyzzy",
    )
    assert result.returncode == 75
    assert "refusing" in result.stderr


def test_root_bbs_user_refuses(tmp_path: Path) -> None:
    """If the configured bbs user is actually UID 0, refuse."""
    jail = tmp_path / "jail"
    _build_minimal_jail(jail)
    audit = tmp_path / "audit.jsonl"
    result = _run_launcher(
        jail_root=jail,
        audit_log=audit,
        session_id="root-user",
        bbs_user="root",
    )
    assert result.returncode == 75
    assert "UID 0" in result.stderr


def test_audit_log_is_append_only(tmp_path: Path) -> None:
    """Two consecutive sessions must produce two audit lines
    (not one overwritten).  This is the basic
    non-repudiation guarantee."""
    jail = tmp_path / "jail"
    _build_minimal_jail(jail)
    audit = tmp_path / "audit.jsonl"
    _run_launcher(jail_root=jail, audit_log=audit, session_id="first")
    _run_launcher(jail_root=jail, audit_log=audit, session_id="second")
    lines = audit.read_text().splitlines()
    assert len(lines) == 2
    sids = [json.loads(line)["session_id"] for line in lines]
    assert sids == ["first", "second"]


def test_audit_log_permission_strict(tmp_path: Path) -> None:
    """Audit log must be created with mode 0640 (group readable
    by `adm`, not world-readable).  Captive users are not in
    the `adm` group so they cannot read their own or others'
    audit entries."""
    jail = tmp_path / "jail"
    _build_minimal_jail(jail)
    audit = tmp_path / "audit.jsonl"
    _run_launcher(jail_root=jail, audit_log=audit, session_id="perm")
    mode = stat.S_IMODE(audit.stat().st_mode)
    assert mode == 0o640
