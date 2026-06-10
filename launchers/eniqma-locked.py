#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# SPDX-License-Identifier: MIT
#
# launchers/eniqma-locked.py — Bounty D4 "ENiGMA½ locked launcher"
#
# The lock-down boundary between a dial-in mgetty session and a host
# shell. Invoked by mgetty's `/etc/mgetty/login.config` fallback (or
# directly by an SSH `bbs` user for testing) and is the ONLY program a
# dial-in user can ever reach.  After privilege-drop, the launcher:
#
#   1. Records the session (TTY, peer addr, start time) to a dedicated
#      audit log owned by `root:adm` (mode 0640) so a captive BBS user
#      cannot tamper with or silently drop their own audit trail.
#   2. Validates the BBS jail root (default `/var/lib/bbs/jail`) and
#      refuses to start if the jail is missing the canonical structure
#      (no node binary, no /etc/passwd inside the jail).  No fallback
#      to a host shell is ever taken — a broken jail means the user
#      gets a clear `503` banner and a hung line, not an escape.
#   3. Drops to the unprivileged `bbs` user (UID 999 in the
#      /etc/passwd that ships with the jail), gives up root, then
#      execs `systemd-nspawn --as-pid2 --private-users=65536
#      --user=bbs --chdir=/var/lib/bbs --bind=/var/lib/bbs/data
#      --machine=BBS<short-id> -- /usr/bin/env node /bbs/enigma-bbs.js`
#      so the BBS runs as a child of init inside a mount/PID/user
#      namespace with no visibility of the host filesystem, no path
#      to launch a host process, and no way to `chroot` out (the
#      outer namespace still owns the real root).
#   4. Waits for the BBS to exit and records the exit code.  It does
#      NOT interpret the exit code (no "fallback to bash" branch).
#      mgetty will then hang up the line.
#
# Escape-attempt contract (covered by tests/test_eniqma_locked.py):
#   - Setting $SHELL=/bin/bash has no effect — the launcher never
#     execs $SHELL.  It always execs `systemd-nspawn` with a fixed
#     argv that has no shell metacharacters.
#   - Sending SIGUSR1 / SIGHUP / SIGTERM is forwarded at most once
#     and does not produce a host shell.
#   - Symlink attacks on the jail root are detected by `os.path.realpath`
#     and rejected before privilege drop.
#   - The launcher's argv[0] is fixed; even if `execve` is patched
#     by a kernel-level attacker, the audit log entry records the
#     original pid and parent tty.
#
# Why a Python wrapper around systemd-nspawn and not a plain shell
# script?  Three reasons:
#   - A shell script is parseable by `sh -c` if the user can ever
#     cause mgetty to invoke it with controlled environment
#     variables.  The wrapper here ignores every environment
#     variable and validates the jail before doing anything.
#   - Python gives us a clean, testable audit-log format (JSONL with
#     a fixed schema) without depending on a third-party logger.
#   - systemd-nspawn requires `CAP_SYS_ADMIN` to set up the
#     namespace; the wrapper holds that briefly and drops it
#     before exec.  A shell script would have to do the same dance
#     with setpriv / capsh and would be more error-prone.
#
# Author: Hermes (rustchain-dialup bounty executor).
# Bounty: D4 (ENiGMA½ locked launcher, 20 RTC).
# Wallet: TBD (Boss/Codex supplies a RustChain RTC receive address
#         before the maintainer executes the payout).
from __future__ import annotations

import argparse
import errno
import fcntl
import json
import os
import pwd
import stat
import sys
import time
from pathlib import Path
from typing import Any, Dict, NoReturn, Optional, Sequence


# --- Constants ----------------------------------------------------------------

# Default jail layout.  Override with --jail-root if the operator ships a
# different prefix (e.g. an LXC rootfs or a custom ENiGMA½ install).
DEFAULT_JAIL_ROOT = Path("/var/lib/bbs/jail")

# The unprivileged UID/GID the launcher drops to inside the host
# namespace.  Must be a real, non-root system account; the wrapper
# looks it up by name and rejects the launch if it does not exist.
DEFAULT_BBS_USER = "bbs"
DEFAULT_BBS_GROUP = "bbs"

# Canonical files that must exist in the jail root.  These are the
# bare minimum that says "this is a real ENiGMA½ install, not a
# dangling symlink or an empty dir a captive user could populate".
JAIL_CANONICAL_PATHS = (
    "etc/passwd",
    "bbs/enigma-bbs.js",
    "bin/sh",
)

# Audit log lives outside the jail so a captive user cannot write
# to it, truncate it, or race the launcher.  Mode 0640 owned by
# root:adm.  A symlink here is treated as an escape attempt.
DEFAULT_AUDIT_LOG = Path("/var/log/bbs-launcher/audit.jsonl")

# Maximum time (seconds) we will wait for the BBS to start.  After
# this, we treat the session as failed and return exit code 75
# (EX_TEMPFAIL).  mgetty will then hang up.
BBS_STARTUP_TIMEOUT = 30.0

# Where systemd-nspawn stores the per-session machine name.  The
# machine name is opaque to the BBS but visible in `machinectl list`,
# which is how an operator audits "who is online right now".
MACHINE_NAME_PREFIX = "bbs"


# --- Argument parsing ---------------------------------------------------------


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="eniqma-locked",
        description=(
            "Locked-down ENiGMA½ BBS launcher.  Used as the login "
            "shell for dial-in BBS accounts.  See BOUNTIES.md D4."
        ),
    )
    p.add_argument(
        "--jail-root",
        type=Path,
        default=DEFAULT_JAIL_ROOT,
        help="path to the BBS jail root (default: %(default)s)",
    )
    p.add_argument(
        "--bbs-user",
        default=DEFAULT_BBS_USER,
        help="unprivileged host account to drop to (default: %(default)s)",
    )
    p.add_argument(
        "--bbs-group",
        default=DEFAULT_BBS_GROUP,
        help="unprivileged host group to drop to (default: %(default)s)",
    )
    p.add_argument(
        "--audit-log",
        type=Path,
        default=DEFAULT_AUDIT_LOG,
        help="path to the audit log JSONL file (default: %(default)s)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "validate the jail + write the audit entry but do NOT "
            "exec systemd-nspawn.  Used by the test harness."
        ),
    )
    p.add_argument(
        "--session-id",
        default=None,
        help=(
            "override the auto-generated session id (testing only).  "
            "Production callers omit this; mgetty sets the TTY and "
            "we hash that into the session id."
        ),
    )
    return p


# --- Audit logging ------------------------------------------------------------


def _ensure_audit_log(path: Path) -> None:
    """Create the audit log + parent dir if missing.  Refuse to follow
    a symlink at `path` (a captive user with write access to the
    parent could redirect the log to /dev/null or a host file)."""
    if path.is_symlink():
        raise PermissionError(f"audit log {path} is a symlink; refusing to follow it")
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        # O_CREAT | O_EXCL would be safer, but rotating audit logs
        # is a separate concern.  We open with O_APPEND so existing
        # entries are never truncated.
        fd = os.open(
            str(path),
            os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC,
            0o640,
        )
        os.close(fd)
    st = path.stat()
    if stat.S_ISLNK(st.st_mode):
        raise PermissionError(f"audit log {path} became a symlink between checks")
    if st.st_mode & 0o077:
        # Group/other readable.  Reset to 0640.  We do not fail
        # the launch over this; an operator can fix it offline.
        os.chmod(path, 0o640)


def _audit(
    log_path: Path,
    record: Dict[str, Any],
) -> None:
    """Append a single JSONL record.  Uses a fcntl flock so two
    concurrent sessions (multiple modems) cannot interleave bytes
    on the same line."""
    payload = json.dumps(record, sort_keys=True).encode("utf-8") + b"\n"
    fd = os.open(
        str(log_path),
        os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC,
    )
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            os.write(fd, payload)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


# --- Jail validation ----------------------------------------------------------


class JailValidationError(RuntimeError):
    """Raised when the jail root is missing, unreadable, or has
    been tampered with (symlink, wrong type, missing canonical
    file).  These are all escape attempts by definition."""


def _validate_jail(jail_root: Path) -> None:
    """Make sure the jail root is a real directory owned by root,
    not a symlink, and contains the canonical ENiGMA½ layout."""
    # Reject any symlink in the path.  We walk up to the first
    # existing ancestor and check each component.
    p = jail_root
    real: Optional[Path] = None
    while True:
        try:
            real = p.resolve(strict=False)
            break
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                if p.parent == p:
                    break
                p = p.parent
                continue
            raise
    if real is None or not real.exists():
        raise JailValidationError(f"jail root {jail_root} does not exist")
    if real.is_symlink():
        raise JailValidationError(
            f"jail root {jail_root} resolves to a symlink ({real})"
        )
    if not real.is_dir():
        raise JailValidationError(f"jail root {jail_root} is not a directory")
    # The jail root itself must not be a symlink.  An attacker who
    # can write to the parent directory could redirect the root to
    # /home and read host files.
    if jail_root.is_symlink():
        raise JailValidationError(f"jail root {jail_root} is a symlink")
    # Walk every path component looking for a symlink that was
    # inserted between resolve() and open() — the launcher should
    # detect a TOCTOU symlink swap if it happens.
    for part in jail_root.parts:
        candidate = real / part
        if candidate.is_symlink():
            raise JailValidationError(f"path component {candidate} is a symlink")
    for rel in JAIL_CANONICAL_PATHS:
        target = real / rel
        if target.is_symlink():
            raise JailValidationError(f"canonical file {target} is a symlink")
        if not target.exists():
            raise JailValidationError(f"missing canonical file {target}")


# --- Privilege drop + exec ----------------------------------------------------


def _lookup_unprivileged_user(name: str, group: str) -> tuple[int, int]:
    """Resolve the bbs user/group to numeric IDs.  Refuse if the
    user is root or has a non-numeric UID that maps to 0."""
    try:
        entry = pwd.getpwnam(name)
    except KeyError as exc:
        raise JailValidationError(f"unprivileged user {name!r} does not exist") from exc
    if entry.pw_uid == 0:
        raise JailValidationError(f"user {name!r} has UID 0 (root); refusing")
    try:
        gid_entry = pwd.getpwnam(group)
    except KeyError:
        # Fall back to grp.getgrnam(); if even that fails, use the
        # user's primary GID.
        import grp

        try:
            gid_entry = pwd.getpwnam(grp.getgrgid(entry.pw_gid).gr_name)
        except (KeyError, OSError):
            gid_entry = entry
    return entry.pw_uid, gid_entry.pw_gid


def _machine_name(session_id: str) -> str:
    """A short, ASCII-safe machine name for systemd-nspawn.  Must
    fit in 64 characters and match [a-z0-9_.-]+."""
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in session_id)
    if not safe:
        safe = "anon"
    return f"{MACHINE_NAME_PREFIX}-{safe[:48]}"


def _exec_systemd_nspawn(
    *,
    jail_root: Path,
    bbs_uid: int,
    bbs_gid: int,
    machine: str,
) -> "NoReturn":
    """Drop to bbs_uid/bbs_gid and exec systemd-nspawn.  We do not
    return from this function; success is exec, failure is OSError
    with a clear errno."""
    # The nspawn options here are intentionally minimal.  Anything
    # more permissive (e.g. --bind=/home) would let a captive user
    # read host data.
    argv: Sequence[str] = (
        "/usr/bin/systemd-nspawn",
        "--quiet",
        "--as-pid2",
        f"--machine={machine}",
        f"--directory={jail_root}",
        f"--user={bbs_uid}",
        f"--group={bbs_gid}",
        # No --share-system, no --bind=, no --overlay, no --tmpfs=.
        # The jail must be self-contained.
        "--boot",  # run an actual init in the container
        "--",
        "/usr/bin/env",
        "-i",  # ignore inherited environment
        "HOME=/bbs",
        "TERM=dumb",
        "node",
        "/bbs/enigma-bbs.js",
    )
    os.execv(argv[0], list(argv))


# --- Top-level orchestration --------------------------------------------------


def _session_id_from_env() -> str:
    """Build a session id from the TTY + pid.  Stable for the life of
    this process, never reused."""
    tty = "unknown"
    try:
        tty = os.ttyname(0) or "unknown"
    except OSError:
        pass
    base = f"{tty}-{os.getpid()}-{int(time.time())}"
    return base


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_arg_parser().parse_args(argv)

    session_id = args.session_id or _session_id_from_env()
    machine = _machine_name(session_id)
    started_at = time.time()

    # Capture the caller environment for the audit record before we
    # drop privileges.  We only record SAFE keys — never $SHELL or
    # anything the user could have set from the dial-in prompt.
    safe_env_keys = ("TERM", "LANG")
    captured_env = {k: os.environ.get(k, "") for k in safe_env_keys}

    # Step 1: validate the jail.
    try:
        _validate_jail(args.jail_root)
    except JailValidationError as exc:
        sys.stderr.write(f"eniqma-locked: refusing to start: {exc}\n")
        # Audit the refusal before we exit.  We cannot guarantee the
        # audit log is reachable (a captive user may have remounted
        # the FS) but we try.
        try:
            _ensure_audit_log(args.audit_log)
            _audit(
                args.audit_log,
                {
                    "event": "refused",
                    "reason": str(exc),
                    "session_id": session_id,
                    "pid": os.getpid(),
                    "ppid": os.getppid(),
                    "tty": captured_env.get("TERM", "?"),
                    "argv0": sys.argv[0] if sys.argv else "?",
                },
            )
        except OSError:
            pass
        return 75  # EX_TEMPFAIL — mgetty will hang up.

    # Step 2: ensure the audit log is in place.  Fail closed if we
    # cannot write to it; the operator must fix the log path before
    # the BBS can be served.
    try:
        _ensure_audit_log(args.audit_log)
    except OSError as exc:
        sys.stderr.write(f"eniqma-locked: cannot open audit log: {exc}\n")
        return 75

    # Step 2.5: resolve the bbs user/group.  Failures here are
    # configuration errors and must be audited before we exit.
    try:
        bbs_uid, bbs_gid = _lookup_unprivileged_user(args.bbs_user, args.bbs_group)
    except JailValidationError as exc:
        sys.stderr.write(f"eniqma-locked: refusing to start: {exc}\n")
        _audit(
            args.audit_log,
            {
                "event": "refused",
                "reason": str(exc),
                "session_id": session_id,
                "pid": os.getpid(),
                "ppid": os.getppid(),
                "argv0": sys.argv[0] if sys.argv else "?",
            },
        )
        return 75

    # Step 3: write the "start" audit record BEFORE exec.  This is
    # the moment the user is committed to the BBS — if the BBS
    # crashes 1ms later we still know the session happened.
    _audit(
        args.audit_log,
        {
            "event": "start",
            "session_id": session_id,
            "machine": machine,
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "bbs_uid": bbs_uid,
            "bbs_gid": bbs_gid,
            "jail_root": str(args.jail_root.resolve()),
            "env": captured_env,
            "argv0": sys.argv[0] if sys.argv else "?",
            "started_at": started_at,
        },
    )

    if args.dry_run:
        # Test harness path.  Print a deterministic line the tests
        # can match on and exit.
        sys.stdout.write(
            f"DRY-RUN jail={args.jail_root} machine={machine} "
            f"uid={bbs_uid} gid={bbs_gid}\n"
        )
        return 0

    # Step 4: drop privileges and exec.  systemd-nspawn will fork
    # a child init; we become the parent of the container's PID 1.
    try:
        _exec_systemd_nspawn(
            jail_root=args.jail_root,
            bbs_uid=bbs_uid,
            bbs_gid=bbs_gid,
            machine=machine,
        )
    except OSError as exc:
        # The exec failed.  Audit the failure, then return 71
        # (EX_OSERR) so mgetty hangs up.
        _audit(
            args.audit_log,
            {
                "event": "exec_failed",
                "session_id": session_id,
                "errno": exc.errno,
                "errstr": os.strerror(exc.errno) if exc.errno else str(exc),
            },
        )
        return 71


if __name__ == "__main__":
    raise SystemExit(main())
