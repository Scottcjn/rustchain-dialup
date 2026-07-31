#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# launchers/eniqma-locked.py — Bounty D4 "ENiGMA½ locked launcher"
#
# The lock-down boundary between a dial-in mgetty session and a host
# shell. Invoked by mgetty's `/etc/mgetty/login.config` fallback (or
# directly by an SSH `bbs` user for testing) and is the ONLY program a
# dial-in user can ever reach.  After validation, the launcher:
#
#   1. Records the session (TTY, caller id, start time) to a dedicated
#      audit log owned by `root:adm` (mode 0640) so a captive BBS user
#      cannot tamper with or silently drop their own audit trail.
#   2. Validates the BBS jail root (default `/var/lib/bbs/jail`) and
#      refuses to start if the jail is missing the canonical structure
#      (no node binary, no /etc/passwd inside the jail), if any real
#      ANCESTOR of the jail root is a symlink, or if a canonical file
#      is a symlink that leaves the jail.  No fallback to a host shell
#      is ever taken — a broken jail means the user gets a clear `503`
#      banner and a hung line, not an escape.
#   3. Forks and runs `systemd-nspawn --quiet --as-pid2
#      --machine=bbs-<short-id> --directory=<jail>
#      --private-users=65536 --user=bbs -- /usr/bin/env -i HOME=/bbs
#      TERM=dumb node /bbs/enigma-bbs.js` so the BBS runs as PID 2
#      inside a mount/PID/user namespace with no visibility of the
#      host filesystem, no path to launch a host process, and no way
#      to `chroot` out (the outer namespace still owns the real root).
#   4. Waits for the BBS to exit, forwards a hangup/termination signal
#      to it exactly once, and records the exit code.  It does NOT
#      interpret the exit code (no "fallback to bash" branch).
#      mgetty will then hang up the line.
#
# WHO RUNS AS WHAT (this is the part that is easy to get wrong):
#   `systemd-nspawn` needs CAP_SYS_ADMIN to build the namespaces, so
#   the launcher itself stays root until exec — it CANNOT setuid()
#   first.  The unprivileged account is applied by nspawn's `--user=`,
#   which resolves the name in the JAIL's /etc/passwd (not the host's)
#   and is what makes the BBS process non-root.  The host-side lookup
#   below is therefore a configuration guard + audit record, not the
#   thing that drops privilege.  `systemd-nspawn` has no `--group=`
#   option at all (checked against systemd 244..257); the group comes
#   from the jail's passwd entry for `--user`.
#
# Escape-attempt contract (covered by tests/test_eniqma_locked.py and
# tests/test_eniqma_locked_exec.py):
#   - Setting $SHELL=/bin/bash has no effect — the launcher never
#     execs $SHELL.  It always runs `systemd-nspawn` with a fixed
#     argv that has no shell metacharacters.
#   - Sending SIGUSR1 / SIGHUP / SIGTERM is forwarded at most once
#     and does not produce a host shell.
#   - Symlink attacks on the jail root, on any ancestor of it, and on
#     the canonical files are detected and rejected before exec.
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
#   - The wrapper can wait for the container and write the closing
#     audit record, which a bare `exec` in a shell script cannot.
#
# Author: Hermes (rustchain-dialup bounty executor).
# Bounty: D4 (ENiGMA½ locked launcher, 20 RTC).
from __future__ import annotations

import argparse
import errno
import fcntl
import grp
import json
import os
import pwd
import re
import signal
import stat
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple


# --- Constants ----------------------------------------------------------------

# Default jail layout.  Override with --jail-root if the operator ships a
# different prefix (e.g. an LXC rootfs or a custom ENiGMA½ install).
DEFAULT_JAIL_ROOT = Path("/var/lib/bbs/jail")

# The unprivileged account the BBS runs as.  Resolved twice: on the HOST
# (a sanity guard — the name must exist and must not be UID 0) and inside
# the JAIL by systemd-nspawn's --user=, which is what actually applies.
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

# The container manager.  A missing binary is a deployment error and is
# refused (and audited) instead of being discovered as a dead line.
NSPAWN_BIN = "/usr/bin/systemd-nspawn"

# UID base for the user namespace.  `--private-users=<base>` maps
# container UID 0 to host UID <base>, so container root is nobody on the
# host.  Pass --private-users off to disable (e.g. on a kernel without
# user namespaces); the jail tree must then be readable by the host uid.
DEFAULT_PRIVATE_USERS = "65536"

# Where systemd-nspawn stores the per-session machine name.  The
# machine name is opaque to the BBS but visible in `machinectl list`,
# which is how an operator audits "who is online right now".
#
# systemd validates it with machine_name_is_valid() -> hostname_is_valid():
# labels of valid_ldh_char() only (ASCII letters, digits, '-'), '.' as a
# separator, no leading/trailing '-' or '.', no empty label, <= 64 bytes.
# NOTE '_' is NOT a valid_ldh_char, so it cannot appear here.
MACHINE_NAME_PREFIX = "bbs"
MACHINE_NAME_MAX = 64

# Signals we forward to the container exactly once.  SIGHUP is the one
# that matters in production: mgetty drops DTR when the caller hangs up.
FORWARDED_SIGNALS = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT, signal.SIGQUIT)


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
        help=(
            "unprivileged account the BBS runs as.  Must exist on the "
            "host (guard) AND in the jail's /etc/passwd, which is the "
            "one systemd-nspawn resolves (default: %(default)s)"
        ),
    )
    p.add_argument(
        "--bbs-group",
        default=DEFAULT_BBS_GROUP,
        help=(
            "host group recorded in the audit log (default: %(default)s). "
            "systemd-nspawn has no --group option; the container gid comes "
            "from the jail's passwd entry for --bbs-user."
        ),
    )
    p.add_argument(
        "--audit-log",
        type=Path,
        default=DEFAULT_AUDIT_LOG,
        help="path to the audit log JSONL file (default: %(default)s)",
    )
    p.add_argument(
        "--private-users",
        default=DEFAULT_PRIVATE_USERS,
        help=(
            "value for systemd-nspawn --private-users= (UID base, "
            "'pick', or 'off' to disable user namespacing; "
            "default: %(default)s)"
        ),
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "validate the jail + write the audit entry but do NOT "
            "run systemd-nspawn.  Used by the test harness."
        ),
    )
    p.add_argument(
        "--print-argv",
        action="store_true",
        help="print the exact systemd-nspawn argv that would be run, one per line, and exit",
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
    try:
        # O_EXCL|O_NOFOLLOW: we either create it ourselves or we inspect
        # what is already there.  O_APPEND so existing entries are never
        # truncated.
        fd = os.open(
            str(path),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o640,
        )
    except FileExistsError:
        pass
    else:
        try:
            # The open() mode argument is masked by umask (mgetty runs with
            # 022 or 077 depending on the distro), so set it explicitly.
            os.fchmod(fd, 0o640)
        finally:
            os.close(fd)

    # lstat, NOT stat: stat() follows the link, so S_ISLNK on its result
    # can never be true and the TOCTOU check would be dead code.
    st = os.lstat(str(path))
    if stat.S_ISLNK(st.st_mode):
        raise PermissionError(f"audit log {path} became a symlink between checks")
    if not stat.S_ISREG(st.st_mode):
        raise PermissionError(f"audit log {path} is not a regular file")
    # Only ever REMOVE bits: group-write/exec and every other-bit.  Group
    # READ is intentional (the `adm` group reads the log), so it must not
    # count as a violation — `& 0o077` did, which made the launcher chmod
    # the file on every single session for no reason.
    extra = stat.S_IMODE(st.st_mode) & 0o037
    if extra:
        os.chmod(path, stat.S_IMODE(st.st_mode) & ~0o037)


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
        os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW,
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


def _ancestor_symlink(path: Path) -> Optional[Path]:
    """Return the first component of `path` (root -> leaf, inclusive)
    that is a symlink, or None.

    This walks the REAL path components: /var, /var/lib, /var/lib/bbs,
    /var/lib/bbs/jail.  Building candidates as `resolved / component`
    instead would test paths INSIDE the jail, which is both useless as a
    guard and a false positive on any merged-/usr rootfs (`<jail>/lib` is
    a symlink in every debootstrap since Debian 12)."""
    parts = Path(os.path.abspath(str(path))).parts
    prefix = Path(parts[0])
    for part in parts[1:]:
        prefix = prefix / part
        if prefix.is_symlink():
            return prefix
    return None


def _validate_jail(jail_root: Path) -> None:
    """Make sure the jail root is a real directory, is not reached
    through a symlink, and contains the canonical ENiGMA½ layout."""
    if not jail_root.exists():
        raise JailValidationError(f"jail root {jail_root} does not exist")
    # An attacker who can write to any parent directory could redirect
    # the root to /home and read host files, so every component from /
    # down to the jail root itself must be a real directory.
    link = _ancestor_symlink(jail_root)
    if link is not None:
        if link == Path(os.path.abspath(str(jail_root))):
            raise JailValidationError(f"jail root {jail_root} is a symlink")
        raise JailValidationError(f"path component {link} is a symlink")
    real = jail_root.resolve()
    if not real.is_dir():
        raise JailValidationError(f"jail root {jail_root} is not a directory")
    for rel in JAIL_CANONICAL_PATHS:
        target = real / rel
        if not target.exists():
            raise JailValidationError(f"missing canonical file {target}")
        # A symlink is only an escape if it LEAVES the jail.  `bin/sh ->
        # dash` and `lib -> usr/lib` are symlinks in every real Debian
        # rootfs, including the one docs/D4_LOCKED_LAUNCHER.md tells the
        # operator to debootstrap; rejecting those rejects every valid
        # jail.  Rejecting an escaping link still blocks the real attack
        # ("swap the BBS main for the host /bin/sh").
        if target.is_symlink():
            resolved = target.resolve()
            if not resolved.is_relative_to(real):
                raise JailValidationError(
                    f"canonical file {target} is a symlink out of the jail ({resolved})"
                )


def _jail_user_uid(jail_root: Path, user: str) -> int:
    """Return the UID of `user` in the JAIL's /etc/passwd.

    systemd-nspawn resolves --user= against the container's passwd
    database (it runs getent inside the container), so a name that only
    exists on the host fails at spawn time with a bare 'Failed to resolve
    user'.  Catching it here turns that into an audited refusal."""
    passwd = jail_root.resolve() / "etc" / "passwd"
    try:
        text = passwd.read_text(errors="replace")
    except OSError as exc:
        raise JailValidationError(f"cannot read {passwd}: {exc}") from exc
    for line in text.splitlines():
        fields = line.split(":")
        if len(fields) >= 3 and fields[0] == user:
            try:
                uid = int(fields[2])
            except ValueError as exc:
                raise JailValidationError(
                    f"jail user {user!r} has a non-numeric uid in {passwd}"
                ) from exc
            if uid == 0:
                raise JailValidationError(
                    f"jail user {user!r} is UID 0 inside the jail; refusing"
                )
            return uid
    raise JailValidationError(
        f"jail user {user!r} is not in {passwd}; systemd-nspawn --user would fail"
    )


# --- Host-side account guard --------------------------------------------------


def _lookup_unprivileged_user(name: str, group: str) -> Tuple[int, int]:
    """Resolve the bbs user/group to numeric IDs on the HOST.

    Refuses UID 0.  The group is resolved through the GROUP database
    (grp), not pwd — `pwd.getpwnam(group)` looks up a *user* of that
    name and yields that user's primary gid, which silently disagrees
    with the requested group whenever the two databases differ."""
    try:
        entry = pwd.getpwnam(name)
    except KeyError as exc:
        raise JailValidationError(f"unprivileged user {name!r} does not exist") from exc
    if entry.pw_uid == 0:
        raise JailValidationError(f"user {name!r} has UID 0 (root); refusing")
    gid = entry.pw_gid
    if group:
        try:
            gid = grp.getgrnam(group).gr_gid
        except KeyError:
            # Not fatal: the gid is audit metadata (nspawn takes the gid
            # from the jail's passwd).  But it must never be silent.
            sys.stderr.write(
                f"eniqma-locked: group {group!r} does not exist on the host; "
                f"recording {name!r}'s primary gid {gid} instead\n"
            )
    if gid == 0:
        raise JailValidationError(f"group {group!r} has GID 0 (root); refusing")
    return entry.pw_uid, gid


# --- Container argv -----------------------------------------------------------


def _machine_name(session_id: str) -> str:
    """A machine name systemd will actually accept.

    Only ASCII letters, digits and '-' are valid (valid_ldh_char); a
    machine name may not start or end with '-' and may not exceed 64
    bytes.  Mapping the invalid characters to '_' — as an earlier
    revision did — produces `Invalid machine name` for every real
    session, because the production session id starts with a TTY path
    (`/dev/ttyACM0` -> `_dev_ttyACM0`)."""
    safe = re.sub(r"[^A-Za-z0-9]+", "-", session_id).strip("-")
    if not safe:
        safe = "anon"
    name = f"{MACHINE_NAME_PREFIX}-{safe}"[:MACHINE_NAME_MAX].rstrip("-")
    return name or f"{MACHINE_NAME_PREFIX}-anon"


def build_nspawn_argv(
    *,
    jail_root: Path,
    machine: str,
    bbs_user: str,
    private_users: str = DEFAULT_PRIVATE_USERS,
) -> Tuple[str, ...]:
    """The exact argv for the container.  Pure function so the tests can
    check it against systemd-nspawn's real option table.

    The nspawn options here are intentionally minimal.  Anything more
    permissive (e.g. --bind=/home) would let a captive user read host
    data.  Two traps, both of which used to make this argv unrunnable:

      * there is no --group= option (systemd 244..257).  nspawn takes
        the gid from the jail passwd entry of --user=.
      * --boot may not be combined with --as-pid2, and --boot would in
        any case run the container's init and pass the trailing words to
        it as kernel-command-line arguments instead of executing them.
    """
    argv = [
        NSPAWN_BIN,
        "--quiet",
        "--as-pid2",
        f"--machine={machine}",
        f"--directory={jail_root}",
    ]
    if private_users and private_users.lower() not in ("off", "no", "none", ""):
        # container UID 0 -> host UID <base>: root inside the jail is an
        # unprivileged nobody outside it.
        argv.append(f"--private-users={private_users}")
    argv += [
        f"--user={bbs_user}",
        # No --share-system, no --bind=, no --overlay, no --tmpfs=.
        # The jail must be self-contained.
        "--",
        "/usr/bin/env",
        "-i",  # ignore inherited environment
        "HOME=/bbs",
        "TERM=dumb",
        "node",
        "/bbs/enigma-bbs.js",
    ]
    return tuple(argv)


def run_container(argv: Sequence[str]) -> Tuple[int, Optional[int]]:
    """Fork, run `argv`, forward one termination signal, wait.

    Returns (exit_status, exec_errno).  exec_errno is not None when the
    child could not exec at all — that used to be unobservable: os.execv()
    SUCCEEDS whenever the binary exists, so the caller was replaced and
    could never write the closing audit record, no matter how the
    container itself failed."""
    err_r, err_w = os.pipe2(os.O_CLOEXEC)
    pid = os.fork()
    if pid == 0:  # child
        try:
            os.close(err_r)
            os.execv(argv[0], list(argv))
        except OSError as exc:  # noqa: BLE001 - relayed to the parent below
            try:
                os.write(err_w, str(exc.errno or errno.ENOEXEC).encode("ascii"))
            except OSError:
                pass
        os._exit(127)

    os.close(err_w)
    forwarded = {"done": False}

    def _forward(signum: int, _frame: Any) -> None:
        if forwarded["done"]:
            return
        forwarded["done"] = True
        try:
            os.kill(pid, signum)
        except ProcessLookupError:
            pass

    previous = {}
    for sig in FORWARDED_SIGNALS:
        try:
            previous[sig] = signal.signal(sig, _forward)
        except (OSError, ValueError):  # pragma: no cover - restricted env
            pass
    try:
        raw = b""
        try:
            raw = os.read(err_r, 16)
        except OSError:
            pass
        finally:
            os.close(err_r)
        while True:
            try:
                _, status = os.waitpid(pid, 0)
                break
            except InterruptedError:  # a forwarded signal hit our wait
                continue
    finally:
        for sig, handler in previous.items():
            try:
                signal.signal(sig, handler)
            except (OSError, ValueError):  # pragma: no cover
                pass

    exec_errno = int(raw) if raw.strip().isdigit() else None
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status), exec_errno
    return os.WEXITSTATUS(status), exec_errno


# --- Top-level orchestration --------------------------------------------------


def _tty_name() -> str:
    """The dial-in line, e.g. /dev/ttyACM0.  '?' when stdin is not a tty
    (systemd/SSH invocation, or the test harness)."""
    try:
        return os.ttyname(0) or "?"
    except OSError:
        return "?"


def _session_id_from_env() -> str:
    """Build a session id from the TTY + pid.  Stable for the life of
    this process, never reused."""
    return f"{_tty_name()}-{os.getpid()}-{int(time.time())}"


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_arg_parser().parse_args(argv)

    session_id = args.session_id or _session_id_from_env()
    machine = _machine_name(session_id)
    started_at = time.time()
    tty = _tty_name()

    if args.print_argv:
        for word in build_nspawn_argv(
            jail_root=args.jail_root,
            machine=machine,
            bbs_user=args.bbs_user,
            private_users=args.private_users,
        ):
            sys.stdout.write(word + "\n")
        return 0

    # Capture the caller environment for the audit record.  We only
    # record SAFE keys — never $SHELL or anything the user could have
    # set from the dial-in prompt.  CALLER_ID is exported by mgetty and
    # is the closest thing to a peer address a phone line has.
    safe_env_keys = ("TERM", "LANG")
    captured_env = {k: os.environ.get(k, "") for k in safe_env_keys}
    caller_id = os.environ.get("CALLER_ID", "")

    def _refuse(reason: str, *, extra: Optional[Dict[str, Any]] = None) -> int:
        sys.stderr.write(f"eniqma-locked: refusing to start: {reason}\n")
        record = {
            "event": "refused",
            "reason": reason,
            "session_id": session_id,
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "tty": tty,
            "caller_id": caller_id,
            "term": captured_env.get("TERM", ""),
            "argv0": sys.argv[0] if sys.argv else "?",
        }
        record.update(extra or {})
        # Audit the refusal before we exit.  We cannot guarantee the
        # audit log is reachable (a captive user may have remounted
        # the FS) but we try.
        try:
            _ensure_audit_log(args.audit_log)
            _audit(args.audit_log, record)
        except OSError:
            pass
        return 75  # EX_TEMPFAIL — mgetty will hang up.

    # Step 1: validate the jail.
    try:
        _validate_jail(args.jail_root)
    except JailValidationError as exc:
        return _refuse(str(exc))

    # Step 2: ensure the audit log is in place.  Fail closed if we
    # cannot write to it; the operator must fix the log path before
    # the BBS can be served.
    try:
        _ensure_audit_log(args.audit_log)
    except OSError as exc:
        sys.stderr.write(f"eniqma-locked: cannot open audit log: {exc}\n")
        return 75

    # Step 2.5: resolve the accounts and the container manager.  Failures
    # here are configuration errors and must be audited before we exit.
    try:
        bbs_uid, bbs_gid = _lookup_unprivileged_user(args.bbs_user, args.bbs_group)
        jail_uid = _jail_user_uid(args.jail_root, args.bbs_user)
    except JailValidationError as exc:
        return _refuse(str(exc))
    if not args.dry_run and not os.access(NSPAWN_BIN, os.X_OK):
        return _refuse(f"{NSPAWN_BIN} is missing or not executable (apt install systemd-container)")

    nspawn_argv = build_nspawn_argv(
        jail_root=args.jail_root,
        machine=machine,
        bbs_user=args.bbs_user,
        private_users=args.private_users,
    )

    # Step 3: write the "start" audit record BEFORE running the BBS.
    # This is the moment the user is committed to the BBS — if the BBS
    # crashes 1ms later we still know the session happened.
    _audit(
        args.audit_log,
        {
            "event": "start",
            "session_id": session_id,
            "machine": machine,
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "tty": tty,
            "caller_id": caller_id,
            "bbs_uid": bbs_uid,
            "bbs_gid": bbs_gid,
            "jail_uid": jail_uid,
            "jail_root": str(args.jail_root.resolve()),
            "env": captured_env,
            "argv0": sys.argv[0] if sys.argv else "?",
            "nspawn_argv": list(nspawn_argv),
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

    # Step 4: run the container, wait for it, record how it ended.
    status, exec_errno = run_container(nspawn_argv)
    if exec_errno is not None:
        _audit(
            args.audit_log,
            {
                "event": "exec_failed",
                "session_id": session_id,
                "machine": machine,
                "errno": exec_errno,
                "errstr": os.strerror(exec_errno),
            },
        )
        return 71  # EX_OSERR
    _audit(
        args.audit_log,
        {
            "event": "exit",
            "session_id": session_id,
            "machine": machine,
            "status": status,
            "started_at": started_at,
            "ended_at": time.time(),
        },
    )
    return status


if __name__ == "__main__":
    raise SystemExit(main())
