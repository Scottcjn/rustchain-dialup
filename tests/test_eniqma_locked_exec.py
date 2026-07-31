#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# tests/test_eniqma_locked_exec.py — Bounty D4, the half that
# tests/test_eniqma_locked.py cannot reach.
#
# Every test in the original suite runs the launcher with --dry-run,
# which returns before the container is ever built.  That is why the
# launcher could ship with an exec that systemd-nspawn rejects three
# different ways while all 13 cases stayed green.  This file tests the
# things that only matter once --dry-run is off:
#
#   * the systemd-nspawn argv is one the real option parser accepts,
#   * the machine name is one systemd's machine_name_is_valid() accepts,
#   * the jail validation accepts a real (merged-/usr) Debian rootfs and
#     still rejects the escape it is there to block,
#   * the launcher observes and records how the container ended.
#
# The oracles are deliberately independent of the launcher: the option
# table is read from `systemd-nspawn --help` when it is installed (and
# from a transcribed table when it is not), and hostname validity is a
# line-by-line transcription of systemd's own hostname_is_valid().
from __future__ import annotations

import errno
import importlib.util
import json
import os
import pwd
import grp
import shutil
import signal
import stat
import subprocess
import sys
from pathlib import Path
from typing import Optional

import pytest

LAUNCHER = Path(__file__).resolve().parent.parent / "launchers" / "eniqma-locked.py"


def _load_launcher():
    """Import the launcher by path (its filename is not a module name)."""
    spec = importlib.util.spec_from_file_location("eniqma_locked", LAUNCHER)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


el = _load_launcher()


def _pick_test_user() -> str:
    for name in ("nobody", "bbs", "games"):
        try:
            if pwd.getpwnam(name).pw_uid != 0:
                return name
        except KeyError:
            continue
    me = pwd.getpwuid(os.getuid())
    if me.pw_uid == 0:
        pytest.skip("no non-root system user available on this runner")
    return me.pw_name


BBS_USER = _pick_test_user()


def _build_jail(root: Path, *, user: str = BBS_USER, uid: int = 999) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for d in ("etc", "bbs", "bin"):
        (root / d).mkdir(exist_ok=True)
    (root / "etc" / "passwd").write_text(
        "root:x:0:0:root:/:/bin/sh\n" f"{user}:x:{uid}:{uid}:bbs:/bbs:/bin/sh\n"
    )
    (root / "bbs" / "enigma-bbs.js").write_text("// placeholder\n")
    (root / "bin" / "sh").write_text("#!/bin/false\n")
    (root / "bin" / "sh").chmod(0o755)
    return root


# --------------------------------------------------------------------------- #
# 1. The systemd-nspawn argv
# --------------------------------------------------------------------------- #

# Long options accepted by systemd-nspawn.  Read from the installed
# binary when present; this transcription (systemd 255, and unchanged in
# 244..257 for every option used here) keeps the test meaningful on a
# runner without systemd-container.  NOTE what is NOT here: --group.
NSPAWN_LONG_OPTIONS = {
    "--ambient-capability", "--as-pid2", "--bind", "--bind-ro", "--bind-user",
    "--boot", "--capability", "--chdir", "--console", "--cpu-affinity",
    "--directory", "--drop-capability", "--ephemeral", "--help", "--hostname",
    "--image", "--image-policy", "--inaccessible", "--keep-unit", "--kill-signal",
    "--link-journal", "--load-credential", "--machine", "--network-bridge",
    "--network-interface", "--network-ipvlan", "--network-macvlan",
    "--network-namespace-path", "--network-veth", "--network-veth-extra",
    "--network-zone", "--no-new-privileges", "--no-pager", "--notify-ready",
    "--oci-bundle", "--oom-score-adjust", "--overlay", "--overlay-ro",
    "--personality", "--pipe", "--pivot-root", "--port", "--private-network",
    "--private-users", "--private-users-ownership", "--property", "--quiet",
    "--read-only", "--register", "--resolv-conf", "--rlimit", "--root-hash",
    "--root-hash-sig", "--selinux-apifs-context", "--selinux-context",
    "--set-credential", "--settings", "--slice", "--suppress-sync",
    "--system-call-filter", "--template", "--timezone", "--tmpfs", "--user",
    "--uuid", "--verity-data", "--version", "--volatile",
}


def _live_option_table() -> Optional[set]:
    """The option table of the systemd-nspawn actually installed here."""
    if not shutil.which("systemd-nspawn"):
        return None
    out = subprocess.run(
        ["systemd-nspawn", "--help"], capture_output=True, text=True, timeout=20
    )
    text = out.stdout + out.stderr
    opts = set()
    for token in text.replace("=", " ").replace(",", " ").split():
        if token.startswith("--") and len(token) > 2:
            opts.add(token.rstrip("[]|"))
    return opts or None


def _argv(**kw):
    kw.setdefault("jail_root", Path("/var/lib/bbs/jail"))
    kw.setdefault("machine", "bbs-dev-ttyACM0-1234-1785000000")
    kw.setdefault("bbs_user", "bbs")
    return el.build_nspawn_argv(**kw)


def _options_of(argv) -> list:
    """Long options before the `--` separator."""
    out = []
    for word in argv[1:]:
        if word == "--":
            break
        if word.startswith("--"):
            out.append(word.split("=", 1)[0])
    return out


def test_every_option_exists_in_nspawn() -> None:
    """Every long option we pass must be in systemd-nspawn's option
    table.  `--group=` is not, and nspawn dies at option parsing:
    `systemd-nspawn: unrecognized option '--group=999'`."""
    table = _live_option_table() or NSPAWN_LONG_OPTIONS
    unknown = [o for o in _options_of(_argv()) if o not in table]
    assert unknown == [], f"systemd-nspawn does not know {unknown}"


def test_boot_and_as_pid2_are_not_combined() -> None:
    """`--boot and --as-pid2 may not be combined.` — systemd-nspawn
    refuses the pair outright, and --boot would in any case hand the
    trailing words to the container's init as kernel-command-line
    arguments instead of executing them."""
    opts = _options_of(_argv())
    assert not ("--boot" in opts and "--as-pid2" in opts)


def test_argv_runs_the_bbs_as_the_container_payload() -> None:
    argv = _argv()
    sep = argv.index("--")
    assert argv[sep + 1 :] == (
        "/usr/bin/env",
        "-i",
        "HOME=/bbs",
        "TERM=dumb",
        "node",
        "/bbs/enigma-bbs.js",
    )
    assert argv[0] == el.NSPAWN_BIN
    # No shell, no metacharacters, nothing interpolated from the caller.
    assert not any(c in w for w in argv for c in ";|&$`\n")


def test_user_is_passed_by_name_not_host_uid() -> None:
    """nspawn resolves --user= inside the container (it runs getent in
    the jail).  A host uid is meaningless there: the jail ships its own
    /etc/passwd where bbs is 999 regardless of the host's numbering."""
    argv = _argv(bbs_user="bbs")
    assert "--user=bbs" in argv
    assert not any(w.startswith("--user=") and w[7:].isdigit() for w in argv)


def test_private_users_default_and_opt_out() -> None:
    assert f"--private-users={el.DEFAULT_PRIVATE_USERS}" in _argv()
    assert not any(w.startswith("--private-users") for w in _argv(private_users="off"))


@pytest.mark.skipif(not shutil.which("systemd-nspawn"), reason="systemd-nspawn not installed")
def test_nspawn_accepts_our_argv(tmp_path: Path) -> None:
    """Hand the real binary our real argv.  Option parsing and machine
    name validation happen before nspawn needs privileges, so this runs
    unprivileged; we only assert it does not die in the parser."""
    jail = _build_jail(tmp_path / "jail")
    argv = list(
        _argv(jail_root=jail, machine=el._machine_name("/dev/ttyACM0-2411-1785000000"))
    )
    out = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    blob = (out.stdout + out.stderr).lower()
    for fatal in ("unrecognized option", "may not be combined", "invalid machine name"):
        assert fatal not in blob, f"systemd-nspawn rejected our argv: {out.stderr.strip()}"


# --------------------------------------------------------------------------- #
# 2. The machine name
# --------------------------------------------------------------------------- #


def _valid_ldh_char(c: str) -> bool:
    return c.isascii() and (c.isalnum() or c == "-")


def hostname_is_valid(s: str) -> bool:
    """Transcription of systemd's hostname_is_valid(s, 0)
    (src/basic/hostname-util.c, v255) — the check behind
    machine_name_is_valid(), i.e. behind `--machine=`."""
    if not s:
        return False
    dot = hyphen = True
    n_dots = 0
    for ch in s:
        if ch == ".":
            if dot or hyphen:
                return False
            dot, hyphen = True, False
            n_dots += 1
        elif ch == "-":
            if dot:
                return False
            dot, hyphen = False, True
        else:
            if not _valid_ldh_char(ch):
                return False
            dot = hyphen = False
    if dot:
        return False
    if hyphen:
        return False
    return len(s.encode()) <= 64  # HOST_NAME_MAX


@pytest.mark.parametrize(
    "session_id",
    [
        "/dev/ttyACM0-2411-1785000000",  # the production shape
        "/dev/ttyS1-9-1",
        "weird!@# session$id",
        "unknown-1-1",
        "....",
        "---",
        "",
        "ünïcödé-tty",
        "x" * 200,
        "/dev/pts/3-1-1",
    ],
)
def test_machine_name_is_valid_for_systemd(session_id: str) -> None:
    """`_machine_name` mapped every invalid character to '_', but '_' is
    not a valid_ldh_char: systemd answers `Invalid machine name:
    bbs-_dev_ttyACM0-...`.  Since the production session id always
    starts with a TTY path, that fired on every single dial-in."""
    name = el._machine_name(session_id)
    assert hostname_is_valid(name), f"systemd would reject {name!r}"
    assert name.startswith("bbs-")
    assert "_" not in name


@pytest.mark.skipif(not shutil.which("systemd-nspawn"), reason="systemd-nspawn not installed")
def test_machine_name_accepted_by_systemd(tmp_path: Path) -> None:
    jail = _build_jail(tmp_path / "jail")
    name = el._machine_name("/dev/ttyACM0-2411-1785000000")
    out = subprocess.run(
        ["systemd-nspawn", "--quiet", f"--machine={name}", f"--directory={jail}",
         "--", "/bin/true"],
        capture_output=True, text=True, timeout=60,
    )
    assert "invalid machine name" not in (out.stdout + out.stderr).lower()


# --------------------------------------------------------------------------- #
# 3. Jail validation
# --------------------------------------------------------------------------- #


def test_symlinked_ancestor_of_the_jail_is_rejected(tmp_path: Path) -> None:
    """The documented attack: "an attacker who can write to the parent
    directory could redirect the root to /home".  The old check built
    its candidates as `resolved_jail / component`, so it inspected
    <jail>/var, <jail>/lib, <jail>/bbs — paths inside the jail — and
    never looked at a single real ancestor."""
    evil = tmp_path / "evil"
    _build_jail(evil / "jail")
    os.symlink(evil, tmp_path / "bbs")  # attacker-controlled component
    with pytest.raises(el.JailValidationError) as exc:
        el._validate_jail(tmp_path / "bbs" / "jail")
    assert "symlink" in str(exc.value)


def test_merged_usr_rootfs_is_accepted(tmp_path: Path) -> None:
    """docs/D4_LOCKED_LAUNCHER.md tells the operator to
    `debootstrap --variant=minbase stable /var/lib/bbs/jail`.  Every
    Debian since 12 is merged-/usr, so that jail has `lib -> usr/lib`
    and `bin/sh -> dash`; and the default jail root has a component
    named `lib`.  The old validator refused both."""
    jail = tmp_path / "var" / "lib" / "bbs" / "jail"
    _build_jail(jail)
    (jail / "usr" / "lib").mkdir(parents=True)
    (jail / "lib").rmdir() if (jail / "lib").is_dir() else None
    os.symlink("usr/lib", jail / "lib")
    # bin/sh -> dash, exactly as a real rootfs ships it
    (jail / "bin" / "sh").unlink()
    (jail / "bin" / "dash").write_text("#!/bin/false\n")
    os.symlink("dash", jail / "bin" / "sh")
    el._validate_jail(jail)  # must not raise


def test_canonical_symlink_out_of_the_jail_is_rejected(tmp_path: Path) -> None:
    jail = _build_jail(tmp_path / "jail")
    (jail / "bbs" / "enigma-bbs.js").unlink()
    os.symlink("/bin/sh", jail / "bbs" / "enigma-bbs.js")
    with pytest.raises(el.JailValidationError) as exc:
        el._validate_jail(jail)
    assert "symlink" in str(exc.value)


def test_missing_jail_user_is_refused_before_spawn(tmp_path: Path) -> None:
    """nspawn resolves --user in the jail; a name that is only on the
    host fails with a bare `Failed to resolve user bbs`."""
    jail = _build_jail(tmp_path / "jail")
    (jail / "etc" / "passwd").write_text("root:x:0:0:root:/:/bin/sh\n")
    with pytest.raises(el.JailValidationError) as exc:
        el._jail_user_uid(jail, "bbs")
    assert "not in" in str(exc.value)


def test_jail_user_with_uid_zero_is_refused(tmp_path: Path) -> None:
    jail = _build_jail(tmp_path / "jail")
    (jail / "etc" / "passwd").write_text("bbs:x:0:0:bbs:/bbs:/bin/sh\n")
    with pytest.raises(el.JailValidationError) as exc:
        el._jail_user_uid(jail, "bbs")
    assert "UID 0" in str(exc.value)


# --------------------------------------------------------------------------- #
# 4. Host account resolution
# --------------------------------------------------------------------------- #


def test_group_is_resolved_through_the_group_database() -> None:
    """`pwd.getpwnam(group)` looks up a *user*.  With --bbs-group adm it
    returned nobody's primary gid (65534) instead of adm's gid (4), and
    the original suite could not see it because it passes
    BBS_GROUP = BBS_USER."""
    try:
        adm = grp.getgrnam("adm").gr_gid
    except KeyError:  # pragma: no cover - runner without an adm group
        pytest.skip("no adm group on this runner")
    uid, gid = el._lookup_unprivileged_user(BBS_USER, "adm")
    assert gid == adm
    assert uid == pwd.getpwnam(BBS_USER).pw_uid


def test_unknown_group_warns_and_falls_back(capsys) -> None:
    uid, gid = el._lookup_unprivileged_user(BBS_USER, "no-such-group-xyzzy")
    assert gid == pwd.getpwnam(BBS_USER).pw_gid
    assert "does not exist" in capsys.readouterr().err


def test_root_group_is_refused() -> None:
    root_group = grp.getgrgid(0).gr_name
    with pytest.raises(el.JailValidationError):
        el._lookup_unprivileged_user(BBS_USER, root_group)


# --------------------------------------------------------------------------- #
# 5. Audit log permissions
# --------------------------------------------------------------------------- #


def _umask(value: int):
    old = os.umask(value)
    return old


def test_created_log_is_0640_under_any_umask(tmp_path: Path) -> None:
    """os.open()'s mode argument is masked by umask.  mgetty runs with
    022 on Debian and 077 on some hardened images; under 077 the log was
    created 0600 and `adm` could not read it (and the original
    test_audit_log_permission_strict passed only by luck, because the
    over-eager chmod below happened to fire under umask 022)."""
    old = _umask(0o077)
    try:
        log = tmp_path / "a.jsonl"
        el._ensure_audit_log(log)
        assert stat.S_IMODE(log.stat().st_mode) == 0o640
    finally:
        os.umask(old)


def test_symlink_swapped_after_the_first_check(tmp_path: Path, monkeypatch) -> None:
    """The second gate — "became a symlink between checks" — used
    `path.stat()`, which follows the link, so `S_ISLNK` on its result can
    never be true.  Here the first gate is neutered to simulate winning
    the race; only an `lstat` catches it."""
    real = tmp_path / "real.jsonl"
    el._ensure_audit_log(real)
    link = tmp_path / "link.jsonl"
    os.symlink(real, link)
    monkeypatch.setattr(Path, "is_symlink", lambda self: False)
    with pytest.raises(PermissionError) as exc:
        el._ensure_audit_log(link)
    assert "symlink" in str(exc.value)


def test_existing_stricter_log_is_kept(tmp_path: Path) -> None:
    """An operator who tightened the log to 0600 keeps it: the mode
    fix-up may only remove bits, never add them."""
    log = tmp_path / "a.jsonl"
    el._ensure_audit_log(log)
    os.chmod(log, 0o600)
    el._ensure_audit_log(log)
    assert stat.S_IMODE(log.stat().st_mode) == 0o600


def test_group_writable_log_is_tightened(tmp_path: Path) -> None:
    log = tmp_path / "a.jsonl"
    el._ensure_audit_log(log)
    os.chmod(log, 0o666)
    el._ensure_audit_log(log)
    mode = stat.S_IMODE(log.stat().st_mode)
    assert mode & 0o037 == 0, oct(mode)


def test_symlinked_log_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real.jsonl"
    el._ensure_audit_log(real)
    link = tmp_path / "link.jsonl"
    os.symlink(real, link)
    with pytest.raises(PermissionError):
        el._ensure_audit_log(link)


# --------------------------------------------------------------------------- #
# 6. Running the container and recording how it ended
# --------------------------------------------------------------------------- #


def test_run_container_reports_exit_status() -> None:
    status, exec_errno = el.run_container(["/bin/sh", "-c", "exit 42"])
    assert (status, exec_errno) == (42, None)


def test_exec_failure_is_observable() -> None:
    """os.execv() succeeds whenever the binary exists, so the old
    `except OSError -> audit exec_failed` branch could only ever fire
    when systemd-nspawn was missing entirely; every failure OF the
    container was invisible, and the audit log's last word for a dead
    session was `"event": "start"`."""
    status, exec_errno = el.run_container(["/nonexistent/systemd-nspawn"])
    assert exec_errno == errno.ENOENT
    assert status == 127


def test_hangup_is_forwarded_to_the_container() -> None:
    """mgetty drops DTR when the caller hangs up; the launcher now has a
    child to pass that on to."""
    old = signal.getsignal(signal.SIGHUP)
    # Park a no-op handler first: the default disposition for SIGHUP is
    # "terminate", so a launcher that does NOT install its own handler
    # must fail this assertion instead of killing the test session.
    signal.signal(signal.SIGHUP, lambda *_: None)
    # A helper process, not a thread: run_container() forks, and forking
    # a multi-threaded process is what the launcher must not do.
    hup = subprocess.Popen(["/bin/sh", "-c", f"sleep 0.4; kill -HUP {os.getpid()}"])
    try:
        status, exec_errno = el.run_container(["/bin/sleep", "5"])
    finally:
        hup.wait(timeout=10)
        signal.signal(signal.SIGHUP, old)
    assert exec_errno is None
    assert status == 128 + signal.SIGHUP


def test_session_start_and_exit_are_both_audited(tmp_path: Path, monkeypatch) -> None:
    jail = _build_jail(tmp_path / "jail")
    log = tmp_path / "audit.jsonl"
    monkeypatch.setattr(el, "NSPAWN_BIN", "/bin/true")
    rc = el.main(
        [
            "--jail-root", str(jail),
            "--bbs-user", BBS_USER,
            "--bbs-group", BBS_USER,
            "--audit-log", str(log),
            "--session-id", "sess-1",
        ]
    )
    events = [json.loads(line) for line in log.read_text().splitlines()]
    assert [e["event"] for e in events] == ["start", "exit"]
    assert rc == 0 and events[1]["status"] == 0
    assert events[1]["ended_at"] >= events[0]["started_at"]
    # The start record must carry the line, not just $TERM under a key
    # called "tty".
    assert "tty" in events[0] and "caller_id" in events[0]
    assert events[0]["jail_uid"] == 999


def test_failing_container_is_audited_with_its_status(tmp_path: Path, monkeypatch) -> None:
    jail = _build_jail(tmp_path / "jail")
    log = tmp_path / "audit.jsonl"
    monkeypatch.setattr(el, "NSPAWN_BIN", "/bin/false")
    rc = el.main(
        [
            "--jail-root", str(jail),
            "--bbs-user", BBS_USER,
            "--bbs-group", BBS_USER,
            "--audit-log", str(log),
            "--session-id", "sess-2",
        ]
    )
    events = [json.loads(line) for line in log.read_text().splitlines()]
    assert rc == 1
    assert events[-1]["event"] == "exit" and events[-1]["status"] == 1


def test_missing_nspawn_is_refused_not_discovered_as_a_dead_line(
    tmp_path: Path, monkeypatch
) -> None:
    jail = _build_jail(tmp_path / "jail")
    log = tmp_path / "audit.jsonl"
    monkeypatch.setattr(el, "NSPAWN_BIN", "/nonexistent/systemd-nspawn")
    rc = el.main(
        [
            "--jail-root", str(jail),
            "--bbs-user", BBS_USER,
            "--audit-log", str(log),
            "--session-id", "sess-3",
        ]
    )
    assert rc == 75
    record = json.loads(log.read_text().splitlines()[-1])
    assert record["event"] == "refused" and "systemd-nspawn" in record["reason"]


def test_print_argv_is_greppable_by_an_operator(tmp_path: Path) -> None:
    jail = _build_jail(tmp_path / "jail")
    out = subprocess.run(
        [sys.executable, str(LAUNCHER), "--jail-root", str(jail),
         "--session-id", "print", "--print-argv"],
        capture_output=True, text=True, timeout=15,
    )
    words = out.stdout.split("\n")
    assert out.returncode == 0
    assert words[0] == el.NSPAWN_BIN
    assert "--boot" not in words
    assert not any(w.startswith("--group") for w in words)
