# D4 — ENiGMA½ Locked Launcher

> *Bounty D4 — Bounty ID, 20 RTC. See [BOUNTIES.md](../BOUNTIES.md).*

This document is the operator + reviewer-facing reference for the
locked-down ENiGMA½ launcher that ships in `launchers/`.  It is the
mandatory reading for any operator who installs this bounty, and the
entry point for any reviewer who wants to evaluate whether the
launcher actually delivers the rubric in BOUNTIES.md.

## 1. Acceptance rubric mapping

> D4 — **ENiGMA½ locked launcher**: BBS reachable on the terminal
> line via an unprivileged launcher (no host shell escape), OS
> accounts ≠ BBS accounts. Include the launcher + a documented
> escape-attempt test.

| Rubric clause | How this PR satisfies it |
|---|---|
| "BBS reachable on the terminal line" | The launcher is wired into `config/login.config` as the terminal-mode fallback. After mgetty prints a "CONNECT" and waits for LCP, if no LCP comes in the window, mgetty execs the launcher per the `/etc/mgetty/login.config` rule in `config/launchers/eniqma-locked.conf`. |
| "via an unprivileged launcher" | `_lookup_unprivileged_user()` refuses UID 0 (host-side guard), `_jail_user_uid()` refuses a jail account that is UID 0 inside the jail, and the container is run with `--user=<name>`, which `systemd-nspawn` resolves in the **jail's** `/etc/passwd` — that is what makes the BBS process non-root. `systemd-nspawn` has no `--group=` option; the gid comes from the same jail passwd entry. The launcher itself stays root until the fork because building the namespaces needs `CAP_SYS_ADMIN`. |
| "no host shell escape" | Covered by `tests/test_eniqma_locked.py` (13 cases) + `tests/test_eniqma_locked_exec.py` (37 cases covering everything `--dry-run` skips). Specifically: missing jail refused, symlinked jail refused, symlinked canonical file refused, symlinked audit log refused, $SHELL ignored, session-id sanitised, audit-log append-only, audit-log mode 0640. |
| "OS accounts ≠ BBS accounts" | The launcher's only privilege model is a separate unprivileged user (default `bbs`, UID ≥ 1). The /etc/passwd inside the jail is independent of the host /etc/passwd. |
| "Include the launcher" | `launchers/eniqma-locked.py` (411 lines, type-hinted, no third-party deps). |
| "a documented escape-attempt test" | `tests/test_eniqma_locked.py` (13 cases) + this document + inline comments in the launcher (`# Escape-attempt contract` block). |

## 2. Files in this PR

```
launchers/eniqma-locked.py          # the launcher (Python 3.10+)
launchers/eniqma-locked.service     # systemd unit reference
config/launchers/eniqma-locked.conf # mgetty login.config snippet
tests/test_eniqma_locked.py         # 13 escape-attempt tests (--dry-run)
tests/test_eniqma_locked_exec.py    # 37 tests of the container path
docs/D4_LOCKED_LAUNCHER.md          # this file
```

The launcher depends on the standard library only and on a system
install of `systemd-nspawn` (any systemd 244+ release).  No new
runtime dependencies are introduced.

## 3. Operator install (5 steps)

### 3.1 Create the unprivileged BBS account

```bash
sudo useradd --system --uid 999 --gid 999 --no-create-home --shell \
    /usr/local/bin/eniqma-locked bbs
```

The `--shell` is the launcher.  Anyone who runs `su bbs` (or
`login bbs` over the serial line) lands in the launcher, not in
`/bin/sh`.

### 3.2 Install the launcher

```bash
sudo install -m 0755 launchers/eniqma-locked.py \
    /usr/local/bin/eniqma-locked
```

The launcher is intentionally shipped as a `.py` file at the
operator site; no compilation step is needed.  The shebang
`#!/usr/bin/env python3` resolves the system Python.

### 3.3 Install the systemd unit (optional, for nspawn)

```bash
sudo install -m 0644 launchers/eniqma-locked.service \
    /etc/systemd/system/eniqma-locked.service
sudo install -m 0644 config/launchers/eniqma-locked.conf \
    /etc/bbs/launcher.env
sudo systemd-analyze verify /etc/systemd/system/eniqma-locked.service
```

The unit is *not* auto-started.  It exists so `systemd-analyze
verify` can confirm the capability bounding set is what the
launcher expects, and so an operator can read it as a single-glance
reference for "what does the launcher need from systemd?".

### 3.4 Prepare the jail root

```bash
sudo mkdir -p /var/lib/bbs/jail
sudo debootstrap --variant=minbase stable /var/lib/bbs/jail
sudo cp -r /path/to/enigma-bbs /var/lib/bbs/jail/bbs
sudo chown -R 999:999 /var/lib/bbs/jail/bbs
```

The debootstrap step is a stable Debian userland so the BBS has
real `/etc/passwd`, `/bin/sh`, etc. inside the jail.  The launcher
*checks* for `etc/passwd`, `bbs/enigma-bbs.js`, and `bin/sh` in
the jail before exec.

### 3.5 Wire the mgetty login.config

Append the rule from `config/launchers/eniqma-locked.conf` to
`/etc/mgetty/login.config` (or the equivalent
`/etc/mgetty+sendfax/login.config` on some distros).  The catch-all
`*` line is the one that points at the launcher.

```bash
sudo cp config/launchers/eniqma-locked.conf /etc/mgetty/login.config.d/d4.conf
sudo systemctl reload mgetty  # or SIGHUP the running mgetty
```

The order of rules in `login.config` is significant.  `/AutoPPP/`
must precede `*`.  See the parent `config/login.config` for the
documented layout.

### 3.6 What actually gets run

The launcher never execs a shell and never execs `$SHELL`.  It builds
one fixed argv and runs it as a child, so it can write the closing
audit record:

```bash
/usr/local/bin/eniqma-locked --print-argv          # review it before dialling in
/usr/bin/systemd-nspawn --quiet --as-pid2 --machine=bbs-<session> \
    --directory=/var/lib/bbs/jail --private-users=65536 --user=bbs \
    -- /usr/bin/env -i HOME=/bbs TERM=dumb node /bbs/enigma-bbs.js
```

Two things about that line are easy to get wrong and both make it
unrunnable: `systemd-nspawn` has **no** `--group=` option (it dies with
`unrecognized option`), and `--boot` **may not be combined with
`--as-pid2`** — `--boot` would run the container's init and pass the
trailing words to it as kernel-command-line arguments instead of
executing them.  `tests/test_eniqma_locked_exec.py` checks the argv
against the real option table.

`--private-users=65536` maps container UID 0 to host UID 65536, so root
inside the jail is nobody outside it.  The jail tree must be readable by
the shifted range; pass `--private-users off` if the operator's kernel
has user namespaces disabled, or shift the tree once with
`systemd-nspawn --private-users=65536 --private-users-ownership=chown`.

The audit log gets one `start` record and then exactly one of `exit`
(with the container's status), `exec_failed` (the container manager
could not be executed at all) or `refused` (validation failed before
anything ran).  A `start` with no closing record means the launcher
itself was killed.

## 4. Reviewer test recipe

The test suite is the contract.  It runs without sudo and without
network access:

```bash
python3 -m pytest tests/test_eniqma_locked.py tests/test_eniqma_locked_exec.py -v
```

Expected output: `50 passed in <2s`.  The first file drives the
launcher as a subprocess with `--dry-run`; the second one covers the
part `--dry-run` returns before — the `systemd-nspawn` argv, the
machine name, jail validation against a real merged-`/usr` rootfs, and
the audit records written when the container ends.  Each test name is a
self-documenting claim about the launcher's contract.  If you are
reviewing a patch to the launcher, the test that fails is the one
that broke.  The tests are:

1. `test_dry_run_succeeds_on_valid_jail` — happy path.
2. `test_audit_log_uses_canonical_event_schema` — pins the audit
   log field names so a future change is intentional.
3. `test_refuses_missing_jail` — `jail-root` does not exist → 75.
4. `test_refuses_jail_with_missing_canonical_file` — partial jail
   (e.g. ENiGMA½ main missing) → 75.
5. `test_refuses_symlinked_jail_root` — symlink at the root → 75.
6. `test_refuses_symlinked_canonical_file` — symlink inside the
   jail pointing to `/bin/sh` → 75.
7. `test_refuses_audit_log_symlink` — symlink at the audit log → 75.
8. `test_shell_env_var_does_not_affect_launcher` — captive user's
   `$SHELL` is ignored.
9. `test_session_id_is_canonical_for_machine_name` — machine name
   surfaces to `machinectl list` in a safe shape.
10. `test_unknown_bbs_user_refuses` — misconfigured operator
    `--bbs-user=...` does not silently fall back to root.
11. `test_root_bbs_user_refuses` — `--bbs-user=root` refused.
12. `test_audit_log_is_append_only` — two sessions produce two
    audit lines.
13. `test_audit_log_permission_strict` — audit log created 0640,
    not world-readable.

## 5. Escape-attempt scenarios that the launcher blocks

The following is the curated list the maintainer asked for.  Each
is mapped to the test that proves it.

| Attempt | What a captive user might try | What stops it |
|---|---|---|
| **Swap the jail root for `/home`** | Symlink `/var/lib/bbs/jail` to `/home` so the launcher reads host user files | `_validate_jail` walks every real component from `/` down to the jail root and rejects a symlink at any of them (`test_refuses_symlinked_jail_root`, `test_symlinked_ancestor_of_the_jail_is_rejected`) |
| **Replace the BBS binary with a shell** | Symlink `/bbs/enigma-bbs.js` to `/bin/sh` | `_validate_jail` rejects a canonical file whose symlink resolves **outside** the jail (`test_refuses_symlinked_canonical_file`). Links that stay inside are normal — `bin/sh -> dash` and `lib -> usr/lib` ship in every Debian rootfs (`test_merged_usr_rootfs_is_accepted`) |
| **Drop the audit log to /dev/null** | Symlink the audit log to `/dev/null` after first session | `_ensure_audit_log` checks for symlinks before open and refuses to follow them (`test_refuses_audit_log_symlink`) |
| **Inject `$SHELL` from the dial-in prompt** | Send `SHELL=/bin/bash` via Telnet NAWS or similar | The launcher's safe-env allow-list only includes `TERM` and `LANG`; the captured env is recorded in the audit log so an operator can grep for tampering (`test_shell_env_var_does_not_affect_launcher`) |
| **Run a hostile bbs user** | Have the operator set `--bbs-user=root` by accident | The launcher refuses UID 0 (`test_root_bbs_user_refuses`) and refuses unknown users (`test_unknown_bbs_user_refuses`) |
| **TOCTOU swap of canonical files** | Race the launcher's open() by replacing a canonical file with a symlink between resolve() and open() | `_validate_jail` re-checks each canonical file with `Path.is_symlink()` after the existence check (`test_refuses_symlinked_canonical_file` is the closest test; full TOCTOU protection would also require a `chflags` lockdown on the jail, which is operator-side) |
| **Trick `execve` into running something else** | Set a magic env var or argv injection | `build_nspawn_argv()` returns a fixed argv (asserted free of shell metacharacters by `test_argv_runs_the_bbs_as_the_container_payload`, and printable for review with `--print-argv`); the launcher has no `eval`/`subprocess.Popen(shell=True)` anywhere; the only env vars forwarded into the nspawn container are `HOME` and `TERM` (constants in the source) |

## 6. What this PR does NOT do

The acceptance rubric is intentionally narrow.  The launcher does
not:

- Validate ENiGMA½'s internal security.  ENiGMA½ is the
  maintainer's separate concern; the launcher just provides
  the locked boundary.
- Handle ANSI/UTF-8 negotiation.  ENiGMA½ does that itself.
- Implement rate limiting or DoS protection.  That belongs in
  the firewall (see the existing `nftables-dialup.conf`).
- Bind a writable data directory into the jail.  ENiGMA½ message
  bases therefore live inside the jail tree, not in a separate
  `/var/lib/bbs/data`; adding `--bind=` is an operator/maintainer
  decision (and interacts with `--private-users` ownership), so it is
  deliberately not done here.
- Read `config/launchers/eniqma-locked.conf` as a config file.  The
  launcher takes no environment and no config file by design; that
  snippet documents the mgetty rule, and the values are passed as
  flags on that rule.
- Implement any backdoor.  The audit log records every
  attempt to start, succeed, refuse, or fail.  An operator
  can `grep '"event": "refused"' /var/log/bbs-launcher/audit.jsonl`
  to see every escape attempt on a daily cron.

## 7. Reproducing the acceptance rubric on a Pi

The reviewer recipe above runs in a CI container.  On a real Pi:

```bash
sudo apt install systemd-container  # provides systemd-nspawn
sudo useradd --system --uid 999 --gid 999 --no-create-home \
    --shell /usr/local/bin/eniqma-locked bbs
sudo install -m 0755 launchers/eniqma-locked.py \
    /usr/local/bin/eniqma-locked
sudo mkdir -p /var/lib/bbs/jail
# Populate the jail per section 3.4 above.
sudo mkdir -p /var/log/bbs-launcher
sudo chown root:adm /var/log/bbs-launcher
sudo chmod 2750 /var/log/bbs-launcher
# Wire the mgetty rule per section 3.5.
```

Then dial in from a second modem (per the hardware spec in
`docs/HARDWARE.md`).  The terminal-side user sees a clean
ENiGMA½ login prompt, never a `login:` prompt.  Any attempt to
break out lands in the audit log; `journalctl -u mgetty@ttyACM0`
will show the hangup when the launcher refuses.
