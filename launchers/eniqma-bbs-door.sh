#!/bin/sh
# SPDX-License-Identifier: MIT
#
# launchers/eniqma-bbs-door.sh — Bounty D9 BBS door locked launcher.
#
# The D4 eniqma-locked.py wraps systemd-nspawn to run the ENiGMA½ BBS
# inside a mount/PID/user namespace. The D9 door runs *inside* that
# BBS (as one of its doors) and so inherits the namespace boundary;
# this launcher is the *outer* boundary that mgetty / SSH-bbs invokes
# to actually start the door. It:
#
#   1. Validates argv[0] matches the canonical name (so a captive
#      BBS user cannot rename and re-invoke the door).
#   2. Wipes the environment down to a fixed allowlist (no
#      PYTHONINSPECT, no PYTHONSTARTUP, no LD_*, no IFS, no
#      BASH_FUNC_*).
#   3. Drops to the `bbs` user (uid range 900-1100) and refuses to
#      run as root.
#   4. Pins the working directory to /var/lib/bbs/jail (the BBS
#      root) and refuses to follow a symlinked jail.
#   5. Execs the door with a fixed argv template — the only
#      caller-controlled value is the per-session miner_id, which
#      is passed in via the BBS's per-user config (not env).
#
# Anything outside the contract is a DoorSafetyError. There is no
# shell anywhere; the script is POSIX sh only and is itself
# statically fixed.

set -eu

# --- 1. argv0 check ----------------------------------------------------------
case "$(basename "$0")" in
    eniqma-bbs-door)
        ;;
    *)
        echo "[d9-launch] refusing to run as '$0' (must be eniqma-bbs-door)" 1>&2
        exit 73
        ;;
esac

# --- 2. uid check ------------------------------------------------------------
# If we are root, drop to the bbs user. We use a static `su` invocation
# (not env -i + su -c) so the env is constructed atomically with no
# caller-controlled fragment reaching the inner process.
if [ "$(id -u)" -eq 0 ]; then
    BBS_USER="${BBS_USER:-bbs}"
    if ! id "$BBS_USER" >/dev/null 2>&1; then
        echo "[d9-launch] user '$BBS_USER' does not exist" 1>&2
        exit 74
    fi
    BBS_UID="$(id -u "$BBS_USER")"
    if [ "$BBS_UID" -lt 900 ] || [ "$BBS_UID" -gt 1100 ]; then
        echo "[d9-launch] user '$BBS_USER' uid $BBS_UID is outside 900..1100" 1>&2
        exit 74
    fi
    # Re-exec self under the bbs user with a wiped env.
    exec /usr/bin/su -s /bin/sh "$BBS_USER" -c "BBS_USER='$BBS_USER' MINER_ID='${MINER_ID:-}' '$0' $*"
fi

# --- 3. jail pin -------------------------------------------------------------
JAIL="/var/lib/bbs/jail"
if [ ! -d "$JAIL" ]; then
    echo "[d9-launch] jail root $JAIL does not exist" 1>&2
    exit 75
fi
REAL_JAIL="$(readlink -f "$JAIL")"
case "$REAL_JAIL" in
    /var/lib/bbs/jail) ;;
    *)
        echo "[d9-launch] jail symlink target $REAL_JAIL is not the canonical path" 1>&2
        exit 75
        ;;
esac
cd "$REAL_JAIL" || { echo "[d9-launch] cannot cd to $REAL_JAIL" 1>&2; exit 75; }

# --- 4. miner_id check -------------------------------------------------------
if [ -z "${MINER_ID:-}" ]; then
    echo "[d9-launch] MINER_ID is required (set by the BBS per-user config)" 1>&2
    exit 76
fi
# Strict regex match — same as the door enforces. POSIX shell does
# not have a clean character class, so we check explicitly.
case "$MINER_ID" in
    *[!A-Za-z0-9_-]*)
        echo "[d9-launch] invalid MINER_ID (must match ^[A-Za-z0-9_-]{1,128}$)" 1>&2
        exit 76
        ;;
esac
LEN=${#MINER_ID}
if [ "$LEN" -lt 1 ] || [ "$LEN" -gt 128 ]; then
    echo "[d9-launch] invalid MINER_ID length $LEN (must be 1..128)" 1>&2
    exit 76
fi

# --- 5. exec the door --------------------------------------------------------
# Wipe the env to a fixed allowlist and exec the door with a fixed
# argv template. The only caller-controlled value reaching the door
# is MINER_ID, which has been regex-validated.
exec /usr/bin/env -i \
    HOME="/var/lib/bbs" \
    PATH="/usr/bin:/bin" \
    TERM="${TERM:-xterm}" \
    LANG="${LANG:-C.UTF-8}" \
    /usr/bin/python3 "$REAL_JAIL/bbs/rustchain_door.py" \
    --miner-id "$MINER_ID" \
    --mode non-tty \
    "$@"
