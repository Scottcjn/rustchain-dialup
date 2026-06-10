#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Build the D7 round-trip harness for host (x86_64) and big-endian
# targets (PowerPC 64-bit BE, IBM S/390x). The big-endian binaries
# are statically linked and run under qemu-user-static; the host
# binary is dynamically linked and runs natively.
#
# Usage: bash tests/d7_harness/build.sh
#
# Requirements (one-time):
#   apt-get install -y gcc-powerpc64-linux-gnu libc6-ppc64-cross \
#                       gcc-s390x-linux-gnu libc6-s390x-cross \
#                       qemu-user-static
#   pip3 install pynacl pytest
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

# -Wno-unused-result: orlp/ed25519's seed.c uses fread() in a function
# (ed25519_create_seed) we never call; the warning is harmless here.
CFLAGS_HOST=(-O2 -Wall -Wextra -Wno-unused-result -I"$HERE")
CFLAGS_BE=(-O2 -Wall -Wextra -Wno-unused-result -I"$HERE" -static)

ORLP=("$HERE/ed25519_orlp/keypair.c" "$HERE/ed25519_orlp/sign.c" "$HERE/ed25519_orlp/verify.c"
      "$HERE/ed25519_orlp/sha512.c"  "$HERE/ed25519_orlp/sc.c"
      "$HERE/ed25519_orlp/fe.c"     "$HERE/ed25519_orlp/ge.c"
      "$HERE/ed25519_orlp/seed.c")

# --- host (x86_64 little-endian) ---
echo "==> building host (x86_64, dynamic)"
gcc "${CFLAGS_HOST[@]}" \
    "$HERE/d7_sign.c" "$HERE/rcc_crypto_be.c" "${ORLP[@]}" \
    -o "$HERE/d7_sign_host"

# --- powerpc64 big-endian ---
if command -v powerpc64-linux-gnu-gcc >/dev/null 2>&1 && \
   command -v qemu-ppc64-static      >/dev/null 2>&1; then
    echo "==> building ppc64 BE (static, run under qemu-ppc64-static)"
    powerpc64-linux-gnu-gcc "${CFLAGS_BE[@]}" \
        "$HERE/d7_sign.c" "$HERE/rcc_crypto_be.c" "${ORLP[@]}" \
        -o "$HERE/d7_sign_ppc64be"
else
    echo "==> SKIP ppc64 BE: missing powerpc64-linux-gnu-gcc or qemu-ppc64-static"
fi

# --- s390x big-endian ---
if command -v s390x-linux-gnu-gcc >/dev/null 2>&1 && \
   command -v qemu-s390x-static   >/dev/null 2>&1; then
    echo "==> building s390x BE (static, run under qemu-s390x-static)"
    s390x-linux-gnu-gcc "${CFLAGS_BE[@]}" \
        "$HERE/d7_sign.c" "$HERE/rcc_crypto_be.c" "${ORLP[@]}" \
        -o "$HERE/d7_sign_s390x"
else
    echo "==> SKIP s390x BE: missing s390x-linux-gnu-gcc or qemu-s390x-static"
fi

echo
echo "Built artifacts:"
ls -l "$HERE"/d7_sign_* 2>/dev/null || true
