/* d7_sign.c — D7 big-endian signature round-trip harness.
 *
 * SPDX-License-Identifier: MIT
 *
 * Stand-alone binary (no networking, no JSON library). Cross-compiles for
 * big-endian targets (powerpc64 BE, s390x) and runs under qemu-user-static
 * to prove the SHA-256 commitment and Ed25519 signature produced by a
 * big-endian vintage client are byte-identical to the host Python
 * reference (gateway/client/attest_sign_reference.py).
 *
 * Usage:
 *     d7_sign --seed-hex <64hex> --miner <id> --wallet <RTC...> \
 *             [--nonce fixednonce0001] [--self-verify]
 *
 * SECURITY: the seed is the Ed25519 private key. Accepting it via
 * `argv` leaks it to the process list and shell history. Use
 * `D7_SEED_HEX` env var instead. `--seed-hex <value>` is still
 * accepted for the canonical test vectors, but emits a stderr warning.
 *
 * Output (line-oriented, easy to diff):
 *     public_key  : <64 hex chars>
 *     nonce       : <server-issued>
 *     commitment  : <64 hex chars>
 *     sign_msg    : miner|wallet|nonce|commitment
 *     signature   : <128 hex chars>
 *     verify      : OK  (only with --self-verify)
 *
 * With `--self-verify`, after signing, the harness runs its own
 * canonical Ed25519 verify (RFC 8032, including the S < L malleability
 * guard) and prints `verify : OK` or `verify : FAIL` plus a reason.
 * This is what proves the signature is *Ed25519-valid* on this target,
 * not just *Ed25519-shaped*.
 *
 * Defaults match gateway/client/attest_sign_reference.py for the canonical
 * reproducible test vector (no network involved, no server nonce needed).
 */
#include "rcc_crypto_be.h"
#include "ed25519_orlp/ed25519.h"
#include "ed25519_orlp/sha512.h"
#include "ed25519_orlp/ge.h"
#include "ed25519_orlp/sc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Must match gateway/client/attest_sign_reference.py byte-for-byte. */
static const char ENTROPY_JSON[] = "{\"variance_ns\":0.0}";

static int hex2bin(const char *hex, uint8_t *out, size_t outlen) {
    for (size_t i = 0; i < outlen; i++) {
        unsigned v;
        if (sscanf(hex + i*2, "%2x", &v) != 1) return 1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

/* ---- Self-verify (canonical RFC 8032, including S < L guard) ---------- */

/* Constants for the Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493
 * and the cofactor.  Reference: RFC 8032 §5.1.3, step 2 ("the verification
 * check that s < L"), and the SUPERCOP "ref10" implementation. */
static const uint8_t L_BYTES[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
};

/* Return 0 if S < L, nonzero otherwise. S is interpreted as a little-endian
 * 256-bit integer (the wire format of Ed25519's lower-half 32 bytes). */
static int s_is_canonical(const uint8_t sig[64]) {
    /* Compare sig[32..63] (little-endian S) to L_BYTES (little-endian L). */
    for (int i = 31; i >= 0; i--) {
        if (sig[32 + i] < L_BYTES[i]) return 1;  /* S < L: canonical */
        if (sig[32 + i] > L_BYTES[i]) return 0;  /* S > L: not canonical */
    }
    return 0;  /* S == L: not canonical (S must be strictly less than L) */
}

/* Constant-time byte comparison. Returns 1 on equal, 0 on unequal. */
static int ct_equal(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t r = 0;
    for (size_t i = 0; i < n; i++) r |= a[i] ^ b[i];
    return r == 0;
}

/* Self-verify: run canonical Ed25519 verify on the freshly produced
 * (pk, sig, sign_msg) tuple. Returns 0 on OK, nonzero on FAIL.
 *   rc 1: S is not canonical (S >= L) — malleability guard
 *   rc 2: signature[63] & 224 != 0  — high bits set
 *   rc 3: public key is not a valid group element
 *   rc 4: signature verification equation did not hold */
static int self_verify(const uint8_t pk[32], const uint8_t sig[64],
                      const uint8_t *msg, size_t msg_len) {
    if ((sig[63] & 224) != 0) return 2;
    if (!s_is_canonical(sig)) return 1;

    ge_p3 A;
    if (ge_frombytes_negate_vartime(&A, pk) != 0) return 3;

    uint8_t h[64];
    sha512_context hash;
    sha512_init(&hash);
    sha512_update(&hash, sig, 32);     /* R */
    sha512_update(&hash, pk, 32);      /* A */
    sha512_update(&hash, msg, msg_len);
    sha512_final(&hash, h);
    sc_reduce(h);

    ge_p2 R;
    ge_double_scalarmult_vartime(&R, h, &A, sig + 32);
    uint8_t checker[32];
    ge_tobytes(checker, &R);

    if (!ct_equal(checker, sig, 32)) return 4;
    return 0;
}

static const char *verify_reason(int rc) {
    switch (rc) {
        case 0: return "OK";
        case 1: return "FAIL: S >= L (signature malleable; not RFC 8032 canonical)";
        case 2: return "FAIL: signature[63] & 224 != 0 (S high bits set)";
        case 3: return "FAIL: public key is not a valid Ed25519 group element";
        case 4: return "FAIL: 8*[S]B = R check failed";
        default: return "FAIL: unknown";
    }
}

int main(int argc, char **argv) {
    const char *seed_hex = NULL, *miner = NULL, *wallet = NULL;
    const char *nonce = "fixednonce0001";
    int do_verify = 0;
    int warn_argv_seed = 0;

    /* env-var path (preferred) */
    const char *env_seed = getenv("D7_SEED_HEX");
    if (env_seed != NULL && env_seed[0] != '\0') {
        seed_hex = env_seed;
    }

    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "--seed-hex") && i+1 < argc) {
            seed_hex = argv[++i];
            warn_argv_seed = 1;
        }
        else if (!strcmp(argv[i], "--miner")    && i+1 < argc) miner    = argv[++i];
        else if (!strcmp(argv[i], "--wallet")   && i+1 < argc) wallet   = argv[++i];
        else if (!strcmp(argv[i], "--nonce")    && i+1 < argc) nonce    = argv[++i];
        else if (!strcmp(argv[i], "--self-verify"))           do_verify = 1;
        else { fprintf(stderr, "unknown arg: %s\n", argv[i]); return 2; }
    }
    if (!seed_hex || !miner || !wallet) {
        fprintf(stderr,
                "usage: d7_sign --miner <id> --wallet <RTC...> [--nonce <n>]\n"
                "       (seed is read from $D7_SEED_HEX; --seed-hex is accepted\n"
                "        for the canonical test vectors but emits a warning.)\n");
        return 2;
    }
    if (strlen(seed_hex) != 64) {
        fprintf(stderr, "--seed-hex / $D7_SEED_HEX must be exactly 64 hex chars (32 bytes)\n");
        return 2;
    }
    if (warn_argv_seed) {
        fprintf(stderr,
                "WARNING: --seed-hex leaks the private key to argv (process list, shell history).\n"
                "         Use D7_SEED_HEX env var for real wallets.\n");
    }

    uint8_t seed[32];
    if (hex2bin(seed_hex, seed, 32)) { fprintf(stderr, "bad seed hex\n"); return 2; }

    /* pubkey (32 bytes) */
    uint8_t pk[32];
    if (rcc_ed25519_pubkey(seed, pk)) { fprintf(stderr, "pubkey failed\n"); return 1; }

    /* commitment = SHA-256( nonce + wallet + entropy_json ) */
    char preimage[2048];
    int plen = snprintf(preimage, sizeof preimage, "%s%s%s", nonce, wallet, ENTROPY_JSON);
    if (plen <= 0 || (size_t)plen >= sizeof preimage) { fprintf(stderr, "preimage too long\n"); return 1; }
    uint8_t cdigest[32];
    rcc_sha256((const uint8_t *)preimage, (size_t)plen, cdigest);

    /* sign miner|wallet|nonce|commitment */
    char signmsg[2048];
    int slen = snprintf(signmsg, sizeof signmsg, "%s|%s|%s|", miner, wallet, nonce);
    if (slen <= 0 || (size_t)slen >= sizeof signmsg) { fprintf(stderr, "signmsg prefix too long\n"); return 1; }
    char commitment_hex[65];
    rcc_hex(cdigest, 32, commitment_hex);
    if ((size_t)slen + 64 >= sizeof signmsg) { fprintf(stderr, "signmsg too long\n"); return 1; }
    memcpy(signmsg + slen, commitment_hex, 64);
    signmsg[slen + 64] = '\0';
    size_t sm_len = (size_t)slen + 64;

    uint8_t sig[64];
    if (rcc_ed25519_sign(seed, (const uint8_t *)signmsg, sm_len, sig)) {
        fprintf(stderr, "sign failed\n"); return 1;
    }

    char pk_hex[65], sig_hex[129];
    rcc_hex(pk, 32, pk_hex);
    rcc_hex(sig, 64, sig_hex);

    /* Format mirrors gateway/client/attest_sign_reference.py for trivial
     * `diff` against the Python reference oracle: label is right-padded
     * to width 10 ("{k:10} : {v[k]}" in Python), so the harness output
     * is byte-identical to the reference signer. */
    printf("%-10s : %s\n", "public_key", pk_hex);
    printf("%-10s : %s\n", "nonce",      nonce);
    printf("%-10s : %s\n", "commitment", commitment_hex);
    printf("%-10s : %s\n", "sign_msg",   signmsg);
    printf("%-10s : %s\n", "signature",  sig_hex);

    if (do_verify) {
        int rc = self_verify(pk, sig, (const uint8_t *)signmsg, sm_len);
        printf("%-10s : %s\n", "verify", verify_reason(rc));
        if (rc != 0) return rc;
    }

    /* Do not leave the seed in memory; the compiler is allowed to keep
     * it in registers, but volatile memset forces a write. */
    for (volatile int i = 0; i < 32; i++) seed[i] = 0;
    return 0;
}
