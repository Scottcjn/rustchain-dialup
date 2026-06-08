/* d7_sign.c — D7 big-endian signature round-trip harness.
 *
 * Stand-alone binary (no networking, no JSON library). Cross-compiles for
 * big-endian targets (powerpc64 BE, s390x) and runs under qemu-user-static
 * to prove the SHA-256 commitment and Ed25519 signature produced by a
 * big-endian vintage client are byte-identical to the host Python
 * reference (gateway/client/attest_sign_reference.py).
 *
 * Usage:
 *     d7_sign --seed-hex <64hex> --miner <id> --wallet <RTC...> \
 *             [--nonce fixednonce0001]
 *
 * Output (line-oriented, easy to diff):
 *     public_key  : <64 hex chars>
 *     nonce       : <server-issued>
 *     commitment  : <64 hex chars>
 *     sign_msg    : miner|wallet|nonce|commitment
 *     signature   : <128 hex chars>
 *
 * Defaults match gateway/client/attest_sign_reference.py for the canonical
 * reproducible test vector (no network involved, no server nonce needed).
 */
#include "rcc_crypto_be.h"
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

int main(int argc, char **argv) {
    const char *seed_hex = NULL, *miner = NULL, *wallet = NULL;
    const char *nonce = "fixednonce0001";
    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "--seed-hex") && i+1 < argc) seed_hex = argv[++i];
        else if (!strcmp(argv[i], "--miner")    && i+1 < argc) miner    = argv[++i];
        else if (!strcmp(argv[i], "--wallet")   && i+1 < argc) wallet   = argv[++i];
        else if (!strcmp(argv[i], "--nonce")    && i+1 < argc) nonce    = argv[++i];
        else { fprintf(stderr, "unknown arg: %s\n", argv[i]); return 2; }
    }
    if (!seed_hex || !miner || !wallet) {
        fprintf(stderr, "usage: d7_sign --seed-hex <64hex> --miner <id> --wallet <RTC...> [--nonce <n>]\n");
        return 2;
    }
    if (strlen(seed_hex) != 64) {
        fprintf(stderr, "--seed-hex must be exactly 64 hex chars (32 bytes)\n");
        return 2;
    }

    uint8_t seed[32];
    if (hex2bin(seed_hex, seed, 32)) { fprintf(stderr, "bad --seed-hex\n"); return 2; }

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
    return 0;
}
