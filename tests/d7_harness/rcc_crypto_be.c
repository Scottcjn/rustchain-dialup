/* rcc_crypto_be.c — Standard RFC 8032 Ed25519 + vendored SHA-256, big-endian-safe.
 *
 * Two goals for this file:
 *
 *   1. Provide the same rcc_crypto surface (rcc_sha256 / rcc_hex /
 *      rcc_ed25519_pubkey / rcc_ed25519_sign) as gateway/client/rcc_crypto.c
 *      so we can drop a sign-only harness into the same path the production
 *      vintage_client.c uses.
 *
 *   2. Use **standard Ed25519 (RFC 8032)**, because that is what the live
 *      RustChain node verifies. We do NOT use Monocypher's variant here —
 *      Monocypher's Ed25519 swaps SHA-512 for BLAKE2b, so its signatures
 *      are non-interoperable with the rest of the Ed25519 ecosystem
 *      (libsodium, OpenSSL, PyNaCl). For the round-trip proof to be
 *      meaningful, the big-endian target must produce signatures that
 *      **any** standard Ed25519 verifier accepts.
 *
 *      (Side note: the existing gateway/client/rcc_crypto.c has an
 *      `#ifdef RCC_MONOCYPHER` backend that, if selected, would emit
 *      non-RFC8032 signatures. That backend should be retired before any
 *      production vintage client relies on it. Filed as a follow-up
 *      concern in docs/D7_BE_ROUNDTRIP.md.)
 *
 * SHA-256 is the same FIPS-180-4 vendored implementation as rcc_crypto.c
 * (all math on uint32_t with explicit big-endian word assembly).
 *
 * Ed25519 is orlp/ed25519 (MIT), a small RFC 8032 implementation that
 * cross-compiles cleanly to powerpc64 BE and s390x (no architecture-
 * specific assembly, no external deps).
 */
#include "rcc_crypto_be.h"
#include "ed25519_orlp/ed25519.h"
#include <string.h>

/* ---- SHA-256 (vendored, byte-for-byte same as gateway/client/rcc_crypto.c) -- */
static uint32_t ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

void rcc_sha256(const uint8_t *data, size_t len, uint8_t out[RCC_SHA256_LEN]) {
    static const uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};

    uint64_t bitlen = (uint64_t)len * 8u;
    size_t total = len + 1;
    while (total % 64 != 56) total++;
    total += 8;

    for (size_t off = 0; off < total; off += 64) {
        uint8_t blk[64];
        for (int i = 0; i < 64; i++) {
            size_t idx = off + (size_t)i;
            uint8_t b;
            if      (idx < len)        b = data[idx];
            else if (idx == len)       b = 0x80;
            else if (idx < total - 8)  b = 0x00;
            else                       b = (uint8_t)(bitlen >> (8 * (total - 1 - idx)));
            blk[i] = b;
        }
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)blk[i*4] << 24) | ((uint32_t)blk[i*4+1] << 16) |
                   ((uint32_t)blk[i*4+2] << 8)  | (uint32_t)blk[i*4+3];
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ror(w[i-15],7) ^ ror(w[i-15],18) ^ (w[i-15] >> 3);
            uint32_t s1 = ror(w[i-2],17) ^ ror(w[i-2],19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = ror(e,6) ^ ror(e,11) ^ ror(e,25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = ror(a,2) ^ ror(a,13) ^ ror(a,22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(h[i] >> 24);
        out[i*4+1] = (uint8_t)(h[i] >> 16);
        out[i*4+2] = (uint8_t)(h[i] >> 8);
        out[i*4+3] = (uint8_t)(h[i]);
    }
}

void rcc_hex(const uint8_t *in, size_t len, char *out) {
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i*2]   = hx[(in[i] >> 4) & 0xf];
        out[i*2+1] = hx[in[i] & 0xf];
    }
    out[len*2] = '\0';
}

/* Standard Ed25519: pk = scalar * G, where scalar = SHA-512(seed)[..32]
 * (clamped). The orlp/ed25519 library follows RFC 8032 exactly; that is
 * what the live RustChain node verifies. */
int rcc_ed25519_pubkey(const uint8_t seed[RCC_ED25519_SK_LEN],
                       uint8_t       pk [RCC_ED25519_PK_LEN]) {
    /* orlp/ed25519 layout:
     *   ed25519_create_keypair(pk, sk, seed)
     *     pk: 32-byte public key
     *     sk: 64-byte secret key = seed (32) || pk (32)
     */
    uint8_t sk[64];
    ed25519_create_keypair(pk, sk, seed);
    /* do not keep the long-term sk around */
    for (volatile int i = 0; i < 64; i++) sk[i] = 0;
    return 0;
}

int rcc_ed25519_sign(const uint8_t *seed,
                     const uint8_t *msg, size_t msglen,
                     uint8_t        sig[RCC_ED25519_SIG_LEN]) {
    uint8_t pk[32], sk[64];
    ed25519_create_keypair(pk, sk, seed);
    ed25519_sign(sig, msg, msglen, pk, sk);
    for (volatile int i = 0; i < 64; i++) sk[i] = 0;
    return 0;
}
