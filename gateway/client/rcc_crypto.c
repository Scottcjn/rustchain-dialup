/* rcc_crypto.c — see rcc_crypto.h.
 *
 * SHA-256: vendored public-domain-style implementation (FIPS 180-4), endian-clean.
 * Ed25519: OpenSSL EVP (default) or Monocypher (-DRCC_MONOCYPHER).
 */
#include "rcc_crypto.h"
#include <string.h>

/* ----------------------------------------------------------------------- */
/* SHA-256 (portable, big- and little-endian safe — all math on uint32_t)  */
/* ----------------------------------------------------------------------- */
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

    /* padded length = len + 1 (0x80) + zeros + 8 (bit length), to a 64-byte multiple */
    uint64_t bitlen = (uint64_t)len * 8u;
    size_t total = len + 1;
    while (total % 64 != 56) total++;
    total += 8;

    for (size_t off = 0; off < total; off += 64) {
        uint8_t blk[64];
        for (int i = 0; i < 64; i++) {
            size_t idx = off + (size_t)i;
            uint8_t b;
            if (idx < len)            b = data[idx];
            else if (idx == len)      b = 0x80;
            else if (idx < total - 8) b = 0x00;
            else                      b = (uint8_t)(bitlen >> (8 * (total - 1 - idx)));
            blk[i] = b;
        }
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)blk[i*4] << 24) | ((uint32_t)blk[i*4+1] << 16) |
                   ((uint32_t)blk[i*4+2] << 8) | (uint32_t)blk[i*4+3];
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

/* ----------------------------------------------------------------------- */
/* Ed25519 backend                                                          */
/* ----------------------------------------------------------------------- */
#ifdef RCC_MONOCYPHER
#include "monocypher.h"   /* drop monocypher.c/.h here for the vintage port */

int rcc_ed25519_pubkey(const uint8_t seed[RCC_ED25519_SK_LEN],
                       uint8_t pk[RCC_ED25519_PK_LEN]) {
    uint8_t sk[64];
    crypto_eddsa_key_pair(sk, pk, (uint8_t *)seed);  /* note: clobbers seed copy */
    crypto_wipe(sk, sizeof sk);
    return 0;
}

int rcc_ed25519_sign(const uint8_t seed[RCC_ED25519_SK_LEN],
                     const uint8_t *msg, size_t msglen,
                     uint8_t sig[RCC_ED25519_SIG_LEN]) {
    uint8_t sk[64], pk[32], seedcopy[32];
    memcpy(seedcopy, seed, 32);
    crypto_eddsa_key_pair(sk, pk, seedcopy);   /* derives full key from seed */
    crypto_eddsa_sign(sig, sk, msg, msglen);
    crypto_wipe(sk, sizeof sk);
    return 0;
}

#else  /* OpenSSL EVP (default) */
#include <openssl/evp.h>

int rcc_ed25519_pubkey(const uint8_t seed[RCC_ED25519_SK_LEN],
                       uint8_t pk[RCC_ED25519_PK_LEN]) {
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed,
                                                 RCC_ED25519_SK_LEN);
    if (!key) return 1;
    size_t pklen = RCC_ED25519_PK_LEN;
    int rc = EVP_PKEY_get_raw_public_key(key, pk, &pklen) == 1 ? 0 : 1;
    EVP_PKEY_free(key);
    return rc;
}

int rcc_ed25519_sign(const uint8_t seed[RCC_ED25519_SK_LEN],
                     const uint8_t *msg, size_t msglen,
                     uint8_t sig[RCC_ED25519_SIG_LEN]) {
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed,
                                                 RCC_ED25519_SK_LEN);
    if (!key) return 1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int rc = 1;
    /* Ed25519 is a one-shot algorithm: EVP_DigestSign (NOT Update/Final). */
    if (ctx && EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) == 1) {
        size_t siglen = RCC_ED25519_SIG_LEN;
        if (EVP_DigestSign(ctx, sig, &siglen, msg, msglen) == 1 &&
            siglen == RCC_ED25519_SIG_LEN)
            rc = 0;
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return rc;
}
#endif
