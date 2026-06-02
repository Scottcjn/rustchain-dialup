/* rcc_crypto.h — crypto primitives for the RustChain dial-up vintage client.
 *
 * Two things the vintage box must do LOCALLY (the proof-of-antiquity invariant):
 *   1. SHA-256 (for the attestation `commitment`)
 *   2. Ed25519 keygen + detached sign (for the attestation signature)
 *
 * The Ed25519 backend is selectable at compile time:
 *   - default / -DRCC_OPENSSL    : OpenSSL 3 EVP   (modern + 486-Linux dev box; verifiable today)
 *   - -DRCC_MONOCYPHER           : Monocypher      (portable vintage target: 68k, PPC, SH-4)
 *                                  drop monocypher.c / monocypher.h next to these sources.
 *
 * SHA-256 is vendored (rcc_crypto.c) so it is identical on every architecture and
 * does not depend on the Ed25519 backend's hash menu (Monocypher has no SHA-256).
 */
#ifndef RCC_CRYPTO_H
#define RCC_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define RCC_SHA256_LEN     32
#define RCC_ED25519_SK_LEN 32   /* seed */
#define RCC_ED25519_PK_LEN 32
#define RCC_ED25519_SIG_LEN 64

/* SHA-256 over `len` bytes of `data` into `out` (32 bytes). */
void rcc_sha256(const uint8_t *data, size_t len, uint8_t out[RCC_SHA256_LEN]);

/* Derive the Ed25519 public key (32 bytes) from a 32-byte seed/private key. */
int rcc_ed25519_pubkey(const uint8_t seed[RCC_ED25519_SK_LEN],
                       uint8_t pk[RCC_ED25519_PK_LEN]);

/* Detached Ed25519 signature (64 bytes) over `msg` using a 32-byte seed.
 * Returns 0 on success, nonzero on failure. */
int rcc_ed25519_sign(const uint8_t seed[RCC_ED25519_SK_LEN],
                     const uint8_t *msg, size_t msglen,
                     uint8_t sig[RCC_ED25519_SIG_LEN]);

/* Lowercase-hex encode `len` bytes into `out` (must hold 2*len+1 chars). */
void rcc_hex(const uint8_t *in, size_t len, char *out);

#endif /* RCC_CRYPTO_H */
