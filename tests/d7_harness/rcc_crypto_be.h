// SPDX-License-Identifier: MIT
/* rcc_crypto_be.h — Big-endian-friendly version of rcc_crypto.h
 *
 * The existing gateway/client/rcc_crypto.h is OpenSSL-only by default; this
 * header exposes the same surface as a small Monocypher-backed shim that
 * we can cross-compile for big-endian targets (powerpc64 BE, s390x, m68k)
 * with no external crypto dependency. Monocypher is single-file and
 * already supports big-endian (it operates on byte arrays).
 *
 * Surface kept identical to rcc_crypto.h so we can drop this into a
 * stand-alone harness that exercises the SAME hex/sha256/sign paths the
 * production vintage_client.c uses — and so the diff between the two
 * surfaces is just the backend (OpenSSL -> Monocypher).
 */
#ifndef RCC_CRYPTO_BE_H
#define RCC_CRYPTO_BE_H

#include <stddef.h>
#include <stdint.h>

#define RCC_SHA256_LEN   32
#define RCC_ED25519_SK_LEN 32
#define RCC_ED25519_PK_LEN 32
#define RCC_ED25519_SIG_LEN 64

void rcc_sha256(const uint8_t *data, size_t len, uint8_t out[RCC_SHA256_LEN]);
void rcc_hex(const uint8_t *in, size_t len, char *out);
int  rcc_ed25519_pubkey(const uint8_t seed[RCC_ED25519_SK_LEN],
                        uint8_t       pk  [RCC_ED25519_PK_LEN]);
int  rcc_ed25519_sign(const uint8_t *seed,
                      const uint8_t *msg, size_t msglen,
                      uint8_t        sig [RCC_ED25519_SIG_LEN]);

#endif
