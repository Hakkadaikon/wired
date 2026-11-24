#ifndef CRYPTO_ASYMMETRIC_ECC_BIP340_BIP340_H
#define CRYPTO_ASYMMETRIC_ECC_BIP340_BIP340_H

#include "common/platform/sys/syscall.h"

/* BIP-340 "Verification": 1 when sig (r || s, 64 bytes) is a valid Schnorr
 * signature of msg[0..len) under the x-only public key pk, else 0. Rejects
 * a pk that fails lift_x, r >= p, s >= n, and an R = s*G - e*P that is
 * infinite, has odd y, or whose x differs from r. Variable time: inputs
 * are public (signature verification only). */
int bip340_verify(const u8 pk[32], const u8* msg, usz len, const u8 sig[64]);

#endif
