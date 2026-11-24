#ifndef CRYPTO_ASYMMETRIC_ECC_SECP256K1_SECP256K1_IMPL_H
#define CRYPTO_ASYMMETRIC_ECC_SECP256K1_SECP256K1_IMPL_H

/* Internal to the secp256k1*.c pieces: the hot field operations, inline so
 * the per-object build keeps them inlined. Not public API. */

#include "common/bytes/util/bytes.h"
#include "common/bytes/util/ct.h"
#include "crypto/asymmetric/ecc/secp256k1/secp256k1.h"

static inline void secp256k1_fe_mul(
    p256_fe r, const p256_fe a, const p256_fe b) {
  mont_mul(r, (fpab){a, b}, &secp256k1_mont_p);
}

static inline void secp256k1_fe_sqr(p256_fe r, const p256_fe a) {
  mont_mul(r, (fpab){a, a}, &secp256k1_mont_p);
}

/* add/sub are the same on Montgomery and plain residues. */
static inline void secp256k1_fe_add(
    p256_fe r, const p256_fe a, const p256_fe b) {
  p256_fp_add(r, (fpab){a, b}, secp256k1_p);
}

static inline void secp256k1_fe_sub(
    p256_fe r, const p256_fe a, const p256_fe b) {
  p256_fp_sub(r, (fpab){a, b}, secp256k1_p);
}

#endif
