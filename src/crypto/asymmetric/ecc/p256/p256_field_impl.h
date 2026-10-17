#ifndef CRYPTO_ASYMMETRIC_ECC_P256_P256_FIELD_IMPL_H
#define CRYPTO_ASYMMETRIC_ECC_P256_P256_FIELD_IMPL_H

/* Internal to the p256_field*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "crypto/asymmetric/ecc/p256/p256_field.h"

int  p256_fe_ge(const p256_fe a, const p256_fe b);
void p256_fe_sub_raw(p256_fe r, const p256_fe a, const p256_fe b);
void p256_fe_mul_wide(u64 w[8], const p256_fe a, const p256_fe b);
void p256_fe_reduce_wide(p256_fe r, u64 w[8], const p256_fe m);
u64  p256_w32(const u64 w[8], usz c);

#endif
