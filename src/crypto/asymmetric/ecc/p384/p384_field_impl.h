#ifndef CRYPTO_ASYMMETRIC_ECC_P384_P384_FIELD_IMPL_H
#define CRYPTO_ASYMMETRIC_ECC_P384_P384_FIELD_IMPL_H

/* Internal to the p384_field*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "crypto/asymmetric/ecc/p384/p384_field.h"

int  fp384_fe6_ge(const p384_fe a, const p384_fe b);
void fp384_fe6_sub_raw(p384_fe r, const p384_fe a, const p384_fe b);
void fp384_fe6_mul_wide(u64 w[12], const p384_fe a, const p384_fe b);
void fp384_fe6_reduce_step(u64 w[12], const p384_fe m, usz sh);
void fp384_build_term384(p384_fe out, const u64 w[12], usz t);
void fp384_add_p(p384_fe r, const p384_fe t);
void fp384_sub_p(p384_fe r, const p384_fe t);
int  fp384_ebit(const p384_fe e, usz i);

#endif
