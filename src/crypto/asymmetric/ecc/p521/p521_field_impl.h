#ifndef CRYPTO_ASYMMETRIC_ECC_P521_P521_FIELD_IMPL_H
#define CRYPTO_ASYMMETRIC_ECC_P521_P521_FIELD_IMPL_H

/* Internal to the p521_field*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "crypto/asymmetric/ecc/p521/p521_field.h"

/* Binary inversion state: x1*a == u and x2*a == v (mod m). */
typedef struct {
  p521_fe u, v, x1, x2;
} fp521_invst;

int  fp521_fe9_ge(const p521_fe a, const p521_fe b);
void fp521_fe9_sub_raw(p521_fe r, const p521_fe a, const p521_fe b);
void fp521_fe9_add_raw(p521_fe r, const p521_fe a, const p521_fe b);

extern const p521_fe fp521_one;

#endif
