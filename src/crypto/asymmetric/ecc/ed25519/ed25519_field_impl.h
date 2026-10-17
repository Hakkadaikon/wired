#ifndef CRYPTO_ASYMMETRIC_ECC_ED25519_ED25519_FIELD_IMPL_H
#define CRYPTO_ASYMMETRIC_ECC_ED25519_ED25519_FIELD_IMPL_H

/* Internal to the ed25519_field*.c pieces of this directory: shared types,
 * macros and the functions and tables more than one piece uses. Not public API.
 */

#include "crypto/asymmetric/ecc/ed25519/ed25519_field.h"

/* RFC 8032 Section 5.1 Ed25519 field/group arithmetic. Field GF(2^255-19) as
 * five 51-bit limbs (radix-2^51, ref10 style; same representation as RFC 7748
 * X25519). Group points in extended homogeneous coordinates. */

typedef ed_fe fe;

typedef ed_ge ge;

#define MASK51 0x7ffffffffffffULL

void ed_fe_0(fe h);
void ed_fe_1(fe h);
void ed_fe_copy(fe h, const fe f);
void ed_fe_add(fe h, const fe f, const fe g);
void ed_fe_sub(fe h, const fe f, const fe g);
void ed_fe_mul(fe h, const fe f, const fe g);
void ed_fe_sq(fe h, const fe f);
void ed_fe_invert(fe out, const fe z);
void ed_fe_pow_p58(fe out, const fe z);
void ed_fe_frombytes(fe h, const u8* s);
void ed_fe_tobytes(u8* s, const fe h);
void ed_fe_neg(fe h, const fe f);
int  ed_fe_isnonzero(const fe f);
int  ed_fe_isnegative(const fe f);
int  ed_fe_equal(const fe a, const fe b);
void ed_fe_cmov(fe h, const fe g, int cond);
void ed_fe_sqrtm1(fe out);
void ed_fe_d(fe out);
void ed_ge_zero(ge* p);

#endif
