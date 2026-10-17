#ifndef CRYPTO_ASYMMETRIC_ECC_ED25519_ED25519_SIGN_IMPL_H
#define CRYPTO_ASYMMETRIC_ECC_ED25519_ED25519_SIGN_IMPL_H

/* Internal to the ed25519_sign*.c pieces of this directory: shared types,
 * macros and the functions and tables more than one piece uses. Not public API.
 */

#include "common/bytes/span/span.h"
#include "crypto/asymmetric/ecc/ed25519/ed25519.h"
#include "crypto/asymmetric/ecc/ed25519/ed25519_field.h"
#include "crypto/symmetric/hash/hash/sha512.h"

/* RFC 8032 Section 5.1 Ed25519 scalar arithmetic, message hashing, and the
 * public keypair/sign/verify API. Group/field arithmetic lives in
 * ed25519_field.c. */

typedef ed_ge ge;

int  ed25519_sign_sc_ge(const u8 a[32], const u8 b[32]);
void ed25519_sign_sc_reduce64(u8 out[32], const u8 in[64]);
void ed25519_sign_hash_k(u8 k[32], const u8* R, const u8* A, wired_span msg);
int  ed25519_sign_decode_checked(ge* p, const u8 in[32]);
int  ed25519_sign_check_equation(
    const u8 S[32], const u8 k[32], const ge* A, const u8 R[32]);

extern const u8 ORDER_L[32];

#endif
