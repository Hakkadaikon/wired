#ifndef CRYPTO_ASYMMETRIC_ECC_SECP256K1_SECP256K1_H
#define CRYPTO_ASYMMETRIC_ECC_SECP256K1_SECP256K1_H

/* SEC 2 2.4.1 secp256k1: y^2 = x^3 + 7 over GF(p), p = 2^256 - 2^32 - 977,
 * prime group order n. VARIABLE TIME, PUBLIC INPUTS ONLY: built for
 * signature verification (BIP-340), never for a secret scalar or key.
 *
 * The 256-bit limb type and the Montgomery core are the P-256 field's,
 * which are generic over any odd modulus m > 2^255 (mont_mul, p256_fp_add,
 * p256_fp_sub, p256_fp_lt); only the constants here are secp256k1's. */

#include "crypto/asymmetric/ecc/p256/p256_field.h"

/* Jacobian point (x/z^2, y/z^3) with coordinates in Montgomery form
 * (a*2^256 mod p); z == 0 is the point at infinity. */
typedef struct {
  p256_fe x, y, z;
} secp256k1_pt;

/* p, n, and (p + 1) / 4 (the square-root exponent: p = 3 mod 4). */
extern const p256_fe secp256k1_p;
extern const p256_fe secp256k1_n;
extern const p256_fe secp256k1_sqrt_exp;
/* Montgomery context for p (R = 2^256). */
extern const mont secp256k1_mont_p;

/* r = a^e for a in Montgomery form (result in Montgomery form). */
void secp256k1_fe_pow(p256_fe r, const p256_fe a, const p256_fe e);
/* Montgomery form <-> plain residue. */
void secp256k1_fe_to_mont(p256_fe r, const p256_fe a);
void secp256k1_fe_from_mont(p256_fe r, const p256_fe a);

/* The generator G (SEC 2 2.4.1). */
void secp256k1_base(secp256k1_pt* g);
/* r = 2a; r = a + b (any inputs, infinity and a == b included). r may
 * alias an input. */
void secp256k1_dbl(secp256k1_pt* r, const secp256k1_pt* a);
void secp256k1_add(
    secp256k1_pt* r, const secp256k1_pt* a, const secp256k1_pt* b);
/* r = k.a * p + k.b * q (Shamir's trick; scalars as plain 256-bit ints). */
void secp256k1_mul2(
    secp256k1_pt* r, fpab k, const secp256k1_pt* p, const secp256k1_pt* q);
/* BIP-340 lift_x: the point with x coordinate x (big-endian) and even y.
 * 0 when x >= p or x^3 + 7 is not a square mod p. */
int secp256k1_lift_x(secp256k1_pt* r, const u8 x[32]);
/* Affine x (big-endian) and the parity of y; 0 for the point at
 * infinity. */
int secp256k1_affine(u8 x[32], int* y_odd, const secp256k1_pt* a);

#endif
