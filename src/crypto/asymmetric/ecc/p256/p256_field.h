#ifndef P256_FIELD_H
#define P256_FIELD_H

#include "common/platform/sys/syscall.h"

/* FIPS 186-4 D.1.2.3 P-256 field GF(p), p = 2^256 - 2^224 + 2^192 + 2^96 - 1.
 * 256-bit values as four little-endian 64-bit limbs (p256_fe[0] is least
 * significant). Operations are generic over a 256-bit odd modulus so the same
 * core serves both the field p and the group order n (RFC 6090). Correctness
 * over speed: reduction is binary long division, inversion is Fermat. */

typedef u64 p256_fe[4];

/* The field prime p and group order n as p256_fe constants. */
extern const p256_fe p256_p;
extern const p256_fe p256_n;

/** Montgomery parameters for one odd modulus m (R = 2^256): n0inv = -m[0]^-1
 * mod 2^64, rr = R^2 mod m (maps to Montgomery form), one = R mod m
 * (Montgomery 1). Lets mul/inverse over m avoid the slow long-division
 * reducer. */
typedef struct {
  p256_fe m;
  p256_fe rr;
  p256_fe one;
  u64     n0inv;
} mont;

/* Precomputed contexts for the field prime p and the group order n. */
extern const mont p256_mont_p;
extern const mont p256_mont_n;

/* Operand pair (a, b) for the two-input modular ops. Two borrowed limb
 * pointers passed by value, so a call stays register-only. */
typedef struct {
  const u64* a;
  const u64* b;
} fpab;

/* r = a * b * R^-1 mod m (Montgomery product); r = a^-1 mod m (Fermat over
 * Montgomery mul). a,b < m. */
void mont_mul(p256_fe r, fpab ab, const mont* mont);
void mont_inv(p256_fe r, const p256_fe a, const mont* mont);

void p256_fp_set(p256_fe r, const p256_fe a);
int  p256_fp_eq(const p256_fe a, const p256_fe b);
int  p256_fp_is_zero(const p256_fe a);
int  p256_fp_lt(
    const p256_fe a, const p256_fe b); /* 1 if a < b as 256-bit integers */

/* r = a mod m, for any a < 2^256. */
void p256_fp_reduce(p256_fe r, const p256_fe a, const p256_fe m);

/* r = (a + b) mod m, r = (a - b) mod m. a,b assumed already < m. */
void p256_fp_add(p256_fe r, fpab ab, const p256_fe m);
void p256_fp_sub(p256_fe r, fpab ab, const p256_fe m);

/* r = (a * b) mod m. a,b may be any value < 2^256. */
void p256_fp_mul(p256_fe r, fpab ab, const p256_fe m);
void p256_fp_sqr(p256_fe r, const p256_fe a, const p256_fe m);

/* r = (a * b) mod n for the P-256 group order, a,b < n. Equivalent to
 * p256_fp_mul(., ., n) but via two Montgomery products instead of the
 * bit-loop long division (~1000x faster); modulus fixed to n. */
void p256_fp_mul_n(p256_fe r, fpab ab);

/* r = a mod n for any a < 2^256. Equivalent to p256_fp_reduce(., ., n):
 * n > 2^255 means 2^256 < 2n, so one conditional subtract replaces the
 * long division. */
void p256_fp_reduce_n(p256_fe r, const p256_fe a);

/* r = (a * b) mod p, r = (a * a) mod p, using the fast FIPS 186-4 D.2.5 Solinas
 * reduction specialised to the P-256 prime. Equivalent to p256_fp_mul(.,.,p)
 * but ~100x faster; the modulus is fixed to p (NOT usable for the order n). */
void p256_fp_mul_p(p256_fe r, const p256_fe a, const p256_fe b);
void p256_fp_sqr_p(p256_fe r, const p256_fe a);

/* r = a^-1 mod m via a^(m-2); m must be prime. */
void p256_fp_inv(p256_fe r, const p256_fe a, const p256_fe m);

/* r = a^-1 mod p via the fast Solinas mul (Fermat). Equivalent to
 * p256_fp_inv(., ., p) but far faster; modulus fixed to p. */
void p256_fp_inv_p(p256_fe r, const p256_fe a);

/* Big-endian 32-byte load/store (wire format for r, s, coordinates). */
void p256_fp_from_be(p256_fe r, const u8 b[32]);
void p256_fp_to_be(u8 b[32], const p256_fe a);

#endif
