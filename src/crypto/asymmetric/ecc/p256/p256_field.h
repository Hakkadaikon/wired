#ifndef QUIC_P256_FIELD_H
#define QUIC_P256_FIELD_H

#include "common/platform/sys/syscall.h"

/* FIPS 186-4 D.1.2.3 P-256 field GF(p), p = 2^256 - 2^224 + 2^192 + 2^96 - 1.
 * 256-bit values as four little-endian 64-bit limbs (p256_fe[0] is least
 * significant). Operations are generic over a 256-bit odd modulus so the same
 * core serves both the field p and the group order n (RFC 6090). Correctness
 * over speed: reduction is binary long division, inversion is Fermat. */

typedef u64 p256_fe[4];

/* The field prime p and group order n as p256_fe constants. */
extern const p256_fe quic_p256_p;
extern const p256_fe quic_p256_n;

/* Montgomery parameters for one odd modulus m (R = 2^256): n0inv = -m[0]^-1 mod
 * 2^64, rr = R^2 mod m (maps to Montgomery form), one = R mod m (Montgomery 1).
 * Lets mul/inverse over m avoid the slow long-division reducer. */
typedef struct {
  p256_fe m;
  p256_fe rr;
  p256_fe one;
  u64     n0inv;
} quic_mont;

/* Precomputed contexts for the field prime p and the group order n. */
extern const quic_mont quic_p256_mont_p;
extern const quic_mont quic_p256_mont_n;

/* Operand pair (a, b) for the two-input modular ops. Two borrowed limb
 * pointers passed by value, so a call stays register-only. */
typedef struct {
  const u64 *a;
  const u64 *b;
} quic_fpab;

/* r = a * b * R^-1 mod m (Montgomery product); r = a^-1 mod m (Fermat over
 * Montgomery mul). a,b < m. */
void quic_mont_mul(p256_fe r, quic_fpab ab, const quic_mont *mont);
void quic_mont_inv(p256_fe r, const p256_fe a, const quic_mont *mont);

void quic_fp_set(p256_fe r, const p256_fe a);
int  quic_fp_eq(const p256_fe a, const p256_fe b);
int  quic_fp_is_zero(const p256_fe a);
int  quic_fp_lt(
     const p256_fe a, const p256_fe b); /* 1 if a < b as 256-bit integers */

/* r = a mod m, for any a < 2^256. */
void quic_fp_reduce(p256_fe r, const p256_fe a, const p256_fe m);

/* r = (a + b) mod m, r = (a - b) mod m. a,b assumed already < m. */
void quic_fp_add(p256_fe r, quic_fpab ab, const p256_fe m);
void quic_fp_sub(p256_fe r, quic_fpab ab, const p256_fe m);

/* r = (a * b) mod m. a,b may be any value < 2^256. */
void quic_fp_mul(p256_fe r, quic_fpab ab, const p256_fe m);
void quic_fp_sqr(p256_fe r, const p256_fe a, const p256_fe m);

/* r = (a * b) mod p, r = (a * a) mod p, using the fast FIPS 186-4 D.2.5 Solinas
 * reduction specialised to the P-256 prime. Equivalent to quic_fp_mul(.,.,p)
 * but ~100x faster; the modulus is fixed to p (NOT usable for the order n). */
void quic_fp_mul_p(p256_fe r, const p256_fe a, const p256_fe b);
void quic_fp_sqr_p(p256_fe r, const p256_fe a);

/* r = a^-1 mod m via a^(m-2); m must be prime. */
void quic_fp_inv(p256_fe r, const p256_fe a, const p256_fe m);

/* r = a^-1 mod p via the fast Solinas mul (Fermat). Equivalent to
 * quic_fp_inv(., ., p) but far faster; modulus fixed to p. */
void quic_fp_inv_p(p256_fe r, const p256_fe a);

/* Big-endian 32-byte load/store (wire format for r, s, coordinates). */
void quic_fp_from_be(p256_fe r, const u8 b[32]);
void quic_fp_to_be(u8 b[32], const p256_fe a);

#endif
