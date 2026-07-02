#ifndef QUIC_P384_FIELD_H
#define QUIC_P384_FIELD_H

#include "common/platform/sys/syscall.h"

/* FIPS 186-4 D.1.2.4 P-384 field GF(p), p = 2^384 - 2^128 - 2^96 + 2^32 - 1.
 * 384-bit values as six little-endian 64-bit limbs (p384_fe[0] is least
 * significant). A copy-and-widen of the P-256 field: generic ops over a
 * 384-bit odd modulus serve both the field p and the group order n, plus a
 * fast FIPS 186-4 D.2.4 Solinas reduction specialised to p. */

typedef u64 p384_fe[6];

extern const p384_fe quic_p384_p;
extern const p384_fe quic_p384_n;

/* Montgomery parameters for one odd modulus m (R = 2^384). */
typedef struct {
  p384_fe m;
  p384_fe rr;
  p384_fe one;
  u64     n0inv;
} quic_mont384;

extern const quic_mont384 quic_p384_mont_p;
extern const quic_mont384 quic_p384_mont_n;

void quic_mont384_mul(
    p384_fe r, const p384_fe a, const p384_fe b, const quic_mont384 *mont);
void quic_mont384_inv(p384_fe r, const p384_fe a, const quic_mont384 *mont);

void quic_fp384_set(p384_fe r, const p384_fe a);
int  quic_fp384_eq(const p384_fe a, const p384_fe b);
int  quic_fp384_is_zero(const p384_fe a);
int  quic_fp384_lt(const p384_fe a, const p384_fe b);

void quic_fp384_reduce(p384_fe r, const p384_fe a, const p384_fe m);
void quic_fp384_add(
    p384_fe r, const p384_fe a, const p384_fe b, const p384_fe m);
void quic_fp384_sub(
    p384_fe r, const p384_fe a, const p384_fe b, const p384_fe m);
void quic_fp384_mul(
    p384_fe r, const p384_fe a, const p384_fe b, const p384_fe m);
void quic_fp384_sqr(p384_fe r, const p384_fe a, const p384_fe m);

/* Fast Solinas reduction, modulus fixed to p (NOT usable for the order n). */
void quic_fp384_mul_p(p384_fe r, const p384_fe a, const p384_fe b);
void quic_fp384_sqr_p(p384_fe r, const p384_fe a);

void quic_fp384_inv(p384_fe r, const p384_fe a, const p384_fe m);
void quic_fp384_inv_p(p384_fe r, const p384_fe a);

/* Big-endian 48-byte load/store. */
void quic_fp384_from_be(p384_fe r, const u8 b[48]);
void quic_fp384_to_be(u8 b[48], const p384_fe a);

#endif
