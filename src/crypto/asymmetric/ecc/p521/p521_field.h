#ifndef P521_FIELD_H
#define P521_FIELD_H

#include "common/platform/sys/syscall.h"

/* FIPS 186-4 D.1.2.5 P-521 arithmetic, verify-only (public inputs, not
 * constant time). 521-bit values as nine little-endian 64-bit limbs
 * (p521_fe[0] least significant), always kept reduced below the modulus. */

typedef u64 p521_fe[9];

extern const p521_fe p521_p; /* 2^521 - 1 */
extern const p521_fe p521_n; /* group order */

void fp521_set(p521_fe r, const p521_fe a);
int  fp521_eq(const p521_fe a, const p521_fe b);
int  fp521_is_zero(const p521_fe a);
int  fp521_lt(const p521_fe a, const p521_fe b);

/* r = a + b / a - b mod m, for a, b < m (m = p or n). add only needs
 * a + b < 2m, so fp521_add(r, x, 0, m) reduces any x < 2m. */
void fp521_add(p521_fe r, const p521_fe a, const p521_fe b, const p521_fe m);
void fp521_sub(p521_fe r, const p521_fe a, const p521_fe b, const p521_fe m);

/* r = a * b mod p, Mersenne fold (the point-arithmetic hot path). */
void fp521_mul_p(p521_fe r, const p521_fe a, const p521_fe b);

/* r = a * b mod m for a, b < m < 2^521, bit-serial double-and-add (slow;
 * only the few mod-n products of one verification use it). */
void fp521_mul(p521_fe r, const p521_fe a, const p521_fe b, const p521_fe m);

/* r = a^-1 mod m for an odd prime m and 0 < a < m (binary extended GCD). */
void fp521_inv(p521_fe r, const p521_fe a, const p521_fe m);

/* Big-endian 66-byte load/store. A load keeps all 528 bits, so the caller
 * range-checks it with fp521_lt. */
void fp521_from_be(p521_fe r, const u8 b[66]);
void fp521_to_be(u8 b[66], const p521_fe a);

#endif
