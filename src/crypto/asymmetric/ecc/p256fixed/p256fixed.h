#ifndef P256FIXED_H
#define P256FIXED_H

#include "crypto/asymmetric/ecc/p256/p256_field.h"

/** Fixed-base scalar multiplication k*G for the FIPS 186-4 D.1.2.3 P-256
 * base point G, via a precomputed windowed table: k is split into 64 4-bit
 * windows d_i (k = sum d_i * 16^i) and T[i][d] = d * 16^i * G is looked up
 * with a constant-time scan, so the whole multiply is 64 mixed additions
 * with no doublings and no scalar-bit branch (timing of k*G leaks the ECDSA
 * nonce k, RFC 6979 / FIPS 186-4 6.3). */

/* 64 windows x 15 nonzero digits x (x, y) as 4 little-endian u64 limbs each
 * (same limb order as p256_fe). Row i, digit d (1..15): limbs at
 * p256fixed_table[i] + (d - 1) * 8, x first then y. */
extern const u64 p256fixed_table[64][120];

/* out = scalar * G in affine coordinates as p256_fe limbs (the shape
 * p256sign's r-computation consumes directly; use p256_fp_to_be for wire
 * bytes). scalar is big-endian 32 bytes, any value < 2^256. Returns 0 when
 * the result is the point at infinity (scalar == 0 mod n), 1 otherwise. */
int p256fixed_mul_g(p256_fe out_x, p256_fe out_y, const u8 scalar[32]);

#endif
