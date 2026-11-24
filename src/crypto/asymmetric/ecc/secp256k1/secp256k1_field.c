#include "crypto/asymmetric/ecc/secp256k1/secp256k1_impl.h"

static void secp256k1_pow_step(p256_fe acc, const p256_fe base, u64 bit);

/* p = 2^256 - 2^32 - 977: low limb 2^64 - (2^32 + 0x3d1) =
 * 0xfffffffefffffc2f, the other three all ones (SEC 2 2.4.1). */
const p256_fe secp256k1_p = {0xfffffffefffffc2fULL, ~0ULL, ~0ULL, ~0ULL};

/* n = 0xffffffff ffffffff ffffffff fffffffe baaedce6 af48a03b bfd25e8c
 * d0364141 (SEC 2 2.4.1), little-endian limbs. */
const p256_fe secp256k1_n = {
    0xbfd25e8cd0364141ULL, 0xbaaedce6af48a03bULL, 0xfffffffffffffffeULL, ~0ULL};

/* (p + 1) / 4 = 2^254 - 2^30 - 244; low limb 2^64 - 2^30 - 0xf4. */
const p256_fe secp256k1_sqrt_exp = {
    0xffffffffbfffff0cULL, ~0ULL, ~0ULL, 0x3fffffffffffffffULL};

/* R = 2^256. one = R mod p = 2^32 + 977 = 0x1000003d1.
 * rr = (2^32 + 977)^2 = 2^64 + 1954 * 2^32 + 977^2 = 2^64 + 0x7a2_0000_0000
 * + 0xe90a1 (< p, already reduced). n0inv = -p^-1 mod 2^64 (only p[0]
 * matters). All three are re-checked arithmetically by the unit test. */
const mont secp256k1_mont_p = {
    .m     = {0xfffffffefffffc2fULL, ~0ULL, ~0ULL, ~0ULL},
    .rr    = {0x000007a2000e90a1ULL, 1, 0, 0},
    .one   = {0x1000003d1ULL, 0, 0, 0},
    .n0inv = 0xd838091dd2253531ULL,
};

/* SEC 2 2.4.1 generator, plain big-endian-read limbs. */
static const p256_fe secp256k1_gx = {
    0x59f2815b16f81798ULL, 0x029bfcdb2dce28d9ULL, 0x55a06295ce870b07ULL,
    0x79be667ef9dcbbacULL};
static const p256_fe secp256k1_gy = {
    0x9c47d08ffb10d4b8ULL, 0xfd17b448a6855419ULL, 0x5da4fbfc0e1108a8ULL,
    0x483ada7726a3c465ULL};

void secp256k1_fe_to_mont(p256_fe r, const p256_fe a) {
  secp256k1_fe_mul(r, a, secp256k1_mont_p.rr);
}

void secp256k1_fe_from_mont(p256_fe r, const p256_fe a) {
  static const p256_fe one = {1, 0, 0, 0};
  secp256k1_fe_mul(r, a, one);
}

static void secp256k1_pow_step(p256_fe acc, const p256_fe base, u64 bit) {
  if (bit) {
    secp256k1_fe_mul(acc, acc, base);
  }
}

/* Left-to-right square-and-multiply; branches on the exponent's bits, which
 * are public constants (p - 2, (p + 1) / 4) here. */
void secp256k1_fe_pow(p256_fe r, const p256_fe a, const p256_fe e) {
  p256_fe acc, base;
  p256_fp_set(base, a);
  p256_fp_set(acc, secp256k1_mont_p.one);
  for (usz i = 256; i-- > 0;) {
    secp256k1_fe_sqr(acc, acc);
    secp256k1_pow_step(acc, base, (e[i / 64] >> (i & 63)) & 1);
  }
  p256_fp_set(r, acc);
}

void secp256k1_base(secp256k1_pt* g) {
  secp256k1_fe_to_mont(g->x, secp256k1_gx);
  secp256k1_fe_to_mont(g->y, secp256k1_gy);
  p256_fp_set(g->z, secp256k1_mont_p.one);
}
