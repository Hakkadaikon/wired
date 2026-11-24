#include "crypto/asymmetric/ecc/secp256k1/secp256k1_impl.h"

static u64 secp256k1_bit(const u64* k, usz i);
static int secp256k1_sqrt(p256_fe y, const p256_fe c);

static u64 secp256k1_bit(const u64* k, usz i) {
  return (k[i / 64] >> (i & 63)) & 1;
}

/* Shamir's trick: one shared doubling chain, adding the table entry picked
 * by the bit pair (tbl[0] is infinity, which add treats as the identity).
 * Branches and indexes on the scalars: public inputs only. */
void secp256k1_mul2(
    secp256k1_pt* r, fpab k, const secp256k1_pt* p, const secp256k1_pt* q) {
  secp256k1_pt tbl[4] = {{{0}, {0}, {0}}, *p, *q, *p}, acc = tbl[0];
  secp256k1_add(&tbl[3], p, q);
  for (usz i = 256; i-- > 0;) {
    secp256k1_dbl(&acc, &acc);
    secp256k1_add(
        &acc, &acc, &tbl[secp256k1_bit(k.a, i) | secp256k1_bit(k.b, i) << 1]);
  }
  *r = acc;
}

/* y = c^((p + 1) / 4) is a square root of c iff y^2 == c (p = 3 mod 4). */
static int secp256k1_sqrt(p256_fe y, const p256_fe c) {
  p256_fe y2;
  secp256k1_fe_pow(y, c, secp256k1_sqrt_exp);
  secp256k1_fe_sqr(y2, y);
  return p256_fp_eq(y2, c);
}

/* BIP-340 lift_x: fail if x >= p; c = x^3 + 7; y = sqrt(c) or fail; pick
 * the even root. */
int secp256k1_lift_x(secp256k1_pt* r, const u8 x[32]) {
  static const p256_fe seven = {7, 0, 0, 0};
  p256_fe              xp, c, s, yp, neg, zero = {0};
  p256_fp_from_be(xp, x);
  if (!p256_fp_lt(xp, secp256k1_p)) {
    return 0;
  }
  secp256k1_fe_to_mont(r->x, xp);
  secp256k1_fe_to_mont(s, seven);
  secp256k1_fe_sqr(c, r->x);
  secp256k1_fe_mul(c, c, r->x);
  secp256k1_fe_add(c, c, s);
  if (!secp256k1_sqrt(r->y, c)) {
    return 0;
  }
  secp256k1_fe_from_mont(yp, r->y);
  secp256k1_fe_sub(neg, zero, yp);
  p256_fp_cmov(yp, neg, (int)(yp[0] & 1));
  secp256k1_fe_to_mont(r->y, yp);
  p256_fp_set(r->z, secp256k1_mont_p.one);
  return 1;
}

/* x = X / Z^2, y = Y / Z^3 with Z^-1 = Z^(p - 2) (Fermat). */
int secp256k1_affine(u8 x[32], int* y_odd, const secp256k1_pt* a) {
  static const p256_fe two = {2, 0, 0, 0};
  p256_fe              e, zi, zi2, t;
  if (p256_fp_is_zero(a->z)) {
    return 0;
  }
  p256_fp_sub(e, (fpab){secp256k1_p, two}, secp256k1_p);
  secp256k1_fe_pow(zi, a->z, e);
  secp256k1_fe_sqr(zi2, zi);
  secp256k1_fe_mul(t, a->x, zi2);
  secp256k1_fe_from_mont(t, t);
  p256_fp_to_be(x, t);
  secp256k1_fe_mul(t, a->y, zi2);
  secp256k1_fe_mul(t, t, zi);
  secp256k1_fe_from_mont(t, t);
  *y_odd = (int)(t[0] & 1);
  return 1;
}
