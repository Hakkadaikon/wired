#include "crypto/asymmetric/ecc/p256/p256_field_impl.h"

static void mont_from(p256_fe r, const p256_fe a, const mont* mont);
static void mont_sqr4(p256_fe acc, const mont* mont);
static void mont_inv_table(p256_fe tbl[16], const p256_fe a, const mont* mont);
static void fp_sqr_k(p256_fe r, usz k);
static void fp_ones_double(p256_fe t, usz k);

/* from Montgomery form: r = a * R^-1 mod m = mont_mul(a, 1). */
static void mont_from(p256_fe r, const p256_fe a, const mont* mont) {
  p256_fe one = {1, 0, 0, 0};
  mont_mul(r, (fpab){a, one}, mont);
}

/* acc <- acc^16 (4 in-place Montgomery squarings, one window's worth). */
static void mont_sqr4(p256_fe acc, const mont* mont) {
  for (usz i = 0; i < 4; i++) {
    mont_mul(acc, (fpab){acc, acc}, mont);
  }
}

/* tbl[i] = a^i in Montgomery form (tbl[0] = R, the Montgomery one), the
 * 4-bit-window multiplier table. */
static void mont_inv_table(p256_fe tbl[16], const p256_fe a, const mont* mont) {
  p256_fp_set(tbl[0], mont->one);
  mont_mul(tbl[1], (fpab){a, mont->rr}, mont); /* to Montgomery */
  for (usz i = 2; i < 16; i++) {
    mont_mul(tbl[i], (fpab){tbl[i - 1], tbl[1]}, mont);
  }
}

/* a^(m-2) mod m via Montgomery mul (Fermat inverse), 4-bit windows over the
 * exponent: 64 window multiplies + 15 table builds instead of the bit loop's
 * one multiply per set exponent bit (~166 for m = n). The window index
 * depends only on the public modulus, never on a, and the multiply is
 * unconditional (tbl[0] is the Montgomery one), so the operation sequence
 * stays input-independent. */
void mont_inv(p256_fe r, const p256_fe a, const mont* mont) {
  p256_fe e, acc, tbl[16], two = {2, 0, 0, 0};
  p256_fe_sub_raw(e, mont->m, two); /* exponent m-2 */
  mont_inv_table(tbl, a, mont);
  p256_fp_set(acc, mont->one); /* acc = R mod m (Montgomery one) */
  for (usz w = 64; w-- > 0;) {
    mont_sqr4(acc, mont);
    mont_mul(acc, (fpab){acc, tbl[(e[w / 16] >> ((w & 15) * 4)) & 15]}, mont);
  }
  mont_from(r, acc, mont); /* back from Montgomery form */
}

/* r <- r^(2^k): k in-place Solinas squarings. */
static void fp_sqr_k(p256_fe r, usz k) {
  for (usz i = 0; i < k; i++) {
    p256_fp_sqr_p(r, r);
  }
}

/* t == a^(2^k - 1) -> t = a^(2^(2k) - 1): the all-ones doubling step of the
 * Fermat ladder (k squarings then one multiply by the saved half). */
static void fp_ones_double(p256_fe t, usz k) {
  p256_fe half;
  p256_fp_set(half, t);
  fp_sqr_k(t, k);
  p256_fp_mul_p(t, t, half);
}

/* a^(p-2) mod p via the fast Solinas mul/sqr: Fermat inverse specialised to
 * p. Called once per scalar multiply (jac_to_affine). Fixed addition chain
 * -- 255 squarings + 13 multiplies instead of the bit loop's 256 + 128 --
 * assembling p-2's bit pattern (1^32, 0^31 1, 0^96, 1^94 01) from the
 * 2^k - 1 ladder t2..t32. The chain is a constant sequence (p-2 is public),
 * so the operations never depend on a. */
void p256_fp_inv_p(p256_fe r, const p256_fe a) {
  p256_fe t2, t4, t8, t16, t32;
  p256_fp_set(t2, a);
  fp_ones_double(t2, 1); /* a^(2^2 - 1) */
  p256_fp_set(t4, t2);
  fp_ones_double(t4, 2); /* a^(2^4 - 1) */
  p256_fp_set(t8, t4);
  fp_ones_double(t8, 4); /* a^(2^8 - 1) */
  p256_fp_set(t16, t8);
  fp_ones_double(t16, 8); /* a^(2^16 - 1) */
  p256_fp_set(t32, t16);
  fp_ones_double(t32, 16); /* a^(2^32 - 1) */
  p256_fp_set(r, t32);
  fp_sqr_k(r, 32);
  p256_fp_mul_p(r, r, a); /* top 64 bits: 1^32 0^31 1 */
  fp_sqr_k(r, 128);
  p256_fp_mul_p(r, r, t32); /* 0^96 then 1^32 */
  fp_sqr_k(r, 32);
  p256_fp_mul_p(r, r, t32);
  fp_sqr_k(r, 16);
  p256_fp_mul_p(r, r, t16);
  fp_sqr_k(r, 8);
  p256_fp_mul_p(r, r, t8);
  fp_sqr_k(r, 4);
  p256_fp_mul_p(r, r, t4);
  fp_sqr_k(r, 2);
  p256_fp_mul_p(r, r, t2); /* low half: 1^94 so far */
  fp_sqr_k(r, 2);
  p256_fp_mul_p(r, r, a); /* trailing bits 01 */
}
