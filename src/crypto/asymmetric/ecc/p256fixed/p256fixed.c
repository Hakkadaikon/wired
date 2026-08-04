#include "crypto/asymmetric/ecc/p256fixed/p256fixed.h"

/* Windowed fixed-base k*G (see p256fixed.h). Accumulates in Jacobian
 * coordinates (x = X/Z^2, y = Y/Z^3, Z == 0 is infinity) so the loop needs
 * no inversion; field ops are the fast Solinas ones from p256_field.h.
 *
 * The mixed addition below deliberately omits the doubling / inverse-pair
 * special cases: after window i the accumulator is (k mod 16^i) * G with
 * k mod 16^i < 16^i, while the table point is d * 16^i * G with
 * 16^i <= d * 16^i <= 15 * 16^63 < n, so the two scalars can only be
 * congruent mod n when their sum is exactly n (k == n): that is the
 * inverse-pair case, and the formula then yields Z3 = 0 == infinity, which
 * is the correct result. The doubling case (difference == n) is impossible
 * because both scalars are < n. */

/* All-ones iff z == 0 (constant-time). */
static u64 p256fixed_zmask(u64 z) { return ((z | (0 - z)) >> 63) - 1; }

/* r <- a when mask is all-ones, unchanged when 0 (constant-time). */
static void p256fixed_cmov(p256_fe r, const u64* a, u64 mask) {
  for (usz i = 0; i < 4; i++) r[i] ^= mask & (r[i] ^ a[i]);
}

/* r = (a - b) mod p. */
static void p256fixed_sub(p256_fe r, const p256_fe a, const p256_fe b) {
  quic_fp_sub(r, (quic_fpab){a, b}, quic_p256_p);
}

typedef struct {
  p256_fe jx, jy, jz;
} p256fixed_pt;

static void p256fixed_pt_cmov(
    p256fixed_pt* r, const p256fixed_pt* a, u64 mask) {
  p256fixed_cmov(r->jx, a->jx, mask);
  p256fixed_cmov(r->jy, a->jy, mask);
  p256fixed_cmov(r->jz, a->jz, mask);
}

/* (x, y) <- table digit d of window row (1..15); (0, 0) for d == 0. Scans
 * every entry with a masked select so the access pattern is d-oblivious. */
static void p256fixed_select(p256_fe x, p256_fe y, const u64* row, u64 d) {
  for (usz i = 0; i < 4; i++) x[i] = y[i] = 0;
  for (u64 j = 0; j < 15; j++) {
    u64 m = p256fixed_zmask(d ^ (j + 1)); /* all-ones iff d == j + 1 */
    p256fixed_cmov(x, row + j * 8, m);
    p256fixed_cmov(y, row + j * 8 + 4, m);
  }
}

/* out = a + (x2, y2): Jacobian + affine mixed addition (a finite; the
 * exceptional cases cannot occur here, see the file comment). */
static void p256fixed_madd(
    p256fixed_pt*       out,
    const p256fixed_pt* a,
    const p256_fe       x2,
    const p256_fe       y2) {
  p256_fe z1z1, u2, s2, h, rr, hh, v, t;
  quic_fp_sqr_p(z1z1, a->jz);
  quic_fp_mul_p(u2, x2, z1z1);
  quic_fp_mul_p(s2, y2, a->jz);
  quic_fp_mul_p(s2, s2, z1z1);
  p256fixed_sub(h, u2, a->jx);  /* H = U2 - X1 */
  p256fixed_sub(rr, s2, a->jy); /* R = S2 - Y1 */
  quic_fp_sqr_p(hh, h);
  quic_fp_mul_p(v, a->jx, hh); /* V = X1 * H^2 */
  quic_fp_mul_p(hh, hh, h);    /* now H^3 */
  quic_fp_sqr_p(t, rr);
  p256fixed_sub(t, t, hh);
  p256fixed_sub(t, t, v);
  p256fixed_sub(out->jx, t, v); /* X3 = R^2 - H^3 - 2V */
  p256fixed_sub(t, v, out->jx);
  quic_fp_mul_p(t, rr, t);
  quic_fp_mul_p(v, a->jy, hh);
  p256fixed_sub(out->jy, t, v); /* Y3 = R(V - X3) - Y1*H^3 */
  quic_fp_mul_p(out->jz, a->jz, h);
}

/* Nibble i of the scalar (i == 0 is least significant). */
static u64 p256fixed_digit(const u8 s[32], usz i) {
  return (u64)((s[31 - i / 2] >> (4 * (i & 1))) & 15);
}

/* acc += d * 16^i * G for window row i, constant-time: the add is always
 * computed; masked moves pick the right result for acc == infinity (start)
 * and d == 0 (window contributes nothing). */
static void p256fixed_step(p256fixed_pt* acc, const u64* row, u64 d) {
  p256fixed_pt nxt, tp;
  u64 ainf = p256fixed_zmask(acc->jz[0] | acc->jz[1] | acc->jz[2] | acc->jz[3]);
  p256fixed_select(tp.jx, tp.jy, row, d);
  tp.jz[0] = 1;
  tp.jz[1] = tp.jz[2] = tp.jz[3] = 0;
  p256fixed_madd(&nxt, acc, tp.jx, tp.jy);
  p256fixed_pt_cmov(&nxt, &tp, ainf);               /* inf + P = P */
  p256fixed_pt_cmov(&nxt, acc, p256fixed_zmask(d)); /* d == 0: keep acc */
  *acc = nxt;
}

/* Jacobian -> affine; 0 if the point is infinity. */
static int p256fixed_to_affine(p256_fe x, p256_fe y, const p256fixed_pt* j) {
  p256_fe zi, zi2;
  if (quic_fp_is_zero(j->jz)) return 0;
  quic_fp_inv_p(zi, j->jz);
  quic_fp_sqr_p(zi2, zi);
  quic_fp_mul_p(x, j->jx, zi2);
  quic_fp_mul_p(zi2, zi2, zi);
  quic_fp_mul_p(y, j->jy, zi2);
  return 1;
}

int quic_p256fixed_mul_g(p256_fe out_x, p256_fe out_y, const u8 scalar[32]) {
  p256fixed_pt acc = {{0}, {0}, {0}}; /* infinity */
  for (usz i = 0; i < 64; i++)
    p256fixed_step(&acc, quic_p256fixed_table[i], p256fixed_digit(scalar, i));
  return p256fixed_to_affine(out_x, out_y, &acc);
}
