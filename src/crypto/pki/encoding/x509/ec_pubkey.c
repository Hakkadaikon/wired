#include "crypto/pki/encoding/x509/ec_pubkey_impl.h"

static int  is_uncompressed(wired_span key);
static int  is_compressed(wired_span key);
static void copy32(u8 dst[32], const u8* src);
static void p256_curve_rhs(p256_fe rhs, const p256_fe x);
static void p256_y_from_x(p256_fe y, const p256_fe x, int want_odd);
static int  p256_on_curve(const p256_fe x, const p256_fe y);
static int  decompress_p256(wired_span key, u8 x[32], u8 y[32]);

/* SEC1 2.3.3. The BIT STRING value is 0x00 (unused bits) then the 65-byte
 * uncompressed point 0x04 || X || Y. */
static int is_uncompressed(wired_span key) {
  if (key.n != 66) {
    return 0;
  }
  return key.p[0] == 0x00 && key.p[1] == 0x04;
}

/* SEC1 2.3.3. 1 if tag is a compressed-point selector (0x02 even Y, 0x03
 * odd Y). */
int x509_is_compress_tag(u8 tag) { return tag == 0x02 || tag == 0x03; }

/* SEC1 2.3.3. The 34-byte compressed form: 0x00 unused-bits then 0x02 || X
 * or 0x03 || X, the tag selecting the parity of the recovered Y. */
static int is_compressed(wired_span key) {
  if (key.n != 34) {
    return 0;
  }
  return key.p[0] == 0x00 && x509_is_compress_tag(key.p[1]);
}

static void copy32(u8 dst[32], const u8* src) {
  for (usz i = 0; i < 32; i++) {
    dst[i] = src[i];
  }
}

/* FIPS 186-4 D.1.2.3 P-256 curve parameter b (a = -3). Duplicated from
 * p256_point.c (there `static`, no public accessor) since decompression
 * needs only the curve equation, not the point-arithmetic API. */
const p256_fe ecpk_p256_b = {
    0x3bce3c3e27d2604bULL, 0x651d06b0cc53b0f6ULL, 0xb3ebbd55769886bcULL,
    0x5ac635d8aa3a93e7ULL};

/* rhs = x^3 - 3x + b mod p (the P-256 curve equation's right-hand side). */
static void p256_curve_rhs(p256_fe rhs, const p256_fe x) {
  p256_fe x2, three_x, three = {3, 0, 0, 0};
  p256_fp_sqr_p(x2, x);
  p256_fp_mul_p(rhs, x2, x);
  p256_fp_mul_p(three_x, three, x);
  p256_fp_sub(rhs, (fpab){rhs, three_x}, p256_p);
  p256_fp_add(rhs, (fpab){rhs, ecpk_p256_b}, p256_p);
}

/* r = a^((p+1)/4) mod p, the modular square root: valid because P-256's p is
 * 3 mod 4 (FIPS 186-4 D.1.2.3), so for a quadratic residue a,
 * (a^((p+1)/4))^2 = a^((p+1)/2) = a * a^((p-1)/2) = a (Euler's criterion).
 * Exponent precomputed as (p+1)/4 = 0x3fffffffc0000000400000000000000000
 * 000000400000000000000000000000 (256-bit little-endian limbs below);
 * square-and-multiply mirrors p256_fp_inv_p's shape. */
void x509_p256_sqrt(p256_fe r, const p256_fe a) {
  static const p256_fe e = {
      0x0000000000000000ULL, 0x0000000040000000ULL, 0x4000000000000000ULL,
      0x3fffffffc0000000ULL};
  p256_fe base;
  p256_fp_set(base, a);
  r[0] = 1;
  r[1] = r[2] = r[3] = 0;
  for (usz bit = 0; bit < 256; bit++) {
    if ((e[bit / 64] >> (bit & 63)) & 1) {
      p256_fp_mul_p(r, r, base);
    }
    p256_fp_sqr_p(base, base);
  }
}

/* Recover Y from X and the compressed tag's parity bit (SEC1 2.3.4): compute
 * a candidate square root, then negate mod p if its parity doesn't match.
 * Returns 1 ok, 0 if x is not on the curve (rhs is not a quadratic residue,
 * caught by the caller's on-curve check). */
static void p256_y_from_x(p256_fe y, const p256_fe x, int want_odd) {
  p256_fe rhs;
  p256_curve_rhs(rhs, x);
  x509_p256_sqrt(y, rhs);
  if ((int)(y[0] & 1) != want_odd) {
    p256_fp_sub(y, (fpab){p256_p, y}, p256_p);
  }
}

/* y^2 == x^3 - 3x + b mod p: confirms the recovered point is genuinely on
 * the curve (rejects an x for which rhs has no square root). */
static int p256_on_curve(const p256_fe x, const p256_fe y) {
  p256_fe rhs, lhs;
  p256_curve_rhs(rhs, x);
  p256_fp_sqr_p(lhs, y);
  return p256_fp_eq(lhs, rhs);
}

/* SEC1 2.3.4 / RFC 5480 2.2. Decompress a 34-byte compressed BIT STRING
 * value (0x00 || tag || X) into (x, y). Returns 1 ok, 0 if X is out of
 * range or not on the curve. */
static int decompress_p256(wired_span key, u8 x[32], u8 y[32]) {
  p256_fe xf, yf;
  int     want_odd = key.p[1] == 0x03;
  copy32(x, key.p + 2);
  p256_fp_from_be(xf, x);
  if (!p256_fp_lt(xf, p256_p)) {
    return 0;
  }
  p256_y_from_x(yf, xf, want_odd);
  if (!p256_on_curve(xf, yf)) {
    return 0;
  }
  p256_fp_to_be(y, yf);
  return 1;
}

int x509_ec_pubkey(wired_span spki_key, u8 x[32], u8 y[32]) {
  if (is_uncompressed(spki_key)) {
    copy32(x, spki_key.p + 2);
    copy32(y, spki_key.p + 34);
    return 1;
  }
  if (is_compressed(spki_key)) {
    return decompress_p256(spki_key, x, y);
  }
  return 0;
}
