#include "crypto/pki/encoding/x509/ec_pubkey.h"

#include "crypto/asymmetric/ecc/p256/p256_field.h"
#include "crypto/asymmetric/ecc/p384/p384_field.h"

/* SEC1 2.3.3. The BIT STRING value is 0x00 (unused bits) then the 65-byte
 * uncompressed point 0x04 || X || Y. */
static int is_uncompressed(wired_span key) {
  if (key.n != 66) return 0;
  return key.p[0] == 0x00 && key.p[1] == 0x04;
}

/* SEC1 2.3.3. 1 if tag is a compressed-point selector (0x02 even Y, 0x03
 * odd Y). */
static int is_compress_tag(u8 tag) { return tag == 0x02 || tag == 0x03; }

/* SEC1 2.3.3. The 34-byte compressed form: 0x00 unused-bits then 0x02 || X
 * or 0x03 || X, the tag selecting the parity of the recovered Y. */
static int is_compressed(wired_span key) {
  if (key.n != 34) return 0;
  return key.p[0] == 0x00 && is_compress_tag(key.p[1]);
}

static void copy32(u8 dst[32], const u8* src) {
  for (usz i = 0; i < 32; i++) dst[i] = src[i];
}

/* FIPS 186-4 D.1.2.3 P-256 curve parameter b (a = -3). Duplicated from
 * p256_point.c (there `static`, no public accessor) since decompression
 * needs only the curve equation, not the point-arithmetic API. */
static const p256_fe ecpk_p256_b = {
    0x3bce3c3e27d2604bULL, 0x651d06b0cc53b0f6ULL, 0xb3ebbd55769886bcULL,
    0x5ac635d8aa3a93e7ULL};

/* rhs = x^3 - 3x + b mod p (the P-256 curve equation's right-hand side). */
static void p256_curve_rhs(p256_fe rhs, const p256_fe x) {
  p256_fe x2, three_x, three = {3, 0, 0, 0};
  quic_fp_sqr_p(x2, x);
  quic_fp_mul_p(rhs, x2, x);
  quic_fp_mul_p(three_x, three, x);
  quic_fp_sub(rhs, (quic_fpab){rhs, three_x}, quic_p256_p);
  quic_fp_add(rhs, (quic_fpab){rhs, ecpk_p256_b}, quic_p256_p);
}

/* r = a^((p+1)/4) mod p, the modular square root: valid because P-256's p is
 * 3 mod 4 (FIPS 186-4 D.1.2.3), so for a quadratic residue a,
 * (a^((p+1)/4))^2 = a^((p+1)/2) = a * a^((p-1)/2) = a (Euler's criterion).
 * Exponent precomputed as (p+1)/4 = 0x3fffffffc0000000400000000000000000
 * 000000400000000000000000000000 (256-bit little-endian limbs below);
 * square-and-multiply mirrors quic_fp_inv_p's shape. */
static void p256_sqrt(p256_fe r, const p256_fe a) {
  static const p256_fe e = {
      0x0000000000000000ULL, 0x0000000040000000ULL, 0x4000000000000000ULL,
      0x3fffffffc0000000ULL};
  p256_fe base;
  quic_fp_set(base, a);
  r[0] = 1;
  r[1] = r[2] = r[3] = 0;
  for (usz bit = 0; bit < 256; bit++) {
    if ((e[bit / 64] >> (bit & 63)) & 1) quic_fp_mul_p(r, r, base);
    quic_fp_sqr_p(base, base);
  }
}

/* Recover Y from X and the compressed tag's parity bit (SEC1 2.3.4): compute
 * a candidate square root, then negate mod p if its parity doesn't match.
 * Returns 1 ok, 0 if x is not on the curve (rhs is not a quadratic residue,
 * caught by the caller's on-curve check). */
static void p256_y_from_x(p256_fe y, const p256_fe x, int want_odd) {
  p256_fe rhs;
  p256_curve_rhs(rhs, x);
  p256_sqrt(y, rhs);
  if ((int)(y[0] & 1) != want_odd)
    quic_fp_sub(y, (quic_fpab){quic_p256_p, y}, quic_p256_p);
}

/* y^2 == x^3 - 3x + b mod p: confirms the recovered point is genuinely on
 * the curve (rejects an x for which rhs has no square root). */
static int p256_on_curve(const p256_fe x, const p256_fe y) {
  p256_fe rhs, lhs;
  p256_curve_rhs(rhs, x);
  quic_fp_sqr_p(lhs, y);
  return quic_fp_eq(lhs, rhs);
}

/* SEC1 2.3.4 / RFC 5480 2.2. Decompress a 34-byte compressed BIT STRING
 * value (0x00 || tag || X) into (x, y). Returns 1 ok, 0 if X is out of
 * range or not on the curve. */
static int decompress_p256(wired_span key, u8 x[32], u8 y[32]) {
  p256_fe xf, yf;
  int     want_odd = key.p[1] == 0x03;
  copy32(x, key.p + 2);
  quic_fp_from_be(xf, x);
  if (!quic_fp_lt(xf, quic_p256_p)) return 0;
  p256_y_from_x(yf, xf, want_odd);
  if (!p256_on_curve(xf, yf)) return 0;
  quic_fp_to_be(y, yf);
  return 1;
}

int quic_x509_ec_pubkey(wired_span spki_key, u8 x[32], u8 y[32]) {
  if (is_uncompressed(spki_key)) {
    copy32(x, spki_key.p + 2);
    copy32(y, spki_key.p + 34);
    return 1;
  }
  if (is_compressed(spki_key)) return decompress_p256(spki_key, x, y);
  return 0;
}

/* The 98-byte P-384 uncompressed form: 0x00 0x04 || X48 || Y48. */
static int is_uncompressed384(wired_span key) {
  if (key.n != 98) return 0;
  return key.p[0] == 0x00 && key.p[1] == 0x04;
}

/* The 50-byte P-384 compressed form: 0x00 || tag || X48. */
static int is_compressed384(wired_span key) {
  if (key.n != 50) return 0;
  return key.p[0] == 0x00 && is_compress_tag(key.p[1]);
}

static void copy48(u8 dst[48], const u8* src) {
  for (usz i = 0; i < 48; i++) dst[i] = src[i];
}

/* FIPS 186-4 D.1.2.4 P-384 curve parameter b (a = -3). Duplicated from
 * p384_point.c for the same reason as ecpk_p256_b above. */
static const p384_fe ecpk_p384_b = {
    0x2a85c8edd3ec2aefULL, 0xc656398d8a2ed19dULL, 0x0314088f5013875aULL,
    0x181d9c6efe814112ULL, 0x988e056be3f82d19ULL, 0xb3312fa7e23ee7e4ULL};

/* rhs = x^3 - 3x + b mod p (the P-384 curve equation's right-hand side). */
static void p384_curve_rhs(p384_fe rhs, const p384_fe x) {
  p384_fe x2, three_x, three = {3, 0, 0, 0, 0, 0};
  quic_fp384_sqr(x2, x, quic_p384_p);
  quic_fp384_mul(rhs, (quic_fp384ab){x2, x}, quic_p384_p);
  quic_fp384_mul(three_x, (quic_fp384ab){three, x}, quic_p384_p);
  quic_fp384_sub(rhs, (quic_fp384ab){rhs, three_x}, quic_p384_p);
  quic_fp384_add(rhs, (quic_fp384ab){rhs, ecpk_p384_b}, quic_p384_p);
}

/* r = a^((p+1)/4) mod p: P-384's p is also 3 mod 4 (FIPS 186-4 D.1.2.4), so
 * the same Euler's-criterion argument as p256_sqrt applies. Exponent
 * (p+1)/4 precomputed as 384-bit little-endian limbs below. */
static void p384_sqrt(p384_fe r, const p384_fe a) {
  static const p384_fe e = {0x0000000040000000ULL, 0xbfffffffc0000000ULL,
                            0xffffffffffffffffULL, 0xffffffffffffffffULL,
                            0xffffffffffffffffULL, 0x3fffffffffffffffULL};
  p384_fe              base;
  quic_fp384_set(base, a);
  r[0] = 1;
  r[1] = r[2] = r[3] = r[4] = r[5] = 0;
  for (usz bit = 0; bit < 384; bit++) {
    if ((e[bit / 64] >> (bit & 63)) & 1) quic_fp384_mul_p(r, r, base);
    quic_fp384_sqr_p(base, base);
  }
}

static void p384_y_from_x(p384_fe y, const p384_fe x, int want_odd) {
  p384_fe rhs;
  p384_curve_rhs(rhs, x);
  p384_sqrt(y, rhs);
  if ((int)(y[0] & 1) != want_odd)
    quic_fp384_sub(y, (quic_fp384ab){quic_p384_p, y}, quic_p384_p);
}

static int p384_on_curve(const p384_fe x, const p384_fe y) {
  p384_fe rhs, lhs;
  p384_curve_rhs(rhs, x);
  quic_fp384_sqr(lhs, y, quic_p384_p);
  return quic_fp384_eq(lhs, rhs);
}

static int decompress_p384(wired_span key, u8 x[48], u8 y[48]) {
  p384_fe xf, yf;
  int     want_odd = key.p[1] == 0x03;
  copy48(x, key.p + 2);
  quic_fp384_from_be(xf, x);
  if (!quic_fp384_lt(xf, quic_p384_p)) return 0;
  p384_y_from_x(yf, xf, want_odd);
  if (!p384_on_curve(xf, yf)) return 0;
  quic_fp384_to_be(y, yf);
  return 1;
}

int quic_x509_ec_pubkey384(wired_span spki_key, u8 x[48], u8 y[48]) {
  if (is_uncompressed384(spki_key)) {
    copy48(x, spki_key.p + 2);
    copy48(y, spki_key.p + 50);
    return 1;
  }
  if (is_compressed384(spki_key)) return decompress_p384(spki_key, x, y);
  return 0;
}
