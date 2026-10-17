#include "crypto/pki/encoding/x509/ec_pubkey_impl.h"

static int  is_uncompressed384(wired_span key);
static int  is_compressed384(wired_span key);
static void copy48(u8 dst[48], const u8* src);
static void p384_curve_rhs(p384_fe rhs, const p384_fe x);
static void p384_sqrt(p384_fe r, const p384_fe a);
static void p384_y_from_x(p384_fe y, const p384_fe x, int want_odd);
static int  p384_on_curve(const p384_fe x, const p384_fe y);
static int  decompress_p384(wired_span key, u8 x[48], u8 y[48]);
static int  is_uncompressed521(wired_span key);

/* The 98-byte P-384 uncompressed form: 0x00 0x04 || X48 || Y48. */
static int is_uncompressed384(wired_span key) {
  if (key.n != 98) return 0;
  return key.p[0] == 0x00 && key.p[1] == 0x04;
}

/* The 50-byte P-384 compressed form: 0x00 || tag || X48. */
static int is_compressed384(wired_span key) {
  if (key.n != 50) return 0;
  return key.p[0] == 0x00 && x509_is_compress_tag(key.p[1]);
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
  fp384_sqr(x2, x, p384_p);
  fp384_mul(rhs, (fp384ab){x2, x}, p384_p);
  fp384_mul(three_x, (fp384ab){three, x}, p384_p);
  fp384_sub(rhs, (fp384ab){rhs, three_x}, p384_p);
  fp384_add(rhs, (fp384ab){rhs, ecpk_p384_b}, p384_p);
}

/* r = a^((p+1)/4) mod p: P-384's p is also 3 mod 4 (FIPS 186-4 D.1.2.4), so
 * the same Euler's-criterion argument as x509_p256_sqrt applies. Exponent
 * (p+1)/4 precomputed as 384-bit little-endian limbs below. */
static void p384_sqrt(p384_fe r, const p384_fe a) {
  static const p384_fe e = {0x0000000040000000ULL, 0xbfffffffc0000000ULL,
                            0xffffffffffffffffULL, 0xffffffffffffffffULL,
                            0xffffffffffffffffULL, 0x3fffffffffffffffULL};
  p384_fe              base;
  fp384_set(base, a);
  r[0] = 1;
  r[1] = r[2] = r[3] = r[4] = r[5] = 0;
  for (usz bit = 0; bit < 384; bit++) {
    if ((e[bit / 64] >> (bit & 63)) & 1) fp384_mul_p(r, r, base);
    fp384_sqr_p(base, base);
  }
}

static void p384_y_from_x(p384_fe y, const p384_fe x, int want_odd) {
  p384_fe rhs;
  p384_curve_rhs(rhs, x);
  p384_sqrt(y, rhs);
  if ((int)(y[0] & 1) != want_odd) fp384_sub(y, (fp384ab){p384_p, y}, p384_p);
}

static int p384_on_curve(const p384_fe x, const p384_fe y) {
  p384_fe rhs, lhs;
  p384_curve_rhs(rhs, x);
  fp384_sqr(lhs, y, p384_p);
  return fp384_eq(lhs, rhs);
}

static int decompress_p384(wired_span key, u8 x[48], u8 y[48]) {
  p384_fe xf, yf;
  int     want_odd = key.p[1] == 0x03;
  copy48(x, key.p + 2);
  fp384_from_be(xf, x);
  if (!fp384_lt(xf, p384_p)) return 0;
  p384_y_from_x(yf, xf, want_odd);
  if (!p384_on_curve(xf, yf)) return 0;
  fp384_to_be(y, yf);
  return 1;
}

int x509_ec_pubkey384(wired_span spki_key, u8 x[48], u8 y[48]) {
  if (is_uncompressed384(spki_key)) {
    copy48(x, spki_key.p + 2);
    copy48(y, spki_key.p + 50);
    return 1;
  }
  if (is_compressed384(spki_key)) return decompress_p384(spki_key, x, y);
  return 0;
}

/* The 134-byte P-521 uncompressed form: 0x00 0x04 || X66 || Y66. */
static int is_uncompressed521(wired_span key) {
  if (key.n != 134) return 0;
  return key.p[0] == 0x00 && key.p[1] == 0x04;
}

int x509_ec_pubkey521(wired_span spki_key, u8 x[66], u8 y[66]) {
  if (!is_uncompressed521(spki_key)) return 0;
  bytes_memcpy(x, spki_key.p + 2, 66);
  bytes_memcpy(y, spki_key.p + 68, 66);
  return 1;
}
