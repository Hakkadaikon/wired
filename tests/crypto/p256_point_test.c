#include "crypto/asymmetric/ecc/p256/p256_point.h"

#include "crypto/asymmetric/ecc/p256sign/rfc6979.h"
#include "crypto/symmetric/hash/hash/sha256.h"
#include "test.h"

/* G lies on the curve. */
static void test_p256_g_on_curve(void) {
  CHECK(quic_ec_on_curve(&quic_p256_g));
}

/* 2G via double equals G + G via add, and is on the curve. */
static void test_p256_double_eq_add(void) {
  ec_point d, s;
  quic_ec_double(&d, &quic_p256_g);
  quic_ec_add(&s, &quic_p256_g, &quic_p256_g);
  CHECK(!d.inf && !s.inf);
  CHECK(quic_fp_eq(d.x, s.x));
  CHECK(quic_fp_eq(d.y, s.y));
  CHECK(quic_ec_on_curve(&d));
}

/* (n)*G is the point at infinity; also 1*G == G. */
static void test_p256_scalar(void) {
  ec_point one_g, kg;
  u8       k1[32] = {0};
  k1[31]          = 1;
  u8 nbytes[32];
  quic_fp_to_be(nbytes, quic_p256_n);
  quic_ec_mul(&one_g, k1, &quic_p256_g);
  CHECK(!one_g.inf && quic_fp_eq(one_g.x, quic_p256_g.x));
  quic_ec_mul(&kg, nbytes, &quic_p256_g);
  CHECK(kg.inf);
}

/* quic_ec_mul is a point on the curve for boundary and random scalars: the
 * Montgomery-ladder constant-time implementation (RFC 6090-style two-
 * accumulator ladder, see p256_point.c) must still produce a valid curve
 * point (or infinity, only for k==0). */
static void mul_on_curve(const u8 k[32]) {
  ec_point p;
  quic_ec_mul(&p, k, &quic_p256_g);
  CHECK(p.inf || quic_ec_on_curve(&p));
}

static void test_p256_mul_ct_boundary(void) {
  u8       k0[32] = {0}, k1[32] = {0}, nm1[32];
  p256_fe  one = {1, 0, 0, 0}, nm1v;
  ec_point zero_g;
  k1[31] = 1;
  quic_fp_sub(nm1v, (quic_fpab){quic_p256_n, one}, quic_p256_n);
  quic_fp_to_be(nm1, nm1v);
  quic_ec_mul(&zero_g, k0, &quic_p256_g);
  CHECK(zero_g.inf); /* 0*G is the point at infinity */
  mul_on_curve(k1);
  mul_on_curve(nm1);
}

/* xorshift32, seeded fixed: deterministic "random" 100-case sweep. */
static u32 ct_xorshift(u32* s) {
  *s ^= *s << 13;
  *s ^= *s >> 17;
  *s ^= *s << 5;
  return *s;
}

static void test_p256_mul_ct_random(void) {
  u32 s = 0xC0FFEE01u;
  for (int i = 0; i < 100; i++) {
    u8 k[32];
    for (usz j = 0; j < 32; j += 4) {
      u32 w    = ct_xorshift(&s);
      k[j]     = (u8)(w >> 24);
      k[j + 1] = (u8)(w >> 16);
      k[j + 2] = (u8)(w >> 8);
      k[j + 3] = (u8)w;
    }
    mul_on_curve(k);
  }
}

/* RFC 6979 Appendix A.2.5 "sample": k*G .x mod n must equal the known r.
 * k itself is derived via the already-vector-checked quic_p256sign_k
 * (see p256sign_test.c test_p256sign_known_vector) rather than pasting an
 * external k hex, so no unverified constant enters this test. */
static void p256pt_hb32(const char* hex, u8 out[32]) {
  for (usz i = 0; i < 32; i++) {
    u8 hi = (u8)hex[i * 2], lo = (u8)hex[i * 2 + 1];
    out[i] = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                  (lo <= '9' ? lo - '0' : lo - 'a' + 10));
  }
}

static void test_p256_mul_ct_rfc6979_vector(void) {
  static const char* priv_hex =
      "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
  static const char* wr_hex =
      "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716";
  u8       priv[32], hash[32], kb[32], wr[32], rb[32];
  ec_point rp;
  p256_fe  r;
  p256pt_hb32(priv_hex, priv);
  p256pt_hb32(wr_hex, wr);
  quic_sha256((const u8*)"sample", 6, hash);
  quic_p256sign_k(priv, hash, kb);
  quic_ec_mul(&rp, kb, &quic_p256_g);
  quic_fp_reduce(r, rp.x, quic_p256_n);
  quic_fp_to_be(rb, r);
  for (usz i = 0; i < 32; i++) CHECK(rb[i] == wr[i]);
}

/* RFC 6090 group law: O + P == P and P + O == P for the point at infinity O
 * (the group identity), on both operand sides of quic_ec_add. */
static void test_p256_add_infinity_identity(void) {
  ec_point o = {{0}, {0}, 1}; /* the point at infinity */
  ec_point r1, r2;
  quic_ec_add(&r1, &o, &quic_p256_g); /* O + G */
  CHECK(!r1.inf);
  CHECK(quic_fp_eq(r1.x, quic_p256_g.x));
  CHECK(quic_fp_eq(r1.y, quic_p256_g.y));
  quic_ec_add(&r2, &quic_p256_g, &o); /* G + O */
  CHECK(!r2.inf);
  CHECK(quic_fp_eq(r2.x, quic_p256_g.x));
  CHECK(quic_fp_eq(r2.y, quic_p256_g.y));
}

/* O + O == O: both operands infinity stays infinity. */
static void test_p256_add_infinity_both(void) {
  ec_point o = {{0}, {0}, 1};
  ec_point r;
  quic_ec_add(&r, &o, &o);
  CHECK(r.inf);
}

void test_p256_point(void) {
  test_p256_g_on_curve();
  test_p256_double_eq_add();
  test_p256_scalar();
  test_p256_mul_ct_boundary();
  test_p256_mul_ct_random();
  test_p256_mul_ct_rfc6979_vector();
  test_p256_add_infinity_identity();
  test_p256_add_infinity_both();
}
