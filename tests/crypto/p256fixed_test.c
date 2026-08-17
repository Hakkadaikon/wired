#include "crypto/asymmetric/ecc/p256fixed/p256fixed.h"

#include "crypto/asymmetric/ecc/p256/p256_point.h"
#include "crypto/asymmetric/ecc/p256sign/rfc6979.h"
#include "crypto/symmetric/hash/hash/sha256.h"
#include "test.h"

/* Fixed-base result must equal the generic ladder's for the same scalar
 * (including both reporting infinity the same way). */
static void pf_check_eq_generic(const u8 k[32]) {
  ec_point g;
  p256_fe  x, y;
  int      fin = quic_p256fixed_mul_g(x, y, k);
  quic_ec_mul(&g, k, &quic_p256_g);
  CHECK(fin == !g.inf);
  if (!fin) return;
  CHECK(quic_fp_eq(x, g.x));
  CHECK(quic_fp_eq(y, g.y));
}

/* 1*G is the base point itself (FIPS 186-4 D.1.2.3 coordinates, as encoded
 * in quic_p256_g in p256_point.c). */
static void test_p256fixed_one_is_g(void) {
  u8      k[32] = {0};
  p256_fe x, y;
  k[31] = 1;
  CHECK(quic_p256fixed_mul_g(x, y, k));
  CHECK(quic_fp_eq(x, quic_p256_g.x));
  CHECK(quic_fp_eq(y, quic_p256_g.y));
}

/* Boundary scalars: 0 and n map to infinity (return 0); 1, 2, n-1 match the
 * generic path. */
static void test_p256fixed_boundary(void) {
  u8      k0[32] = {0}, k1[32] = {0}, k2[32] = {0}, nb[32], nm1[32];
  p256_fe x, y, one                          = {1, 0, 0, 0}, nm1v;
  k1[31] = 1;
  k2[31] = 2;
  quic_fp_to_be(nb, quic_p256_n);
  quic_fp_sub(nm1v, (quic_fpab){quic_p256_n, one}, quic_p256_n);
  quic_fp_to_be(nm1, nm1v);
  CHECK(!quic_p256fixed_mul_g(x, y, k0));
  CHECK(!quic_p256fixed_mul_g(x, y, nb));
  pf_check_eq_generic(k1);
  pf_check_eq_generic(k2);
  pf_check_eq_generic(nm1);
}

/* Scalars with all-zero and all-one 4-bit windows, and single set windows at
 * both ends: the d == 0 masked skip and every window position get hit. */
static void test_p256fixed_window_patterns(void) {
  u8 k[32];
  for (usz i = 0; i < 32; i++) k[i] = 0x11; /* every window d == 1 */
  pf_check_eq_generic(k);
  for (usz i = 0; i < 32; i++) k[i] = 0xff; /* every window d == 15 */
  pf_check_eq_generic(k);
  for (usz i = 0; i < 32; i++) k[i] = (i < 16) ? 0 : 0xf0; /* gappy */
  pf_check_eq_generic(k);
  for (usz i = 0; i < 32; i++) k[i] = 0;
  k[0] = 0x10; /* only the top window set */
  pf_check_eq_generic(k);
}

/* Deterministic LCG sweep: 64 pseudo-random scalars, fixed-base vs generic
 * differential. */
static void test_p256fixed_differential(void) {
  u64 s = 0x9E3779B97F4A7C15ULL;
  for (int c = 0; c < 64; c++) {
    u8 k[32];
    for (usz j = 0; j < 32; j++) {
      s    = s * 6364136223846793005ULL + 1442695040888963407ULL;
      k[j] = (u8)(s >> 56);
    }
    pf_check_eq_generic(k);
  }
}

/* RFC 6979 Appendix A.2.5 "sample": (k*G).x mod n equals the vector's r,
 * with k derived by the repo's own vector-checked quic_p256sign_k (same
 * scheme as tests/crypto/p256_point_test.c, no new external constants). */
static void pf_hb32(const char* hex, u8 out[32]) {
  for (usz i = 0; i < 32; i++) {
    u8 hi = (u8)hex[i * 2], lo = (u8)hex[i * 2 + 1];
    out[i] = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                  (lo <= '9' ? lo - '0' : lo - 'a' + 10));
  }
}

static void test_p256fixed_rfc6979_vector(void) {
  static const char* priv_hex =
      "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
  static const char* wr_hex =
      "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716";
  u8      priv[32], hash[32], kb[32], wr[32], rb[32];
  p256_fe x, y, r;
  pf_hb32(priv_hex, priv);
  pf_hb32(wr_hex, wr);
  wired_sha256((const u8*)"sample", 6, hash);
  quic_p256sign_k(priv, hash, kb);
  CHECK(quic_p256fixed_mul_g(x, y, kb));
  quic_fp_reduce(r, x, quic_p256_n);
  quic_fp_to_be(rb, r);
  for (usz i = 0; i < 32; i++) CHECK(rb[i] == wr[i]);
}

void test_p256fixed(void) {
  test_p256fixed_one_is_g();
  test_p256fixed_boundary();
  test_p256fixed_window_patterns();
  test_p256fixed_differential();
  test_p256fixed_rfc6979_vector();
}
