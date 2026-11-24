#include "crypto/asymmetric/ecc/secp256k1/secp256k1_impl.h"
#include "test.h"
#include "vectors/boringssl/bssl_vec.h"

/* SEC 2 2.4.1 generator coordinates and the well-known multiples 2G and 3G
 * (3G's x is BIP-340 test vector 0's public key, secret key 3). */
static const char* const secp256k1t_gx =
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
static const char* const secp256k1t_gy =
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
static const char* const secp256k1t_2gx =
    "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
static const char* const secp256k1t_3gx =
    "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

static void secp256k1t_fe(p256_fe r, const char* hex) {
  u8 b[32];
  bssl_hex(hex, b, 32);
  p256_fp_from_be(r, b);
}

static int secp256k1t_x_is(const secp256k1_pt* a, const char* hex, int* odd) {
  u8 x[32], want[32];
  bssl_hex(hex, want, 32);
  return secp256k1_affine(x, odd, a) && ct_diff32(x, want) == 0;
}

/* Montgomery constants re-derived from p: n0inv * p[0] = -1 mod 2^64,
 * one = 2^256 - p, rr = one^2 mod p (generic long-division oracle), and the
 * square-root exponent e < p satisfies 4e = 1 mod p (so e = (p + 1) / 4). */
static void test_secp256k1_constants(void) {
  const mont* m = &secp256k1_mont_p;
  p256_fe     rr, e4, one = {1, 0, 0, 0};
  CHECK(m->m[0] * m->n0inv == ~(u64)0);
  CHECK(m->one[0] == 0x1000003d1ULL && m->one[1] == 0 && m->one[3] == 0);
  p256_fp_mul(rr, (fpab){m->one, m->one}, secp256k1_p);
  CHECK(p256_fp_eq(rr, m->rr));
  p256_fp_add(e4, (fpab){secp256k1_sqrt_exp, secp256k1_sqrt_exp}, secp256k1_p);
  p256_fp_add(e4, (fpab){e4, e4}, secp256k1_p);
  CHECK(p256_fp_eq(e4, one)); /* 4e = p + 1 = 1 mod p */
}

/* lift_x(Gx) returns G itself (Gy is even), so G is on the curve. */
static void test_secp256k1_lift_g(void) {
  secp256k1_pt g, b;
  p256_fe      y, gy;
  CHECK(secp256k1_lift_x(
      &g, (const u8*)"\x79\xbe\x66\x7e\xf9\xdc\xbb\xac"
                     "\x55\xa0\x62\x95\xce\x87\x0b\x07"
                     "\x02\x9b\xfc\xdb\x2d\xce\x28\xd9"
                     "\x59\xf2\x81\x5b\x16\xf8\x17\x98"));
  secp256k1_base(&b);
  secp256k1_fe_from_mont(y, g.y);
  secp256k1t_fe(gy, secp256k1t_gy);
  CHECK(p256_fp_eq(y, gy));
  secp256k1_fe_from_mont(y, b.y);
  CHECK(p256_fp_eq(y, gy));
}

/* G + G (general add falls into doubling) and dbl agree with 2G; 2G + G =
 * 3G; adding infinity is the identity. */
static void test_secp256k1_add_dbl(void) {
  secp256k1_pt g, d, s, t, inf = {{0}, {0}, {0}};
  int          odd;
  secp256k1_base(&g);
  secp256k1_dbl(&d, &g);
  CHECK(secp256k1t_x_is(&d, secp256k1t_2gx, &odd));
  secp256k1_add(&s, &g, &g);
  CHECK(secp256k1t_x_is(&s, secp256k1t_2gx, &odd));
  secp256k1_add(&t, &s, &g);
  CHECK(secp256k1t_x_is(&t, secp256k1t_3gx, &odd));
  CHECK(odd == 0); /* BIP-340 vector 0 public key is the even-y 3G */
  secp256k1_add(&t, &inf, &g);
  CHECK(secp256k1t_x_is(&t, secp256k1t_gx, &odd));
  secp256k1_add(&t, &g, &inf);
  CHECK(secp256k1t_x_is(&t, secp256k1t_gx, &odd));
}

/* n*G = infinity, (n-1)*G = -G (x = Gx, odd y), G + (-G) = infinity, and
 * the Shamir combination 1*G + 2*G = 3G. */
static void test_secp256k1_mul2(void) {
  secp256k1_pt g, r, ng;
  p256_fe      zero = {0}, one = {1, 0, 0, 0}, two = {2, 0, 0, 0}, nm1;
  u8           x[32];
  int          odd;
  secp256k1_base(&g);
  secp256k1_mul2(&r, (fpab){secp256k1_n, zero}, &g, &g);
  CHECK(secp256k1_affine(x, &odd, &r) == 0);
  p256_fp_sub(nm1, (fpab){secp256k1_n, one}, secp256k1_n);
  secp256k1_mul2(&ng, (fpab){nm1, zero}, &g, &g);
  CHECK(secp256k1t_x_is(&ng, secp256k1t_gx, &odd));
  CHECK(odd == 1);
  secp256k1_add(&r, &ng, &g);
  CHECK(secp256k1_affine(x, &odd, &r) == 0);
  secp256k1_mul2(&r, (fpab){one, two}, &g, &g);
  CHECK(secp256k1t_x_is(&r, secp256k1t_3gx, &odd));
}

/* lift_x rejects x >= p (p itself, all-ones) and an x with no curve point
 * (BIP-340 vector 5's public key); 3G's x is accepted. */
static void test_secp256k1_lift_reject(void) {
  secp256k1_pt r;
  u8           b[32];
  p256_fp_to_be(b, secp256k1_p);
  CHECK(secp256k1_lift_x(&r, b) == 0);
  bytes_memset(b, 0xff, 32);
  CHECK(secp256k1_lift_x(&r, b) == 0);
  bssl_hex(
      "eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34", b,
      32);
  CHECK(secp256k1_lift_x(&r, b) == 0);
  bssl_hex(secp256k1t_3gx, b, 32);
  CHECK(secp256k1_lift_x(&r, b) == 1);
}

/* lift_x always yields the even root (the raw c^((p+1)/4) of one of these
 * is odd, so dropping the parity fix fails here). */
static void test_secp256k1_lift_even(void) {
  const char* const xs[2] = {secp256k1t_2gx, secp256k1t_3gx};
  for (usz i = 0; i < 2; i++) {
    secp256k1_pt r;
    u8           b[32];
    int          odd = 1;
    bssl_hex(xs[i], b, 32);
    CHECK(secp256k1_lift_x(&r, b) == 1);
    CHECK(secp256k1t_x_is(&r, xs[i], &odd));
    CHECK(odd == 0);
  }
}

void test_secp256k1(void) {
  test_secp256k1_constants();
  test_secp256k1_lift_g();
  test_secp256k1_add_dbl();
  test_secp256k1_mul2();
  test_secp256k1_lift_reject();
  test_secp256k1_lift_even();
}
