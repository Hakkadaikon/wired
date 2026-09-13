#include "crypto/asymmetric/ecc/p256/ecdsa_verify.h"
#include "crypto/asymmetric/ecc/p256/p256_point.h"
#include "crypto/asymmetric/ecc/p256sign/sign.h"
#include "crypto/symmetric/hash/hash/sha256.h"
#include "test.h"

/* Differential: ecdsa_p256_verify (fixed-base G table + fast n-reduction)
 * against a reference built only from the generic API (constant-time
 * ec_mul ladder for both u1*G and u2*Q, long-division p256_fp_reduce /
 * p256_fp_mul over n). FIPS 186-4 6.4.2 either way; the two must agree on
 * every (r, s, Q, hash) tuple, valid or not. */

typedef struct {
  u8 qx[32], qy[32], r[32], s[32], h[32];
} ecdsadiff_tuple;

/* Reference u1*G + u2*Q via the generic ladder; 0 if R is infinity. */
static int ecdsadiff_ref_point(
    ec_point* rp, const p256_fe u1, const p256_fe u2, const ec_point* q) {
  ec_point a, b;
  u8       u1b[32], u2b[32];
  p256_fp_to_be(u1b, u1);
  p256_fp_to_be(u2b, u2);
  ec_mul(&a, u1b, &p256_g);
  ec_mul(&b, u2b, q);
  ec_add(rp, &a, &b);
  return !rp->inf;
}

/* 1 if 1 <= v < n. */
static int ecdsadiff_in_range(const p256_fe v) {
  return !p256_fp_is_zero(v) && p256_fp_lt(v, p256_n);
}

static int ecdsadiff_ref_verify(const ecdsadiff_tuple* t) {
  ec_point q, rp;
  p256_fe  r, s, e, w, u1, u2, rx;
  p256_fp_from_be(r, t->r);
  p256_fp_from_be(s, t->s);
  if (!ecdsadiff_in_range(r) || !ecdsadiff_in_range(s)) return 0;
  p256_fp_from_be(q.x, t->qx);
  p256_fp_from_be(q.y, t->qy);
  q.inf = 0;
  if (!ec_on_curve(&q)) return 0;
  p256_fp_from_be(e, t->h);
  p256_fp_reduce(e, e, p256_n);
  mont_inv(w, s, &p256_mont_n);
  p256_fp_mul(u1, (fpab){e, w}, p256_n);
  p256_fp_mul(u2, (fpab){r, w}, p256_n);
  if (!ecdsadiff_ref_point(&rp, u1, u2, &q)) return 0;
  p256_fp_reduce(rx, rp.x, p256_n);
  return p256_fp_eq(rx, r);
}

/* Both paths must agree; `want` additionally pins the expected verdict. */
static void ecdsadiff_check(const ecdsadiff_tuple* t, int want) {
  int got = ecdsa_p256_verify(t->qx, t->qy, t->r, t->s, t->h);
  CHECK(got == want);
  CHECK(got == ecdsadiff_ref_verify(t));
}

/* 32 deterministic bytes: SHA-256 of (tag, counter). */
static void ecdsadiff_derive(u8 out[32], u8 tag, u32 c) {
  u8 in[5] = {tag, (u8)(c >> 24), (u8)(c >> 16), (u8)(c >> 8), (u8)c};
  wired_sha256(in, 5, out);
}

/* Key pair from counter c: priv = H('k', c) (< n with overwhelming
 * probability; a >= n draw would only make sign/verify disagree by
 * construction, which the CHECK would flag), Q = priv*G. */
static void ecdsadiff_keypair(ecdsadiff_tuple* t, u8 priv[32], u32 c) {
  ec_point q;
  ecdsadiff_derive(priv, 'k', c);
  ec_mul(&q, priv, &p256_g);
  p256_fp_to_be(t->qx, q.x);
  p256_fp_to_be(t->qy, q.y);
}

/* Valid signature tuple c: sign H('m', c) with key c. */
static void ecdsadiff_valid(ecdsadiff_tuple* t, u32 c) {
  u8 priv[32];
  ecdsadiff_keypair(t, priv, c);
  ecdsadiff_derive(t->h, 'm', c);
  p256sign_sign(priv, t->h, t->r, t->s);
}

/* 12 valid signatures: new path must accept, and agree with the reference. */
static void test_ecdsadiff_valid(void) {
  for (u32 c = 0; c < 12; c++) {
    ecdsadiff_tuple t;
    ecdsadiff_valid(&t, c);
    ecdsadiff_check(&t, 1);
  }
}

/* Tampered hash / r / s on a valid tuple: both paths reject. */
static void test_ecdsadiff_tampered(void) {
  for (u32 c = 0; c < 4; c++) {
    ecdsadiff_tuple t;
    ecdsadiff_valid(&t, c);
    t.h[c] ^= 0x80;
    ecdsadiff_check(&t, 0);
    ecdsadiff_valid(&t, c);
    t.r[31 - c] ^= 0x01;
    ecdsadiff_check(&t, 0);
    ecdsadiff_valid(&t, c);
    t.s[16] ^= 0x10;
    ecdsadiff_check(&t, 0);
  }
}

/* Unrelated (r, s) pairs against a real key: both paths reject. */
static void test_ecdsadiff_random_sig(void) {
  for (u32 c = 0; c < 4; c++) {
    ecdsadiff_tuple t;
    u8              priv[32];
    ecdsadiff_keypair(&t, priv, c);
    ecdsadiff_derive(t.h, 'm', c);
    ecdsadiff_derive(t.r, 'r', c);
    ecdsadiff_derive(t.s, 's', c);
    t.r[0] &= 0x7f; /* keep r, s < n so the range check is not the reason */
    t.s[0] &= 0x7f;
    ecdsadiff_check(&t, 0);
  }
}

/* e == 0 edge (u1 == 0, so u1*G is the identity): a signature over the
 * all-zero hash verifies with hash 0 and with hash == n (both reduce to 0),
 * on both paths. Also r == 0 / s == 0 / r == n / s == n rejected. */
static void test_ecdsadiff_edges(void) {
  ecdsadiff_tuple t;
  u8              priv[32];
  ecdsadiff_keypair(&t, priv, 99);
  for (usz i = 0; i < 32; i++) t.h[i] = 0;
  p256sign_sign(priv, t.h, t.r, t.s);
  ecdsadiff_check(&t, 1);
  p256_fp_to_be(t.h, p256_n);
  ecdsadiff_check(&t, 1);
  ecdsadiff_tuple z = t;
  for (usz i = 0; i < 32; i++) z.r[i] = 0;
  ecdsadiff_check(&z, 0);
  z = t;
  for (usz i = 0; i < 32; i++) z.s[i] = 0;
  ecdsadiff_check(&z, 0);
  z = t;
  p256_fp_to_be(z.r, p256_n);
  ecdsadiff_check(&z, 0);
  z = t;
  p256_fp_to_be(z.s, p256_n);
  ecdsadiff_check(&z, 0);
}

void test_ecdsa_diff(void) {
  test_ecdsadiff_valid();
  test_ecdsadiff_tampered();
  test_ecdsadiff_random_sig();
  test_ecdsadiff_edges();
}
