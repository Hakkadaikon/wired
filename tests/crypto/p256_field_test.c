#include "crypto/asymmetric/ecc/p256/p256_field.h"

#include "test.h"

static void p256_hb32(const char* hex, u8 out[32]) {
  for (usz i = 0; i < 32; i++) {
    u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
    out[i] = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                  (lo <= '9' ? lo - '0' : lo - 'a' + 10));
  }
}

/* a * a^-1 == 1 (mod p) and (mod n). */
static void test_p256_field_inv(void) {
  fe a, ai, prod, one = {1, 0, 0, 0};
  u8 ab[32];
  p256_hb32(
      "00112233445566778899aabbccddeeff00112233445566778899aabbccddee01", ab);
  p256_fp_from_be(a, ab);

  p256_fp_inv(ai, a, p256_p);
  p256_fp_mul(prod, (fpab){a, ai}, p256_p);
  CHECK(p256_fp_eq(prod, one));

  p256_fp_inv(ai, a, p256_n);
  p256_fp_mul(prod, (fpab){a, ai}, p256_n);
  CHECK(p256_fp_eq(prod, one));
}

/* add/sub round-trip: (a + b) - b == a (mod p). */
static void test_p256_field_addsub(void) {
  fe a, b, s, d;
  u8 ab[32], bb[32];
  p256_hb32(
      "0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff02", ab);
  p256_hb32(
      "00000000000000000000000000000000000000000000000000000000000000ff", bb);
  p256_fp_from_be(a, ab);
  p256_fp_from_be(b, bb);
  p256_fp_add(s, (fpab){a, b}, p256_p);
  p256_fp_sub(d, (fpab){s, b}, p256_p);
  CHECK(p256_fp_eq(d, a));
}

/* The masked add/sub/reduce at the modulus boundaries, pinned to values
 * computed by hand: (m-1)+1 = 0, (m-1)+(m-1) = m-2, 0-1 = m-1, 1-(m-1) = 2
 * for m = p and n; n mod n = 0, (2^256-1) mod n = 2^256-1-n; inv_p(0) = 0
 * (infinity's Z in jac_to_affine); the scalar range [1, n-1]; cmov. */
static void p256f_minus(fe r, const fe m, u64 k) {
  for (usz i = 0; i < 4; i++) {
    r[i] = m[i];
  }
  r[0] -= k; /* m[0] >= k for p and n, no borrow */
}

static void p256f_edges_mod(const fe m) {
  fe zero = {0}, one = {1, 0, 0, 0}, two = {2, 0, 0, 0}, m1, m2, r;
  p256f_minus(m1, m, 1);
  p256f_minus(m2, m, 2);
  p256_fp_add(r, (fpab){m1, one}, m);
  CHECK(p256_fp_is_zero(r));
  p256_fp_add(r, (fpab){m1, m1}, m);
  CHECK(p256_fp_eq(r, m2));
  p256_fp_sub(r, (fpab){zero, one}, m);
  CHECK(p256_fp_eq(r, m1));
  p256_fp_sub(r, (fpab){one, m1}, m);
  CHECK(p256_fp_eq(r, two));
}

static void test_p256_field_ct_edges(void) {
  static const fe ones = {~0ULL, ~0ULL, ~0ULL, ~0ULL};
  static const fe zero = {0}, one = {1, 0, 0, 0};
  fe              r, want, n1;
  p256f_edges_mod(p256_p);
  p256f_edges_mod(p256_n);
  p256_fp_reduce_n(r, p256_n);
  CHECK(p256_fp_is_zero(r));
  p256f_minus(n1, p256_n, 1);
  p256_fp_reduce_n(r, n1);
  CHECK(p256_fp_eq(r, n1));
  p256_fp_reduce_n(r, ones);
  for (usz i = 0; i < 4; i++) {
    want[i] = ~p256_n[i]; /* 2^256-1-n, limb-wise with no borrow */
  }
  CHECK(p256_fp_eq(r, want));
  p256_fp_inv_p(r, zero);
  CHECK(p256_fp_is_zero(r));
  CHECK(p256_scalar_in_range(zero) == 0);
  CHECK(p256_scalar_in_range(one) == 1);
  CHECK(p256_scalar_in_range(n1) == 1);
  CHECK(p256_scalar_in_range(p256_n) == 0);
  CHECK(p256_scalar_in_range(ones) == 0);
  p256_fp_set(r, one);
  p256_fp_cmov(r, n1, 0);
  CHECK(p256_fp_eq(r, one));
  p256_fp_cmov(r, n1, 1);
  CHECK(p256_fp_eq(r, n1));
}

/* mont_finalize's carry limb: CIOS ends with t = t[4]*2^256 + t[0..3] < 2m,
 * and t[4] = 1 exactly when t lands in [2^256, 2m). For m = n that is
 * (n-1)^2 in test_p256_field_mul_all_ones_limbs. For m = p, 2p - 2^256 is
 * only ~2^-32 of the range, so the operand below was found by a search over
 * a = b near p with a big-integer model of the same CIOS rows (t[4] == 1
 * after the last row); want = a^2 * 2^-256 mod p. */
static void test_p256_field_mont_carry_limb_p(void) {
  static const fe a = {
      0x91b7584a2265b1f4ULL, 0xcd613e31d8f16adfULL, 0x1027c4d1c386bbc4ULL,
      0xfffffffeffffff83ULL};
  static const fe want = {
      0xd39b3517f25779deULL, 0x9ea6db5dabf15ee7ULL, 0x6e86fd71b343b77eULL,
      0xcf53efdeac963da6ULL};
  fe r;
  mont_mul(r, (fpab){a, a}, &p256_mont_p);
  CHECK(p256_fp_eq(r, want));
}

/* be round-trip: bytes -> fe -> bytes is identity. */
static void test_p256_field_bytes(void) {
  fe a;
  u8 in[32], out[32];
  p256_hb32(
      "0123456789abcdeffedcba98765432100011223344556677889900aabbccddee", in);
  p256_fp_from_be(a, in);
  p256_fp_to_be(out, a);
  for (usz i = 0; i < 32; i++) {
    CHECK(out[i] == in[i]);
  }
}

/* Deterministic xorshift so the differential test is reproducible. */
static u64 p256_rng(u64* s) {
  *s ^= *s << 13;
  *s ^= *s >> 7;
  *s ^= *s << 17;
  return *s;
}

/* The fast P-256 Solinas mul/sqr/inv must agree with the generic long-division
 * reducer mod p on random and boundary inputs (the reducer is the oracle: it is
 * slow but obviously correct). This pins the hand-derived FIPS 186-4 D.2.5 word
 * rearrangement that powers the ~600x speedup. */
static void test_p256_field_fast_matches_generic(void) {
  u64 s = 0x9e3779b97f4a7c15ULL;
  fe  a, b, r1, r2;
  for (int it = 0; it < 4096; it++) {
    for (int i = 0; i < 4; i++) {
      a[i] = p256_rng(&s);
      b[i] = p256_rng(&s);
    }
    p256_fp_mul(r1, (fpab){a, b}, p256_p); /* oracle */
    p256_fp_mul_p(r2, a, b);               /* fast */
    CHECK(p256_fp_eq(r1, r2));
    p256_fp_sqr(r1, a, p256_p);
    p256_fp_sqr_p(r2, a);
    CHECK(p256_fp_eq(r1, r2));
  }
  /* boundary: a = p - 1. */
  for (int i = 0; i < 4; i++) {
    a[i] = p256_p[i];
  }
  a[0] -= 1;
  p256_fp_mul(r1, (fpab){a, a}, p256_p);
  p256_fp_sqr_p(r2, a);
  CHECK(p256_fp_eq(r1, r2));
  /* fast inverse: a * a^-1 == 1 (mod p). */
  {
    fe ai, prod, one = {1, 0, 0, 0};
    p256_fp_inv_p(ai, a);
    p256_fp_mul_p(prod, a, ai);
    CHECK(p256_fp_eq(prod, one));
  }
}

/* a * (a^-1) == 1 (mod n) via the fast Montgomery inverse, cross-checked
 * against the generic Fermat inverse on a few values (the generic one is the
 * oracle but ~100ms each, so only a handful). Pins the Montgomery constants
 * (n0inv / rr / one) and the CIOS multiply for the group order n. */
static void test_p256_field_mont_inv_n(void) {
  u64 s = 0x243f6a8885a308d3ULL;
  fe  a, ai, prod, ref, one = {1, 0, 0, 0};
  for (int it = 0; it < 64; it++) {
    for (int i = 0; i < 4; i++) {
      a[i] = p256_rng(&s);
    }
    p256_fp_reduce(a, a, p256_n);
    if (p256_fp_is_zero(a)) {
      continue;
    }
    mont_inv(ai, a, &p256_mont_n);
    p256_fp_mul(prod, (fpab){a, ai}, p256_n);
    CHECK(p256_fp_eq(prod, one));
    if (it < 4) { /* spot-check against the slow oracle */
      p256_fp_inv(ref, a, p256_n);
      CHECK(p256_fp_eq(ai, ref));
    }
  }
}

/* a * (a^-1) == 1 (mod p) via the fast Fermat inverse on random inputs, and
 * on the boundaries 1, p-1, and the reduced all-ones pattern, each boundary
 * also cross-checked against the generic slow oracle. Pins p256_fp_inv_p's
 * exponentiation so a reshaped power x25519_ladder cannot silently drift. */
static void test_p256_field_inv_p_edges(void) {
  u64 s = 0xb7e151628aed2a6bULL;
  fe  a, ai, prod, ref, one = {1, 0, 0, 0};
  for (int it = 0; it < 64; it++) {
    for (int i = 0; i < 4; i++) {
      a[i] = p256_rng(&s);
    }
    p256_fp_reduce(a, a, p256_p);
    if (p256_fp_is_zero(a)) {
      continue;
    }
    p256_fp_inv_p(ai, a);
    p256_fp_mul_p(prod, a, ai);
    CHECK(p256_fp_eq(prod, one));
  }
  {
    fe edges[3] = {{1, 0, 0, 0}};
    for (int i = 0; i < 4; i++) {
      edges[1][i] = p256_p[i];
      edges[2][i] = ~0ULL;
    }
    edges[1][0] -= 1; /* p - 1 */
    p256_fp_reduce(edges[2], edges[2], p256_p);
    for (int e = 0; e < 3; e++) {
      p256_fp_inv_p(ai, edges[e]);
      p256_fp_inv(ref, edges[e], p256_p);
      CHECK(p256_fp_eq(ai, ref));
      p256_fp_mul_p(prod, edges[e], ai);
      CHECK(p256_fp_eq(prod, one));
    }
  }
}

/* The Montgomery inverse mod n on the same boundary shapes (1, n-1, the
 * reduced all-ones pattern), cross-checked against the generic oracle. */
static void test_p256_field_mont_inv_n_edges(void) {
  fe ai, prod, ref, one = {1, 0, 0, 0};
  fe edges[3] = {{1, 0, 0, 0}};
  for (int i = 0; i < 4; i++) {
    edges[1][i] = p256_n[i];
    edges[2][i] = ~0ULL;
  }
  edges[1][0] -= 1; /* n - 1 */
  p256_fp_reduce(edges[2], edges[2], p256_n);
  for (int e = 0; e < 3; e++) {
    mont_inv(ai, edges[e], &p256_mont_n);
    p256_fp_inv(ref, edges[e], p256_n);
    CHECK(p256_fp_eq(ai, ref));
    p256_fp_mul(prod, (fpab){edges[e], ai}, p256_n);
    CHECK(p256_fp_eq(prod, one));
  }
}

/* Carry propagation at every limb boundary (CVE-2021-4160 class): all-ones
 * limbs through the schoolbook rows and the Montgomery CIOS rows, pinned to
 * values computed with arbitrary-precision arithmetic.
 *   (2^256-1)^2 mod p, and mont_mul(m-1, m-1) = (m-1)^2 * 2^-256 = 2^-256
 * mod m for both the prime p and the order n. */
static void test_p256_field_mul_all_ones_limbs(void) {
  static const fe ones = {
      0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL,
      0xffffffffffffffffULL};
  static const fe want = {
      0x0000000000000002ULL, 0xfffffffdffffffffULL, 0xfffffffffffffffeULL,
      0x00000002ffffffffULL};
  static const fe rinv_p = {
      0x0000000300000000ULL, 0x00000001fffffffeULL, 0xfffffffd00000002ULL,
      0xfffffffe00000003ULL};
  static const fe rinv_n = {
      0xce1bc8f79c197c79ULL, 0xbadef3e243566fafULL, 0x07f8b6041e607725ULL,
      0x60d066334905c1e9ULL};
  fe r, pm1, nm1;
  p256_fp_mul(r, (fpab){ones, ones}, p256_p);
  CHECK(p256_fp_eq(r, want));
  for (usz i = 0; i < 4; i++) {
    pm1[i] = p256_p[i];
    nm1[i] = p256_n[i];
  }
  pm1[0] -= 1;
  nm1[0] -= 1;
  mont_mul(r, (fpab){pm1, pm1}, &p256_mont_p);
  CHECK(p256_fp_eq(r, rinv_p));
  mont_mul(r, (fpab){nm1, nm1}, &p256_mont_n);
  CHECK(p256_fp_eq(r, rinv_n));
}

void test_p256_field(void) {
  test_p256_field_ct_edges();
  test_p256_field_mont_carry_limb_p();
  test_p256_field_inv();
  test_p256_field_addsub();
  test_p256_field_bytes();
  test_p256_field_fast_matches_generic();
  test_p256_field_mont_inv_n();
  test_p256_field_inv_p_edges();
  test_p256_field_mont_inv_n_edges();
  test_p256_field_mul_all_ones_limbs();
}
