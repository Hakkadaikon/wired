#include "crypto/asymmetric/ecc/p256/p256_field.h"

#include "test.h"

static void p256_hb32(const char *hex, u8 out[32]) {
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
  quic_fp_from_be(a, ab);

  quic_fp_inv(ai, a, quic_p256_p);
  quic_fp_mul(prod, (quic_fpab){a, ai}, quic_p256_p);
  CHECK(quic_fp_eq(prod, one));

  quic_fp_inv(ai, a, quic_p256_n);
  quic_fp_mul(prod, (quic_fpab){a, ai}, quic_p256_n);
  CHECK(quic_fp_eq(prod, one));
}

/* add/sub round-trip: (a + b) - b == a (mod p). */
static void test_p256_field_addsub(void) {
  fe a, b, s, d;
  u8 ab[32], bb[32];
  p256_hb32(
      "0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff02", ab);
  p256_hb32(
      "00000000000000000000000000000000000000000000000000000000000000ff", bb);
  quic_fp_from_be(a, ab);
  quic_fp_from_be(b, bb);
  quic_fp_add(s, (quic_fpab){a, b}, quic_p256_p);
  quic_fp_sub(d, (quic_fpab){s, b}, quic_p256_p);
  CHECK(quic_fp_eq(d, a));
}

/* be round-trip: bytes -> fe -> bytes is identity. */
static void test_p256_field_bytes(void) {
  fe a;
  u8 in[32], out[32];
  p256_hb32(
      "0123456789abcdeffedcba98765432100011223344556677889900aabbccddee", in);
  quic_fp_from_be(a, in);
  quic_fp_to_be(out, a);
  for (usz i = 0; i < 32; i++) CHECK(out[i] == in[i]);
}

/* Deterministic xorshift so the differential test is reproducible. */
static u64 p256_rng(u64 *s) {
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
    quic_fp_mul(r1, (quic_fpab){a, b}, quic_p256_p); /* oracle */
    quic_fp_mul_p(r2, a, b);                         /* fast */
    CHECK(quic_fp_eq(r1, r2));
    quic_fp_sqr(r1, a, quic_p256_p);
    quic_fp_sqr_p(r2, a);
    CHECK(quic_fp_eq(r1, r2));
  }
  /* boundary: a = p - 1. */
  for (int i = 0; i < 4; i++) a[i] = quic_p256_p[i];
  a[0] -= 1;
  quic_fp_mul(r1, (quic_fpab){a, a}, quic_p256_p);
  quic_fp_sqr_p(r2, a);
  CHECK(quic_fp_eq(r1, r2));
  /* fast inverse: a * a^-1 == 1 (mod p). */
  {
    fe ai, prod, one = {1, 0, 0, 0};
    quic_fp_inv_p(ai, a);
    quic_fp_mul_p(prod, a, ai);
    CHECK(quic_fp_eq(prod, one));
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
    for (int i = 0; i < 4; i++) a[i] = p256_rng(&s);
    quic_fp_reduce(a, a, quic_p256_n);
    if (quic_fp_is_zero(a)) continue;
    quic_mont_inv(ai, a, &quic_p256_mont_n);
    quic_fp_mul(prod, (quic_fpab){a, ai}, quic_p256_n);
    CHECK(quic_fp_eq(prod, one));
    if (it < 4) { /* spot-check against the slow oracle */
      quic_fp_inv(ref, a, quic_p256_n);
      CHECK(quic_fp_eq(ai, ref));
    }
  }
}

void test_p256_field(void) {
  test_p256_field_inv();
  test_p256_field_addsub();
  test_p256_field_bytes();
  test_p256_field_fast_matches_generic();
  test_p256_field_mont_inv_n();
}
