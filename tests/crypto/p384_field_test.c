#include "crypto/asymmetric/ecc/p384/p384_field.h"

#include "test.h"

/* A small xorshift PRNG so the differential test is deterministic and needs
 * no syscalls. */
static u64 pf_rng_state = 0x9e3779b97f4a7c15ULL;
static u64 pf_rng(void) {
  u64 x = pf_rng_state;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  pf_rng_state = x;
  return x;
}

/* A random field element reduced below p. */
static void pf_rand(p384_fe r) {
  p384_fe t;
  for (usz i = 0; i < 6; i++) t[i] = pf_rng();
  quic_fp384_reduce(r, t, quic_p384_p);
}

/* One differential case: Solinas mul_p == generic mul mod p. */
static void pf_diff_one(const p384_fe a, const p384_fe b) {
  p384_fe fast, slow;
  quic_fp384_mul_p(fast, a, b);
  quic_fp384_mul(slow, (quic_fp384ab){a, b}, quic_p384_p);
  CHECK(quic_fp384_eq(fast, slow) == 1);
}

/* Solinas vs the generic reducer over boundary values and 4000 random pairs.
 * (The generic reducer itself was cross-checked against Python's arbitrary-
 * precision arithmetic over 20006 cases at derivation time.) */
static void test_p384_field_fast_matches_generic(void) {
  static const p384_fe zero = {0, 0, 0, 0, 0, 0};
  static const p384_fe one  = {1, 0, 0, 0, 0, 0};
  p384_fe              pm1, a, b;
  quic_fp384_sub(pm1, (quic_fp384ab){zero, one}, quic_p384_p); /* p - 1 */
  pf_diff_one(zero, pm1);
  pf_diff_one(one, pm1);
  pf_diff_one(pm1, pm1);
  for (usz i = 0; i < 4000; i++) {
    pf_rand(a);
    pf_rand(b);
    pf_diff_one(a, b);
  }
}

/* sqr_p agrees with mul_p(a,a), and add/sub round-trip. */
static void test_p384_field_addsub(void) {
  p384_fe a, b, s, d, sq, mm;
  pf_rand(a);
  pf_rand(b);
  quic_fp384_add(s, (quic_fp384ab){a, b}, quic_p384_p);
  quic_fp384_sub(d, (quic_fp384ab){s, b}, quic_p384_p);
  CHECK(quic_fp384_eq(d, a) == 1);
  quic_fp384_sqr_p(sq, a);
  quic_fp384_mul_p(mm, a, a);
  CHECK(quic_fp384_eq(sq, mm) == 1);
}

/* a * a^-1 == 1 mod p (the Solinas Fermat inverse). */
static void test_p384_field_inv(void) {
  p384_fe              a, inv, prod;
  static const p384_fe one = {1, 0, 0, 0, 0, 0};
  pf_rand(a);
  quic_fp384_inv_p(inv, a);
  quic_fp384_mul_p(prod, a, inv);
  CHECK(quic_fp384_eq(prod, one) == 1);
}

/* Montgomery inverse over the group order n agrees: a * a^-1 == 1 mod n. */
static void test_p384_field_mont_inv_n(void) {
  p384_fe              a, t, inv, prod;
  static const p384_fe one = {1, 0, 0, 0, 0, 0};
  for (usz i = 0; i < 6; i++) t[i] = pf_rng();
  quic_fp384_reduce(a, t, quic_p384_n);
  quic_mont384_inv(inv, a, &quic_p384_mont_n);
  quic_fp384_mul(prod, (quic_fp384ab){a, inv}, quic_p384_n);
  CHECK(quic_fp384_eq(prod, one) == 1);
}

/* 48-byte big-endian load/store round-trips. */
static void test_p384_field_bytes(void) {
  u8      be[48], out[48];
  p384_fe a;
  for (usz i = 0; i < 48; i++) be[i] = (u8)(i * 7 + 1);
  be[0] &= 0x7f; /* keep it < p */
  quic_fp384_from_be(a, be);
  quic_fp384_to_be(out, a);
  for (usz i = 0; i < 48; i++) CHECK(out[i] == be[i]);
}

void test_p384_field(void) {
  test_p384_field_fast_matches_generic();
  test_p384_field_addsub();
  test_p384_field_inv();
  test_p384_field_mont_inv_n();
  test_p384_field_bytes();
}
