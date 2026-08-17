#include "crypto/asymmetric/ecc/p256/p256_field.h"
#include "test.h"

/* Deterministic LCG so the random operands are reproducible run to run. */
static u64 p256field_n_state = 0x123456789abcdefULL;

static u64 p256field_n_rng(void) {
  p256field_n_state =
      p256field_n_state * 6364136223846793005ULL + 1442695040888963407ULL;
  return p256field_n_state;
}

static void p256field_n_rand(p256_fe r) {
  for (usz i = 0; i < 4; i++) r[i] = p256field_n_rng();
}

/* n-1 / n+1: n's low limb is 0x...2551 (odd, not 0, not all-ones), so both
 * are single-limb adjustments with no borrow/carry. */
static void p256field_n_off(p256_fe r, i64 delta) {
  p256_fp_set(r, p256_n);
  r[0] = (u64)((i64)r[0] + delta);
}

/* p256_fp_reduce_n agrees with the generic long-division reducer on the
 * boundaries 0, 1, n-1, n, n+1, 2^256-1 and on random 256-bit values. */
static void test_p256field_n_reduce_matches_generic(void) {
  p256_fe cases[6] = {{0, 0, 0, 0}, {1, 0, 0, 0}};
  p256field_n_off(cases[2], -1);
  p256_fp_set(cases[3], p256_n);
  p256field_n_off(cases[4], 1);
  for (usz i = 0; i < 4; i++) cases[5][i] = ~(u64)0;
  for (usz i = 0; i < 6; i++) {
    p256_fe fast, slow;
    p256_fp_reduce_n(fast, cases[i]);
    p256_fp_reduce(slow, cases[i], p256_n);
    CHECK(p256_fp_eq(fast, slow));
  }
  for (usz i = 0; i < 200; i++) {
    p256_fe a, fast, slow;
    p256field_n_rand(a);
    p256_fp_reduce_n(fast, a);
    p256_fp_reduce(slow, a, p256_n);
    CHECK(p256_fp_eq(fast, slow));
  }
}

/* p256_fp_mul_n agrees with the generic modular multiply for operands < n:
 * the boundary set {0, 1, n-1} crossed with itself, then random reduced
 * pairs. */
static void test_p256field_n_mul_matches_generic(void) {
  p256_fe    b0 = {0, 0, 0, 0}, b1 = {1, 0, 0, 0}, bn1;
  const u64* bounds[3];
  p256field_n_off(bn1, -1);
  bounds[0] = b0;
  bounds[1] = b1;
  bounds[2] = bn1;
  for (usz i = 0; i < 3; i++)
    for (usz j = 0; j < 3; j++) {
      p256_fe fast, slow;
      p256_fp_mul_n(fast, (fpab){bounds[i], bounds[j]});
      p256_fp_mul(slow, (fpab){bounds[i], bounds[j]}, p256_n);
      CHECK(p256_fp_eq(fast, slow));
    }
  for (usz i = 0; i < 200; i++) {
    p256_fe a, b, fast, slow;
    p256field_n_rand(a);
    p256field_n_rand(b);
    p256_fp_reduce_n(a, a);
    p256_fp_reduce_n(b, b);
    p256_fp_mul_n(fast, (fpab){a, b});
    p256_fp_mul(slow, (fpab){a, b}, p256_n);
    CHECK(p256_fp_eq(fast, slow));
  }
}

void test_p256field_n(void) {
  test_p256field_n_reduce_matches_generic();
  test_p256field_n_mul_matches_generic();
}
