#include "crypto/asymmetric/ecc/p521/p521_field.h"

#include "test.h"

/* Expected values computed with Python's arbitrary-precision integers
 * (random.seed(521); a, b uniform below p; pow(a, -1, m)). */
static const p521_fe pf5_a = {
    0x00179ea0198f7eb9ULL, 0x4f0f8fecdbbda106ULL, 0x68d8fa9f4056c2b4ULL,
    0xb66cb7eacba3eaf4ULL, 0xdd88272dc63c0cd6ULL, 0x2d736535faacd706ULL,
    0x5b0d046ecf58db82ULL, 0x5b246f35de30f538ULL, 0x00000000000001f0ULL};
static const p521_fe pf5_b = {
    0xd2e1715219ce6a4bULL, 0x5260a73ea6bf38c9ULL, 0x4f71360b459e8603ULL,
    0x20dd0bc88d36471aULL, 0x6bb89e7f095cddc9ULL, 0x2c8bc013bd73f1a9ULL,
    0xac1f5de7565f0388ULL, 0x142b52d321a5e03fULL, 0x00000000000001b4ULL};
static const p521_fe pf5_ab_p = {
    0xd1367484f91f7bf6ULL, 0x66c47b952f79730eULL, 0x6b26963ca2eed0e0ULL,
    0xe683352804eebe5fULL, 0xa55bdb92941c89b9ULL, 0xfb35dfc065be2941ULL,
    0x9275440a1f7ae437ULL, 0xe4cc2df554ae486eULL, 0x00000000000000cbULL};
static const p521_fe pf5_ab_n = {
    0xbb52fce5d220e749ULL, 0x014302aac695c0f1ULL, 0x160ca71aad9a8e7dULL,
    0xb506feed0ca30aafULL, 0xb2b185347e163cebULL, 0xc3d74296d6965e5bULL,
    0x55b819f7ad9d0524ULL, 0xfc98ac7f3d525711ULL, 0x00000000000000fcULL};
static const p521_fe pf5_inv_p = {
    0xdc33abdec8611237ULL, 0xa4c37acd28b94f54ULL, 0x95518dadacd7c7a5ULL,
    0xd05f24236e4b094cULL, 0x898a686704f2db0cULL, 0x89e2590282d9e8f1ULL,
    0x8dc25c6c1921ccebULL, 0x9bbb5de8907c047fULL, 0x000000000000010bULL};
static const p521_fe pf5_inv_n = {
    0x283a50e9d82882f1ULL, 0x100a76f2e9638f30ULL, 0x2ea5ed998a30650dULL,
    0xe82e310ab6a2968eULL, 0x4ac7de7af3c58e0aULL, 0x9166f4b208c90027ULL,
    0x10a8b0ee31387c2fULL, 0x496b7580eea11051ULL, 0x000000000000000aULL};
static const p521_fe pf5_zero = {0};
static const p521_fe pf5_one  = {1};

/* Products against Python, both moduli; (p-1)^2 = 1 hits the fold edge. */
static void test_p521_field_mul(void) {
  p521_fe r, pm1;
  fp521_mul_p(r, pf5_a, pf5_b);
  CHECK(fp521_eq(r, pf5_ab_p));
  fp521_mul(r, pf5_a, pf5_b, p521_p);
  CHECK(fp521_eq(r, pf5_ab_p));
  fp521_mul(r, pf5_a, pf5_b, p521_n);
  CHECK(fp521_eq(r, pf5_ab_n));
  fp521_sub(pm1, pf5_zero, pf5_one, p521_p);
  fp521_mul_p(r, pm1, pm1);
  CHECK(fp521_eq(r, pf5_one));
}

/* Wrap-around at the modulus: 0 - 1 = p-1, (p-1) + 1 = 0. */
static void test_p521_field_addsub(void) {
  p521_fe r, pm1;
  fp521_sub(pm1, pf5_zero, pf5_one, p521_p);
  CHECK(pm1[0] == 0xfffffffffffffffeULL && pm1[8] == 0x1ff);
  fp521_add(r, pm1, pf5_one, p521_p);
  CHECK(fp521_is_zero(r));
  fp521_add(r, pf5_a, pf5_b, p521_n);
  fp521_sub(r, r, pf5_b, p521_n);
  CHECK(fp521_eq(r, pf5_a));
}

static void test_p521_field_inv(void) {
  p521_fe r;
  fp521_inv(r, pf5_a, p521_p);
  CHECK(fp521_eq(r, pf5_inv_p));
  fp521_inv(r, pf5_a, p521_n);
  CHECK(fp521_eq(r, pf5_inv_n));
  fp521_inv(r, pf5_one, p521_n);
  CHECK(fp521_eq(r, pf5_one));
}

static void test_p521_field_be(void) {
  u8      b[66];
  p521_fe r;
  fp521_to_be(b, pf5_a);
  CHECK(b[0] == 0x01 && b[1] == 0xf0 && b[65] == 0xb9);
  fp521_from_be(r, b);
  CHECK(fp521_eq(r, pf5_a));
  CHECK(fp521_lt(pf5_a, p521_p) && !fp521_lt(p521_p, p521_p));
}

/* Differential: fold mul == double-and-add mul mod p, and a * a^-1 == 1,
 * over 200 xorshift elements (top limb masked below p). */
static void test_p521_field_diff(void) {
  u64 st = 0x9e3779b97f4a7c15ULL;
  for (int k = 0; k < 200; k++) {
    p521_fe a, b, f, g;
    for (usz i = 0; i < 18; i++) {
      st ^= st << 13;
      st ^= st >> 7;
      st ^= st << 17;
      (i < 9 ? a : b)[i % 9] = st;
    }
    a[8] &= 0xff;
    b[8] &= 0x1ff;
    a[0] |= 1; /* nonzero */
    fp521_mul_p(f, a, b);
    fp521_mul(g, a, b, p521_p);
    CHECK(fp521_eq(f, g));
    fp521_inv(g, a, p521_p);
    fp521_mul_p(f, a, g);
    CHECK(fp521_eq(f, pf5_one));
  }
}

void test_p521_field(void) {
  test_p521_field_diff();
  test_p521_field_mul();
  test_p521_field_addsub();
  test_p521_field_inv();
  test_p521_field_be();
}
