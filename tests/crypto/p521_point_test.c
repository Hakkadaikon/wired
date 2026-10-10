#include "crypto/asymmetric/ecc/p521/p521_point.h"

#include "test.h"

/* 2G and 3G x coordinates, computed with Python's affine formulas. */
static const p521_fe pp5_2gx = {
    0xf43e3933ba6d783dULL, 0xcf2fa364d60fd967ULL, 0xaa104a3a35c5af41ULL,
    0xb3b204da6ef55507ULL, 0x2c6e5505d769be97ULL, 0x7403279b1ccc0635ULL,
    0x2fcb288148c28274ULL, 0x3c219024277e7e68ULL, 0x0000000000000043ULL};
static const p521_fe pp5_3gx = {
    0xa5919d2ede37ad7dULL, 0xaeb490862c32ea05ULL, 0x1da6bd16b59fe21bULL,
    0xad3f164a3a483205ULL, 0xe5ad7a112d7a8dd1ULL, 0xb52a6e5b123d9ab9ULL,
    0xd91d6a64b5959479ULL, 0x3d352443de29195dULL, 0x00000000000001a7ULL};
static const p521_fe pp5_0 = {0}, pp5_1 = {1}, pp5_2 = {2};

static void test_p521_point_on_curve(void) {
  p521_fe y;
  CHECK(p521_on_curve(p521_gx, p521_gy));
  fp521_add(y, p521_gy, pp5_1, p521_p);
  CHECK(!p521_on_curve(p521_gx, y));
}

/* Plain multiples, and the table entry G+Q doubling when Q == G. */
static void test_p521_point_multiples(void) {
  p521_fe x;
  CHECK(p521_mul2_x(x, pp5_1, pp5_0, p521_gx, p521_gy) && fp521_eq(x, p521_gx));
  CHECK(p521_mul2_x(x, pp5_2, pp5_0, p521_gx, p521_gy) && fp521_eq(x, pp5_2gx));
  CHECK(p521_mul2_x(x, pp5_1, pp5_1, p521_gx, p521_gy) && fp521_eq(x, pp5_2gx));
  CHECK(p521_mul2_x(x, pp5_1, pp5_2, p521_gx, p521_gy) && fp521_eq(x, pp5_3gx));
}

/* Sums that hit infinity: G + (-G) (the G+Q table entry itself) and
 * (n-1)G + G (the final addition of the loop). */
static void test_p521_point_infinity(void) {
  p521_fe x, ny, nm1;
  fp521_sub(ny, pp5_0, p521_gy, p521_p);
  CHECK(p521_mul2_x(x, pp5_1, pp5_1, p521_gx, ny) == 0);
  fp521_sub(nm1, p521_n, pp5_1, p521_p);
  CHECK(p521_mul2_x(x, nm1, pp5_1, p521_gx, p521_gy) == 0);
}

void test_p521_point(void) {
  test_p521_point_on_curve();
  test_p521_point_multiples();
  test_p521_point_infinity();
}
