#include "crypto/asymmetric/ecc/p256/p256_point_impl.h"

static void rhs_lhs(p256_fe lhs, p256_fe rhs, const ec_point* p);

/* FIPS 186-4 D.1.2.3 P-256 domain parameters. */
static const p256_fe p256_b = {
    0x3bce3c3e27d2604bULL, 0x651d06b0cc53b0f6ULL, 0xb3ebbd55769886bcULL,
    0x5ac635d8aa3a93e7ULL};

const ec_point p256_g = {
    {0xf4a13945d898c296ULL, 0x77037d812deb33a0ULL, 0xf8bce6e563a440f2ULL,
     0x6b17d1f2e12c4247ULL},
    {0xcbb6406837bf51f5ULL, 0x2bce33576b315eceULL, 0x8ee7eb4a7c0f9e16ULL,
     0x4fe342e2fe1a7f9bULL},
    0};

void ec_set(ec_point* r, const ec_point* p) {
  p256_fp_set(r->x, p->x);
  p256_fp_set(r->y, p->y);
  r->inf = p->inf;
}

/* y^2 mod p. */
static void rhs_lhs(p256_fe lhs, p256_fe rhs, const ec_point* p) {
  p256_fe x2, three_x, three = {3, 0, 0, 0};
  p256_fp_sqr_p(lhs, p->y);                       /* y^2 */
  p256_fp_sqr_p(x2, p->x);                        /* x^2 */
  p256_fp_mul_p(rhs, x2, p->x);                   /* x^3 */
  p256_fp_mul_p(three_x, three, p->x);            /* 3x  */
  p256_fp_sub(rhs, (fpab){rhs, three_x}, p256_p); /* x^3 - 3x */
  p256_fp_add(rhs, (fpab){rhs, p256_b}, p256_p);  /* + b */
}

/* RFC 6090 3: both coordinates must be elements of Fp (less than p); an
 * unreduced x + p would otherwise alias the on-curve point x. */
static int ec_in_field(const ec_point* p) {
  return p256_fp_lt(p->x, p256_p) && p256_fp_lt(p->y, p256_p);
}

int ec_on_curve(const ec_point* p) {
  p256_fe lhs, rhs;
  if (p->inf) {
    return 1;
  }
  rhs_lhs(lhs, rhs, p);
  return ec_in_field(p) && p256_fp_eq(lhs, rhs);
}
