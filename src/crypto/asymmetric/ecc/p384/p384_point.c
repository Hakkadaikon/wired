#include "crypto/asymmetric/ecc/p384/p384_point_impl.h"

static void p384pt_rhs_lhs(p384_fe lhs, p384_fe rhs, const ec_point384* p);

/* FIPS 186-4 D.1.2.4 P-384 domain parameters. */
static const p384_fe p384_b = {0x2a85c8edd3ec2aefULL, 0xc656398d8a2ed19dULL,
                               0x0314088f5013875aULL, 0x181d9c6efe814112ULL,
                               0x988e056be3f82d19ULL, 0xb3312fa7e23ee7e4ULL};

const ec_point384 p384_g = {
    {0x3a545e3872760ab7ULL, 0x5502f25dbf55296cULL, 0x59f741e082542a38ULL,
     0x6e1d3b628ba79b98ULL, 0x8eb1c71ef320ad74ULL, 0xaa87ca22be8b0537ULL},
    {0x7a431d7c90ea0e5fULL, 0x0a60b1ce1d7e819dULL, 0xe9da3113b5f0b8c0ULL,
     0xf8f41dbd289a147cULL, 0x5d9e98bf9292dc29ULL, 0x3617de4a96262c6fULL},
    0};

void p384_point_set(ec_point384* r, const ec_point384* p) {
  fp384_set(r->x, p->x);
  fp384_set(r->y, p->y);
  r->inf = p->inf;
}

/* lhs = y^2, rhs = x^3 - 3x + b (all mod p). */
static void p384pt_rhs_lhs(p384_fe lhs, p384_fe rhs, const ec_point384* p) {
  p384_fe x2, three_x, three = {3, 0, 0, 0, 0, 0};
  fp384_sqr(lhs, p->y, p384_p);
  fp384_sqr(x2, p->x, p384_p);
  fp384_mul(rhs, (fp384ab){x2, p->x}, p384_p);
  fp384_mul(three_x, (fp384ab){three, p->x}, p384_p);
  fp384_sub(rhs, (fp384ab){rhs, three_x}, p384_p);
  fp384_add(rhs, (fp384ab){rhs, p384_b}, p384_p);
}

int p384_point_on_curve(const ec_point384* p) {
  p384_fe lhs, rhs;
  if (p->inf) return 1;
  p384pt_rhs_lhs(lhs, rhs, p);
  return fp384_eq(lhs, rhs);
}
