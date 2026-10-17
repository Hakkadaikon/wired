#include "crypto/asymmetric/ecc/p256/p256_point_impl.h"

/* r = k * p, constant-time: no branch keys off a scalar bit directly (see
 * p256_ladder_step). k big-endian 32 bytes. */
void ec_mul(ec_point* r, const u8 k[32], const ec_point* p) {
  jac r0 = {{0}, {0}, {0}}; /* infinity */
  jac r1;
  u64 swap = 0;
  p256pt_jac_from_affine(&r1, p);
  for (usz i = 0; i < 256; i++) {
    u64 bit = (k[i / 8] >> (7 - (i & 7))) & 1; /* MSB-first, big-endian */
    swap ^= bit;
    p256pt_jac_cswap(&r0, &r1, (u64)0 - swap);
    swap = bit;
    p256_ladder_step(&r0, &r1);
  }
  p256pt_jac_cswap(&r0, &r1, (u64)0 - swap);
  p256pt_jac_to_affine(r, &r0);
}
