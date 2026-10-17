#include "crypto/asymmetric/ecc/p384/p384_field_impl.h"

/* FIPS 186-4 D.1.2.4. */
const p384_fe p384_p = {0x00000000ffffffffULL, 0xffffffff00000000ULL,
                        0xfffffffffffffffeULL, 0xffffffffffffffffULL,
                        0xffffffffffffffffULL, 0xffffffffffffffffULL};

const p384_fe p384_n = {0xecec196accc52973ULL, 0x581a0db248b0a77aULL,
                        0xc7634d81f4372ddfULL, 0xffffffffffffffffULL,
                        0xffffffffffffffffULL, 0xffffffffffffffffULL};

/* Montgomery contexts (R = 2^384). Constants precomputed in Python and
 * limb-checked. */
const mont384 p384_mont_p = {
    {0x00000000ffffffffULL, 0xffffffff00000000ULL, 0xfffffffffffffffeULL,
     0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL},
    {0xfffffffe00000001ULL, 0x0000000200000000ULL, 0xfffffffe00000000ULL,
     0x0000000200000000ULL, 0x0000000000000001ULL, 0x0000000000000000ULL},
    {0xffffffff00000001ULL, 0x00000000ffffffffULL, 0x0000000000000001ULL,
     0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL},
    0x0000000100000001ULL};

const mont384 p384_mont_n = {
    {0xecec196accc52973ULL, 0x581a0db248b0a77aULL, 0xc7634d81f4372ddfULL,
     0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL},
    {0x2d319b2419b409a9ULL, 0xff3d81e5df1aa419ULL, 0xbc3e483afcb82947ULL,
     0xd40d49174aab1cc5ULL, 0x3fb05b7a28266895ULL, 0x0c84ee012b39bf21ULL},
    {0x1313e695333ad68dULL, 0xa7e5f24db74f5885ULL, 0x389cb27e0bc8d220ULL,
     0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL},
    0x6ed46089e88fdc45ULL};

void fp384_set(p384_fe r, const p384_fe a) {
  for (usz i = 0; i < 6; i++) r[i] = a[i];
}

int fp384_is_zero(const p384_fe a) {
  u64 d = 0;
  for (usz i = 0; i < 6; i++) d |= a[i];
  return d == 0;
}

int fp384_eq(const p384_fe a, const p384_fe b) {
  u64 d = 0;
  for (usz i = 0; i < 6; i++) d |= a[i] ^ b[i];
  return d == 0;
}
