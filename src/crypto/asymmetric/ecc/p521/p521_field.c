#include "crypto/asymmetric/ecc/p521/p521_field_impl.h"

/* FIPS 186-4 D.1.2.5 (cross-checked against `openssl ecparam -name
 * secp521r1 -param_enc explicit`). */
const p521_fe p521_p = {~0ULL, ~0ULL, ~0ULL, ~0ULL,   ~0ULL,
                        ~0ULL, ~0ULL, ~0ULL, 0x1ffULL};

const p521_fe p521_n = {
    0xbb6fb71e91386409ULL, 0x3bb5c9b8899c47aeULL, 0x7fcc0148f709a5d0ULL,
    0x51868783bf2f966bULL, 0xfffffffffffffffaULL, 0xffffffffffffffffULL,
    0xffffffffffffffffULL, 0xffffffffffffffffULL, 0x00000000000001ffULL};

const p521_fe fp521_one = {1};

void fp521_set(p521_fe r, const p521_fe a) {
  for (usz i = 0; i < 9; i++) r[i] = a[i];
}

int fp521_is_zero(const p521_fe a) {
  u64 d = 0;
  for (usz i = 0; i < 9; i++) d |= a[i];
  return d == 0;
}

int fp521_eq(const p521_fe a, const p521_fe b) {
  u64 d = 0;
  for (usz i = 0; i < 9; i++) d |= a[i] ^ b[i];
  return d == 0;
}
