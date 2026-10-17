#include "crypto/asymmetric/ecc/p256/p256_field_impl.h"

void p256_fp_from_be(p256_fe r, const u8 b[32]) {
  for (usz i = 0; i < 4; i++) {
    u64 v = 0;
    for (usz j = 0; j < 8; j++) {
      v = (v << 8) | b[i * 8 + j];
    }
    r[3 - i] = v;
  }
}

void p256_fp_to_be(u8 b[32], const p256_fe a) {
  for (usz i = 0; i < 4; i++) {
    for (usz j = 0; j < 8; j++) {
      b[i * 8 + j] = (u8)(a[3 - i] >> (56 - 8 * j));
    }
  }
}
