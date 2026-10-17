#include "crypto/asymmetric/ecc/p384/p384_field_impl.h"

static void mont6_from(p384_fe r, const p384_fe a, const mont384* mont);

static void mont6_from(p384_fe r, const p384_fe a, const mont384* mont) {
  p384_fe one = {1, 0, 0, 0, 0, 0};
  mont384_mul(r, (fp384ab){a, one}, mont);
}

void mont384_inv(p384_fe r, const p384_fe a, const mont384* mont) {
  p384_fe e, base, acc, two = {2, 0, 0, 0, 0, 0};
  fp384_fe6_sub_raw(e, mont->m, two);
  mont384_mul(base, (fp384ab){a, mont->rr}, mont);
  fp384_set(acc, mont->one);
  for (usz bit = 0; bit < 384; bit++) {
    if (fp384_ebit(e, bit)) {
      mont384_mul(acc, (fp384ab){acc, base}, mont);
    }
    mont384_mul(base, (fp384ab){base, base}, mont);
  }
  mont6_from(r, acc, mont);
}

void fp384_from_be(p384_fe r, const u8 b[48]) {
  for (usz i = 0; i < 6; i++) {
    u64 v = 0;
    for (usz j = 0; j < 8; j++) {
      v = (v << 8) | b[i * 8 + j];
    }
    r[5 - i] = v;
  }
}

void fp384_to_be(u8 b[48], const p384_fe a) {
  for (usz i = 0; i < 6; i++) {
    for (usz j = 0; j < 8; j++) {
      b[i * 8 + j] = (u8)(a[5 - i] >> (56 - 8 * j));
    }
  }
}
