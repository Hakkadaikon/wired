#include "crypto/asymmetric/ecc/p384/p384_field_impl.h"

static u64 fe6_add_raw(p384_fe t, const p384_fe a, const p384_fe b);

/* 1 if a >= b (limb 5 most significant). */
int fp384_fe6_ge(const p384_fe a, const p384_fe b) {
  for (usz i = 6; i-- > 0;) {
    if (a[i] != b[i]) {
      return a[i] > b[i];
    }
  }
  return 1;
}

int fp384_lt(const p384_fe a, const p384_fe b) { return !fp384_fe6_ge(a, b); }

/* r = a - b assuming a >= b; ignores final borrow. */
void fp384_fe6_sub_raw(p384_fe r, const p384_fe a, const p384_fe b) {
  unsigned __int128 br = 0;
  for (usz i = 0; i < 6; i++) {
    unsigned __int128 t = (unsigned __int128)a[i] - b[i] - br;
    r[i]                = (u64)t;
    br                  = (t >> 64) & 1;
  }
}

/* t = a + b (384-bit); returns carry out of bit 383. */
static u64 fe6_add_raw(p384_fe t, const p384_fe a, const p384_fe b) {
  unsigned __int128 c = 0;
  for (usz i = 0; i < 6; i++) {
    c += (unsigned __int128)a[i] + b[i];
    t[i] = (u64)c;
    c >>= 64;
  }
  return (u64)c;
}

void fp384_add(p384_fe r, fp384ab ab, const p384_fe m) {
  p384_fe t;
  u64     carry = fe6_add_raw(t, ab.a, ab.b);
  int     over  = carry || fp384_fe6_ge(t, m);
  if (over) {
    fp384_fe6_sub_raw(r, t, m);
  } else {
    fp384_set(r, t);
  }
}

void fp384_sub(p384_fe r, fp384ab ab, const p384_fe m) {
  if (fp384_fe6_ge(ab.a, ab.b)) {
    fp384_fe6_sub_raw(r, ab.a, ab.b);
  } else {
    p384_fe t;
    fp384_fe6_sub_raw(t, ab.b, ab.a);
    fp384_fe6_sub_raw(r, m, t);
  }
}
