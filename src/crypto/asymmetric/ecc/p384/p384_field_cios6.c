#include "crypto/asymmetric/ecc/p384/p384_field_impl.h"

static void cios6_mul_row(u64 t[8], u64 ai, const p384_fe b);
static void cios6_reduce_row(u64 t[8], const mont384* mont);
static int  mont6_needs_sub(const u64 t[8], const p384_fe m);
static void mont6_finalize(p384_fe r, const u64 t[8], const p384_fe m);

/* --- Montgomery arithmetic over an arbitrary odd modulus (order n) ------- */

static void cios6_mul_row(u64 t[8], u64 ai, const p384_fe b) {
  unsigned __int128 c = 0;
  for (usz j = 0; j < 6; j++) {
    c += (unsigned __int128)ai * b[j] + t[j];
    t[j] = (u64)c;
    c >>= 64;
  }
  c += t[6];
  t[6] = (u64)c;
  t[7] = (u64)(c >> 64);
}

static void cios6_reduce_row(u64 t[8], const mont384* mont) {
  u64               u = t[0] * mont->n0inv;
  unsigned __int128 c = (unsigned __int128)u * mont->m[0] + t[0];
  c >>= 64;
  for (usz j = 1; j < 6; j++) {
    c += (unsigned __int128)u * mont->m[j] + t[j];
    t[j - 1] = (u64)c;
    c >>= 64;
  }
  c += t[6];
  t[5] = (u64)c;
  t[6] = t[7] + (u64)(c >> 64);
  t[7] = 0;
}

static int mont6_needs_sub(const u64 t[8], const p384_fe m) {
  return t[6] != 0 || fp384_fe6_ge(t, m);
}

static void mont6_finalize(p384_fe r, const u64 t[8], const p384_fe m) {
  int sub = mont6_needs_sub(t, m);
  for (usz i = 0; i < 6; i++) {
    r[i] = t[i];
  }
  if (sub) {
    fp384_fe6_sub_raw(r, r, m);
  }
}

void mont384_mul(p384_fe r, fp384ab ab, const mont384* mont) {
  u64 t[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  for (usz i = 0; i < 6; i++) {
    cios6_mul_row(t, ab.a[i], ab.b);
    cios6_reduce_row(t, mont);
  }
  mont6_finalize(r, t, mont->m);
}
