#include "crypto/asymmetric/ecc/p521/p521_field_impl.h"

static void fe9_cond_sub(p521_fe r, const p521_fe m);
static void fe9_mul_row(u64 w[18], u64 ai, const p521_fe b, usz i);
static void fe9_fold_top(p521_fe r);

/* 1 if a >= b (limb 8 most significant). */
int fp521_fe9_ge(const p521_fe a, const p521_fe b) {
  for (usz i = 9; i-- > 0;) {
    if (a[i] != b[i]) {
      return a[i] > b[i];
    }
  }
  return 1;
}

int fp521_lt(const p521_fe a, const p521_fe b) { return !fp521_fe9_ge(a, b); }

/* r = a - b, final borrow dropped (callers ensure a >= b). */
void fp521_fe9_sub_raw(p521_fe r, const p521_fe a, const p521_fe b) {
  unsigned __int128 br = 0;
  for (usz i = 0; i < 9; i++) {
    unsigned __int128 t = (unsigned __int128)a[i] - b[i] - br;
    r[i]                = (u64)t;
    br                  = (t >> 64) & 1;
  }
}

/* r = a + b; operands stay below 2^523, so 576 bits never carry out. */
void fp521_fe9_add_raw(p521_fe r, const p521_fe a, const p521_fe b) {
  unsigned __int128 c = 0;
  for (usz i = 0; i < 9; i++) {
    c += (unsigned __int128)a[i] + b[i];
    r[i] = (u64)c;
    c >>= 64;
  }
}

static void fe9_cond_sub(p521_fe r, const p521_fe m) {
  if (fp521_fe9_ge(r, m)) {
    fp521_fe9_sub_raw(r, r, m);
  }
}

void fp521_add(p521_fe r, const p521_fe a, const p521_fe b, const p521_fe m) {
  fp521_fe9_add_raw(r, a, b);
  fe9_cond_sub(r, m);
}

/* a + m - b lies in [1, 2m), so one conditional subtraction reduces it. */
void fp521_sub(p521_fe r, const p521_fe a, const p521_fe b, const p521_fe m) {
  p521_fe t;
  fp521_fe9_add_raw(t, a, m);
  fp521_fe9_sub_raw(t, t, b);
  fe9_cond_sub(t, m);
  fp521_set(r, t);
}

/* w[i..i+9] += ai * b: one row of the schoolbook product. */
static void fe9_mul_row(u64 w[18], u64 ai, const p521_fe b, usz i) {
  unsigned __int128 c = 0;
  for (usz j = 0; j < 9; j++) {
    c += (unsigned __int128)ai * b[j] + w[i + j];
    w[i + j] = (u64)c;
    c >>= 64;
  }
  w[i + 9] = (u64)c;
}

/* r < 2^522 -> r < p: 2^521 == 1 (mod p), so bit 521 folds onto bit 0. */
static void fe9_fold_top(p521_fe r) {
  p521_fe c = {r[8] >> 9};
  r[8] &= 0x1ff;
  fp521_fe9_add_raw(r, r, c);
  fe9_cond_sub(r, p521_p);
}

/* p = 2^521 - 1: w = hi*2^521 + lo == hi + lo (mod p). */
void fp521_mul_p(p521_fe r, const p521_fe a, const p521_fe b) {
  u64     w[18] = {0};
  p521_fe hi;
  for (usz i = 0; i < 9; i++) {
    fe9_mul_row(w, a[i], b, i);
  }
  for (usz i = 0; i < 9; i++) {
    r[i]  = w[i];
    hi[i] = (w[8 + i] >> 9) | (w[9 + i] << 55);
  }
  r[8] &= 0x1ff;
  fp521_fe9_add_raw(r, r, hi);
  fe9_fold_top(r);
}
