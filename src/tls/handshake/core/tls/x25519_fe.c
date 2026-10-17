#include "tls/handshake/core/tls/x25519_impl.h"

static void x25519_store_reduced(u8* s, const fe r);
static void x25519_carry_pass(fe r);
static void x25519_carry_final(fe r);

/* Load 32 little-endian bytes into limbs (top bit of byte 31 is cleared). */
void x25519_fe_frombytes(fe h, const u8* s) {
  u64 t[4];
  for (usz i = 0; i < 4; i++) {
    t[i] = 0;
    for (usz j = 0; j < 8; j++) {
      t[i] |= (u64)s[i * 8 + j] << (8 * j);
    }
  }
  h[0] = t[0] & MASK51;
  h[1] = ((t[0] >> 51) | (t[1] << 13)) & MASK51;
  h[2] = ((t[1] >> 38) | (t[2] << 26)) & MASK51;
  h[3] = ((t[2] >> 25) | (t[3] << 39)) & MASK51;
  h[4] = (t[3] >> 12) & MASK51;
}

/* Pack five reduced 51-bit limbs into 32 little-endian bytes. */
static void x25519_store_reduced(u8* s, const fe r) {
  u64 w[4];
  w[0] = r[0] | (r[1] << 51);
  w[1] = (r[1] >> 13) | (r[2] << 38);
  w[2] = (r[2] >> 26) | (r[3] << 25);
  w[3] = (r[3] >> 39) | (r[4] << 12);
  for (usz i = 0; i < 4; i++) {
    for (usz j = 0; j < 8; j++) {
      s[i * 8 + j] = (u8)(w[i] >> (8 * j));
    }
  }
}

/* One weak-carry pass: every limb < 2^51, top carry folded by 19. */
static void x25519_carry_pass(fe r) {
  u64 c = 0;
  for (usz i = 0; i < 5; i++) {
    r[i] += c;
    c = r[i] >> 51;
    r[i] &= MASK51;
  }
  r[0] += c * 19;
}

/* Final carry after the conditional +19: propagate carries and DISCARD the
 * 2^255 overflow bit (that bit is exactly the p we conditionally subtracted).
 * Folding it back by 19 (as the weak pass does) would re-add p and leave the
 * result 19 short — the bug that made r==p reduce to 19 instead of 0. */
static void x25519_carry_final(fe r) {
  u64 c = 0;
  for (usz i = 0; i < 5; i++) {
    r[i] += c;
    c = r[i] >> 51;
    r[i] &= MASK51;
  }
}

/* Fully reduce h mod p and store 32 little-endian bytes. h's limbs come in
 * below 2^52 (weak-reduced), so two weak passes bring r into [0, 2p). */
void x25519_fe_tobytes(u8* s, const fe h) {
  fe  r;
  u64 q;
  x25519_fe_copy(r, h);
  x25519_carry_pass(r);
  x25519_carry_pass(r);
  q = (r[0] + 19) >> 51; /* q==1 iff r >= p (adding 19 overflows 2^255) */
  for (usz i = 1; i < 5; i++) {
    q = (r[i] + q) >> 51;
  }
  r[0] += 19 * q;        /* if r >= p, +19 pushes past 2^255 = subtract p */
  x25519_carry_final(r); /* drop the 2^255 carry instead of folding it */
  x25519_store_reduced(s, r);
}

/* One Montgomery x25519_ladder step on st with difference x1. */
void x25519_ladder_step(ladder_state* st, const fe x1) {
  fe a, b, c, d, e, da, cb;
  x25519_fe_add(a, st->x2, st->z2);
  x25519_fe_sub(b, st->x2, st->z2);
  x25519_fe_add(c, st->x3, st->z3);
  x25519_fe_sub(d, st->x3, st->z3);
  x25519_fe_mul(da, d, a);
  x25519_fe_mul(cb, c, b);
  x25519_fe_add(st->x3, da, cb);
  x25519_fe_sq(st->x3, st->x3);
  x25519_fe_sub(st->z3, da, cb);
  x25519_fe_sq(st->z3, st->z3);
  x25519_fe_mul(st->z3, st->z3, x1);
  x25519_fe_sq(a, a);
  x25519_fe_sq(b, b);
  x25519_fe_mul(st->x2, a, b);
  x25519_fe_sub(e, a, b);
  x25519_fe_mul121666(da, e);
  x25519_fe_add(da, da, b);
  x25519_fe_mul(st->z2, e, da);
}
