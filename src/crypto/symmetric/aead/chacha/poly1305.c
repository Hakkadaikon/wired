#include "crypto/symmetric/aead/chacha/poly1305_impl.h"

/* Load and clamp r (RFC 8439 2.5.1) into 26-bit limbs; copy s into pad. */
/* RFC 8439 2.5: r = key[0..16) clamped, as five 26-bit limbs. */
static void poly_clamp_r(poly* st, const u8 key[16]) {
  u32 t0 = poly1305_rd32le(key), t1 = poly1305_rd32le(key + 4);
  u32 t2 = poly1305_rd32le(key + 8), t3 = poly1305_rd32le(key + 12);
  st->r[0] = t0 & 0x3ffffff;
  st->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
  st->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
  st->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
  st->r[4] = (t3 >> 8) & 0x00fffff;
}

void poly_init(poly* st, const u8 key[32]) {
  poly_clamp_r(st, key);
  for (usz i = 0; i < 5; i++) st->h[i] = 0;
  for (usz i = 0; i < 4; i++) st->pad[i] = poly1305_rd32le(key + 16 + 4 * i);
}
