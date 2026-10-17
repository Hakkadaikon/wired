#include "crypto/symmetric/aead/chacha/poly1305_impl.h"

static void full_carry(u32 h[5]);
static void plus_five(const u32 h[5], u32 g[5]);
static void select_mod(u32 h[5], const u32 g[5]);
static void pack(const u32 h[5], u32 w[4]);
static void poly_finish(poly* st, u8 tag[16]);

/* Fully carry h so each limb is < 2^26. */
static void full_carry(u32 h[5]) {
  for (usz i = 1; i < 5; i++) {
    h[i] += h[i - 1] >> 26;
    h[i - 1] &= 0x3ffffff;
  }
  h[0] += (h[4] >> 26) * 5;
  h[1] += h[0] >> 26;
  h[0] &= 0x3ffffff;
  h[4] &= 0x3ffffff;
}

/* Compute g = h + 5 (the candidate for h >= 2^130-5) into g[5]. */
static void plus_five(const u32 h[5], u32 g[5]) {
  u32 c = 5;
  for (usz i = 0; i < 5; i++) {
    g[i] = h[i] + c;
    c    = g[i] >> 26;
    g[i] &= 0x3ffffff;
  }
  g[4] -= (1 << 26); /* subtract 2^130 to complete mod-(2^130-5) test */
}

/* Select g if h >= 2^130-5 (i.e. g did not borrow), else keep h. */
static void select_mod(u32 h[5], const u32 g[5]) {
  u32 mask = (g[4] >> 31) - 1; /* all-ones if no borrow */
  for (usz i = 0; i < 5; i++) {
    h[i] = (h[i] & ~mask) | (g[i] & mask);
  }
}

/* Pack the 5 26-bit limbs into four 32-bit words. */
static void pack(const u32 h[5], u32 w[4]) {
  w[0] = h[0] | (h[1] << 26);
  w[1] = (h[1] >> 6) | (h[2] << 20);
  w[2] = (h[2] >> 12) | (h[3] << 14);
  w[3] = (h[3] >> 18) | (h[4] << 8);
}

/* Final reduction and tag = (h + pad) mod 2^128, serialized little-endian. */
static void poly_finish(poly* st, u8 tag[16]) {
  u32 g[5], w[4];
  u64 f = 0;
  full_carry(st->h);
  plus_five(st->h, g);
  select_mod(st->h, g);
  pack(st->h, w);
  for (usz i = 0; i < 4; i++) {
    f += (u64)w[i] + st->pad[i];
    tag[4 * i]     = (u8)f;
    tag[4 * i + 1] = (u8)(f >> 8);
    tag[4 * i + 2] = (u8)(f >> 16);
    tag[4 * i + 3] = (u8)(f >> 24);
    f >>= 32;
  }
}

void poly1305(
    const u8 key[POLY1305_KEY], const u8* msg, usz len, u8 tag[POLY1305_TAG]) {
  poly st;
  poly_init(&st, key);
  poly_blocks(&st, msg, len);
  poly_finish(&st, tag);
}
