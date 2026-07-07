#include "crypto/symmetric/aead/chacha/poly1305.h"

/* 26-bit x5 limb representation (poly1305-donna style). h is the accumulator,
 * r the clamped key half, pad the second key half added to the final tag. */
typedef struct {
  u32 r[5];
  u32 h[5];
  u32 pad[4];
} poly;

static u32 rd32le(const u8* p) {
  return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

/* Load and clamp r (RFC 8439 2.5.1) into 26-bit limbs; copy s into pad. */
static void poly_init(poly* st, const u8 key[32]) {
  u32 t0 = rd32le(key), t1 = rd32le(key + 4);
  u32 t2 = rd32le(key + 8), t3 = rd32le(key + 12);
  st->r[0] = t0 & 0x3ffffff;
  st->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
  st->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
  st->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
  st->r[4] = (t3 >> 8) & 0x00fffff;
  for (usz i = 0; i < 5; i++) st->h[i] = 0;
  for (usz i = 0; i < 4; i++) st->pad[i] = rd32le(key + 16 + 4 * i);
}

/* Add a 16-byte (zero-padded) block with the high bit `hibit` into h. */
static void poly_add(poly* st, const u8* m, u32 hibit) {
  u32 t0 = rd32le(m), t1 = rd32le(m + 4), t2 = rd32le(m + 8),
      t3 = rd32le(m + 12);
  st->h[0] += t0 & 0x3ffffff;
  st->h[1] += ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
  st->h[2] += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
  st->h[3] += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
  st->h[4] += (t3 >> 8) | hibit;
}

/* Propagate carries from the 64-bit products d[] back into 26-bit h limbs. */
static void carry_reduce(poly* st, u64 d[5]) {
  u64 c = 0;
  for (usz i = 0; i < 5; i++) {
    d[i] += c;
    st->h[i] = (u32)d[i] & 0x3ffffff;
    c        = d[i] >> 26;
  }
  st->h[0] += (u32)c * 5;
  st->h[1] += st->h[0] >> 26;
  st->h[0] &= 0x3ffffff;
}

/* Schoolbook multiply h*r mod 2^130-5, then carry-reduce into 26-bit limbs. */
static void poly_mulmod(poly* st) {
  u64 d[5];
  u32 r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3], r4 = st->r[4];
  u32 s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
  u32* h = st->h;
  d[0]   = (u64)h[0] * r0 + (u64)h[1] * s4 + (u64)h[2] * s3 + (u64)h[3] * s2 +
           (u64)h[4] * s1;
  d[1]   = (u64)h[0] * r1 + (u64)h[1] * r0 + (u64)h[2] * s4 + (u64)h[3] * s3 +
           (u64)h[4] * s2;
  d[2]   = (u64)h[0] * r2 + (u64)h[1] * r1 + (u64)h[2] * r0 + (u64)h[3] * s4 +
           (u64)h[4] * s3;
  d[3]   = (u64)h[0] * r3 + (u64)h[1] * r2 + (u64)h[2] * r1 + (u64)h[3] * r0 +
           (u64)h[4] * s4;
  d[4]   = (u64)h[0] * r4 + (u64)h[1] * r3 + (u64)h[2] * r2 + (u64)h[3] * r1 +
           (u64)h[4] * r0;
  carry_reduce(st, d);
}

/* Byte i of a final block of n message bytes: data, then 0x01, then zeros. */
static u8 pad_byte(const u8* m, usz i, usz n) {
  if (i < n) return m[i];
  return (i == n) ? 1 : 0;
}

/* Pad a final partial block: copy n bytes, append 0x01, zero the rest. */
static void poly_final_block(poly* st, const u8* m, usz n) {
  u8 b[16];
  for (usz i = 0; i < 16; i++) b[i] = pad_byte(m, i, n);
  poly_add(st, b, 0); /* hibit already provided by the 0x01 byte in b */
  poly_mulmod(st);
}

/* Absorb full 16-byte blocks (hibit set), one partial block padded with a 1. */
static void poly_blocks(poly* st, const u8* msg, usz len) {
  usz off = 0;
  while (len - off >= 16) {
    poly_add(st, msg + off, 1 << 24);
    poly_mulmod(st);
    off += 16;
  }
  if (off < len) poly_final_block(st, msg + off, len - off);
}

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
  for (usz i = 0; i < 5; i++) h[i] = (h[i] & ~mask) | (g[i] & mask);
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

void quic_poly1305(
    const u8  key[QUIC_POLY1305_KEY],
    const u8* msg,
    usz       len,
    u8        tag[QUIC_POLY1305_TAG]) {
  poly st;
  poly_init(&st, key);
  poly_blocks(&st, msg, len);
  poly_finish(&st, tag);
}
