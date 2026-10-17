#include "crypto/symmetric/aead/chacha/poly1305_impl.h"

static void poly_add(poly* st, const u8* m, u32 hibit);
static void carry_reduce(poly* st, u64 d[5]);
static u64  poly_row(const u32 h[5], u32 a, u32 b, u32 c, u32 d, u32 e);
static void poly_mulmod(poly* st);
static u8   pad_byte(const u8* m, usz i, usz n);
static void poly_final_block(poly* st, const u8* m, usz n);

/* Add a 16-byte (zero-padded) block with the high bit `hibit` into h. */
static void poly_add(poly* st, const u8* m, u32 hibit) {
  u32 t0 = poly1305_rd32le(m), t1 = poly1305_rd32le(m + 4),
      t2 = poly1305_rd32le(m + 8), t3 = poly1305_rd32le(m + 12);
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

/* One schoolbook row: h[0]*a + h[1]*b + h[2]*c + h[3]*d + h[4]*e. */
static u64 poly_row(const u32 h[5], u32 a, u32 b, u32 c, u32 d, u32 e) {
  return (u64)h[0] * a + (u64)h[1] * b + (u64)h[2] * c + (u64)h[3] * d +
         (u64)h[4] * e;
}

/* Schoolbook multiply h*r mod 2^130-5, then carry-reduce into 26-bit limbs. */
static void poly_mulmod(poly* st) {
  u64        d[5];
  const u32* r  = st->r;
  const u32* h  = st->h;
  u32        s1 = r[1] * 5, s2 = r[2] * 5, s3 = r[3] * 5, s4 = r[4] * 5;
  d[0] = poly_row(h, r[0], s4, s3, s2, s1);
  d[1] = poly_row(h, r[1], r[0], s4, s3, s2);
  d[2] = poly_row(h, r[2], r[1], r[0], s4, s3);
  d[3] = poly_row(h, r[3], r[2], r[1], r[0], s4);
  d[4] = poly_row(h, r[4], r[3], r[2], r[1], r[0]);
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
void poly_blocks(poly* st, const u8* msg, usz len) {
  usz off = 0;
  while (len - off >= 16) {
    poly_add(st, msg + off, 1 << 24);
    poly_mulmod(st);
    off += 16;
  }
  if (off < len) poly_final_block(st, msg + off, len - off);
}
