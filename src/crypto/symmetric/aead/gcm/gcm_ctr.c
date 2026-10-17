#include "crypto/symmetric/aead/gcm/gcm_impl.h"

static usz  block_n(usz off, usz len);
static void load_block(u8 b[16], const u8* p, usz off, usz len);
static usz  ctr_chunk(gcm_ctr* c, wired_span in, u8* out);

/* Absorb one 16-byte block into the GHASH accumulator y (y ^= block; y *= H).
 */
void gcm_ghash_block(const u8 h[16], u8 y[16], const u8* block) {
  u8 hk[16], out[16];
  gcm_xor16(y, block);
  for (usz i = 0; i < 16; i++) hk[i] = h[i];
  gcm_gf_mul(y, hk, out);
  for (usz i = 0; i < 16; i++) y[i] = out[i];
}

/* Bytes remaining at off, capped at one block. */
static usz block_n(usz off, usz len) {
  return (len - off < 16) ? len - off : 16;
}

/* Copy up to 16 bytes from p+off into b, zero-padding the rest. */
static void load_block(u8 b[16], const u8* p, usz off, usz len) {
  usz n = block_n(off, len);
  for (usz i = 0; i < 16; i++) b[i] = (i < n) ? p[off + i] : 0;
}

/* Absorb len bytes (zero-padded to a block multiple) into GHASH. */
void gcm_ghash_bytes(const u8 h[16], u8 y[16], const u8* p, usz len) {
  usz off = 0;
  while (off < len) {
    u8 b[16];
    load_block(b, p, off, len);
    gcm_ghash_block(h, y, b);
    off += 16;
  }
}

/* Big-endian 64-bit store. */
void gcm_put_be64(u8* p, u64 v) {
  for (usz i = 0; i < 8; i++) p[i] = (u8)(v >> (56 - i * 8));
}

/* Increment the low 32 bits of a counter block (GCM uses a 32-bit counter). */
void gcm_ctr_inc(u8 c[16]) {
  for (usz i = 16; i > 12; i--)
    if (++c[i - 1] != 0) return;
}

/* XOR up to 16 keystream bytes E(K,ctr) into out; returns bytes done. */
static usz ctr_chunk(gcm_ctr* c, wired_span in, u8* out) {
  u8  ks[16];
  usz n = (in.n < 16) ? in.n : 16;
  aes128_encrypt(c->a, c->ctr, ks);
  for (usz i = 0; i < n; i++) out[i] = in.p[i] ^ ks[i];
  gcm_ctr_inc(c->ctr);
  return n;
}

/* XOR keystream E(K, counter) over in, advancing the counter. */
void gcm_ctr_xor(gcm_ctr* c, wired_span in, u8* out) {
  usz off = 0;
  while (off < in.n)
    off += ctr_chunk(c, wired_span_of(in.p + off, in.n - off), out + off);
}

/* Build H = E(K, 0^128) and J0 = nonce || 0x00000001. */
void gcm_setup(const gcm_ctx* g, gcm_st* st) {
  u8 zero[16];
  st->g = g;
  for (usz i = 0; i < 16; i++) zero[i] = 0;
  aes128_encrypt(g->aes, zero, st->h);
  for (usz i = 0; i < 12; i++) st->j0[i] = g->nonce[i];
  st->j0[12] = 0;
  st->j0[13] = 0;
  st->j0[14] = 0;
  st->j0[15] = 1;
}
