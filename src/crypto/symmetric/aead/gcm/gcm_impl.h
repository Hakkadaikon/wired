#ifndef CRYPTO_SYMMETRIC_AEAD_GCM_GCM_IMPL_H
#define CRYPTO_SYMMETRIC_AEAD_GCM_GCM_IMPL_H

#include "crypto/symmetric/aead/gcm/gcm_impl_head.h"

/* Absorb one 16-byte block into the GHASH accumulator y (y ^= block; y *= H).
 */
static inline void gcm_ghash_block(const u8 h[16], u8 y[16], const u8* block) {
  u8 hk[16], out[16];
  gcm_xor16(y, block);
  for (usz i = 0; i < 16; i++) hk[i] = h[i];
  gcm_gf_mul(y, hk, out);
  for (usz i = 0; i < 16; i++) y[i] = out[i];
}
/* Big-endian 64-bit store. */
static inline void gcm_put_be64(u8* p, u64 v) {
  for (usz i = 0; i < 8; i++) p[i] = (u8)(v >> (56 - i * 8));
}
/* Increment the low 32 bits of a counter block (GCM uses a 32-bit counter). */
static inline void gcm_ctr_inc(u8 c[16]) {
  for (usz i = 16; i > 12; i--)
    if (++c[i - 1] != 0) return;
}

/* XOR keystream E(K, counter) over in, advancing the counter. */
static inline void gcm_ctr_xor(gcm_ctr* c, wired_span in, u8* out) {
  usz off = 0;
  while (off < in.n)
    off += ctr_chunk(c, wired_span_of(in.p + off, in.n - off), out + off);
}
/* Absorb len bytes (zero-padded to a block multiple) into GHASH. */
static inline void gcm_ghash_bytes(
    const u8 h[16], u8 y[16], const u8* p, usz len) {
  usz off = 0;
  while (off < len) {
    u8 b[16];
    load_block(b, p, off, len);
    gcm_ghash_block(h, y, b);
    off += 16;
  }
}

#endif
