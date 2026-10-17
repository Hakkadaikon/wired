#ifndef CRYPTO_SYMMETRIC_AEAD_GCM_GCM_IMPL_HEAD_H
#define CRYPTO_SYMMETRIC_AEAD_GCM_GCM_IMPL_HEAD_H

/* Internal to the gcm*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "common/bytes/util/be.h"
#include "common/bytes/util/ct.h"
#include "crypto/symmetric/aead/gcm/gcm.h"
#include "crypto/symmetric/aead/gcm/gcm256.h"
#include "crypto/symmetric/aead/gcmx86/gcmx86.h"

/* AES-NI/PCLMULQDQ dispatch for AES-128-GCM (RFC 9001 5.3 uses the same AEAD
 * regardless of which block-cipher backend computes it). Nonce/tag sizes
 * must agree between the two paths for the dispatch below to be transparent. */
_Static_assert(GCM_NONCE == GCMX86_NONCE, "gcm/gcmx86 nonce size");

_Static_assert(GCM_TAG == GCMX86_TAG, "gcm/gcmx86 tag size");

/* AES-CTR keystream state: key schedule plus the running counter block. */
typedef struct {
  const aes128* a;
  u8            ctr[16];
} gcm_ctr;

/* Per-invocation GHASH state: the inputs plus H = E(K, 0^128) and J0. */
typedef struct {
  const gcm_ctx* g;
  u8             h[16];
  u8             j0[16];
} gcm_st;

/* AES-256-GCM (RFC 8446 Appendix B.4, 0x1302). Same mode of operation as
 * AES-128-GCM above; only the block cipher call (aes256_encrypt) and
 * the types carrying it differ. GHASH/counter helpers (gcm_ghash_bytes,
 * gcm_ghash_block, gcm_ctr_inc, gcm_put_be64) are shared, not duplicated. */

/* AES-256-CTR keystream state: key schedule plus the running counter block. */
typedef struct {
  const aes256* a;
  u8            ctr[16];
} gcm256_ctr;

/* Per-invocation GHASH state: the inputs plus H = E(K, 0^128) and J0. */
typedef struct {
  const gcm256_ctx* g;
  u8                h[16];
  u8                j0[16];
} gcm256_st;

void gcm_setup(const gcm_ctx* g, gcm_st* st);

/* Forward declarations: the inline definitions below are unordered. */
static inline usz  block_n(usz off, usz len);
static inline void load_block(u8 b[16], const u8* p, usz off, usz len);
static inline usz  ctr_chunk(gcm_ctr* c, wired_span in, u8* out);
static inline void shr1(u8 x[16]);
static inline void gf_step(u8 z[16], u8 v[16], u8 mask);
static inline void gcm_xor16(u8* dst, const u8* src);
static inline void gcm_gf_mul(const u8 x[16], const u8 y[16], u8 z[16]);
static inline void gcm_ghash_block(const u8 h[16], u8 y[16], const u8* block);
static inline void gcm_put_be64(u8* p, u64 v);
static inline void gcm_ctr_inc(u8 c[16]);
static inline void gcm_ctr_xor(gcm_ctr* c, wired_span in, u8* out);
static inline void gcm_ghash_bytes(
    const u8 h[16], u8 y[16], const u8* p, usz len);

/* Bytes remaining at off, capped at one block. */
static inline usz block_n(usz off, usz len) {
  return (len - off < 16) ? len - off : 16;
}

/* Copy up to 16 bytes from p+off into b, zero-padding the rest. */
static inline void load_block(u8 b[16], const u8* p, usz off, usz len) {
  usz n = block_n(off, len);
  for (usz i = 0; i < 16; i++) {
    b[i] = (i < n) ? p[off + i] : 0;
  }
}

/* XOR up to 16 keystream bytes E(K,ctr) into out; returns bytes done. */
static inline usz ctr_chunk(gcm_ctr* c, wired_span in, u8* out) {
  u8  ks[16];
  usz n = (in.n < 16) ? in.n : 16;
  aes128_encrypt(c->a, c->ctr, ks);
  for (usz i = 0; i < n; i++) {
    out[i] = in.p[i] ^ ks[i];
  }
  gcm_ctr_inc(c->ctr);
  return n;
}

/* Shift a 128-bit big-endian value right by one bit. */
static inline void shr1(u8 x[16]) {
  for (usz i = 15; i > 0; i--) {
    x[i] = (u8)((x[i] >> 1) | (x[i - 1] << 7));
  }
  x[0] >>= 1;
}

/* z ^= v & mask (per-byte), then v = (v >> 1) reduced by R when its LSB set. */
static inline void gf_step(u8 z[16], u8 v[16], u8 mask) {
  for (usz j = 0; j < 16; j++) {
    z[j] ^= v[j] & mask;
  }
  u8 lsb = (u8) - (v[15] & 1);
  shr1(v);
  v[0] ^= 0xe1 & lsb;
}

/* XOR 16 bytes of src into dst. */
static inline void gcm_xor16(u8* dst, const u8* src) {
  for (usz i = 0; i < 16; i++) {
    dst[i] ^= src[i];
  }
}
/* GF(2^128) multiply z = x * y per SP 800-38D (bit-reflected polynomial
 * R = 0xe1 in the high byte). y is consumed. */
static inline void gcm_gf_mul(const u8 x[16], const u8 y[16], u8 z[16]) {
  u8 v[16];
  for (usz i = 0; i < 16; i++) {
    z[i] = 0;
    v[i] = x[i];
  }
  for (usz bit = 0; bit < 128; bit++) {
    gf_step(z, v, (u8) - ((y[bit / 8] >> (7 - bit % 8)) & 1));
  }
}

#endif
