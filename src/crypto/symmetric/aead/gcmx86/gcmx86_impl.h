#ifndef CRYPTO_SYMMETRIC_AEAD_GCMX86_GCMX86_IMPL_H
#define CRYPTO_SYMMETRIC_AEAD_GCMX86_GCMX86_IMPL_H

/* Internal to the gcmx86*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "common/arch/x8664/simd128.h"
#include "common/bytes/util/be.h"
#include "common/bytes/util/ct.h"
#include "crypto/symmetric/aead/aes/aes.h"
#include "crypto/symmetric/aead/gcmx86/gcmx86.h"

/* AES-128-GCM per NIST SP 800-38D on x86-64 AES-NI + PCLMULQDQ. The
 * instruction wrappers live in the arch adapter (simd128.h); this file is
 * only the GCM math on top of them. */

/* One SSE register: u8 lanes for load/store/XOR, u32 lanes for the GHASH
 * shift arithmetic (casts between same-size vector types reinterpret bits).
 */
typedef wired_arch_v128 gcmx86_v;

typedef wired_arch_v128w gcmx86_w;

void gcmx86_ctr_tail(const gcmx86* x, u8 j[16], wired_span in, u8* out);
void gcmx86_ctr(const gcmx86* x, u8 j[16], wired_span in, u8* out);
void gcmx86_j0(u8 j[16], const u8 nonce[GCMX86_NONCE]);
void gcmx86_tag(
    const gcmx86* x,
    const u8      j0[16],
    wired_span    aad,
    wired_span    ct,
    u8            tag[16]);

/* Forward declarations: the inline definitions below are unordered. */
static inline void     gcmx86_shl1_256(gcmx86_v* lo, gcmx86_v* hi);
static inline gcmx86_v gcmx86_reduce(gcmx86_v lo, gcmx86_v hi);
static inline void     gcmx86_clmul256(
    gcmx86_v a, gcmx86_v b, gcmx86_v* lo, gcmx86_v* hi);
static inline gcmx86_v gcmx86_load(const u8* p);
static inline void     gcmx86_store(u8* p, gcmx86_v v);
static inline gcmx86_v gcmx86_load_rev(const u8* p, usz n);
static inline gcmx86_v gcmx86_rev(gcmx86_v a);
static inline gcmx86_v gcmx86_aes(const gcmx86* x, gcmx86_v in);
static inline gcmx86_v gcmx86_gfmul(gcmx86_v a, gcmx86_v b);
static inline gcmx86_v gcmx86_ghash(gcmx86_v h, gcmx86_v y, wired_span in);
static inline void     gcmx86_inc32(u8 j[16]);
static inline void     gcmx86_ctr_block(
    const gcmx86* x, u8 j[16], const u8* in, u8* out);

/* Shift the 256-bit value [hi:lo] left one bit (aligns the reflected
 * carry-less product with the GHASH bit order, SP 800-38D 6.3). */
static inline void gcmx86_shl1_256(gcmx86_v* lo, gcmx86_v* hi) {
  gcmx86_w l  = (gcmx86_w)*lo;
  gcmx86_w h  = (gcmx86_w)*hi;
  gcmx86_w cl = l >> 31; /* per-lane carry bits */
  gcmx86_w ch = h >> 31;
  *lo         = (gcmx86_v)(l << 1) | WIRED_ARCH_VSHLB((gcmx86_v)cl, 4);
  *hi         = (gcmx86_v)(h << 1) | WIRED_ARCH_VSHLB((gcmx86_v)ch, 4) |
                WIRED_ARCH_VSHRB((gcmx86_v)cl, 12);
}

/* Reduce [hi:lo] modulo x^128 + x^7 + x^2 + x + 1 in the bit-reflected
 * representation (NIST SP 800-38D 6.3; shift-based reduction from Intel's
 * CLMUL white paper). */
static inline gcmx86_v gcmx86_reduce(gcmx86_v lo, gcmx86_v hi) {
  gcmx86_w l    = (gcmx86_w)lo;
  gcmx86_w t    = (l << 31) ^ (l << 30) ^ (l << 25);
  gcmx86_v keep = WIRED_ARCH_VSHRB((gcmx86_v)t, 4);
  l ^= (gcmx86_w)WIRED_ARCH_VSHLB((gcmx86_v)t, 12);
  gcmx86_w r = (l >> 1) ^ (l >> 2) ^ (l >> 7) ^ (gcmx86_w)keep;
  return hi ^ (gcmx86_v)(l ^ r);
}

/* 256-bit carry-less product [hi:lo] = a * b (Karatsuba: three CLMULs). */
static inline void gcmx86_clmul256(
    gcmx86_v a, gcmx86_v b, gcmx86_v* lo, gcmx86_v* hi) {
  gcmx86_v d  = WIRED_ARCH_CLMUL(a, b, 0x00); /* a0*b0 */
  gcmx86_v c  = WIRED_ARCH_CLMUL(a, b, 0x11); /* a1*b1 */
  gcmx86_v ax = a ^ WIRED_ARCH_VSHRB(a, 8);   /* a0^a1 in the low half */
  gcmx86_v bx = b ^ WIRED_ARCH_VSHRB(b, 8);
  gcmx86_v e  = WIRED_ARCH_CLMUL(ax, bx, 0x00) ^ c ^ d; /* middle term */
  *lo         = d ^ WIRED_ARCH_VSHLB(e, 8);
  *hi         = c ^ WIRED_ARCH_VSHRB(e, 8);
}

static inline gcmx86_v gcmx86_load(const u8* p) {
  gcmx86_v v;
  for (usz i = 0; i < 16; i++) {
    v[i] = p[i];
  }
  return v;
}
static inline void gcmx86_store(u8* p, gcmx86_v v) {
  for (usz i = 0; i < 16; i++) {
    p[i] = v[i];
  }
}
/* Load n (<=16) bytes byte-reversed into a GHASH operand, zero-padded.
 * GHASH treats blocks as big-endian bit strings; reversing the bytes puts
 * them in the little-endian lane order the CLMUL math below expects. */
static inline gcmx86_v gcmx86_load_rev(const u8* p, usz n) {
  gcmx86_v v = {0};
  for (usz i = 0; i < n; i++) {
    v[15 - i] = p[i];
  }
  return v;
}
/* Reverse the 16 bytes of a register (GHASH operand <-> wire order). */
static inline gcmx86_v gcmx86_rev(gcmx86_v a) {
  return __builtin_shufflevector(
      a, a, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
}
/* AES-128 encrypt one block with AES-NI: rounds 1..9 aesenc, 10 aesenclast.
 */
static inline gcmx86_v gcmx86_aes(const gcmx86* x, gcmx86_v in) {
  gcmx86_v s = in ^ gcmx86_load(x->rk[0]);
  for (usz i = 1; i < 10; i++) {
    s = wired_arch_aesenc(s, gcmx86_load(x->rk[i]));
  }
  return wired_arch_aesenclast(s, gcmx86_load(x->rk[10]));
}
/* GF(2^128) multiply of byte-reversed GHASH operands (SP 800-38D 6.3). */
static inline gcmx86_v gcmx86_gfmul(gcmx86_v a, gcmx86_v b) {
  gcmx86_v lo, hi;
  gcmx86_clmul256(a, b, &lo, &hi);
  gcmx86_shl1_256(&lo, &hi);
  return gcmx86_reduce(lo, hi);
}
/* Absorb in (zero-padded to a block multiple) into the GHASH accumulator y:
 * per block, y = (y ^ block) * H. */
static inline gcmx86_v gcmx86_ghash(gcmx86_v h, gcmx86_v y, wired_span in) {
  usz off = 0;
  for (; off + 16 <= in.n; off += 16) {
    y = gcmx86_gfmul(y ^ gcmx86_rev(gcmx86_load(in.p + off)), h);
  }
  if (off < in.n) {
    y = gcmx86_gfmul(y ^ gcmx86_load_rev(in.p + off, in.n - off), h);
  }
  return y;
}
/* Increment the low 32 bits of a counter block big-endian (SP 800-38D 6.2).
 */
static inline void gcmx86_inc32(u8 j[16]) {
  for (usz i = 16; i > 12; i--) {
    if (++j[i - 1] != 0) {
      return;
    }
  }
}
/* Advance the counter and XOR one full keystream block into out. */
static inline void gcmx86_ctr_block(
    const gcmx86* x, u8 j[16], const u8* in, u8* out) {
  gcmx86_inc32(j);
  gcmx86_store(out, gcmx86_load(in) ^ gcmx86_aes(x, gcmx86_load(j)));
}

#endif
