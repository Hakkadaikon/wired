#include "crypto/symmetric/aead/gcmx86/gcmx86.h"

#include "common/arch/x8664/simd128.h"
#include "common/bytes/util/be.h"
#include "common/bytes/util/ct.h"
#include "crypto/symmetric/aead/aes/aes.h"

/* AES-128-GCM per NIST SP 800-38D on x86-64 AES-NI + PCLMULQDQ. The
 * instruction wrappers live in the arch adapter (simd128.h); this file is
 * only the GCM math on top of them. */

/* One SSE register: u8 lanes for load/store/XOR, u32 lanes for the GHASH
 * shift arithmetic (casts between same-size vector types reinterpret bits).
 */
typedef wired_arch_v128  gcmx86_v;
typedef wired_arch_v128w gcmx86_w;

/* CPUID.1:ECX bit 25 (AES-NI) and bit 1 (PCLMULQDQ). */
static int gcmx86_cpuid_ok(void) {
  u32 c = wired_arch_cpuid_ecx(1u);
  return (int)((c >> 25) & (c >> 1) & 1u);
}

int quic_gcmx86_supported(void) {
  static int cached; /* 0 unknown, 1 unsupported, 2 supported */
  if (cached == 0) cached = 1 + gcmx86_cpuid_ok();
  return cached - 1;
}

static gcmx86_v gcmx86_load(const u8* p) {
  gcmx86_v v;
  for (usz i = 0; i < 16; i++) v[i] = p[i];
  return v;
}

static void gcmx86_store(u8* p, gcmx86_v v) {
  for (usz i = 0; i < 16; i++) p[i] = v[i];
}

/* Load n (<=16) bytes byte-reversed into a GHASH operand, zero-padded.
 * GHASH treats blocks as big-endian bit strings; reversing the bytes puts
 * them in the little-endian lane order the CLMUL math below expects. */
static gcmx86_v gcmx86_load_rev(const u8* p, usz n) {
  gcmx86_v v = {0};
  for (usz i = 0; i < n; i++) v[15 - i] = p[i];
  return v;
}

/* Reverse the 16 bytes of a register (GHASH operand <-> wire order). */
static gcmx86_v gcmx86_rev(gcmx86_v a) {
  return __builtin_shufflevector(
      a, a, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
}

/* AES-128 encrypt one block with AES-NI: rounds 1..9 aesenc, 10 aesenclast.
 */
static gcmx86_v gcmx86_aes(const quic_gcmx86* x, gcmx86_v in) {
  gcmx86_v s = in ^ gcmx86_load(x->rk[0]);
  for (usz i = 1; i < 10; i++) s = wired_arch_aesenc(s, gcmx86_load(x->rk[i]));
  return wired_arch_aesenclast(s, gcmx86_load(x->rk[10]));
}

/* 256-bit carry-less product [hi:lo] = a * b (Karatsuba: three CLMULs). */
static void gcmx86_clmul256(
    gcmx86_v a, gcmx86_v b, gcmx86_v* lo, gcmx86_v* hi) {
  gcmx86_v d  = WIRED_ARCH_CLMUL(a, b, 0x00); /* a0*b0 */
  gcmx86_v c  = WIRED_ARCH_CLMUL(a, b, 0x11); /* a1*b1 */
  gcmx86_v ax = a ^ WIRED_ARCH_VSHRB(a, 8);   /* a0^a1 in the low half */
  gcmx86_v bx = b ^ WIRED_ARCH_VSHRB(b, 8);
  gcmx86_v e  = WIRED_ARCH_CLMUL(ax, bx, 0x00) ^ c ^ d; /* middle term */
  *lo         = d ^ WIRED_ARCH_VSHLB(e, 8);
  *hi         = c ^ WIRED_ARCH_VSHRB(e, 8);
}

/* Shift the 256-bit value [hi:lo] left one bit (aligns the reflected
 * carry-less product with the GHASH bit order, SP 800-38D 6.3). */
static void gcmx86_shl1_256(gcmx86_v* lo, gcmx86_v* hi) {
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
static gcmx86_v gcmx86_reduce(gcmx86_v lo, gcmx86_v hi) {
  gcmx86_w l    = (gcmx86_w)lo;
  gcmx86_w t    = (l << 31) ^ (l << 30) ^ (l << 25);
  gcmx86_v keep = WIRED_ARCH_VSHRB((gcmx86_v)t, 4);
  l ^= (gcmx86_w)WIRED_ARCH_VSHLB((gcmx86_v)t, 12);
  gcmx86_w r = (l >> 1) ^ (l >> 2) ^ (l >> 7) ^ (gcmx86_w)keep;
  return hi ^ (gcmx86_v)(l ^ r);
}

/* GF(2^128) multiply of byte-reversed GHASH operands (SP 800-38D 6.3). */
static gcmx86_v gcmx86_gfmul(gcmx86_v a, gcmx86_v b) {
  gcmx86_v lo, hi;
  gcmx86_clmul256(a, b, &lo, &hi);
  gcmx86_shl1_256(&lo, &hi);
  return gcmx86_reduce(lo, hi);
}

/* Absorb in (zero-padded to a block multiple) into the GHASH accumulator y:
 * per block, y = (y ^ block) * H. */
static gcmx86_v gcmx86_ghash(gcmx86_v h, gcmx86_v y, wired_span in) {
  usz off = 0;
  for (; off + 16 <= in.n; off += 16)
    y = gcmx86_gfmul(y ^ gcmx86_rev(gcmx86_load(in.p + off)), h);
  if (off < in.n)
    y = gcmx86_gfmul(y ^ gcmx86_load_rev(in.p + off, in.n - off), h);
  return y;
}

/* Increment the low 32 bits of a counter block big-endian (SP 800-38D 6.2).
 */
static void gcmx86_inc32(u8 j[16]) {
  for (usz i = 16; i > 12; i--)
    if (++j[i - 1] != 0) return;
}

/* Advance the counter and XOR one full keystream block into out. */
static void gcmx86_ctr_block(
    const quic_gcmx86* x, u8 j[16], const u8* in, u8* out) {
  gcmx86_inc32(j);
  gcmx86_store(out, gcmx86_load(in) ^ gcmx86_aes(x, gcmx86_load(j)));
}

/* Advance the counter and XOR the final partial block (in.n < 16). */
static void gcmx86_ctr_tail(
    const quic_gcmx86* x, u8 j[16], wired_span in, u8* out) {
  u8 ks[16];
  gcmx86_inc32(j);
  gcmx86_store(ks, gcmx86_aes(x, gcmx86_load(j)));
  for (usz i = 0; i < in.n; i++) out[i] = in.p[i] ^ ks[i];
}

/* CTR-encrypt in into out; j enters as J0 (data blocks use J0+1, J0+2, ...).
 * ponytail: one block per AES call; interleave 4-8 counter blocks if a
 * profiler ever shows the aesenc dependency chain dominating. */
static void gcmx86_ctr(const quic_gcmx86* x, u8 j[16], wired_span in, u8* out) {
  usz off = 0;
  for (; off + 16 <= in.n; off += 16)
    gcmx86_ctr_block(x, j, in.p + off, out + off);
  if (off < in.n)
    gcmx86_ctr_tail(x, j, wired_span_of(in.p + off, in.n - off), out + off);
}

/* J0 = nonce || 0x00000001 (SP 800-38D 7.1, 96-bit IV). */
static void gcmx86_j0(u8 j[16], const u8 nonce[QUIC_GCMX86_NONCE]) {
  for (usz i = 0; i < 12; i++) j[i] = nonce[i];
  j[12] = 0;
  j[13] = 0;
  j[14] = 0;
  j[15] = 1;
}

/* tag = GHASH(H; aad, ct, len block) ^ E(K, J0) (SP 800-38D 7.1). */
static void gcmx86_tag(
    const quic_gcmx86* x,
    const u8           j0[16],
    wired_span         aad,
    wired_span         ct,
    u8                 tag[16]) {
  u8       lens[16];
  gcmx86_v h = gcmx86_load_rev(x->h, 16);
  gcmx86_v y = {0};
  y          = gcmx86_ghash(h, y, aad);
  y          = gcmx86_ghash(h, y, ct);
  quic_put_be64(lens, (u64)aad.n * 8);
  quic_put_be64(lens + 8, (u64)ct.n * 8);
  y = gcmx86_gfmul(y ^ gcmx86_load_rev(lens, 16), h);
  gcmx86_store(tag, gcmx86_rev(y) ^ gcmx86_aes(x, gcmx86_load(j0)));
}

void quic_gcmx86_init(quic_gcmx86* x, const u8 key[16]) {
  quic_aes128 a;
  gcmx86_v    zero = {0};
  quic_aes128_init(&a, key); /* cold path: reuse the scalar key schedule */
  for (usz i = 0; i < QUIC_AES_RK_WORDS; i++)
    quic_put_be32((u8*)x->rk + 4 * i, a.rk[i]); /* be words = FIPS bytes */
  gcmx86_store(x->h, gcmx86_aes(x, zero));      /* H = E(K, 0^128), 6.4 */
}

usz quic_gcmx86_seal(
    const quic_gcmx86* x,
    const u8           nonce[QUIC_GCMX86_NONCE],
    wired_span         aad,
    wired_span         pt,
    u8*                out) {
  u8 j0[16], j[16];
  gcmx86_j0(j0, nonce);
  for (usz i = 0; i < 16; i++) j[i] = j0[i];
  gcmx86_ctr(x, j, pt, out);
  gcmx86_tag(x, j0, aad, wired_span_of(out, pt.n), out + pt.n);
  return pt.n + QUIC_GCMX86_TAG;
}

usz quic_gcmx86_open(
    const quic_gcmx86* x,
    const u8           nonce[QUIC_GCMX86_NONCE],
    wired_span         aad,
    wired_span         ct,
    u8*                out) {
  u8 j[16], want[16];
  if (ct.n < QUIC_GCMX86_TAG) return 0;
  wired_span body = wired_span_of(ct.p, ct.n - QUIC_GCMX86_TAG);
  gcmx86_j0(j, nonce);
  gcmx86_tag(x, j, aad, body, want);
  if (quic_ct_diff16(want, ct.p + body.n) != 0)
    return 0; /* reject: leave out untouched */
  gcmx86_ctr(x, j, body, out);
  return body.n;
}
