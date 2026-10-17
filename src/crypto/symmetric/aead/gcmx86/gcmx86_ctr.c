#include "crypto/symmetric/aead/gcmx86/gcmx86_impl.h"

static void gcmx86_aes4_init(const gcmx86* x, gcmx86_v s[4]);
static void gcmx86_aes4_round(const gcmx86* x, gcmx86_v s[4], usz r);
static void gcmx86_aes4_last(const gcmx86* x, gcmx86_v s[4]);
static void gcmx86_aes4(const gcmx86* x, gcmx86_v s[4]);
static void gcmx86_ctr_x4_advance(u8 j[16], gcmx86_v s[4]);
static void gcmx86_ctr_x4_store(gcmx86_v s[4], const u8* in, u8* out);
static void gcmx86_ctr_x4(const gcmx86* x, u8 j[16], const u8* in, u8* out);
static usz gcmx86_ctr_x4_all(const gcmx86* x, u8 j[16], wired_span in, u8* out);

/* AddRoundKey with rk[0] across 4 independent lanes. */
static void gcmx86_aes4_init(const gcmx86* x, gcmx86_v s[4]) {
  gcmx86_v rk0 = gcmx86_load(x->rk[0]);
  for (usz i = 0; i < 4; i++) {
    s[i] ^= rk0;
  }
}

/* One aesenc round across 4 independent lanes: all 4 aesenc issue before any
 * lane's result is consumed again, so the 4 dependency chains interleave. */
static void gcmx86_aes4_round(const gcmx86* x, gcmx86_v s[4], usz r) {
  gcmx86_v rk = gcmx86_load(x->rk[r]);
  for (usz i = 0; i < 4; i++) {
    s[i] = wired_arch_aesenc(s[i], rk);
  }
}

/* Final aesenclast round across 4 independent lanes. */
static void gcmx86_aes4_last(const gcmx86* x, gcmx86_v s[4]) {
  gcmx86_v rk = gcmx86_load(x->rk[10]);
  for (usz i = 0; i < 4; i++) {
    s[i] = wired_arch_aesenclast(s[i], rk);
  }
}

/* AES-128 encrypt 4 independent blocks, interleaving their aesenc chains
 * (round r for all 4 lanes before round r+1 for any) to hide the aesenc
 * latency behind the other lanes' independent chains. */
static void gcmx86_aes4(const gcmx86* x, gcmx86_v s[4]) {
  gcmx86_aes4_init(x, s);
  for (usz r = 1; r < 10; r++) {
    gcmx86_aes4_round(x, s, r);
  }
  gcmx86_aes4_last(x, s);
}

/* Advance the counter 4 times, loading each resulting J into a lane. */
static void gcmx86_ctr_x4_advance(u8 j[16], gcmx86_v s[4]) {
  for (usz i = 0; i < 4; i++) {
    gcmx86_inc32(j);
    s[i] = gcmx86_load(j);
  }
}

/* XOR 4 keystream lanes into 4 consecutive input blocks, storing to out. */
static void gcmx86_ctr_x4_store(gcmx86_v s[4], const u8* in, u8* out) {
  for (usz i = 0; i < 4; i++) {
    gcmx86_store(out + 16 * i, gcmx86_load(in + 16 * i) ^ s[i]);
  }
}

/* Advance the counter 4 times and XOR 4 full keystream blocks into out. */
static void gcmx86_ctr_x4(const gcmx86* x, u8 j[16], const u8* in, u8* out) {
  gcmx86_v s[4];
  gcmx86_ctr_x4_advance(j, s);
  gcmx86_aes4(x, s);
  gcmx86_ctr_x4_store(s, in, out);
}

/* Encrypt every full 4-block (64-byte) group of in, interleaving 4
 * independent aesenc chains (measured 20-31% faster than one block at a
 * time). Returns the byte offset of the first byte not yet processed. */
static usz gcmx86_ctr_x4_all(
    const gcmx86* x, u8 j[16], wired_span in, u8* out) {
  usz off = 0;
  for (; off + 64 <= in.n; off += 64) {
    gcmx86_ctr_x4(x, j, in.p + off, out + off);
  }
  return off;
}

/* CTR-encrypt in into out; j enters as J0 (data blocks use J0+1, J0+2, ...).
 * The remainder after the last full 4-block group (<4 blocks, then <16
 * bytes) falls back to the sequential single-block path. */
void gcmx86_ctr(const gcmx86* x, u8 j[16], wired_span in, u8* out) {
  usz off = gcmx86_ctr_x4_all(x, j, in, out);
  for (; off + 16 <= in.n; off += 16) {
    gcmx86_ctr_block(x, j, in.p + off, out + off);
  }
  if (off < in.n) {
    gcmx86_ctr_tail(x, j, wired_span_of(in.p + off, in.n - off), out + off);
  }
}

/* J0 = nonce || 0x00000001 (SP 800-38D 7.1, 96-bit IV). */
void gcmx86_j0(u8 j[16], const u8 nonce[GCMX86_NONCE]) {
  for (usz i = 0; i < 12; i++) {
    j[i] = nonce[i];
  }
  j[12] = 0;
  j[13] = 0;
  j[14] = 0;
  j[15] = 1;
}

/* tag = GHASH(H; aad, ct, len block) ^ E(K, J0) (SP 800-38D 7.1). */
void gcmx86_tag(
    const gcmx86* x,
    const u8      j0[16],
    wired_span    aad,
    wired_span    ct,
    u8            tag[16]) {
  u8       lens[16];
  gcmx86_v h = gcmx86_load_rev(x->h, 16);
  gcmx86_v y = {0};
  y          = gcmx86_ghash(h, y, aad);
  y          = gcmx86_ghash(h, y, ct);
  be_put_be64(lens, (u64)aad.n * 8);
  be_put_be64(lens + 8, (u64)ct.n * 8);
  y = gcmx86_gfmul(y ^ gcmx86_load_rev(lens, 16), h);
  gcmx86_store(tag, gcmx86_rev(y) ^ gcmx86_aes(x, gcmx86_load(j0)));
}

void gcmx86_init(gcmx86* x, const u8 key[16]) {
  aes128   a;
  gcmx86_v zero = {0};
  aes128_init(&a, key); /* cold path: reuse the scalar key schedule */
  for (usz i = 0; i < AES_RK_WORDS; i++) {
    be_put_be32((u8*)x->rk + 4 * i, a.rk[i]); /* be words = FIPS bytes */
  }
  gcmx86_store(x->h, gcmx86_aes(x, zero)); /* H = E(K, 0^128), 6.4 */
}
