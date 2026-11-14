#include "crypto/symmetric/aead/gcmx86/gcmx86_impl.h"

/** A CTR position: J0 and the low 32 bits of the next counter block. */
typedef struct {
  gcmx86_v j0; /**< the pre-counter block J0 */
  u32      c;  /**< counter of the next block, modulo 2^32 */
} gcmx86_cnt;

static void gcmx86_aes4_init(const gcmx86* x, gcmx86_v s[4]);
static void gcmx86_aes4_round(const gcmx86* x, gcmx86_v s[4], usz r);
static void gcmx86_aes4_last(const gcmx86* x, gcmx86_v s[4]);
static void gcmx86_aes4(const gcmx86* x, gcmx86_v s[4]);
static void gcmx86_ctr_x4_load(gcmx86_v j0, u32 c, gcmx86_v s[4]);
static void gcmx86_ctr_x4_store(gcmx86_v s[4], const u8* in, u8* out);
static void gcmx86_ctr_x4(
    const gcmx86* x, const gcmx86_cnt* k, const u8* in, u8* out);
static usz gcmx86_ctr_x4_all(
    const gcmx86* x, gcmx86_cnt* k, wired_span in, u8* out);
static usz gcmx86_ctr_x1_all(
    const gcmx86* x, gcmx86_cnt* k, wired_span in, u8* out, usz off);
static void gcmx86_init_powers(gcmx86* x);

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

/* The 4 counter blocks c .. c+3 of J0, one per lane. */
static void gcmx86_ctr_x4_load(gcmx86_v j0, u32 c, gcmx86_v s[4]) {
  for (u32 i = 0; i < 4; i++) {
    s[i] = gcmx86_ctr_at(j0, c + i);
  }
}

/* XOR 4 keystream lanes into 4 consecutive input blocks, storing to out. */
static void gcmx86_ctr_x4_store(gcmx86_v s[4], const u8* in, u8* out) {
  for (usz i = 0; i < 4; i++) {
    gcmx86_store(out + 16 * i, gcmx86_load(in + 16 * i) ^ s[i]);
  }
}

/* XOR the 4 keystream blocks of counters c .. c+3 into out. */
static void gcmx86_ctr_x4(
    const gcmx86* x, const gcmx86_cnt* k, const u8* in, u8* out) {
  gcmx86_v s[4];
  gcmx86_ctr_x4_load(k->j0, k->c, s);
  gcmx86_aes4(x, s);
  gcmx86_ctr_x4_store(s, in, out);
}

/* Encrypt every full 4-block (64-byte) group of in, interleaving 4
 * independent aesenc chains (measured 20-31% faster than one block at a
 * time). Returns the byte offset of the first byte not yet processed. */
static usz gcmx86_ctr_x4_all(
    const gcmx86* x, gcmx86_cnt* k, wired_span in, u8* out) {
  usz off = 0;
  for (; off + 64 <= in.n; off += 64, k->c += 4) {
    gcmx86_ctr_x4(x, k, in.p + off, out + off);
  }
  return off;
}

/* Every full block left after the 4-block groups, one at a time. */
static usz gcmx86_ctr_x1_all(
    const gcmx86* x, gcmx86_cnt* k, wired_span in, u8* out, usz off) {
  for (; off + 16 <= in.n; off += 16, k->c++) {
    gcmx86_v ks = gcmx86_aes(x, gcmx86_ctr_at(k->j0, k->c));
    gcmx86_store(out + off, gcmx86_load(in.p + off) ^ ks);
  }
  return off;
}

/* CTR-encrypt in into out; j is J0 (data blocks use J0+1, J0+2, ..., the
 * low 32 bits wrapping, SP 800-38D 6.5). The remainder after the last
 * full 4-block group (<4 blocks, then <16 bytes) takes the single-block
 * path. */
void gcmx86_ctr(const gcmx86* x, const u8 j[16], wired_span in, u8* out) {
  gcmx86_cnt k   = {gcmx86_load(j), be_get_be32(j + 12) + 1u};
  usz        off = gcmx86_ctr_x4_all(x, &k, in, out);
  off            = gcmx86_ctr_x1_all(x, &k, in, out, off);
  if (off < in.n) {
    gcmx86_ctr_tail(
        x, gcmx86_ctr_at(k.j0, k.c), wired_span_of(in.p + off, in.n - off),
        out + off);
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

/* hp[i] = H^(i+1) as GHASH operands, for the four-block fold
 * (gcmx86_ghash.c). */
static void gcmx86_init_powers(gcmx86* x) {
  gcmx86_v h = gcmx86_load_rev(x->h, 16);
  gcmx86_v p = h;
  gcmx86_store(x->hp[0], p);
  for (usz i = 1; i < 4; i++) {
    p = gcmx86_gfmul(p, h);
    gcmx86_store(x->hp[i], p);
  }
}

void gcmx86_init(gcmx86* x, const u8 key[16]) {
  aes128   a;
  gcmx86_v zero = {0};
  aes128_init(&a, key); /* cold path: reuse the scalar key schedule */
  for (usz i = 0; i < AES_RK_WORDS; i++) {
    be_put_be32((u8*)x->rk + 4 * i, a.rk[i]); /* be words = FIPS bytes */
  }
  gcmx86_store(x->h, gcmx86_aes(x, zero)); /* H = E(K, 0^128), 6.4 */
  gcmx86_init_powers(x);
}
