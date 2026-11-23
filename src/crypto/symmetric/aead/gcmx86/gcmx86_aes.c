#include "crypto/symmetric/aead/gcmx86/gcmx86_impl.h"

static gcmx86_v gcmx86_rk_word(const u32* rk);
static void     gcmx86_init_powers(gcmx86* x);

/* SubWord (FIPS 197 5.2) by the S-box inside aesenclast: with w in all four
 * columns ShiftRows (5.1.2) moves nothing, so column 0 is SubBytes(w) and
 * the zero round key leaves it. The S-box is byte-wise, so the lane's byte
 * order does not matter. No table is indexed with the key. */
u32 gcmx86_subword(u32 w) {
  gcmx86_w v    = {w, w, w, w};
  gcmx86_v zero = {0};
  return ((gcmx86_w)wired_arch_aesenclast((gcmx86_v)v, zero))[0];
}

/* Round-key words rk[0..3] (big-endian FIPS 197 5.2 words) as the 16 state
 * bytes aesenc XORs in: one byte swap per 32-bit lane. */
static gcmx86_v gcmx86_rk_word(const u32* rk) {
  static const gcmx86_v swap = {3,  2,  1, 0, 7,  6,  5,  4,
                                11, 10, 9, 8, 15, 14, 13, 12};
  gcmx86_w              w    = {rk[0], rk[1], rk[2], rk[3]};
  return wired_arch_pshufb((gcmx86_v)w, swap);
}

/* FIPS 197 5.1 Cipher with AES-NI: aesenc for rounds 1..nr-1, aesenclast
 * for round nr. */
void gcmx86_aes_words(const u32* rk, usz nr, const u8 in[16], u8 out[16]) {
  gcmx86_v s = gcmx86_load(in) ^ gcmx86_rk_word(rk);
  for (usz r = 1; r < nr; r++) {
    s = wired_arch_aesenc(s, gcmx86_rk_word(rk + 4 * r));
  }
  gcmx86_store(out, wired_arch_aesenclast(s, gcmx86_rk_word(rk + 4 * nr)));
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

void gcmx86_init_rk(gcmx86* x, const u32* rk, usz nr) {
  gcmx86_v zero = {0};
  x->nr         = nr;
  for (usz i = 0; i < 4 * (nr + 1); i++) {
    be_put_be32((u8*)x->rk + 4 * i, rk[i]); /* be words = FIPS bytes */
  }
  gcmx86_store(x->h, gcmx86_aes(x, zero)); /* H = E(K, 0^128), 6.4 */
  gcmx86_init_powers(x);
}

void gcmx86_init(gcmx86* x, const u8 key[16]) {
  aes128 a;
  aes128_init(&a, key); /* SubWord through aesenclast (gcmx86_subword) */
  gcmx86_init_rk(x, a.rk, AES_ROUNDS);
}
