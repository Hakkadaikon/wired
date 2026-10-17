#include "crypto/symmetric/aead/gcm/gcm_impl.h"

static usz  ctr_chunk256(gcm256_ctr* c, wired_span in, u8* out);
static void ctr_xor256(gcm256_ctr* c, wired_span in, u8* out);
static void gcm_setup256(const gcm256_ctx* g, gcm256_st* st);
static void data_ctr256(const gcm256_st* st, gcm256_ctr* c);
static void gcm_tag256(const gcm256_st* st, wired_span ct, u8 tag[16]);

/* XOR up to 16 keystream bytes E(K,ctr) into out; returns bytes done. */
static usz ctr_chunk256(gcm256_ctr* c, wired_span in, u8* out) {
  u8  ks[16];
  usz n = (in.n < 16) ? in.n : 16;
  aes256_encrypt(c->a, c->ctr, ks);
  for (usz i = 0; i < n; i++) {
    out[i] = in.p[i] ^ ks[i];
  }
  gcm_ctr_inc(c->ctr);
  return n;
}

/* XOR keystream E(K, counter) over in, advancing the counter. */
static void ctr_xor256(gcm256_ctr* c, wired_span in, u8* out) {
  usz off = 0;
  while (off < in.n) {
    off += ctr_chunk256(c, wired_span_of(in.p + off, in.n - off), out + off);
  }
}

/* Build H = E(K, 0^128) and J0 = nonce || 0x00000001. */
static void gcm_setup256(const gcm256_ctx* g, gcm256_st* st) {
  u8 zero[16];
  st->g = g;
  for (usz i = 0; i < 16; i++) {
    zero[i] = 0;
  }
  aes256_encrypt(g->aes, zero, st->h);
  for (usz i = 0; i < 12; i++) {
    st->j0[i] = g->nonce[i];
  }
  st->j0[12] = 0;
  st->j0[13] = 0;
  st->j0[14] = 0;
  st->j0[15] = 1;
}

/* Start the data counter at J0+1 (J0 itself encrypts the tag). */
static void data_ctr256(const gcm256_st* st, gcm256_ctr* c) {
  c->a = st->g->aes;
  for (usz i = 0; i < 16; i++) {
    c->ctr[i] = st->j0[i];
  }
  gcm_ctr_inc(c->ctr);
}

/* Compute the authentication tag over the AAD and ct using H and J0. */
static void gcm_tag256(const gcm256_st* st, wired_span ct, u8 tag[16]) {
  u8 y[16], lens[16], ej0[16];
  for (usz i = 0; i < 16; i++) {
    y[i] = 0;
  }
  gcm_ghash_bytes(st->h, y, st->g->aad.p, st->g->aad.n);
  gcm_ghash_bytes(st->h, y, ct.p, ct.n);
  gcm_put_be64(lens, (u64)st->g->aad.n * 8);
  gcm_put_be64(lens + 8, (u64)ct.n * 8);
  gcm_ghash_block(st->h, y, lens);
  aes256_encrypt(st->g->aes, st->j0, ej0);
  for (usz i = 0; i < 16; i++) {
    tag[i] = y[i] ^ ej0[i];
  }
}

usz gcm256_seal(const gcm256_ctx* g, wired_span pt, u8* out) {
  gcm256_st  st;
  gcm256_ctr c;
  gcm_setup256(g, &st);
  data_ctr256(&st, &c);
  ctr_xor256(&c, pt, out);
  gcm_tag256(&st, wired_span_of(out, pt.n), out + pt.n);
  return pt.n + GCM_TAG;
}

int gcm256_open(const gcm256_ctx* g, wired_span ct, u8* pt) {
  gcm256_st  st;
  gcm256_ctr c;
  u8         want[16];
  if (ct.n < GCM_TAG) {
    return 0;
  }
  wired_span body = wired_span_of(ct.p, ct.n - GCM_TAG);
  gcm_setup256(g, &st);
  gcm_tag256(&st, body, want);
  if (ct_diff16(want, ct.p + body.n) != 0) {
    return 0; /* reject: leave pt untouched */
  }
  data_ctr256(&st, &c);
  ctr_xor256(&c, body, pt);
  return 1;
}
