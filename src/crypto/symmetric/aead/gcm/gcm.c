#include "crypto/symmetric/aead/gcm/gcm.h"

#include "common/bytes/util/ct.h"

/* XOR 16 bytes of src into dst. */
static void xor16(u8 *dst, const u8 *src) {
  for (usz i = 0; i < 16; i++) dst[i] ^= src[i];
}

/* Shift a 128-bit big-endian value right by one bit. */
static void shr1(u8 x[16]) {
  for (usz i = 15; i > 0; i--) x[i] = (u8)((x[i] >> 1) | (x[i - 1] << 7));
  x[0] >>= 1;
}

/* z ^= v & mask (per-byte), then v = (v >> 1) reduced by R when its LSB set. */
static void gf_step(u8 z[16], u8 v[16], u8 mask) {
  for (usz j = 0; j < 16; j++) z[j] ^= v[j] & mask;
  u8 lsb = (u8) - (v[15] & 1);
  shr1(v);
  v[0] ^= 0xe1 & lsb;
}

/* GF(2^128) multiply z = x * y per SP 800-38D (bit-reflected polynomial
 * R = 0xe1 in the high byte). y is consumed. */
static void gf_mul(const u8 x[16], const u8 y[16], u8 z[16]) {
  u8 v[16];
  for (usz i = 0; i < 16; i++) {
    z[i] = 0;
    v[i] = x[i];
  }
  for (usz bit = 0; bit < 128; bit++)
    gf_step(z, v, (u8) - ((y[bit / 8] >> (7 - bit % 8)) & 1));
}

/* Absorb one 16-byte block into the GHASH accumulator y (y ^= block; y *= H).
 */
static void ghash_block(const u8 h[16], u8 y[16], const u8 *block) {
  u8 hk[16], out[16];
  xor16(y, block);
  for (usz i = 0; i < 16; i++) hk[i] = h[i];
  gf_mul(y, hk, out);
  for (usz i = 0; i < 16; i++) y[i] = out[i];
}

/* Bytes remaining at off, capped at one block. */
static usz block_n(usz off, usz len) {
  return (len - off < 16) ? len - off : 16;
}

/* Copy up to 16 bytes from p+off into b, zero-padding the rest. */
static void load_block(u8 b[16], const u8 *p, usz off, usz len) {
  usz n = block_n(off, len);
  for (usz i = 0; i < 16; i++) b[i] = (i < n) ? p[off + i] : 0;
}

/* Absorb len bytes (zero-padded to a block multiple) into GHASH. */
static void ghash_bytes(const u8 h[16], u8 y[16], const u8 *p, usz len) {
  usz off = 0;
  while (off < len) {
    u8 b[16];
    load_block(b, p, off, len);
    ghash_block(h, y, b);
    off += 16;
  }
}

/* Big-endian 64-bit store. */
static void put_be64(u8 *p, u64 v) {
  for (usz i = 0; i < 8; i++) p[i] = (u8)(v >> (56 - i * 8));
}

/* Increment the low 32 bits of a counter block (GCM uses a 32-bit counter). */
static void ctr_inc(u8 c[16]) {
  for (usz i = 16; i > 12; i--)
    if (++c[i - 1] != 0) return;
}

/* AES-CTR keystream state: key schedule plus the running counter block. */
typedef struct {
  const quic_aes128 *a;
  u8                 ctr[16];
} quic_gcm_ctr;

/* XOR up to 16 keystream bytes E(K,ctr) into out; returns bytes done. */
static usz ctr_chunk(quic_gcm_ctr *c, quic_span in, u8 *out) {
  u8  ks[16];
  usz n = (in.n < 16) ? in.n : 16;
  quic_aes128_encrypt(c->a, c->ctr, ks);
  for (usz i = 0; i < n; i++) out[i] = in.p[i] ^ ks[i];
  ctr_inc(c->ctr);
  return n;
}

/* XOR keystream E(K, counter) over in, advancing the counter. */
static void ctr_xor(quic_gcm_ctr *c, quic_span in, u8 *out) {
  usz off = 0;
  while (off < in.n)
    off += ctr_chunk(c, quic_span_of(in.p + off, in.n - off), out + off);
}

/* Per-invocation GHASH state: the inputs plus H = E(K, 0^128) and J0. */
typedef struct {
  const quic_gcm_ctx *g;
  u8                  h[16];
  u8                  j0[16];
} quic_gcm_st;

/* Build H = E(K, 0^128) and J0 = nonce || 0x00000001. */
static void gcm_setup(const quic_gcm_ctx *g, quic_gcm_st *st) {
  u8 zero[16];
  st->g = g;
  for (usz i = 0; i < 16; i++) zero[i] = 0;
  quic_aes128_encrypt(g->aes, zero, st->h);
  for (usz i = 0; i < 12; i++) st->j0[i] = g->nonce[i];
  st->j0[12] = 0;
  st->j0[13] = 0;
  st->j0[14] = 0;
  st->j0[15] = 1;
}

/* Start the data counter at J0+1 (J0 itself encrypts the tag). */
static void data_ctr(const quic_gcm_st *st, quic_gcm_ctr *c) {
  c->a = st->g->aes;
  for (usz i = 0; i < 16; i++) c->ctr[i] = st->j0[i];
  ctr_inc(c->ctr);
}

/* Compute the authentication tag over the AAD and ct using H and J0. */
static void gcm_tag(const quic_gcm_st *st, quic_span ct, u8 tag[16]) {
  u8 y[16], lens[16], ej0[16];
  for (usz i = 0; i < 16; i++) y[i] = 0;
  ghash_bytes(st->h, y, st->g->aad.p, st->g->aad.n);
  ghash_bytes(st->h, y, ct.p, ct.n);
  put_be64(lens, (u64)st->g->aad.n * 8);
  put_be64(lens + 8, (u64)ct.n * 8);
  ghash_block(st->h, y, lens);
  quic_aes128_encrypt(st->g->aes, st->j0, ej0);
  for (usz i = 0; i < 16; i++) tag[i] = y[i] ^ ej0[i];
}

usz quic_gcm_seal(const quic_gcm_ctx *g, quic_span pt, u8 *out) {
  quic_gcm_st  st;
  quic_gcm_ctr c;
  gcm_setup(g, &st);
  data_ctr(&st, &c);
  ctr_xor(&c, pt, out);
  gcm_tag(&st, quic_span_of(out, pt.n), out + pt.n);
  return pt.n + QUIC_GCM_TAG;
}

int quic_gcm_open(const quic_gcm_ctx *g, quic_span ct, u8 *pt) {
  quic_gcm_st  st;
  quic_gcm_ctr c;
  u8           want[16];
  if (ct.n < QUIC_GCM_TAG) return 0;
  quic_span body = quic_span_of(ct.p, ct.n - QUIC_GCM_TAG);
  gcm_setup(g, &st);
  gcm_tag(&st, body, want);
  if (quic_ct_diff16(want, ct.p + body.n) != 0)
    return 0; /* reject: leave pt untouched */
  data_ctr(&st, &c);
  ctr_xor(&c, body, pt);
  return 1;
}
