#include "crypto/symmetric/aead/gcm/gcm.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/ct.h"
#include "crypto/symmetric/aead/gcm/gcm256.h"
#include "crypto/symmetric/aead/gcmx86/gcmx86.h"

/* AES-NI/PCLMULQDQ dispatch for AES-128-GCM (RFC 9001 5.3 uses the same AEAD
 * regardless of which block-cipher backend computes it). Nonce/tag sizes
 * must agree between the two paths for the dispatch below to be transparent. */
_Static_assert(QUIC_GCM_NONCE == QUIC_GCMX86_NONCE, "gcm/gcmx86 nonce size");
_Static_assert(QUIC_GCM_TAG == QUIC_GCMX86_TAG, "gcm/gcmx86 tag size");

/* XOR 16 bytes of src into dst. */
static void xor16(u8* dst, const u8* src) {
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
static void ghash_block(const u8 h[16], u8 y[16], const u8* block) {
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
static void load_block(u8 b[16], const u8* p, usz off, usz len) {
  usz n = block_n(off, len);
  for (usz i = 0; i < 16; i++) b[i] = (i < n) ? p[off + i] : 0;
}

/* Absorb len bytes (zero-padded to a block multiple) into GHASH. */
static void ghash_bytes(const u8 h[16], u8 y[16], const u8* p, usz len) {
  usz off = 0;
  while (off < len) {
    u8 b[16];
    load_block(b, p, off, len);
    ghash_block(h, y, b);
    off += 16;
  }
}

/* Big-endian 64-bit store. */
static void put_be64(u8* p, u64 v) {
  for (usz i = 0; i < 8; i++) p[i] = (u8)(v >> (56 - i * 8));
}

/* Increment the low 32 bits of a counter block (GCM uses a 32-bit counter). */
static void ctr_inc(u8 c[16]) {
  for (usz i = 16; i > 12; i--)
    if (++c[i - 1] != 0) return;
}

/* AES-CTR keystream state: key schedule plus the running counter block. */
typedef struct {
  const aes128* a;
  u8            ctr[16];
} gcm_ctr;

/* XOR up to 16 keystream bytes E(K,ctr) into out; returns bytes done. */
static usz ctr_chunk(gcm_ctr* c, wired_span in, u8* out) {
  u8  ks[16];
  usz n = (in.n < 16) ? in.n : 16;
  aes128_encrypt(c->a, c->ctr, ks);
  for (usz i = 0; i < n; i++) out[i] = in.p[i] ^ ks[i];
  ctr_inc(c->ctr);
  return n;
}

/* XOR keystream E(K, counter) over in, advancing the counter. */
static void ctr_xor(gcm_ctr* c, wired_span in, u8* out) {
  usz off = 0;
  while (off < in.n)
    off += ctr_chunk(c, wired_span_of(in.p + off, in.n - off), out + off);
}

/* Per-invocation GHASH state: the inputs plus H = E(K, 0^128) and J0. */
typedef struct {
  const gcm_ctx* g;
  u8             h[16];
  u8             j0[16];
} gcm_st;

/* Build H = E(K, 0^128) and J0 = nonce || 0x00000001. */
static void gcm_setup(const gcm_ctx* g, gcm_st* st) {
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

/* Start the data counter at J0+1 (J0 itself encrypts the tag). */
static void data_ctr(const gcm_st* st, gcm_ctr* c) {
  c->a = st->g->aes;
  for (usz i = 0; i < 16; i++) c->ctr[i] = st->j0[i];
  ctr_inc(c->ctr);
}

/* Compute the authentication tag over the AAD and ct using H and J0. */
static void gcm_tag(const gcm_st* st, wired_span ct, u8 tag[16]) {
  u8 y[16], lens[16], ej0[16];
  for (usz i = 0; i < 16; i++) y[i] = 0;
  ghash_bytes(st->h, y, st->g->aad.p, st->g->aad.n);
  ghash_bytes(st->h, y, ct.p, ct.n);
  put_be64(lens, (u64)st->g->aad.n * 8);
  put_be64(lens + 8, (u64)ct.n * 8);
  ghash_block(st->h, y, lens);
  aes128_encrypt(st->g->aes, st->j0, ej0);
  for (usz i = 0; i < 16; i++) tag[i] = y[i] ^ ej0[i];
}

/* Recover the original 16-byte AES-128 key from the first four round-key
 * words (aes128_init sets rk[0..3] to the key itself, FIPS 197 5.2). */
static void gcm_key_from_aes128(const aes128* a, u8 key[16]) {
  for (usz i = 0; i < 4; i++) be_put_be32(key + 4 * i, a->rk[i]);
}

/* Build an AES-NI key schedule from the scalar aes128 already held by
 * g. Repeated per call by design (ponytail: caching would need per-
 * connection state this task doesn't touch; one AES key schedule + one AES
 * block is microseconds, already measured acceptable. Upgrade path: cache
 * the expanded gcmx86 on aes128 itself if profiling ever shows the
 * expansion cost matters). */
static void gcm_x86_from(const gcm_ctx* g, gcmx86* x) {
  u8 key[16];
  gcm_key_from_aes128(g->aes, key);
  gcmx86_init(x, key);
}

/* gcmx86_open returns the plaintext length, so it cannot distinguish an
 * authentic empty plaintext (ct.n == QUIC_GCM_TAG, returns 0) from AUTH_FAIL
 * (also returns 0). For that one boundary case, verify the tag directly with
 * the scalar GHASH tag computation (cheap: zero-length body) instead of
 * trusting the ambiguous return value. */
static int gcm_open_x86_empty(const gcm_ctx* g, wired_span ct) {
  gcm_st st;
  u8     want[16];
  gcm_setup(g, &st);
  gcm_tag(&st, wired_span_of(ct.p, 0), want);
  return ct_diff16(want, ct.p) == 0;
}

static int gcm_open_x86(const gcm_ctx* g, wired_span ct, u8* pt) {
  gcmx86 x;
  if (ct.n == QUIC_GCM_TAG) return gcm_open_x86_empty(g, ct);
  gcm_x86_from(g, &x);
  return gcmx86_open(&x, g->nonce, g->aad, ct, pt) != 0;
}

usz gcm_seal(const gcm_ctx* g, wired_span pt, u8* out) {
  gcm_st  st;
  gcm_ctr c;
  if (gcmx86_supported()) {
    gcmx86 x;
    gcm_x86_from(g, &x);
    return gcmx86_seal(&x, g->nonce, g->aad, pt, out);
  }
  gcm_setup(g, &st);
  data_ctr(&st, &c);
  ctr_xor(&c, pt, out);
  gcm_tag(&st, wired_span_of(out, pt.n), out + pt.n);
  return pt.n + QUIC_GCM_TAG;
}

/* Scalar-path body: verify the tag, then decrypt on success. Split out of
 * gcm_open so its CCN stays under budget alongside the dispatch. */
static int gcm_open_scalar(const gcm_ctx* g, wired_span ct, u8* pt) {
  gcm_st     st;
  gcm_ctr    c;
  u8         want[16];
  wired_span body = wired_span_of(ct.p, ct.n - QUIC_GCM_TAG);
  gcm_setup(g, &st);
  gcm_tag(&st, body, want);
  if (ct_diff16(want, ct.p + body.n) != 0)
    return 0; /* reject: leave pt untouched */
  data_ctr(&st, &c);
  ctr_xor(&c, body, pt);
  return 1;
}

int gcm_open(const gcm_ctx* g, wired_span ct, u8* pt) {
  if (ct.n < QUIC_GCM_TAG) return 0;
  if (gcmx86_supported()) return gcm_open_x86(g, ct, pt);
  return gcm_open_scalar(g, ct, pt);
}

/* AES-256-GCM (RFC 8446 Appendix B.4, 0x1302). Same mode of operation as
 * AES-128-GCM above; only the block cipher call (aes256_encrypt) and
 * the types carrying it differ. GHASH/counter helpers (ghash_bytes,
 * ghash_block, ctr_inc, put_be64) are shared, not duplicated. */

/* AES-256-CTR keystream state: key schedule plus the running counter block. */
typedef struct {
  const aes256* a;
  u8            ctr[16];
} gcm256_ctr;

/* XOR up to 16 keystream bytes E(K,ctr) into out; returns bytes done. */
static usz ctr_chunk256(gcm256_ctr* c, wired_span in, u8* out) {
  u8  ks[16];
  usz n = (in.n < 16) ? in.n : 16;
  aes256_encrypt(c->a, c->ctr, ks);
  for (usz i = 0; i < n; i++) out[i] = in.p[i] ^ ks[i];
  ctr_inc(c->ctr);
  return n;
}

/* XOR keystream E(K, counter) over in, advancing the counter. */
static void ctr_xor256(gcm256_ctr* c, wired_span in, u8* out) {
  usz off = 0;
  while (off < in.n)
    off += ctr_chunk256(c, wired_span_of(in.p + off, in.n - off), out + off);
}

/* Per-invocation GHASH state: the inputs plus H = E(K, 0^128) and J0. */
typedef struct {
  const gcm256_ctx* g;
  u8                h[16];
  u8                j0[16];
} gcm256_st;

/* Build H = E(K, 0^128) and J0 = nonce || 0x00000001. */
static void gcm_setup256(const gcm256_ctx* g, gcm256_st* st) {
  u8 zero[16];
  st->g = g;
  for (usz i = 0; i < 16; i++) zero[i] = 0;
  aes256_encrypt(g->aes, zero, st->h);
  for (usz i = 0; i < 12; i++) st->j0[i] = g->nonce[i];
  st->j0[12] = 0;
  st->j0[13] = 0;
  st->j0[14] = 0;
  st->j0[15] = 1;
}

/* Start the data counter at J0+1 (J0 itself encrypts the tag). */
static void data_ctr256(const gcm256_st* st, gcm256_ctr* c) {
  c->a = st->g->aes;
  for (usz i = 0; i < 16; i++) c->ctr[i] = st->j0[i];
  ctr_inc(c->ctr);
}

/* Compute the authentication tag over the AAD and ct using H and J0. */
static void gcm_tag256(const gcm256_st* st, wired_span ct, u8 tag[16]) {
  u8 y[16], lens[16], ej0[16];
  for (usz i = 0; i < 16; i++) y[i] = 0;
  ghash_bytes(st->h, y, st->g->aad.p, st->g->aad.n);
  ghash_bytes(st->h, y, ct.p, ct.n);
  put_be64(lens, (u64)st->g->aad.n * 8);
  put_be64(lens + 8, (u64)ct.n * 8);
  ghash_block(st->h, y, lens);
  aes256_encrypt(st->g->aes, st->j0, ej0);
  for (usz i = 0; i < 16; i++) tag[i] = y[i] ^ ej0[i];
}

usz gcm256_seal(const gcm256_ctx* g, wired_span pt, u8* out) {
  gcm256_st  st;
  gcm256_ctr c;
  gcm_setup256(g, &st);
  data_ctr256(&st, &c);
  ctr_xor256(&c, pt, out);
  gcm_tag256(&st, wired_span_of(out, pt.n), out + pt.n);
  return pt.n + QUIC_GCM_TAG;
}

int gcm256_open(const gcm256_ctx* g, wired_span ct, u8* pt) {
  gcm256_st  st;
  gcm256_ctr c;
  u8         want[16];
  if (ct.n < QUIC_GCM_TAG) return 0;
  wired_span body = wired_span_of(ct.p, ct.n - QUIC_GCM_TAG);
  gcm_setup256(g, &st);
  gcm_tag256(&st, body, want);
  if (ct_diff16(want, ct.p + body.n) != 0)
    return 0; /* reject: leave pt untouched */
  data_ctr256(&st, &c);
  ctr_xor256(&c, body, pt);
  return 1;
}
