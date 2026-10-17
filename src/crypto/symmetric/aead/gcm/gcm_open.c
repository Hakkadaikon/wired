#include "crypto/symmetric/aead/gcm/gcm_impl.h"

static void data_ctr(const gcm_st* st, gcm_ctr* c);
static void gcm_tag(const gcm_st* st, wired_span ct, u8 tag[16]);
static void gcm_key_from_aes128(const aes128* a, u8 key[16]);
static void gcm_x86_from(const gcm_ctx* g, gcmx86* x);
static int  gcm_open_x86_empty(const gcm_ctx* g, wired_span ct);
static int  gcm_open_x86(const gcm_ctx* g, wired_span ct, u8* pt);
static int  gcm_open_scalar(const gcm_ctx* g, wired_span ct, u8* pt);

/* Start the data counter at J0+1 (J0 itself encrypts the tag). */
static void data_ctr(const gcm_st* st, gcm_ctr* c) {
  c->a = st->g->aes;
  for (usz i = 0; i < 16; i++) c->ctr[i] = st->j0[i];
  gcm_ctr_inc(c->ctr);
}

/* Compute the authentication tag over the AAD and ct using H and J0. */
static void gcm_tag(const gcm_st* st, wired_span ct, u8 tag[16]) {
  u8 y[16], lens[16], ej0[16];
  for (usz i = 0; i < 16; i++) y[i] = 0;
  gcm_ghash_bytes(st->h, y, st->g->aad.p, st->g->aad.n);
  gcm_ghash_bytes(st->h, y, ct.p, ct.n);
  gcm_put_be64(lens, (u64)st->g->aad.n * 8);
  gcm_put_be64(lens + 8, (u64)ct.n * 8);
  gcm_ghash_block(st->h, y, lens);
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
 * authentic empty plaintext (ct.n == GCM_TAG, returns 0) from AUTH_FAIL
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
  if (ct.n == GCM_TAG) return gcm_open_x86_empty(g, ct);
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
  gcm_ctr_xor(&c, pt, out);
  gcm_tag(&st, wired_span_of(out, pt.n), out + pt.n);
  return pt.n + GCM_TAG;
}

/* Scalar-path body: verify the tag, then decrypt on success. Split out of
 * gcm_open so its CCN stays under budget alongside the dispatch. */
static int gcm_open_scalar(const gcm_ctx* g, wired_span ct, u8* pt) {
  gcm_st     st;
  gcm_ctr    c;
  u8         want[16];
  wired_span body = wired_span_of(ct.p, ct.n - GCM_TAG);
  gcm_setup(g, &st);
  gcm_tag(&st, body, want);
  if (ct_diff16(want, ct.p + body.n) != 0)
    return 0; /* reject: leave pt untouched */
  data_ctr(&st, &c);
  gcm_ctr_xor(&c, body, pt);
  return 1;
}

int gcm_open(const gcm_ctx* g, wired_span ct, u8* pt) {
  if (ct.n < GCM_TAG) return 0;
  if (gcmx86_supported()) return gcm_open_x86(g, ct, pt);
  return gcm_open_scalar(g, ct, pt);
}
