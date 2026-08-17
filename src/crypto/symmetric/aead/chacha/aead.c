#include "crypto/symmetric/aead/chacha/aead.h"

#include "common/bytes/util/ct.h"

/* The MAC input is aad || pad16 || ct || pad16 || le64(aad_len) ||
 * le64(ct_len). We build it into a caller buffer via a small cursor. */

/* Append src, then zero-pad up to a 16-byte boundary. */
static usz put_padded(u8* buf, usz off, wired_span src) {
  usz pad = (16 - (src.n % 16)) % 16;
  for (usz i = 0; i < src.n; i++) buf[off + i] = src.p[i];
  for (usz i = 0; i < pad; i++) buf[off + src.n + i] = 0;
  return off + src.n + pad;
}

/* Append a little-endian 64-bit length. */
static usz put_le64(u8* buf, usz off, u64 v) {
  for (usz i = 0; i < 8; i++) buf[off + i] = (u8)(v >> (8 * i));
  return off + 8;
}

/* Derive the one-time Poly1305 key: first 32 bytes of the counter-0 block. */
static void poly_key(const chapoly_ctx* c, u8 pk[POLY1305_KEY]) {
  u8 block[CHACHA_BLOCK];
  chacha20_block(c->key, 0, c->nonce, block);
  for (usz i = 0; i < POLY1305_KEY; i++) pk[i] = block[i];
}

/* Compute the tag over (aad, ct). mac_buf must hold the padded construction. */
static void chapoly_tag(const chapoly_ctx* c, wired_span ct, u8 tag[16]) {
  u8 pk[POLY1305_KEY];
  u8 mac[16 + 1500 + 1500 + 16]; /* MTU-bounded scratch (ponytail: fixed cap) */
  usz n = 0;
  poly_key(c, pk);
  n = put_padded(mac, n, c->aad);
  n = put_padded(mac, n, ct);
  n = put_le64(mac, n, c->aad.n);
  n = put_le64(mac, n, ct.n);
  poly1305(pk, mac, n, tag);
}

/* Encrypt/decrypt with the per-message ChaCha20 stream (counter 1). */
static void chapoly_stream(const chapoly_ctx* c, wired_span in, u8* out) {
  chacha_ctx x = {c->key, c->nonce, 1};
  chacha20_xor(&x, in, out);
}

usz chapoly_seal(const chapoly_ctx* c, wired_span pt, u8* out) {
  chapoly_stream(c, pt, out);
  chapoly_tag(c, wired_span_of(out, pt.n), out + pt.n);
  return pt.n + CHAPOLY_TAG;
}

int chapoly_open(const chapoly_ctx* c, wired_span ct, u8* pt) {
  u8 want[16];
  if (ct.n < CHAPOLY_TAG) return 0;
  wired_span body = wired_span_of(ct.p, ct.n - CHAPOLY_TAG);
  chapoly_tag(c, body, want);
  if (ct_diff16(want, ct.p + body.n) != 0)
    return 0; /* reject: leave pt untouched */
  chapoly_stream(c, body, pt);
  return 1;
}
