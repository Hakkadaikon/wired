#include "crypto/symmetric/hash/hash/hmac.h"

/* Copy a short key (<= block) into the zero-filled block. */
static void short_key(quic_span key, u8 kb[QUIC_SHA256_BLOCK]) {
  for (usz i = 0; i < QUIC_SHA256_BLOCK; i++) kb[i] = 0;
  for (usz i = 0; i < key.n; i++) kb[i] = key.p[i];
}

/* Normalize the key into a 64-byte block: hash it if it is too long,
 * otherwise zero-pad. (FIPS 198-1 step 1-3.) */
static void key_block(quic_span key, u8 kb[QUIC_SHA256_BLOCK]) {
  if (key.n > QUIC_SHA256_BLOCK) {
    for (usz i = 0; i < QUIC_SHA256_BLOCK; i++) kb[i] = 0;
    quic_sha256(key.p, key.n, kb);
  } else {
    short_key(key, kb);
  }
}

/* XOR each block byte with pad and feed it into the hash. */
static void feed_pad(
    quic_sha256_ctx *s, const u8 kb[QUIC_SHA256_BLOCK], u8 pad) {
  u8 b[QUIC_SHA256_BLOCK];
  for (usz i = 0; i < QUIC_SHA256_BLOCK; i++) b[i] = kb[i] ^ pad;
  quic_sha256_update(s, b, QUIC_SHA256_BLOCK);
}

/* inner = H((K^ipad) || msg) */
static void inner_hash(
    const u8 kb[QUIC_SHA256_BLOCK], quic_span msg, u8 out[QUIC_SHA256_DIGEST]) {
  quic_sha256_ctx s;
  quic_sha256_init(&s);
  feed_pad(&s, kb, 0x36);
  quic_sha256_update(&s, msg.p, msg.n);
  quic_sha256_final(&s, out);
}

void quic_hmac_sha256(
    quic_span key, quic_span msg, u8 out[QUIC_SHA256_DIGEST]) {
  u8              kb[QUIC_SHA256_BLOCK];
  u8              inner[QUIC_SHA256_DIGEST];
  quic_sha256_ctx s;
  key_block(key, kb);
  inner_hash(kb, msg, inner);
  quic_sha256_init(&s);
  feed_pad(&s, kb, 0x5c); /* outer: K^opad */
  quic_sha256_update(&s, inner, QUIC_SHA256_DIGEST);
  quic_sha256_final(&s, out);
}
