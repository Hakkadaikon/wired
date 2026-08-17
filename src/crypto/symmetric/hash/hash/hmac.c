#include "crypto/symmetric/hash/hash/hmac.h"

#include "common/bytes/util/bytes.h"

/* Copy a short key (<= block) into the zero-filled block. */
static void short_key(wired_span key, u8 kb[QUIC_SHA256_BLOCK]) {
  for (usz i = 0; i < QUIC_SHA256_BLOCK; i++) kb[i] = 0;
  for (usz i = 0; i < key.n; i++) kb[i] = key.p[i];
}

/* Normalize the key into a 64-byte block: hash it if it is too long,
 * otherwise zero-pad. (FIPS 198-1 step 1-3.) */
static void key_block(wired_span key, u8 kb[QUIC_SHA256_BLOCK]) {
  if (key.n > QUIC_SHA256_BLOCK) {
    for (usz i = 0; i < QUIC_SHA256_BLOCK; i++) kb[i] = 0;
    wired_sha256(key.p, key.n, kb);
  } else {
    short_key(key, kb);
  }
}

/* XOR each block byte with pad and feed it into the hash. */
static void feed_pad(
    quic_sha256_ctx* s, const u8 kb[QUIC_SHA256_BLOCK], u8 pad) {
  u8 b[QUIC_SHA256_BLOCK];
  for (usz i = 0; i < QUIC_SHA256_BLOCK; i++) b[i] = kb[i] ^ pad;
  quic_sha256_update(s, b, QUIC_SHA256_BLOCK);
}

/* inner = H((K^ipad) || msg) */
static void inner_hash(
    const u8   kb[QUIC_SHA256_BLOCK],
    wired_span msg,
    u8         out[QUIC_SHA256_DIGEST]) {
  quic_sha256_ctx s;
  quic_sha256_init(&s);
  feed_pad(&s, kb, 0x36);
  quic_sha256_update(&s, msg.p, msg.n);
  quic_sha256_final(&s, out);
}

void quic_hmac_sha256(
    wired_span key, wired_span msg, u8 out[QUIC_SHA256_DIGEST]) {
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

/* FIPS 198-1 5, "Truncation of HMAC Output": MAC = leftmost Tlen bytes of
 * HMAC(K, text). Clamp out_len so a caller error cannot read past the
 * 32-byte digest computed on the stack. */
void quic_hmac_sha256_truncated(
    wired_span key, wired_span msg, u8* out, usz out_len) {
  u8  full[QUIC_SHA256_DIGEST];
  usz n = out_len < QUIC_SHA256_DIGEST ? out_len : QUIC_SHA256_DIGEST;
  quic_hmac_sha256(key, msg, full);
  quic_memcpy(out, full, n);
}

/* Copy a short key (<= block) into the zero-filled 128-byte block. */
static void short_key384(wired_span key, u8 kb[QUIC_SHA512_BLOCK]) {
  for (usz i = 0; i < QUIC_SHA512_BLOCK; i++) kb[i] = 0;
  for (usz i = 0; i < key.n; i++) kb[i] = key.p[i];
}

/* Normalize the key into a 128-byte block: hash it if too long, else
 * zero-pad. (RFC 2104 step 1-3, block size per FIPS 180-4 5.3.4.) */
static void key_block384(wired_span key, u8 kb[QUIC_SHA512_BLOCK]) {
  if (key.n > QUIC_SHA512_BLOCK) {
    for (usz i = 0; i < QUIC_SHA512_BLOCK; i++) kb[i] = 0;
    quic_sha384(key.p, key.n, kb);
  } else {
    short_key384(key, kb);
  }
}

/* XOR each block byte with pad and feed it into the hash. */
static void feed_pad384(
    quic_sha512_ctx* s, const u8 kb[QUIC_SHA512_BLOCK], u8 pad) {
  u8 b[QUIC_SHA512_BLOCK];
  for (usz i = 0; i < QUIC_SHA512_BLOCK; i++) b[i] = kb[i] ^ pad;
  quic_sha512_update(s, b, QUIC_SHA512_BLOCK);
}

/* inner = H((K^ipad) || msg) */
static void inner_hash384(
    const u8   kb[QUIC_SHA512_BLOCK],
    wired_span msg,
    u8         out[QUIC_SHA384_DIGEST]) {
  quic_sha512_ctx s;
  quic_sha384_init(&s);
  feed_pad384(&s, kb, 0x36);
  quic_sha512_update(&s, msg.p, msg.n);
  quic_sha384_final(&s, out);
}

void quic_hmac_sha384(
    wired_span key, wired_span msg, u8 out[QUIC_SHA384_DIGEST]) {
  u8              kb[QUIC_SHA512_BLOCK];
  u8              inner[QUIC_SHA384_DIGEST];
  quic_sha512_ctx s;
  key_block384(key, kb);
  inner_hash384(kb, msg, inner);
  quic_sha384_init(&s);
  feed_pad384(&s, kb, 0x5c); /* outer: K^opad */
  quic_sha512_update(&s, inner, QUIC_SHA384_DIGEST);
  quic_sha384_final(&s, out);
}
