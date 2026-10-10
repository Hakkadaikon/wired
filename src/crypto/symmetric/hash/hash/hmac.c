#include "crypto/symmetric/hash/hash/hmac.h"

#include "common/bytes/util/bytes.h"

/* Copy a short key (<= block) into the zero-filled block. */
static void short_key(wired_span key, u8 kb[SHA256_BLOCK]) {
  for (usz i = 0; i < SHA256_BLOCK; i++) kb[i] = 0;
  for (usz i = 0; i < key.n; i++) kb[i] = key.p[i];
}

/* Normalize the key into a 64-byte block: hash it if it is too long,
 * otherwise zero-pad. (FIPS 198-1 step 1-3.) */
static void key_block(wired_span key, u8 kb[SHA256_BLOCK]) {
  if (key.n > SHA256_BLOCK) {
    for (usz i = 0; i < SHA256_BLOCK; i++) kb[i] = 0;
    wired_sha256(key.p, key.n, kb);
  } else {
    short_key(key, kb);
  }
}

/* XOR each block byte with pad and feed it into the hash. */
static void feed_pad(sha256_ctx* s, const u8 kb[SHA256_BLOCK], u8 pad) {
  u8 b[SHA256_BLOCK];
  for (usz i = 0; i < SHA256_BLOCK; i++) b[i] = kb[i] ^ pad;
  sha256_update(s, b, SHA256_BLOCK);
}

/* inner = H((K^ipad) || msg) */
static void inner_hash(
    const u8 kb[SHA256_BLOCK], wired_span msg, u8 out[SHA256_DIGEST]) {
  sha256_ctx s;
  sha256_init(&s);
  feed_pad(&s, kb, 0x36);
  sha256_update(&s, msg.p, msg.n);
  sha256_final(&s, out);
}

void hmac_sha256(wired_span key, wired_span msg, u8 out[SHA256_DIGEST]) {
  u8         kb[SHA256_BLOCK];
  u8         inner[SHA256_DIGEST];
  sha256_ctx s;
  key_block(key, kb);
  inner_hash(kb, msg, inner);
  sha256_init(&s);
  feed_pad(&s, kb, 0x5c); /* outer: K^opad */
  sha256_update(&s, inner, SHA256_DIGEST);
  sha256_final(&s, out);
}

/* FIPS 198-1 5, "Truncation of HMAC Output": MAC = leftmost Tlen bytes of
 * HMAC(K, text). Clamp out_len so a caller error cannot read past the
 * 32-byte digest computed on the stack. */
void hmac_sha256_truncated(
    wired_span key, wired_span msg, u8* out, usz out_len) {
  u8  full[SHA256_DIGEST];
  usz n = out_len < SHA256_DIGEST ? out_len : SHA256_DIGEST;
  hmac_sha256(key, msg, full);
  bytes_memcpy(out, full, n);
}

/* SHA-384 and SHA-512 (FIPS 180-4 6.4/6.5) share the 128-byte block and the
 * sha512_ctx; they differ only in IV and output length, so one RFC 2104 body
 * serves both HMACs. */
typedef struct {
  void (*init)(sha512_ctx*);
  void (*final)(sha512_ctx*, u8*);
  usz n; /* digest length */
} hmac512_hash;

static const hmac512_hash HMAC512_SHA384 = {
    sha384_init, sha384_final, SHA384_DIGEST};
static const hmac512_hash HMAC512_SHA512 = {
    sha512_init, sha512_final, SHA512_DIGEST};

/* H(prefix || msg) with the variant's IV and output length. */
static void hmac512_hash2(
    const hmac512_hash* h, wired_span prefix, wired_span msg, u8* out) {
  sha512_ctx s;
  h->init(&s);
  sha512_update(&s, prefix.p, prefix.n);
  sha512_update(&s, msg.p, msg.n);
  h->final(&s, out);
}

/* Normalize the key into a zero-padded 128-byte block, hashing it first if
 * it is longer than the block (RFC 2104 2, steps 1-3). */
static void hmac512_key_block(
    const hmac512_hash* h, wired_span key, u8 kb[SHA512_BLOCK]) {
  for (usz i = 0; i < SHA512_BLOCK; i++) kb[i] = 0;
  if (key.n > SHA512_BLOCK)
    hmac512_hash2(h, key, wired_span_of(kb, 0), kb);
  else
    bytes_memcpy(kb, key.p, key.n);
}

/* H((K ^ pad) || msg) */
static void hmac512_pad_hash(
    const hmac512_hash* h,
    const u8            kb[SHA512_BLOCK],
    u8                  pad,
    wired_span          msg,
    u8*                 out) {
  u8 b[SHA512_BLOCK];
  for (usz i = 0; i < SHA512_BLOCK; i++) b[i] = kb[i] ^ pad;
  hmac512_hash2(h, wired_span_of(b, SHA512_BLOCK), msg, out);
}

static void hmac512_mac(
    const hmac512_hash* h, wired_span key, wired_span msg, u8* out) {
  u8 kb[SHA512_BLOCK];
  u8 inner[SHA512_DIGEST];
  hmac512_key_block(h, key, kb);
  hmac512_pad_hash(h, kb, 0x36, msg, inner);
  hmac512_pad_hash(h, kb, 0x5c, wired_span_of(inner, h->n), out);
}

void hmac_sha384(wired_span key, wired_span msg, u8 out[SHA384_DIGEST]) {
  hmac512_mac(&HMAC512_SHA384, key, msg, out);
}

void hmac_sha512(wired_span key, wired_span msg, u8 out[SHA512_DIGEST]) {
  hmac512_mac(&HMAC512_SHA512, key, msg, out);
}
