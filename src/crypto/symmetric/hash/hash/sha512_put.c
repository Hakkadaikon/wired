#include "crypto/symmetric/hash/hash/sha512_impl.h"

static void sha512_pad_message(sha512_ctx* s);
static void put_len(u8 lenbe[16], u64 bits);
static void sha512_put_be64(u8* out, u64 v);

/* Append 0x80 then zero bytes until exactly 112 bytes sit in the block,
 * leaving room for the 16-byte length (FIPS 180-4 5.1.2). */
static void sha512_pad_message(sha512_ctx* s) {
  u8 b = 0x80;
  sha512_update(s, &b, 1);
  b = 0;
  while (s->buf_len != 112) sha512_update(s, &b, 1);
}

/* Write the 128-bit message length: high 64 bits are always zero here. */
static void put_len(u8 lenbe[16], u64 bits) {
  for (usz i = 0; i < 8; i++) lenbe[i] = 0;
  for (usz i = 0; i < 8; i++) lenbe[8 + i] = (u8)(bits >> (56 - i * 8));
}

/* Store one 64-bit hash word big-endian at out[0..7]. */
static void sha512_put_be64(u8* out, u64 v) {
  for (usz j = 0; j < 8; j++) out[j] = (u8)(v >> (56 - j * 8));
}

void sha512_final(sha512_ctx* s, u8 out[SHA512_DIGEST]) {
  u8 lenbe[16];
  put_len(lenbe, s->total * 8);
  sha512_pad_message(s);
  sha512_update(s, lenbe, 16);
  for (usz i = 0; i < 8; i++) sha512_put_be64(out + i * 8, s->h[i]);
}

void sha512(const u8* data, usz len, u8 out[SHA512_DIGEST]) {
  sha512_ctx s;
  sha512_init(&s);
  sha512_update(&s, data, len);
  sha512_final(&s, out);
}
