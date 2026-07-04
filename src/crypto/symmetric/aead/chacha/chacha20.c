#include "crypto/symmetric/aead/chacha/chacha20.h"

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* RFC 8439 2.1 quarter-round on four state words. */
#define QR(a, b, c, d) \
  (a) += (b);          \
  (d) ^= (a);          \
  (d) = ROTL((d), 16); \
  (c) += (d);          \
  (b) ^= (c);          \
  (b) = ROTL((b), 12); \
  (a) += (b);          \
  (d) ^= (a);          \
  (d) = ROTL((d), 8);  \
  (c) += (d);          \
  (b) ^= (c);          \
  (b) = ROTL((b), 7)

static u32 rd32(const u8* p) {
  return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

/* One double-round: four column QRs then four diagonal QRs. */
static void double_round(u32 x[16]) {
  QR(x[0], x[4], x[8], x[12]);
  QR(x[1], x[5], x[9], x[13]);
  QR(x[2], x[6], x[10], x[14]);
  QR(x[3], x[7], x[11], x[15]);
  QR(x[0], x[5], x[10], x[15]);
  QR(x[1], x[6], x[11], x[12]);
  QR(x[2], x[7], x[8], x[13]);
  QR(x[3], x[4], x[9], x[14]);
}

/* Build the initial 16-word state: constants, key, counter, nonce. */
static void init_state(const u8* key, u32 counter, const u8* nonce, u32 s[16]) {
  s[0] = 0x61707865;
  s[1] = 0x3320646e;
  s[2] = 0x79622d32;
  s[3] = 0x6b206574;
  for (usz i = 0; i < 8; i++) s[4 + i] = rd32(key + 4 * i);
  s[12] = counter;
  for (usz i = 0; i < 3; i++) s[13 + i] = rd32(nonce + 4 * i);
}

/* Add the original state back in and serialize little-endian to out. */
static void serialize(const u32 x[16], const u32 s[16], u8 out[64]) {
  for (usz i = 0; i < 16; i++) {
    u32 v          = x[i] + s[i];
    out[4 * i]     = (u8)v;
    out[4 * i + 1] = (u8)(v >> 8);
    out[4 * i + 2] = (u8)(v >> 16);
    out[4 * i + 3] = (u8)(v >> 24);
  }
}

void quic_chacha20_block(
    const u8 key[QUIC_CHACHA_KEY],
    u32      counter,
    const u8 nonce[QUIC_CHACHA_NONCE],
    u8       out[QUIC_CHACHA_BLOCK]) {
  u32 s[16], x[16];
  init_state(key, counter, nonce, s);
  for (usz i = 0; i < 16; i++) x[i] = s[i];
  for (usz i = 0; i < 10; i++) double_round(x);
  serialize(x, s, out);
}

/* XOR up to one block of keystream into out; returns bytes done. */
static usz xor_chunk(const quic_chacha_ctx* c, quic_span in, u8* out) {
  u8  ks[QUIC_CHACHA_BLOCK];
  usz n = (in.n < QUIC_CHACHA_BLOCK) ? in.n : QUIC_CHACHA_BLOCK;
  quic_chacha20_block(c->key, c->counter, c->nonce, ks);
  for (usz i = 0; i < n; i++) out[i] = in.p[i] ^ ks[i];
  return n;
}

void quic_chacha20_xor(const quic_chacha_ctx* c, quic_span in, u8* out) {
  quic_chacha_ctx cc  = *c;
  usz             off = 0;
  while (off < in.n) {
    off += xor_chunk(&cc, quic_span_of(in.p + off, in.n - off), out + off);
    cc.counter++;
  }
}
