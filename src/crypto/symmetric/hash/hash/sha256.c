#include "crypto/symmetric/hash/hash/sha256.h"

/* FIPS 180-4 4.2.2 round constants. */
static const u32 K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static const u32 H0[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BS0(x) (ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22))
#define BS1(x) (ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25))
#define SS0(x) (ROR(x, 7) ^ ROR(x, 18) ^ ((x) >> 3))
#define SS1(x) (ROR(x, 17) ^ ROR(x, 19) ^ ((x) >> 10))

void quic_sha256_init(quic_sha256_ctx *s) {
  for (usz i = 0; i < 8; i++) s->h[i] = H0[i];
  s->total   = 0;
  s->buf_len = 0;
}

/* Build the 64-word message schedule from one 64-byte block. */
static void schedule(const u8 *p, u32 w[64]) {
  for (usz i = 0; i < 16; i++)
    w[i] = ((u32)p[i * 4] << 24) | ((u32)p[i * 4 + 1] << 16) |
           ((u32)p[i * 4 + 2] << 8) | (u32)p[i * 4 + 3];
  for (usz i = 16; i < 64; i++)
    w[i] = SS1(w[i - 2]) + w[i - 7] + SS0(w[i - 15]) + w[i - 16];
}

/* One round: mix the working vector v[0..7] with schedule word w[i]. */
static void round_step(u32 v[8], u32 kw) {
  u32 t1 = v[7] + BS1(v[4]) + CH(v[4], v[5], v[6]) + kw;
  u32 t2 = BS0(v[0]) + MAJ(v[0], v[1], v[2]);
  for (usz j = 7; j > 0; j--) v[j] = v[j - 1]; /* shift e..a down */
  v[4] += t1;     /* e += t1 (after shift, v[4] holds old d) */
  v[0] = t1 + t2; /* a = t1 + t2 */
}

/* Run all 64 rounds over the working vector seeded from the hash state. */
static void run_rounds(const u32 *h, const u32 w[64], u32 v[8]) {
  for (usz i = 0; i < 8; i++) v[i] = h[i];
  for (usz i = 0; i < 64; i++) round_step(v, K[i] + w[i]);
}

static void compress(quic_sha256_ctx *s, const u8 *p) {
  u32 w[64];
  u32 v[8];
  schedule(p, w);
  run_rounds(s->h, w, v);
  for (usz i = 0; i < 8; i++) s->h[i] += v[i];
}

/* Absorb whole 64-byte blocks straight from data; returns bytes consumed. */
static usz absorb_blocks(quic_sha256_ctx *s, const u8 *data, usz len) {
  usz off = 0;
  while (len - off >= QUIC_SHA256_BLOCK) {
    compress(s, data + off);
    off += QUIC_SHA256_BLOCK;
  }
  return off;
}

/* Append n bytes (n < block, no overflow) into the pending buffer. */
static void buffer(quic_sha256_ctx *s, const u8 *data, usz n) {
  for (usz i = 0; i < n; i++) s->buf[s->buf_len + i] = data[i];
  s->buf_len += n;
}

/* Bytes to pull from data to complete a pending partial block, or 0 if
 * there is no partial block or not enough data to fill it. */
static usz pending_take(const quic_sha256_ctx *s, usz len) {
  usz want = QUIC_SHA256_BLOCK - s->buf_len;
  return (s->buf_len != 0 && len >= want) ? want : 0;
}

/* If a partial block is pending, top it up from data and flush when full.
 * Returns the number of bytes consumed from data. */
static usz fill_pending(quic_sha256_ctx *s, const u8 *data, usz len) {
  usz take = pending_take(s, len);
  buffer(s, data, take);
  if (take != 0) {
    compress(s, s->buf);
    s->buf_len = 0;
  }
  return take;
}

void quic_sha256_update(quic_sha256_ctx *s, const u8 *data, usz len) {
  usz off = fill_pending(s, data, len);
  off += absorb_blocks(s, data + off, len - off);
  buffer(s, data + off, len - off);
  s->total += len;
}

/* Write the 8-bit-per-byte big-endian length and hash words out. */
static void put_be32(u8 *p, u32 v) {
  p[0] = (u8)(v >> 24);
  p[1] = (u8)(v >> 16);
  p[2] = (u8)(v >> 8);
  p[3] = (u8)v;
}

/* Append 0x80 then zero bytes until exactly 56 bytes sit in the block,
 * leaving room for the 8-byte length (FIPS 180-4 5.1.1). */
static void pad_message(quic_sha256_ctx *s) {
  u8 b = 0x80;
  quic_sha256_update(s, &b, 1);
  b = 0;
  while (s->buf_len != 56) quic_sha256_update(s, &b, 1);
}

void quic_sha256_final(quic_sha256_ctx *s, u8 out[QUIC_SHA256_DIGEST]) {
  u64 bits = s->total * 8;
  u8  lenbe[8];
  for (usz i = 0; i < 8; i++) lenbe[i] = (u8)(bits >> (56 - i * 8));
  pad_message(s);
  quic_sha256_update(s, lenbe, 8);
  for (usz i = 0; i < 8; i++) put_be32(out + i * 4, s->h[i]);
}

void quic_sha256(const u8 *data, usz len, u8 out[QUIC_SHA256_DIGEST]) {
  quic_sha256_ctx s;
  quic_sha256_init(&s);
  quic_sha256_update(&s, data, len);
  quic_sha256_final(&s, out);
}
