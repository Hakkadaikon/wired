#include "crypto/symmetric/aead/aes/aes_impl.h"

/* The S-box without a table (FIPS 197 5.1.1): the multiplicative inverse
 * in GF(2^8), then the affine map. Eight bytes are packed one per byte of
 * a u64 and every step is a fixed sequence of shifts, ANDs, XORs and
 * multiplications by public constants, so no branch or memory index
 * depends on the bytes. The AES-NI path never calls it. */

#define AES_LANES 0x0101010101010101ull

static u64 aes_xt8(u64 x);
static u64 aes_gmul8(u64 a, u64 b);
static u64 aes_inv8(u64 x);
static u64 aes_rotl8(u64 x, unsigned k);

/* xtime (FIPS 197 4.2.1) of every byte; the reduction is a mask, not a
 * branch on the top bit. */
static u64 aes_xt8(u64 x) {
  return ((x & (AES_LANES * 0x7f)) << 1) ^ (((x >> 7) & AES_LANES) * 0x1b);
}

/* Byte-wise product in GF(2^8) (FIPS 197 4.2): bit i of each byte of b
 * becomes an all-ones or all-zero byte mask over a * x^i. */
static u64 aes_gmul8(u64 a, u64 b) {
  u64 r = 0;
  for (unsigned i = 0; i < 8; i++) {
    r ^= a & (((b >> i) & AES_LANES) * 0xff);
    a = aes_xt8(a);
  }
  return r;
}

/* x^254, the inverse of x (and 0 for 0, as 5.1.1 maps {00} to itself),
 * by a fixed addition chain: 2, 3, 6, 12, 15, 30, 60, 120, 240, 252, 254. */
static u64 aes_inv8(u64 x) {
  u64 x2  = aes_gmul8(x, x);
  u64 x3  = aes_gmul8(x2, x);
  u64 x6  = aes_gmul8(x3, x3);
  u64 x12 = aes_gmul8(x6, x6);
  u64 y   = aes_gmul8(x12, x3);
  for (unsigned i = 0; i < 4; i++) {
    y = aes_gmul8(y, y);
  }
  return aes_gmul8(aes_gmul8(y, x12), x2);
}

/* Rotate every byte left by k (1..4). */
static u64 aes_rotl8(u64 x, unsigned k) {
  u64 hi = AES_LANES * (u8)(0xffu << k);
  u64 lo = AES_LANES * (0xffu >> (8 - k));
  return ((x << k) & hi) | ((x >> (8 - k)) & lo);
}

/* 5.1.1 affine map: b ^ rotl(b,1) ^ rotl(b,2) ^ rotl(b,3) ^ rotl(b,4) ^
 * {63}, on the inverse b of each byte. */
u64 aes128_sbox8(u64 x) {
  u64 b = aes_inv8(x);
  u64 s = b ^ (AES_LANES * 0x63);
  for (unsigned k = 1; k < 5; k++) {
    s ^= aes_rotl8(b, k);
  }
  return s;
}
