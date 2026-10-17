#include "crypto/symmetric/aead/gcm/gcm_impl.h"

static void shr1(u8 x[16]);
static void gf_step(u8 z[16], u8 v[16], u8 mask);

/* XOR 16 bytes of src into dst. */
void gcm_xor16(u8* dst, const u8* src) {
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
void gcm_gf_mul(const u8 x[16], const u8 y[16], u8 z[16]) {
  u8 v[16];
  for (usz i = 0; i < 16; i++) {
    z[i] = 0;
    v[i] = x[i];
  }
  for (usz bit = 0; bit < 128; bit++)
    gf_step(z, v, (u8) - ((y[bit / 8] >> (7 - bit % 8)) & 1));
}
