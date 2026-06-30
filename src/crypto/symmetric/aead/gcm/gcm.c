#include "crypto/symmetric/aead/gcm/gcm.h"

#include "common/bytes/util/ct.h"

/* XOR 16 bytes of src into dst. */
static void xor16(u8 *dst, const u8 *src) {
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
static void gf_mul(const u8 x[16], const u8 y[16], u8 z[16]) {
  u8 v[16];
  for (usz i = 0; i < 16; i++) {
    z[i] = 0;
    v[i] = x[i];
  }
  for (usz bit = 0; bit < 128; bit++)
    gf_step(z, v, (u8) - ((y[bit / 8] >> (7 - bit % 8)) & 1));
}

/* Absorb one 16-byte block into the GHASH accumulator y (y ^= block; y *= H).
 */
static void ghash_block(const u8 h[16], u8 y[16], const u8 *block) {
  u8 hk[16], out[16];
  xor16(y, block);
  for (usz i = 0; i < 16; i++) hk[i] = h[i];
  gf_mul(y, hk, out);
  for (usz i = 0; i < 16; i++) y[i] = out[i];
}

/* Bytes remaining at off, capped at one block. */
static usz block_n(usz off, usz len) {
  return (len - off < 16) ? len - off : 16;
}

/* Copy up to 16 bytes from p+off into b, zero-padding the rest. */
static void load_block(u8 b[16], const u8 *p, usz off, usz len) {
  usz n = block_n(off, len);
  for (usz i = 0; i < 16; i++) b[i] = (i < n) ? p[off + i] : 0;
}

/* Absorb len bytes (zero-padded to a block multiple) into GHASH. */
static void ghash_bytes(const u8 h[16], u8 y[16], const u8 *p, usz len) {
  usz off = 0;
  while (off < len) {
    u8 b[16];
    load_block(b, p, off, len);
    ghash_block(h, y, b);
    off += 16;
  }
}

/* Big-endian 64-bit store. */
static void put_be64(u8 *p, u64 v) {
  for (usz i = 0; i < 8; i++) p[i] = (u8)(v >> (56 - i * 8));
}

/* Increment the low 32 bits of a counter block (GCM uses a 32-bit counter). */
static void ctr_inc(u8 c[16]) {
  for (usz i = 16; i > 12; i--)
    if (++c[i - 1] != 0) return;
}

/* XOR up to 16 keystream bytes E(K,ctr) into out[off..]; returns bytes done. */
static usz ctr_chunk(
    const quic_aes128 *a, u8 ctr[16], const u8 *in, usz off, usz len, u8 *out) {
  u8  ks[16];
  usz n = (len - off < 16) ? len - off : 16;
  quic_aes128_encrypt(a, ctr, ks);
  for (usz i = 0; i < n; i++) out[off + i] = in[off + i] ^ ks[i];
  ctr_inc(ctr);
  return n;
}

/* XOR keystream E(K, counter) over len bytes, advancing the counter. */
static void ctr_xor(
    const quic_aes128 *a, u8 ctr[16], const u8 *in, usz len, u8 *out) {
  usz off = 0;
  while (off < len) off += ctr_chunk(a, ctr, in, off, len, out);
}

/* Build H = E(K, 0^128) and J0 = nonce || 0x00000001. */
static void gcm_setup(
    const quic_aes128 *a, const u8 *nonce, u8 h[16], u8 j0[16]) {
  u8 zero[16];
  for (usz i = 0; i < 16; i++) zero[i] = 0;
  quic_aes128_encrypt(a, zero, h);
  for (usz i = 0; i < 12; i++) j0[i] = nonce[i];
  j0[12] = 0;
  j0[13] = 0;
  j0[14] = 0;
  j0[15] = 1;
}

/* Compute the authentication tag over aad and ct using H and J0. */
static void gcm_tag(
    const quic_aes128 *a,
    const u8           h[16],
    const u8           j0[16],
    const u8          *aad,
    usz                aad_len,
    const u8          *ct,
    usz                ct_len,
    u8                 tag[16]) {
  u8 y[16], lens[16], ej0[16];
  for (usz i = 0; i < 16; i++) y[i] = 0;
  ghash_bytes(h, y, aad, aad_len);
  ghash_bytes(h, y, ct, ct_len);
  put_be64(lens, (u64)aad_len * 8);
  put_be64(lens + 8, (u64)ct_len * 8);
  ghash_block(h, y, lens);
  quic_aes128_encrypt(a, j0, ej0);
  for (usz i = 0; i < 16; i++) tag[i] = y[i] ^ ej0[i];
}

usz quic_gcm_seal(
    const quic_aes128 *a,
    const u8           nonce[QUIC_GCM_NONCE],
    const u8          *aad,
    usz                aad_len,
    const u8          *pt,
    usz                pt_len,
    u8                *ct,
    u8                 tag[QUIC_GCM_TAG]) {
  u8 h[16], j0[16], ctr[16];
  gcm_setup(a, nonce, h, j0);
  for (usz i = 0; i < 16; i++) ctr[i] = j0[i];
  ctr_inc(ctr); /* counter starts at J0+1 for the data */
  ctr_xor(a, ctr, pt, pt_len, ct);
  gcm_tag(a, h, j0, aad, aad_len, ct, pt_len, tag);
  return pt_len;
}

int quic_gcm_open(
    const quic_aes128 *a,
    const u8           nonce[QUIC_GCM_NONCE],
    const u8          *aad,
    usz                aad_len,
    const u8          *ct,
    usz                ct_len,
    const u8           tag[QUIC_GCM_TAG],
    u8                *pt) {
  u8 h[16], j0[16], ctr[16], want[16];
  gcm_setup(a, nonce, h, j0);
  gcm_tag(a, h, j0, aad, aad_len, ct, ct_len, want);
  if (quic_ct_diff16(want, tag) != 0) return 0; /* reject: leave pt untouched */
  for (usz i = 0; i < 16; i++) ctr[i] = j0[i];
  ctr_inc(ctr);
  ctr_xor(a, ctr, ct, ct_len, pt);
  return 1;
}
