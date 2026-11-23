#include "crypto/asymmetric/ecc/ed25519/ed25519_sign_impl.h"

static int  sc_lt_l(const u8 r[32]);
static void sc_subl(u8 r[32], u8 mask);
static void sc_shl1(u8 r[32], int bit);
static void sc_dbl_add_bit(u8 r[32], int bit);
static int  bytes_equal(const u8 a[32], const u8 b[32]);
static int compute_rhs(u8 out[32], const u8 k[32], const ge* A, const u8 R[32]);

/* L = 2^252 + 27742317777372353535851937790883648493, little-endian. */
const u8 ORDER_L[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
                        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};

/* a >= b for 32-byte little-endian integers. Variable time: public inputs
 * only (verify's S < L check). */
int ed25519_sign_sc_ge(const u8 a[32], const u8 b[32]) {
  for (usz i = 32; i-- > 0;) {
    if (a[i] != b[i]) {
      return a[i] > b[i];
    }
  }
  return 1;
}

/* 1 when r < L (the borrow out of r - L), without branching on r: r is the
 * secret nonce or S on the signing path (RFC 8032 8.1). */
static int sc_lt_l(const u8 r[32]) {
  int borrow = 0;
  for (usz i = 0; i < 32; i++) {
    borrow = ((int)r[i] - ORDER_L[i] - borrow) < 0;
  }
  return borrow;
}

/* r -= L & mask (mask 0x00 or 0xff; 32-byte little-endian, assumes r >= L
 * when mask is set). Subtracting a masked L, not selecting between r and
 * r - L, keeps the compiler from turning it into a secret-indexed load. */
static void sc_subl(u8 r[32], u8 mask) {
  int borrow = 0;
  for (usz i = 0; i < 32; i++) {
    int v  = (int)r[i] - (ORDER_L[i] & mask) - borrow;
    borrow = v < 0;
    r[i]   = (u8)(v + (borrow << 8));
  }
}

/* r = (r << 1) | bit (the caller keeps r < 2^255, so nothing shifts out). */
static void sc_shl1(u8 r[32], int bit) {
  int carry = bit;
  for (usz i = 0; i < 32; i++) {
    int v = (r[i] << 1) | carry;
    r[i]  = (u8)v;
    carry = v >> 8;
  }
}

/* r = (r << 1) | bit then reduce mod L, in constant time: r < L < 2^253
 * before, so 2r + bit < 2L < 2^254 fits in 32 bytes and one masked
 * subtract of L suffices. */
static void sc_dbl_add_bit(u8 r[32], int bit) {
  sc_shl1(r, bit);
  sc_subl(r, (u8)wired_arch_value_barrier((u64)0 - (u64)(sc_lt_l(r) ^ 1)));
}

/* out = in (64-byte LE) mod L, via bitwise shift-and-reduce (RFC 8032: the
 * digest is reduced mod the group order). */
void ed25519_sign_sc_reduce64(u8 out[32], const u8 in[64]) {
  for (usz i = 0; i < 32; i++) {
    out[i] = 0;
  }
  for (usz i = 512; i-- > 0;) {
    sc_dbl_add_bit(out, (in[i >> 3] >> (i & 7)) & 1);
  }
}

/* k = SHA-512(R || A || M) mod L (RFC 8032 5.1.7 step 2). */
void ed25519_sign_hash_k(u8 k[32], const u8* R, const u8* A, wired_span msg) {
  sha512_ctx h;
  u8         digest[64];
  sha512_init(&h);
  sha512_update(&h, R, 32);
  sha512_update(&h, A, 32);
  sha512_update(&h, msg.p, msg.n);
  sha512_final(&h, digest);
  ed25519_sign_sc_reduce64(k, digest);
}

static int bytes_equal(const u8 a[32], const u8 b[32]) {
  u8 diff = 0;
  for (usz i = 0; i < 32; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

/* Decode a verification input point, rejecting small-order A or R: the
 * non-cofactored check below would otherwise accept signatures built from
 * torsion components ("Taming the many EdDSAs"). */
int ed25519_sign_decode_checked(ge* p, const u8 in[32]) {
  return ed_ge_decode(p, in) && !ed_ge_is_small_order(p);
}

/* rhs = R + [k]A' as 32-byte encoding; returns 1 on success (R decodes). */
static int compute_rhs(
    u8 out[32], const u8 k[32], const ge* A, const u8 R[32]) {
  ge kA, rhs;
  ed_ge_scalarmult(&kA, k, A);
  if (!ed25519_sign_decode_checked(&rhs, R)) {
    return 0;
  }
  ed_ge_add(&rhs, &rhs, &kA);
  ed_ge_encode(out, &rhs);
  return 1;
}

/* Final check: [S]B == R + [k]A' (RFC 8032 5.1.7 step 3, sufficient form). */
int ed25519_sign_check_equation(
    const u8 S[32], const u8 k[32], const ge* A, const u8 R[32]) {
  ge B, sB;
  u8 lhs[32], want[32];
  if (!compute_rhs(want, k, A, R)) {
    return 0;
  }
  ed_ge_base(&B);
  ed_ge_scalarmult(&sB, S, &B);
  ed_ge_encode(lhs, &sB);
  return bytes_equal(lhs, want);
}
