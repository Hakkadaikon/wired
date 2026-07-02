#include "common/bytes/span/span.h"
#include "crypto/asymmetric/ecc/ed25519/ed25519.h"
#include "crypto/asymmetric/ecc/ed25519/ed25519_field.h"
#include "crypto/symmetric/hash/hash/sha512.h"

/* RFC 8032 Section 5.1 Ed25519 scalar arithmetic, message hashing, and the
 * public keypair/sign/verify API. Group/field arithmetic lives in
 * ed25519_field.c. */

typedef quic_ed_ge ge;

/* L = 2^252 + 27742317777372353535851937790883648493, little-endian. */
static const u8 ORDER_L[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
                               0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};

/* a >= b for 32-byte little-endian integers. */
static int sc_ge(const u8 a[32], const u8 b[32]) {
  for (usz i = 32; i-- > 0;) {
    if (a[i] != b[i]) return a[i] > b[i];
  }
  return 1;
}

/* r -= L (32-byte little-endian, assumes r >= L). */
static void sc_subl(u8 r[32]) {
  int borrow = 0;
  for (usz i = 0; i < 32; i++) {
    int v  = (int)r[i] - ORDER_L[i] - borrow;
    borrow = v < 0;
    r[i]   = (u8)(v + (borrow << 8));
  }
}

/* r = (r << 1) | bit; returns the bit shifted out past 256 bits. */
static int sc_shl1(u8 r[32], int bit) {
  int carry = bit;
  for (usz i = 0; i < 32; i++) {
    int v = (r[i] << 1) | carry;
    r[i]  = (u8)v;
    carry = v >> 8;
  }
  return carry;
}

/* r = (r << 1) | bit then conditionally reduce mod L. */
static void sc_dbl_add_bit(u8 r[32], int bit) {
  int overflow = sc_shl1(r, bit);
  int reduce   = overflow | sc_ge(r, ORDER_L);
  if (reduce) sc_subl(r);
}

/* out = in (64-byte LE) mod L, via bitwise shift-and-reduce (RFC 8032: the
 * digest is reduced mod the group order). */
static void sc_reduce64(u8 out[32], const u8 in[64]) {
  for (usz i = 0; i < 32; i++) out[i] = 0;
  for (usz i = 512; i-- > 0;) sc_dbl_add_bit(out, (in[i >> 3] >> (i & 7)) & 1);
}

/* k = SHA-512(R || A || M) mod L (RFC 8032 5.1.7 step 2). */
static void hash_k(u8 k[32], const u8 *R, const u8 *A, quic_span msg) {
  quic_sha512_ctx h;
  u8              digest[64];
  quic_sha512_init(&h);
  quic_sha512_update(&h, R, 32);
  quic_sha512_update(&h, A, 32);
  quic_sha512_update(&h, msg.p, msg.n);
  quic_sha512_final(&h, digest);
  sc_reduce64(k, digest);
}

static int bytes_equal(const u8 a[32], const u8 b[32]) {
  u8 diff = 0;
  for (usz i = 0; i < 32; i++) diff |= a[i] ^ b[i];
  return diff == 0;
}

/* rhs = R + [k]A' as 32-byte encoding; returns 1 on success (R decodes). */
static int compute_rhs(
    u8 out[32], const u8 k[32], const ge *A, const u8 R[32]) {
  ge kA, rhs;
  quic_ed_ge_scalarmult(&kA, k, A);
  if (!quic_ed_ge_decode(&rhs, R)) return 0;
  quic_ed_ge_add(&rhs, &rhs, &kA);
  quic_ed_ge_encode(out, &rhs);
  return 1;
}

/* Final check: [S]B == R + [k]A' (RFC 8032 5.1.7 step 3, sufficient form). */
static int check_equation(
    const u8 S[32], const u8 k[32], const ge *A, const u8 R[32]) {
  ge B, sB;
  u8 lhs[32], want[32];
  if (!compute_rhs(want, k, A, R)) return 0;
  quic_ed_ge_base(&B);
  quic_ed_ge_scalarmult(&sB, S, &B);
  quic_ed_ge_encode(lhs, &sB);
  return bytes_equal(lhs, want);
}

/* Accumulate a[i]*b into the schoolbook column array at offset i. */
static void sc_mul_row(u64 t[64], const u8 a[32], const u8 b[32], usz i) {
  for (usz j = 0; j < 32; j++) t[i + j] += (u64)a[i] * b[j];
}

/* 256x256 -> 512-bit product of two 32-byte little-endian scalars. */
static void sc_mul512(u8 out[64], const u8 a[32], const u8 b[32]) {
  u64 t[64] = {0};
  u64 c     = 0;
  for (usz i = 0; i < 32; i++) sc_mul_row(t, a, b, i);
  for (usz i = 0; i < 64; i++) {
    t[i] += c;
    out[i] = (u8)t[i];
    c      = t[i] >> 8;
  }
}

/* prod512 += c (32-byte LE addend) with carry. */
static void sc_add32(u8 prod[64], const u8 c[32]) {
  int carry = 0;
  for (usz i = 0; i < 64; i++) {
    int v   = prod[i] + carry + (i < 32 ? c[i] : 0);
    prod[i] = (u8)v;
    carry   = v >> 8;
  }
}

/* s = (a*b + c) mod L (RFC 8032 5.1.6 step 4: S = (r + k*a) mod L). */
static void sc_muladd(
    u8 s[32], const u8 a[32], const u8 b[32], const u8 c[32]) {
  u8 prod[64];
  sc_mul512(prod, a, b);
  sc_add32(prod, c);
  sc_reduce64(s, prod);
}

/* Apply the RFC 8032 5.1.5 clamping to a 32-byte scalar in place. */
static void sc_clamp(u8 a[32]) {
  a[0] &= 0xf8;
  a[31] &= 0x7f;
  a[31] |= 0x40;
}

/* Public key A = [clamp(SHA512(seed)[0:32])]B encoded (RFC 8032 5.1.5). */
int quic_ed25519_keypair(
    const u8 seed[QUIC_ED25519_SEED], u8 public_key[QUIC_ED25519_PUBKEY]) {
  u8 h[64], a[32];
  ge B, A;
  quic_sha512(seed, 32, h);
  for (usz i = 0; i < 32; i++) a[i] = h[i];
  sc_clamp(a);
  quic_ed_ge_base(&B);
  quic_ed_ge_scalarmult(&A, a, &B);
  quic_ed_ge_encode(public_key, &A);
  return 1;
}

/* r = SHA512(prefix || msg) mod L (RFC 8032 5.1.6 step 2). */
static void hash_r(u8 r[32], const u8 prefix[32], const u8 *msg, usz msg_len) {
  quic_sha512_ctx h;
  u8              digest[64];
  quic_sha512_init(&h);
  quic_sha512_update(&h, prefix, 32);
  quic_sha512_update(&h, msg, msg_len);
  quic_sha512_final(&h, digest);
  sc_reduce64(r, digest);
}

/* sig = R || S where R = [r]B, S = (r + k*a) mod L (RFC 8032 5.1.6). */
int quic_ed25519_sign(
    const u8  seed[QUIC_ED25519_SEED],
    const u8 *msg,
    usz       msg_len,
    u8        sig[QUIC_ED25519_SIG]) {
  u8 h[64], a[32], r[32], k[32];
  u8 A_enc[32];
  ge B, R, A;
  quic_sha512(seed, 32, h);
  for (usz i = 0; i < 32; i++) a[i] = h[i];
  sc_clamp(a);
  quic_ed_ge_base(&B);
  quic_ed_ge_scalarmult(&A, a, &B);
  quic_ed_ge_encode(A_enc, &A);
  hash_r(r, h + 32, msg, msg_len);
  quic_ed_ge_scalarmult(&R, r, &B);
  quic_ed_ge_encode(sig, &R);
  hash_k(k, sig, A_enc, (quic_span){msg, msg_len});
  sc_muladd(sig + 32, k, a, r);
  return 1;
}

int quic_ed25519_verify(
    const u8  sig[QUIC_ED25519_SIG],
    const u8 *msg,
    usz       msg_len,
    const u8  pubkey[QUIC_ED25519_PUBKEY]) {
  ge        A;
  u8        k[32];
  const u8 *R = sig;
  const u8 *S = sig + 32;
  if (sc_ge(S, ORDER_L)) return 0; /* S must be < L */
  if (!quic_ed_ge_decode(&A, pubkey)) return 0;
  hash_k(k, R, pubkey, (quic_span){msg, msg_len});
  return check_equation(S, k, &A, R);
}
