#include "crypto/asymmetric/ecc/ed25519/ed25519_sign_impl.h"

static void sc_mul_row(u64 t[64], const u8 a[32], const u8 b[32], usz i);
static void sc_mul512(u8 out[64], const u8 a[32], const u8 b[32]);
static void sc_add32(u8 prod[64], const u8 c[32]);
static void sc_muladd(u8 s[32], const u8 a[32], const u8 b[32], const u8 c[32]);
static void sc_clamp(u8 a[32]);
static void hash_r(u8 r[32], const u8 prefix[32], const u8* msg, usz msg_len);

/* Accumulate a[i]*b into the schoolbook column array at offset i. */
static void sc_mul_row(u64 t[64], const u8 a[32], const u8 b[32], usz i) {
  for (usz j = 0; j < 32; j++) {
    t[i + j] += (u64)a[i] * b[j];
  }
}

/* 256x256 -> 512-bit product of two 32-byte little-endian scalars. */
static void sc_mul512(u8 out[64], const u8 a[32], const u8 b[32]) {
  u64 t[64] = {0};
  u64 c     = 0;
  for (usz i = 0; i < 32; i++) {
    sc_mul_row(t, a, b, i);
  }
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
  ed25519_sign_sc_reduce64(s, prod);
}

/* Apply the RFC 8032 5.1.5 clamping to a 32-byte scalar in place. */
static void sc_clamp(u8 a[32]) {
  a[0] &= 0xf8;
  a[31] &= 0x7f;
  a[31] |= 0x40;
}

/* Public key A = [clamp(SHA512(seed)[0:32])]B encoded (RFC 8032 5.1.5). */
int ed25519_keypair(
    const u8 seed[ED25519_SEED], u8 public_key[ED25519_PUBKEY]) {
  u8 h[64], a[32];
  ge B, A;
  sha512(seed, 32, h);
  for (usz i = 0; i < 32; i++) {
    a[i] = h[i];
  }
  sc_clamp(a);
  ed_ge_base(&B);
  ed_ge_scalarmult(&A, a, &B);
  ed_ge_encode(public_key, &A);
  return 1;
}

/* r = SHA512(prefix || msg) mod L (RFC 8032 5.1.6 step 2). */
static void hash_r(u8 r[32], const u8 prefix[32], const u8* msg, usz msg_len) {
  sha512_ctx h;
  u8         digest[64];
  sha512_init(&h);
  sha512_update(&h, prefix, 32);
  sha512_update(&h, msg, msg_len);
  sha512_final(&h, digest);
  ed25519_sign_sc_reduce64(r, digest);
}

/* sig = R || S where R = [r]B, S = (r + k*a) mod L (RFC 8032 5.1.6). */
int ed25519_sign(
    const u8  seed[ED25519_SEED],
    const u8* msg,
    usz       msg_len,
    u8        sig[ED25519_SIG]) {
  u8 h[64], a[32], r[32], k[32];
  u8 A_enc[32];
  ge B, R, A;
  sha512(seed, 32, h);
  for (usz i = 0; i < 32; i++) {
    a[i] = h[i];
  }
  sc_clamp(a);
  ed_ge_base(&B);
  ed_ge_scalarmult(&A, a, &B);
  ed_ge_encode(A_enc, &A);
  hash_r(r, h + 32, msg, msg_len);
  ed_ge_scalarmult(&R, r, &B);
  ed_ge_encode(sig, &R);
  ed25519_sign_hash_k(k, sig, A_enc, (wired_span){msg, msg_len});
  sc_muladd(sig + 32, k, a, r);
  return 1;
}

int ed25519_verify(
    const u8  sig[ED25519_SIG],
    const u8* msg,
    usz       msg_len,
    const u8  pubkey[ED25519_PUBKEY]) {
  ge        A;
  u8        k[32];
  const u8* R = sig;
  const u8* S = sig + 32;
  if (ed25519_sign_sc_ge(S, ORDER_L)) {
    return 0; /* S must be < L */
  }
  if (!ed25519_sign_decode_checked(&A, pubkey)) {
    return 0;
  }
  ed25519_sign_hash_k(k, R, pubkey, (wired_span){msg, msg_len});
  return ed25519_sign_check_equation(S, k, &A, R);
}
