#include "crypto/asymmetric/ecc/p256sign/rfc6979.h"

#include "crypto/asymmetric/ecc/p256/p256_field.h"
#include "crypto/symmetric/hash/hash/hmac.h"

/* RFC 6979 Section 3.2 for P-256 / SHA-256 (hlen == qlen == 256 bits). */

static void p256sign_copy(u8* dst, const u8* src, usz n) {
  for (usz i = 0; i < n; i++) dst[i] = src[i];
}

static void p256sign_set(u8* dst, u8 val, usz n) {
  for (usz i = 0; i < n; i++) dst[i] = val;
}

/* bits2octets(hash): reduce the 256-bit hash mod n into 32 big-endian bytes. */
static void ps_hash_mod_n(const u8 hash[32], u8 out[32]) {
  p256_fe h, e;
  p256_fp_from_be(h, hash);
  p256_fp_reduce_n(e, h);
  p256_fp_to_be(out, e);
}

/* msg = V || sep || priv || hred ; returns its length. */
static usz ps_build_seed(
    u8 msg[97], const u8 v[32], u8 sep, const u8 priv[32], const u8 hred[32]) {
  p256sign_copy(msg, v, 32);
  msg[32] = sep;
  p256sign_copy(msg + 33, priv, 32);
  p256sign_copy(msg + 65, hred, 32);
  return 97;
}

/* One HMAC step that mixes in (sep, priv, hred): K = HMAC(K, seed); V = HMAC(K,
 * V). */
static void ps_mix(
    u8 k[32], u8 v[32], u8 sep, const u8 priv[32], const u8 hred[32]) {
  u8  msg[97];
  usz n = ps_build_seed(msg, v, sep, priv, hred);
  hmac_sha256(wired_span_of(k, 32), wired_span_of(msg, n), k);
  hmac_sha256(wired_span_of(k, 32), wired_span_of(v, 32), v);
}

/* 1 if 1 <= cand < n (in range as a nonce). */
static int ps_k_in_range(const u8 cand[32]) {
  p256_fe c;
  p256_fp_from_be(c, cand);
  return !p256_fp_is_zero(c) && p256_fp_lt(c, p256_n);
}

/* RFC 6979 step h.3: on reject, K = HMAC_K(V||0x00); V = HMAC_K(V). */
static void ps_advance(u8 k[32], u8 v[32]) {
  u8 msg[33];
  p256sign_copy(msg, v, 32);
  msg[32] = 0x00;
  hmac_sha256(wired_span_of(k, 32), wired_span_of(msg, 33), k);
  hmac_sha256(wired_span_of(k, 32), wired_span_of(v, 32), v);
}

/* 1 if v is both in [1,n-1] and accepted by the caller's suitability check
 * (RFC 6979 Section 3.2 step h.3 / Section 3.4). */
static int ps_accept(const u8 v[32], p256sign_k_ok ok, void* ctx) {
  if (!ps_k_in_range(v)) return 0;
  return ok(v, ctx);
}

/* RFC 6979 step h: T = HMAC(K, V); loop via ps_advance until ps_accept. */
static void ps_gen_candidate(
    u8 k[32], u8 v[32], u8 out[32], p256sign_k_ok ok, void* ctx) {
  for (;;) {
    hmac_sha256(wired_span_of(k, 32), wired_span_of(v, 32), v);
    if (ps_accept(v, ok, ctx)) break;
    ps_advance(k, v);
  }
  p256sign_copy(out, v, 32);
}

static int ps_always_ok(const u8 cand[32], void* ctx) {
  (void)cand;
  (void)ctx;
  return 1;
}

void p256sign_k_retry(
    const u8      priv[32],
    const u8      hash[32],
    u8            out[32],
    p256sign_k_ok ok,
    void*         ctx) {
  u8 k[32], v[32], hred[32];
  p256sign_set(k, 0x00, 32);
  p256sign_set(v, 0x01, 32);
  ps_hash_mod_n(hash, hred);
  ps_mix(k, v, 0x00, priv, hred);
  ps_mix(k, v, 0x01, priv, hred);
  ps_gen_candidate(k, v, out, ok, ctx);
}

void p256sign_k(const u8 priv[32], const u8 hash[32], u8 out[32]) {
  p256sign_k_retry(priv, hash, out, ps_always_ok, 0);
}
