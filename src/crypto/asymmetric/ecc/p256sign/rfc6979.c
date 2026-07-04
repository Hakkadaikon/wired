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
  quic_fp_from_be(h, hash);
  quic_fp_reduce(e, h, quic_p256_n);
  quic_fp_to_be(out, e);
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
  quic_hmac_sha256(quic_span_of(k, 32), quic_span_of(msg, n), k);
  quic_hmac_sha256(quic_span_of(k, 32), quic_span_of(v, 32), v);
}

/* 1 if 1 <= cand < n (in range as a nonce). */
static int ps_k_in_range(const u8 cand[32]) {
  p256_fe c;
  quic_fp_from_be(c, cand);
  return !quic_fp_is_zero(c) && quic_fp_lt(c, quic_p256_n);
}

/* RFC 6979 step h: T = HMAC(K, V); on reject, K=HMAC(K,V||0x00); V=HMAC(K,V).
 */
static void ps_gen_candidate(u8 k[32], u8 v[32], u8 out[32]) {
  for (;;) {
    quic_hmac_sha256(quic_span_of(k, 32), quic_span_of(v, 32), v);
    if (ps_k_in_range(v)) break;
    u8 z = 0x00;
    u8 msg[33];
    p256sign_copy(msg, v, 32);
    msg[32] = z;
    quic_hmac_sha256(quic_span_of(k, 32), quic_span_of(msg, 33), k);
    quic_hmac_sha256(quic_span_of(k, 32), quic_span_of(v, 32), v);
  }
  p256sign_copy(out, v, 32);
}

void quic_p256sign_k(const u8 priv[32], const u8 hash[32], u8 out[32]) {
  u8 k[32], v[32], hred[32];
  p256sign_set(k, 0x00, 32);
  p256sign_set(v, 0x01, 32);
  ps_hash_mod_n(hash, hred);
  ps_mix(k, v, 0x00, priv, hred);
  ps_mix(k, v, 0x01, priv, hred);
  ps_gen_candidate(k, v, out);
}
