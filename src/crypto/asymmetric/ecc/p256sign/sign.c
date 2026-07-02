#include "crypto/asymmetric/ecc/p256sign/sign.h"

#include "crypto/asymmetric/ecc/p256/p256_point.h"
#include "crypto/asymmetric/ecc/p256sign/rfc6979.h"

/* FIPS 186-4 Section 6.3. */

/* r = (k*G).x mod n. Returns 1 if r != 0. */
static int ps_compute_r(p256_fe r, const u8 kb[32]) {
  ec_point rp;
  quic_ec_mul(&rp, kb, &quic_p256_g);
  quic_fp_reduce(r, rp.x, quic_p256_n);
  return !quic_fp_is_zero(r);
}

/* s = k^-1 * sum mod n, with sum = (e + r*d) mod n from the caller. */
static void ps_compute_s(p256_fe s, const u8 kb[32], const p256_fe sum) {
  p256_fe k, kinv;
  quic_fp_from_be(k, kb);
  quic_mont_inv(kinv, k, &quic_p256_mont_n); /* k^-1 mod n, fast Montgomery */
  quic_fp_mul(s, (quic_fpab){kinv, sum}, quic_p256_n);
}

/* Low-S (RFC 6979 / BoringSSL): replace s with min(s, n - s) so s <= n/2. */
static void ps_low_s(p256_fe s) {
  p256_fe ns;
  quic_fp_sub(ns, (quic_fpab){quic_p256_n, s}, quic_p256_n);
  if (quic_fp_lt(ns, s)) quic_fp_set(s, ns);
}

int quic_p256sign_sign(
    const u8 priv[32], const u8 hash[32], u8 r[32], u8 s[32]) {
  u8      kb[32];
  p256_fe rv, sv, e, eh, d, rd, sum;
  quic_p256sign_k(priv, hash, kb);
  if (!ps_compute_r(rv, kb)) return 0;
  quic_fp_from_be(eh, hash);
  quic_fp_reduce(e, eh, quic_p256_n);
  quic_fp_from_be(d, priv);
  quic_fp_mul(rd, (quic_fpab){rv, d}, quic_p256_n);
  quic_fp_add(sum, (quic_fpab){e, rd}, quic_p256_n);
  ps_compute_s(sv, kb, sum);
  ps_low_s(sv);
  if (quic_fp_is_zero(sv)) return 0;
  quic_fp_to_be(r, rv);
  quic_fp_to_be(s, sv);
  return 1;
}
