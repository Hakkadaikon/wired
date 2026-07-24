#include "crypto/asymmetric/ecc/p256/p256_ecdhe.h"

#include "common/platform/rng/rng.h"

/* FIPS 186-4 B.4.2: a candidate is a valid private key iff 0 < cand < n. */
static int p256_scalar_ok(const u8 cand[32]) {
  p256_fe v;
  quic_fp_from_be(v, cand);
  return !quic_fp_is_zero(v) && quic_fp_lt(v, quic_p256_n);
}

/* One rejection-sampling draw: 1 = accepted, 0 = out of range, -1 = hard RNG
 * failure (caller must not retry). */
static int p256_keygen_draw(u8 priv[32]) {
  if (!quic_rng_bytes(priv, 32)) return -1;
  return p256_scalar_ok(priv);
}

int quic_p256_keygen(u8 priv[32]) {
  for (int tries = 0; tries < 256; tries++) {
    int r = p256_keygen_draw(priv);
    if (r != 0) return r > 0;
  }
  return 0; /* astronomically unlikely: rejection rate is ~2^-32 */
}

int quic_p256_pubkey_encode(u8 out[QUIC_P256_PUBKEY_LEN], const u8 priv[32]) {
  ec_point p;
  quic_ec_mul(&p, priv, &quic_p256_g);
  if (p.inf) return 0;
  out[0] = 0x04;
  quic_fp_to_be(out + 1, p.x);
  quic_fp_to_be(out + 33, p.y);
  return 1;
}

int quic_p256_pubkey_decode(const u8 in[QUIC_P256_PUBKEY_LEN], ec_point* out) {
  if (in[0] != 0x04) return 0;
  quic_fp_from_be(out->x, in + 1);
  quic_fp_from_be(out->y, in + 33);
  out->inf = 0;
  return quic_ec_on_curve(out);
}

int quic_p256_ecdh(
    u8 out[32], const u8 priv[32], const u8 peer_pub[QUIC_P256_PUBKEY_LEN]) {
  ec_point peer, shared;
  if (!quic_p256_pubkey_decode(peer_pub, &peer)) return 0;
  quic_ec_mul(&shared, priv, &peer);
  if (shared.inf) return 0;
  quic_fp_to_be(out, shared.x);
  return 1;
}
