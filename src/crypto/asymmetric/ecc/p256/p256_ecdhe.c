#include "crypto/asymmetric/ecc/p256/p256_ecdhe.h"

#include "common/platform/rng/rng.h"

/* FIPS 186-4 B.4.2: a candidate is a valid private key iff 0 < cand < n. */
int p256_keygen_accept(const u8 cand[32]) {
  p256_fe v;
  int     ok;
  p256_fp_from_be(v, cand);
  ok = p256_scalar_in_range(v);
  p256_ct_public(&ok, sizeof ok);
  return ok;
}

/* One rejection-sampling draw: 1 = accepted, 0 = out of range, -1 = hard RNG
 * failure (caller must not retry). */
static int p256_keygen_draw(u8 priv[32]) {
  if (!rng_bytes(priv, 32)) {
    return -1;
  }
  return p256_keygen_accept(priv);
}

int p256_keygen(u8 priv[32]) {
  for (int tries = 0; tries < 256; tries++) {
    int r = p256_keygen_draw(priv);
    if (r != 0) {
      return r > 0;
    }
  }
  return 0; /* astronomically unlikely: rejection rate is ~2^-32 */
}

/* Constant-time: the encoding is always written (all-zero coordinates when
 * priv*G is infinity, i.e. priv == 0 mod n) and the result is returned. */
int p256_pubkey_encode(u8 out[P256_PUBKEY_LEN], const u8 priv[32]) {
  ec_point p;
  int      ok;
  ec_mul(&p, priv, &p256_g);
  out[0] = 0x04;
  p256_fp_to_be(out + 1, p.x);
  p256_fp_to_be(out + 33, p.y);
  ok = p.inf ^ 1;
  p256_ct_public(&ok, sizeof ok); /* fails only for priv == 0 mod n: public */
  return ok;
}

int p256_pubkey_decode(const u8 in[P256_PUBKEY_LEN], ec_point* out) {
  if (in[0] != 0x04) {
    return 0;
  }
  p256_fp_from_be(out->x, in + 1);
  p256_fp_from_be(out->y, in + 33);
  out->inf = 0;
  return ec_on_curve(out);
}

int p256_ecdh(
    u8 out[32], const u8 priv[32], const u8 peer_pub[P256_PUBKEY_LEN]) {
  ec_point peer, shared;
  int      ok;
  if (!p256_pubkey_decode(peer_pub, &peer)) {
    return 0;
  }
  ec_mul(&shared, priv, &peer);
  p256_fp_to_be(out, shared.x); /* all-zero when infinity */
  ok = shared.inf ^ 1;
  p256_ct_public(&ok, sizeof ok); /* fails only for priv == 0 mod n: public */
  return ok;
}
