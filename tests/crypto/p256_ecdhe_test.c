#include "crypto/asymmetric/ecc/p256/p256_ecdhe.h"

#include "test.h"

/* --- keygen: rejection sampling into [1, n-1] --------------------------- */

/* Every generated scalar must be nonzero and < n (FIPS 186-4 B.4.2 domain). */
static void test_p256_keygen_range(void) {
  for (int i = 0; i < 200; i++) {
    u8      priv[32];
    p256_fe v;
    CHECK(quic_p256_keygen(priv) == 1);
    quic_fp_from_be(v, priv);
    CHECK(!quic_fp_is_zero(v));
    CHECK(quic_fp_lt(v, quic_p256_n));
  }
}

/* Boundary values for the accept predicate, computed from the same n the
 * production code uses (no external constant). */
static void test_p256_keygen_boundary(void) {
  u8      zero[32] = {0};
  u8      nbytes[32], nm1bytes[32];
  p256_fe one = {1, 0, 0, 0}, nm1;
  quic_fp_to_be(nbytes, quic_p256_n);
  quic_fp_sub(nm1, (quic_fpab){quic_p256_n, one}, quic_p256_n);
  quic_fp_to_be(nm1bytes, nm1);
  CHECK(p256_scalar_ok(zero) == 0);     /* 0 rejected */
  CHECK(p256_scalar_ok(nbytes) == 0);   /* n rejected (not < n) */
  CHECK(p256_scalar_ok(nm1bytes) == 1); /* n-1 accepted */
}

/* --- SEC1 uncompressed encode/decode round trip -------------------------- */

static void test_p256_pubkey_roundtrip(void) {
  u8       priv[32], pub[QUIC_P256_PUBKEY_LEN];
  ec_point p;
  CHECK(quic_p256_keygen(priv) == 1);
  CHECK(quic_p256_pubkey_encode(pub, priv) == 1);
  CHECK(pub[0] == 0x04);
  CHECK(quic_p256_pubkey_decode(pub, &p) == 1);
  CHECK(!p.inf);
  CHECK(quic_ec_on_curve(&p));
  {
    u8 xbe[32], ybe[32];
    quic_fp_to_be(xbe, p.x);
    quic_fp_to_be(ybe, p.y);
    for (usz i = 0; i < 32; i++) CHECK(xbe[i] == pub[1 + i]);
    for (usz i = 0; i < 32; i++) CHECK(ybe[i] == pub[33 + i]);
  }
}

static void test_p256_pubkey_decode_rejects_bad_prefix(void) {
  u8       pub[QUIC_P256_PUBKEY_LEN] = {0};
  ec_point p;
  pub[0] = 0x02; /* compressed form: not supported */
  CHECK(quic_p256_pubkey_decode(pub, &p) == 0);
}

/* 1 * G == G: hand-computable base case for the encoder. */
static void test_p256_pubkey_encode_scalar_one(void) {
  u8 priv[32] = {0}, pub[QUIC_P256_PUBKEY_LEN], gx[32], gy[32];
  priv[31]    = 1;
  CHECK(quic_p256_pubkey_encode(pub, priv) == 1);
  quic_fp_to_be(gx, quic_p256_g.x);
  quic_fp_to_be(gy, quic_p256_g.y);
  for (usz i = 0; i < 32; i++) CHECK(pub[1 + i] == gx[i]);
  for (usz i = 0; i < 32; i++) CHECK(pub[33 + i] == gy[i]);
}

/* --- ECDH shared-secret wrapper ------------------------------------------ */

/* Diffie-Hellman symmetry: ecdh(a, B) == ecdh(b, A) for A = aG, B = bG. This
 * is the standard cross-check for an ECDH implementation when no external
 * vector is trusted blindly (RFC 8446/SEC1 offer no worked P-256 example in
 * the primary source itself). */
static void test_p256_ecdh_symmetry(void) {
  u8 priv_a[32], priv_b[32];
  u8 pub_a[QUIC_P256_PUBKEY_LEN], pub_b[QUIC_P256_PUBKEY_LEN];
  u8 secret_a[32], secret_b[32];
  CHECK(quic_p256_keygen(priv_a) == 1);
  CHECK(quic_p256_keygen(priv_b) == 1);
  CHECK(quic_p256_pubkey_encode(pub_a, priv_a) == 1);
  CHECK(quic_p256_pubkey_encode(pub_b, priv_b) == 1);
  CHECK(quic_p256_ecdh(secret_a, priv_a, pub_b) == 1);
  CHECK(quic_p256_ecdh(secret_b, priv_b, pub_a) == 1);
  for (usz i = 0; i < 32; i++) CHECK(secret_a[i] == secret_b[i]);
}

/* ecdh(1, B) == X(B): hand-computable base case (scalar 1 is the identity for
 * scalar multiplication). */
static void test_p256_ecdh_scalar_one(void) {
  u8 priv_one[32] = {0};
  u8 priv_b[32], pub_b[QUIC_P256_PUBKEY_LEN], secret[32];
  priv_one[31] = 1;
  CHECK(quic_p256_keygen(priv_b) == 1);
  CHECK(quic_p256_pubkey_encode(pub_b, priv_b) == 1);
  CHECK(quic_p256_ecdh(secret, priv_one, pub_b) == 1);
  for (usz i = 0; i < 32; i++) CHECK(secret[i] == pub_b[1 + i]);
}

/* Boundary scalar n-1 (largest valid private key) still produces a valid
 * shared secret. */
static void test_p256_ecdh_scalar_max(void) {
  u8      priv_max[32];
  p256_fe one = {1, 0, 0, 0}, nm1;
  u8      priv_b[32], pub_b[QUIC_P256_PUBKEY_LEN], secret[32];
  quic_fp_sub(nm1, (quic_fpab){quic_p256_n, one}, quic_p256_n);
  quic_fp_to_be(priv_max, nm1);
  CHECK(quic_p256_keygen(priv_b) == 1);
  CHECK(quic_p256_pubkey_encode(pub_b, priv_b) == 1);
  CHECK(quic_p256_ecdh(secret, priv_max, pub_b) == 1);
}

static void test_p256_ecdh_rejects_bad_peer_key(void) {
  u8 priv[32], pub_bad[QUIC_P256_PUBKEY_LEN] = {0}, secret[32];
  CHECK(quic_p256_keygen(priv) == 1);
  pub_bad[0] = 0x02;
  CHECK(quic_p256_ecdh(secret, priv, pub_bad) == 0);
}

void test_p256_ecdhe(void) {
  test_p256_keygen_range();
  test_p256_keygen_boundary();
  test_p256_pubkey_roundtrip();
  test_p256_pubkey_decode_rejects_bad_prefix();
  test_p256_pubkey_encode_scalar_one();
  test_p256_ecdh_symmetry();
  test_p256_ecdh_scalar_one();
  test_p256_ecdh_scalar_max();
  test_p256_ecdh_rejects_bad_peer_key();
}
