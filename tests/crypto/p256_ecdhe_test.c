#include "crypto/asymmetric/ecc/p256/p256_ecdhe.h"

#include "test.h"

/* --- keygen: rejection sampling into [1, n-1] --------------------------- */

/* Every generated scalar must be nonzero and < n (FIPS 186-4 B.4.2 domain). */
static void test_p256_keygen_range(void) {
  for (int i = 0; i < 200; i++) {
    u8      priv[32];
    p256_fe v;
    CHECK(p256_keygen(priv) == 1);
    p256_fp_from_be(v, priv);
    CHECK(!p256_fp_is_zero(v));
    CHECK(p256_fp_lt(v, p256_n));
  }
}

/* Boundary values for the accept predicate, computed from the same n the
 * production code uses (no external constant). */
static void test_p256_keygen_boundary(void) {
  u8      zero[32] = {0};
  u8      nbytes[32], nm1bytes[32];
  p256_fe one = {1, 0, 0, 0}, nm1;
  p256_fp_to_be(nbytes, p256_n);
  p256_fp_sub(nm1, (fpab){p256_n, one}, p256_n);
  p256_fp_to_be(nm1bytes, nm1);
  CHECK(p256_scalar_ok(zero) == 0);     /* 0 rejected */
  CHECK(p256_scalar_ok(nbytes) == 0);   /* n rejected (not < n) */
  CHECK(p256_scalar_ok(nm1bytes) == 1); /* n-1 accepted */
}

/* --- SEC1 uncompressed encode/decode round trip -------------------------- */

static void test_p256_pubkey_roundtrip(void) {
  u8       priv[32], pub[P256_PUBKEY_LEN];
  ec_point p;
  CHECK(p256_keygen(priv) == 1);
  CHECK(p256_pubkey_encode(pub, priv) == 1);
  CHECK(pub[0] == 0x04);
  CHECK(p256_pubkey_decode(pub, &p) == 1);
  CHECK(!p.inf);
  CHECK(ec_on_curve(&p));
  {
    u8 xbe[32], ybe[32];
    p256_fp_to_be(xbe, p.x);
    p256_fp_to_be(ybe, p.y);
    for (usz i = 0; i < 32; i++) {
      CHECK(xbe[i] == pub[1 + i]);
    }
    for (usz i = 0; i < 32; i++) {
      CHECK(ybe[i] == pub[33 + i]);
    }
  }
}

static void test_p256_pubkey_decode_rejects_bad_prefix(void) {
  u8       pub[P256_PUBKEY_LEN] = {0};
  ec_point p;
  pub[0] = 0x02; /* compressed form: not supported */
  CHECK(p256_pubkey_decode(pub, &p) == 0);
}

/* 1 * G == G: hand-computable base case for the encoder. */
static void test_p256_pubkey_encode_scalar_one(void) {
  u8 priv[32] = {0}, pub[P256_PUBKEY_LEN], gx[32], gy[32];
  priv[31]    = 1;
  CHECK(p256_pubkey_encode(pub, priv) == 1);
  p256_fp_to_be(gx, p256_g.x);
  p256_fp_to_be(gy, p256_g.y);
  for (usz i = 0; i < 32; i++) {
    CHECK(pub[1 + i] == gx[i]);
  }
  for (usz i = 0; i < 32; i++) {
    CHECK(pub[33 + i] == gy[i]);
  }
}

/* --- ECDH shared-secret wrapper ------------------------------------------ */

/* Diffie-Hellman symmetry: ecdh(a, B) == ecdh(b, A) for A = aG, B = bG. This
 * is the standard cross-check for an ECDH implementation when no external
 * vector is trusted blindly (RFC 8446/SEC1 offer no worked P-256 example in
 * the primary source itself). */
static void test_p256_ecdh_symmetry(void) {
  u8 priv_a[32], priv_b[32];
  u8 pub_a[P256_PUBKEY_LEN], pub_b[P256_PUBKEY_LEN];
  u8 secret_a[32], secret_b[32];
  CHECK(p256_keygen(priv_a) == 1);
  CHECK(p256_keygen(priv_b) == 1);
  CHECK(p256_pubkey_encode(pub_a, priv_a) == 1);
  CHECK(p256_pubkey_encode(pub_b, priv_b) == 1);
  CHECK(p256_ecdh(secret_a, priv_a, pub_b) == 1);
  CHECK(p256_ecdh(secret_b, priv_b, pub_a) == 1);
  for (usz i = 0; i < 32; i++) {
    CHECK(secret_a[i] == secret_b[i]);
  }
}

/* RFC 5903 8.1 (256-bit random ECP group): initiator i, responder r, their
 * public keys g^i = (gix, giy), g^r = (grx, gry), and the shared secret
 * girx, copied from the RFC text. */
static const u8 r5903_i[32] = {
    0xc8, 0x8f, 0x01, 0xf5, 0x10, 0xd9, 0xac, 0x3f, 0x70, 0xa2, 0x92,
    0xda, 0xa2, 0x31, 0x6d, 0xe5, 0x44, 0xe9, 0xaa, 0xb8, 0xaf, 0xe8,
    0x40, 0x49, 0xc6, 0x2a, 0x9c, 0x57, 0x86, 0x2d, 0x14, 0x33,
};
static const u8 r5903_gi[P256_PUBKEY_LEN] = {
    0x04, 0xda, 0xd0, 0xb6, 0x53, 0x94, 0x22, 0x1c, 0xf9, 0xb0, 0x51,
    0xe1, 0xfe, 0xca, 0x57, 0x87, 0xd0, 0x98, 0xdf, 0xe6, 0x37, 0xfc,
    0x90, 0xb9, 0xef, 0x94, 0x5d, 0x0c, 0x37, 0x72, 0x58, 0x11, 0x80,
    0x52, 0x71, 0xa0, 0x46, 0x1c, 0xdb, 0x82, 0x52, 0xd6, 0x1f, 0x1c,
    0x45, 0x6f, 0xa3, 0xe5, 0x9a, 0xb1, 0xf4, 0x5b, 0x33, 0xac, 0xcf,
    0x5f, 0x58, 0x38, 0x9e, 0x05, 0x77, 0xb8, 0x99, 0x0b, 0xb3,
};
static const u8 r5903_r[32] = {
    0xc6, 0xef, 0x9c, 0x5d, 0x78, 0xae, 0x01, 0x2a, 0x01, 0x11, 0x64,
    0xac, 0xb3, 0x97, 0xce, 0x20, 0x88, 0x68, 0x5d, 0x8f, 0x06, 0xbf,
    0x9b, 0xe0, 0xb2, 0x83, 0xab, 0x46, 0x47, 0x6b, 0xee, 0x53,
};
static const u8 r5903_gr[P256_PUBKEY_LEN] = {
    0x04, 0xd1, 0x2d, 0xfb, 0x52, 0x89, 0xc8, 0xd4, 0xf8, 0x12, 0x08,
    0xb7, 0x02, 0x70, 0x39, 0x8c, 0x34, 0x22, 0x96, 0x97, 0x0a, 0x0b,
    0xcc, 0xb7, 0x4c, 0x73, 0x6f, 0xc7, 0x55, 0x44, 0x94, 0xbf, 0x63,
    0x56, 0xfb, 0xf3, 0xca, 0x36, 0x6c, 0xc2, 0x3e, 0x81, 0x57, 0x85,
    0x4c, 0x13, 0xc5, 0x8d, 0x6a, 0xac, 0x23, 0xf0, 0x46, 0xad, 0xa3,
    0x0f, 0x83, 0x53, 0xe7, 0x4f, 0x33, 0x03, 0x98, 0x72, 0xab,
};
static const u8 r5903_girx[32] = {
    0xd6, 0x84, 0x0f, 0x6b, 0x42, 0xf6, 0xed, 0xaf, 0xd1, 0x31, 0x16,
    0xe0, 0xe1, 0x25, 0x65, 0x20, 0x2f, 0xef, 0x8e, 0x9e, 0xce, 0x7d,
    0xce, 0x03, 0x81, 0x24, 0x64, 0xd0, 0x4b, 0x94, 0x42, 0xde,
};

static int r5903_eq(const u8* a, const u8* b, usz n) {
  int d = 0;
  for (usz i = 0; i < n; i++) {
    d |= a[i] ^ b[i];
  }
  return d == 0;
}

/* RFC 5903 8.1 known answer: both public keys and the shared secret from
 * each side. */
static void test_p256_ecdh_rfc5903(void) {
  u8 pub[P256_PUBKEY_LEN], z[32];
  CHECK(p256_pubkey_encode(pub, r5903_i) == 1);
  CHECK(r5903_eq(pub, r5903_gi, P256_PUBKEY_LEN));
  CHECK(p256_pubkey_encode(pub, r5903_r) == 1);
  CHECK(r5903_eq(pub, r5903_gr, P256_PUBKEY_LEN));
  CHECK(p256_ecdh(z, r5903_i, r5903_gr) == 1);
  CHECK(r5903_eq(z, r5903_girx, 32));
  CHECK(p256_ecdh(z, r5903_r, r5903_gi) == 1);
  CHECK(r5903_eq(z, r5903_girx, 32));
}

/* ecdh(1, B) == X(B): hand-computable base case (scalar 1 is the identity for
 * scalar multiplication). */
static void test_p256_ecdh_scalar_one(void) {
  u8 priv_one[32] = {0};
  u8 priv_b[32], pub_b[P256_PUBKEY_LEN], secret[32];
  priv_one[31] = 1;
  CHECK(p256_keygen(priv_b) == 1);
  CHECK(p256_pubkey_encode(pub_b, priv_b) == 1);
  CHECK(p256_ecdh(secret, priv_one, pub_b) == 1);
  for (usz i = 0; i < 32; i++) {
    CHECK(secret[i] == pub_b[1 + i]);
  }
}

/* Boundary scalar n-1 (largest valid private key) still produces a valid
 * shared secret. */
static void test_p256_ecdh_scalar_max(void) {
  u8      priv_max[32];
  p256_fe one = {1, 0, 0, 0}, nm1;
  u8      priv_b[32], pub_b[P256_PUBKEY_LEN], secret[32];
  p256_fp_sub(nm1, (fpab){p256_n, one}, p256_n);
  p256_fp_to_be(priv_max, nm1);
  CHECK(p256_keygen(priv_b) == 1);
  CHECK(p256_pubkey_encode(pub_b, priv_b) == 1);
  CHECK(p256_ecdh(secret, priv_max, pub_b) == 1);
}

static void test_p256_ecdh_rejects_bad_peer_key(void) {
  u8 priv[32], pub_bad[P256_PUBKEY_LEN] = {0}, secret[32];
  CHECK(p256_keygen(priv) == 1);
  pub_bad[0] = 0x02;
  CHECK(p256_ecdh(secret, priv, pub_bad) == 0);
}

/* RFC 6090 3: a peer share whose x is p (congruent to the on-curve x = 0,
 * but not an element of Fp) is rejected; the canonical (0, y) is accepted.
 * y = sqrt(b) mod p, computed with Python big integers. */
static void test_p256_ecdh_rejects_coord_ge_p(void) {
  static const u8 y0[32] = {0x66, 0x48, 0x5c, 0x78, 0x0e, 0x2f, 0x83, 0xd7,
                            0x24, 0x33, 0xbd, 0x5d, 0x84, 0xa0, 0x6b, 0xb6,
                            0x54, 0x1c, 0x2a, 0xf3, 0x1d, 0xae, 0x87, 0x17,
                            0x28, 0xbf, 0x85, 0x6a, 0x17, 0x4f, 0x93, 0xf4};
  u8              priv[32], pub[P256_PUBKEY_LEN] = {0x04}, secret[32];
  CHECK(p256_keygen(priv) == 1);
  for (usz i = 0; i < 32; i++) {
    pub[33 + i] = y0[i];
  }
  CHECK(p256_ecdh(secret, priv, pub) == 1);
  p256_fp_to_be(pub + 1, p256_p); /* x = p */
  CHECK(p256_ecdh(secret, priv, pub) == 0);
}

/* A zero private key yields the point at infinity, which has no encoding
 * (SEC1 2.3.3) and no shared secret (SP 800-56A 5.7.1.2). */
static void test_p256_ecdh_zero_scalar(void) {
  u8 zero[32] = {0}, priv[32], pub[P256_PUBKEY_LEN], secret[32];
  CHECK(p256_pubkey_encode(pub, zero) == 0);
  CHECK(p256_keygen(priv) == 1);
  CHECK(p256_pubkey_encode(pub, priv) == 1);
  CHECK(p256_ecdh(secret, zero, pub) == 0);
}

void test_p256_ecdhe(void) {
  test_p256_keygen_range();
  test_p256_keygen_boundary();
  test_p256_pubkey_roundtrip();
  test_p256_pubkey_decode_rejects_bad_prefix();
  test_p256_pubkey_encode_scalar_one();
  test_p256_ecdh_symmetry();
  test_p256_ecdh_rfc5903();
  test_p256_ecdh_scalar_one();
  test_p256_ecdh_scalar_max();
  test_p256_ecdh_rejects_bad_peer_key();
  test_p256_ecdh_rejects_coord_ge_p();
  test_p256_ecdh_zero_scalar();
}
