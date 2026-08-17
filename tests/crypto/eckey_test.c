#include "crypto/pki/encoding/eckey/eckey.h"

#include "common/bytes/util/bytes.h"
#include "common/bytes/util/ct.h"
#include "crypto/asymmetric/ecc/ed25519/ed25519.h"
#include "eckey_golden.h"
#include "test.h"
#include "tls/handshake/core/tls/x25519.h"

/* RFC 5915 3. SEC1 ECPrivateKey DER yields the 32-byte scalar. */
static void test_eckey_sec1_golden(void) {
  u8 out[32];
  CHECK(
      wired_eckey_p256_priv(
          wired_span_of(eckey_sec1_der, sizeof(eckey_sec1_der)), out) == 1);
  CHECK(ct_diff32(out, eckey_priv) == 0);
}

/* RFC 5958 2. The same key wrapped in PKCS#8 yields the same scalar. */
static void test_eckey_pkcs8_golden(void) {
  u8 out[32];
  CHECK(
      wired_eckey_p256_priv(
          wired_span_of(eckey_pkcs8_der, sizeof(eckey_pkcs8_der)), out) == 1);
  CHECK(ct_diff32(out, eckey_priv) == 0);
}

/* Copy the SEC1 golden and overwrite one byte at off. */
static wired_span mutated(u8* buf, usz off, u8 v) {
  bytes_memcpy(buf, eckey_sec1_der, sizeof(eckey_sec1_der));
  buf[off] = v;
  return wired_span_of(buf, sizeof(eckey_sec1_der));
}

/* Broken outer tag and unsupported version INTEGER are rejected. */
static void test_eckey_bad_structure(void) {
  u8 buf[sizeof(eckey_sec1_der)];
  u8 out[32];
  /* SEC1 layout: [0]=SEQUENCE, [4]=version, [6]=scalar length. */
  CHECK(eckey_sec1_der[4] == 0x01 && eckey_sec1_der[6] == 0x20);
  CHECK(wired_eckey_p256_priv(mutated(buf, 0, 0x31), out) == 0);
  CHECK(wired_eckey_p256_priv(mutated(buf, 4, 0x02), out) == 0);
}

/* A private key OCTET STRING of 31 or 33 bytes is not a P-256 scalar. */
static void test_eckey_bad_scalar_len(void) {
  u8 buf[sizeof(eckey_sec1_der)];
  u8 out[32];
  CHECK(wired_eckey_p256_priv(mutated(buf, 6, 0x1f), out) == 0);
  CHECK(wired_eckey_p256_priv(mutated(buf, 6, 0x21), out) == 0);
}

/* Truncated DER is rejected. */
static void test_eckey_truncated(void) {
  u8 out[32];
  CHECK(wired_eckey_p256_priv(wired_span_of(eckey_sec1_der, 10), out) == 0);
  CHECK(wired_eckey_p256_priv(wired_span_of(0, 0), out) == 0);
}

/* RFC 8410 7. Encoding the golden Ed25519 seed reproduces the exact
 * OneAsymmetricKey DER OpenSSL emits (hand-decoded byte layout documented
 * in eckey_golden.h). */
static void test_eckey_ed25519_encode_golden(void) {
  u8         buf[64];
  wired_obuf o = obuf_of(buf, sizeof(buf));
  CHECK(wired_eckey_ed25519_pkcs8_encode(eckey_ed25519_seed, &o) == 1);
  CHECK(o.len == sizeof(eckey_ed25519_pkcs8_der));
  CHECK(ct_diffn(buf, eckey_ed25519_pkcs8_der, o.len) == 0);
}

/* Encoding fails when out has no room for the 48-byte encoding. */
static void test_eckey_ed25519_encode_too_small(void) {
  u8         buf[47];
  wired_obuf o = obuf_of(buf, sizeof(buf));
  CHECK(wired_eckey_ed25519_pkcs8_encode(eckey_ed25519_seed, &o) == 0);
}

/* RFC 8410 7. Decoding the OpenSSL-produced OneAsymmetricKey DER (P-256
 * golden's Ed25519 counterpart) yields the same 32-byte seed. */
static void test_eckey_curve25519_decode_golden(void) {
  u8 out[32];
  CHECK(
      wired_eckey_curve25519_priv(
          wired_span_of(
              eckey_ed25519_pkcs8_der, sizeof(eckey_ed25519_pkcs8_der)),
          out) == 1);
  CHECK(ct_diff32(out, eckey_ed25519_seed) == 0);
}

/* Round-trip: wired_eckey_ed25519_pkcs8_encode then
 * wired_eckey_curve25519_priv reproduces the original seed exactly. */
static void test_eckey_ed25519_roundtrip(void) {
  u8         buf[64], out[32];
  wired_obuf o = obuf_of(buf, sizeof(buf));
  CHECK(wired_eckey_ed25519_pkcs8_encode(eckey_ed25519_seed, &o) == 1);
  CHECK(wired_eckey_curve25519_priv(wired_span_of(buf, o.len), out) == 1);
  CHECK(ct_diff32(out, eckey_ed25519_seed) == 0);
}

/* RFC 8032 7.1 TEST 1: importing the OneAsymmetricKey-wrapped secret key and
 * deriving its public key (RFC 8032 5.1.5, which clamps internally) yields
 * the RFC-published public key, proving the decoder returns the seed
 * unaltered for the clamp-on-use signing primitive to consume. */
static void test_eckey_ed25519_import_then_keypair(void) {
  u8 seed[32], pub[32];
  CHECK(
      wired_eckey_curve25519_priv(
          wired_span_of(
              eckey_ed25519_test1_pkcs8_der,
              sizeof(eckey_ed25519_test1_pkcs8_der)),
          seed) == 1);
  CHECK(ed25519_keypair(seed, pub) == 1);
  CHECK(ct_diff32(pub, eckey_ed25519_test1_pub) == 0);
}

/* RFC 7748 5.2 X25519 test vector: Alice's private key is RAW (not itself a
 * validly clamped scalar -- see the comment on eckey_x25519_alice_raw
 * in eckey_golden.h). Importing it via wired_eckey_curve25519_priv must
 * return those exact unclamped bytes; only wired_x25519_base's internal RFC
 * 7748 5 decodeScalar25519 clamping, applied on use, makes X25519(a, 9)
 * match Alice's published public key. */
static void test_eckey_x25519_import_clamped_on_use(void) {
  u8 scalar[32], pub[32];
  CHECK(
      wired_eckey_curve25519_priv(
          wired_span_of(
              eckey_x25519_alice_pkcs8_der,
              sizeof(eckey_x25519_alice_pkcs8_der)),
          scalar) == 1);
  /* The decoder does not clamp: the imported bytes equal the raw input. */
  CHECK(ct_diff32(scalar, eckey_x25519_alice_raw) == 0);
  CHECK(wired_x25519_base(pub, scalar) == 1);
  CHECK(ct_diff32(pub, eckey_x25519_alice_pub) == 0);
}

/* Wrong version (SEC1's version 1, not PKCS#8's 0) is rejected. */
static void test_eckey_curve25519_wrong_version(void) {
  u8 buf[sizeof(eckey_ed25519_pkcs8_der)];
  u8 out[32];
  bytes_memcpy(buf, eckey_ed25519_pkcs8_der, sizeof(eckey_ed25519_pkcs8_der));
  buf[4] = 0x01; /* version INTEGER value */
  CHECK(wired_eckey_curve25519_priv(wired_span_of(buf, sizeof(buf)), out) == 0);
}

/* A privateKey octet count other than 32 is rejected. */
static void test_eckey_curve25519_bad_len(void) {
  u8 buf[sizeof(eckey_ed25519_pkcs8_der)];
  u8 out[32];
  bytes_memcpy(buf, eckey_ed25519_pkcs8_der, sizeof(eckey_ed25519_pkcs8_der));
  buf[15] = 0x1f; /* inner OCTET STRING length octet (34 -> 31) */
  CHECK(wired_eckey_curve25519_priv(wired_span_of(buf, sizeof(buf)), out) == 0);
}

void test_eckey(void) {
  test_eckey_sec1_golden();
  test_eckey_pkcs8_golden();
  test_eckey_bad_structure();
  test_eckey_bad_scalar_len();
  test_eckey_truncated();
  test_eckey_ed25519_encode_golden();
  test_eckey_ed25519_encode_too_small();
  test_eckey_curve25519_decode_golden();
  test_eckey_ed25519_roundtrip();
  test_eckey_ed25519_import_then_keypair();
  test_eckey_x25519_import_clamped_on_use();
  test_eckey_curve25519_wrong_version();
  test_eckey_curve25519_bad_len();
}
