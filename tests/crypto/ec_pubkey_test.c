#include "crypto/pki/encoding/x509/ec_pubkey.h"

#include "test.h"

/* SEC1 2.3.3. 0x00 (unused bits) || 0x04 || X(32) || Y(32) splits into X, Y. */
static void test_ec_pubkey_extract(void) {
  u8 key[66];
  u8 x[32], y[32];
  key[0] = 0x00;
  key[1] = 0x04;
  for (usz i = 0; i < 32; i++) {
    key[2 + i]  = (u8)i;
    key[34 + i] = (u8)(0x40 + i);
  }
  CHECK(x509_ec_pubkey(wired_span_of(key, sizeof(key)), x, y) == 1);
  CHECK(x[0] == 0 && x[31] == 31);
  CHECK(y[0] == 0x40 && y[31] == 0x5f);
}

/* A 66-byte key with a compressed tag is malformed (compressed keys are
 * 34 bytes); wrong length is rejected either way. */
static void test_ec_pubkey_bad(void) {
  u8 key[66], x[32], y[32];
  key[0] = 0x00;
  key[1] = 0x02;
  CHECK(x509_ec_pubkey(wired_span_of(key, sizeof(key)), x, y) == 0);
  key[1] = 0x04;
  CHECK(x509_ec_pubkey(wired_span_of(key, 65), x, y) == 0); /* short */
}

/* FIPS 186-4 D.1.2.3 P-256 base point G, big-endian X/Y (hand-verified: Y is
 * odd, so SEC1 2.3.3 compression tags it 0x03). */
static const u8 p256_gx[32] = {0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
                               0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
                               0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
                               0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96};
static const u8 p256_gy[32] = {0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
                               0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
                               0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
                               0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5};

/* SEC1 2.3.4 / RFC 5480 2.2. G compressed with the correct tag (0x03, Y odd)
 * decompresses back to the known Y. */
static void test_ec_pubkey_compressed_odd(void) {
  u8 key[34], x[32], y[32];
  key[0] = 0x00;
  key[1] = 0x03;
  for (usz i = 0; i < 32; i++) key[2 + i] = p256_gx[i];
  CHECK(x509_ec_pubkey(wired_span_of(key, sizeof(key)), x, y) == 1);
  for (usz i = 0; i < 32; i++) CHECK(x[i] == p256_gx[i]);
  for (usz i = 0; i < 32; i++) CHECK(y[i] == p256_gy[i]);
}

/* The wrong parity tag (0x02, Y even) on the same X recovers p - Y instead
 * (SEC1 2.3.4's other root), not the known odd Y. */
static void test_ec_pubkey_compressed_even_selects_other_root(void) {
  u8 key[34], x[32], y[32];
  key[0] = 0x00;
  key[1] = 0x02;
  for (usz i = 0; i < 32; i++) key[2 + i] = p256_gx[i];
  CHECK(x509_ec_pubkey(wired_span_of(key, sizeof(key)), x, y) == 1);
  CHECK((y[31] & 1) == 0);
  int same = 1;
  for (usz i = 0; i < 32; i++)
    if (y[i] != p256_gy[i]) same = 0;
  CHECK(same == 0);
}

/* An unrecognized tag octet (neither 0x02/0x03/0x04) is rejected. */
static void test_ec_pubkey_bad_tag(void) {
  u8 key[34], x[32], y[32];
  key[0] = 0x00;
  key[1] = 0x05;
  for (usz i = 0; i < 32; i++) key[2 + i] = p256_gx[i];
  CHECK(x509_ec_pubkey(wired_span_of(key, sizeof(key)), x, y) == 0);
}

/* FIPS 186-4 D.1.2.4 P-384 base point G, big-endian X/Y (hand-verified: Y is
 * odd, so SEC1 2.3.3 compression tags it 0x03). */
static const u8 p384_gx[48] = {
    0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37, 0x8e, 0xb1, 0xc7, 0x1e,
    0xf3, 0x20, 0xad, 0x74, 0x6e, 0x1d, 0x3b, 0x62, 0x8b, 0xa7, 0x9b, 0x98,
    0x59, 0xf7, 0x41, 0xe0, 0x82, 0x54, 0x2a, 0x38, 0x55, 0x02, 0xf2, 0x5d,
    0xbf, 0x55, 0x29, 0x6c, 0x3a, 0x54, 0x5e, 0x38, 0x72, 0x76, 0x0a, 0xb7};
static const u8 p384_gy[48] = {
    0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f, 0x5d, 0x9e, 0x98, 0xbf,
    0x92, 0x92, 0xdc, 0x29, 0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c,
    0xe9, 0xda, 0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0, 0x0a, 0x60, 0xb1, 0xce,
    0x1d, 0x7e, 0x81, 0x9d, 0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f};

/* SEC1 2.3.4 / RFC 5480 2.2. P-384 G compressed with the correct tag (0x03,
 * Y odd) decompresses back to the known Y. */
static void test_ec_pubkey384_compressed_odd(void) {
  u8 key[50], x[48], y[48];
  key[0] = 0x00;
  key[1] = 0x03;
  for (usz i = 0; i < 48; i++) key[2 + i] = p384_gx[i];
  CHECK(x509_ec_pubkey384(wired_span_of(key, sizeof(key)), x, y) == 1);
  for (usz i = 0; i < 48; i++) CHECK(x[i] == p384_gx[i]);
  for (usz i = 0; i < 48; i++) CHECK(y[i] == p384_gy[i]);
}

/* The wrong parity tag (0x02, Y even) recovers p - Y instead. */
static void test_ec_pubkey384_compressed_even_selects_other_root(void) {
  u8 key[50], x[48], y[48];
  key[0] = 0x00;
  key[1] = 0x02;
  for (usz i = 0; i < 48; i++) key[2 + i] = p384_gx[i];
  CHECK(x509_ec_pubkey384(wired_span_of(key, sizeof(key)), x, y) == 1);
  CHECK((y[47] & 1) == 0);
  int same = 1;
  for (usz i = 0; i < 48; i++)
    if (y[i] != p384_gy[i]) same = 0;
  CHECK(same == 0);
}

/* An unrecognized tag octet is rejected. */
static void test_ec_pubkey384_bad_tag(void) {
  u8 key[50], x[48], y[48];
  key[0] = 0x00;
  key[1] = 0x05;
  for (usz i = 0; i < 48; i++) key[2 + i] = p384_gx[i];
  CHECK(x509_ec_pubkey384(wired_span_of(key, sizeof(key)), x, y) == 0);
}

void test_ec_pubkey(void) {
  test_ec_pubkey_extract();
  test_ec_pubkey_bad();
  test_ec_pubkey_compressed_odd();
  test_ec_pubkey_compressed_even_selects_other_root();
  test_ec_pubkey_bad_tag();
  test_ec_pubkey384_compressed_odd();
  test_ec_pubkey384_compressed_even_selects_other_root();
  test_ec_pubkey384_bad_tag();
}
