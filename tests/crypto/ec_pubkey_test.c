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
  CHECK(quic_x509_ec_pubkey(key, sizeof(key), x, y) == 1);
  CHECK(x[0] == 0 && x[31] == 31);
  CHECK(y[0] == 0x40 && y[31] == 0x5f);
}

/* A compressed point (0x02 prefix) or wrong length is rejected. */
static void test_ec_pubkey_bad(void) {
  u8 key[66], x[32], y[32];
  key[0] = 0x00;
  key[1] = 0x02;
  CHECK(
      quic_x509_ec_pubkey(key, sizeof(key), x, y) == 0); /* not uncompressed */
  key[1] = 0x04;
  CHECK(quic_x509_ec_pubkey(key, 65, x, y) == 0); /* wrong length */
}

void test_ec_pubkey(void) {
  test_ec_pubkey_extract();
  test_ec_pubkey_bad();
}
