#include "crypto/pki/encoding/x509/rsa_pubkey.h"

#include "test.h"

/* RFC 8017 A.1.1. A minimal RSAPublicKey: SEQUENCE { INTEGER n, INTEGER e }
 * wrapped in a BIT STRING value (0x00 unused-bits prefix). n carries a 0x00
 * sign pad that must be stripped; e is 65537 (0x010001). */
static void test_rsa_pubkey_extract(void) {
  const u8 key[] = {
      0x00,                                     /* BIT STRING unused bits */
      0x30, 0x0c,                               /* SEQUENCE, len 12 */
      0x02, 0x05, 0x00, 0x81, 0x82, 0x83, 0x84, /* INTEGER n (padded) */
      0x02, 0x03, 0x01, 0x00, 0x01,             /* INTEGER e = 65537 */
  };
  const u8 *n, *e;
  usz       n_len, e_len;
  CHECK(quic_x509_rsa_pubkey(key, sizeof(key), &n, &n_len, &e, &e_len) == 1);
  CHECK(n_len == 4 && n[0] == 0x81 && n[3] == 0x84); /* pad stripped */
  CHECK(e_len == 3 && e[0] == 0x01 && e[2] == 0x01);
}

/* A BIT STRING that does not lead with the 0x00 unused-bits octet is rejected.
 */
static void test_rsa_pubkey_bad_prefix(void) {
  const u8  key[] = {0x01, 0x30, 0x03, 0x02, 0x01, 0x01};
  const u8 *n, *e;
  usz       n_len, e_len;
  CHECK(quic_x509_rsa_pubkey(key, sizeof(key), &n, &n_len, &e, &e_len) == 0);
}

/* A SEQUENCE with only one INTEGER has no publicExponent. */
static void test_rsa_pubkey_missing_e(void) {
  const u8  key[] = {0x00, 0x30, 0x03, 0x02, 0x01, 0x05};
  const u8 *n, *e;
  usz       n_len, e_len;
  CHECK(quic_x509_rsa_pubkey(key, sizeof(key), &n, &n_len, &e, &e_len) == 0);
}

void test_rsa_pubkey(void) {
  test_rsa_pubkey_extract();
  test_rsa_pubkey_bad_prefix();
  test_rsa_pubkey_missing_e();
}
