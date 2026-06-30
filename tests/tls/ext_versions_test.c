#include "test.h"

static void test_ext_versions_golden(void) {
  u8  buf[16];
  usz w = quic_tls_ext_supported_versions(buf, sizeof(buf));
  /* wire: type 0x002b, ext_data len 0x0003, list len 0x02, version 0x0304 */
  CHECK(w == 7);
  CHECK(buf[0] == 0x00 && buf[1] == 0x2b);
  CHECK(buf[2] == 0x00 && buf[3] == 0x03);
  CHECK(buf[4] == 0x02);
  CHECK(buf[5] == 0x03 && buf[6] == 0x04);
}

static void test_ext_versions_roundtrip(void) {
  u8  buf[16];
  usz w = quic_tls_ext_supported_versions(buf, sizeof(buf));
  CHECK(quic_tls_ext_versions_has_tls13(buf, w) == 1);
}

static void test_ext_versions_absent(void) {
  /* type ok, single version 0x0303 (TLS 1.2) -> not present */
  u8 buf[7] = {0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x03};
  CHECK(quic_tls_ext_versions_has_tls13(buf, sizeof(buf)) == 0);
}

static void test_ext_versions_decode_guards(void) {
  u8  buf[16];
  usz w = quic_tls_ext_supported_versions(buf, sizeof(buf));
  /* truncated body */
  CHECK(quic_tls_ext_versions_has_tls13(buf, w - 1) == 0);
  /* wrong extension_type */
  buf[1] = 0x2c;
  CHECK(quic_tls_ext_versions_has_tls13(buf, w) == 0);
  /* odd list length */
  u8 odd[6] = {0x00, 0x2b, 0x00, 0x02, 0x01, 0x03};
  CHECK(quic_tls_ext_versions_has_tls13(odd, sizeof(odd)) == 0);
}

static void test_ext_versions_encode_guard(void) {
  u8 buf[6];
  CHECK(quic_tls_ext_supported_versions(buf, sizeof(buf)) == 0);
}

void test_ext_versions(void) {
  test_ext_versions_golden();
  test_ext_versions_roundtrip();
  test_ext_versions_absent();
  test_ext_versions_decode_guards();
  test_ext_versions_encode_guard();
}
