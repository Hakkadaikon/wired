#include "crypto/pki/cert/tbscert/version_serial.h"

#include "crypto/pki/cert/tbscert/fields.h"
#include "test.h"
#include "x509_golden.h"

/* RFC 5280 4.1.2.1/4.1.2.2. version and serialNumber off the real tbs. */
static void test_vs_golden(void) {
  quic_tbscert t;
  CHECK(quic_tbscert_parse(quic_x509_golden + 4, 305, &t) == 1);

  u64 ver;
  CHECK(quic_tbscert_version(&t, &ver) == 1 && ver == 2);

  const u8 *serial;
  usz       len;
  CHECK(quic_tbscert_serial(&t, &serial, &len) == 1);
  CHECK(serial == quic_x509_golden + 15 && len == 20);
  CHECK(serial[0] == 0x60);
}

/* RFC 5280 4.1.2.1. An absent [0] version defaults to v1 (0). */
static void test_vs_default_v1(void) {
  quic_tbscert t;
  t.version     = 0;
  t.version_len = 0;
  u64 ver;
  CHECK(quic_tbscert_version(&t, &ver) == 1 && ver == 0);
}

/* RFC 5280 4.1.2.2. serialNumber over 20 octets is rejected. */
static void test_vs_serial_too_long(void) {
  quic_tbscert t;
  t.serial     = quic_x509_golden;
  t.serial_len = 21;
  const u8 *serial;
  usz       len;
  CHECK(quic_tbscert_serial(&t, &serial, &len) == 0);
}

void test_version_serial(void) {
  test_vs_golden();
  test_vs_default_v1();
  test_vs_serial_too_long();
}
