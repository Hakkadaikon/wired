#include "crypto/pki/cert/tbscert/version_serial.h"

#include "crypto/pki/cert/tbscert/fields.h"
#include "test.h"
#include "x509_golden.h"

/* RFC 5280 4.1.2.1/4.1.2.2. version and serialNumber off the real tbs. */
static void test_vs_golden(void) {
  tbscert t;
  CHECK(tbscert_parse(wired_span_of(x509_golden + 4, 305), &t) == 1);

  u64 ver;
  CHECK(tbscert_version(&t, &ver) == 1 && ver == 2);

  wired_span serial;
  CHECK(tbscert_serial(&t, &serial) == 1);
  CHECK(serial.p == x509_golden + 15 && serial.n == 20);
  CHECK(serial.p[0] == 0x60);
}

/* RFC 5280 4.1.2.1. An absent [0] version defaults to v1 (0). */
static void test_vs_default_v1(void) {
  tbscert t;
  t.version = wired_span_of(0, 0);
  u64 ver;
  CHECK(tbscert_version(&t, &ver) == 1 && ver == 0);
}

/* RFC 5280 4.1.2.2. serialNumber over 20 octets is rejected. */
static void test_vs_serial_too_long(void) {
  tbscert t;
  t.serial = wired_span_of(x509_golden, 21);
  wired_span serial;
  CHECK(tbscert_serial(&t, &serial) == 0);
}

void test_version_serial(void) {
  test_vs_golden();
  test_vs_default_v1();
  test_vs_serial_too_long();
}
