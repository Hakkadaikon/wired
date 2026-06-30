#include "crypto/pki/encoding/x509/validity.h"

#include "crypto/pki/encoding/x509/x509.h"
#include "test.h"
#include "x509_golden.h"

/* The golden cert is valid 20260628030430 .. 20270628030430 (UTCTime). */
#define NB 20260628030430ULL
#define NA 20270628030430ULL

static void test_validity_golden(void) {
  quic_x509 c;
  CHECK(quic_x509_parse(quic_x509_golden, sizeof(quic_x509_golden), &c) == 1);

  /* exactly notBefore and notAfter are inclusive */
  CHECK(quic_x509_validity_ok(c.tbs, c.tbs_len, NB) == 1);
  CHECK(quic_x509_validity_ok(c.tbs, c.tbs_len, NA) == 1);
  /* a moment inside the window */
  CHECK(quic_x509_validity_ok(c.tbs, c.tbs_len, 20261225000000ULL) == 1);
  /* one second before notBefore: expired/not-yet-valid */
  CHECK(quic_x509_validity_ok(c.tbs, c.tbs_len, NB - 1) == 0);
  /* one second after notAfter: expired */
  CHECK(quic_x509_validity_ok(c.tbs, c.tbs_len, NA + 1) == 0);
}

static void test_validity_malformed(void) {
  /* tbs too short to read a SEQUENCE header */
  CHECK(quic_x509_validity_ok(quic_x509_golden + 4, 3, NB) == 0);
  /* tbs SEQUENCE without enough elements to reach validity */
  const u8 tbs[] = {0x30, 0x03, 0x02, 0x01, 0x02};
  CHECK(quic_x509_validity_ok(tbs, sizeof(tbs), NB) == 0);
}

void test_validity(void) {
  test_validity_golden();
  test_validity_malformed();
}
