#include "crypto/pki/encoding/x509/basicconstraints.h"

#include "chain_golden.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "test.h"

/* cert1 carries basicConstraints with cA TRUE. */
static void test_ca_true(void) {
  quic_x509 c;
  CHECK(
      quic_x509_parse(quic_chain_golden1, sizeof(quic_chain_golden1), &c) == 1);
  CHECK(quic_x509_is_ca(c.tbs, c.tbs_len) == 1);
}

/* cert2 has basicConstraints present but cA absent (DER-default FALSE). */
static void test_ca_false(void) {
  quic_x509 c;
  CHECK(
      quic_x509_parse(quic_chain_golden2, sizeof(quic_chain_golden2), &c) == 1);
  CHECK(quic_x509_is_ca(c.tbs, c.tbs_len) == 0);
}

/* No extensions at all: not a CA. */
static void test_no_extensions(void) {
  const u8 tbs[] = {0x30, 0x03, 0x02, 0x01, 0x02};
  CHECK(quic_x509_is_ca(tbs, sizeof(tbs)) == 0);
}

void test_basicconstraints(void) {
  test_ca_true();
  test_ca_false();
  test_no_extensions();
}
