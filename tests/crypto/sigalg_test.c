#include "crypto/pki/cert/tbscert/sigalg.h"

#include "crypto/pki/cert/tbscert/fields.h"
#include "crypto/pki/encoding/asn1/derval.h"
#include "test.h"
#include "x509_golden.h"

/* RFC 5280 4.1.2.3. The tbs signature OID is ecdsa-with-SHA256. */
static void test_sigalg_oid(void) {
  quic_tbscert t;
  CHECK(quic_tbscert_parse(quic_span_of(quic_x509_golden + 4, 305), &t) == 1);

  quic_span oid;
  CHECK(quic_tbscert_sigalg_oid(&t, &oid) == 1);
  CHECK(oid.p == quic_x509_golden + 39 && oid.n == 8);
  CHECK(
      quic_der_oid_equal(
          oid, quic_span_of(
                   quic_oid_ecdsa_sha256, sizeof(quic_oid_ecdsa_sha256))) == 1);
}

/* RFC 5280 4.1.1.2. The tbs OID matches the outer signatureAlgorithm OID. */
static void test_sigalg_matches(void) {
  quic_tbscert t;
  CHECK(quic_tbscert_parse(quic_span_of(quic_x509_golden + 4, 305), &t) == 1);
  CHECK(
      quic_tbscert_sigalg_matches(
          &t, quic_span_of(
                  quic_oid_ecdsa_sha256, sizeof(quic_oid_ecdsa_sha256))) == 1);
}

/* RFC 5280 4.1.1.2. A different outer OID is a mismatch. */
static void test_sigalg_mismatch(void) {
  quic_tbscert t;
  CHECK(quic_tbscert_parse(quic_span_of(quic_x509_golden + 4, 305), &t) == 1);
  CHECK(
      quic_tbscert_sigalg_matches(
          &t, quic_span_of(quic_oid_ec_pubkey, sizeof(quic_oid_ec_pubkey))) ==
      0);
}

void test_sigalg(void) {
  test_sigalg_oid();
  test_sigalg_matches();
  test_sigalg_mismatch();
}
