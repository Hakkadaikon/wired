#include "crypto/pki/cert/tbscert/sigalg.h"

#include "crypto/pki/cert/tbscert/fields.h"
#include "crypto/pki/encoding/asn1/derval.h"
#include "test.h"
#include "x509_golden.h"

/* RFC 5280 4.1.2.3. The tbs signature OID is ecdsa-with-SHA256. */
static void test_sigalg_oid(void) {
  quic_tbscert t;
  CHECK(quic_tbscert_parse(wired_span_of(quic_x509_golden + 4, 305), &t) == 1);

  wired_span oid;
  CHECK(quic_tbscert_sigalg_oid(&t, &oid) == 1);
  CHECK(oid.p == quic_x509_golden + 39 && oid.n == 8);
  CHECK(
      quic_der_oid_equal(
          oid, wired_span_of(
                   quic_oid_ecdsa_sha256, sizeof(quic_oid_ecdsa_sha256))) == 1);
}

/* RFC 5280 4.1.1.2. The tbs OID matches the outer signatureAlgorithm OID. */
static void test_sigalg_matches(void) {
  quic_tbscert t;
  CHECK(quic_tbscert_parse(wired_span_of(quic_x509_golden + 4, 305), &t) == 1);
  CHECK(
      quic_tbscert_sigalg_matches(
          &t, wired_span_of(
                  quic_oid_ecdsa_sha256, sizeof(quic_oid_ecdsa_sha256))) == 1);
}

/* RFC 5280 4.1.1.2. A different outer OID is a mismatch. */
static void test_sigalg_mismatch(void) {
  quic_tbscert t;
  CHECK(quic_tbscert_parse(wired_span_of(quic_x509_golden + 4, 305), &t) == 1);
  CHECK(
      quic_tbscert_sigalg_matches(
          &t, wired_span_of(quic_oid_ec_pubkey, sizeof(quic_oid_ec_pubkey))) ==
      0);
}

/* RFC 5758 2. AlgorithmIdentifier VALUE bytes (SEQUENCE header stripped) for
 * ecdsa-with-SHA256, with the parameters field absent vs. present as NULL.
 * "MUST accept both NULL and absent parameters as legal and equivalent" --
 * quic_tbscert_sigalg_oid reads only the first (OID) element of sig_alg, so
 * it takes the same OID from either encoding without inspecting parameters. */
static const u8 sao_body_absent[]   = {0x06, 0x08, 0x2a, 0x86, 0x48,
                                       0xce, 0x3d, 0x04, 0x03, 0x02};
static const u8 sao_body_withnull[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
                                       0x3d, 0x04, 0x03, 0x02, 0x05, 0x00};

/* Every other quic_tbscert field is unused by quic_tbscert_sigalg_oid. */
static void sigalg_oid_of(wired_span sig_alg_body, wired_span* oid) {
  quic_tbscert t = {0};
  t.sig_alg      = sig_alg_body;
  CHECK(quic_tbscert_sigalg_oid(&t, oid) == 1);
}

/* RFC 5758 2. Absent parameters is a legal encoding. */
static void test_sigalg_params_absent_ok(void) {
  wired_span oid;
  sigalg_oid_of(wired_span_of(sao_body_absent, sizeof(sao_body_absent)), &oid);
  CHECK(
      quic_der_oid_equal(
          oid, wired_span_of(
                   quic_oid_ecdsa_sha256, sizeof(quic_oid_ecdsa_sha256))) == 1);
}

/* RFC 5758 2. A NULL parameters field is an equivalent legal encoding,
 * yielding the identical OID. */
static void test_sigalg_params_null_ok(void) {
  wired_span oid;
  sigalg_oid_of(
      wired_span_of(sao_body_withnull, sizeof(sao_body_withnull)), &oid);
  CHECK(
      quic_der_oid_equal(
          oid, wired_span_of(
                   quic_oid_ecdsa_sha256, sizeof(quic_oid_ecdsa_sha256))) == 1);
}

void test_sigalg(void) {
  test_sigalg_oid();
  test_sigalg_matches();
  test_sigalg_mismatch();
  test_sigalg_params_absent_ok();
  test_sigalg_params_null_ok();
}
