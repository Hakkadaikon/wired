#include "tls/handshake/core/tls/certverify.h"

#include "rsacv_golden.h"
#include "test.h"
#include "x509_golden.h"

/* RFC 8446 4.4.3. An unknown SignatureScheme is rejected outright. */
static void test_certverify_bad_scheme(void) {
  u8                 th[32], sig[64];
  quic_certverify_in in;
  for (usz i = 0; i < 32; i++) th[i] = (u8)i;
  for (usz i = 0; i < 64; i++) sig[i] = 0;
  in.cert            = quic_span_of(quic_x509_golden, sizeof(quic_x509_golden));
  in.sig             = quic_span_of(sig, sizeof(sig));
  in.transcript_hash = th;
  in.scheme          = 0x0000;
  CHECK(quic_tls_verify_cert_signature(&in) == 0);
  in.scheme = 0xffff;
  CHECK(quic_tls_verify_cert_signature(&in) == 0);
}

/* The golden cert is EC; a bogus ECDSA signature over the transcript fails
 * verification rather than crashing, exercising the ecdsa_p256 branch. */
static void test_certverify_ecdsa_bogus(void) {
  u8 th[32];
  /* ECDSA-Sig-Value SEQUENCE { INTEGER 1, INTEGER 1 }: well-formed DER,
   * wrong signature. */
  const u8            sig[] = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};
  quic_certverify_in  in;
  for (usz i = 0; i < 32; i++) th[i] = (u8)i;
  in.scheme          = QUIC_TLS_SCHEME_ECDSA_P256;
  in.cert            = quic_span_of(quic_x509_golden, sizeof(quic_x509_golden));
  in.sig             = quic_span_of(sig, sizeof(sig));
  in.transcript_hash = th;
  CHECK(quic_tls_verify_cert_signature(&in) == 0);
}

/* A malformed ECDSA signature (not a SEQUENCE) is rejected before verify. */
static void test_certverify_ecdsa_malformed(void) {
  u8                  th[32];
  const u8             sig[] = {0x02, 0x01, 0x01}; /* a bare INTEGER, not SEQUENCE */
  quic_certverify_in  in;
  for (usz i = 0; i < 32; i++) th[i] = (u8)i;
  in.scheme          = QUIC_TLS_SCHEME_ECDSA_P256;
  in.cert            = quic_span_of(quic_x509_golden, sizeof(quic_x509_golden));
  in.sig             = quic_span_of(sig, sizeof(sig));
  in.transcript_hash = th;
  CHECK(quic_tls_verify_cert_signature(&in) == 0);
}

/* RFC 8446 9.1: an OpenSSL-generated RSASSA-PSS signature over the CV
 * content verifies under scheme rsa_pss_rsae_sha256. */
static void test_certverify_pss_ok(void) {
  quic_certverify_in in;
  in.scheme = QUIC_TLS_SCHEME_RSA_PSS_SHA256;
  in.cert =
      quic_span_of(quic_rsacv_cert_der, sizeof(quic_rsacv_cert_der));
  in.sig = quic_span_of(quic_rsacv_pss_sig, sizeof(quic_rsacv_pss_sig));
  in.transcript_hash = quic_rsacv_th;
  CHECK(quic_tls_verify_cert_signature(&in) == 1);
}

/* A PKCS#1 v1.5 signature over the same content must NOT pass as PSS. */
static void test_certverify_pss_rejects_pkcs1(void) {
  quic_certverify_in in;
  in.scheme = QUIC_TLS_SCHEME_RSA_PSS_SHA256;
  in.cert =
      quic_span_of(quic_rsacv_cert_der, sizeof(quic_rsacv_cert_der));
  in.sig = quic_span_of(quic_rsacv_pkcs1_sig, sizeof(quic_rsacv_pkcs1_sig));
  in.transcript_hash = quic_rsacv_th;
  CHECK(quic_tls_verify_cert_signature(&in) == 0);
}

void test_certverify(void) {
  test_certverify_bad_scheme();
  test_certverify_ecdsa_bogus();
  test_certverify_ecdsa_malformed();
  test_certverify_pss_ok();
  test_certverify_pss_rejects_pkcs1();
}
