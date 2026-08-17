#include "tls/handshake/core/tls/certverify.h"

#include "rsacv_golden.h"
#include "test.h"
#include "x509_golden.h"

/* RFC 8446 4.4.3. An unknown SignatureScheme is rejected outright. */
static void test_certverify_bad_scheme(void) {
  u8            th[32], sig[64];
  certverify_in in;
  for (usz i = 0; i < 32; i++) th[i] = (u8)i;
  for (usz i = 0; i < 64; i++) sig[i] = 0;
  in.cert            = wired_span_of(x509_golden, sizeof(x509_golden));
  in.sig             = wired_span_of(sig, sizeof(sig));
  in.transcript_hash = th;
  in.scheme          = 0x0000;
  CHECK(tls_verify_cert_signature(&in) == 0);
  in.scheme = 0xffff;
  CHECK(tls_verify_cert_signature(&in) == 0);
}

/* The golden cert is EC; a bogus ECDSA signature over the transcript fails
 * verification rather than crashing, exercising the ecdsa_p256 branch. */
static void test_certverify_ecdsa_bogus(void) {
  u8 th[32];
  /* ECDSA-Sig-Value SEQUENCE { INTEGER 1, INTEGER 1 }: well-formed DER,
   * wrong signature. */
  const u8      sig[] = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};
  certverify_in in;
  for (usz i = 0; i < 32; i++) th[i] = (u8)i;
  in.scheme          = TLS_SCHEME_ECDSA_P256;
  in.cert            = wired_span_of(x509_golden, sizeof(x509_golden));
  in.sig             = wired_span_of(sig, sizeof(sig));
  in.transcript_hash = th;
  CHECK(tls_verify_cert_signature(&in) == 0);
}

/* A malformed ECDSA signature (not a SEQUENCE) is rejected before verify. */
static void test_certverify_ecdsa_malformed(void) {
  u8            th[32];
  const u8      sig[] = {0x02, 0x01, 0x01}; /* a bare INTEGER, not SEQUENCE */
  certverify_in in;
  for (usz i = 0; i < 32; i++) th[i] = (u8)i;
  in.scheme          = TLS_SCHEME_ECDSA_P256;
  in.cert            = wired_span_of(x509_golden, sizeof(x509_golden));
  in.sig             = wired_span_of(sig, sizeof(sig));
  in.transcript_hash = th;
  CHECK(tls_verify_cert_signature(&in) == 0);
}

/* RFC 8446 9.1: an OpenSSL-generated RSASSA-PSS signature over the CV
 * content verifies under scheme rsa_pss_rsae_sha256. */
static void test_certverify_pss_ok(void) {
  certverify_in in;
  in.scheme          = TLS_SCHEME_RSA_PSS_SHA256;
  in.cert            = wired_span_of(rsacv_cert_der, sizeof(rsacv_cert_der));
  in.sig             = wired_span_of(rsacv_pss_sig, sizeof(rsacv_pss_sig));
  in.transcript_hash = rsacv_th;
  CHECK(tls_verify_cert_signature(&in) == 1);
}

/* A PKCS#1 v1.5 signature over the same content must NOT pass as PSS. */
static void test_certverify_pss_rejects_pkcs1(void) {
  certverify_in in;
  in.scheme          = TLS_SCHEME_RSA_PSS_SHA256;
  in.cert            = wired_span_of(rsacv_cert_der, sizeof(rsacv_cert_der));
  in.sig             = wired_span_of(rsacv_pkcs1_sig, sizeof(rsacv_pkcs1_sig));
  in.transcript_hash = rsacv_th;
  CHECK(tls_verify_cert_signature(&in) == 0);
}

void test_certverify(void) {
  test_certverify_bad_scheme();
  test_certverify_ecdsa_bogus();
  test_certverify_ecdsa_malformed();
  test_certverify_pss_ok();
  test_certverify_pss_rejects_pkcs1();
}
