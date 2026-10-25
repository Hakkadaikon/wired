#include "tls/handshake/core/tls/certverify.h"

#include "rsacv_golden.h"
#include "spkialg_golden.h"
#include "test.h"
#include "x509_golden.h"

/* RFC 8446 4.4.3. An unknown SignatureScheme is rejected outright. */
static void test_certverify_bad_scheme(void) {
  u8            th[32], sig[64];
  certverify_in in;
  for (usz i = 0; i < 32; i++) {
    th[i] = (u8)i;
  }
  for (usz i = 0; i < 64; i++) {
    sig[i] = 0;
  }
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
  for (usz i = 0; i < 32; i++) {
    th[i] = (u8)i;
  }
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
  for (usz i = 0; i < 32; i++) {
    th[i] = (u8)i;
  }
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

/* Verify sig over the transcript hash 00 01 .. 1f under cert and scheme. */
static int cv_spkialg(
    const u8* cert, usz cert_n, u16 scheme, const u8* sig, usz sig_n) {
  u8            th[32];
  certverify_in in;
  for (usz i = 0; i < 32; i++) {
    th[i] = (u8)i;
  }
  in.scheme          = scheme;
  in.cert            = wired_span_of(cert, cert_n);
  in.sig             = wired_span_of(sig, sig_n);
  in.transcript_hash = th;
  return tls_verify_cert_signature(&in);
}

#define CV_P256(c)                                              \
  cv_spkialg(                                                   \
      c, sizeof(c), TLS_SCHEME_ECDSA_P256, spkialg_cv_p256_sig, \
      sizeof(spkialg_cv_p256_sig))

/* RFC 5480 2.1.1/2.1.2: ecdsa_secp256r1_sha256 needs an id-ecPublicKey key
 * whose namedCurve is secp256r1. The same key under id-ecDH / id-ecMQV, with
 * absent, implicitCurve (NULL) or specifiedCurve parameters, or labelled
 * secp384r1 is refused. */
static void test_certverify_spki_ec_alg(void) {
  CHECK(CV_P256(spkialg_p256_ok) == 1);
  CHECK(CV_P256(spkialg_ecdh) == 0);
  CHECK(CV_P256(spkialg_ecmqv) == 0);
  CHECK(CV_P256(spkialg_p256_noparams) == 0);
  CHECK(CV_P256(spkialg_p256_implicit) == 0);
  CHECK(CV_P256(spkialg_p256_specified) == 0);
  CHECK(CV_P256(spkialg_p256_as_p384) == 0);
}

/* RFC 8410 3/6: only an id-Ed25519 key verifies Ed25519; the same 32 bytes
 * labelled id-X25519 are refused. */
static void test_certverify_spki_ed25519_alg(void) {
  const u8* s = spkialg_cv_ed25519_sig;
  usz       n = sizeof(spkialg_cv_ed25519_sig);
  CHECK(
      cv_spkialg(
          spkialg_ed25519, sizeof(spkialg_ed25519), TLS_SCHEME_ED25519, s, n) ==
      1);
  CHECK(
      cv_spkialg(
          spkialg_x25519, sizeof(spkialg_x25519), TLS_SCHEME_ED25519, s, n) ==
      0);
}

/* RFC 8446 4.2.3: rsa_pss_rsae_* needs an rsaEncryption key; the same key
 * labelled id-RSASSA-PSS is refused. */
static void test_certverify_spki_rsa_alg(void) {
  const u8* s = spkialg_cv_rsapss_sig;
  usz       n = sizeof(spkialg_cv_rsapss_sig);
  CHECK(
      cv_spkialg(
          spkialg_rsa, sizeof(spkialg_rsa), TLS_SCHEME_RSA_PSS_SHA256, s, n) ==
      1);
  CHECK(
      cv_spkialg(
          spkialg_rsapss, sizeof(spkialg_rsapss), TLS_SCHEME_RSA_PSS_SHA256, s,
          n) == 0);
}

void test_certverify(void) {
  test_certverify_bad_scheme();
  test_certverify_ecdsa_bogus();
  test_certverify_ecdsa_malformed();
  test_certverify_pss_ok();
  test_certverify_pss_rejects_pkcs1();
  test_certverify_spki_ec_alg();
  test_certverify_spki_ed25519_alg();
  test_certverify_spki_rsa_alg();
}
