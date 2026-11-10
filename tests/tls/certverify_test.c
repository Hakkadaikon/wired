#include "tls/handshake/core/tls/certverify.h"

#include "mtls_golden.h"
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

/* Verify an OpenSSL signature over the transcript hash 00 01 .. n-1 by the
 * client leaf, under the client (1) or server (0) context string. */
static int cv_client_vec(const u8* sig, usz sig_n, usz n, int client) {
  u8            th[48];
  certverify_in in;
  for (usz i = 0; i < n; i++) {
    th[i] = (u8)i;
  }
  in.scheme          = TLS_SCHEME_ECDSA_P256;
  in.cert            = wired_span_of(mtlsg_leaf_ok, sizeof(mtlsg_leaf_ok));
  in.sig             = wired_span_of(sig, sig_n);
  in.transcript_hash = th;
  return tls_verify_cert_signature_ctx(&in, client, n);
}

/* RFC 8446 4.4.3: a client signature is over "TLS 1.3, client
 * CertificateVerify" and the transcript hash at the suite's length (32 for
 * SHA-256, 48 for SHA-384); the same bytes under the server context, or at
 * another length, do not verify. */
static void test_certverify_client_context(void) {
  const u8* s32 = mtlsg_client_cv_sig32;
  const u8* s48 = mtlsg_client_cv_sig48;
  CHECK(cv_client_vec(s32, sizeof(mtlsg_client_cv_sig32), 32, 1) == 1);
  CHECK(cv_client_vec(s48, sizeof(mtlsg_client_cv_sig48), 48, 1) == 1);
  CHECK(cv_client_vec(s32, sizeof(mtlsg_client_cv_sig32), 32, 0) == 0);
  CHECK(cv_client_vec(s48, sizeof(mtlsg_client_cv_sig48), 32, 1) == 0);
}

/* A copy of der with der[off] replaced by v, verified as cv_spkialg does. */
static int cv_patched(
    const u8* der, usz n, usz off, u8 v, u16 scheme, wired_span sig) {
  u8 buf[512];
  for (usz i = 0; i < n; i++) {
    buf[i] = der[i];
  }
  buf[off] = v;
  return cv_spkialg(buf, n, scheme, sig.p, sig.n);
}

/* RFC 5480 2.2 / RFC 8017 A.1.1 / RFC 8410 4: the subjectPublicKey must
 * hold an uncompressed P-256 point (0x04 lead), an RSAPublicKey SEQUENCE,
 * or a whole-byte (0 unused bits) Ed25519 key; a SubjectPublicKeyInfo
 * whose BIT STRING is not one is unusable. RFC 8446 4.4.3: no
 * transcript hash is longer than SHA-384's 48 bytes. */
static void test_certverify_bad_key_encodings(void) {
  wired_span p256 =
      wired_span_of(spkialg_cv_p256_sig, sizeof(spkialg_cv_p256_sig));
  wired_span rsa =
      wired_span_of(spkialg_cv_rsapss_sig, sizeof(spkialg_cv_rsapss_sig));
  wired_span ed =
      wired_span_of(spkialg_cv_ed25519_sig, sizeof(spkialg_cv_ed25519_sig));
  u8            th[64] = {0};
  certverify_in in     = {
      TLS_SCHEME_ECDSA_P256,
      wired_span_of(mtlsg_leaf_ok, sizeof(mtlsg_leaf_ok)), p256, th};
  /* spkialg_p256_ok: BIT STRING 03 42 00 04 at 121 */
  CHECK(
      cv_patched(
          spkialg_p256_ok, sizeof(spkialg_p256_ok), 124, 0x02,
          TLS_SCHEME_ECDSA_P256, p256) == 0);
  CHECK(
      cv_patched(
          spkialg_p256_ok, sizeof(spkialg_p256_ok), 121, 0x04,
          TLS_SCHEME_ECDSA_P256, p256) == 0); /* not a BIT STRING */
  /* spkialg_rsa: BIT STRING value 00 30 82 01 0a at 116 */
  CHECK(
      cv_patched(
          spkialg_rsa, sizeof(spkialg_rsa), 117, 0x31,
          TLS_SCHEME_RSA_PSS_SHA256, rsa) == 0);
  /* spkialg_ed25519: BIT STRING 03 21 00 at 108 */
  CHECK(
      cv_patched(
          spkialg_ed25519, sizeof(spkialg_ed25519), 110, 0x01,
          TLS_SCHEME_ED25519, ed) == 0);
  CHECK(tls_verify_cert_signature_ctx(&in, 1, 49) == 0);
}

void test_certverify(void) {
  test_certverify_client_context();
  test_certverify_bad_scheme();
  test_certverify_bad_key_encodings();
  test_certverify_ecdsa_bogus();
  test_certverify_ecdsa_malformed();
  test_certverify_pss_ok();
  test_certverify_pss_rejects_pkcs1();
  test_certverify_spki_ec_alg();
  test_certverify_spki_ed25519_alg();
  test_certverify_spki_rsa_alg();
}
