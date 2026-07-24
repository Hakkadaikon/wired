#include "crypto/pki/encoding/x509/sigalgoid.h"

#include "test.h"

static int sao_is(const u8* oid, usz n, u8 key, u8 hash) {
  quic_x509_sigalg a;
  return quic_x509_sigalg_lookup(quic_span_of(oid, n), &a) == 1 &&
         a.key_kind == key && a.hash_kind == hash;
}

/* Every allowlisted OID resolves to its key kind and digest. */
static void test_sigalgoid_listed(void) {
  static const u8 ec224[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x01};
  static const u8 ec256[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02};
  static const u8 ec384[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03};
  static const u8 ec512[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04};
  static const u8 r256[]  = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                             0x0d, 0x01, 0x01, 0x0b};
  static const u8 r384[]  = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                             0x0d, 0x01, 0x01, 0x0c};
  static const u8 r512[]  = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                             0x0d, 0x01, 0x01, 0x0d};
  CHECK(sao_is(ec224, 8, QUIC_X509_SIG_ECDSA, QUIC_X509_HASH_SHA224));
  CHECK(sao_is(ec256, 8, QUIC_X509_SIG_ECDSA, QUIC_X509_HASH_SHA256));
  CHECK(sao_is(ec384, 8, QUIC_X509_SIG_ECDSA, QUIC_X509_HASH_SHA384));
  CHECK(sao_is(ec512, 8, QUIC_X509_SIG_ECDSA, QUIC_X509_HASH_SHA512));
  CHECK(sao_is(r256, 9, QUIC_X509_SIG_RSA_PKCS1, QUIC_X509_HASH_SHA256));
  CHECK(sao_is(r384, 9, QUIC_X509_SIG_RSA_PKCS1, QUIC_X509_HASH_SHA384));
  CHECK(sao_is(r512, 9, QUIC_X509_SIG_RSA_PKCS1, QUIC_X509_HASH_SHA512));
}

/* Anything else fails closed: sha224WithRSA, sha1WithRSA, md5WithRSA,
 * RSASSA-PSS, and truncated OIDs. */
static void test_sigalgoid_unknown(void) {
  static const u8  r224[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                             0x0d, 0x01, 0x01, 0x0e};
  static const u8  sha1[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                             0x0d, 0x01, 0x01, 0x05};
  static const u8  md5[]  = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                             0x0d, 0x01, 0x01, 0x04};
  static const u8  pss[]  = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                             0x0d, 0x01, 0x01, 0x0a};
  quic_x509_sigalg a;
  CHECK(quic_x509_sigalg_lookup(quic_span_of(r224, sizeof(r224)), &a) == 0);
  CHECK(quic_x509_sigalg_lookup(quic_span_of(sha1, sizeof(sha1)), &a) == 0);
  CHECK(quic_x509_sigalg_lookup(quic_span_of(md5, sizeof(md5)), &a) == 0);
  CHECK(quic_x509_sigalg_lookup(quic_span_of(pss, sizeof(pss)), &a) == 0);
  CHECK(quic_x509_sigalg_lookup(quic_span_of(r224, 8), &a) == 0); /* short */
}

void test_sigalgoid(void) {
  test_sigalgoid_listed();
  test_sigalgoid_unknown();
}
