#include "crypto/pki/encoding/x509/sigalgoid.h"

#include "test.h"

/* Absent AlgorithmIdentifier parameters. */
static const wired_span sao_none = {0};

static int sao_is(const u8* oid, usz n, u8 key, u8 hash) {
  x509_sigalg a;
  return x509_sigalg_lookup(wired_span_of(oid, n), sao_none, &a) == 1 &&
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
  CHECK(sao_is(ec224, 8, X509_SIG_ECDSA, X509_HASH_SHA224));
  CHECK(sao_is(ec256, 8, X509_SIG_ECDSA, X509_HASH_SHA256));
  CHECK(sao_is(ec384, 8, X509_SIG_ECDSA, X509_HASH_SHA384));
  CHECK(sao_is(ec512, 8, X509_SIG_ECDSA, X509_HASH_SHA512));
  CHECK(sao_is(r256, 9, X509_SIG_RSA_PKCS1, X509_HASH_SHA256));
  CHECK(sao_is(r384, 9, X509_SIG_RSA_PKCS1, X509_HASH_SHA384));
  CHECK(sao_is(r512, 9, X509_SIG_RSA_PKCS1, X509_HASH_SHA512));
  /* RFC 8410 3: id-Ed25519 (1.3.101.112) signs the message itself. */
  static const u8 ed[] = {0x2b, 0x65, 0x70};
  CHECK(sao_is(ed, 3, X509_SIG_ED25519, X509_HASH_NONE));
}

/* Anything else fails closed: sha224WithRSA, sha1WithRSA, md5WithRSA,
 * RSASSA-PSS without parameters, and truncated OIDs. */
static void test_sigalgoid_unknown(void) {
  static const u8 r224[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                            0x0d, 0x01, 0x01, 0x0e};
  static const u8 sha1[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                            0x0d, 0x01, 0x01, 0x05};
  static const u8 md5[]  = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                            0x0d, 0x01, 0x01, 0x04};
  static const u8 pss[]  = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                            0x0d, 0x01, 0x01, 0x0a};
  x509_sigalg     a;
  CHECK(
      x509_sigalg_lookup(wired_span_of(r224, sizeof(r224)), sao_none, &a) == 0);
  CHECK(
      x509_sigalg_lookup(wired_span_of(sha1, sizeof(sha1)), sao_none, &a) == 0);
  CHECK(x509_sigalg_lookup(wired_span_of(md5, sizeof(md5)), sao_none, &a) == 0);
  CHECK(x509_sigalg_lookup(wired_span_of(pss, sizeof(pss)), sao_none, &a) == 0);
  CHECK(
      x509_sigalg_lookup(wired_span_of(r224, 8), sao_none, &a) ==
      0); /* short */
}

/* RFC 4055 3.1 id-RSASSA-PSS (1.2.840.113549.1.1.10). */
static const u8 sao_pss_oid[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                 0x0d, 0x01, 0x01, 0x0a};

/* RSASSA-PSS-params as OpenSSL 3.0.13 writes them for SHA-256: hash
 * [0] {sha256, NULL}, mask [1] {mgf1, {sha256, NULL}}, salt [2] 32; 54
 * octets. Octets 54..58 are an explicit trailerField [3] 1 (the outer length
 * at [1] grows 0x34 -> 0x39), which DER forbids. Offsets: hash OID last arc
 * [16], mgf1 OID last arc [33], MGF1 hash OID last arc [46], saltLength value
 * [53]. */
static const u8 sao_pss_base[59] = {
    0x30, 0x34, 0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06,
    0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d,
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0xa2, 0x03, 0x02, 0x01, 0x20, 0xa3, 0x03, 0x02, 0x01, 0x01,
};

/* The same SHA-256 params with both hash AlgorithmIdentifiers' parameters
 * absent instead of NULL (RFC 4055 2.1: both MUST be accepted). */
static const u8 sao_pss_nonull[] = {
    0x30, 0x30, 0xa0, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0xa1, 0x1a, 0x30,
    0x18, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
    0x01, 0x08, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0xa2, 0x03, 0x02, 0x01, 0x20,
};

/* Up to three (offset, value) edits of sao_pss_base, then a lookup of the
 * first len octets. Returns the resolved hash kind, 0 if rejected. */
typedef struct {
  usz at;
  u8  v;
} sao_edit;

static u8 sao_pss(usz len, const sao_edit* e, usz ne) {
  u8          b[sizeof(sao_pss_base)];
  x509_sigalg a = {0};
  for (usz i = 0; i < sizeof(b); i++) {
    b[i] = sao_pss_base[i];
  }
  for (usz i = 0; i < ne; i++) {
    b[e[i].at] = e[i].v;
  }
  if (!x509_sigalg_lookup(
          wired_span_of(sao_pss_oid, sizeof(sao_pss_oid)),
          wired_span_of(b, len), &a)) {
    return 0;
  }
  CHECK(a.key_kind == X509_SIG_RSA_PSS);
  return a.hash_kind;
}

/* RFC 4055 3.1 / RFC 8446 4.2.3: SHA-256/384/512 with MGF1 over the same
 * hash and saltLength = hLen resolve, trailerField absent. */
static void test_sigalgoid_pss_listed(void) {
  static const sao_edit h384[] = {{16, 0x02}, {46, 0x02}, {53, 0x30}};
  static const sao_edit h512[] = {{16, 0x03}, {46, 0x03}, {53, 0x40}};
  x509_sigalg           a      = {0};
  CHECK(sao_pss(54, 0, 0) == X509_HASH_SHA256);
  CHECK(sao_pss(54, h384, 3) == X509_HASH_SHA384);
  CHECK(sao_pss(54, h512, 3) == X509_HASH_SHA512);
  CHECK(
      x509_sigalg_lookup(
          wired_span_of(sao_pss_oid, sizeof(sao_pss_oid)),
          wired_span_of(sao_pss_nonull, sizeof(sao_pss_nonull)), &a) == 1);
  CHECK(a.key_kind == X509_SIG_RSA_PSS && a.hash_kind == X509_HASH_SHA256);
}

/* Fail closed: MGF1 hash != message hash, a non-MGF1 mask, salt != hLen,
 * any explicit trailerField (1 is the DEFAULT, which DER omits; others are
 * not trailerFieldBC), SHA-224, and malformed DER. */
static void test_sigalgoid_pss_policy(void) {
  static const sao_edit mgfh[]   = {{46, 0x02}};
  static const sao_edit mgf[]    = {{33, 0x09}};
  static const sao_edit salt[]   = {{53, 0x14}};
  static const sao_edit trl1[]   = {{1, 0x39}};
  static const sao_edit trl2[]   = {{1, 0x39}, {58, 0x02}};
  static const sao_edit h224[]   = {{16, 0x04}, {46, 0x04}, {53, 0x1c}};
  static const sao_edit len[]    = {{1, 0x35}};
  static const sao_edit notag[]  = {{2, 0xa1}};
  static const sao_edit nosalt[] = {{1, 0x2f}};
  CHECK(sao_pss(54, mgfh, 1) == 0);
  CHECK(sao_pss(54, mgf, 1) == 0);
  CHECK(sao_pss(54, salt, 1) == 0);
  CHECK(sao_pss(59, trl1, 1) == 0); /* X.690 11.5: DEFAULT 1 encoded */
  CHECK(sao_pss(59, trl2, 2) == 0);
  CHECK(sao_pss(54, h224, 3) == 0);
  CHECK(sao_pss(54, len, 1) == 0);    /* SEQUENCE overruns the octets */
  CHECK(sao_pss(55, 0, 0) == 0);      /* an octet after the SEQUENCE */
  CHECK(sao_pss(54, notag, 1) == 0);  /* hashAlgorithm [0] absent */
  CHECK(sao_pss(49, nosalt, 1) == 0); /* saltLength absent: default 20 */
}

/* RFC 4055 3.1: the all-default parameters mean SHA-1, MGF1-SHA-1 and salt
 * 20 -- rejected, as are absent and NULL parameters. */
static void test_sigalgoid_pss_defaults(void) {
  static const u8 empty[] = {0x30, 0x00}, null[] = {0x05, 0x00};
  x509_sigalg     a;
  wired_span      oid = wired_span_of(sao_pss_oid, sizeof(sao_pss_oid));
  CHECK(x509_sigalg_lookup(oid, wired_span_of(empty, 2), &a) == 0);
  CHECK(x509_sigalg_lookup(oid, wired_span_of(null, 2), &a) == 0);
  CHECK(x509_sigalg_lookup(oid, sao_none, &a) == 0);
}

void test_sigalgoid(void) {
  test_sigalgoid_listed();
  test_sigalgoid_unknown();
  test_sigalgoid_pss_listed();
  test_sigalgoid_pss_policy();
  test_sigalgoid_pss_defaults();
}
