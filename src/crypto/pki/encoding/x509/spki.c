#include "crypto/pki/encoding/x509/spki.h"

#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/asn1/derval.h"

/* RFC 5280 4.1.2.1. version is [0] EXPLICIT, optional and default v1. */
#define X509_VERSION_TAG 0xa0
/* RFC 5280 4.1. Elements before subjectPublicKeyInfo, version excluded:
 * serialNumber, signature, issuer, validity, subject. */
#define SPKI_SKIP 5

/* id-ecPublicKey = 1.2.840.10045.2.1 */
static const u8 oid_ec[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
/* rsaEncryption = 1.2.840.113549.1.1.1 */
static const u8 oid_rsa[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                             0x0d, 0x01, 0x01, 0x01};
/* prime256v1 = 1.2.840.10045.3.1.7 */
static const u8 oid_p256[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
/* secp384r1 = 1.3.132.0.34 */
static const u8 oid_p384[] = {0x2b, 0x81, 0x04, 0x00, 0x22};

int quic_x509_is_ec(const u8 *alg_oid, usz alg_len) {
  return quic_der_oid_equal(alg_oid, alg_len, oid_ec, sizeof(oid_ec));
}

int quic_x509_is_rsa(const u8 *alg_oid, usz alg_len) {
  return quic_der_oid_equal(alg_oid, alg_len, oid_rsa, sizeof(oid_rsa));
}

int quic_x509_is_p256(const u8 *oid, usz oid_len) {
  return quic_der_oid_equal(oid, oid_len, oid_p256, sizeof(oid_p256));
}

int quic_x509_is_p384(const u8 *oid, usz oid_len) {
  return quic_der_oid_equal(oid, oid_len, oid_p384, sizeof(oid_p384));
}

/* The tbs SEQUENCE value (after its own header). 0 if not a SEQUENCE. */
static int tbs_value(const u8 *tbs, usz tbs_len, const u8 **v, usz *vlen) {
  u8  tag;
  usz used;
  if (!quic_der_read(tbs, tbs_len, &tag, v, vlen, &used)) return 0;
  return tag == QUIC_DER_SEQUENCE;
}

/* Drop the optional version element, leaving the cursor before serialNumber. */
static int skip_version(quic_derseq *c) {
  u8        tag;
  const u8 *val;
  usz       vlen;
  if (c->off < c->len && c->p[c->off] == X509_VERSION_TAG)
    return quic_derseq_next(c, &tag, &val, &vlen);
  return 1;
}

/* Advance the cursor past n elements. 1 if all were present. */
static int skip_n(quic_derseq *c, usz n) {
  u8        tag;
  const u8 *val;
  usz       vlen;
  for (usz i = 0; i < n; i++)
    if (!quic_derseq_next(c, &tag, &val, &vlen)) return 0;
  return 1;
}

/* Next element of c, requiring its tag. 1 ok, 0 at end or wrong tag. */
static int next_tagged(quic_derseq *c, u8 want, const u8 **val, usz *vlen) {
  u8 tag;
  if (!quic_derseq_next(c, &tag, val, vlen)) return 0;
  return tag == want;
}

/* RFC 5280 4.1.1.2. The algorithm OID inside an AlgorithmIdentifier. */
static int spki_alg_oid(
    const u8 *alg, usz alg_len, const u8 **oid, usz *oid_len) {
  quic_derseq c;
  quic_derseq_init(&c, alg, alg_len);
  return next_tagged(&c, QUIC_DER_OID, oid, oid_len);
}

/* RFC 5280 4.1.2.7. Split a SPKI value into algorithm OID and key bits. */
static int split_spki(
    const u8  *spki,
    usz        spki_len,
    const u8 **oid,
    usz       *oid_len,
    const u8 **key,
    usz       *key_len) {
  quic_derseq c;
  const u8   *alg;
  usz         alg_len;
  quic_derseq_init(&c, spki, spki_len);
  return next_tagged(&c, QUIC_DER_SEQUENCE, &alg, &alg_len) &&
         next_tagged(&c, QUIC_DER_BIT_STRING, key, key_len) &&
         spki_alg_oid(alg, alg_len, oid, oid_len);
}

/* Position c before serialNumber, inside the tbs SEQUENCE value. */
static int tbs_cursor(const u8 *tbs, usz tbs_len, quic_derseq *c) {
  const u8 *v;
  usz       vlen;
  if (!tbs_value(tbs, tbs_len, &v, &vlen)) return 0;
  quic_derseq_init(c, v, vlen);
  return skip_version(c);
}

/* Walk tbs to the subjectPublicKeyInfo element value. */
static int reach_spki(const u8 *tbs, usz tbs_len, const u8 **spki, usz *slen) {
  quic_derseq c;
  return tbs_cursor(tbs, tbs_len, &c) && skip_n(&c, SPKI_SKIP) &&
         next_tagged(&c, QUIC_DER_SEQUENCE, spki, slen);
}

int quic_x509_public_key(
    const u8  *tbs,
    usz        tbs_len,
    const u8 **alg_oid,
    usz       *alg_len,
    const u8 **key,
    usz       *key_len) {
  const u8 *spki;
  usz       slen;
  return reach_spki(tbs, tbs_len, &spki, &slen) &&
         split_spki(spki, slen, alg_oid, alg_len, key, key_len);
}

/* RFC 5480 2.1.1. The namedCurve OID: the AlgorithmIdentifier's second
 * element (its parameters), after the id-ecPublicKey OID. */
static int alg_named_curve(
    const u8 *alg, usz alg_len, const u8 **oid, usz *oid_len) {
  quic_derseq c;
  const u8   *first;
  usz         first_len;
  quic_derseq_init(&c, alg, alg_len);
  if (!next_tagged(&c, QUIC_DER_OID, &first, &first_len)) return 0;
  return next_tagged(&c, QUIC_DER_OID, oid, oid_len);
}

/* The SPKI's algorithm SEQUENCE value. */
static int reach_alg(const u8 *tbs, usz tbs_len, const u8 **alg, usz *alg_len) {
  const u8   *spki;
  usz         slen;
  quic_derseq c;
  if (!reach_spki(tbs, tbs_len, &spki, &slen)) return 0;
  quic_derseq_init(&c, spki, slen);
  return next_tagged(&c, QUIC_DER_SEQUENCE, alg, alg_len);
}

int quic_x509_ec_curve(
    const u8 *tbs, usz tbs_len, const u8 **curve_oid, usz *curve_len) {
  const u8 *alg;
  usz       alg_len;
  if (!reach_alg(tbs, tbs_len, &alg, &alg_len)) return 0;
  return alg_named_curve(alg, alg_len, curve_oid, curve_len);
}
