#include "crypto/pki/encoding/x509/spki.h"

#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/asn1/derval.h"
#include "crypto/pki/encoding/x509/x509.h"

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

int quic_x509_is_ec(quic_span alg_oid) {
  return quic_der_oid_equal(alg_oid, quic_span_of(oid_ec, sizeof(oid_ec)));
}

int quic_x509_is_rsa(quic_span alg_oid) {
  return quic_der_oid_equal(alg_oid, quic_span_of(oid_rsa, sizeof(oid_rsa)));
}

int quic_x509_is_p256(quic_span oid) {
  return quic_der_oid_equal(oid, quic_span_of(oid_p256, sizeof(oid_p256)));
}

int quic_x509_is_p384(quic_span oid) {
  return quic_der_oid_equal(oid, quic_span_of(oid_p384, sizeof(oid_p384)));
}

/* RFC 5280 4.1.1.2. The algorithm OID inside an AlgorithmIdentifier. */
static int spki_alg_oid(quic_span alg, quic_span* oid) {
  quic_derseq c;
  quic_derseq_init(&c, alg);
  return quic_derseq_next_tagged(&c, QUIC_DER_OID, oid);
}

/* RFC 5280 4.1.2.7. Split a SPKI value into algorithm OID and key bits. */
static int split_spki(quic_span spki, quic_span* oid, quic_span* key) {
  quic_derseq c;
  quic_span   alg;
  quic_derseq_init(&c, spki);
  return quic_derseq_next_tagged(&c, QUIC_DER_SEQUENCE, &alg) &&
         quic_derseq_next_tagged(&c, QUIC_DER_BIT_STRING, key) &&
         spki_alg_oid(alg, oid);
}

/* Walk tbs to the subjectPublicKeyInfo element value. */
static int reach_spki(quic_span tbs, quic_span* spki) {
  quic_derseq c;
  return quic_x509_tbs_cursor(tbs, &c) && quic_derseq_skip(&c, SPKI_SKIP) &&
         quic_derseq_next_tagged(&c, QUIC_DER_SEQUENCE, spki);
}

int quic_x509_public_key(quic_span tbs, quic_span* alg_oid, quic_span* key) {
  quic_span spki;
  return reach_spki(tbs, &spki) && split_spki(spki, alg_oid, key);
}

/* RFC 5480 2.1.1. The namedCurve OID: the AlgorithmIdentifier's second
 * element (its parameters), after the id-ecPublicKey OID. */
static int alg_named_curve(quic_span alg, quic_span* oid) {
  quic_derseq c;
  quic_span   first;
  quic_derseq_init(&c, alg);
  if (!quic_derseq_next_tagged(&c, QUIC_DER_OID, &first)) return 0;
  return quic_derseq_next_tagged(&c, QUIC_DER_OID, oid);
}

/* The SPKI's algorithm SEQUENCE value. */
static int reach_alg(quic_span tbs, quic_span* alg) {
  quic_span   spki;
  quic_derseq c;
  if (!reach_spki(tbs, &spki)) return 0;
  quic_derseq_init(&c, spki);
  return quic_derseq_next_tagged(&c, QUIC_DER_SEQUENCE, alg);
}

int quic_x509_ec_curve(quic_span tbs, quic_span* curve_oid) {
  quic_span alg;
  if (!reach_alg(tbs, &alg)) return 0;
  return alg_named_curve(alg, curve_oid);
}
