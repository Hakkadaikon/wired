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
/* RFC 8410 3. id-X25519 = 1.3.101.110. */
static const u8 oid_x25519[] = {0x2b, 0x65, 0x6e};
/* RFC 8410 3. id-X448 = 1.3.101.111. */
static const u8 oid_x448[] = {0x2b, 0x65, 0x6f};
/* RFC 8410 3. id-Ed25519 = 1.3.101.112. */
static const u8 spki_oid_ed25519[] = {0x2b, 0x65, 0x70};
/* RFC 8410 3. id-Ed448 = 1.3.101.113. */
static const u8 oid_ed448[] = {0x2b, 0x65, 0x71};
/* RFC 5480 2.1.2. id-ecDH = 1.3.132.1.12 (iso(1) identified-organization(3)
 * certicom(132) schemes(1) ecdh(12)). */
static const u8 oid_ecdh[] = {0x2b, 0x81, 0x04, 0x01, 0x0c};
/* RFC 5480 2.1.2. id-ecMQV = 1.3.132.1.13 (... schemes(1) ecmqv(13)). */
static const u8 oid_ecmqv[] = {0x2b, 0x81, 0x04, 0x01, 0x0d};

int quic_x509_is_ec(wired_span alg_oid) {
  return quic_der_oid_equal(alg_oid, wired_span_of(oid_ec, sizeof(oid_ec)));
}

int quic_x509_is_rsa(wired_span alg_oid) {
  return quic_der_oid_equal(alg_oid, wired_span_of(oid_rsa, sizeof(oid_rsa)));
}

int quic_x509_is_x25519(wired_span alg_oid) {
  return quic_der_oid_equal(
      alg_oid, wired_span_of(oid_x25519, sizeof(oid_x25519)));
}

int quic_x509_is_x448(wired_span alg_oid) {
  return quic_der_oid_equal(alg_oid, wired_span_of(oid_x448, sizeof(oid_x448)));
}

int quic_x509_is_ed25519(wired_span alg_oid) {
  return quic_der_oid_equal(
      alg_oid, wired_span_of(spki_oid_ed25519, sizeof(spki_oid_ed25519)));
}

int quic_x509_is_ed448(wired_span alg_oid) {
  return quic_der_oid_equal(
      alg_oid, wired_span_of(oid_ed448, sizeof(oid_ed448)));
}

int quic_x509_is_p256(wired_span oid) {
  return quic_der_oid_equal(oid, wired_span_of(oid_p256, sizeof(oid_p256)));
}

int quic_x509_is_p384(wired_span oid) {
  return quic_der_oid_equal(oid, wired_span_of(oid_p384, sizeof(oid_p384)));
}

/* RFC 5480 2.1.2. 1 if the SubjectPublicKeyInfo algorithm OID is the
 * restricted id-ecDH / id-ecMQV key-agreement identifier. */
int quic_x509_is_ecdh(wired_span alg_oid) {
  return quic_der_oid_equal(alg_oid, wired_span_of(oid_ecdh, sizeof(oid_ecdh)));
}

int quic_x509_is_ecmqv(wired_span alg_oid) {
  return quic_der_oid_equal(
      alg_oid, wired_span_of(oid_ecmqv, sizeof(oid_ecmqv)));
}

/* RFC 5280 4.1.1.2. The algorithm OID inside an AlgorithmIdentifier. */
static int spki_alg_oid(wired_span alg, wired_span* oid) {
  quic_derseq c;
  quic_derseq_init(&c, alg);
  return quic_derseq_next_tagged(&c, QUIC_DER_OID, oid);
}

/* RFC 5280 4.1.2.7. Split a SPKI value into algorithm OID and key bits. */
static int split_spki(wired_span spki, wired_span* oid, wired_span* key) {
  quic_derseq c;
  wired_span  alg;
  quic_derseq_init(&c, spki);
  return quic_derseq_next_tagged(&c, QUIC_DER_SEQUENCE, &alg) &&
         quic_derseq_next_tagged(&c, QUIC_DER_BIT_STRING, key) &&
         spki_alg_oid(alg, oid);
}

/* Walk tbs to the subjectPublicKeyInfo element value. */
static int reach_spki(wired_span tbs, wired_span* spki) {
  quic_derseq c;
  return quic_x509_tbs_cursor(tbs, &c) && quic_derseq_skip(&c, SPKI_SKIP) &&
         quic_derseq_next_tagged(&c, QUIC_DER_SEQUENCE, spki);
}

int quic_x509_public_key(wired_span tbs, wired_span* alg_oid, wired_span* key) {
  wired_span spki;
  return reach_spki(tbs, &spki) && split_spki(spki, alg_oid, key);
}

/* RFC 5480 2.1.1. The namedCurve OID: the AlgorithmIdentifier's second
 * element (its parameters), after the id-ecPublicKey OID. */
static int alg_named_curve(wired_span alg, wired_span* oid) {
  quic_derseq c;
  wired_span  first;
  quic_derseq_init(&c, alg);
  if (!quic_derseq_next_tagged(&c, QUIC_DER_OID, &first)) return 0;
  return quic_derseq_next_tagged(&c, QUIC_DER_OID, oid);
}

/* The SPKI's algorithm SEQUENCE value. */
static int reach_alg(wired_span tbs, wired_span* alg) {
  wired_span  spki;
  quic_derseq c;
  if (!reach_spki(tbs, &spki)) return 0;
  quic_derseq_init(&c, spki);
  return quic_derseq_next_tagged(&c, QUIC_DER_SEQUENCE, alg);
}

int quic_x509_ec_curve(wired_span tbs, wired_span* curve_oid) {
  wired_span alg;
  if (!reach_alg(tbs, &alg)) return 0;
  return alg_named_curve(alg, curve_oid);
}

/* 1 if alg_oid is the restricted id-ecDH or id-ecMQV identifier (RFC 5480
 * 2.1.2), the two algorithms for which ECParameters is mandatory. */
static int is_ec_restricted(wired_span alg_oid) {
  return quic_x509_is_ecdh(alg_oid) || quic_x509_is_ecmqv(alg_oid);
}

/* RFC 5480 2.1.2: "the parameters are always ECParameters and they MUST
 * always be present" for id-ecDH / id-ecMQV. 1 if tbs's SubjectPublicKeyInfo
 * algorithm is not id-ecDH/id-ecMQV (requirement doesn't apply), or it is
 * and a well-formed ECParameters namedCurve is present. 0 if the algorithm
 * is id-ecDH/id-ecMQV but ECParameters is absent/malformed, or tbs itself is
 * malformed. */
int quic_x509_ec_restricted_params_ok(wired_span tbs) {
  wired_span alg_oid, key, curve_oid;
  if (!quic_x509_public_key(tbs, &alg_oid, &key)) return 0;
  if (!is_ec_restricted(alg_oid)) return 1;
  return quic_x509_ec_curve(tbs, &curve_oid);
}
