#include "crypto/pki/encoding/x509/x509.h"

#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derval.h"

/* RFC 5280 4.1.2.1. version is [0] EXPLICIT, optional and default v1. */
#define X509_VERSION_TAG 0xa0
/* RFC 5280 4.1.2.9. extensions is [3] EXPLICIT. */
#define X509_EXTENSIONS_TAG 0xa3
/* RFC 5280 4.1. tbs elements before extensions (version excluded):
 * serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo. */
#define X509_EXT_SKIP 6

/* RFC 5280 4.1.1.2. signatureAlgorithm ::= SEQUENCE { algorithm OID, ... }.
 * Extract the OID value from the AlgorithmIdentifier blob. */
static int alg_oid(quic_span alg, quic_span *oid) {
  quic_derseq c;
  quic_derseq_init(&c, alg);
  return quic_derseq_next_tagged(&c, QUIC_DER_OID, oid);
}

/* Read one element of the outer SEQUENCE, keeping its header-included span
 * (the signed bytes for tbsCertificate). */
static int outer_next(quic_derseq *c, quic_span *whole, quic_der_tlv *e) {
  const u8 *start = c->p + c->off;
  quic_span val;
  if (!quic_derseq_next(c, &e->tag, &val)) return 0;
  e->val = val;
  *whole = quic_span_of(start, (usz)(c->p + c->off - start));
  return 1;
}

/* RFC 5280 4.1. tbsCertificate: keep the header-included span (signed bytes).
 */
static int take_tbs(quic_derseq *c, quic_x509 *out) {
  quic_der_tlv e;
  if (!outer_next(c, &out->tbs, &e)) return 0;
  return e.tag == QUIC_DER_SEQUENCE;
}

/* RFC 5280 4.1.1.2. signatureAlgorithm: pull out its OID. */
static int take_alg(quic_derseq *c, quic_x509 *out) {
  quic_span    whole;
  quic_der_tlv e;
  if (!outer_next(c, &whole, &e)) return 0;
  if (e.tag != QUIC_DER_SEQUENCE) return 0;
  return alg_oid(e.val, &out->sig_alg_oid);
}

/* RFC 5280 4.1.1.3. signatureValue: a BIT STRING. */
static int take_sig(quic_derseq *c, quic_x509 *out) {
  quic_span    whole;
  quic_der_tlv e;
  if (!outer_next(c, &whole, &e)) return 0;
  out->sig = e.val;
  return e.tag == QUIC_DER_BIT_STRING;
}

/* RFC 5280 4.1. The three fields in order: tbs, algorithm, signature. */
static int take_fields(quic_span seq, quic_x509 *out) {
  quic_derseq c;
  quic_derseq_init(&c, seq);
  return take_tbs(&c, out) && take_alg(&c, out) && take_sig(&c, out);
}

int quic_x509_parse(quic_span cert, quic_x509 *out) {
  quic_span seq;
  return quic_der_seq(cert, &seq) && take_fields(seq, out);
}

/* Drop the optional version element, leaving the cursor before serialNumber. */
static int skip_version(quic_derseq *c) {
  quic_span val;
  if (c->off < c->len && c->p[c->off] == X509_VERSION_TAG)
    return quic_derseq_next_tagged(c, X509_VERSION_TAG, &val);
  return 1;
}

int quic_x509_tbs_cursor(quic_span tbs, quic_derseq *c) {
  quic_span v;
  if (!quic_der_seq(tbs, &v)) return 0;
  quic_derseq_init(c, v);
  return skip_version(c);
}

/* Position the cursor before the extensions [3] element. */
static int at_extensions(quic_span tbs, quic_derseq *c) {
  return quic_x509_tbs_cursor(tbs, c) && quic_derseq_skip(c, X509_EXT_SKIP);
}

/* RFC 5280 4.1.2.9. Reach the extensions SEQUENCE value inside [3]. */
static int reach_extensions(quic_span tbs, quic_span *ext) {
  quic_derseq c;
  quic_span   wrapped;
  if (!at_extensions(tbs, &c)) return 0;
  if (!quic_derseq_next_tagged(&c, X509_EXTENSIONS_TAG, &wrapped)) return 0;
  return quic_der_seq(wrapped, ext);
}

/* RFC 5280 4.1.2.9. extnID of one Extension equals the wanted OID. */
static int ext_id_is(quic_span e, quic_span oid) {
  quic_derseq f;
  quic_span   id;
  quic_derseq_init(&f, e);
  if (!quic_derseq_next_tagged(&f, QUIC_DER_OID, &id)) return 0;
  return quic_der_oid_equal(id, oid);
}

/* RFC 5280 4.1.2.9. The extnValue OCTET STRING of one Extension (its last
 * element, after extnID and the optional critical BOOLEAN). */
static int ext_value(quic_span e, quic_span *val) {
  quic_derseq f;
  u8          tag;
  quic_span   o;
  quic_derseq_init(&f, e);
  while (quic_derseq_next(&f, &tag, &o))
    if (tag == QUIC_DER_OCTET_STRING) {
      *val = o;
      return 1;
    }
  return 0;
}

/* Scan the extensions SEQUENCE for the wanted extnID. */
static int find_in_extensions(quic_span ext, quic_span oid, quic_span *val) {
  quic_derseq exts;
  u8          tag;
  quic_span   e;
  quic_derseq_init(&exts, ext);
  while (quic_derseq_next(&exts, &tag, &e))
    if (ext_id_is(e, oid)) return ext_value(e, val);
  return 0;
}

int quic_x509_find_ext(quic_span tbs, quic_span oid, quic_span *val) {
  quic_span ext;
  if (!reach_extensions(tbs, &ext)) return 0;
  return find_in_extensions(ext, oid, val);
}
