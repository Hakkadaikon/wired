#include "crypto/pki/encoding/x509/x509.h"

#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derval.h"

/* RFC 5280 4.1.2.1. version is [0] EXPLICIT, optional and default v1. */
#define X509_VERSION_TAG 0xa0
/* RFC 5280 4.1. issuerUniqueID is [1] IMPLICIT, subjectUniqueID is [2]
 * IMPLICIT; both optional (v2/v3 only). */
#define X509_ISSUER_UID_TAG 0xa1
#define X509_SUBJECT_UID_TAG 0xa2
/* RFC 5280 4.1.2.9. extensions is [3] EXPLICIT. */
#define X509_EXTENSIONS_TAG 0xa3
/* RFC 5280 4.1. tbs elements before extensions (version excluded):
 * serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo. */
#define X509_EXT_SKIP 6

/* RFC 5280 4.1.1.2. signatureAlgorithm ::= SEQUENCE { algorithm OID, ... }.
 * Extract the OID value from the AlgorithmIdentifier blob. */
static int alg_oid(quic_span alg, quic_span* oid) {
  quic_derseq c;
  quic_derseq_init(&c, alg);
  return quic_derseq_next_tagged(&c, QUIC_DER_OID, oid);
}

/* Read one element of the outer SEQUENCE, keeping its header-included span
 * (the signed bytes for tbsCertificate). */
static int outer_next(quic_derseq* c, quic_span* whole, quic_der_tlv* e) {
  const u8* start = c->p + c->off;
  quic_span val;
  if (!quic_derseq_next(c, &e->tag, &val)) return 0;
  e->val = val;
  *whole = quic_span_of(start, (usz)(c->p + c->off - start));
  return 1;
}

/* RFC 5280 4.1. tbsCertificate: keep the header-included span (signed bytes).
 */
static int take_tbs(quic_derseq* c, quic_x509* out) {
  quic_der_tlv e;
  if (!outer_next(c, &out->tbs, &e)) return 0;
  return e.tag == QUIC_DER_SEQUENCE;
}

/* RFC 5280 4.1.1.2. signatureAlgorithm: pull out its OID. */
static int take_alg(quic_derseq* c, quic_x509* out) {
  quic_span    whole;
  quic_der_tlv e;
  if (!outer_next(c, &whole, &e)) return 0;
  if (e.tag != QUIC_DER_SEQUENCE) return 0;
  return alg_oid(e.val, &out->sig_alg_oid);
}

/* RFC 5280 4.1.1.3. signatureValue: a BIT STRING. */
static int take_sig(quic_derseq* c, quic_x509* out) {
  quic_span    whole;
  quic_der_tlv e;
  if (!outer_next(c, &whole, &e)) return 0;
  out->sig = e.val;
  return e.tag == QUIC_DER_BIT_STRING;
}

/* RFC 5280 4.1. The three fields in order: tbs, algorithm, signature. */
static int take_fields(quic_span seq, quic_x509* out) {
  quic_derseq c;
  quic_derseq_init(&c, seq);
  return take_tbs(&c, out) && take_alg(&c, out) && take_sig(&c, out);
}

int quic_x509_parse(quic_span cert, quic_x509* out) {
  quic_span seq;
  return quic_der_seq(cert, &seq) && take_fields(seq, out);
}

/* Drop one optional IMPLICIT/EXPLICIT-tagged context element if the cursor
 * currently sits on it, else leave the cursor untouched. Used for version
 * [0], issuerUniqueID [1], and subjectUniqueID [2], all of which are
 * DER-optional and so must be probed by tag rather than counted as fixed
 * positions. */
static int skip_tagged_if_present(quic_derseq* c, u8 want_tag) {
  quic_span val;
  if (c->off < c->len && c->p[c->off] == want_tag)
    return quic_derseq_next_tagged(c, want_tag, &val);
  return 1;
}

int quic_x509_tbs_cursor(quic_span tbs, quic_derseq* c) {
  quic_span v;
  if (!quic_der_seq(tbs, &v)) return 0;
  quic_derseq_init(c, v);
  return skip_tagged_if_present(c, X509_VERSION_TAG);
}

/* RFC 5280 4.1. Drop issuerUniqueID [1] and subjectUniqueID [2] if either is
 * present; a v1 tbs (neither present) leaves the cursor untouched. */
static int skip_unique_ids(quic_derseq* c) {
  if (!skip_tagged_if_present(c, X509_ISSUER_UID_TAG)) return 0;
  return skip_tagged_if_present(c, X509_SUBJECT_UID_TAG);
}

/* Position the cursor before the extensions [3] element. */
static int at_extensions(quic_span tbs, quic_derseq* c) {
  if (!quic_x509_tbs_cursor(tbs, c)) return 0;
  if (!quic_derseq_skip(c, X509_EXT_SKIP)) return 0;
  return skip_unique_ids(c);
}

/* RFC 5280 4.1.2.9. Reach the extensions SEQUENCE value inside [3]. */
static int reach_extensions(quic_span tbs, quic_span* ext) {
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

/* X.690 8.2. BOOLEAN universal tag. */
#define X509_TAG_BOOLEAN 0x01

/* X.690 11.1. A DER BOOLEAN encoding TRUE (single non-zero octet). */
static int is_true_boolean(u8 tag, quic_span v) {
  return tag == X509_TAG_BOOLEAN && v.n == 1 && v.p[0] != 0x00;
}

/* RFC 5280 4.1.2.9. critical of one Extension: the element right after
 * extnID when it is a BOOLEAN, else the X.690 DEFAULT FALSE. */
static int ext_critical(quic_span e) {
  quic_derseq f;
  u8          tag;
  quic_span   id, v;
  quic_derseq_init(&f, e);
  if (!quic_derseq_next_tagged(&f, QUIC_DER_OID, &id)) return 0;
  if (!quic_derseq_next(&f, &tag, &v)) return 0;
  return is_true_boolean(tag, v);
}

/* RFC 5280 4.1.2.9. The extnValue OCTET STRING of one Extension (its last
 * element, after extnID and the optional critical BOOLEAN). */
static int ext_value(quic_span e, quic_span* val) {
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
static int find_in_extensions(quic_span ext, quic_span oid, quic_span* val) {
  quic_derseq exts;
  u8          tag;
  quic_span   e;
  quic_derseq_init(&exts, ext);
  while (quic_derseq_next(&exts, &tag, &e))
    if (ext_id_is(e, oid)) return ext_value(e, val);
  return 0;
}

int quic_x509_find_ext(quic_span tbs, quic_span oid, quic_span* val) {
  quic_span ext;
  if (!reach_extensions(tbs, &ext)) return 0;
  return find_in_extensions(ext, oid, val);
}

/* RFC 5280 4.2. extnIDs this SDK understands the semantics of. Any other
 * critical extension must reject the certificate (4.2 "MUST reject"). */
static const u8 oid_bc_[] = {0x55, 0x1d, 0x13}; /* 2.5.29.19 basicConstraints */
static const u8 oid_san_[] = {0x55, 0x1d, 0x11}; /* 2.5.29.17 subjectAltName */
static const u8 oid_ku_[]  = {0x55, 0x1d, 0x0f}; /* 2.5.29.15 keyUsage */
static const u8 oid_eku_[] = {0x55, 0x1d, 0x25}; /* 2.5.29.37 extKeyUsage */
static const u8 oid_nc_[]  = {0x55, 0x1d, 0x1e}; /* 2.5.29.30 nameConstraints */
static const u8 oid_pc_[]  = {0x55, 0x1d, 0x24}; /* 2.5.29.36 policyConstr. */
static const u8 oid_iap_[] = {0x55, 0x1d, 0x36}; /* 2.5.29.54 inhibitAnyPol. */
static const u8 oid_cp_[]  = {0x55, 0x1d, 0x20}; /* 2.5.29.32 certPolicies */

static const quic_span known_ext_oids[] = {
    {oid_bc_, sizeof(oid_bc_)},   {oid_san_, sizeof(oid_san_)},
    {oid_ku_, sizeof(oid_ku_)},   {oid_eku_, sizeof(oid_eku_)},
    {oid_nc_, sizeof(oid_nc_)},   {oid_pc_, sizeof(oid_pc_)},
    {oid_iap_, sizeof(oid_iap_)}, {oid_cp_, sizeof(oid_cp_)},
};
#define KNOWN_EXT_OID_COUNT (sizeof(known_ext_oids) / sizeof(known_ext_oids[0]))

/* extnID of one Extension. */
static int ext_id(quic_span e, quic_span* id) {
  quic_derseq f;
  quic_derseq_init(&f, e);
  return quic_derseq_next_tagged(&f, QUIC_DER_OID, id);
}

/* 1 if id matches one of the known extension OIDs. */
static int id_is_known(quic_span id) {
  for (usz i = 0; i < KNOWN_EXT_OID_COUNT; i++)
    if (quic_der_oid_equal(id, known_ext_oids[i])) return 1;
  return 0;
}

/* RFC 5280 4.2. One Extension rejects iff it is critical and unrecognized. */
static int ext_is_unknown_critical(quic_span e) {
  quic_span id;
  if (!ext_id(e, &id)) return 1;
  if (!ext_critical(e)) return 0;
  return !id_is_known(id);
}

/* Scan the extensions SEQUENCE for any unknown-critical Extension. */
static int scan_unknown_critical(quic_span ext) {
  quic_derseq exts;
  u8          tag;
  quic_span   e;
  quic_derseq_init(&exts, ext);
  while (quic_derseq_next(&exts, &tag, &e))
    if (ext_is_unknown_critical(e)) return 1;
  return 0;
}

int quic_x509_has_unknown_critical(quic_span tbs) {
  quic_span ext;
  if (!reach_extensions(tbs, &ext)) return 0;
  return scan_unknown_critical(ext);
}
