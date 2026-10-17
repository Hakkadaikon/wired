/* RFC 5280 4.1.2.1. version is [0] EXPLICIT, optional and default v1. */
/* RFC 5280 4.1. issuerUniqueID is [1] IMPLICIT, subjectUniqueID is [2]
 * IMPLICIT; both optional (v2/v3 only). */
/* RFC 5280 4.1.2.9. extensions is [3] EXPLICIT. */
/* RFC 5280 4.1. tbs elements before extensions (version excluded):
 * serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo. */

#include "crypto/pki/encoding/x509/x509_impl.h"

static int alg_oid(wired_span alg, wired_span* oid);
static int outer_next(derseq* c, wired_span* whole, der_tlv* e);
static int take_tbs(derseq* c, x509* out);
static int take_alg(derseq* c, x509* out);
static int take_sig(derseq* c, x509* out);
static int take_fields(wired_span seq, x509* out);
static int skip_tagged_if_present(derseq* c, u8 want_tag);
static int skip_unique_ids(derseq* c);

/* RFC 5280 4.1.1.2. signatureAlgorithm ::= SEQUENCE { algorithm OID, ... }.
 * Extract the OID value from the AlgorithmIdentifier blob. */
static int alg_oid(wired_span alg, wired_span* oid) {
  derseq c;
  derseq_init(&c, alg);
  return derseq_next_tagged(&c, DER_OID, oid);
}

/* Read one element of the outer SEQUENCE, keeping its header-included span
 * (the signed bytes for tbsCertificate). */
static int outer_next(derseq* c, wired_span* whole, der_tlv* e) {
  const u8*  start = c->p + c->off;
  wired_span val;
  if (!derseq_next(c, &e->tag, &val)) return 0;
  e->val = val;
  *whole = wired_span_of(start, (usz)(c->p + c->off - start));
  return 1;
}

/* RFC 5280 4.1. tbsCertificate: keep the header-included span (signed bytes).
 */
static int take_tbs(derseq* c, x509* out) {
  der_tlv e;
  if (!outer_next(c, &out->tbs, &e)) return 0;
  return e.tag == DER_SEQUENCE;
}

/* RFC 5280 4.1.1.2. signatureAlgorithm: pull out its OID. */
static int take_alg(derseq* c, x509* out) {
  wired_span whole;
  der_tlv    e;
  if (!outer_next(c, &whole, &e)) return 0;
  if (e.tag != DER_SEQUENCE) return 0;
  return alg_oid(e.val, &out->sig_alg_oid);
}

/* RFC 5280 4.1.1.3. signatureValue: a BIT STRING. */
static int take_sig(derseq* c, x509* out) {
  wired_span whole;
  der_tlv    e;
  if (!outer_next(c, &whole, &e)) return 0;
  out->sig = e.val;
  return e.tag == DER_BIT_STRING;
}

/* RFC 5280 4.1. The three fields in order: tbs, algorithm, signature. */
static int take_fields(wired_span seq, x509* out) {
  derseq c;
  derseq_init(&c, seq);
  return take_tbs(&c, out) && take_alg(&c, out) && take_sig(&c, out);
}

int x509_parse(wired_span cert, x509* out) {
  wired_span seq;
  return der_seq(cert, &seq) && take_fields(seq, out);
}

/* Drop one optional IMPLICIT/EXPLICIT-tagged context element if the cursor
 * currently sits on it, else leave the cursor untouched. Used for version
 * [0], issuerUniqueID [1], and subjectUniqueID [2], all of which are
 * DER-optional and so must be probed by tag rather than counted as fixed
 * positions. */
static int skip_tagged_if_present(derseq* c, u8 want_tag) {
  wired_span val;
  if (c->off < c->len && c->p[c->off] == want_tag)
    return derseq_next_tagged(c, want_tag, &val);
  return 1;
}

int x509_tbs_cursor(wired_span tbs, derseq* c) {
  wired_span v;
  if (!der_seq(tbs, &v)) return 0;
  derseq_init(c, v);
  return skip_tagged_if_present(c, X509_VERSION_TAG);
}

/* RFC 5280 4.1. Drop issuerUniqueID [1] and subjectUniqueID [2] if either is
 * present; a v1 tbs (neither present) leaves the cursor untouched. */
static int skip_unique_ids(derseq* c) {
  if (!skip_tagged_if_present(c, X509_ISSUER_UID_TAG)) return 0;
  return skip_tagged_if_present(c, X509_SUBJECT_UID_TAG);
}

/* Position the cursor before the extensions [3] element. */
int x509_at_extensions(wired_span tbs, derseq* c) {
  if (!x509_tbs_cursor(tbs, c)) return 0;
  if (!derseq_skip(c, X509_EXT_SKIP)) return 0;
  return skip_unique_ids(c);
}
