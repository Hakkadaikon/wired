#include "crypto/pki/encoding/x509/policymap.h"

#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/asn1/derval.h"
#include "crypto/pki/encoding/x509/certpolicies.h"
#include "crypto/pki/encoding/x509/x509.h"

/* A CertPolicyId usable in a mapping: a non-empty OID that is not
 * anyPolicy (RFC 5280 6.1.4 (a)). */
static int pm_id_ok(wired_span oid) {
  return oid.n > 0 && !der_oid_equal(oid, x509_any_policy_oid());
}

/* The next element at c is a usable CertPolicyId OID. */
static int pm_take_id(derseq* c, wired_span* oid) {
  return derseq_next_tagged(c, DER_OID, oid) && pm_id_ok(*oid);
}

/* SEQUENCE { issuerDomainPolicy, subjectDomainPolicy } value v, exactly
 * two elements. */
static int pm_pair(wired_span v, wired_span* idp, wired_span* sdp) {
  derseq c;
  derseq_init(&c, v);
  if (!pm_take_id(&c, idp)) {
    return 0;
  }
  return pm_take_id(&c, sdp) && c.off == c.len;
}

/* Keep one pair; past X509_POLICY_MAPS_MAX it is dropped and *m marked
 * truncated (still valid DER, so not an error). */
static void pm_store(x509_policy_maps* m, wired_span idp, wired_span sdp) {
  if (m->n >= X509_POLICY_MAPS_MAX) {
    m->truncated = 1;
    return;
  }
  m->idp[m->n] = idp;
  m->sdp[m->n] = sdp;
  m->n++;
}

/* Element (tag, v) of the outer SEQUENCE is one pair. */
static int pm_add(x509_policy_maps* m, u8 tag, wired_span v) {
  wired_span idp, sdp;
  if (tag != DER_SEQUENCE) {
    return 0;
  }
  if (!pm_pair(v, &idp, &sdp)) {
    return 0;
  }
  pm_store(m, idp, sdp);
  return 1;
}

/* The cursor consumed the whole SEQUENCE and SIZE (1..MAX) holds. */
static int pm_done(const derseq* c, const x509_policy_maps* m) {
  return c->off == c->len && m->n > 0;
}

/* Every element of the outer SEQUENCE value is a pair. */
static int pm_scan(wired_span seq, x509_policy_maps* m) {
  derseq     c;
  u8         tag;
  wired_span v;
  derseq_init(&c, seq);
  while (derseq_next(&c, &tag, &v)) {
    if (!pm_add(m, tag, v)) {
      return 0;
    }
  }
  return pm_done(&c, m);
}

/* t is one SEQUENCE TLV spanning the whole extnValue raw. */
static int pm_whole_seq(const der_tlv* t, wired_span raw) {
  return t->tag == DER_SEQUENCE && t->used == raw.n;
}

/* The extnValue is exactly one SEQUENCE TLV of pairs. */
static int pm_parse(wired_span raw, x509_policy_maps* m) {
  der_tlv t;
  if (!der_read(raw, &t)) {
    return 0;
  }
  if (!pm_whole_seq(&t, raw)) {
    return 0;
  }
  return pm_scan(t.val, m);
}

int x509_policy_mappings(wired_span tbs, x509_policy_maps* m) {
  wired_span raw;
  m->n         = 0;
  m->truncated = 0;
  if (!x509_find_ext(
          tbs,
          wired_span_of(
              x509_oid_policy_mappings, sizeof(x509_oid_policy_mappings)),
          &raw)) {
    return 0;
  }
  return pm_parse(raw, m) ? 1 : -1;
}

int x509_pm_unprocessed_critical(wired_span tbs) {
  x509_policy_maps m;
  if (!x509_ext_critical(
          tbs,
          wired_span_of(
              x509_oid_policy_mappings, sizeof(x509_oid_policy_mappings)))) {
    return 0;
  }
  return x509_policy_mappings(tbs, &m) < 0;
}
