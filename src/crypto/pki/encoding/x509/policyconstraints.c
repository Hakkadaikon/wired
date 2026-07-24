#include "crypto/pki/encoding/x509/policyconstraints.h"

#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/asn1/derval.h"
#include "crypto/pki/encoding/x509/x509.h"

/* id-ce-policyConstraints = 2.5.29.36 */
static const u8 oid_policy_constraints[] = {0x55, 0x1d, 0x24};
/* id-ce-inhibitAnyPolicy = 2.5.29.54 */
static const u8 oid_inhibit_any_policy[] = {0x55, 0x1d, 0x36};

/* RFC 5280 4.2.1.11. requireExplicitPolicy is [0] IMPLICIT SkipCerts, the
 * first element of PolicyConstraints when present. */
#define POLICYCONSTRAINTS_REQEXP_TAG 0x80

/* A DER INTEGER's content octets, decoded via the shared unsigned-integer
 * reader. QUIC_X509_SKIPCERTS_MALFORMED on a negative/oversized encoding. */
static u64 skipcerts_uint(quic_span v) {
  u64 out;
  if (!quic_der_uint(v.p, v.n, &out)) return QUIC_X509_SKIPCERTS_MALFORMED;
  return out;
}

/* The PolicyConstraints SEQUENCE value, if the extension is present. */
static int policy_constraints_locate(quic_span tbs, quic_span* val) {
  quic_span raw;
  if (!quic_x509_find_ext(
          tbs,
          quic_span_of(oid_policy_constraints, sizeof(oid_policy_constraints)),
          &raw))
    return 0;
  return quic_der_seq(raw, val);
}

/* RFC 5280 4.2.1.11. requireExplicitPolicy, the SEQUENCE's leading element
 * when tagged [0]; absent if the SEQUENCE is empty or starts with [1]
 * (inhibitPolicyMapping only). */
static u64 policy_constraints_reqexp(quic_span seq) {
  quic_derseq c;
  u8          tag;
  quic_span   v;
  quic_derseq_init(&c, seq);
  if (!quic_derseq_next(&c, &tag, &v)) return QUIC_X509_SKIPCERTS_NONE;
  if (tag != POLICYCONSTRAINTS_REQEXP_TAG) return QUIC_X509_SKIPCERTS_NONE;
  return skipcerts_uint(v);
}

u64 quic_x509_require_explicit_policy(quic_span tbs) {
  quic_span seq;
  if (!policy_constraints_locate(tbs, &seq)) return QUIC_X509_SKIPCERTS_NONE;
  return policy_constraints_reqexp(seq);
}

/* RFC 5280 4.2.1.14. InhibitAnyPolicy's extnValue is a bare SkipCerts
 * INTEGER TLV (not a SEQUENCE). */
static u64 inhibit_any_policy_val(quic_span raw) {
  quic_der_tlv t;
  if (!quic_der_read(raw, &t)) return QUIC_X509_SKIPCERTS_MALFORMED;
  if (t.tag != QUIC_DER_INTEGER) return QUIC_X509_SKIPCERTS_MALFORMED;
  return skipcerts_uint(t.val);
}

u64 quic_x509_inhibit_any_policy(quic_span tbs) {
  quic_span raw;
  if (!quic_x509_find_ext(
          tbs,
          quic_span_of(oid_inhibit_any_policy, sizeof(oid_inhibit_any_policy)),
          &raw))
    return QUIC_X509_SKIPCERTS_NONE;
  return inhibit_any_policy_val(raw);
}
