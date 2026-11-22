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
/* inhibitPolicyMapping is [1] IMPLICIT SkipCerts. */
#define POLICYCONSTRAINTS_INHIBIT_MAP_TAG 0x81

/* A DER INTEGER's content octets, decoded via the shared unsigned-integer
 * reader. X509_SKIPCERTS_MALFORMED on a negative/oversized encoding. */
static u64 skipcerts_uint(wired_span v) {
  u64 out;
  if (!der_uint(v.p, v.n, &out)) {
    return X509_SKIPCERTS_MALFORMED;
  }
  return out;
}

/* The extnValue is exactly one SEQUENCE TLV; views its value. */
static int pc_outer(wired_span raw, wired_span* seq) {
  der_tlv t;
  if (!der_read(raw, &t)) {
    return 0;
  }
  *seq = t.val;
  return t.tag == DER_SEQUENCE && t.used == raw.n;
}

/* tag names a field not before *next: DER order, [0] then [1], no repeat. */
static int pc_tag_ok(u8 tag, u8 next) {
  return tag >= next && tag <= POLICYCONSTRAINTS_INHIBIT_MAP_TAG;
}

/* Store element (tag, v) into f[tag - [0]]; 0 on a misplaced tag or a
 * malformed SkipCerts. */
static int pc_take(u8 tag, wired_span v, u8* next, u64* f) {
  usz k = (usz)(tag - POLICYCONSTRAINTS_REQEXP_TAG);
  if (!pc_tag_ok(tag, *next)) {
    return 0;
  }
  f[k]  = skipcerts_uint(v);
  *next = (u8)(tag + 1);
  return f[k] != X509_SKIPCERTS_MALFORMED;
}

/* RFC 5280 4.2.1.11. The PolicyConstraints SEQUENCE value into f: its
 * elements must fill it exactly. */
static int pc_parse(wired_span seq, u64* f) {
  derseq     c;
  u8         tag;
  wired_span v;
  u8         next = POLICYCONSTRAINTS_REQEXP_TAG;
  derseq_init(&c, seq);
  while (derseq_next(&c, &tag, &v)) {
    if (!pc_take(tag, v, &next, f)) {
      return 0;
    }
  }
  return c.off == c.len;
}

/* f[0] requireExplicitPolicy, f[1] inhibitPolicyMapping, each
 * X509_SKIPCERTS_NONE when absent (or the extension is). 0 if present but
 * malformed. */
static int pc_read(wired_span tbs, u64* f) {
  wired_span raw, seq;
  f[0] = X509_SKIPCERTS_NONE;
  f[1] = X509_SKIPCERTS_NONE;
  if (!x509_find_ext(
          tbs,
          wired_span_of(oid_policy_constraints, sizeof(oid_policy_constraints)),
          &raw)) {
    return 1;
  }
  if (!pc_outer(raw, &seq)) {
    return 0;
  }
  return pc_parse(seq, f);
}

/* Field k of tbs's PolicyConstraints, or X509_SKIPCERTS_MALFORMED. */
static u64 pc_lookup(wired_span tbs, usz k) {
  u64 f[2];
  if (!pc_read(tbs, f)) {
    return X509_SKIPCERTS_MALFORMED;
  }
  return f[k];
}

u64 x509_require_explicit_policy(wired_span tbs) { return pc_lookup(tbs, 0); }

u64 x509_inhibit_policy_mapping(wired_span tbs) { return pc_lookup(tbs, 1); }

int x509_pc_unprocessed_critical(wired_span tbs) {
  u64 f[2];
  if (!x509_ext_critical(
          tbs, wired_span_of(
                   oid_policy_constraints, sizeof(oid_policy_constraints)))) {
    return 0;
  }
  return !pc_read(tbs, f);
}

/* RFC 5280 4.2.1.14. InhibitAnyPolicy's extnValue is a bare SkipCerts
 * INTEGER TLV (not a SEQUENCE). */
static u64 inhibit_any_policy_val(wired_span raw) {
  der_tlv t;
  if (!der_read(raw, &t)) {
    return X509_SKIPCERTS_MALFORMED;
  }
  if (t.tag != DER_INTEGER) {
    return X509_SKIPCERTS_MALFORMED;
  }
  return skipcerts_uint(t.val);
}

u64 x509_inhibit_any_policy(wired_span tbs) {
  wired_span raw;
  if (!x509_find_ext(
          tbs,
          wired_span_of(oid_inhibit_any_policy, sizeof(oid_inhibit_any_policy)),
          &raw)) {
    return X509_SKIPCERTS_NONE;
  }
  return inhibit_any_policy_val(raw);
}
