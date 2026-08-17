#include "crypto/pki/encoding/x509/nameconstraints.h"

#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/x509/x509.h"

/* id-ce-nameConstraints = 2.5.29.30 */
static const u8 oid_name_constraints[] = {0x55, 0x1d, 0x1e};

/* RFC 5280 4.2.1.10. permittedSubtrees is [0], excludedSubtrees is [1],
 * both EXPLICIT (GeneralSubtrees is a SEQUENCE, a constructed type). */
#define NC_PERMITTED_TAG 0xa0
#define NC_EXCLUDED_TAG 0xa1
/* RFC 5280 4.2.1.6. GeneralName directoryName is [4] EXPLICIT Name (a CHOICE
 * arm, always EXPLICIT per X.690 31.2.7). */
#define NC_DIRECTORYNAME_TAG 0xa4

/* The NameConstraints extnValue SEQUENCE, if the extension is present. */
static int nc_locate(wired_span tbs, wired_span* val) {
  wired_span raw;
  if (!quic_x509_find_ext(
          tbs,
          wired_span_of(oid_name_constraints, sizeof(oid_name_constraints)),
          &raw))
    return 0;
  return quic_der_seq(raw, val);
}

/* Find the [0] permittedSubtrees or [1] excludedSubtrees element inside the
 * NameConstraints SEQUENCE. Both are EXPLICIT (RFC 5280 4.2.1.10), so the
 * element's value is the GeneralSubtrees SEQUENCE's own TLV; unwrap it once
 * more to reach the SEQUENCE OF GeneralSubtree content. Returns 0 if that
 * half is absent or malformed. */
static int nc_half(wired_span seq, u8 want_tag, wired_span* subtrees) {
  quic_derseq c;
  u8          tag;
  wired_span  v;
  quic_derseq_init(&c, seq);
  while (quic_derseq_next(&c, &tag, &v))
    if (tag == want_tag) return quic_der_seq(v, subtrees);
  return 0;
}

/* GeneralSubtree ::= SEQUENCE { base GeneralName, ... }. View base if it is
 * the directoryName CHOICE arm; 0 if base is some other GeneralName form
 * (out of scope, RFC 5280 4.2.1.10) or the element is malformed. */
static int subtree_directoryname_base(wired_span subtree, wired_span* base) {
  quic_derseq c;
  u8          tag;
  quic_derseq_init(&c, subtree);
  if (!quic_derseq_next(&c, &tag, base)) return 0;
  return tag == NC_DIRECTORYNAME_TAG;
}

/* 1 if the two byte spans of equal length differ nowhere. */
static int nc_bytes_eq(const u8* a, const u8* b, usz n) {
  usz diff = 0;
  for (usz i = 0; i < n; i++) diff |= (usz)(a[i] ^ b[i]);
  return diff == 0;
}

/* RFC 5280 4.2.1.10 / 7.1: name is within base's directoryName subtree iff
 * base's RDN sequence is a prefix, RDN-for-RDN, of name's RDN sequence. Name
 * is itself a SEQUENCE OF RelativeDistinguishedName, so comparing the
 * SEQUENCE *contents* (their tag+length header stripped) as a byte prefix
 * cannot straddle into the middle of an RDN's own tag+length: each RDN is a
 * self-delimiting TLV, so a byte-exact prefix of whole RDNs is necessarily a
 * boundary-aligned prefix (RFC 5280 does not require DN-component
 * normalization for this SDK's directoryName-only, no-mapping subtree
 * check). Comparing base's own outer SEQUENCE TLV (header included) against
 * name's would instead compare unrelated length octets when the two Names
 * have a different total encoded length, which is the common case for a
 * base that is a strict ancestor. */
static int rdns_prefix_ok(wired_span base_rdns, wired_span name_rdns) {
  if (base_rdns.n > name_rdns.n) return 0;
  return nc_bytes_eq(base_rdns.p, name_rdns.p, base_rdns.n);
}

static int dn_within_base(wired_span base, wired_span name) {
  wired_span base_rdns, name_rdns;
  if (!quic_der_seq(base, &base_rdns)) return 0;
  if (!quic_der_seq(name, &name_rdns)) return 0;
  return rdns_prefix_ok(base_rdns, name_rdns);
}

/* Fold one GeneralSubtree element into *any_directoryname and *covered: a
 * non-directoryName entry changes neither; a directoryName entry sets
 * *any_directoryname and, if it covers subject, sets *covered. */
static void subtree_fold(
    wired_span e, wired_span subject, int* any_directoryname, int* covered) {
  wired_span base;
  if (!subtree_directoryname_base(e, &base)) return;
  *any_directoryname = 1;
  if (dn_within_base(base, subject)) *covered = 1;
}

/* Scan a GeneralSubtrees SEQUENCE; *any_directoryname records whether at
 * least one entry was a directoryName form (entries in other GeneralName
 * forms do not participate in this SDK's directoryName-only check). Returns
 * 1 if some directoryName entry covers subject. */
static int subtrees_scan(
    wired_span subtrees, wired_span subject, int* any_directoryname) {
  quic_derseq c;
  u8          tag;
  wired_span  e;
  int         covered = 0;
  quic_derseq_init(&c, subtrees);
  while (quic_derseq_next(&c, &tag, &e))
    subtree_fold(e, subject, any_directoryname, &covered);
  return covered;
}

/* RFC 5280 6.1.4 (g)(1): if permittedSubtrees is present, subject must fall
 * within at least one of its directoryName entries (subtrees in other
 * GeneralName forms are silently not consulted -- see the header comment).
 * No directoryName entries at all in permittedSubtrees is vacuously
 * permitting (this SDK constrains only the forms it understands). */
static int permitted_ok(wired_span seq, wired_span subject) {
  wired_span permitted;
  int        any_dn = 0;
  if (!nc_half(seq, NC_PERMITTED_TAG, &permitted)) return 1;
  if (!subtrees_scan(permitted, subject, &any_dn)) return !any_dn;
  return 1;
}

/* RFC 5280 6.1.4 (g)(2): if excludedSubtrees is present, subject must fall
 * within none of its directoryName entries. */
static int excluded_ok(wired_span seq, wired_span subject) {
  wired_span excluded;
  int        any_dn = 0;
  if (!nc_half(seq, NC_EXCLUDED_TAG, &excluded)) return 1;
  return !subtrees_scan(excluded, subject, &any_dn);
}

int quic_x509_name_constraints_permit(wired_span cert_tbs, wired_span subject) {
  wired_span seq;
  if (!nc_locate(cert_tbs, &seq)) return 1;
  if (!permitted_ok(seq, subject)) return 0;
  return excluded_ok(seq, subject);
}
