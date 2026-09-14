#include "crypto/pki/encoding/x509/nameconstraints.h"

#include "common/bytes/util/bytes.h"
#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/x509/chain.h"
#include "crypto/pki/encoding/x509/dirstring.h"
#include "crypto/pki/encoding/x509/san.h"
#include "crypto/pki/encoding/x509/x509.h"

/* id-ce-nameConstraints = 2.5.29.30 */
static const u8 oid_name_constraints[] = {0x55, 0x1d, 0x1e};
/* id-ce-subjectAltName = 2.5.29.17 */
static const u8 nc_oid_san[] = {0x55, 0x1d, 0x11};

/* RFC 5280 4.2.1.10. permittedSubtrees is [0], excludedSubtrees is [1],
 * both EXPLICIT (GeneralSubtrees is a SEQUENCE, a constructed type). */
#define NC_PERMITTED_TAG 0xa0
#define NC_EXCLUDED_TAG 0xa1
/* RFC 5280 4.2.1.6. The GeneralName CHOICE arms a GeneralSubtree base can
 * take that this SDK evaluates: dNSName is [2] IMPLICIT IA5String, URI is
 * [6] IMPLICIT IA5String, iPAddress is [7] IMPLICIT OCTET STRING, and
 * directoryName is [4] EXPLICIT Name (always EXPLICIT per X.690 31.2.7). */
#define NC_DNSNAME_TAG 0x82
#define NC_DIRECTORYNAME_TAG 0xa4
#define NC_URI_TAG 0x86
#define NC_IPADDR_TAG 0x87

/* The NameConstraints extnValue SEQUENCE, if the extension is present. */
static int nc_locate(wired_span tbs, wired_span* val) {
  wired_span raw;
  if (!x509_find_ext(
          tbs,
          wired_span_of(oid_name_constraints, sizeof(oid_name_constraints)),
          &raw))
    return 0;
  return der_seq(raw, val);
}

/* Find the [0] permittedSubtrees or [1] excludedSubtrees element inside the
 * NameConstraints SEQUENCE. RFC 5280 Appendix A tags IMPLICITly, so [0]/[1]
 * replaces the GeneralSubtrees SEQUENCE's own tag: the element's value IS
 * the SEQUENCE OF GeneralSubtree content (byte-verified against OpenSSL
 * 3.0.13's own emitted encoding). Returns 0 if that half is absent. */
static int nc_half(wired_span seq, u8 want_tag, wired_span* subtrees) {
  derseq     c;
  u8         tag;
  wired_span v;
  derseq_init(&c, seq);
  while (derseq_next(&c, &tag, &v))
    if (tag == want_tag) {
      *subtrees = v;
      return 1;
    }
  return 0;
}

/* GeneralSubtree ::= SEQUENCE { base GeneralName, ... }. View base and its
 * GeneralName CHOICE tag; 0 if the element is malformed (a malformed
 * subtree entry is skipped, like any GeneralName form this SDK does not
 * evaluate). */
static int subtree_base(wired_span subtree, u8* tag, wired_span* base) {
  derseq c;
  derseq_init(&c, subtree);
  return derseq_next(&c, tag, base);
}

/* RFC 5280 4.2.1.10 / 7.1: name is within base's directoryName subtree iff
 * base's RDN sequence is a prefix, RDN for RDN, of name's. Each RDN pair is
 * compared with the same RFC 4518 caseIgnoreMatch rules as x509_dn_equal_ci
 * (dirstring.h): RFC 5280 4.2.1.10 wants the base "stated identically to
 * the encoding used in the subject", but a subject spelled with different
 * DirectoryString case than an excludedSubtrees base must not escape it,
 * and a permittedSubtrees base must admit the subject it names. */
static int dn_within_base(wired_span base, wired_span name) {
  return x509_dn_prefix_ci(base, name);
}

/* RFC 5280 4.2.1.10: base's octets equal name's trailing octets,
 * ASCII case-insensitively. */
static int dns_suffix_eq(wired_span base, wired_span name) {
  if (name.n < base.n) return 0;
  return ascii_dns_eq(base, wired_span_of(name.p + name.n - base.n, base.n));
}

/* name is longer than base and the octet just before the suffix is the
 * label separator '.'. */
static int dns_dot_boundary(wired_span base, wired_span name) {
  return name.n > base.n && name.p[name.n - base.n - 1] == '.';
}

/* name is a strict subdomain of base ("adding one or more labels to the
 * left-hand side", RFC 5280 4.2.1.10). */
static int dns_subdomain(wired_span base, wired_span name) {
  return dns_dot_boundary(base, name) && dns_suffix_eq(base, name);
}

static int dns_eq_or_subdomain(wired_span base, wired_span name) {
  return ascii_dns_eq(base, name) || dns_subdomain(base, name);
}

/* RFC 5280 4.2.1.10 dNSName subtree membership. A '*' in name is an
 * ordinary byte, so a wildcard SAN entry is classified by its literal
 * suffix. An empty base covers the whole DNS namespace; a base with a
 * leading '.' covers subdomains only (the widely-deployed subdomains-only
 * spelling); otherwise base covers itself and every subdomain. */
static int nc_dns_within(wired_span base, wired_span name) {
  if (base.n == 0) return 1;
  if (base.p[0] == '.') return dns_suffix_eq(base, name);
  return dns_eq_or_subdomain(base, name);
}

/* (addr ^ name) & mask == 0, over n address octets with the mask octets
 * following the address in base. */
static int ip_mask_match(const u8* base, const u8* name, usz n) {
  u8 acc = 0;
  for (usz i = 0; i < n; i++) acc |= (u8)((base[i] ^ name[i]) & base[n + i]);
  return acc == 0;
}

/* RFC 5280 4.2.1.10 iPAddress subtree membership: base is address||mask,
 * exactly twice the SAN address length (8 octets against IPv4, 32 against
 * IPv6). A base of the other family covers nothing, so a permitted subtree
 * fails closed against it (a base of malformed length never reaches here,
 * see ip_bases_malformed). */
static int nc_ip_within(wired_span base, wired_span name) {
  if (base.n != 2 * name.n) return 0;
  return ip_mask_match(base.p, name.p, name.n);
}

typedef int (*nc_matcher)(wired_span base, wired_span name);

/* A base of the wanted GeneralName form participates: record it in *any and
 * fold its match into *covered. */
static void typed_mark(
    u8         tag,
    wired_span base,
    u8         want,
    wired_span name,
    nc_matcher m,
    int*       any,
    int*       covered) {
  if (tag != want) return;
  *any = 1;
  if (m(base, name)) *covered = 1;
}

/* One GeneralSubtree element folded into *any / *covered. */
static void typed_fold(
    wired_span sub,
    u8         want,
    wired_span name,
    nc_matcher m,
    int*       any,
    int*       covered) {
  u8         tag;
  wired_span base;
  if (!subtree_base(sub, &tag, &base)) return;
  typed_mark(tag, base, want, name, m, any, covered);
}

/* Scan a GeneralSubtrees SEQUENCE for bases of one GeneralName form; *any
 * records whether at least one entry had that form. Returns 1 if some entry
 * of the form covers name. */
static int typed_scan(
    wired_span subtrees, u8 want, wired_span name, nc_matcher m, int* any) {
  derseq     c;
  u8         tag;
  wired_span e;
  int        covered = 0;
  derseq_init(&c, subtrees);
  while (derseq_next(&c, &tag, &e)) typed_fold(e, want, name, m, any, &covered);
  return covered;
}

/* RFC 5280 6.1.4 (g)(1): if permittedSubtrees carries at least one entry of
 * name's form, name must fall within one of them; entries of other forms do
 * not constrain it. */
static int typed_permitted_ok(
    wired_span seq, u8 want, wired_span name, nc_matcher m) {
  wired_span permitted;
  int        any = 0;
  if (!nc_half(seq, NC_PERMITTED_TAG, &permitted)) return 1;
  if (typed_scan(permitted, want, name, m, &any)) return 1;
  return !any;
}

/* RFC 5280 6.1.4 (g)(2): name must fall within no excludedSubtrees entry of
 * its form. */
static int typed_excluded_ok(
    wired_span seq, u8 want, wired_span name, nc_matcher m) {
  wired_span excluded;
  int        any = 0;
  if (!nc_half(seq, NC_EXCLUDED_TAG, &excluded)) return 1;
  return !typed_scan(excluded, want, name, m, &any);
}

/* Both halves of the constraint, for one name of one GeneralName form. */
static int typed_name_ok(
    wired_span seq, u8 want, wired_span name, nc_matcher m) {
  if (!typed_permitted_ok(seq, want, name, m)) return 0;
  return typed_excluded_ok(seq, want, name, m);
}

/* Number of GeneralSubtree elements in one half (0 if the half is absent). */
static usz half_count(wired_span seq, u8 half) {
  derseq     c;
  u8         tag;
  wired_span subtrees, e;
  usz        n = 0;
  if (!nc_half(seq, half, &subtrees)) return 0;
  derseq_init(&c, subtrees);
  while (derseq_next(&c, &tag, &e)) n++;
  return n;
}

/* The extension carries more GeneralSubtree entries than
 * X509_NC_SUBTREES_MAX (see the header): unusable, fail closed. */
static int nc_too_many(wired_span seq) {
  return half_count(seq, NC_PERMITTED_TAG) + half_count(seq, NC_EXCLUDED_TAG) >
         X509_NC_SUBTREES_MAX;
}

int x509_name_constraints_permit(wired_span cert_tbs, wired_span subject) {
  wired_span seq;
  if (!nc_locate(cert_tbs, &seq)) return 1;
  if (nc_too_many(seq)) return 0;
  return typed_name_ok(seq, NC_DIRECTORYNAME_TAG, subject, dn_within_base);
}

/* A matcher that always covers: probes whether a half carries any subtree
 * of a form at all. */
static int nc_always(wired_span base, wired_span name) {
  (void)base;
  (void)name;
  return 1;
}

/* RFC 5280 4.2.1.10: an iPAddress base of any length other than 8 (IPv4
 * address||mask) or 32 (IPv6) is malformed. */
static int nc_ip_malformed(wired_span base, wired_span name) {
  (void)name;
  return base.n != 8 && base.n != 32;
}

/* 1 if some subtree base of the given form in the given half satisfies m
 * (m is probed against the half itself as a dummy name). */
static int half_covers(wired_span seq, u8 half, u8 want, nc_matcher m) {
  wired_span subtrees;
  int        any = 0;
  if (!nc_half(seq, half, &subtrees)) return 0;
  return typed_scan(subtrees, want, subtrees, m, &any);
}

/* An iPAddress base of malformed length in either half makes the whole
 * extension unusable: fail closed regardless of the child's names. */
static int ip_bases_malformed(wired_span seq) {
  return half_covers(seq, NC_PERMITTED_TAG, NC_IPADDR_TAG, nc_ip_malformed) ||
         half_covers(seq, NC_EXCLUDED_TAG, NC_IPADDR_TAG, nc_ip_malformed);
}

/* URI matching is not implemented: a child URI SAN under an issuer whose
 * nameConstraints carries any URI subtree (either half) rejects outright
 * (fail closed; see the header). */
static int uri_san_ok(wired_span seq) {
  if (half_covers(seq, NC_PERMITTED_TAG, NC_URI_TAG, nc_always)) return 0;
  return !half_covers(seq, NC_EXCLUDED_TAG, NC_URI_TAG, nc_always);
}

/* One SAN GeneralNames entry whose form this SDK evaluates beyond dNSName:
 * iPAddress against the iPAddress subtrees, URI as above. Forms this SDK
 * never consumes (rfc822Name, otherName, ...) are unconstrained. */
static int san_other_entry_ok(wired_span seq, u8 tag, wired_span e) {
  if (tag == NC_IPADDR_TAG) return typed_name_ok(seq, tag, e, nc_ip_within);
  if (tag == NC_URI_TAG) return uri_san_ok(seq);
  return 1;
}

/* One SAN GeneralNames entry; a dNSName entry also records its presence,
 * which rules out the CN fallback below. */
static int san_entry_ok(wired_span seq, u8 tag, wired_span e, int* has_dns) {
  if (tag != NC_DNSNAME_TAG) return san_other_entry_ok(seq, tag, e);
  *has_dns = 1;
  return typed_name_ok(seq, tag, e, nc_dns_within);
}

/* Every entry of the child's SAN GeneralNames is admitted. */
static int san_list_ok(wired_span seq, wired_span gn, int* has_dns) {
  derseq     c;
  u8         tag;
  wired_span e;
  derseq_init(&c, gn);
  while (derseq_next(&c, &tag, &e))
    if (!san_entry_ok(seq, tag, e, has_dns)) return 0;
  return 1;
}

/* The child's SAN, if present, is admitted entry by entry; a malformed SAN
 * extension fails closed. */
static int child_san_ok(wired_span seq, wired_span child_tbs, int* has_dns) {
  wired_span raw, gn;
  if (!x509_find_ext(
          child_tbs, wired_span_of(nc_oid_san, sizeof(nc_oid_san)), &raw))
    return 1;
  if (!der_seq(raw, &gn)) return 0;
  return san_list_ok(seq, gn, has_dns);
}

/* c is in [lo, hi], branch-free. */
static int nc_in_range(u8 c, u8 lo, u8 hi) {
  return (u8)(c - lo) <= (u8)(hi - lo);
}

/* ASCII letter (case-folded via |0x20) or digit. */
static int nc_alnum(u8 c) {
  return nc_in_range((u8)(c | 0x20), 'a', 'z') | nc_in_range(c, '0', '9');
}

/* A byte a hostname (RFC 952/1123 shape, plus the '*' wildcard byte and the
 * '.' separator) may contain. */
static int nc_host_byte(u8 c) {
  return nc_alnum(c) | (c == '-') | (c == '.') | (c == '*');
}

/* cn is non-empty and made only of hostname bytes -- the shape
 * x509_san_matches' CN-ID fallback could match a hostname against. */
static int nc_dns_shaped(wired_span cn) {
  int ok = cn.n != 0;
  for (usz i = 0; i < cn.n; i++) ok &= nc_host_byte(cn.p[i]);
  return ok;
}

/* RFC 6125 6.4.4 / RFC 9525 fallback practice: with no SAN dNSName entry, a
 * DNS-shaped subject commonName is the name x509_san_matches would fall
 * back to, so the dNSName subtrees apply to it. A CN that is not DNS-shaped
 * (or absent) is constrained by directoryName subtrees only.
 * ponytail: iPAddress subtrees are not applied to an IP-literal CN; extend
 * here if a CA constrained by iPAddress-only subtrees must also pin
 * SAN-less IP-literal-CN leaves. */
static int cn_fallback_ok(wired_span seq, wired_span child_tbs) {
  wired_span cn;
  if (!x509_subject_cn(child_tbs, &cn)) return 1;
  if (!nc_dns_shaped(cn)) return 1;
  return typed_name_ok(seq, NC_DNSNAME_TAG, cn, nc_dns_within);
}

/* The child's SAN entries and, when no SAN dNSName exists, its CN. */
static int child_names_ok(wired_span seq, wired_span child_tbs) {
  int has_dns = 0;
  if (!child_san_ok(seq, child_tbs, &has_dns)) return 0;
  if (has_dns) return 1;
  return cn_fallback_ok(seq, child_tbs);
}

/* The child's subject Name against the directoryName subtrees; an
 * unreadable subject fails closed. */
static int child_subject_ok(wired_span seq, wired_span child_tbs) {
  wired_span subj;
  if (!x509_subject(child_tbs, &subj)) return 0;
  return typed_name_ok(seq, NC_DIRECTORYNAME_TAG, subj, dn_within_base);
}

/* The extension is one this SDK will evaluate at all: no malformed
 * iPAddress base, and within the GeneralSubtree count bound. */
static int nc_usable(wired_span seq) {
  return !ip_bases_malformed(seq) && !nc_too_many(seq);
}

/* A usable extension admits the child's subject and its names. */
static int nc_admit(wired_span seq, wired_span child_tbs) {
  if (!nc_usable(seq)) return 0;
  if (!child_subject_ok(seq, child_tbs)) return 0;
  return child_names_ok(seq, child_tbs);
}

int x509_name_constraints_admit(wired_span issuer_tbs, wired_span child_tbs) {
  wired_span seq;
  if (!nc_locate(issuer_tbs, &seq)) return 1;
  return nc_admit(seq, child_tbs);
}
