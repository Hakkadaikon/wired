#include "crypto/pki/encoding/x509/nameconstraints_impl.h"

static int  subtree_base(wired_span subtree, u8* tag, wired_span* base);
static int  dns_suffix_eq(wired_span base, wired_span name);
static int  dns_dot_boundary(wired_span base, wired_span name);
static int  dns_subdomain(wired_span base, wired_span name);
static int  dns_eq_or_subdomain(wired_span base, wired_span name);
static int  ip_mask_match(const u8* base, const u8* name, usz n);
static void typed_mark(
    u8         tag,
    wired_span base,
    u8         want,
    wired_span name,
    nc_matcher m,
    int*       any,
    int*       covered);

/* id-ce-nameConstraints = 2.5.29.30 */
static const u8 oid_name_constraints[] = {0x55, 0x1d, 0x1e};

/* id-ce-subjectAltName = 2.5.29.17 */
const u8 nc_oid_san[] = {0x55, 0x1d, 0x11};

/* The NameConstraints extnValue SEQUENCE, if the extension is present. */
int x509_nc_locate(wired_span tbs, wired_span* val) {
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
int x509_nc_half(wired_span seq, u8 want_tag, wired_span* subtrees) {
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
int x509_dn_within_base(wired_span base, wired_span name) {
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
int x509_nc_dns_within(wired_span base, wired_span name) {
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
 * see x509_ip_bases_malformed). */
int x509_nc_ip_within(wired_span base, wired_span name) {
  if (base.n != 2 * name.n) return 0;
  return ip_mask_match(base.p, name.p, name.n);
}

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
void x509_typed_fold(
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
