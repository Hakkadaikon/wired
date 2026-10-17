#include "crypto/pki/encoding/x509/nameconstraints_impl.h"

static int san_entry_ok(wired_span seq, u8 tag, wired_span e, int* has_dns);
static int san_list_ok(wired_span seq, wired_span gn, int* has_dns);
static int child_san_ok(wired_span seq, wired_span child_tbs, int* has_dns);
static int nc_in_range(u8 c, u8 lo, u8 hi);
static int nc_alnum(u8 c);
static int nc_host_byte(u8 c);
static int nc_dns_shaped(wired_span cn);
static int cn_fallback_ok(wired_span seq, wired_span child_tbs);
static int child_names_ok(wired_span seq, wired_span child_tbs);
static int child_subject_ok(wired_span seq, wired_span child_tbs);
static int nc_usable(wired_span seq);
static int nc_admit(wired_span seq, wired_span child_tbs);

/* One SAN GeneralNames entry; a dNSName entry also records its presence,
 * which rules out the CN fallback below. */
static int san_entry_ok(wired_span seq, u8 tag, wired_span e, int* has_dns) {
  if (tag != NC_DNSNAME_TAG) return x509_san_other_entry_ok(seq, tag, e);
  *has_dns = 1;
  return x509_typed_name_ok(seq, tag, e, x509_nc_dns_within);
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
  return x509_typed_name_ok(seq, NC_DNSNAME_TAG, cn, x509_nc_dns_within);
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
  return x509_typed_name_ok(
      seq, NC_DIRECTORYNAME_TAG, subj, x509_dn_within_base);
}

/* The extension is one this SDK will evaluate at all: no malformed
 * iPAddress base, and within the GeneralSubtree count bound. */
static int nc_usable(wired_span seq) {
  return !x509_ip_bases_malformed(seq) && !x509_nc_too_many(seq);
}

/* A usable extension admits the child's subject and its names. */
static int nc_admit(wired_span seq, wired_span child_tbs) {
  if (!nc_usable(seq)) return 0;
  if (!child_subject_ok(seq, child_tbs)) return 0;
  return child_names_ok(seq, child_tbs);
}

int x509_name_constraints_admit(wired_span issuer_tbs, wired_span child_tbs) {
  wired_span seq;
  if (!x509_nc_locate(issuer_tbs, &seq)) return 1;
  return nc_admit(seq, child_tbs);
}
