#include "crypto/pki/encoding/x509/nameconstraints_impl.h"

static int typed_scan(
    wired_span subtrees, u8 want, wired_span name, nc_matcher m, int* any);
static int typed_permitted_ok(
    wired_span seq, u8 want, wired_span name, nc_matcher m);
static int typed_excluded_ok(
    wired_span seq, u8 want, wired_span name, nc_matcher m);
static usz half_count(wired_span seq, u8 half);
static int nc_always(wired_span base, wired_span name);
static int nc_ip_malformed(wired_span base, wired_span name);
static int half_covers(wired_span seq, u8 half, u8 want, nc_matcher m);
static int uri_san_ok(wired_span seq);

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
  while (derseq_next(&c, &tag, &e))
    x509_typed_fold(e, want, name, m, any, &covered);
  return covered;
}

/* RFC 5280 6.1.4 (g)(1): if permittedSubtrees carries at least one entry of
 * name's form, name must fall within one of them; entries of other forms do
 * not constrain it. */
static int typed_permitted_ok(
    wired_span seq, u8 want, wired_span name, nc_matcher m) {
  wired_span permitted;
  int        any = 0;
  if (!x509_nc_half(seq, NC_PERMITTED_TAG, &permitted)) return 1;
  if (typed_scan(permitted, want, name, m, &any)) return 1;
  return !any;
}

/* RFC 5280 6.1.4 (g)(2): name must fall within no excludedSubtrees entry of
 * its form. */
static int typed_excluded_ok(
    wired_span seq, u8 want, wired_span name, nc_matcher m) {
  wired_span excluded;
  int        any = 0;
  if (!x509_nc_half(seq, NC_EXCLUDED_TAG, &excluded)) return 1;
  return !typed_scan(excluded, want, name, m, &any);
}

/* Both halves of the constraint, for one name of one GeneralName form. */
int x509_typed_name_ok(wired_span seq, u8 want, wired_span name, nc_matcher m) {
  if (!typed_permitted_ok(seq, want, name, m)) return 0;
  return typed_excluded_ok(seq, want, name, m);
}

/* Number of GeneralSubtree elements in one half (0 if the half is absent). */
static usz half_count(wired_span seq, u8 half) {
  derseq     c;
  u8         tag;
  wired_span subtrees, e;
  usz        n = 0;
  if (!x509_nc_half(seq, half, &subtrees)) return 0;
  derseq_init(&c, subtrees);
  while (derseq_next(&c, &tag, &e)) n++;
  return n;
}

/* The extension carries more GeneralSubtree entries than
 * X509_NC_SUBTREES_MAX (see the header): unusable, fail closed. */
int x509_nc_too_many(wired_span seq) {
  return half_count(seq, NC_PERMITTED_TAG) + half_count(seq, NC_EXCLUDED_TAG) >
         X509_NC_SUBTREES_MAX;
}

int x509_name_constraints_permit(wired_span cert_tbs, wired_span subject) {
  wired_span seq;
  if (!x509_nc_locate(cert_tbs, &seq)) return 1;
  if (x509_nc_too_many(seq)) return 0;
  return x509_typed_name_ok(
      seq, NC_DIRECTORYNAME_TAG, subject, x509_dn_within_base);
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
  if (!x509_nc_half(seq, half, &subtrees)) return 0;
  return typed_scan(subtrees, want, subtrees, m, &any);
}

/* An iPAddress base of malformed length in either half makes the whole
 * extension unusable: fail closed regardless of the child's names. */
int x509_ip_bases_malformed(wired_span seq) {
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
int x509_san_other_entry_ok(wired_span seq, u8 tag, wired_span e) {
  if (tag == NC_IPADDR_TAG)
    return x509_typed_name_ok(seq, tag, e, x509_nc_ip_within);
  if (tag == NC_URI_TAG) return uri_san_ok(seq);
  return 1;
}
