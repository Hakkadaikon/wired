#include "crypto/pki/encoding/x509/san.h"

#include "common/bytes/util/bytes.h"
#include "common/bytes/util/ct.h"
#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/asn1/derval.h"
#include "crypto/pki/encoding/x509/x509.h"

/* RFC 5280 4.2.1.6. GeneralName dNSName is [2] IMPLICIT IA5String. */
#define SAN_DNSNAME_TAG 0x82

/* RFC 5280 4.2.1.6. GeneralName iPAddress is [7] IMPLICIT OCTET STRING. */
#define SAN_IPADDR_TAG 0x87

/* An IPv4 address in its 4-octet form. */
#define SAN_IPV4_LEN 4

/* id-ce-subjectAltName = 2.5.29.17 */
static const u8 oid_san[] = {0x55, 0x1d, 0x11};

/* RFC 5280 A.1. id-at-commonName = 2.5.4.3. */
static const u8 san_oid_cn[] = {0x55, 0x04, 0x03};

/* RFC 5280 4.1. tbs elements before subject (version already skipped by
 * x509_tbs_cursor): serialNumber, signature, issuer, validity. */
#define SAN_SUBJECT_SKIP 4

/* RFC 6125 6.4.1: hostname comparison is ASCII case-insensitive. */
static int dns_eq(wired_span a, wired_span b) { return ascii_dns_eq(a, b); }

/* Offset of the first '.' in name, or its length if none. */
static usz first_dot(wired_span name) {
  usz i = 0;
  while (i < name.n && name.p[i] != '.') i++;
  return i;
}

/* Offset of '*' within the left-most label of entry, or entry.n's first-dot
 * offset if the label carries none. */
static usz wildcard_star(wired_span label) {
  usz i = 0;
  while (i < label.n && label.p[i] != '*') i++;
  return i;
}

/* RFC 6125 6.4.3 rule 2 (MAY): the left-most label matches host's left-most
 * label when it is prefix + '*' + suffix, i.e. host's label starts with
 * prefix, ends with suffix, and is at least as long as prefix+suffix
 * combined (the '*' may cover zero or more characters). */
static int label_wildcard_match(wired_span label, wired_span hlabel, usz star) {
  wired_span prefix = wired_span_of(label.p, star);
  wired_span suffix = wired_span_of(label.p + star + 1, label.n - star - 1);
  if (hlabel.n < prefix.n + suffix.n) return 0;
  return dns_eq(prefix, wired_span_of(hlabel.p, prefix.n)) &&
         dns_eq(
             suffix, wired_span_of(hlabel.p + hlabel.n - suffix.n, suffix.n));
}

/* RFC 6125 6.4.3. entry's left-most label contains a '*' (rule 2's fragment
 * wildcard covers the plain "*." case too, star at offset 0). */
static int is_wildcard(wired_span entry) {
  usz ldot = first_dot(entry);
  return ldot < entry.n && wildcard_star(wired_span_of(entry.p, ldot)) < ldot;
}

/* entry carries a fragment wildcard and host actually has a label to match
 * it against (a bare hostname with no '.' has no remainder to compare). */
static int wildcard_applicable(wired_span entry, usz hdot, usz host_n) {
  return is_wildcard(entry) && hdot < host_n;
}

/* RFC 6125 6.4.3. entry's left-most label, possibly containing one '*'
 * fragment wildcard, matches host's left-most label and the remainders
 * (from the first '.' on) are equal. */
static int wildcard_match(wired_span entry, wired_span host) {
  usz edot = first_dot(entry);
  usz hdot = first_dot(host);
  usz star = wildcard_star(wired_span_of(entry.p, edot));
  if (!wildcard_applicable(entry, hdot, host.n)) return 0;
  if (!label_wildcard_match(
          wired_span_of(entry.p, edot), wired_span_of(host.p, hdot), star))
    return 0;
  return dns_eq(
      wired_span_of(entry.p + edot, entry.n - edot),
      wired_span_of(host.p + hdot, host.n - hdot));
}

/* One GeneralName dNSName entry matches the hostname. */
static int entry_matches(wired_span e, wired_span host) {
  return dns_eq(e, host) || wildcard_match(e, host);
}

/* d.n is a valid octet digit-run length: 1 to 3 octets. */
static int octet_len_ok(wired_span d) { return d.n >= 1 && d.n <= 3; }

/* d has no leading '0' unless d is the single digit "0". */
static int no_leading_zero(wired_span d) { return d.n == 1 || d.p[0] != '0'; }

/* d.n in [1,3], and no leading '0' unless d is the single digit "0". */
static int octet_digits_shape_ok(wired_span d) {
  if (!octet_len_ok(d)) return 0;
  return no_leading_zero(d);
}

/* One ASCII decimal digit's value, or -1 if c is not a digit. */
static int digit_value(u8 c) { return (c >= '0' && c <= '9') ? c - '0' : -1; }

/* Decimal value of d's digits, requiring every octet to be a digit.
 * Returns 1 ok, 0 on a non-digit. */
static int digits_value(wired_span d, u32* out) {
  u32 v = 0;
  for (usz i = 0; i < d.n; i++) {
    int dv = digit_value(d.p[i]);
    if (dv < 0) return 0;
    v = v * 10 + (u32)dv;
  }
  *out = v;
  return 1;
}

/* Decimal value of one octet's digits (span.n in [1,3]), rejecting a leading
 * '0' on any but a single "0" digit, and any non-digit. Returns 1 ok. */
static int octet_digits_value(wired_span d, u32* out) {
  if (!octet_digits_shape_ok(d)) return 0;
  return digits_value(d, out);
}

/* Offset of the next '.' in s starting at from, or s.n if none. */
static usz next_dot(wired_span s, usz from) {
  usz i = from;
  while (i < s.n && s.p[i] != '.') i++;
  return i;
}

/* Offset just past the separating '.' at s[end] if one is there, else end. */
static usz skip_dot(wired_span s, usz end) {
  if (end < s.n) return end + 1;
  return end;
}

/* One dot-separated IPv4 octet starting at *off, ending at a '.' or the
 * span's end. Advances *off past the value and its separating '.' (if any).
 * Returns 1 ok, 0 if the digits are malformed or out of range. */
static int ipv4_octet(wired_span s, usz* off, u8* out) {
  usz start = *off;
  usz end   = next_dot(s, start);
  u32 v;
  if (!octet_digits_value(wired_span_of(s.p + start, end - start), &v))
    return 0;
  if (v > 255) return 0;
  *off = skip_dot(s, end);
  *out = (u8)v;
  return 1;
}

/* RFC 791 3.1-shaped dotted-decimal text -> 4 octets. Rejects a leading zero
 * on any octet wider than one digit, out-of-range octets, and anything not
 * exactly 4 dot-separated octets (a DNS name or an IPv6 literal included). */
static int san_ipv4_parse(wired_span host, u8 out[SAN_IPV4_LEN]) {
  usz off = 0;
  for (usz i = 0; i < SAN_IPV4_LEN; i++)
    if (!ipv4_octet(host, &off, &out[i])) return 0;
  return off == host.n;
}

/* One GeneralName iPAddress entry (raw 4-octet value) matches the parsed
 * IPv4 hostname. */
static int ipv4_entry_matches(wired_span e, const u8 want[SAN_IPV4_LEN]) {
  return e.n == SAN_IPV4_LEN && ct_diffn(e.p, want, SAN_IPV4_LEN) == 0;
}

/* RFC 5280 4.2.1.6. The GeneralNames SEQUENCE value inside the extnValue. */
static int san_names(wired_span tbs, wired_span* names) {
  wired_span san;
  if (!x509_find_ext(tbs, wired_span_of(oid_san, sizeof(oid_san)), &san))
    return 0;
  return der_seq(san, names);
}

/* One GeneralNames element: if it is a dNSName, records that (*found_dnsname
 * = 1) and folds its match outcome into *match. */
static void names_match_one(
    u8 tag, wired_span e, wired_span host, int* found_dnsname, int* match) {
  if (tag != SAN_DNSNAME_TAG) return;
  *found_dnsname = 1;
  if (entry_matches(e, host)) *match = 1;
}

/* RFC 5280 4.2.1.6 / RFC 6125 6.4.4: scan the GeneralNames. found_dnsname is
 * set to 1 if any dNSName entry is present at all (regardless of match) --
 * that alone rules out the RFC 6125 6.4.4 CN-ID fallback, matched entries or
 * not. Returns 1 on a matching dNSName. */
static int names_match(wired_span gn, wired_span host, int* found_dnsname) {
  derseq     names;
  u8         tag;
  wired_span e;
  int        match = 0;
  derseq_init(&names, gn);
  while (derseq_next(&names, &tag, &e))
    names_match_one(tag, e, host, found_dnsname, &match);
  return match;
}

/* One GeneralNames element is an iPAddress entry matching want. */
static int ipv4_names_one(u8 tag, wired_span e, const u8 want[SAN_IPV4_LEN]) {
  return tag == SAN_IPADDR_TAG && ipv4_entry_matches(e, want);
}

/* RFC 5280 4.2.1.6: scan the GeneralNames for iPAddress entries only. Never
 * considers dNSName entries -- an IPv4-literal hostname is matched solely
 * against iPAddress SAN entries, with no fallback to a dNSName entry. */
static int ipv4_names_match(wired_span gn, const u8 want[SAN_IPV4_LEN]) {
  derseq     names;
  u8         tag;
  wired_span e;
  derseq_init(&names, gn);
  while (derseq_next(&names, &tag, &e))
    if (ipv4_names_one(tag, e, want)) return 1;
  return 0;
}

/* RFC 5280 4.1.2.4. One AttributeTypeAndValue's value, if its type is
 * id-at-commonName. */
static int atv_cn_value(wired_span atv, wired_span* val) {
  derseq     f;
  u8         tag;
  wired_span id;
  derseq_init(&f, atv);
  if (!derseq_next_tagged(&f, DER_OID, &id)) return 0;
  if (!der_oid_equal(id, wired_span_of(san_oid_cn, sizeof(san_oid_cn))))
    return 0;
  return derseq_next(&f, &tag, val);
}

/* RFC 5280 4.1.2.4. One RelativeDistinguishedName (a SET of ATVs): the first
 * commonName value found in it, if any. */
static int rdn_cn_value(wired_span rdn, wired_span* val) {
  derseq     f;
  u8         tag;
  wired_span atv;
  derseq_init(&f, rdn);
  while (derseq_next(&f, &tag, &atv))
    if (atv_cn_value(atv, val)) return 1;
  return 0;
}

/* RFC 5280 4.1.2.4. Name SEQUENCE OF RDN: the first commonName value found
 * across every RDN, if any. */
static int name_cn_value(wired_span name_seq, wired_span* val) {
  derseq     f;
  u8         tag;
  wired_span rdn;
  derseq_init(&f, name_seq);
  while (derseq_next(&f, &tag, &rdn))
    if (rdn_cn_value(rdn, val)) return 1;
  return 0;
}

/* RFC 5280 4.1: a tbs cursor positioned right before the subject Name
 * element (past version, serialNumber, signature, issuer, validity). */
static int subject_cursor(wired_span tbs, derseq* c) {
  if (!x509_tbs_cursor(tbs, c)) return 0;
  return derseq_skip(c, SAN_SUBJECT_SKIP);
}

int x509_subject_cn(wired_span tbs, wired_span* val) {
  derseq     c;
  wired_span subject;
  if (!subject_cursor(tbs, &c)) return 0;
  if (!derseq_next_tagged(&c, DER_SEQUENCE, &subject)) return 0;
  return name_cn_value(subject, val);
}

/* RFC 6125 6.4.4: the CN-ID fallback -- only reached when the certificate has
 * no dNSName SAN entry at all. */
static int cn_id_matches(wired_span tbs, wired_span host) {
  wired_span cn;
  if (!x509_subject_cn(tbs, &cn)) return 0;
  return entry_matches(cn, host);
}

/* RFC 5280 4.2.1.6: an IPv4-literal hostname is matched against a
 * certificate's iPAddress SAN entries only. When the certificate carries a
 * SAN extension at all (dNSName-only or otherwise), a missing/non-matching
 * iPAddress entry is a hard mismatch -- there is no dNSName fallback. When
 * the certificate carries no SAN extension at all, RFC 6125 6.4.4's CN-ID
 * fallback still applies (matched as a literal string). */
static int ipv4_san_matches(
    wired_span tbs, wired_span hostname, const u8 want[SAN_IPV4_LEN]) {
  wired_span gn;
  if (!san_names(tbs, &gn)) return cn_id_matches(tbs, hostname);
  return ipv4_names_match(gn, want);
}

/* RFC 5280 4.2.1.6: dNSName-based matching, with the RFC 6125 6.4.4 CN-ID
 * fallback when the certificate has no dNSName SAN entry at all. */
static int dns_san_matches(wired_span tbs, wired_span hostname) {
  wired_span gn;
  int        found_dnsname = 0;
  int        match         = 0;
  if (san_names(tbs, &gn)) match = names_match(gn, hostname, &found_dnsname);
  return found_dnsname ? match : cn_id_matches(tbs, hostname);
}

int x509_san_matches(wired_span tbs, wired_span hostname) {
  u8 ipv4[SAN_IPV4_LEN];
  if (san_ipv4_parse(hostname, ipv4))
    return ipv4_san_matches(tbs, hostname, ipv4);
  return dns_san_matches(tbs, hostname);
}
