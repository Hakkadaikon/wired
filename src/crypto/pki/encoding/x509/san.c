#include "crypto/pki/encoding/x509/san.h"

#include "common/bytes/util/bytes.h"
#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/asn1/derval.h"
#include "crypto/pki/encoding/x509/x509.h"

/* RFC 5280 4.2.1.6. GeneralName dNSName is [2] IMPLICIT IA5String. */
#define SAN_DNSNAME_TAG 0x82

/* id-ce-subjectAltName = 2.5.29.17 */
static const u8 oid_san[] = {0x55, 0x1d, 0x11};

/* RFC 5280 A.1. id-at-commonName = 2.5.4.3. */
static const u8 san_oid_cn[] = {0x55, 0x04, 0x03};

/* RFC 5280 4.1. tbs elements before subject (version already skipped by
 * quic_x509_tbs_cursor): serialNumber, signature, issuer, validity. */
#define SAN_SUBJECT_SKIP 4

/* RFC 6125 6.4.1: hostname comparison is ASCII case-insensitive. */
static int dns_eq(wired_span a, wired_span b) {
  return quic_ascii_dns_eq(a, b);
}

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

/* RFC 5280 4.2.1.6. The GeneralNames SEQUENCE value inside the extnValue. */
static int san_names(wired_span tbs, wired_span* names) {
  wired_span san;
  if (!quic_x509_find_ext(tbs, wired_span_of(oid_san, sizeof(oid_san)), &san))
    return 0;
  return quic_der_seq(san, names);
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
  quic_derseq names;
  u8          tag;
  wired_span  e;
  int         match = 0;
  quic_derseq_init(&names, gn);
  while (quic_derseq_next(&names, &tag, &e))
    names_match_one(tag, e, host, found_dnsname, &match);
  return match;
}

/* RFC 5280 4.1.2.4. One AttributeTypeAndValue's value, if its type is
 * id-at-commonName. */
static int atv_cn_value(wired_span atv, wired_span* val) {
  quic_derseq f;
  u8          tag;
  wired_span  id;
  quic_derseq_init(&f, atv);
  if (!quic_derseq_next_tagged(&f, QUIC_DER_OID, &id)) return 0;
  if (!quic_der_oid_equal(id, wired_span_of(san_oid_cn, sizeof(san_oid_cn))))
    return 0;
  return quic_derseq_next(&f, &tag, val);
}

/* RFC 5280 4.1.2.4. One RelativeDistinguishedName (a SET of ATVs): the first
 * commonName value found in it, if any. */
static int rdn_cn_value(wired_span rdn, wired_span* val) {
  quic_derseq f;
  u8          tag;
  wired_span  atv;
  quic_derseq_init(&f, rdn);
  while (quic_derseq_next(&f, &tag, &atv))
    if (atv_cn_value(atv, val)) return 1;
  return 0;
}

/* RFC 5280 4.1.2.4. Name SEQUENCE OF RDN: the first commonName value found
 * across every RDN, if any. */
static int name_cn_value(wired_span name_seq, wired_span* val) {
  quic_derseq f;
  u8          tag;
  wired_span  rdn;
  quic_derseq_init(&f, name_seq);
  while (quic_derseq_next(&f, &tag, &rdn))
    if (rdn_cn_value(rdn, val)) return 1;
  return 0;
}

/* RFC 5280 4.1: a tbs cursor positioned right before the subject Name
 * element (past version, serialNumber, signature, issuer, validity). */
static int subject_cursor(wired_span tbs, quic_derseq* c) {
  if (!quic_x509_tbs_cursor(tbs, c)) return 0;
  return quic_derseq_skip(c, SAN_SUBJECT_SKIP);
}

/* RFC 5280 4.1: locate and read the subject Name's commonName value out of
 * tbs. Returns 1 and sets *val on success, 0 if the certificate carries no
 * commonName. */
static int subject_cn(wired_span tbs, wired_span* val) {
  quic_derseq c;
  wired_span  subject;
  if (!subject_cursor(tbs, &c)) return 0;
  if (!quic_derseq_next_tagged(&c, QUIC_DER_SEQUENCE, &subject)) return 0;
  return name_cn_value(subject, val);
}

/* RFC 6125 6.4.4: the CN-ID fallback -- only reached when the certificate has
 * no dNSName SAN entry at all. */
static int cn_id_matches(wired_span tbs, wired_span host) {
  wired_span cn;
  if (!subject_cn(tbs, &cn)) return 0;
  return entry_matches(cn, host);
}

int quic_x509_san_matches(wired_span tbs, wired_span hostname) {
  wired_span gn;
  int        found_dnsname = 0;
  int        match         = 0;
  if (san_names(tbs, &gn)) match = names_match(gn, hostname, &found_dnsname);
  return found_dnsname ? match : cn_id_matches(tbs, hostname);
}
