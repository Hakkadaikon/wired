#include "crypto/pki/encoding/x509/san_impl.h"

static int ipv4_names_match(wired_span gn, const u8 want[SAN_IPV4_LEN]);
static int atv_cn_value(wired_span atv, wired_span* val);
static int rdn_cn_value(wired_span rdn, wired_span* val);
static int name_cn_value(wired_span name_seq, wired_span* val);
static int subject_cursor(wired_span tbs, derseq* c);
static int cn_id_matches(wired_span tbs, wired_span host);
static int ipv4_san_matches(
    wired_span tbs, wired_span hostname, const u8 want[SAN_IPV4_LEN]);
static int dns_san_matches(wired_span tbs, wired_span hostname);

/* RFC 5280 4.2.1.6: scan the GeneralNames for iPAddress entries only. Never
 * considers dNSName entries -- an IPv4-literal hostname is matched solely
 * against iPAddress SAN entries, with no fallback to a dNSName entry. */
static int ipv4_names_match(wired_span gn, const u8 want[SAN_IPV4_LEN]) {
  derseq     names;
  u8         tag;
  wired_span e;
  derseq_init(&names, gn);
  while (derseq_next(&names, &tag, &e)) {
    if (x509_ipv4_names_one(tag, e, want)) {
      return 1;
    }
  }
  return 0;
}

/* RFC 5280 4.1.2.4. One AttributeTypeAndValue's value, if its type is
 * id-at-commonName. */
static int atv_cn_value(wired_span atv, wired_span* val) {
  derseq     f;
  u8         tag;
  wired_span id;
  derseq_init(&f, atv);
  if (!derseq_next_tagged(&f, DER_OID, &id)) {
    return 0;
  }
  if (!der_oid_equal(id, wired_span_of(san_oid_cn, sizeof(san_oid_cn)))) {
    return 0;
  }
  return derseq_next(&f, &tag, val);
}

/* RFC 5280 4.1.2.4. One RelativeDistinguishedName (a SET of ATVs): the first
 * commonName value found in it, if any. */
static int rdn_cn_value(wired_span rdn, wired_span* val) {
  derseq     f;
  u8         tag;
  wired_span atv;
  derseq_init(&f, rdn);
  while (derseq_next(&f, &tag, &atv)) {
    if (atv_cn_value(atv, val)) {
      return 1;
    }
  }
  return 0;
}

/* RFC 5280 4.1.2.4. Name SEQUENCE OF RDN: the first commonName value found
 * across every RDN, if any. */
static int name_cn_value(wired_span name_seq, wired_span* val) {
  derseq     f;
  u8         tag;
  wired_span rdn;
  derseq_init(&f, name_seq);
  while (derseq_next(&f, &tag, &rdn)) {
    if (rdn_cn_value(rdn, val)) {
      return 1;
    }
  }
  return 0;
}

/* RFC 5280 4.1: a tbs cursor positioned right before the subject Name
 * element (past version, serialNumber, signature, issuer, validity). */
static int subject_cursor(wired_span tbs, derseq* c) {
  if (!x509_tbs_cursor(tbs, c)) {
    return 0;
  }
  return derseq_skip(c, SAN_SUBJECT_SKIP);
}

int x509_subject_cn(wired_span tbs, wired_span* val) {
  derseq     c;
  wired_span subject;
  if (!subject_cursor(tbs, &c)) {
    return 0;
  }
  if (!derseq_next_tagged(&c, DER_SEQUENCE, &subject)) {
    return 0;
  }
  return name_cn_value(subject, val);
}

/* RFC 6125 6.4.4: the CN-ID fallback -- only reached when the certificate has
 * no dNSName SAN entry at all. */
static int cn_id_matches(wired_span tbs, wired_span host) {
  wired_span cn;
  if (!x509_subject_cn(tbs, &cn)) {
    return 0;
  }
  return x509_entry_matches(cn, host);
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
  if (!san_names(tbs, &gn)) {
    return cn_id_matches(tbs, hostname);
  }
  return ipv4_names_match(gn, want);
}

/* RFC 5280 4.2.1.6: dNSName-based matching, with the RFC 6125 6.4.4 CN-ID
 * fallback when the certificate has no dNSName SAN entry at all. */
static int dns_san_matches(wired_span tbs, wired_span hostname) {
  wired_span gn;
  int        found_dnsname = 0;
  int        match         = 0;
  if (san_names(tbs, &gn)) {
    match = x509_names_match(gn, hostname, &found_dnsname);
  }
  return found_dnsname ? match : cn_id_matches(tbs, hostname);
}

int x509_san_matches(wired_span tbs, wired_span hostname) {
  u8 ipv4[SAN_IPV4_LEN];
  if (san_ipv4_parse(hostname, ipv4)) {
    return ipv4_san_matches(tbs, hostname, ipv4);
  }
  return dns_san_matches(tbs, hostname);
}
