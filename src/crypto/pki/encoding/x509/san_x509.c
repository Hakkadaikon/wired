#include "crypto/pki/encoding/x509/san_impl.h"

static int ip_names_match(wired_span gn, wired_span want);
static int atv_cn_value(wired_span atv, wired_span* val);
static int rdn_cn_value(wired_span rdn, wired_span* val);
static int name_cn_value(wired_span name_seq, wired_span* val);
static int subject_cursor(wired_span tbs, derseq* c);
static int cn_id_matches(wired_span tbs, wired_span host);
static int ip_san_matches(wired_span tbs, wired_span want);
static int ipv6_san_matches(wired_span tbs, wired_span hostname);
static int dns_san_matches(wired_span tbs, wired_span hostname);

/* RFC 5280 4.2.1.6: scan the GeneralNames for iPAddress entries only. Never
 * considers dNSName entries -- an IP-literal hostname is matched solely
 * against iPAddress SAN entries, with no fallback to a dNSName entry. */
static int ip_names_match(wired_span gn, wired_span want) {
  derseq     names;
  u8         tag;
  wired_span e;
  derseq_init(&names, gn);
  while (derseq_next(&names, &tag, &e)) {
    if (x509_ip_names_one(tag, e, want)) {
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

/* RFC 6125 6.4.4: the CN-ID fallback -- only reached when the certificate
 * presents no DNS-ID, URI-ID or SRV-ID. */
static int cn_id_matches(wired_span tbs, wired_span host) {
  wired_span cn;
  if (!x509_subject_cn(tbs, &cn)) {
    return 0;
  }
  return x509_entry_matches(cn, host);
}

/* RFC 5280 4.2.1.6 / RFC 9525 6.3 / RFC 2818 3.1: an IP-literal hostname
 * is matched against a certificate's iPAddress SAN entries only -- no
 * dNSName fallback, and no CN-ID fallback either (RFC 6125 6.4.4 applies
 * it to DNS names only), so a certificate without a SAN never matches. */
static int ip_san_matches(wired_span tbs, wired_span want) {
  wired_span gn;
  return san_names(tbs, &gn) && ip_names_match(gn, want);
}

/* RFC 5280 4.2.1.6: dNSName-based matching, with the RFC 6125 6.4.4 CN-ID
 * fallback only when the SAN presents no DNS-ID, URI-ID or SRV-ID. */
static int dns_san_matches(wired_span tbs, wired_span hostname) {
  wired_span gn;
  int        found_id = 0;
  int        match    = 0;
  if (san_names(tbs, &gn)) {
    match = x509_names_match(gn, hostname, &found_id);
  }
  return found_id ? match : cn_id_matches(tbs, hostname);
}

/* RFC 9525 6.3: a reference identity holding a ':' is an IPv6 address (no
 * DNS name has one), compared with 16-octet iPAddress entries only; one
 * that does not parse (an RFC 6874 zone ID included) matches nothing. */
static int ipv6_san_matches(wired_span tbs, wired_span hostname) {
  u8 ip[SAN_IPV6_LEN];
  return san_ipv6_parse(hostname, ip) &&
         ip_san_matches(tbs, wired_span_of(ip, SAN_IPV6_LEN));
}

int x509_san_matches(wired_span tbs, wired_span hostname) {
  u8 ipv4[SAN_IPV4_LEN];
  if (san_ipv4_parse(hostname, ipv4)) {
    return ip_san_matches(tbs, wired_span_of(ipv4, SAN_IPV4_LEN));
  }
  if (san_ipv6_shaped(hostname)) {
    return ipv6_san_matches(tbs, hostname);
  }
  return dns_san_matches(tbs, hostname);
}
