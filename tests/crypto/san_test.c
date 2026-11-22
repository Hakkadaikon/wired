#include "crypto/pki/encoding/x509/san.h"

#include "chain_golden.h"
#include "common/bytes/util/bytes.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "san_id_golden.h"
#include "test.h"

/* Parse a golden cert and match host (a string literal span) against it. */
static int san_match(const u8* der, usz der_len, const u8* host, usz hlen) {
  x509 c;
  CHECK(x509_parse(wired_span_of(der, der_len), &c) == 1);
  return x509_san_matches(c.tbs, wired_span_of(host, hlen));
}

/* cert1 SAN lists example.com and *.example.com. */
static void test_exact_match(void) {
  const u8 host[] = "example.com";
  CHECK(
      san_match(chain_golden1, sizeof(chain_golden1), host, sizeof(host) - 1) ==
      1);
}

/* *.example.com covers one label below example.com. */
static void test_wildcard_match(void) {
  const u8 host[] = "www.example.com";
  CHECK(
      san_match(chain_golden1, sizeof(chain_golden1), host, sizeof(host) - 1) ==
      1);
}

/* The wildcard matches a single label only, not nested subdomains. */
static void test_wildcard_no_nested(void) {
  const u8 host[] = "a.b.example.com";
  CHECK(
      san_match(chain_golden1, sizeof(chain_golden1), host, sizeof(host) - 1) ==
      0);
}

/* An unrelated hostname matches neither entry. */
static void test_no_match(void) {
  const u8 host[] = "example.org";
  CHECK(
      san_match(chain_golden1, sizeof(chain_golden1), host, sizeof(host) - 1) ==
      0);
}

/* RFC 6125 6.4.4: a cert without a SAN extension falls back to CN-ID, so a
 * name unrelated to golden2's CN (other.example) still matches nothing. */
static void test_no_san(void) {
  const u8 host[] = "unrelated.example";
  CHECK(
      san_match(chain_golden2, sizeof(chain_golden2), host, sizeof(host) - 1) ==
      0);
}

/* RFC 6125 6.4.1: comparison is ASCII case-insensitive — an upper/mixed-case
 * hostname matches the lowercase SAN, exactly and through the wildcard. */
static void test_san_case_fold(void) {
  const u8 upper[] = "EXAMPLE.com";
  const u8 mixed[] = "WwW.Example.COM";
  CHECK(
      san_match(
          chain_golden1, sizeof(chain_golden1), upper, sizeof(upper) - 1) == 1);
  CHECK(
      san_match(
          chain_golden1, sizeof(chain_golden1), mixed, sizeof(mixed) - 1) == 1);
}

/* RFC 6125 6.4.4: cert2 has no SAN at all, so its CN (other.example) is the
 * fallback identifier. */
static void test_san_cn_id_fallback(void) {
  const u8 host[] = "other.example";
  CHECK(
      san_match(chain_golden2, sizeof(chain_golden2), host, sizeof(host) - 1) ==
      1);
}

/* RFC 6125 6.4.4: cert1 HAS a SAN (with dNSName entries), so its CN
 * (example.com, which is also a SAN entry) must not be reached via the
 * fallback for a name the SAN does not cover -- cert1's CN itself is
 * "example.com", already proven by test_exact_match to match through SAN;
 * this checks a name that is neither a SAN entry nor (were fallback wrongly
 * allowed) anything CN-related is still rejected. */
static void test_san_present_suppresses_cn_fallback(void) {
  const u8 host[] = "other.example";
  CHECK(
      san_match(chain_golden1, sizeof(chain_golden1), host, sizeof(host) - 1) ==
      0);
}

/* Minimal synthetic tbsCertificate: 6 filler NULL TLVs (serialNumber,
 * signature, issuer, validity, subject, spki -- san.c never inspects their
 * content) followed by a [3] extensions block holding one subjectAltName
 * dNSName "baz*.example.net" (RFC 6125 6.4.3 rule 2 fragment wildcard). */
static const u8 san_fragment_tbs[] = {
    0x30, 0x2d, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
    0x05, 0x00, 0xa3, 0x1f, 0x30, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x1d,
    0x11, 0x04, 0x14, 0x30, 0x12, 0x82, 0x10, 0x62, 0x61, 0x7a, 0x2a, 0x2e,
    0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x6e, 0x65, 0x74,
};

/* RFC 6125 6.4.3 rule 2 (MAY): "baz*.example.net" covers any left-most label
 * starting with "baz", including the degenerate empty-middle case. */
static void test_san_fragment_wildcard_match(void) {
  const u8 host1[] = "baz1.example.net";
  const u8 host2[] = "baz.example.net";
  CHECK(
      x509_san_matches(
          wired_span_of(san_fragment_tbs, sizeof(san_fragment_tbs)),
          wired_span_of(host1, sizeof(host1) - 1)) == 1);
  CHECK(
      x509_san_matches(
          wired_span_of(san_fragment_tbs, sizeof(san_fragment_tbs)),
          wired_span_of(host2, sizeof(host2) - 1)) == 1);
}

/* The fragment wildcard's fixed prefix "baz" must still match literally. */
static void test_san_fragment_wildcard_no_match(void) {
  const u8 host[] = "bar1.example.net";
  CHECK(
      x509_san_matches(
          wired_span_of(san_fragment_tbs, sizeof(san_fragment_tbs)),
          wired_span_of(host, sizeof(host) - 1)) == 0);
}

/* Minimal synthetic tbsCertificate: 6 filler NULL TLVs followed by a [3]
 * extensions block holding one subjectAltName iPAddress 127.0.0.1 (RFC 5280
 * 4.2.1.6: GeneralName iPAddress is [7] IMPLICIT OCTET STRING). */
static const u8 san_ipv4_single_tbs[] = {
    0x30, 0x21, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
    0x05, 0x00, 0xa3, 0x13, 0x30, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d,
    0x11, 0x04, 0x08, 0x30, 0x06, 0x87, 0x04, 0x7f, 0x00, 0x00, 0x01,
};

/* Same shape, two iPAddress SAN entries: 192.168.1.1 and 10.0.0.1. */
static const u8 san_ipv4_multi_tbs[] = {
    0x30, 0x27, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05,
    0x00, 0x05, 0x00, 0xa3, 0x19, 0x30, 0x17, 0x30, 0x15, 0x06, 0x03,
    0x55, 0x1d, 0x11, 0x04, 0x0e, 0x30, 0x0c, 0x87, 0x04, 0xc0, 0xa8,
    0x01, 0x01, 0x87, 0x04, 0x0a, 0x00, 0x00, 0x01,
};

/* Same shape, one dNSName SAN "example.com" and no iPAddress entry at all. */
static const u8 san_dnsname_only_tbs[] = {
    0x30, 0x28, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05,
    0x00, 0x05, 0x00, 0xa3, 0x1a, 0x30, 0x18, 0x30, 0x16, 0x06, 0x03,
    0x55, 0x1d, 0x11, 0x04, 0x0f, 0x30, 0x0d, 0x82, 0x0b, 0x65, 0x78,
    0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
};

/* Minimal synthetic tbsCertificate carrying NO extensions block at all: 4
 * filler NULL TLVs (serialNumber, signature, issuer, validity) followed by
 * a subject Name with a single commonName RDN "127.0.0.1". */
static const u8 san_cn_only_ipv4_tbs[] = {
    0x30, 0x1e, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x30,
    0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
    0x09, 0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31,
};

static int san_match_tbs(const u8* tbs, usz tbs_len, const u8* host, usz hlen) {
  return x509_san_matches(
      wired_span_of(tbs, tbs_len), wired_span_of(host, hlen));
}

/* An IPv4-literal hostname matches a certificate's matching iPAddress SAN. */
static void test_san_ipv4_match(void) {
  const u8 host[] = "127.0.0.1";
  CHECK(
      san_match_tbs(
          san_ipv4_single_tbs, sizeof(san_ipv4_single_tbs), host,
          sizeof(host) - 1) == 1);
}

/* An IPv4-literal hostname that differs from the cert's iPAddress SAN. */
static void test_san_ipv4_mismatch(void) {
  const u8 host[] = "127.0.0.2";
  CHECK(
      san_match_tbs(
          san_ipv4_single_tbs, sizeof(san_ipv4_single_tbs), host,
          sizeof(host) - 1) == 0);
}

/* An IPv4-literal hostname must not fall back to a dNSName SAN entry: no
 * iPAddress entry at all is a mismatch even though a dNSName is present. */
static void test_san_ipv4_no_dnsname_fallback(void) {
  const u8 host[] = "127.0.0.1";
  CHECK(
      san_match_tbs(
          san_dnsname_only_tbs, sizeof(san_dnsname_only_tbs), host,
          sizeof(host) - 1) == 0);
}

/* Multiple iPAddress SAN entries: a match on any one of them is enough. */
static void test_san_ipv4_multi_match(void) {
  const u8 host[] = "10.0.0.1";
  CHECK(
      san_match_tbs(
          san_ipv4_multi_tbs, sizeof(san_ipv4_multi_tbs), host,
          sizeof(host) - 1) == 1);
}

/* An unrelated IPv4 literal against multiple iPAddress SAN entries. */
static void test_san_ipv4_multi_no_match(void) {
  const u8 host[] = "10.0.0.2";
  CHECK(
      san_match_tbs(
          san_ipv4_multi_tbs, sizeof(san_ipv4_multi_tbs), host,
          sizeof(host) - 1) == 0);
}

/* An IPv6-literal hostname is not parsed as IPv4 and falls through to a
 * mismatch, never reaching the dNSName logic. */
static void test_san_ipv6_hostname_mismatch(void) {
  const u8 host[] = "::1";
  CHECK(
      san_match_tbs(
          san_ipv4_single_tbs, sizeof(san_ipv4_single_tbs), host,
          sizeof(host) - 1) == 0);
  CHECK(
      san_match_tbs(
          san_dnsname_only_tbs, sizeof(san_dnsname_only_tbs), host,
          sizeof(host) - 1) == 0);
}

/* RFC 6125 6.4.4 / RFC 9525 6.3: the CN-ID fallback is for DNS names
 * only. An IPv4-literal hostname needs an iPAddress SAN, so a SAN-less
 * certificate whose CN spells the same literal does not match. */
static void test_san_ipv4_no_cn_id_fallback(void) {
  const u8 host[] = "127.0.0.1";
  CHECK(
      san_match_tbs(
          san_cn_only_ipv4_tbs, sizeof(san_cn_only_ipv4_tbs), host,
          sizeof(host) - 1) == 0);
}

/* RFC 6125 6.4.4: a URI-ID or SRV-ID among the presented identifiers rules
 * out the CN-ID fallback even with no DNS-ID, so CN=host.example no longer
 * matches; an rfc822Name (not a server identifier type) leaves the fallback
 * in place. */
static void test_san_uri_srv_suppress_cn_fallback(void) {
  const u8 host[] = "host.example";
  CHECK(
      san_match(
          sanid_iduri_der, sizeof(sanid_iduri_der), host, sizeof(host) - 1) ==
      0);
  CHECK(
      san_match(
          sanid_idsrv_der, sizeof(sanid_idsrv_der), host, sizeof(host) - 1) ==
      0);
  CHECK(
      san_match(
          sanid_idmail_der, sizeof(sanid_idmail_der), host, sizeof(host) - 1) ==
      1);
}

/* RFC 6125 6.4.3 rule 3: a '*' inside an IDN A-label (xn--ab*, in either
 * case of the xn-- prefix) is not treated as a wildcard. */
static void test_san_alabel_wildcard_no_match(void) {
  const u8 h1[] = "xn--abc.example.net";
  const u8 h2[] = "xn--cde.example.net";
  CHECK(
      san_match(sanid_idxn_der, sizeof(sanid_idxn_der), h1, sizeof(h1) - 1) ==
      0);
  CHECK(
      san_match(sanid_idxn_der, sizeof(sanid_idxn_der), h2, sizeof(h2) - 1) ==
      0);
}

/* RFC 6125 6.4.3 rule 2: "baz*" needs a host label at least as long as its
 * fixed "baz" prefix, so "ba" is not covered. */
static void test_san_fragment_wildcard_label_too_short(void) {
  const u8 host[] = "ba.example.net";
  CHECK(
      san_match_tbs(
          san_fragment_tbs, sizeof(san_fragment_tbs), host, sizeof(host) - 1) ==
      0);
}

/* RFC 3986 3.2.2 IPv4address: a dec-octet above 255 is not an IPv4 literal,
 * so it never matches the 127.0.0.1 iPAddress SAN. */
static void test_san_ipv4_octet_over_255(void) {
  const u8 host[] = "256.0.0.1";
  CHECK(
      san_match_tbs(
          san_ipv4_single_tbs, sizeof(san_ipv4_single_tbs), host,
          sizeof(host) - 1) == 0);
}

/* serialNumber, signature, issuer, validity stand-ins (SAN_SUBJECT_SKIP). */
#define SANT_DUMMY4 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00

/* RFC 5280 4.1.2.6: no subject commonName is read from a tbs that is not a
 * SEQUENCE, a subject that is not a SEQUENCE, or an AttributeTypeAndValue
 * without its type OID. */
static void test_subject_cn_malformed(void) {
  static const u8 not_seq[]  = {0x31, 0x00};
  static const u8 set_subj[] = {0x30, 0x0a, SANT_DUMMY4, 0x31, 0x00};
  static const u8 no_oid[]   = {0x30, 0x10, SANT_DUMMY4, 0x30, 0x06, 0x31,
                                0x04, 0x30, 0x02,        0x05, 0x00};
  wired_span      cn;
  CHECK(x509_subject_cn(wired_span_of(not_seq, sizeof(not_seq)), &cn) == 0);
  CHECK(x509_subject_cn(wired_span_of(set_subj, sizeof(set_subj)), &cn) == 0);
  CHECK(x509_subject_cn(wired_span_of(no_oid, sizeof(no_oid)), &cn) == 0);
}

/* A synthetic tbs (six NULL fillers, then [3] extensions) whose SAN holds
 * the single dNSName name, the same shape as san_dnsname_only_tbs. */
static wired_span s6125_dns_tbs(u8* t, const char* name) {
  static const u8 fill[] = {0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
                            0x05, 0x00, 0x05, 0x00, 0x05, 0x00};
  static const u8 san[]  = {0x06, 0x03, 0x55, 0x1d, 0x11, 0x04};
  usz             n = wired_cstr_len(name), k = 0;
  t[k++] = 0x30;
  t[k++] = (u8)(sizeof fill + 2 + n + 15);
  bytes_memcpy(t + k, fill, sizeof fill);
  k += sizeof fill;
  t[k++] = 0xa3;
  t[k++] = (u8)(n + 15);
  t[k++] = 0x30;
  t[k++] = (u8)(n + 13);
  t[k++] = 0x30;
  t[k++] = (u8)(n + 11);
  bytes_memcpy(t + k, san, sizeof san);
  k += sizeof san;
  t[k++] = (u8)(n + 4);
  t[k++] = 0x30;
  t[k++] = (u8)(n + 2);
  t[k++] = 0x82;
  t[k++] = (u8)n;
  bytes_memcpy(t + k, name, n);
  return wired_span_of(t, k + n);
}

static int s6125_dns_match(const char* presented, const char* host) {
  u8 t[128];
  return x509_san_matches(
      s6125_dns_tbs(t, presented),
      wired_span_of((const u8*)host, wired_cstr_len(host)));
}

/* RFC 6125 6.4.3 rule 1: a '*' that is not in the left-most label is not a
 * wildcard -- bar.*.example.net covers no host. */
static void test_san_wildcard_not_leftmost(void) {
  CHECK(s6125_dns_match("bar.*.example.net", "bar.foo.example.net") == 0);
  CHECK(s6125_dns_match("bar.*.example.net", "bar.example.net") == 0);
}

/* RFC 6125 6.4.2: A-labels compare as case-insensitive ASCII, label by
 * label -- the case of xn-- and of the punycode does not matter, a one
 * character change or an extra label does. */
static void test_san_alabel_compare(void) {
  CHECK(s6125_dns_match("xn--caf-dma.example", "XN--CAF-DMA.Example") == 1);
  CHECK(s6125_dns_match("xn--caf-dma.example", "xn--caf-dmb.example") == 0);
  CHECK(s6125_dns_match("xn--caf-dma.example", "a.xn--caf-dma.example") == 0);
}

/* A SAN-less tbs (four NULL fillers) whose subject is two RDNs: an
 * organizationalUnitName (2.5.4.11) of "host.example", then a commonName
 * (2.5.4.3) of "other.example". */
static const u8 s6125_ou_cn_tbs[] = {
    0x30, 0x39, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x30, 0x2f,
    0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x0c, 'h',
    'o',  's',  't',  '.',  'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x31,
    0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0d, 'o',  't',
    'h',  'e',  'r',  '.',  'e',  'x',  'a',  'm',  'p',  'l',  'e',
};

/* RFC 6125 6.2.1: only the CN RDN is a presented identifier -- a host equal
 * to another RDN's value does not match, the CN's value does. */
static void test_san_non_cn_rdn_ignored(void) {
  const u8 ou[] = "host.example", cn[] = "other.example";
  CHECK(
      san_match_tbs(
          s6125_ou_cn_tbs, sizeof(s6125_ou_cn_tbs), ou, sizeof(ou) - 1) == 0);
  CHECK(
      san_match_tbs(
          s6125_ou_cn_tbs, sizeof(s6125_ou_cn_tbs), cn, sizeof(cn) - 1) == 1);
}

void test_san(void) {
  test_san_fragment_wildcard_label_too_short();
  test_san_ipv4_octet_over_255();
  test_subject_cn_malformed();
  test_exact_match();
  test_wildcard_match();
  test_wildcard_no_nested();
  test_no_match();
  test_no_san();
  test_san_case_fold();
  test_san_cn_id_fallback();
  test_san_present_suppresses_cn_fallback();
  test_san_fragment_wildcard_match();
  test_san_fragment_wildcard_no_match();
  test_san_ipv4_match();
  test_san_ipv4_mismatch();
  test_san_ipv4_no_dnsname_fallback();
  test_san_ipv4_multi_match();
  test_san_ipv4_multi_no_match();
  test_san_ipv6_hostname_mismatch();
  test_san_ipv4_no_cn_id_fallback();
  test_san_uri_srv_suppress_cn_fallback();
  test_san_alabel_wildcard_no_match();
  test_san_wildcard_not_leftmost();
  test_san_alabel_compare();
  test_san_non_cn_rdn_ignored();
}
