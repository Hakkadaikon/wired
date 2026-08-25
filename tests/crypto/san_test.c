#include "crypto/pki/encoding/x509/san.h"

#include "chain_golden.h"
#include "crypto/pki/encoding/x509/x509.h"
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

/* RFC 6125 6.4.4: a cert without any SAN extension falls back to the CN-ID,
 * and that fallback also applies when the hostname is an IPv4 literal and
 * the CN's value is the same literal string. */
static void test_san_ipv4_cn_id_fallback(void) {
  const u8 host[] = "127.0.0.1";
  CHECK(
      san_match_tbs(
          san_cn_only_ipv4_tbs, sizeof(san_cn_only_ipv4_tbs), host,
          sizeof(host) - 1) == 1);
}

/* The CN-ID fallback for an IPv4-literal hostname still requires an exact
 * string match against the CN value. */
static void test_san_ipv4_cn_id_fallback_no_match(void) {
  const u8 host[] = "127.0.0.2";
  CHECK(
      san_match_tbs(
          san_cn_only_ipv4_tbs, sizeof(san_cn_only_ipv4_tbs), host,
          sizeof(host) - 1) == 0);
}

void test_san(void) {
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
  test_san_ipv4_cn_id_fallback();
  test_san_ipv4_cn_id_fallback_no_match();
}
