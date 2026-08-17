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
}
