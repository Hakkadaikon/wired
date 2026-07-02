#include "crypto/pki/encoding/x509/san.h"

#include "chain_golden.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "test.h"

/* Parse a golden cert and match host (a string literal span) against it. */
static int san_match(const u8 *der, usz der_len, const u8 *host, usz hlen) {
  quic_x509 c;
  CHECK(quic_x509_parse(quic_span_of(der, der_len), &c) == 1);
  return quic_x509_san_matches(c.tbs, quic_span_of(host, hlen));
}

/* cert1 SAN lists example.com and *.example.com. */
static void test_exact_match(void) {
  const u8 host[] = "example.com";
  CHECK(
      san_match(
          quic_chain_golden1, sizeof(quic_chain_golden1), host,
          sizeof(host) - 1) == 1);
}

/* *.example.com covers one label below example.com. */
static void test_wildcard_match(void) {
  const u8 host[] = "www.example.com";
  CHECK(
      san_match(
          quic_chain_golden1, sizeof(quic_chain_golden1), host,
          sizeof(host) - 1) == 1);
}

/* The wildcard matches a single label only, not nested subdomains. */
static void test_wildcard_no_nested(void) {
  const u8 host[] = "a.b.example.com";
  CHECK(
      san_match(
          quic_chain_golden1, sizeof(quic_chain_golden1), host,
          sizeof(host) - 1) == 0);
}

/* An unrelated hostname matches neither entry. */
static void test_no_match(void) {
  const u8 host[] = "example.org";
  CHECK(
      san_match(
          quic_chain_golden1, sizeof(quic_chain_golden1), host,
          sizeof(host) - 1) == 0);
}

/* A cert without a SAN extension matches nothing. */
static void test_no_san(void) {
  const u8 host[] = "other.example";
  CHECK(
      san_match(
          quic_chain_golden2, sizeof(quic_chain_golden2), host,
          sizeof(host) - 1) == 0);
}

/* RFC 6125 6.4.1: comparison is ASCII case-insensitive — an upper/mixed-case
 * hostname matches the lowercase SAN, exactly and through the wildcard. */
static void test_san_case_fold(void) {
  const u8 upper[] = "EXAMPLE.com";
  const u8 mixed[] = "WwW.Example.COM";
  CHECK(
      san_match(
          quic_chain_golden1, sizeof(quic_chain_golden1), upper,
          sizeof(upper) - 1) == 1);
  CHECK(
      san_match(
          quic_chain_golden1, sizeof(quic_chain_golden1), mixed,
          sizeof(mixed) - 1) == 1);
}

void test_san(void) {
  test_exact_match();
  test_wildcard_match();
  test_wildcard_no_nested();
  test_no_match();
  test_no_san();
  test_san_case_fold();
}
