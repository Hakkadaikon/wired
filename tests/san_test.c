#include "test.h"
#include "x509/x509.h"
#include "x509/san.h"
#include "chain_golden.h"

/* cert1 SAN lists example.com and *.example.com. */
static void test_exact_match(void)
{
    quic_x509 c;
    const u8 host[] = "example.com";
    CHECK(quic_x509_parse(quic_chain_golden1, sizeof(quic_chain_golden1), &c) == 1);
    CHECK(quic_x509_san_matches(c.tbs, c.tbs_len, host, sizeof(host) - 1) == 1);
}

/* *.example.com covers one label below example.com. */
static void test_wildcard_match(void)
{
    quic_x509 c;
    const u8 host[] = "www.example.com";
    CHECK(quic_x509_parse(quic_chain_golden1, sizeof(quic_chain_golden1), &c) == 1);
    CHECK(quic_x509_san_matches(c.tbs, c.tbs_len, host, sizeof(host) - 1) == 1);
}

/* The wildcard matches a single label only, not nested subdomains. */
static void test_wildcard_no_nested(void)
{
    quic_x509 c;
    const u8 host[] = "a.b.example.com";
    CHECK(quic_x509_parse(quic_chain_golden1, sizeof(quic_chain_golden1), &c) == 1);
    CHECK(quic_x509_san_matches(c.tbs, c.tbs_len, host, sizeof(host) - 1) == 0);
}

/* An unrelated hostname matches neither entry. */
static void test_no_match(void)
{
    quic_x509 c;
    const u8 host[] = "example.org";
    CHECK(quic_x509_parse(quic_chain_golden1, sizeof(quic_chain_golden1), &c) == 1);
    CHECK(quic_x509_san_matches(c.tbs, c.tbs_len, host, sizeof(host) - 1) == 0);
}

/* A cert without a SAN extension matches nothing. */
static void test_no_san(void)
{
    quic_x509 c;
    const u8 host[] = "other.example";
    CHECK(quic_x509_parse(quic_chain_golden2, sizeof(quic_chain_golden2), &c) == 1);
    CHECK(quic_x509_san_matches(c.tbs, c.tbs_len, host, sizeof(host) - 1) == 0);
}

void test_san(void)
{
    test_exact_match();
    test_wildcard_match();
    test_wildcard_no_nested();
    test_no_match();
    test_no_san();
}
