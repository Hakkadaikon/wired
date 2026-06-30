#include "test.h"

static void test_alpn_match_is_h3(void)
{
    const u8 h3[] = {0x68, 0x33};
    const u8 h2[] = {0x68, 0x32};
    const u8 long_h3[] = {0x68, 0x33, 0x33};
    CHECK(quic_tls_alpn_is_h3(h3, 2) == 1);
    CHECK(quic_tls_alpn_is_h3(h2, 2) == 0);
    CHECK(quic_tls_alpn_is_h3(long_h3, 3) == 0);
    CHECK(quic_tls_alpn_is_h3(h3, 1) == 0);
}

static void test_alpn_match_equal(void)
{
    const u8 a[] = {'h', 't', 't', 'p', '/', '1', '.', '1'};
    const u8 b[] = {'h', 't', 't', 'p', '/', '1', '.', '1'};
    const u8 c[] = {'h', '3'};
    CHECK(quic_tls_alpn_equal(a, sizeof(a), b, sizeof(b)) == 1);
    CHECK(quic_tls_alpn_equal(a, sizeof(a), c, sizeof(c)) == 0);
    CHECK(quic_tls_alpn_equal(a, sizeof(a), a, sizeof(a) - 1) == 0);
}

void test_alpn_match(void)
{
    test_alpn_match_is_h3();
    test_alpn_match_equal();
}
