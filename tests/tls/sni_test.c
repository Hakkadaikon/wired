#include "test.h"

static void test_sni_roundtrip(void)
{
    const u8 host[] = {'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'};
    u8 buf[32];
    const u8 *out;
    usz olen;
    usz w = quic_tls_sni_encode(buf, sizeof(buf), host, sizeof(host));
    usz r = quic_tls_sni_decode(buf, w, &out, &olen);
    CHECK(w == 3 + sizeof(host) && r == w);
    CHECK(olen == sizeof(host) && out == buf + 3);
    for (usz i = 0; i < sizeof(host); i++) CHECK(out[i] == host[i]);
    /* wire: name_type host_name, length */
    CHECK(buf[0] == 0x00);
    CHECK(buf[1] == 0x00 && buf[2] == (u8)sizeof(host));
}

static void test_sni_truncated(void)
{
    const u8 host[] = {'a', 'b', 'c'};
    u8 buf[16];
    const u8 *out;
    usz olen;
    usz w = quic_tls_sni_encode(buf, sizeof(buf), host, sizeof(host));
    /* length claims 3 but only 2 data bytes readable */
    CHECK(quic_tls_sni_decode(buf, w - 1, &out, &olen) == 0);
    /* short header */
    CHECK(quic_tls_sni_decode(buf, 2, &out, &olen) == 0);
}

static void test_sni_wrong_type(void)
{
    u8 buf[8] = {0x01, 0x00, 0x00};
    const u8 *out;
    usz olen;
    CHECK(quic_tls_sni_decode(buf, 3, &out, &olen) == 0);
}

static void test_sni_no_room(void)
{
    const u8 host[] = {'a', 'b', 'c'};
    u8 buf[4];
    CHECK(quic_tls_sni_encode(buf, sizeof(buf), host, sizeof(host)) == 0);
}

void test_sni(void)
{
    test_sni_roundtrip();
    test_sni_truncated();
    test_sni_wrong_type();
    test_sni_no_room();
}
