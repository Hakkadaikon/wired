#include "test.h"
#include "tls/x25519.c"

static void hb32(const char *hex, u8 out[32])
{
    for (usz i = 0; i < 32; i++) {
        u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
        out[i] = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                      (lo <= '9' ? lo - '0' : lo - 'a' + 10));
    }
}

/* RFC 7748 Section 5.2 test vector 1. */
static void test_x25519_rfc_v1(void)
{
    u8 scalar[32], point[32], out[32], want[32];
    hb32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", scalar);
    hb32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", point);
    hb32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", want);
    quic_x25519(out, scalar, point);
    for (usz i = 0; i < 32; i++) CHECK(out[i] == want[i]);
}

/* RFC 7748 Section 5.2 test vector 2. */
static void test_x25519_rfc_v2(void)
{
    u8 scalar[32], point[32], out[32], want[32];
    hb32("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", scalar);
    hb32("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", point);
    hb32("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957", want);
    quic_x25519(out, scalar, point);
    for (usz i = 0; i < 32; i++) CHECK(out[i] == want[i]);
}

/* An ECDHE exchange agrees: pub_a = a*G, pub_b = b*G, a*pub_b == b*pub_a. */
static void test_x25519_ecdhe(void)
{
    u8 a[32] = {0}, b[32] = {0}, pa[32], pb[32], sa[32], sb[32];
    a[0] = 5; a[31] = 0x40; /* arbitrary clamped-ish scalars */
    b[0] = 9; b[31] = 0x40;
    quic_x25519_base(pa, a);
    quic_x25519_base(pb, b);
    quic_x25519(sa, a, pb);
    quic_x25519(sb, b, pa);
    for (usz i = 0; i < 32; i++) CHECK(sa[i] == sb[i]); /* shared secret */
}

void test_x25519(void)
{
    test_x25519_rfc_v1();
    test_x25519_rfc_v2();
    test_x25519_ecdhe();
}
