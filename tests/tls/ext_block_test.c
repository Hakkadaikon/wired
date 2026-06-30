#include "test.h"

static void test_ext_block_concat(void)
{
    u8 buf[64];
    u8 v[16], g[16];
    usz off;
    usz vw = quic_tls_ext_supported_versions(v, sizeof(v));
    usz gw = quic_tls_ext_supported_groups(g, sizeof(g));
    CHECK(quic_tls_ext_block_begin(buf, sizeof(buf), &off) == 1);
    CHECK(off == 2);
    CHECK(quic_tls_ext_append(buf, sizeof(buf), &off, v, vw) == 1);
    CHECK(quic_tls_ext_append(buf, sizeof(buf), &off, g, gw) == 1);
    usz total = quic_tls_ext_block_finish(buf, off, 0);
    /* block length covers both extensions; total adds the 2-byte length */
    CHECK(total == 2 + vw + gw);
    CHECK(((usz)buf[0] << 8 | buf[1]) == vw + gw);
    /* the two extensions sit back to back after the length */
    CHECK(buf[2] == 0x00 && buf[3] == 0x2b);
    CHECK(buf[2 + vw] == 0x00 && buf[3 + vw] == 0x0a);
}

static void test_ext_block_begin_guard(void)
{
    u8 buf[1];
    usz off;
    CHECK(quic_tls_ext_block_begin(buf, sizeof(buf), &off) == 0);
}

static void test_ext_block_append_guard(void)
{
    u8 buf[8];
    u8 ext[8] = {0};
    usz off;
    quic_tls_ext_block_begin(buf, sizeof(buf), &off);
    /* 7 bytes past the 2-byte length overflow the 8-byte buffer */
    CHECK(quic_tls_ext_append(buf, sizeof(buf), &off, ext, 7) == 0);
}

void test_ext_block(void)
{
    test_ext_block_concat();
    test_ext_block_begin_guard();
    test_ext_block_append_guard();
}
