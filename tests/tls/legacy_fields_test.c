#include "test.h"

/* Build a ClientHello (RFC 8446 4.1.2) with the given legacy_version, a
 * session_id of sid_len bytes, and compression bytes comp[comp_len]. Returns
 * total handshake message length. */
static usz legacy_build_ch(u8 *out, u16 ver, u8 sid_len, const u8 *comp, u8 comp_len)
{
    usz off = quic_hs_begin(out, 256, 1);
    out[off] = (u8)(ver >> 8);
    out[off + 1] = (u8)ver;
    for (usz i = 0; i < 32; i++) out[off + 2 + i] = (u8)i;
    out[off + 34] = sid_len;
    for (usz i = 0; i < sid_len; i++) out[off + 35 + i] = (u8)(0xA0 + i);
    usz p = 35 + sid_len;
    out[off + p] = 0;
    out[off + p + 1] = 2; /* cipher_suites len */
    out[off + p + 2] = 0x13;
    out[off + p + 3] = 0x01;
    p += 4;
    out[off + p] = comp_len;
    for (usz i = 0; i < comp_len; i++) out[off + p + 1 + i] = comp[i];
    p += 1 + comp_len;
    out[off + p] = 0; /* empty extensions block */
    out[off + p + 1] = 0;
    p += 2;
    quic_hs_finish(out, off + p);
    return off + p;
}

static void test_legacy_version_ok(void)
{
    u8 buf[256];
    u8 comp[1] = {0};
    usz w = legacy_build_ch(buf, 0x0303, 0, comp, 1);
    CHECK(quic_legacy_check_client_hello(buf, w) == 1);
}

static void test_legacy_version_wrong(void)
{
    u8 buf[256];
    u8 comp[1] = {0};
    usz w = legacy_build_ch(buf, 0x0304, 0, comp, 1);
    CHECK(quic_legacy_check_client_hello(buf, w) == 0);
}

static void test_legacy_compression_null_only(void)
{
    u8 buf[256];
    u8 comp[1] = {0};
    usz w = legacy_build_ch(buf, 0x0303, 5, comp, 1);
    CHECK(quic_legacy_check_client_hello(buf, w) == 1);
}

static void test_legacy_compression_nonnull(void)
{
    u8 buf[256];
    u8 comp[1] = {1};
    usz w = legacy_build_ch(buf, 0x0303, 0, comp, 1);
    CHECK(quic_legacy_check_client_hello(buf, w) == 0);
}

static void test_legacy_compression_extra_method(void)
{
    u8 buf[256];
    u8 comp[2] = {0, 1};
    usz w = legacy_build_ch(buf, 0x0303, 0, comp, 2);
    CHECK(quic_legacy_check_client_hello(buf, w) == 0);
}

static void test_legacy_truncated(void)
{
    u8 buf[256];
    u8 comp[1] = {0};
    usz w = legacy_build_ch(buf, 0x0303, 0, comp, 1);
    CHECK(quic_legacy_check_client_hello(buf, 3) == 0);
    CHECK(quic_legacy_check_client_hello(buf, w - 1) == 0);
}

static void test_legacy_not_client_hello(void)
{
    u8 buf[256];
    u8 comp[1] = {0};
    usz w = legacy_build_ch(buf, 0x0303, 0, comp, 1);
    buf[0] = 2; /* ServerHello */
    CHECK(quic_legacy_check_client_hello(buf, w) == 0);
}

static void test_legacy_session_id_empty(void)
{
    u8 buf[256];
    u8 comp[1] = {0};
    const u8 *sid = (const u8 *)1;
    u8 sid_len = 99;
    usz w = legacy_build_ch(buf, 0x0303, 0, comp, 1);
    CHECK(quic_legacy_session_id(buf, w, &sid, &sid_len) == 1);
    CHECK(sid_len == 0);
}

static void test_legacy_session_id_extract(void)
{
    u8 buf[256];
    u8 comp[1] = {0};
    const u8 *sid = 0;
    u8 sid_len = 0;
    usz w = legacy_build_ch(buf, 0x0303, 32, comp, 1);
    CHECK(quic_legacy_session_id(buf, w, &sid, &sid_len) == 1);
    CHECK(sid_len == 32);
    CHECK(sid[0] == 0xA0);
    CHECK(sid[31] == (u8)(0xA0 + 31));
}

static void test_legacy_session_id_overlong(void)
{
    u8 buf[256];
    const u8 *sid = 0;
    u8 sid_len = 0;
    usz off = quic_hs_begin(buf, 256, 1);
    buf[off] = 0x03;
    buf[off + 1] = 0x03;
    for (usz i = 0; i < 32; i++) buf[off + 2 + i] = 0;
    buf[off + 34] = 33; /* invalid: > 32 */
    quic_hs_finish(buf, off + 35 + 33);
    CHECK(quic_legacy_session_id(buf, off + 35 + 33, &sid, &sid_len) == 0);
}

void test_legacy_fields(void)
{
    test_legacy_version_ok();
    test_legacy_version_wrong();
    test_legacy_compression_null_only();
    test_legacy_compression_nonnull();
    test_legacy_compression_extra_method();
    test_legacy_truncated();
    test_legacy_not_client_hello();
    test_legacy_session_id_empty();
    test_legacy_session_id_extract();
    test_legacy_session_id_overlong();
}
