#include "test.h"

/* Build a minimal ServerHello (RFC 8446 4.1.3) carrying supported_versions and
 * a single x25519 key_share entry. Returns total message length. */
static usz build_sh(u8 *out, usz cap, const u8 pub[32])
{
    usz off = quic_hs_begin(out, cap, 2);
    usz block, end;
    out[off] = 0x03; out[off + 1] = 0x03;            /* legacy_version */
    for (usz i = 0; i < 32; i++) out[off + 2 + i] = (u8)(0x10 + i); /* random */
    out[off + 34] = 0;                               /* session_id len */
    out[off + 35] = 0x13; out[off + 36] = 0x01;      /* cipher_suite */
    out[off + 37] = 0;                               /* compression */
    block = off + 38;
    off = block + 2;
    /* supported_versions: type 002b, len 2, TLS 1.3 */
    out[off] = 0x00; out[off + 1] = 0x2b;
    out[off + 2] = 0x00; out[off + 3] = 2;
    out[off + 4] = 0x03; out[off + 5] = 0x04;
    off += 6;
    /* key_share: type 0033, len 36, group 001d, ke_len 32, key */
    out[off] = 0x00; out[off + 1] = 0x33;
    out[off + 2] = 0x00; out[off + 3] = 36;
    out[off + 4] = 0x00; out[off + 5] = 0x1d;
    out[off + 6] = 0x00; out[off + 7] = 32;
    for (usz i = 0; i < 32; i++) out[off + 8 + i] = pub[i];
    off += 40;
    out[block] = (u8)((off - block - 2) >> 8);
    out[block + 1] = (u8)(off - block - 2);
    quic_hs_finish(out, off);
    (void)cap; (void)end;
    return off;
}

static void test_server_hello_roundtrip(void)
{
    u8 pub[32], got[32], buf[256];
    u16 cipher = 0, version = 0;
    for (usz i = 0; i < 32; i++) pub[i] = (u8)(0x80 + i);
    usz w = build_sh(buf, sizeof(buf), pub);
    CHECK(quic_tls_parse_server_hello(buf, w, got, &cipher, &version) == 1);
    CHECK(cipher == 0x1301);
    CHECK(version == 0x0304);
    for (usz i = 0; i < 32; i++) CHECK(got[i] == pub[i]);
}

static void test_server_hello_wrong_type(void)
{
    u8 pub[32] = {0}, got[32], buf[256];
    u16 cipher, version;
    usz w = build_sh(buf, sizeof(buf), pub);
    buf[0] = 1;                                       /* claim ClientHello */
    CHECK(quic_tls_parse_server_hello(buf, w, got, &cipher, &version) == 0);
}

static void test_server_hello_truncated(void)
{
    u8 pub[32] = {0}, got[32], buf[256];
    u16 cipher, version;
    usz w = build_sh(buf, sizeof(buf), pub);
    CHECK(quic_tls_parse_server_hello(buf, w - 10, got, &cipher, &version) == 0);
}

void test_serverhello(void)
{
    test_server_hello_roundtrip();
    test_server_hello_wrong_type();
    test_server_hello_truncated();
}
