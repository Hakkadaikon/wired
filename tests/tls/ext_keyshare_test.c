#include "test.h"

static void test_ext_key_share_wire(void)
{
    u8 pub[32], buf[64];
    for (usz i = 0; i < 32; i++) pub[i] = (u8)(i + 1);
    usz w = quic_tls_ext_key_share(buf, sizeof(buf), pub);
    CHECK(w == 42);
    /* RFC 8446 4.2.8 header bytes */
    CHECK(buf[0] == 0x00 && buf[1] == 0x33);     /* type */
    CHECK(buf[2] == 0x00 && buf[3] == 38);       /* ext_len */
    CHECK(buf[4] == 0x00 && buf[5] == 36);       /* shares_len */
    CHECK(buf[6] == 0x00 && buf[7] == 0x1d);     /* x25519 */
    CHECK(buf[8] == 0x00 && buf[9] == 32);       /* key_exchange len */
    CHECK(buf[10] == 1 && buf[41] == 32);        /* key contents */
}

static void test_ext_key_share_roundtrip(void)
{
    u8 pub[32], got[32], buf[64];
    for (usz i = 0; i < 32; i++) pub[i] = (u8)(0xA0 + i);
    quic_tls_ext_key_share(buf, sizeof(buf), pub);
    /* parse the KeyShareEntry that begins at buf+6 (group/ke_len/key) */
    CHECK(quic_tls_ext_key_share_parse(buf + 6, 36, got) == 1);
    for (usz i = 0; i < 32; i++) CHECK(got[i] == pub[i]);
}

static void test_ext_key_share_parse_guards(void)
{
    u8 got[32];
    u8 wrong_group[36] = {0x00, 0x17, 0x00, 32};   /* secp256r1, not x25519 */
    u8 wrong_len[36] = {0x00, 0x1d, 0x00, 31};
    CHECK(quic_tls_ext_key_share_parse(wrong_group, 36, got) == 0);
    CHECK(quic_tls_ext_key_share_parse(wrong_len, 36, got) == 0);
    CHECK(quic_tls_ext_key_share_parse(wrong_group, 35, got) == 0);
}

static void test_ext_key_share_cap_guard(void)
{
    u8 pub[32] = {0}, buf[41];
    CHECK(quic_tls_ext_key_share(buf, sizeof(buf), pub) == 0);
}

/* RFC 8446 4.2.8: a ClientHello key_share is client_shares<2> then a list of
 * KeyShareEntry. curl/quiche send several groups and x25519 is not always
 * first; scan the list and pull x25519's 32-byte key out from any position. */
static void test_ext_key_share_scan_not_first(void)
{
    u8 got[32];
    /* shares_len(2)=72 | secp256r1(0x0017) len 32 [32 bytes] | x25519 len 32 */
    u8 b[2 + 36 + 36];
    b[0] = 0x00; b[1] = 72;
    b[2] = 0x00; b[3] = 0x17; b[4] = 0x00; b[5] = 32;   /* secp256r1 entry */
    for (usz i = 0; i < 32; i++) b[6 + i] = 0xEE;
    b[38] = 0x00; b[39] = 0x1d; b[40] = 0x00; b[41] = 32; /* x25519 entry */
    for (usz i = 0; i < 32; i++) b[42 + i] = (u8)(0x50 + i);
    CHECK(quic_tls_ext_key_share_scan(b, sizeof(b), got) == 1);
    for (usz i = 0; i < 32; i++) CHECK(got[i] == (u8)(0x50 + i));
}

static void test_ext_key_share_scan_first(void)
{
    u8 got[32];
    u8 b[2 + 36];
    b[0] = 0x00; b[1] = 36;
    b[2] = 0x00; b[3] = 0x1d; b[4] = 0x00; b[5] = 32;
    for (usz i = 0; i < 32; i++) b[6 + i] = (u8)(0x70 + i);
    CHECK(quic_tls_ext_key_share_scan(b, sizeof(b), got) == 1);
    for (usz i = 0; i < 32; i++) CHECK(got[i] == (u8)(0x70 + i));
}

static void test_ext_key_share_scan_absent(void)
{
    u8 got[32];
    u8 b[2 + 36];
    b[0] = 0x00; b[1] = 36;
    b[2] = 0x00; b[3] = 0x17; b[4] = 0x00; b[5] = 32;   /* secp256r1 only */
    for (usz i = 0; i < 32; i++) b[6 + i] = 0xEE;
    CHECK(quic_tls_ext_key_share_scan(b, sizeof(b), got) == 0);
}

/* A truncated key_exchange length must fail, not read past n. */
static void test_ext_key_share_scan_oob(void)
{
    u8 got[32];
    u8 b[2 + 6];
    b[0] = 0x00; b[1] = 36;     /* claims 36 bytes of entries, only 6 present */
    b[2] = 0x00; b[3] = 0x1d; b[4] = 0x00; b[5] = 32;
    CHECK(quic_tls_ext_key_share_scan(b, sizeof(b), got) == 0);
}

void test_ext_keyshare(void)
{
    test_ext_key_share_wire();
    test_ext_key_share_roundtrip();
    test_ext_key_share_parse_guards();
    test_ext_key_share_cap_guard();
    test_ext_key_share_scan_not_first();
    test_ext_key_share_scan_first();
    test_ext_key_share_scan_absent();
    test_ext_key_share_scan_oob();
}
