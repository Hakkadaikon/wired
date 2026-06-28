#include "test.h"

static void test_ext_groups_golden(void)
{
    u8 buf[16];
    usz w = quic_tls_ext_supported_groups(buf, sizeof(buf));
    /* wire: type 0x000a, ext_data 0x0004, list 0x0002, x25519 0x001d */
    CHECK(w == 8);
    CHECK(buf[0] == 0x00 && buf[1] == 0x0a);
    CHECK(buf[2] == 0x00 && buf[3] == 0x04);
    CHECK(buf[4] == 0x00 && buf[5] == 0x02);
    CHECK(buf[6] == 0x00 && buf[7] == 0x1d);
}

static void test_ext_sig_algs_golden(void)
{
    u8 buf[16];
    usz w = quic_tls_ext_sig_algs(buf, sizeof(buf));
    /* wire: type 0x000d, ext_data 0x0008, list 0x0006, then three schemes */
    CHECK(w == 12);
    CHECK(buf[0] == 0x00 && buf[1] == 0x0d);
    CHECK(buf[2] == 0x00 && buf[3] == 0x08);
    CHECK(buf[4] == 0x00 && buf[5] == 0x06);
    CHECK(buf[6] == 0x04 && buf[7] == 0x03);   /* ecdsa_secp256r1_sha256 */
    CHECK(buf[8] == 0x08 && buf[9] == 0x04);   /* rsa_pss_rsae_sha256 */
    CHECK(buf[10] == 0x08 && buf[11] == 0x07); /* ed25519 */
}

static void test_ext_algs_encode_guard(void)
{
    u8 g[7];
    u8 s[11];
    CHECK(quic_tls_ext_supported_groups(g, sizeof(g)) == 0);
    CHECK(quic_tls_ext_sig_algs(s, sizeof(s)) == 0);
}

void test_ext_algs(void)
{
    test_ext_groups_golden();
    test_ext_sig_algs_golden();
    test_ext_algs_encode_guard();
}
