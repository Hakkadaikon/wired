#include "test.h"

/* RFC 8439 2.5.2 worked example. */
static void test_poly1305_rfc(void)
{
    u8 key[32], tag[16], want[16];
    const char *kx =
        "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b";
    for (usz i = 0; i < 32; i++) {
        u8 hi = kx[i * 2], lo = kx[i * 2 + 1];
        key[i] = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                      (lo <= '9' ? lo - '0' : lo - 'a' + 10));
    }
    const char *msg = "Cryptographic Forum Research Group";
    quic_poly1305(key, (const u8 *)msg, 34, tag);
    const char *tx = "a8061dc1305136c6c22b8baf0c0127a9";
    for (usz i = 0; i < 16; i++) {
        u8 hi = tx[i * 2], lo = tx[i * 2 + 1];
        want[i] = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                       (lo <= '9' ? lo - '0' : lo - 'a' + 10));
    }
    for (usz i = 0; i < 16; i++) CHECK(tag[i] == want[i]);
}

void test_poly1305(void)
{
    test_poly1305_rfc();
}
