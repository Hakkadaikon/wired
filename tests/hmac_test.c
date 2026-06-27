#include "test.h"

/* digest_eq is defined in sha256_test.c, included before this file. */

/* RFC 4231 HMAC-SHA-256 test vectors. */
static void test_hmac_vectors(void)
{
    u8 mac[QUIC_SHA256_DIGEST];
    u8 key1[20];
    for (usz i = 0; i < 20; i++) key1[i] = 0x0b;
    quic_hmac_sha256(key1, 20, (const u8 *)"Hi There", 8, mac);
    CHECK(digest_eq(mac,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));

    quic_hmac_sha256((const u8 *)"Jefe", 4,
        (const u8 *)"what do ya want for nothing?", 28, mac);
    CHECK(digest_eq(mac,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
}

/* A key longer than the block size is hashed first (RFC 4231 case 6). */
static void test_hmac_long_key(void)
{
    u8 key[131], mac[QUIC_SHA256_DIGEST];
    for (usz i = 0; i < 131; i++) key[i] = 0xaa;
    quic_hmac_sha256(key, 131,
        (const u8 *)"Test Using Larger Than Block-Size Key - Hash Key First",
        54, mac);
    CHECK(digest_eq(mac,
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));
}

void test_hmac(void)
{
    test_hmac_vectors();
    test_hmac_long_key();
}
