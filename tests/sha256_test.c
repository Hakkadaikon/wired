#include "test.h"

/* Compare a computed digest against a hex literal. */
static int digest_eq(const u8 *got, const char *hex)
{
    for (usz i = 0; i < QUIC_SHA256_DIGEST; i++) {
        u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
        u8 b = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                    (lo <= '9' ? lo - '0' : lo - 'a' + 10));
        if (got[i] != b) return 0;
    }
    return 1;
}

/* NIST FIPS 180-4 sample vectors. */
static void test_sha256_vectors(void)
{
    u8 d[QUIC_SHA256_DIGEST];
    quic_sha256((const u8 *)"", 0, d);
    CHECK(digest_eq(d,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    quic_sha256((const u8 *)"abc", 3, d);
    CHECK(digest_eq(d,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    /* 56-byte input exercises the two-block padding path */
    quic_sha256((const u8 *)
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, d);
    CHECK(digest_eq(d,
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
}

/* Streaming in pieces must match the one-shot digest. */
static void test_sha256_streaming(void)
{
    u8 a[QUIC_SHA256_DIGEST], b[QUIC_SHA256_DIGEST];
    quic_sha256((const u8 *)"hello world", 11, a);
    quic_sha256_ctx s;
    quic_sha256_init(&s);
    quic_sha256_update(&s, (const u8 *)"hello ", 6);
    quic_sha256_update(&s, (const u8 *)"world", 5);
    quic_sha256_final(&s, b);
    CHECK(digest_eq(a, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"));
    for (usz i = 0; i < QUIC_SHA256_DIGEST; i++) CHECK(a[i] == b[i]);
}

void test_sha256(void)
{
    test_sha256_vectors();
    test_sha256_streaming();
}
