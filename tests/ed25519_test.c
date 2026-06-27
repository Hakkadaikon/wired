#include "test.h"

static u8 hexnib(char c)
{
    return (u8)(c <= '9' ? c - '0' : c - 'a' + 10);
}

static void hexbytes(const char *hex, u8 *out, usz n)
{
    for (usz i = 0; i < n; i++)
        out[i] = (u8)((hexnib(hex[i * 2]) << 4) | hexnib(hex[i * 2 + 1]));
}

/* Verify a single RFC 8032 7.1 vector accepts, and that flipping one
 * signature byte makes it reject. */
static void check_vector(const char *pk, const char *sig,
                         const char *msg, usz msg_len)
{
    u8 A[32], S[64], M[2], tampered[64];
    hexbytes(pk, A, 32);
    hexbytes(sig, S, 64);
    if (msg_len) hexbytes(msg, M, msg_len);
    CHECK(quic_ed25519_verify(S, M, msg_len, A) == 1);
    for (usz i = 0; i < 64; i++) tampered[i] = S[i];
    tampered[0] ^= 0x01;
    CHECK(quic_ed25519_verify(tampered, M, msg_len, A) == 0);
}

/* RFC 8032 7.1 TEST 1: empty message. */
static void test_ed25519_rfc_test1(void)
{
    check_vector(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015"
        "55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        "", 0);
}

/* RFC 8032 7.1 TEST 2: one-byte message 0x72. */
static void test_ed25519_rfc_test2(void)
{
    check_vector(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69d"
        "a085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        "72", 1);
}

/* RFC 8032 7.1 TEST 3: two-byte message 0xaf82. */
static void test_ed25519_rfc_test3(void)
{
    check_vector(
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3a"
        "c18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        "af82", 2);
}

/* SHA-512 of the empty string (FIPS 180-4 known-answer). */
static void test_sha512_empty(void)
{
    static const u8 want[64] = {
        0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28,
        0x50, 0xd6, 0x6d, 0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57,
        0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce, 0x47,
        0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2,
        0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a,
        0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e
    };
    u8 out[64];
    quic_sha512((const u8 *)"", 0, out);
    for (usz i = 0; i < 64; i++) CHECK(out[i] == want[i]);
}

void test_ed25519(void)
{
    test_sha512_empty();
    test_ed25519_rfc_test1();
    test_ed25519_rfc_test2();
    test_ed25519_rfc_test3();
}
