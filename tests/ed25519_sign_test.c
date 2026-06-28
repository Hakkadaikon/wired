#include "test.h"

static u8 sgn_hexnib(char c)
{
    return (u8)(c <= '9' ? c - '0' : c - 'a' + 10);
}

static void sgn_hexbytes(const char *hex, u8 *out, usz n)
{
    for (usz i = 0; i < n; i++)
        out[i] = (u8)((sgn_hexnib(hex[i * 2]) << 4) | sgn_hexnib(hex[i * 2 + 1]));
}

/* One RFC 8032 7.1 vector: seed -> public, (seed,msg) -> signature, and the
 * produced signature verifies. */
static void sign_vector(const char *seed, const char *pub,
                        const char *msg, usz msg_len, const char *sig)
{
    u8 sd[32], pk[32], want_pk[32], M[2], want_sig[64], got_pk[32], got_sig[64];
    sgn_hexbytes(seed, sd, 32);
    sgn_hexbytes(pub, want_pk, 32);
    sgn_hexbytes(sig, want_sig, 64);
    if (msg_len) sgn_hexbytes(msg, M, msg_len);

    quic_ed25519_keypair(sd, got_pk);
    for (usz i = 0; i < 32; i++) CHECK(got_pk[i] == want_pk[i]);

    quic_ed25519_sign(sd, M, msg_len, got_sig);
    for (usz i = 0; i < 64; i++) CHECK(got_sig[i] == want_sig[i]);

    for (usz i = 0; i < 32; i++) pk[i] = want_pk[i];
    CHECK(quic_ed25519_verify(got_sig, M, msg_len, pk) == 1);
}

/* RFC 8032 7.1 TEST 1: empty message. */
static void test_ed25519_sign_test1(void)
{
    sign_vector(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "", 0,
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015"
        "55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
}

/* RFC 8032 7.1 TEST 2: one-byte message 0x72. */
static void test_ed25519_sign_test2(void)
{
    sign_vector(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72", 1,
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69d"
        "a085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
}

/* RFC 8032 7.1 TEST 3: two-byte message 0xaf82. */
static void test_ed25519_sign_test3(void)
{
    sign_vector(
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82", 2,
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3a"
        "c18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");
}

void test_ed25519_sign(void)
{
    test_ed25519_sign_test1();
    test_ed25519_sign_test2();
    test_ed25519_sign_test3();
}
