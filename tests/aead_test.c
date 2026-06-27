#include "test.h"

/* uh2 parses hex into out; returns byte count. */
static usz uh2(const char *hex, u8 *out)
{
    usz i = 0;
    while (hex[i * 2] != 0) {
        u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
        out[i] = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                      (lo <= '9' ? lo - '0' : lo - 'a' + 10));
        i++;
    }
    return i;
}

/* RFC 8439 2.8.2 worked example. */
static void test_chapoly_rfc(void)
{
    u8 key[32], nonce[12], aad[12], pt[114], ct[114], tag[16];
    u8 want_ct[114], want_tag[16];
    uh2("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", key);
    uh2("070000004041424344454647", nonce);
    usz al = uh2("50515253c0c1c2c3c4c5c6c7", aad);
    usz n = uh2(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
        "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
        "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
        "637265656e20776f756c642062652069742e", pt);
    uh2("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116", want_ct);
    uh2("1ae10b594f09e26a7e902ecbd0600691", want_tag);

    quic_chapoly_seal(key, nonce, aad, al, pt, n, ct, tag);
    for (usz i = 0; i < n; i++) CHECK(ct[i] == want_ct[i]);
    for (usz i = 0; i < 16; i++) CHECK(tag[i] == want_tag[i]);
}

static void test_chapoly_open(void)
{
    u8 key[32] = {0}, nonce[12] = {0};
    u8 pt[20], ct[20], dec[20], tag[16], bad[16];
    for (usz i = 0; i < 20; i++) { pt[i] = (u8)(i * 7); dec[i] = 0xCC; }
    quic_chapoly_seal(key, nonce, (const u8 *)"aad", 3, pt, 20, ct, tag);
    CHECK(quic_chapoly_open(key, nonce, (const u8 *)"aad", 3, ct, 20, tag, dec));
    for (usz i = 0; i < 20; i++) CHECK(dec[i] == pt[i]);
    /* tamper the tag: reject, leave dec untouched */
    for (usz i = 0; i < 20; i++) dec[i] = 0xCC;
    for (usz i = 0; i < 16; i++) bad[i] = tag[i];
    bad[7] ^= 0x80;
    CHECK(quic_chapoly_open(key, nonce, (const u8 *)"aad", 3, ct, 20, bad, dec) == 0);
    for (usz i = 0; i < 20; i++) CHECK(dec[i] == 0xCC);
}

void test_aead(void)
{
    test_chapoly_rfc();
    test_chapoly_open();
}
