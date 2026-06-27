#include "test.h"

/* uh parses hex into out; returns byte count. */
static usz uh(const char *hex, u8 *out)
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

/* RFC 8439 A.1 test vector 1: all-zero key, nonce, counter 0. */
static void test_chacha_block(void)
{
    u8 key[32] = {0}, nonce[12] = {0}, ks[64], want[64];
    quic_chacha20_block(key, 0, nonce, ks);
    uh("76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
       "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586", want);
    for (usz i = 0; i < 64; i++) CHECK(ks[i] == want[i]);
}

/* RFC 8439 2.4.2: encrypt the sunscreen plaintext, key 00..1f, nonce
 * 00:00:00:00:00:00:00:4a:00:00:00:00, counter 1. */
static void test_chacha_encrypt(void)
{
    u8 key[32], nonce[12], pt[114], want[114], ct[114];
    for (usz i = 0; i < 32; i++) key[i] = (u8)i;
    uh("000000000000004a00000000", nonce);
    usz n = uh(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
        "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
        "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
        "637265656e20776f756c642062652069742e", pt);
    uh("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
       "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
       "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
       "5af90bbf74a35be6b40b8eedf2785e42874d", want);
    quic_chacha20_xor(key, 1, nonce, pt, n, ct);
    for (usz i = 0; i < n; i++) CHECK(ct[i] == want[i]);
}

void test_chacha20(void)
{
    test_chacha_block();
    test_chacha_encrypt();
}
