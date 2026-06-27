#include "test.h"
#include "retrytoken/retrytoken.c"

/* A token verifies for the address and original DCID it was made for, and
 * not for a different address. */
void test_retrytoken(void)
{
    u8 key[QUIC_RETRYTOKEN_KEY];
    for (usz i = 0; i < QUIC_RETRYTOKEN_KEY; i++) key[i] = (u8)(i + 1);
    const u8 addr[4] = {192, 0, 2, 1};
    const u8 addr2[4] = {192, 0, 2, 2};
    const u8 odcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};

    u8 token[QUIC_RETRYTOKEN_LEN];
    quic_retrytoken_make(key, addr, 4, odcid, 8, token);

    CHECK(quic_retrytoken_verify(key, addr, 4, odcid, 8, token) == 1);
    CHECK(quic_retrytoken_verify(key, addr2, 4, odcid, 8, token) == 0);
    u8 odcid2[8] = {1, 2, 3, 4, 5, 6, 7, 9};
    CHECK(quic_retrytoken_verify(key, addr, 4, odcid2, 8, token) == 0);
    token[0] ^= 0x01;
    CHECK(quic_retrytoken_verify(key, addr, 4, odcid, 8, token) == 0);
}

