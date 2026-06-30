#include "test.h"

/* Challenge and reset token fill their full width and differ between draws. */
static void test_challenge_distinct(void)
{
    u8 a[8], b[8];
    for (usz i = 0; i < 8; i++) { a[i] = 0; b[i] = 0; }
    CHECK(quic_challenge_generate(a) == 1);
    CHECK(quic_challenge_generate(b) == 1);
    int differ = 0;
    for (usz i = 0; i < 8; i++) if (a[i] != b[i]) differ = 1;
    CHECK(differ);
}

static void test_reset_token_distinct(void)
{
    u8 a[16], b[16];
    for (usz i = 0; i < 16; i++) { a[i] = 0; b[i] = 0; }
    CHECK(quic_reset_token_generate(a) == 1);
    CHECK(quic_reset_token_generate(b) == 1);
    int differ = 0;
    for (usz i = 0; i < 16; i++) if (a[i] != b[i]) differ = 1;
    CHECK(differ);
}

void test_challenge(void)
{
    test_challenge_distinct();
    test_reset_token_distinct();
}
