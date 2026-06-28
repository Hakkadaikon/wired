#include "test.h"

/* len boundaries: 0 and 21 are invalid, 1 and 20 are valid. */
static void test_cidgen_len_bounds(void)
{
    CHECK(quic_cid_len_valid(0) == 0);
    CHECK(quic_cid_len_valid(1) == 1);
    CHECK(quic_cid_len_valid(20) == 1);
    CHECK(quic_cid_len_valid(21) == 0);

    u8 cid[20];
    CHECK(quic_cid_generate(cid, 0) == 0);
    CHECK(quic_cid_generate(cid, 21) == 0);
    CHECK(quic_cid_generate(cid, 1) == 1);
    CHECK(quic_cid_generate(cid, 20) == 1);
}

/* A generated CID fills the requested length and differs between draws. */
static void test_cidgen_distinct_and_full(void)
{
    u8 a[20], b[20];
    for (usz i = 0; i < 20; i++) { a[i] = 0; b[i] = 0; }
    CHECK(quic_cid_generate(a, 20) == 1);
    CHECK(quic_cid_generate(b, 20) == 1);
    int differ = 0;
    for (usz i = 0; i < 20; i++) if (a[i] != b[i]) differ = 1;
    CHECK(differ);
}

void test_cidgen(void)
{
    test_cidgen_len_bounds();
    test_cidgen_distinct_and_full();
}
