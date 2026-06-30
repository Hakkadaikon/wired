#include "test.h"

/* RFC 9000 12.2: concatenate several packets into one datagram buffer. */
static void test_tx_pack_two(void)
{
    u8 pkts[5] = {0xAA, 0xBB, 0xCC, 0x11, 0x22};
    usz lens[2] = {3, 2};
    u8 scratch[8];
    usz len = quic_udploop_pack(pkts, lens, 2, scratch, sizeof scratch);

    CHECK(len == 5);
    CHECK(scratch[0] == 0xAA && scratch[2] == 0xCC);
    CHECK(scratch[3] == 0x11 && scratch[4] == 0x22);
}

/* Packing that would exceed the scratch capacity returns 0. */
static void test_tx_pack_overflow(void)
{
    u8 pkts[5] = {1, 2, 3, 4, 5};
    usz lens[2] = {3, 2};
    u8 scratch[4];
    CHECK(quic_udploop_pack(pkts, lens, 2, scratch, sizeof scratch) == 0);
}

/* No packets yields an empty datagram (length 0). */
static void test_tx_pack_none(void)
{
    u8 scratch[4];
    CHECK(quic_udploop_pack((const u8 *)0, (const usz *)0, 0, scratch, 4) == 0);
}

void test_txloop(void)
{
    test_tx_pack_two();
    test_tx_pack_overflow();
    test_tx_pack_none();
}
