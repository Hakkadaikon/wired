#include "test.h"

/* 0x31 frame is built with explicit length and reports its wire length. */
void test_dg_send_with_length(void)
{
    const u8 data[] = {0xAA, 0xBB, 0xCC};
    u8 out[16];
    usz n = 0;
    int ok = quic_dgdeliver_frame(data, 3, 1, 64, out, sizeof(out), &n);
    CHECK(ok == 1 && out[0] == QUIC_FRAME_DATAGRAM_LEN);
    /* type + length varint(1) + 3 data = 5 */
    CHECK(n == 5);
}

/* 0x30 frame omits the length; data runs to the end. */
void test_dg_send_no_length(void)
{
    const u8 data[] = {1, 2, 3, 4};
    u8 out[16];
    usz n = 0;
    int ok = quic_dgdeliver_frame(data, 4, 0, 64, out, sizeof(out), &n);
    CHECK(ok == 1 && out[0] == QUIC_FRAME_DATAGRAM && n == 5); /* type + 4 */
}

/* A frame whose total size exceeds max_datagram_frame_size is rejected. */
void test_dg_send_over_max(void)
{
    const u8 data[] = {1, 2, 3, 4, 5};
    u8 out[16];
    usz n = 99;
    /* 0x31: 1 type + 1 len + 5 = 7 bytes; cap the limit at 4 */
    int ok = quic_dgdeliver_frame(data, 5, 1, 4, out, sizeof(out), &n);
    CHECK(ok == 0 && n == 99); /* out_len untouched on failure */
}

/* max_datagram_frame_size == 0 means the peer does not support datagrams. */
void test_dg_send_unsupported(void)
{
    const u8 data[] = {1};
    u8 out[16];
    usz n = 0;
    CHECK(quic_dgdeliver_frame(data, 1, 1, 0, out, sizeof(out), &n) == 0);
}

/* A buffer too small to hold the frame fails without writing out_len. */
void test_dg_send_no_room(void)
{
    const u8 data[] = {1, 2, 3, 4};
    u8 out[2];
    usz n = 7;
    CHECK(quic_dgdeliver_frame(data, 4, 1, 64, out, sizeof(out), &n) == 0);
    CHECK(n == 7);
}
