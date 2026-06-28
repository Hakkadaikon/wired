#include "test.h"

/* send -> loss -> rebuild: a STREAM frame stored under its original pn is
 * recovered for a new packet, ACK/PADDING dropped, missing pns skipped. */
static void test_collect_lost_streams(void)
{
    quic_rtxbytes st;
    const u8 s1[] = {0x08, 0x00, 0x02, 'h', 'i'};
    const u8 ack[] = {0x02, 0x00, 0x00, 0x00};
    const u8 s2[] = {0x08, 0x04, 0x03, 'b', 'y', 'e'};
    const u64 lost[] = {10, 11, 12, 99};
    u8 out[64];
    usz out_len;

    quic_rtxbytes_init(&st);
    quic_rtxbytes_store(&st, 10, s1, sizeof s1);
    quic_rtxbytes_store(&st, 11, ack, sizeof ack);
    quic_rtxbytes_store(&st, 12, s2, sizeof s2);

    CHECK(quic_rtxbytes_collect(&st, lost, 4, out, sizeof out, &out_len) == 1);
    CHECK(out_len == sizeof s1 + sizeof s2);
    for (usz i = 0; i < sizeof s1; i++) CHECK(out[i] == s1[i]);
    for (usz i = 0; i < sizeof s2; i++) CHECK(out[sizeof s1 + i] == s2[i]);
}

static void test_collect_no_room(void)
{
    quic_rtxbytes st;
    const u8 s1[] = {0x08, 0x00, 0x02, 'h', 'i'};
    const u64 lost[] = {10};
    u8 out[3];
    usz out_len;

    quic_rtxbytes_init(&st);
    quic_rtxbytes_store(&st, 10, s1, sizeof s1);
    CHECK(quic_rtxbytes_collect(&st, lost, 1, out, sizeof out, &out_len) == 0);
}

void test_collect(void)
{
    test_collect_lost_streams();
    test_collect_no_room();
}
