#include "test.h"
#include "frame/ack.c"

/* Single contiguous range round-trips: acks 10..7 (largest 10, first 3). */
static void test_ack_single_range(void)
{
    quic_ack_frame in = {.ack_delay = 25, .n_ranges = 1};
    in.ranges[0].hi = 10; in.ranges[0].lo = 7;
    u8 buf[32];
    usz w = quic_ack_encode(buf, sizeof(buf), &in);
    CHECK(w != 0 && buf[0] == QUIC_FRAME_ACK);

    quic_ack_frame out;
    usz r = quic_ack_decode(buf, w, &out);
    CHECK(r == w && out.n_ranges == 1 && out.ack_delay == 25);
    CHECK(out.ranges[0].hi == 10 && out.ranges[0].lo == 7);
}

/* Multiple ranges with gaps: acks {20..18, 15..15, 12..10}. */
static void test_ack_multi_range(void)
{
    quic_ack_frame in = {.ack_delay = 0, .n_ranges = 3};
    in.ranges[0].hi = 20; in.ranges[0].lo = 18;
    in.ranges[1].hi = 15; in.ranges[1].lo = 15;
    in.ranges[2].hi = 12; in.ranges[2].lo = 10;
    u8 buf[64];
    usz w = quic_ack_encode(buf, sizeof(buf), &in);
    CHECK(w != 0);

    quic_ack_frame out;
    usz r = quic_ack_decode(buf, w, &out);
    CHECK(r == w && out.n_ranges == 3);
    CHECK(out.ranges[0].hi == 20 && out.ranges[0].lo == 18);
    CHECK(out.ranges[1].hi == 15 && out.ranges[1].lo == 15);
    CHECK(out.ranges[2].hi == 12 && out.ranges[2].lo == 10);
}

static void test_ack_truncated(void)
{
    quic_ack_frame in = {.ack_delay = 0, .n_ranges = 2};
    in.ranges[0].hi = 8; in.ranges[0].lo = 8;
    in.ranges[1].hi = 5; in.ranges[1].lo = 4;
    u8 buf[64];
    usz w = quic_ack_encode(buf, sizeof(buf), &in);
    quic_ack_frame out;
    CHECK(quic_ack_decode(buf, w - 1, &out) == 0); /* second pair cut short */
    /* empty range set is rejected on encode */
    quic_ack_frame empty = {.ack_delay = 0, .n_ranges = 0};
    CHECK(quic_ack_encode(buf, sizeof(buf), &empty) == 0);
}

/* Type 0x03 carries ECN counts (ECT0, ECT1, CE) after the ranges. */
static void test_ack_ecn(void)
{
    quic_ack_frame in = {.ack_delay = 10, .n_ranges = 1, .has_ecn = 1,
                         .ect0 = 100, .ect1 = 5, .ce = 2};
    in.ranges[0].hi = 50; in.ranges[0].lo = 48;
    u8 buf[48];
    usz w = quic_ack_encode(buf, sizeof(buf), &in);
    CHECK(w != 0 && buf[0] == QUIC_FRAME_ACK_ECN);

    quic_ack_frame out;
    usz r = quic_ack_decode(buf, w, &out);
    CHECK(r == w && out.has_ecn == 1);
    CHECK(out.ect0 == 100 && out.ect1 == 5 && out.ce == 2);
    CHECK(out.ranges[0].hi == 50 && out.ranges[0].lo == 48);

    /* a plain 0x02 frame decodes with has_ecn == 0 and no ECN counts */
    quic_ack_frame plain = {.ack_delay = 0, .n_ranges = 1, .has_ecn = 0};
    plain.ranges[0].hi = 9; plain.ranges[0].lo = 9;
    usz pw = quic_ack_encode(buf, sizeof(buf), &plain);
    quic_ack_frame pout;
    CHECK(quic_ack_decode(buf, pw, &pout) == pw && pout.has_ecn == 0);
}

void test_ack(void)
{
    test_ack_single_range();
    test_ack_multi_range();
    test_ack_truncated();
    test_ack_ecn();
}
