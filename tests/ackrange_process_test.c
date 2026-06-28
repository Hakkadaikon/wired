#include "test.h"

/* Encode an ACK frame from explicit [hi,lo] ranges (descending). */
static usz build_ack(u8 *buf, usz cap, const quic_ack_range *r, usz n)
{
    quic_ack_frame f;
    f.ack_delay = 0;
    f.has_ecn = 0;
    f.n_ranges = n;
    for (usz i = 0; i < n; i++) f.ranges[i] = r[i];
    return quic_ack_encode(buf, cap, &f);
}

/* RFC 9002 6 / RFC 9000 19.3: ACK frame range -> sent acked confirmation. */
void test_ackrange_process(void)
{
    u8 buf[64];
    u64 acked[16];
    usz n;

    /* contiguous range 3..5 acks exactly those sent packets */
    {
        quic_sentpkt t;
        quic_sentpkt_init(&t);
        for (u64 pn = 1; pn <= 5; pn++) quic_sentpkt_on_send(&t, pn, 0, 1, 1);
        quic_ack_range r[1] = {{5, 3}};
        usz len = build_ack(buf, sizeof buf, r, 1);
        CHECK(len > 0);
        CHECK(quic_ackrange_process(&t, buf, len, acked, &n) == 1);
        CHECK(n == 3);                      /* 5,4,3 acked */
        CHECK(quic_sentpkt_count(&t) == 2); /* 1,2 still in flight */
    }

    /* gap-separated ranges 7..8 and 3..4: 5,6 skipped, stay in flight */
    {
        quic_sentpkt t;
        quic_sentpkt_init(&t);
        for (u64 pn = 1; pn <= 8; pn++) quic_sentpkt_on_send(&t, pn, 0, 1, 1);
        quic_ack_range r[2] = {{8, 7}, {4, 3}};
        usz len = build_ack(buf, sizeof buf, r, 2);
        CHECK(len > 0);
        CHECK(quic_ackrange_process(&t, buf, len, acked, &n) == 1);
        CHECK(n == 4);                      /* 8,7,4,3 acked */
        CHECK(quic_sentpkt_count(&t) == 4); /* 1,2,5,6 remain */
    }

    /* malformed frame: report failure, nothing acked */
    {
        quic_sentpkt t;
        quic_sentpkt_init(&t);
        quic_sentpkt_on_send(&t, 1, 0, 1, 1);
        u8 bad[2] = {0x02, 0x00};
        CHECK(quic_ackrange_process(&t, bad, sizeof bad, acked, &n) == 0);
        CHECK(n == 0);
        CHECK(quic_sentpkt_count(&t) == 1);
    }
}
