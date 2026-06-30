#include "test.h"

#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/frame/ack.h"
#include "transport/packet/frame/frame/flowctl.h"

/* Wire one frame into buf via its encoder, returning the byte count. */

static void ds_init(quic_framedispatch_state *st, quic_stream_read *s,
                    quic_sentpkt *t, quic_flow_credit *c)
{
    quic_stream_read_init(s);
    quic_sentpkt_init(t);
    quic_flow_credit_init(c, 0);
    st->stream = s;
    st->sent = t;
    st->credit = c;
    st->ack_eliciting = 0;
    st->close = 0;
}

/* STREAM frame delivers bytes the application can pull back. */
static void test_dispatch_stream(void)
{
    quic_framedispatch_state st;
    quic_stream_read s; quic_sentpkt t; quic_flow_credit c;
    ds_init(&st, &s, &t, &c);
    u8 buf[32];
    quic_stream_frame f = {3, 0, 4, (const u8 *)"data", 0};
    usz n = quic_frame_put_stream(buf, sizeof buf, &f);
    CHECK(quic_framedispatch_handle(&st, buf[0], buf, n) == 1);
    u8 out[8]; usz got = 0;
    quic_stream_read_pull(&s, out, sizeof out, &got);
    CHECK(got == 4);
    CHECK(st.ack_eliciting == 1);
}

/* ACK frame removes acknowledged packets from the sent table. */
static void test_dispatch_ack(void)
{
    quic_framedispatch_state st;
    quic_stream_read s; quic_sentpkt t; quic_flow_credit c;
    ds_init(&st, &s, &t, &c);
    for (u64 pn = 1; pn <= 5; pn++) quic_sentpkt_on_send(&t, pn, 0, 1, 1);
    quic_ack_frame f;
    for (usz i = 0; i < sizeof f; i++) ((u8 *)&f)[i] = 0;
    f.n_ranges = 1; f.ranges[0].hi = 5; f.ranges[0].lo = 3;
    u8 buf[32];
    usz n = quic_ack_encode(buf, sizeof buf, &f);
    CHECK(quic_framedispatch_handle(&st, buf[0], buf, n) == 1);
    CHECK(quic_sentpkt_count(&t) == 2);   /* 5,4,3 acked; 1,2 remain */
    CHECK(st.ack_eliciting == 0);          /* ACK is not ack-eliciting */
}

/* MAX_DATA frame raises the flow credit limit. */
static void test_dispatch_max_data(void)
{
    quic_framedispatch_state st;
    quic_stream_read s; quic_sentpkt t; quic_flow_credit c;
    ds_init(&st, &s, &t, &c);
    quic_data_frame f = {9000};
    u8 buf[16];
    usz n = quic_max_data_encode(buf, sizeof buf, &f);
    CHECK(quic_framedispatch_handle(&st, buf[0], buf, n) == 1);
    CHECK(quic_flow_credit_violation(&c, 9000) == 0);
    CHECK(quic_flow_credit_violation(&c, 9001) == 1);
}

/* PING sets the ack-eliciting flag and nothing else. */
static void test_dispatch_ping(void)
{
    quic_framedispatch_state st;
    quic_stream_read s; quic_sentpkt t; quic_flow_credit c;
    ds_init(&st, &s, &t, &c);
    u8 buf[1] = {QUIC_FRAME_PING};
    CHECK(quic_framedispatch_handle(&st, buf[0], buf, 1) == 1);
    CHECK(st.ack_eliciting == 1);
    CHECK(st.close == 0);
}

/* CONNECTION_CLOSE sets the close flag. */
static void test_dispatch_close(void)
{
    quic_framedispatch_state st;
    quic_stream_read s; quic_sentpkt t; quic_flow_credit c;
    ds_init(&st, &s, &t, &c);
    quic_conn_close_frame f = {0, 7, 0, 0, (const u8 *)0};
    u8 buf[16];
    usz n = quic_frame_put_conn_close(buf, sizeof buf, &f);
    CHECK(quic_framedispatch_handle(&st, buf[0], buf, n) == 1);
    CHECK(st.close == 1);
    CHECK(st.ack_eliciting == 0);          /* CONNECTION_CLOSE is exempt */
}

/* PADDING is ignored and is not ack-eliciting. */
static void test_dispatch_padding(void)
{
    quic_framedispatch_state st;
    quic_stream_read s; quic_sentpkt t; quic_flow_credit c;
    ds_init(&st, &s, &t, &c);
    u8 buf[1] = {QUIC_FRAME_PADDING};
    CHECK(quic_framedispatch_handle(&st, buf[0], buf, 1) == 1);
    CHECK(st.ack_eliciting == 0);
    CHECK(st.close == 0);
}

/* Unknown frame type is rejected. */
static void test_dispatch_unknown(void)
{
    quic_framedispatch_state st;
    quic_stream_read s; quic_sentpkt t; quic_flow_credit c;
    ds_init(&st, &s, &t, &c);
    u8 buf[1] = {0x7f};
    CHECK(quic_framedispatch_handle(&st, 0x7f, buf, 1) == 0);
}

/* Standalone ack-eliciting predicate (RFC 9000 13.2.1). */
static void test_dispatch_ack_eliciting_predicate(void)
{
    CHECK(quic_framedispatch_ack_eliciting(QUIC_FRAME_PADDING) == 0);
    CHECK(quic_framedispatch_ack_eliciting(QUIC_FRAME_ACK) == 0);
    CHECK(quic_framedispatch_ack_eliciting(QUIC_FRAME_ACK_ECN) == 0);
    CHECK(quic_framedispatch_ack_eliciting(QUIC_FRAME_CONN_CLOSE_TPT) == 0);
    CHECK(quic_framedispatch_ack_eliciting(QUIC_FRAME_CONN_CLOSE_APP) == 0);
    CHECK(quic_framedispatch_ack_eliciting(QUIC_FRAME_PING) == 1);
    CHECK(quic_framedispatch_ack_eliciting(QUIC_FRAME_STREAM_BASE) == 1);
    CHECK(quic_framedispatch_ack_eliciting(QUIC_FRAME_MAX_DATA) == 1);
}

void test_dispatch_state(void)
{
    test_dispatch_stream();
    test_dispatch_ack();
    test_dispatch_max_data();
    test_dispatch_ping();
    test_dispatch_close();
    test_dispatch_padding();
    test_dispatch_unknown();
    test_dispatch_ack_eliciting_predicate();
}
