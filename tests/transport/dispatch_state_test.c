#include "app/datagram/datagram/datagram.h"
#include "test.h"
#include "transport/packet/frame/frame/ack.h"
#include "transport/packet/frame/frame/connctl.h"
#include "transport/packet/frame/frame/flowctl.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/frame/stream_ctl.h"

/* Wire one frame into buf via its encoder, returning the byte count. */

static void ds_init(
    framedispatch_state* st, stream_read* s, sentpkt* t, flow_credit* c) {
  stream_read_init(s);
  sentpkt_init(t);
  flow_credit_init(c, 0);
  st->stream            = s;
  st->sent              = t;
  st->credit            = c;
  st->ack_eliciting     = 0;
  st->close             = 0;
  st->has_datagram      = 0;
  st->violation         = 0;
  st->stop_sending_owed = 0;
  st->has_reset_stream  = 0;
}

/* STREAM frame delivers bytes the application can pull back. */
static void test_dispatch_stream(void) {
  framedispatch_state st;
  stream_read         s;
  sentpkt             t;
  flow_credit         c;
  ds_init(&st, &s, &t, &c);
  u8           buf[32];
  stream_frame f = {3, 0, 4, (const u8*)"data", 0};
  usz          n = frame_put_stream(buf, sizeof buf, &f);
  CHECK(framedispatch_handle(&st, buf[0], wired_span_of(buf, n)) == 1);
  u8         out[8];
  wired_obuf ob = obuf_of(out, sizeof out);
  stream_read_pull(&s, &ob);
  CHECK(ob.len == 4);
  CHECK(st.ack_eliciting == 1);
}

/* ACK frame removes acknowledged packets from the sent table. */
static void test_dispatch_ack(void) {
  framedispatch_state st;
  stream_read         s;
  sentpkt             t;
  flow_credit         c;
  ds_init(&st, &s, &t, &c);
  for (u64 pn = 1; pn <= 5; pn++)
    sentpkt_on_send(&t, &(sentpkt_out){pn, 0, 1, 1});
  ack_frame f;
  for (usz i = 0; i < sizeof f; i++) ((u8*)&f)[i] = 0;
  f.n_ranges     = 1;
  f.ranges[0].hi = 5;
  f.ranges[0].lo = 3;
  u8  buf[32];
  usz n = ack_encode(buf, sizeof buf, &f);
  CHECK(framedispatch_handle(&st, buf[0], wired_span_of(buf, n)) == 1);
  CHECK(sentpkt_count(&t) == 2); /* 5,4,3 acked; 1,2 remain */
  CHECK(st.ack_eliciting == 0);  /* ACK is not ack-eliciting */
}

/* MAX_DATA frame raises the flow credit limit. */
static void test_dispatch_max_data(void) {
  framedispatch_state st;
  stream_read         s;
  sentpkt             t;
  flow_credit         c;
  ds_init(&st, &s, &t, &c);
  data_frame f = {9000};
  u8         buf[16];
  usz        n = max_data_encode(buf, sizeof buf, &f);
  CHECK(framedispatch_handle(&st, buf[0], wired_span_of(buf, n)) == 1);
  CHECK(flow_credit_violation(&c, 9000) == 0);
  CHECK(flow_credit_violation(&c, 9001) == 1);
}

/* PING sets the ack-eliciting flag and nothing else. */
static void test_dispatch_ping(void) {
  framedispatch_state st;
  stream_read         s;
  sentpkt             t;
  flow_credit         c;
  ds_init(&st, &s, &t, &c);
  u8 buf[1] = {FRAME_PING};
  CHECK(framedispatch_handle(&st, buf[0], wired_span_of(buf, 1)) == 1);
  CHECK(st.ack_eliciting == 1);
  CHECK(st.close == 0);
}

/* CONNECTION_CLOSE sets the close flag. */
static void test_dispatch_close(void) {
  framedispatch_state st;
  stream_read         s;
  sentpkt             t;
  flow_credit         c;
  ds_init(&st, &s, &t, &c);
  conn_close_frame f = {0, 7, 0, 0, (const u8*)0};
  u8               buf[16];
  usz              n = frame_put_conn_close(buf, sizeof buf, &f);
  CHECK(framedispatch_handle(&st, buf[0], wired_span_of(buf, n)) == 1);
  CHECK(st.close == 1);
  CHECK(st.ack_eliciting == 0); /* CONNECTION_CLOSE is exempt */
}

/* PADDING is ignored and is not ack-eliciting. */
static void test_dispatch_padding(void) {
  framedispatch_state st;
  stream_read         s;
  sentpkt             t;
  flow_credit         c;
  ds_init(&st, &s, &t, &c);
  u8 buf[1] = {FRAME_PADDING};
  CHECK(framedispatch_handle(&st, buf[0], wired_span_of(buf, 1)) == 1);
  CHECK(st.ack_eliciting == 0);
  CHECK(st.close == 0);
}

/* RFC 9221 5: a DATAGRAM frame is decoded and its payload exposed on state. */
static void test_dispatch_datagram(void) {
  framedispatch_state st;
  stream_read         s;
  sentpkt             t;
  flow_credit         c;
  ds_init(&st, &s, &t, &c);
  datagram_frame f = {4, (const u8*)"data"};
  u8             buf[16];
  usz            n = datagram_encode(wired_mspan_of(buf, sizeof buf), &f, 1);
  CHECK(n != 0);
  CHECK(framedispatch_handle(&st, buf[0], wired_span_of(buf, n)) == 1);
  CHECK(st.has_datagram == 1);
  CHECK(st.datagram.n == 4);
  CHECK(st.datagram.p[0] == 'd' && st.datagram.p[3] == 'a');
  CHECK(st.ack_eliciting == 1); /* RFC 9221 4: DATAGRAM is ack-eliciting */
}

/* A DATAGRAM frame whose LEN varint overruns the buffer is malformed and
 * rejected, leaving has_datagram unset. */
static void test_dispatch_datagram_malformed(void) {
  framedispatch_state st;
  stream_read         s;
  sentpkt             t;
  flow_credit         c;
  ds_init(&st, &s, &t, &c);
  u8 buf[3] = {FRAME_DATAGRAM_LEN, 0x40, 0xff}; /* length varint = 255 */
  CHECK(framedispatch_handle(&st, buf[0], wired_span_of(buf, sizeof buf)) == 0);
  CHECK(st.has_datagram == 0);
}

/* Unknown frame type is rejected. */
static void test_dispatch_unknown(void) {
  framedispatch_state st;
  stream_read         s;
  sentpkt             t;
  flow_credit         c;
  ds_init(&st, &s, &t, &c);
  u8 buf[1] = {0x7f};
  CHECK(framedispatch_handle(&st, 0x7f, wired_span_of(buf, 1)) == 0);
}

/* RFC 9000 19.7: a server receiving NEW_TOKEN is a protocol violation. */
static void test_dispatch_new_token_violation(void) {
  framedispatch_state st;
  stream_read         s;
  sentpkt             t;
  flow_credit         c;
  ds_init(&st, &s, &t, &c);
  new_token_frame f = {4, (const u8*)"tokn"};
  u8              buf[16];
  usz             n = new_token_encode(buf, sizeof buf, &f);
  CHECK(framedispatch_handle(&st, FRAME_NEW_TOKEN, wired_span_of(buf, n)) == 0);
  CHECK(st.violation == 1);
}

/* RFC 9000 19.20: a server receiving HANDSHAKE_DONE is a protocol
 * violation. */
static void test_dispatch_handshake_done_violation(void) {
  framedispatch_state st;
  stream_read         s;
  sentpkt             t;
  flow_credit         c;
  ds_init(&st, &s, &t, &c);
  u8  buf[1];
  usz n = handshake_done_encode(buf, sizeof buf);
  CHECK(
      framedispatch_handle(&st, FRAME_HANDSHAKE_DONE, wired_span_of(buf, n)) ==
      0);
  CHECK(st.violation == 1);
}

/* A frame a server may legitimately receive leaves violation unset. */
static void test_dispatch_no_violation_on_normal_frame(void) {
  framedispatch_state st;
  stream_read         s;
  sentpkt             t;
  flow_credit         c;
  ds_init(&st, &s, &t, &c);
  u8 buf[1] = {FRAME_PING};
  CHECK(framedispatch_handle(&st, buf[0], wired_span_of(buf, 1)) == 1);
  CHECK(st.violation == 0);
}

/* Standalone ack-eliciting predicate (RFC 9000 13.2.1). */
static void test_dispatch_ack_eliciting_predicate(void) {
  CHECK(framedispatch_ack_eliciting(FRAME_PADDING) == 0);
  CHECK(framedispatch_ack_eliciting(FRAME_ACK) == 0);
  CHECK(framedispatch_ack_eliciting(FRAME_ACK_ECN) == 0);
  CHECK(framedispatch_ack_eliciting(FRAME_CONN_CLOSE_TPT) == 0);
  CHECK(framedispatch_ack_eliciting(FRAME_CONN_CLOSE_APP) == 0);
  CHECK(framedispatch_ack_eliciting(FRAME_PING) == 1);
  CHECK(framedispatch_ack_eliciting(FRAME_STREAM_BASE) == 1);
  CHECK(framedispatch_ack_eliciting(FRAME_MAX_DATA) == 1);
}

/* RFC 9000 3.5: STOP_SENDING makes the receiving endpoint owe an automatic
 * RESET_STREAM echoing the same stream ID and error code. */
static void test_dispatch_stop_sending_owes_reset(void) {
  framedispatch_state st;
  stream_read         s;
  sentpkt             t;
  flow_credit         c;
  ds_init(&st, &s, &t, &c);
  stop_sending_frame f = {.stream_id = 9, .error_code = 0x42};
  u8                 buf[16];
  usz                n = stop_sending_encode(buf, sizeof buf, &f);
  CHECK(
      framedispatch_handle(&st, FRAME_STOP_SENDING, wired_span_of(buf, n)) ==
      1);
  CHECK(st.stop_sending_owed == 1);
  CHECK(st.stop_sending_stream_id == 9);
  CHECK(st.stop_sending_error_code == 0x42);
  CHECK(st.ack_eliciting == 1);
}

/* RFC 9000 19.4: RESET_STREAM is decoded and its stream ID/error code
 * exposed on state. */
static void test_dispatch_reset_stream(void) {
  framedispatch_state st;
  stream_read         s;
  sentpkt             t;
  flow_credit         c;
  ds_init(&st, &s, &t, &c);
  reset_stream_frame f = {.stream_id = 3, .error_code = 0x9, .final_size = 100};
  u8                 buf[32];
  usz                n = reset_stream_encode(buf, sizeof buf, &f);
  CHECK(
      framedispatch_handle(&st, FRAME_RESET_STREAM, wired_span_of(buf, n)) ==
      1);
  CHECK(st.has_reset_stream == 1);
  CHECK(st.reset_stream_stream_id == 3);
  CHECK(st.reset_stream_error_code == 0x9);
}

void test_dispatch_state(void) {
  test_dispatch_stream();
  test_dispatch_ack();
  test_dispatch_max_data();
  test_dispatch_ping();
  test_dispatch_close();
  test_dispatch_padding();
  test_dispatch_datagram();
  test_dispatch_datagram_malformed();
  test_dispatch_unknown();
  test_dispatch_new_token_violation();
  test_dispatch_handshake_done_violation();
  test_dispatch_no_violation_on_normal_frame();
  test_dispatch_ack_eliciting_predicate();
  test_dispatch_stop_sending_owes_reset();
  test_dispatch_reset_stream();
}
