#include "test.h"

/* A stream arriving before establishment is buffered, then becomes
 * associated once the session is established (no rejection, no data loss). */
static void test_stream_buffered_then_established(void) {
  wired_wt_session s;
  wired_wt_session_init(&s, 4);
  CHECK(wired_wt_session_offer_stream(&s, 8) == 1);
  CHECK(s.streams[0].in_use == 1);
  CHECK(s.streams[0].stream_id == 8);
  CHECK(wired_wt_session_establish(&s) == 1);
  CHECK(s.state == WIRED_WT_ESTABLISHED);
  /* the buffered slot is still considered live (associated) post-establish */
  CHECK(s.streams[0].in_use == 1);
}

/* A datagram arriving before establishment is buffered similarly. */
static void test_datagram_buffered_then_established(void) {
  wired_wt_session s;
  u8               payload[3] = {1, 2, 3};
  wired_wt_session_init(&s, 4);
  CHECK(wired_wt_session_offer_datagram(&s, wired_span_of(payload, 3)) == 1);
  CHECK(s.datagrams[0].in_use == 1);
  CHECK(s.datagrams[0].len == 3);
  CHECK(s.datagrams[0].data[0] == 1);
  CHECK(s.datagrams[0].data[2] == 3);
  CHECK(wired_wt_session_establish(&s) == 1);
  CHECK(s.datagrams[0].in_use == 1);
}

/* Exceeding the stream buffer limit rejects the (N+1)th offer; the buffer
 * still holds exactly N entries. */
static void test_stream_buffer_limit_rejects_overflow(void) {
  wired_wt_session s;
  wired_wt_session_init(&s, 4);
  for (u64 i = 0; i < WIRED_WT_MAX_BUFFERED_STREAMS; i++)
    CHECK(wired_wt_session_offer_stream(&s, i + 100) == 1);
  CHECK(wired_wt_session_offer_stream(&s, 999) == 0);
  int used = 0;
  for (usz i = 0; i < WIRED_WT_MAX_BUFFERED_STREAMS; i++)
    if (s.streams[i].in_use) used++;
  CHECK(used == WIRED_WT_MAX_BUFFERED_STREAMS);
}

/* Exceeding the datagram buffer limit drops the (N+1)th offer (drop-newest);
 * existing buffered datagrams are unchanged. */
static void test_datagram_buffer_limit_drops_overflow(void) {
  wired_wt_session s;
  u8               a                = 0xaa;
  u8               overflow_payload = 0xff;
  wired_wt_session_init(&s, 4);
  for (u64 i = 0; i < WIRED_WT_MAX_BUFFERED_DATAGRAMS; i++)
    CHECK(wired_wt_session_offer_datagram(&s, wired_span_of(&a, 1)) == 1);
  CHECK(
      wired_wt_session_offer_datagram(
          &s, wired_span_of(&overflow_payload, 1)) == 0);
  for (usz i = 0; i < WIRED_WT_MAX_BUFFERED_DATAGRAMS; i++) {
    CHECK(s.datagrams[i].in_use == 1);
    CHECK(s.datagrams[i].data[0] == 0xaa);
  }
}

/* close() from established reaches CLOSED. */
static void test_close_from_established(void) {
  wired_wt_session s;
  wired_wt_session_init(&s, 4);
  wired_wt_session_establish(&s);
  CHECK(wired_wt_session_close(&s) == 1);
  CHECK(s.state == WIRED_WT_CLOSED);
}

/* close() from draining also reaches CLOSED -- draining sessions can still
 * close via either trigger. */
static void test_close_from_draining(void) {
  wired_wt_session s;
  wired_wt_session_init(&s, 4);
  wired_wt_session_establish(&s);
  wired_wt_session_drain(&s);
  CHECK(s.state == WIRED_WT_DRAINING);
  CHECK(wired_wt_session_close(&s) == 1);
  CHECK(s.state == WIRED_WT_CLOSED);
}

/* drain() from established reaches DRAINING, not CLOSED -- drain is
 * advisory, not terminal. */
static void test_drain_is_advisory_not_terminal(void) {
  wired_wt_session s;
  wired_wt_session_init(&s, 4);
  wired_wt_session_establish(&s);
  CHECK(wired_wt_session_drain(&s) == 1);
  CHECK(s.state == WIRED_WT_DRAINING);
  CHECK(s.state != WIRED_WT_CLOSED);
}

/* closed is absorbing: further establish/drain/close calls no-op. */
static void test_closed_is_absorbing(void) {
  wired_wt_session s;
  wired_wt_session_init(&s, 4);
  wired_wt_session_establish(&s);
  wired_wt_session_close(&s);
  CHECK(wired_wt_session_establish(&s) == 0);
  CHECK(wired_wt_session_drain(&s) == 0);
  CHECK(wired_wt_session_close(&s) == 0);
  CHECK(s.state == WIRED_WT_CLOSED);
}

/* After establish, a brand-new stream (never buffered) associates directly
 * rather than routing through the pre-establishment buffering path -- proves
 * established-state offers don't accidentally still buffer. */
static void test_established_new_stream_associates_directly(void) {
  wired_wt_session s;
  wired_wt_session_init(&s, 4);
  wired_wt_session_establish(&s);
  CHECK(wired_wt_session_offer_stream(&s, 42) == 1);
  /* no buffer slot was consumed: buffering only matters pre-establishment */
  for (usz i = 0; i < WIRED_WT_MAX_BUFFERED_STREAMS; i++)
    CHECK(s.streams[i].in_use == 0);
}

/* A freshly-initialized session has no WT_MAX_STREAMS/WT_MAX_DATA limit
 * recorded yet, so opening a stream or sending data is always allowed
 * (flow control is opt-in per SS5.1). */
static void test_flow_control_unset_limit_always_allows(void) {
  wired_wt_session s;
  wired_wt_session_init(&s, 4);
  CHECK(wired_wt_session_stream_open_allowed(&s, 1) == 1);
  CHECK(wired_wt_session_stream_open_allowed(&s, 0) == 1);
  CHECK(wired_wt_session_data_send_allowed(&s, 1000000) == 1);
}

/* Setting WT_MAX_STREAMS(bidi) to 2 allows opening exactly 2 bidi streams,
 * then rejects the 3rd -- WTH3-057/058. The uni limit is independent and
 * stays unset (still unconditionally allowed). */
static void test_flow_control_max_streams_bidi_enforced(void) {
  wired_wt_session s;
  wired_wt_session_init(&s, 4);
  CHECK(wired_wt_session_set_max_streams(&s, 1, 2) == 1);

  CHECK(wired_wt_session_stream_open_allowed(&s, 1) == 1);
  wired_wt_session_note_stream_opened(&s, 1);
  CHECK(wired_wt_session_stream_open_allowed(&s, 1) == 1);
  wired_wt_session_note_stream_opened(&s, 1);
  CHECK(wired_wt_session_stream_open_allowed(&s, 1) == 0);

  CHECK(wired_wt_session_stream_open_allowed(&s, 0) == 1);
}

/* The uni limit is tracked separately from bidi. */
static void test_flow_control_max_streams_uni_enforced(void) {
  wired_wt_session s;
  wired_wt_session_init(&s, 4);
  CHECK(wired_wt_session_set_max_streams(&s, 0, 1) == 1);
  CHECK(wired_wt_session_stream_open_allowed(&s, 0) == 1);
  wired_wt_session_note_stream_opened(&s, 0);
  CHECK(wired_wt_session_stream_open_allowed(&s, 0) == 0);
  CHECK(wired_wt_session_stream_open_allowed(&s, 1) == 1);
}

/* WT_MAX_STREAMS values are cumulative and delivered in order: a value
 * lower than one already recorded must be rejected by the setter (the
 * caller is then responsible for closing the session with
 * WT_FLOW_CONTROL_ERROR) and must not overwrite the stored limit. */
static void test_flow_control_max_streams_decreasing_rejected(void) {
  wired_wt_session s;
  wired_wt_session_init(&s, 4);
  CHECK(wired_wt_session_set_max_streams(&s, 1, 5) == 1);
  CHECK(wired_wt_session_set_max_streams(&s, 1, 3) == 0);
  /* still enforces the higher, previously-recorded limit */
  for (u64 i = 0; i < 5; i++) {
    CHECK(wired_wt_session_stream_open_allowed(&s, 1) == 1);
    wired_wt_session_note_stream_opened(&s, 1);
  }
  CHECK(wired_wt_session_stream_open_allowed(&s, 1) == 0);
}

/* Re-sending the same WT_MAX_STREAMS value is not a decrease -- accepted. */
static void test_flow_control_max_streams_equal_value_accepted(void) {
  wired_wt_session s;
  wired_wt_session_init(&s, 4);
  CHECK(wired_wt_session_set_max_streams(&s, 1, 5) == 1);
  CHECK(wired_wt_session_set_max_streams(&s, 1, 5) == 1);
}

/* WT_MAX_DATA enforcement: exactly at the limit is allowed, one byte over is
 * not -- WTH3-060/061. */
static void test_flow_control_max_data_enforced(void) {
  wired_wt_session s;
  wired_wt_session_init(&s, 4);
  CHECK(wired_wt_session_set_max_data(&s, 100) == 1);
  CHECK(wired_wt_session_data_send_allowed(&s, 100) == 1);
  wired_wt_session_note_data_sent(&s, 60);
  CHECK(wired_wt_session_data_send_allowed(&s, 40) == 1);
  CHECK(wired_wt_session_data_send_allowed(&s, 41) == 0);
  wired_wt_session_note_data_sent(&s, 40);
  CHECK(wired_wt_session_data_send_allowed(&s, 1) == 0);
}

/* WT_MAX_DATA values are also cumulative/in-order: a decrease is rejected
 * and does not overwrite the stored limit. */
static void test_flow_control_max_data_decreasing_rejected(void) {
  wired_wt_session s;
  wired_wt_session_init(&s, 4);
  CHECK(wired_wt_session_set_max_data(&s, 1000) == 1);
  CHECK(wired_wt_session_set_max_data(&s, 500) == 0);
  CHECK(wired_wt_session_data_send_allowed(&s, 1000) == 1);
  CHECK(wired_wt_session_data_send_allowed(&s, 1001) == 0);
}

void test_wt_session(void) {
  test_stream_buffered_then_established();
  test_datagram_buffered_then_established();
  test_stream_buffer_limit_rejects_overflow();
  test_datagram_buffer_limit_drops_overflow();
  test_close_from_established();
  test_close_from_draining();
  test_drain_is_advisory_not_terminal();
  test_closed_is_absorbing();
  test_established_new_stream_associates_directly();
  test_flow_control_unset_limit_always_allows();
  test_flow_control_max_streams_bidi_enforced();
  test_flow_control_max_streams_uni_enforced();
  test_flow_control_max_streams_decreasing_rejected();
  test_flow_control_max_streams_equal_value_accepted();
  test_flow_control_max_data_enforced();
  test_flow_control_max_data_decreasing_rejected();
}
