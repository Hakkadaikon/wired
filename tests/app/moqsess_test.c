#include "app/moqt/sess/moqsess.h"

#include "test.h"

/* draft-ietf-moq-transport-19 3.3 / 5.1 -- session establishment/control-
 * stream discipline and the subscribe lifecycle, translated from the
 * acceptance scenarios (each test lists initial state -> event sequence ->
 * expected state + expected output, matching the scenario content without
 * carrying over any tracking IDs). */

/* ===================== A. Session establishment ===================== */

/* Session establishment: both sides send/receive SETUP -> Established, no
 * error, buffering no longer required. */
static void test_moqsess_establish(void) {
  moqsess s;
  moqsess_init(&s);
  CHECK(moqsess_should_buffer(&s) == 1);
  CHECK(moqsess_step(&s, MOQSESS_EV_SENT_SETUP) == MOQSESS_CLOSE_NONE);
  CHECK(moqsess_established(&s) == 0);
  CHECK(moqsess_step(&s, MOQSESS_EV_RECV_SETUP) == MOQSESS_CLOSE_NONE);
  CHECK(moqsess_established(&s) == 1);
  CHECK(moqsess_should_buffer(&s) == 0);
}

/* Established session accepts a well-formed request: no buffering, no
 * close. (Delivery to the application is a run-layer concern; the session
 * machine's contribution is "do not buffer, do not close".) */
static void test_moqsess_established_accepts_request(void) {
  moqsess s;
  moqsess_init(&s);
  moqsess_step(&s, MOQSESS_EV_SENT_SETUP);
  moqsess_step(&s, MOQSESS_EV_RECV_SETUP);
  CHECK(moqsess_established(&s) == 1);
  CHECK(moqsess_should_buffer(&s) == 0);
  CHECK(s.state == MOQSESS_ESTABLISHED);
}

/* Pipelined request right after sending own SETUP (peer's not yet
 * received): the session is not closed while progressing toward
 * Established. */
static void test_moqsess_pipeline_before_peer_setup(void) {
  moqsess s;
  moqsess_init(&s);
  moqsess_step(&s, MOQSESS_EV_SENT_SETUP);
  CHECK(s.state == MOQSESS_SETUP_HALF);
  CHECK(moqsess_step(&s, MOQSESS_EV_RECV_SETUP) == MOQSESS_CLOSE_NONE);
  CHECK(moqsess_established(&s) == 1);
}

/* Request stream arriving before SETUP completes must be buffered; once
 * SETUP completes, buffering is no longer required so it can be handed to
 * the application (this test represents both the request-stream and the
 * data-stream buffering scenarios: moqsess_should_buffer is the same
 * gate for either). */
static void test_moqsess_buffer_before_setup_then_deliver(void) {
  moqsess s;
  moqsess_init(&s);
  CHECK(moqsess_should_buffer(&s) == 1); /* stream arrives here */
  moqsess_step(&s, MOQSESS_EV_RECV_SETUP);
  CHECK(moqsess_should_buffer(&s) == 1); /* still half-open */
  moqsess_step(&s, MOQSESS_EV_SENT_SETUP);
  CHECK(moqsess_should_buffer(&s) == 0); /* now deliverable */
}

/* A bidirectional stream may instead be reset while SETUP is incomplete;
 * once Established, that reset window is gone (should_buffer flips to
 * false so the run layer stops choosing the pre-setup reset path). */
static void test_moqsess_pre_setup_reset_window(void) {
  moqsess s;
  moqsess_init(&s);
  CHECK(moqsess_should_buffer(&s) == 1);
  moqsess_step(&s, MOQSESS_EV_SENT_SETUP);
  moqsess_step(&s, MOQSESS_EV_RECV_SETUP);
  CHECK(moqsess_should_buffer(&s) == 0);
}

/* Established session, one side sent GOAWAY: a new request from the peer
 * may be rejected with GOING_AWAY, and the session stays open. */
static void test_moqsess_goaway_reject_new_request(void) {
  moqsess s;
  moqsess_init(&s);
  moqsess_step(&s, MOQSESS_EV_SENT_SETUP);
  moqsess_step(&s, MOQSESS_EV_RECV_SETUP);
  CHECK(moqsess_step(&s, MOQSESS_EV_SEND_GOAWAY) == MOQSESS_CLOSE_NONE);
  CHECK(s.goaway_sent == 1);
  CHECK(s.state == MOQSESS_ESTABLISHED);
}

/* Established session, GOAWAY received: the receiver should not initiate
 * new requests of its own, and the session is not closed by GOAWAY alone
 * (draining to NO_ERROR close is a run-layer decision once all
 * subscriptions finish). */
static void test_moqsess_goaway_clean_shutdown(void) {
  moqsess s;
  moqsess_init(&s);
  moqsess_step(&s, MOQSESS_EV_SENT_SETUP);
  moqsess_step(&s, MOQSESS_EV_RECV_SETUP);
  CHECK(moqsess_step(&s, MOQSESS_EV_RECV_GOAWAY) == MOQSESS_CLOSE_NONE);
  CHECK(s.goaway_recv == 1);
  CHECK(s.state == MOQSESS_ESTABLISHED);
}

/* ---------- violation / abnormal ---------- */

/* Peer fails to close within the GOAWAY timeout: sender closes with
 * GOAWAY_TIMEOUT. */
static void test_moqsess_goaway_timeout_closes(void) {
  moqsess s;
  moqsess_init(&s);
  moqsess_step(&s, MOQSESS_EV_SEND_GOAWAY);
  CHECK(
      moqsess_step(&s, MOQSESS_EV_GOAWAY_TIMEOUT) ==
      MOQSESS_CLOSE_GOAWAY_TIMEOUT);
  CHECK(s.state == MOQSESS_CLOSED);
}

/* New request stream's first message is not a First-type message ->
 * PROTOCOL_VIOLATION; the request is never delivered (the run layer simply
 * never sees an application callback once the session is closed). */
static void test_moqsess_bad_first_message(void) {
  moqsess s;
  moqsess_init(&s);
  moqsess_step(&s, MOQSESS_EV_SENT_SETUP);
  moqsess_step(&s, MOQSESS_EV_RECV_SETUP);
  CHECK(
      moqsess_step(&s, MOQSESS_EV_BAD_FIRST) ==
      MOQSESS_CLOSE_PROTOCOL_VIOLATION);
}

/* Request ID parity does not match the sender -> INVALID_REQUEST_ID. */
static void test_moqsess_bad_request_id_parity(void) {
  moqsess s;
  moqsess_init(&s);
  moqsess_step(&s, MOQSESS_EV_SENT_SETUP);
  moqsess_step(&s, MOQSESS_EV_RECV_SETUP);
  CHECK(
      moqsess_step(&s, MOQSESS_EV_BAD_REQUEST_ID) ==
      MOQSESS_CLOSE_INVALID_REQUEST_ID);
}

/* A reused Request ID -> also INVALID_REQUEST_ID (same event/output as
 * parity violation; the codec layer distinguishes the two causes). */
static void test_moqsess_duplicate_request_id(void) {
  moqsess s;
  moqsess_init(&s);
  moqsess_step(&s, MOQSESS_EV_SENT_SETUP);
  moqsess_step(&s, MOQSESS_EV_RECV_SETUP);
  CHECK(
      moqsess_step(&s, MOQSESS_EV_BAD_REQUEST_ID) ==
      MOQSESS_CLOSE_INVALID_REQUEST_ID);
  CHECK(s.state == MOQSESS_CLOSED);
}

/* Unknown message type, or a Length/Body mismatch, on the control stream
 * -> PROTOCOL_VIOLATION. */
static void test_moqsess_malformed_control_message(void) {
  moqsess s;
  moqsess_init(&s);
  moqsess_step(&s, MOQSESS_EV_RECV_SETUP);
  CHECK(
      moqsess_step(&s, MOQSESS_EV_MALFORMED_CTRL) ==
      MOQSESS_CLOSE_PROTOCOL_VIOLATION);
}

/* Control stream closed at the transport layer -> PROTOCOL_VIOLATION. */
static void test_moqsess_ctrl_stream_transport_close(void) {
  moqsess s;
  moqsess_init(&s);
  moqsess_step(&s, MOQSESS_EV_SENT_SETUP);
  moqsess_step(&s, MOQSESS_EV_RECV_SETUP);
  CHECK(
      moqsess_step(&s, MOQSESS_EV_CTRL_CLOSED) ==
      MOQSESS_CLOSE_PROTOCOL_VIOLATION);
}

/* Unidirectional stream with an unknown head type identifier ->
 * PROTOCOL_VIOLATION. */
static void test_moqsess_unknown_uni_stream_type(void) {
  moqsess s;
  moqsess_init(&s);
  moqsess_step(&s, MOQSESS_EV_SENT_SETUP);
  moqsess_step(&s, MOQSESS_EV_RECV_SETUP);
  CHECK(
      moqsess_step(&s, MOQSESS_EV_UNKNOWN_UNI) ==
      MOQSESS_CLOSE_PROTOCOL_VIOLATION);
}

/* A 2nd GOAWAY on the same control stream -> PROTOCOL_VIOLATION. */
static void test_moqsess_second_goaway(void) {
  moqsess s;
  moqsess_init(&s);
  moqsess_step(&s, MOQSESS_EV_SENT_SETUP);
  moqsess_step(&s, MOQSESS_EV_RECV_SETUP);
  CHECK(moqsess_step(&s, MOQSESS_EV_RECV_GOAWAY) == MOQSESS_CLOSE_NONE);
  CHECK(
      moqsess_step(&s, MOQSESS_EV_RECV_GOAWAY) ==
      MOQSESS_CLOSE_PROTOCOL_VIOLATION);
}

/* Client GOAWAY with a non-zero New Session URI Length, received by the
 * server -> PROTOCOL_VIOLATION. */
static void test_moqsess_goaway_bad_uri(void) {
  moqsess s;
  moqsess_init(&s);
  moqsess_step(&s, MOQSESS_EV_SENT_SETUP);
  moqsess_step(&s, MOQSESS_EV_RECV_SETUP);
  CHECK(
      moqsess_step(&s, MOQSESS_EV_RECV_GOAWAY_BAD_URI) ==
      MOQSESS_CLOSE_PROTOCOL_VIOLATION);
}

/* Same peer opens a 2nd control stream -> PROTOCOL_VIOLATION (Session
 * notes decision 10, derived from the single-control-stream requirement). */
static void test_moqsess_second_control_stream(void) {
  moqsess s;
  moqsess_init(&s);
  moqsess_step(&s, MOQSESS_EV_SENT_SETUP);
  moqsess_step(&s, MOQSESS_EV_RECV_SETUP);
  CHECK(
      moqsess_step(&s, MOQSESS_EV_SECOND_CTRL) ==
      MOQSESS_CLOSE_PROTOCOL_VIOLATION);
}

/* Once closed, further events are no-ops: the close reason is sticky. */
static void test_moqsess_closed_is_sticky(void) {
  moqsess s;
  moqsess_init(&s);
  moqsess_step(&s, MOQSESS_EV_CTRL_CLOSED);
  CHECK(s.state == MOQSESS_CLOSED);
  CHECK(
      moqsess_step(&s, MOQSESS_EV_SENT_SETUP) ==
      MOQSESS_CLOSE_PROTOCOL_VIOLATION);
  CHECK(s.state == MOQSESS_CLOSED);
}

/* ===================== B. Subscribe lifecycle ===================== */

/* SUBSCRIBE -> SUBSCRIBE_OK establishes the subscription. */
static void test_moqsub_subscribe_establish(void) {
  moqsub s;
  moqsub_init(&s);
  CHECK(moqsub_step(&s, MOQSUB_EV_OPEN) == 1);
  CHECK(s.state == MOQSUB_PENDING);
  CHECK(moqsub_step(&s, MOQSUB_EV_OK) == 1);
  CHECK(s.state == MOQSUB_ESTABLISHED);
}

/* SUBSCRIBE rejected: REQUEST_ERROR terminates the subscription; no Object
 * is ever sent for it. */
static void test_moqsub_subscribe_rejected(void) {
  moqsub s;
  moqsub_init(&s);
  moqsub_step(&s, MOQSUB_EV_OPEN);
  CHECK(moqsub_step(&s, MOQSUB_EV_ERROR) == 1);
  CHECK(s.state == MOQSUB_TERMINATED);
}

/* ---------- violation / abnormal ---------- */

/* A 2nd response to the same request -> session-level protocol error, not
 * a local termination alone: session_fault is set. */
static void test_moqsub_duplicate_response_is_session_fault(void) {
  moqsub s;
  moqsub_init(&s);
  moqsub_step(&s, MOQSUB_EV_OPEN);
  CHECK(moqsub_step(&s, MOQSUB_EV_OK) == 1);
  CHECK(s.session_fault == 0);
  CHECK(moqsub_step(&s, MOQSUB_EV_OK) == 0);
  CHECK(s.session_fault == 1);
}

/* A second SUBSCRIBE on an open request is ignored (no re-open). */
static void test_moqsub_reopen_ignored(void) {
  moqsub s;
  moqsub_init(&s);
  moqsub_step(&s, MOQSUB_EV_OPEN);
  moqsub_step(&s, MOQSUB_EV_OK);
  CHECK(moqsub_step(&s, MOQSUB_EV_OPEN) == 0);
  CHECK(s.state == MOQSUB_ESTABLISHED);
}

/* A REQUEST_ERROR after SUBSCRIBE_OK is a second response: the
 * subscription stays established and session_fault is set. */
static void test_moqsub_error_after_ok_is_session_fault(void) {
  moqsub s;
  moqsub_init(&s);
  moqsub_step(&s, MOQSUB_EV_OPEN);
  moqsub_step(&s, MOQSUB_EV_OK);
  CHECK(moqsub_step(&s, MOQSUB_EV_ERROR) == 0);
  CHECK(s.session_fault == 1);
  CHECK(s.state == MOQSUB_ESTABLISHED);
}

/* A terminated subscription takes no further event, and an event outside
 * the table is ignored rather than indexed. */
static void test_moqsub_terminated_and_unknown_event(void) {
  moqsub s;
  moqsub_init(&s);
  moqsub_step(&s, MOQSUB_EV_OPEN);
  CHECK(moqsub_step(&s, (moqsub_event)99) == 0);
  CHECK(s.state == MOQSUB_PENDING);
  moqsub_step(&s, MOQSUB_EV_ERROR);
  CHECK(moqsub_step(&s, MOQSUB_EV_OK) == 0);
  CHECK(s.state == MOQSUB_TERMINATED);
}

/* An event outside the session table leaves the session open. */
static void test_moqsess_unknown_event_ignored(void) {
  moqsess s;
  moqsess_init(&s);
  moqsess_step(&s, MOQSESS_EV_SENT_SETUP);
  moqsess_step(&s, MOQSESS_EV_RECV_SETUP);
  CHECK(moqsess_step(&s, (moqsess_event)99) == MOQSESS_CLOSE_NONE);
  CHECK(moqsess_established(&s));
}

void test_moqsess(void) {
  test_moqsub_reopen_ignored();
  test_moqsub_error_after_ok_is_session_fault();
  test_moqsub_terminated_and_unknown_event();
  test_moqsess_unknown_event_ignored();
  test_moqsess_establish();
  test_moqsess_established_accepts_request();
  test_moqsess_pipeline_before_peer_setup();
  test_moqsess_buffer_before_setup_then_deliver();
  test_moqsess_pre_setup_reset_window();
  test_moqsess_goaway_reject_new_request();
  test_moqsess_goaway_clean_shutdown();
  test_moqsess_goaway_timeout_closes();
  test_moqsess_bad_first_message();
  test_moqsess_bad_request_id_parity();
  test_moqsess_duplicate_request_id();
  test_moqsess_malformed_control_message();
  test_moqsess_ctrl_stream_transport_close();
  test_moqsess_unknown_uni_stream_type();
  test_moqsess_second_goaway();
  test_moqsess_goaway_bad_uri();
  test_moqsess_second_control_stream();
  test_moqsess_closed_is_sticky();

  test_moqsub_subscribe_establish();
  test_moqsub_subscribe_rejected();
  test_moqsub_duplicate_response_is_session_fault();
}
