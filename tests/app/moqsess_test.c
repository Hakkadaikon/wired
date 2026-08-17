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
 * received): still not rejected -- may_reject_request stays false and the
 * session is not closed while progressing toward Established. */
static void test_moqsess_pipeline_before_peer_setup(void) {
  moqsess s;
  moqsess_init(&s);
  moqsess_step(&s, MOQSESS_EV_SENT_SETUP);
  CHECK(s.state == MOQSESS_SETUP_HALF);
  CHECK(moqsess_may_reject_request(&s) == 0);
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
  CHECK(moqsess_may_reject_request(&s) == 1);
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
  CHECK(moqsess_suppress_own_requests(&s) == 1);
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
  moqsub_init(&s, MOQSUB_ROLE_SUBSCRIBER);
  CHECK(moqsub_step(&s, MOQSUB_EV_OPEN) == 1);
  CHECK(s.state == MOQSUB_PENDING);
  CHECK(moqsub_step(&s, MOQSUB_EV_OK) == 1);
  CHECK(moqsub_established(&s) == 1);
}

/* Established (SUBSCRIBE-initiated) subscription may forward Objects when
 * FORWARD == 1. */
static void test_moqsub_object_delivery_after_subscribe(void) {
  moqsub s;
  moqsub_init(&s, MOQSUB_ROLE_SUBSCRIBER);
  moqsub_step(&s, MOQSUB_EV_OPEN);
  moqsub_step(&s, MOQSUB_EV_OK);
  CHECK(moqsub_may_forward(&s, 1) == 1);
}

/* PUBLISH -> PUBLISH_OK (REQUEST_OK) establishes the subscription. */
static void test_moqsub_publish_establish(void) {
  moqsub s;
  moqsub_init(&s, MOQSUB_ROLE_PUBLISHER);
  moqsub_step(&s, MOQSUB_EV_OPEN);
  CHECK(moqsub_step(&s, MOQSUB_EV_OK) == 1);
  CHECK(moqsub_established(&s) == 1);
}

/* An Object sent before PUBLISH_OK is still deliverable (Pending(Publisher)
 * allows forwarding); the later PUBLISH_OK still establishes normally. */
static void test_moqsub_object_before_publish_ok(void) {
  moqsub s;
  moqsub_init(&s, MOQSUB_ROLE_PUBLISHER);
  moqsub_step(&s, MOQSUB_EV_OPEN);
  CHECK(moqsub_may_forward(&s, 1) == 1); /* Object arrives here */
  CHECK(moqsub_step(&s, MOQSUB_EV_OK) == 1);
  CHECK(moqsub_established(&s) == 1);
}

/* Forward State 0: no Object may be forwarded even once established;
 * control messages (OK/PUBLISH_DONE) are unaffected by the gate. */
static void test_moqsub_forward_state_zero_blocks_objects(void) {
  moqsub s;
  moqsub_init(&s, MOQSUB_ROLE_SUBSCRIBER);
  moqsub_step(&s, MOQSUB_EV_OPEN);
  moqsub_step(&s, MOQSUB_EV_OK);
  CHECK(moqsub_may_forward(&s, 0) == 0);
  CHECK(moqsub_established(&s) == 1); /* OK/PUBLISH_DONE still legal */
}

/* REQUEST_UPDATE leaves an established subscription's state unchanged. */
static void test_moqsub_update_keeps_established(void) {
  moqsub s;
  moqsub_init(&s, MOQSUB_ROLE_SUBSCRIBER);
  moqsub_step(&s, MOQSUB_EV_OPEN);
  moqsub_step(&s, MOQSUB_EV_OK);
  CHECK(moqsub_step(&s, MOQSUB_EV_UPDATE) == 1);
  CHECK(moqsub_established(&s) == 1);
}

/* PUBLISH_DONE (exact Stream Count, all data streams already closed) + FIN
 * terminates the subscription; the publisher may not open new data streams
 * afterward (that gate is moqsub_may_send_publish_done at the call
 * site, checked before this event fires). */
static void test_moqsub_publish_done_terminates_and_reclaims(void) {
  moqsub s;
  moqsub_init(&s, MOQSUB_ROLE_SUBSCRIBER);
  moqsub_step(&s, MOQSUB_EV_OPEN);
  moqsub_step(&s, MOQSUB_EV_OK);
  CHECK(moqsub_may_send_publish_done(0) == 1); /* 0 open streams */
  CHECK(moqsub_step(&s, MOQSUB_EV_PUBLISH_DONE) == 1);
  CHECK(moqsub_terminated(&s) == 1);
  CHECK(s.term_reason == MOQSUB_TERM_PUBLISH_DONE);
  CHECK(s.pending_ok == 0); /* already responded via OK, no late OK owed */
}

/* PUBLISH_DONE arriving before any response: subscriber owes exactly one
 * deferred PUBLISH_OK before it FINs (pending_ok signals the caller to
 * send that late OK). */
static void test_moqsub_publish_done_before_response_defers_ok(void) {
  moqsub s;
  moqsub_init(&s, MOQSUB_ROLE_PUBLISHER);
  moqsub_step(&s, MOQSUB_EV_OPEN);
  CHECK(moqsub_step(&s, MOQSUB_EV_PUBLISH_DONE) == 1);
  CHECK(moqsub_terminated(&s) == 1);
  CHECK(s.pending_ok == 1);
  CHECK(s.responded == 1); /* exactly-one-response satisfied by late OK */
}

/* Requester FINs its own direction right after sending, before any
 * response: the request is not failed and still awaits a response. */
static void test_moqsub_requester_early_fin_not_failed(void) {
  moqsub s;
  moqsub_init(&s, MOQSUB_ROLE_SUBSCRIBER);
  moqsub_step(&s, MOQSUB_EV_OPEN);
  CHECK(moqsub_step(&s, MOQSUB_EV_FIN_REQ) == 1);
  CHECK(moqsub_terminated(&s) == 0);
  CHECK(s.state == MOQSUB_PENDING);
}

/* Cancelling an established subscription: STOP_SENDING terminates it, and
 * the publisher resets every open data stream (represented here as "no
 * longer forwardable" once terminated). */
static void test_moqsub_cancel_established(void) {
  moqsub s;
  moqsub_init(&s, MOQSUB_ROLE_SUBSCRIBER);
  moqsub_step(&s, MOQSUB_EV_OPEN);
  moqsub_step(&s, MOQSUB_EV_OK);
  CHECK(moqsub_step(&s, MOQSUB_EV_STOP_SENDING) == 1);
  CHECK(moqsub_terminated(&s) == 1);
  CHECK(s.term_reason == MOQSUB_TERM_STOP_SENDING);
  CHECK(moqsub_may_forward(&s, 1) == 0);
}

/* Cancel after the subscriber's own direction is already FIN'd: only
 * STOP_SENDING is sent (nothing on the FIN'd direction); the subscription
 * still terminates. */
static void test_moqsub_cancel_after_fin(void) {
  moqsub s;
  moqsub_init(&s, MOQSUB_ROLE_SUBSCRIBER);
  moqsub_step(&s, MOQSUB_EV_OPEN);
  moqsub_step(&s, MOQSUB_EV_FIN_REQ);
  CHECK(s.fin_req == 1);
  CHECK(moqsub_step(&s, MOQSUB_EV_STOP_SENDING) == 1);
  CHECK(moqsub_terminated(&s) == 1);
}

/* SUBSCRIBE rejected: REQUEST_ERROR terminates the subscription; no Object
 * is ever sent for it. */
static void test_moqsub_subscribe_rejected(void) {
  moqsub s;
  moqsub_init(&s, MOQSUB_ROLE_SUBSCRIBER);
  moqsub_step(&s, MOQSUB_EV_OPEN);
  CHECK(moqsub_step(&s, MOQSUB_EV_ERROR) == 1);
  CHECK(moqsub_terminated(&s) == 1);
  CHECK(s.term_reason == MOQSUB_TERM_ERROR);
  CHECK(moqsub_may_forward(&s, 1) == 0);
}

/* PUBLISH rejected (UNINTERESTED): REQUEST_ERROR + FIN + STOP_SENDING on
 * the receiving direction; the subscription terminates. */
static void test_moqsub_publish_rejected(void) {
  moqsub s;
  moqsub_init(&s, MOQSUB_ROLE_PUBLISHER);
  moqsub_step(&s, MOQSUB_EV_OPEN);
  CHECK(moqsub_step(&s, MOQSUB_EV_ERROR) == 1);
  CHECK(moqsub_terminated(&s) == 1);
  CHECK(s.term_reason == MOQSUB_TERM_ERROR);
}

/* ---------- violation / abnormal ---------- */

/* A 2nd response to the same request -> session-level protocol error, not
 * a local termination alone: session_fault is set. */
static void test_moqsub_duplicate_response_is_session_fault(void) {
  moqsub s;
  moqsub_init(&s, MOQSUB_ROLE_SUBSCRIBER);
  moqsub_step(&s, MOQSUB_EV_OPEN);
  CHECK(moqsub_step(&s, MOQSUB_EV_OK) == 1);
  CHECK(s.session_fault == 0);
  CHECK(moqsub_step(&s, MOQSUB_EV_OK) == 0);
  CHECK(s.session_fault == 1);
}

/* The responder FINs its own direction without ever sending a response:
 * the requester treats the request as failed and terminates. */
static void test_moqsub_early_fin_before_response(void) {
  moqsub s;
  moqsub_init(&s, MOQSUB_ROLE_SUBSCRIBER);
  moqsub_step(&s, MOQSUB_EV_OPEN);
  CHECK(moqsub_step(&s, MOQSUB_EV_FIN_RESP) == 1);
  CHECK(s.fin_resp == 1);
  CHECK(s.responded == 0);
  CHECK(moqsub_step(&s, MOQSUB_EV_STOP_SENDING) == 1);
  CHECK(moqsub_terminated(&s) == 1);
}

void test_moqsess(void) {
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
  test_moqsub_object_delivery_after_subscribe();
  test_moqsub_publish_establish();
  test_moqsub_object_before_publish_ok();
  test_moqsub_forward_state_zero_blocks_objects();
  test_moqsub_update_keeps_established();
  test_moqsub_publish_done_terminates_and_reclaims();
  test_moqsub_publish_done_before_response_defers_ok();
  test_moqsub_requester_early_fin_not_failed();
  test_moqsub_cancel_established();
  test_moqsub_cancel_after_fin();
  test_moqsub_subscribe_rejected();
  test_moqsub_publish_rejected();
  test_moqsub_duplicate_response_is_session_fault();
  test_moqsub_early_fin_before_response();
}
