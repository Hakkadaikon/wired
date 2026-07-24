#include "app/http3/core/h3/frame.h"
#include "app/http3/server/h3srv/priupdate.h"
#include "test.h"

/* RFC 9218 7.1: on the client control stream, a request-variant
 * PRIORITY_UPDATE naming a client-initiated bidi stream id is accepted. */
static void test_h3srv_priupdate_control_ok(void) {
  u16 err = 0xffff;
  CHECK(wired_h3srv_priupdate_check(1, 0, 0, &err));
  CHECK(err == 0);
  CHECK(wired_h3srv_priupdate_check(1, 0, 4, &err));
  CHECK(err == 0);
}

/* RFC 9218 7.1 (push variant): the push element id space carries no bidi-id
 * restriction here (this SDK does not otherwise support push, so it is
 * accepted at the check layer -- nothing is ever applied for it). */
static void test_h3srv_priupdate_control_push_ok(void) {
  u16 err = 0xffff;
  CHECK(wired_h3srv_priupdate_check(1, 1, 2, &err));
  CHECK(err == 0);
}

/* 9218-013: PRIORITY_UPDATE received anywhere but the client control stream
 * is H3_FRAME_UNEXPECTED. */
static void test_h3srv_priupdate_wrong_stream_unexpected(void) {
  u16 err = 0;
  CHECK(!wired_h3srv_priupdate_check(0, 0, 0, &err));
  CHECK(err == QUIC_H3_FRAME_UNEXPECTED);
}

/* 9218-014: a request-variant element id outside the client-initiated bidi
 * stream id space (low bits != 00) is H3_ID_ERROR. */
static void test_h3srv_priupdate_bad_id_error(void) {
  u16 err = 0;
  CHECK(!wired_h3srv_priupdate_check(1, 0, 1, &err)); /* client uni */
  CHECK(err == QUIC_H3_ID_ERROR);
  err = 0;
  CHECK(!wired_h3srv_priupdate_check(1, 0, 2, &err)); /* server bidi */
  CHECK(err == QUIC_H3_ID_ERROR);
  err = 0;
  CHECK(!wired_h3srv_priupdate_check(1, 0, 3, &err)); /* server uni */
  CHECK(err == QUIC_H3_ID_ERROR);
}

/* Boundary: id 0 and a large id both on the client bidi id space (low bits
 * 00) are accepted. */
static void test_h3srv_priupdate_id_boundaries(void) {
  u16 err = 0xffff;
  CHECK(wired_h3srv_priupdate_check(1, 0, 0, &err));
  CHECK(err == 0);
  err = 0xffff;
  CHECK(wired_h3srv_priupdate_check(1, 0, 4000, &err));
  CHECK(err == 0);
}

/* The wrong-stream check outranks the id check: an off-control-stream frame
 * with an otherwise-bad id still reports H3_FRAME_UNEXPECTED, not
 * H3_ID_ERROR (mirrors peer.c's own priority-ordered rule table). */
static void test_h3srv_priupdate_wrong_stream_outranks_id(void) {
  u16 err = 0;
  CHECK(!wired_h3srv_priupdate_check(0, 0, 1, &err));
  CHECK(err == QUIC_H3_FRAME_UNEXPECTED);
}

void test_h3srv_priupdate(void) {
  test_h3srv_priupdate_control_ok();
  test_h3srv_priupdate_control_push_ok();
  test_h3srv_priupdate_wrong_stream_unexpected();
  test_h3srv_priupdate_bad_id_error();
  test_h3srv_priupdate_id_boundaries();
  test_h3srv_priupdate_wrong_stream_outranks_id();
}
