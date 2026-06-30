#include "app/http3/core/h3/frame.h"
#include "app/http3/core/h3conn/establish.h"
#include "app/http3/core/h3conn/response.h"
#include "app/http3/request/h3reqdrive/request_drive.h"
#include "app/http3/server/h3srv/control.h"
#include "app/http3/server/h3srv/peer.h"
#include "app/http3/server/h3srv/respond.h"
#include "test.h"

static int srv_eq(const u8 *a, usz alen, const char *b, usz blen) {
  if (alen != blen) return 0;
  for (usz i = 0; i < alen; i++)
    if (a[i] != (u8)b[i]) return 0;
  return 1;
}

/* RFC 9114 6.2.1: the server opens one control stream and SETTINGS is the very
 * first frame (the peer-side SETTINGS-first check accepts what we just wrote).
 */
static void test_h3srv_control_settings_first(void) {
  quic_h3srv_state st = {0};
  u8               out[64];
  usz              len = 0;

  CHECK(!st.settings_sent);
  CHECK(quic_h3srv_open_control(&st, out, sizeof(out), &len));
  CHECK(st.settings_sent);
  CHECK(quic_h3conn_peer_settings_ok(out, len));
}

/* RFC 9114 6.2.1: with no control capacity nothing is emitted and SETTINGS is
 * not marked sent. */
static void test_h3srv_control_no_capacity(void) {
  quic_h3srv_state st = {0};
  u8               out[1];
  usz              len = 0;

  CHECK(!quic_h3srv_open_control(&st, out, sizeof(out), &len));
  CHECK(!st.settings_sent);
}

/* RFC 9114 7.2.4: a peer control whose first frame is SETTINGS is accepted and
 * peer SETTINGS recorded; no error. */
static void test_h3srv_peer_settings_first_ok(void) {
  quic_h3srv_state st  = {0};
  u16              err = 0xffff;

  CHECK(quic_h3srv_on_peer_control(&st, QUIC_H3_FRAME_SETTINGS, &err));
  CHECK(err == 0);
  CHECK(st.peer_settings);
}

/* RFC 9114 7.2.4: a non-SETTINGS first frame is H3_MISSING_SETTINGS,
 * specifically not H3_STREAM_CREATION_ERROR. */
static void test_h3srv_peer_non_settings_first_missing(void) {
  quic_h3srv_state st  = {0};
  u16              err = 0;

  CHECK(!quic_h3srv_on_peer_control(&st, QUIC_H3_FRAME_HEADERS, &err));
  CHECK(err == QUIC_H3_MISSING_SETTINGS);
  CHECK(err != QUIC_H3_STREAM_CREATION_ERROR);
}

/* RFC 9114 7.2.4: a second SETTINGS frame is H3_FRAME_UNEXPECTED. */
static void test_h3srv_peer_second_settings_unexpected(void) {
  quic_h3srv_state st  = {0};
  u16              err = 0;

  CHECK(quic_h3srv_on_peer_control(&st, QUIC_H3_FRAME_SETTINGS, &err));
  CHECK(!quic_h3srv_on_peer_control(&st, QUIC_H3_FRAME_SETTINGS, &err));
  CHECK(err == QUIC_H3_FRAME_UNEXPECTED);
}

/* RFC 9114 6.2.1: a second control stream (non-SETTINGS re-open after one is
 * already open) is H3_STREAM_CREATION_ERROR. */
static void test_h3srv_peer_second_control_creation(void) {
  quic_h3srv_state st  = {0};
  u16              err = 0;

  CHECK(quic_h3srv_on_peer_control(&st, QUIC_H3_FRAME_SETTINGS, &err));
  /* peer_settings is now set; a 2nd control opening with a non-SETTINGS first
   * frame is a stream-creation error, distinct from missing/unexpected. */
  st.peer_settings = 0; /* model: a brand-new control stream, no SETTINGS yet */
  CHECK(!quic_h3srv_on_peer_control(&st, QUIC_H3_FRAME_HEADERS, &err));
  CHECK(err == QUIC_H3_STREAM_CREATION_ERROR);
}

/* RFC 9114 6.2 / RFC 9204 4.2: peer control/encoder/decoder uni streams are
 * accepted (no connection error). */
static void test_h3srv_accept_uni_streams(void) {
  CHECK(quic_h3srv_accept_uni(QUIC_H3_STREAM_CONTROL));
  CHECK(quic_h3srv_accept_uni(QUIC_H3_STREAM_QPACK_ENCODER));
  CHECK(quic_h3srv_accept_uni(QUIC_H3_STREAM_QPACK_DECODER));
}

/* RFC 9114 4.1: a GET request HEADERS is decoded, marking request_seen, and
 * the :path / :authority are recovered. */
static void test_h3srv_request_decode(void) {
  quic_h3srv_state    st     = {0};
  const u8            path[] = {'/', 'a'};
  const u8            auth[] = {'h', '1'};
  u8                  req[256], scratch[128];
  usz                 req_len = 0;
  quic_h3reqdrive_req r;

  CHECK(quic_h3reqdrive_send_get(
      0, path, sizeof(path), auth, sizeof(auth), req, sizeof(req), &req_len));
  CHECK(quic_h3srv_on_request(&st, req, req_len, scratch, sizeof(scratch), &r));
  CHECK(st.request_seen);
  CHECK(srv_eq(r.path, r.path_len, "/a", 2));
  CHECK(srv_eq(r.authority, r.authority_len, "h1", 2));
}

/* RFC 9114 4.1 / 4.3.2: request HEADERS -> 200 response carrying :status and
 * body, round-tripped by the client decoder. */
static void test_h3srv_request_answered(void) {
  quic_h3srv_state    st     = {0};
  const u8            path[] = {'/'};
  const u8            auth[] = {'x'};
  const u8            body[] = {'o', 'k'};
  u8                  req[256], scratch[128], resp[256];
  usz                 req_len = 0, resp_len = 0;
  quic_h3reqdrive_req r;
  u16                 status    = 0;
  const u8           *rbody     = 0;
  usz                 rbody_len = 0;

  st.settings_sent = 1;
  CHECK(quic_h3reqdrive_send_get(
      0, path, sizeof(path), auth, sizeof(auth), req, sizeof(req), &req_len));
  CHECK(quic_h3srv_on_request(&st, req, req_len, scratch, sizeof(scratch), &r));
  CHECK(quic_h3srv_build_response(
      &st, 0, 200, body, sizeof(body), resp, sizeof(resp), &resp_len));
  CHECK(quic_h3conn_recv_response(resp, resp_len, &status, &rbody, &rbody_len));
  CHECK(status == 200);
  CHECK(rbody_len == 2 && rbody[0] == 'o' && rbody[1] == 'k');
}

/* RFC 9110 9.3.2: a HEAD response carries the same :status as the GET would but
 * MUST NOT include message content; build_response_for_method drops the DATA
 * frame so the client decoder sees status with body_len 0. */
static void test_h3srv_head_no_body(void) {
  quic_h3srv_state st     = {0};
  const u8         head[] = {'H', 'E', 'A', 'D'};
  const u8         body[] = {'o', 'k'};
  u8               resp[256];
  usz              resp_len  = 0;
  u16              status    = 0;
  const u8        *rbody     = (const u8 *)1;
  usz              rbody_len = 99;

  st.settings_sent = 1;
  st.request_seen  = 1;
  CHECK(quic_h3srv_build_response_for_method(
      &st, 0, head, sizeof(head), 200, body, sizeof(body), resp, sizeof(resp),
      &resp_len));
  CHECK(quic_h3conn_recv_response(resp, resp_len, &status, &rbody, &rbody_len));
  CHECK(status == 200);  /* :status still returned for HEAD */
  CHECK(rbody_len == 0); /* no DATA frame: body suppressed */
}

/* RFC 9110 9.3.1 (contrast): GET keeps its DATA frame; same path through
 * build_response_for_method preserves the body for non-HEAD methods. */
static void test_h3srv_get_keeps_body(void) {
  quic_h3srv_state st     = {0};
  const u8         get[]  = {'G', 'E', 'T'};
  const u8         body[] = {'o', 'k'};
  u8               resp[256];
  usz              resp_len  = 0;
  u16              status    = 0;
  const u8        *rbody     = 0;
  usz              rbody_len = 0;

  st.settings_sent = 1;
  st.request_seen  = 1;
  CHECK(quic_h3srv_build_response_for_method(
      &st, 0, get, sizeof(get), 200, body, sizeof(body), resp, sizeof(resp),
      &resp_len));
  CHECK(quic_h3conn_recv_response(resp, resp_len, &status, &rbody, &rbody_len));
  CHECK(status == 200);
  CHECK(rbody_len == 2 && rbody[0] == 'o' && rbody[1] == 'k');
}

/* RFC 9114 4.3.1: an OPTIONS request in asterisk-form (:path = "*", a single
 * 0x2a octet) is not malformed; it round-trips through encode/decode with the
 * method and path recovered intact. */
static void test_h3srv_options_asterisk(void) {
  quic_h3srv_state    st       = {0};
  const u8            method[] = {'O', 'P', 'T', 'I', 'O', 'N', 'S'};
  const u8            star[]   = {'*'};
  const u8            auth[]   = {'x'};
  u8                  req[256], scratch[128];
  usz                 req_len = 0;
  quic_h3reqdrive_req r;

  CHECK(quic_h3reqdrive_send_method(
      0, method, sizeof(method), star, sizeof(star), auth, sizeof(auth), 0, 0,
      req, sizeof(req), &req_len));
  CHECK(quic_h3srv_on_request(&st, req, req_len, scratch, sizeof(scratch), &r));
  CHECK(srv_eq(r.method, r.method_len, "OPTIONS", 7));
  CHECK(srv_eq(r.path, r.path_len, "*", 1)); /* 0x2a recovered, not rejected */
}

/* RFC 9114 4.1: no response on a stream that never received a request. */
static void test_h3srv_no_response_without_request(void) {
  quic_h3srv_state st = {0};
  u8               resp[256];
  usz              resp_len = 0;

  st.settings_sent = 1; /* own SETTINGS sent, but no request seen */
  CHECK(!st.request_seen);
  CHECK(!quic_h3srv_build_response(
      &st, 0, 200, 0, 0, resp, sizeof(resp), &resp_len));
}

/* RFC 9114 6.2.1 / 7.2.4: no response before the server's own SETTINGS-first.
 */
static void test_h3srv_no_response_before_own_settings(void) {
  quic_h3srv_state st = {0};
  u8               resp[256];
  usz              resp_len = 0;

  st.request_seen = 1; /* request received, but own SETTINGS not yet sent */
  CHECK(!st.settings_sent);
  CHECK(!quic_h3srv_build_response(
      &st, 0, 200, 0, 0, resp, sizeof(resp), &resp_len));
}

/* RFC 9114 7.2.4.2: the server responds without having seen the peer SETTINGS.
 */
static void test_h3srv_respond_without_peer_settings(void) {
  quic_h3srv_state st = {0};
  u8               resp[256];
  usz              resp_len  = 0;
  u16              status    = 0;
  const u8        *rbody     = 0;
  usz              rbody_len = 0;

  st.settings_sent = 1;
  st.request_seen  = 1;
  CHECK(!st.peer_settings); /* peer SETTINGS never seen */
  CHECK(quic_h3srv_build_response(
      &st, 0, 200, 0, 0, resp, sizeof(resp), &resp_len));
  CHECK(quic_h3conn_recv_response(resp, resp_len, &status, &rbody, &rbody_len));
  CHECK(status == 200); /* :status present without waiting on peer SETTINGS */
}

void test_h3srv(void) {
  test_h3srv_control_settings_first();
  test_h3srv_control_no_capacity();
  test_h3srv_peer_settings_first_ok();
  test_h3srv_peer_non_settings_first_missing();
  test_h3srv_peer_second_settings_unexpected();
  test_h3srv_peer_second_control_creation();
  test_h3srv_accept_uni_streams();
  test_h3srv_request_decode();
  test_h3srv_request_answered();
  test_h3srv_head_no_body();
  test_h3srv_get_keeps_body();
  test_h3srv_options_asterisk();
  test_h3srv_no_response_without_request();
  test_h3srv_no_response_before_own_settings();
  test_h3srv_respond_without_peer_settings();
}
