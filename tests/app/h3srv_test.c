#include "app/http3/core/h3/frame.h"
#include "app/http3/core/h3conn/establish.h"
#include "app/http3/core/h3conn/response.h"
#include "app/http3/request/h3reqdrive/request_drive.h"
#include "app/http3/server/h3srv/control.h"
#include "app/http3/server/h3srv/peer.h"
#include "app/http3/server/h3srv/respond.h"
#include "test.h"

static int srv_eq(const u8* a, usz alen, const char* b, usz blen) {
  if (alen != blen) return 0;
  for (usz i = 0; i < alen; i++)
    if (a[i] != (u8)b[i]) return 0;
  return 1;
}

/* RFC 9114 6.2.1: the server opens one control stream and SETTINGS is the very
 * first frame (the peer-side SETTINGS-first check accepts what we just wrote).
 */
static void test_h3srv_control_settings_first(void) {
  wired_h3srv_state st = {0};
  u8                out[64];
  quic_obuf         ob = {out, sizeof out, 0};

  CHECK(!st.settings_sent);
  CHECK(wired_h3srv_open_control(&st, &ob));
  CHECK(st.settings_sent);
  CHECK(quic_h3conn_peer_settings_ok(out, ob.len));
}

/* RFC 9114 6.2.1: with no control capacity nothing is emitted and SETTINGS is
 * not marked sent. */
static void test_h3srv_control_no_capacity(void) {
  wired_h3srv_state st = {0};
  u8                out[1];
  quic_obuf         ob = {out, sizeof out, 0};

  CHECK(!wired_h3srv_open_control(&st, &ob));
  CHECK(!st.settings_sent);
}

/* RFC 9114 7.2.4: a peer control whose first frame is SETTINGS is accepted and
 * peer SETTINGS recorded; no error. */
static void test_h3srv_peer_settings_first_ok(void) {
  wired_h3srv_state st  = {0};
  u16               err = 0xffff;

  CHECK(wired_h3srv_on_peer_control(&st, QUIC_H3_FRAME_SETTINGS, &err));
  CHECK(err == 0);
  CHECK(st.peer_settings);
}

/* RFC 9114 7.2.4: a non-SETTINGS first frame is H3_MISSING_SETTINGS,
 * specifically not H3_STREAM_CREATION_ERROR. */
static void test_h3srv_peer_non_settings_first_missing(void) {
  wired_h3srv_state st  = {0};
  u16               err = 0;

  CHECK(!wired_h3srv_on_peer_control(&st, QUIC_H3_FRAME_HEADERS, &err));
  CHECK(err == QUIC_H3_MISSING_SETTINGS);
  CHECK(err != QUIC_H3_STREAM_CREATION_ERROR);
}

/* RFC 9114 7.2.4: a second SETTINGS frame is H3_FRAME_UNEXPECTED. */
static void test_h3srv_peer_second_settings_unexpected(void) {
  wired_h3srv_state st  = {0};
  u16               err = 0;

  CHECK(wired_h3srv_on_peer_control(&st, QUIC_H3_FRAME_SETTINGS, &err));
  CHECK(!wired_h3srv_on_peer_control(&st, QUIC_H3_FRAME_SETTINGS, &err));
  CHECK(err == QUIC_H3_FRAME_UNEXPECTED);
}

/* RFC 9114 6.2.1: a second control stream (non-SETTINGS re-open after one is
 * already open) is H3_STREAM_CREATION_ERROR. */
static void test_h3srv_peer_second_control_creation(void) {
  wired_h3srv_state st  = {0};
  u16               err = 0;

  CHECK(wired_h3srv_on_peer_control(&st, QUIC_H3_FRAME_SETTINGS, &err));
  /* peer_settings is now set; a 2nd control opening with a non-SETTINGS first
   * frame is a stream-creation error, distinct from missing/unexpected. */
  st.peer_settings = 0; /* model: a brand-new control stream, no SETTINGS yet */
  CHECK(!wired_h3srv_on_peer_control(&st, QUIC_H3_FRAME_HEADERS, &err));
  CHECK(err == QUIC_H3_STREAM_CREATION_ERROR);
}

/* RFC 9114 6.2 / RFC 9204 4.2: peer control/encoder/decoder uni streams are
 * accepted (no connection error). */
static void test_h3srv_accept_uni_streams(void) {
  CHECK(wired_h3srv_accept_uni(QUIC_H3_STREAM_CONTROL));
  CHECK(wired_h3srv_accept_uni(QUIC_H3_STREAM_QPACK_ENCODER));
  CHECK(wired_h3srv_accept_uni(QUIC_H3_STREAM_QPACK_DECODER));
}

/* RFC 9114 4.1: a GET request HEADERS is decoded, marking request_seen, and
 * the :path / :authority are recovered. */
static void test_h3srv_request_decode(void) {
  wired_h3srv_state    st     = {0};
  const u8             path[] = {'/', 'a'};
  const u8             auth[] = {'h', '1'};
  u8                   req[256], scratch[128];
  quic_obuf            req_ob = {req, sizeof req, 0};
  wired_h3reqdrive_req r;

  CHECK(wired_h3reqdrive_send_get(
      0,
      &(wired_h3reqdrive_get_in){quic_span_of(path, sizeof path),
                                 quic_span_of(auth, sizeof auth)},
      &req_ob));
  CHECK(wired_h3srv_on_request(
      &st,
      &(wired_h3srv_req_in){quic_span_of(req, req_ob.len),
                            quic_mspan_of(scratch, sizeof scratch)},
      &r));
  CHECK(st.request_seen);
  CHECK(srv_eq(r.path, r.path_len, "/a", 2));
  CHECK(srv_eq(r.authority, r.authority_len, "h1", 2));
}

/* RFC 9114 4.1 / 4.3.2: request HEADERS -> 200 response carrying :status and
 * body, round-tripped by the client decoder. */
static void test_h3srv_request_answered(void) {
  wired_h3srv_state st     = {0};
  const u8          path[] = {'/'};
  const u8          auth[] = {'x'};
  const u8          body[] = {'o', 'k'};
  u8                req[256], scratch[128], resp[256];
  quic_obuf req_ob = {req, sizeof req, 0}, resp_ob = {resp, sizeof resp, 0};
  wired_h3reqdrive_req r;
  quic_h3conn_resp     resp_out = {0};

  st.settings_sent = 1;
  CHECK(wired_h3reqdrive_send_get(
      0,
      &(wired_h3reqdrive_get_in){quic_span_of(path, sizeof path),
                                 quic_span_of(auth, sizeof auth)},
      &req_ob));
  CHECK(wired_h3srv_on_request(
      &st,
      &(wired_h3srv_req_in){quic_span_of(req, req_ob.len),
                            quic_mspan_of(scratch, sizeof scratch)},
      &r));
  {
    wired_h3srv_send_in send = {0, {200, quic_span_of(body, sizeof body), 0}};
    CHECK(wired_h3srv_build_response(&st, &send, &resp_ob));
  }
  CHECK(quic_h3conn_recv_response(quic_span_of(resp, resp_ob.len), &resp_out));
  CHECK(resp_out.status == 200);
  CHECK(
      resp_out.body.n == 2 && resp_out.body.p[0] == 'o' &&
      resp_out.body.p[1] == 'k');
}

/* RFC 9110 9.3.2: a HEAD response carries the same :status as the GET would but
 * MUST NOT include message content; build_response_for_method drops the DATA
 * frame so the client decoder sees status with body_len 0. */
static void test_h3srv_head_no_body(void) {
  wired_h3srv_state st     = {0};
  const u8          head[] = {'H', 'E', 'A', 'D'};
  const u8          body[] = {'o', 'k'};
  u8                resp[256];
  quic_obuf         resp_ob  = {resp, sizeof resp, 0};
  quic_h3conn_resp  resp_out = {0, quic_span_of((const u8*)1, 99), 0};

  st.settings_sent = 1;
  st.request_seen  = 1;
  {
    wired_h3srv_send_in send = {0, {200, quic_span_of(body, sizeof body), 0}};
    wired_h3srv_resp_for_method_in in = {quic_span_of(head, sizeof head), send};
    CHECK(wired_h3srv_build_response_for_method(&st, &in, &resp_ob));
  }
  CHECK(quic_h3conn_recv_response(quic_span_of(resp, resp_ob.len), &resp_out));
  CHECK(resp_out.status == 200); /* :status still returned for HEAD */
  CHECK(resp_out.body.n == 0);   /* no DATA frame: body suppressed */
}

/* RFC 9110 9.3.1 (contrast): GET keeps its DATA frame; same path through
 * build_response_for_method preserves the body for non-HEAD methods. */
static void test_h3srv_get_keeps_body(void) {
  wired_h3srv_state st     = {0};
  const u8          get[]  = {'G', 'E', 'T'};
  const u8          body[] = {'o', 'k'};
  u8                resp[256];
  quic_obuf         resp_ob  = {resp, sizeof resp, 0};
  quic_h3conn_resp  resp_out = {0};

  st.settings_sent = 1;
  st.request_seen  = 1;
  {
    wired_h3srv_send_in send = {0, {200, quic_span_of(body, sizeof body), 0}};
    wired_h3srv_resp_for_method_in in = {quic_span_of(get, sizeof get), send};
    CHECK(wired_h3srv_build_response_for_method(&st, &in, &resp_ob));
  }
  CHECK(quic_h3conn_recv_response(quic_span_of(resp, resp_ob.len), &resp_out));
  CHECK(resp_out.status == 200);
  CHECK(
      resp_out.body.n == 2 && resp_out.body.p[0] == 'o' &&
      resp_out.body.p[1] == 'k');
}

/* RFC 9114 4.3.1: an OPTIONS request in asterisk-form (:path = "*", a single
 * 0x2a octet) is not malformed; it round-trips through encode/decode with the
 * method and path recovered intact. */
static void test_h3srv_options_asterisk(void) {
  wired_h3srv_state        st       = {0};
  const u8                 method[] = {'O', 'P', 'T', 'I', 'O', 'N', 'S'};
  const u8                 star[]   = {'*'};
  const u8                 auth[]   = {'x'};
  u8                       req[256], scratch[128];
  quic_obuf                req_ob = {req, sizeof req, 0};
  wired_h3reqdrive_req     r;
  wired_h3reqdrive_send_in in = {
      quic_span_of(method, sizeof method), quic_span_of(star, sizeof star),
      quic_span_of(auth, sizeof auth), quic_span_of(0, 0)};

  CHECK(wired_h3reqdrive_send_method(0, &in, &req_ob));
  CHECK(wired_h3srv_on_request(
      &st,
      &(wired_h3srv_req_in){quic_span_of(req, req_ob.len),
                            quic_mspan_of(scratch, sizeof scratch)},
      &r));
  CHECK(srv_eq(r.method, r.method_len, "OPTIONS", 7));
  CHECK(srv_eq(r.path, r.path_len, "*", 1)); /* 0x2a recovered, not rejected */
}

/* RFC 9114 4.1: no response on a stream that never received a request. */
static void test_h3srv_no_response_without_request(void) {
  wired_h3srv_state st = {0};
  u8                resp[256];
  quic_obuf         resp_ob = {resp, sizeof resp, 0};

  wired_h3srv_send_in send = {0, {200, quic_span_of(0, 0), 0}};
  st.settings_sent         = 1; /* own SETTINGS sent, but no request seen */
  CHECK(!st.request_seen);
  CHECK(!wired_h3srv_build_response(&st, &send, &resp_ob));
}

/* RFC 9114 6.2.1 / 7.2.4: no response before the server's own SETTINGS-first.
 */
static void test_h3srv_no_response_before_own_settings(void) {
  wired_h3srv_state st = {0};
  u8                resp[256];
  quic_obuf         resp_ob = {resp, sizeof resp, 0};

  wired_h3srv_send_in send = {0, {200, quic_span_of(0, 0), 0}};
  st.request_seen = 1; /* request received, but own SETTINGS not yet sent */
  CHECK(!st.settings_sent);
  CHECK(!wired_h3srv_build_response(&st, &send, &resp_ob));
}

/* RFC 9114 7.2.4.2: the server responds without having seen the peer SETTINGS.
 */
static void test_h3srv_respond_without_peer_settings(void) {
  wired_h3srv_state st = {0};
  u8                resp[256];
  quic_obuf         resp_ob  = {resp, sizeof resp, 0};
  quic_h3conn_resp  resp_out = {0};

  wired_h3srv_send_in send = {0, {200, quic_span_of(0, 0), 0}};
  st.settings_sent         = 1;
  st.request_seen          = 1;
  CHECK(!st.peer_settings); /* peer SETTINGS never seen */
  CHECK(wired_h3srv_build_response(&st, &send, &resp_ob));
  CHECK(quic_h3conn_recv_response(quic_span_of(resp, resp_ob.len), &resp_out));
  CHECK(
      resp_out.status ==
      200); /* :status present without waiting on peer SETTINGS */
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
