#include "app/http3/core/h3/frame.h"
#include "app/http3/core/h3conn/establish.h"
#include "app/http3/core/h3conn/response.h"
#include "app/http3/core/h3settings/control_settings.h"
#include "app/http3/request/h3reqdrive/request_drive.h"
#include "app/http3/server/h3srv/control.h"
#include "app/http3/server/h3srv/peer.h"
#include "app/http3/server/h3srv/respond.h"
#include "test.h"
#include "transport/stream/data/appdata/stream_send.h"

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
  wired_obuf        ob = {out, sizeof out, 0};

  CHECK(!st.settings_sent);
  CHECK(wired_h3srv_open_control(&st, 0, &ob));
  CHECK(st.settings_sent);
  CHECK(h3conn_peer_settings_ok(out, ob.len));
}

/* RFC 9114 6.2.1: with no control capacity nothing is emitted and SETTINGS is
 * not marked sent. */
static void test_h3srv_control_no_capacity(void) {
  wired_h3srv_state st = {0};
  u8                out[1];
  wired_obuf        ob = {out, sizeof out, 0};

  CHECK(!wired_h3srv_open_control(&st, 0, &ob));
  CHECK(!st.settings_sent);
}

/* RFC 9114 7.2.4: a peer control whose first frame is SETTINGS is accepted and
 * peer SETTINGS recorded; no error. */
static void test_h3srv_peer_settings_first_ok(void) {
  wired_h3srv_state st  = {0};
  u16               err = 0xffff;

  CHECK(wired_h3srv_on_peer_control(&st, H3_FRAME_SETTINGS, &err));
  CHECK(err == 0);
  CHECK(st.peer_settings);
}

/* RFC 9114 7.2.4: a non-SETTINGS first frame is H3_MISSING_SETTINGS,
 * specifically not H3_STREAM_CREATION_ERROR. */
static void test_h3srv_peer_non_settings_first_missing(void) {
  wired_h3srv_state st  = {0};
  u16               err = 0;

  CHECK(!wired_h3srv_on_peer_control(&st, H3_FRAME_HEADERS, &err));
  CHECK(err == H3_MISSING_SETTINGS);
  CHECK(err != H3_STREAM_CREATION_ERROR);
}

/* RFC 9114 7.2.4: a second SETTINGS frame is H3_FRAME_UNEXPECTED. */
static void test_h3srv_peer_second_settings_unexpected(void) {
  wired_h3srv_state st  = {0};
  u16               err = 0;

  CHECK(wired_h3srv_on_peer_control(&st, H3_FRAME_SETTINGS, &err));
  CHECK(!wired_h3srv_on_peer_control(&st, H3_FRAME_SETTINGS, &err));
  CHECK(err == H3_FRAME_UNEXPECTED);
}

/* RFC 9114 6.2.1: a second control stream (non-SETTINGS re-open after one is
 * already open) is H3_STREAM_CREATION_ERROR. */
static void test_h3srv_peer_second_control_creation(void) {
  wired_h3srv_state st  = {0};
  u16               err = 0;

  CHECK(wired_h3srv_on_peer_control(&st, H3_FRAME_SETTINGS, &err));
  /* peer_settings is now set; a 2nd control opening with a non-SETTINGS first
   * frame is a stream-creation error, distinct from missing/unexpected. */
  st.peer_settings = 0; /* model: a brand-new control stream, no SETTINGS yet */
  CHECK(!wired_h3srv_on_peer_control(&st, H3_FRAME_HEADERS, &err));
  CHECK(err == H3_STREAM_CREATION_ERROR);
}

/* RFC 9114 6.2 / RFC 9204 4.2: peer control/encoder/decoder uni streams are
 * accepted (no connection error). */
static void test_h3srv_accept_uni_streams(void) {
  CHECK(wired_h3srv_accept_uni(H3_STREAM_CONTROL));
  CHECK(wired_h3srv_accept_uni(H3_STREAM_QPACK_ENCODER));
  CHECK(wired_h3srv_accept_uni(H3_STREAM_QPACK_DECODER));
}

/* draft-ietf-webtrans-http3-15 4.3: the WebTransport uni stream type (0x54)
 * is accepted; an unknown/unassigned type is not. */
static void test_h3srv_accept_uni_webtransport(void) {
  CHECK(wired_h3srv_accept_uni(H3_STREAM_WEBTRANSPORT));
  CHECK(!wired_h3srv_accept_uni(0x99));
}

/* RFC 9204 4.2: the first QPACK encoder and the first QPACK decoder stream
 * are each accepted independently, no error. */
static void test_h3srv_peer_qpack_first_ok(void) {
  wired_h3srv_state st  = {0};
  u16               err = 0xffff;

  CHECK(wired_h3srv_on_peer_qpack(&st, H3_STREAM_QPACK_ENCODER, &err));
  CHECK(err == 0);
  CHECK(st.peer_qpack_encoder);

  CHECK(wired_h3srv_on_peer_qpack(&st, H3_STREAM_QPACK_DECODER, &err));
  CHECK(err == 0);
  CHECK(st.peer_qpack_decoder);
}

/* RFC 9204 4.2: a second encoder stream is H3_STREAM_CREATION_ERROR. */
static void test_h3srv_peer_second_qpack_encoder(void) {
  wired_h3srv_state st  = {0};
  u16               err = 0;

  CHECK(wired_h3srv_on_peer_qpack(&st, H3_STREAM_QPACK_ENCODER, &err));
  CHECK(!wired_h3srv_on_peer_qpack(&st, H3_STREAM_QPACK_ENCODER, &err));
  CHECK(err == H3_STREAM_CREATION_ERROR);
}

/* RFC 9204 4.2: a second decoder stream is H3_STREAM_CREATION_ERROR,
 * independent of the encoder stream's state. */
static void test_h3srv_peer_second_qpack_decoder(void) {
  wired_h3srv_state st  = {0};
  u16               err = 0;

  CHECK(wired_h3srv_on_peer_qpack(&st, H3_STREAM_QPACK_DECODER, &err));
  CHECK(!wired_h3srv_on_peer_qpack(&st, H3_STREAM_QPACK_DECODER, &err));
  CHECK(err == H3_STREAM_CREATION_ERROR);
}

/* Any non-QPACK stream type (e.g. control) is a no-op: accepted, no error,
 * and neither peer_qpack_* flag is touched. */
static void test_h3srv_peer_qpack_ignores_other_types(void) {
  wired_h3srv_state st  = {0};
  u16               err = 0xffff;

  CHECK(wired_h3srv_on_peer_qpack(&st, H3_STREAM_CONTROL, &err));
  CHECK(err == 0);
  CHECK(!st.peer_qpack_encoder);
  CHECK(!st.peer_qpack_decoder);
}

/* RFC 9114 4.1: a GET request HEADERS is decoded, marking request_seen, and
 * the :path / :authority are recovered. */
static void test_h3srv_request_decode(void) {
  wired_h3srv_state    st     = {0};
  const u8             path[] = {'/', 'a'};
  const u8             auth[] = {'h', '1'};
  u8                   req[256], scratch[128];
  wired_obuf           req_ob = {req, sizeof req, 0};
  wired_h3reqdrive_req r;

  CHECK(wired_h3reqdrive_send_get(
      0,
      &(wired_h3reqdrive_get_in){
          wired_span_of(path, sizeof path), wired_span_of(auth, sizeof auth)},
      &req_ob));
  CHECK(wired_h3srv_on_request(
      &st,
      &(wired_h3srv_req_in){
          wired_span_of(req, req_ob.len),
          wired_mspan_of(scratch, sizeof scratch)},
      &r));
  CHECK(st.request_seen);
  CHECK(srv_eq(r.path, r.path_len, "/a", 2));
  CHECK(srv_eq(r.authority, r.authority_len, "h1", 2));
}

/* Pinned to a captured Chrome interop run: the browser's real 456-byte
 * request HEADERS (static-table + Huffman literals, ~0.9 KiB decoded).
 * The decode scratch is sized by the shared WIRED_H3_MAX_FIELD_SECTION --
 * the old separate 512-byte scratch overflowed on exactly this request and
 * every Chrome request was aborted with H3_REQUEST_INCOMPLETE while the
 * SETTINGS advertised a 16 KiB field-section limit. */
static void test_h3srv_request_decode_chrome_headers(void) {
  static const u8 chrome[456] = {
      0x01, 0x41, 0xc5, 0x00, 0x00, 0xd1, 0x50, 0x85, 0x41, 0x6c, 0xee, 0x5b,
      0x1a, 0xd7, 0x51, 0x96, 0x62, 0x93, 0xd4, 0x84, 0xd8, 0x7b, 0x50, 0xb4,
      0xb6, 0x1a, 0x69, 0xd2, 0x5a, 0x8b, 0x22, 0xdd, 0x4b, 0xea, 0x33, 0x8e,
      0xc9, 0x3f, 0x2f, 0x00, 0x41, 0x48, 0xb1, 0x27, 0x5a, 0xd1, 0xff, 0xb8,
      0xfe, 0x74, 0x9d, 0x3f, 0xd4, 0x37, 0x2e, 0xd8, 0x3a, 0xa4, 0xfe, 0x7e,
      0xfb, 0xc1, 0xfc, 0xbd, 0xfc, 0xfd, 0x29, 0xfc, 0xde, 0x9e, 0xc3, 0xd2,
      0x6b, 0x69, 0xfe, 0x7e, 0xfb, 0xc1, 0xfc, 0x85, 0xa6, 0xbf, 0x9f, 0xa5,
      0x3f, 0x9c, 0x47, 0x3c, 0xd4, 0x15, 0x4b, 0xd3, 0xd8, 0x7a, 0x4b, 0xfc,
      0xfd, 0xf7, 0x83, 0xf9, 0x0b, 0x4d, 0x7f, 0x3f, 0x2f, 0x04, 0x41, 0x48,
      0xb1, 0x27, 0x5a, 0xd1, 0xad, 0x49, 0xe3, 0x35, 0x05, 0x02, 0x3f, 0x30,
      0x2f, 0x06, 0x41, 0x48, 0xb1, 0x27, 0x5a, 0xd1, 0xad, 0x5d, 0x03, 0x4c,
      0xa7, 0xb2, 0x9f, 0x07, 0x22, 0x4c, 0x69, 0x6e, 0x75, 0x78, 0x22, 0xff,
      0x1f, 0x5f, 0x50, 0xd3, 0xd0, 0x7f, 0x66, 0xa2, 0x81, 0xb0, 0xda, 0xe0,
      0x53, 0xfa, 0xfc, 0x08, 0x7e, 0xd4, 0xce, 0x6a, 0xad, 0xf2, 0xa7, 0x97,
      0x9c, 0x89, 0xc6, 0xbf, 0xb5, 0x21, 0xae, 0xba, 0x0b, 0xc8, 0xb1, 0xe6,
      0x32, 0x58, 0x6d, 0x97, 0x57, 0x65, 0xc5, 0x3f, 0xac, 0xd8, 0xf7, 0xe8,
      0xcf, 0xf4, 0xa5, 0x06, 0xea, 0x55, 0x31, 0x14, 0x9d, 0x4f, 0xfd, 0xa9,
      0x8c, 0xa3, 0x92, 0x82, 0xa1, 0x17, 0xa7, 0xb0, 0xf4, 0x95, 0x80, 0xb4,
      0xd2, 0xe0, 0x5c, 0x0b, 0x81, 0x4d, 0xc3, 0x94, 0x76, 0x19, 0x86, 0xd9,
      0x75, 0x76, 0x5c, 0x5f, 0x0e, 0xe5, 0x49, 0x7c, 0xa5, 0x89, 0xd3, 0x4d,
      0x1f, 0x43, 0xae, 0xba, 0x0c, 0x41, 0xa4, 0xc7, 0xa9, 0x8f, 0x33, 0xa6,
      0x9a, 0x3f, 0xdf, 0x9a, 0x68, 0xfa, 0x1d, 0x75, 0xd0, 0x62, 0x0d, 0x26,
      0x3d, 0x4c, 0x79, 0xa6, 0x8f, 0xbe, 0xd0, 0x01, 0x77, 0xfe, 0x8d, 0x48,
      0xe6, 0x2b, 0x03, 0xee, 0x69, 0x7e, 0x8d, 0x48, 0xe6, 0x2b, 0x1e, 0x0b,
      0x1d, 0x7f, 0x46, 0xa4, 0x73, 0x15, 0x81, 0xd7, 0x54, 0xdf, 0x5f, 0x2c,
      0x7c, 0xfd, 0xf6, 0x80, 0x0b, 0xbd, 0xf4, 0x3a, 0xeb, 0xa0, 0xc4, 0x1a,
      0x4c, 0x7a, 0x98, 0x41, 0xa6, 0xa8, 0xb2, 0x2c, 0x5f, 0x24, 0x9c, 0x75,
      0x4c, 0x5f, 0xbe, 0xf0, 0x46, 0xcf, 0xdf, 0x68, 0x00, 0xbb, 0xbf, 0x2f,
      0x03, 0x41, 0x48, 0xb4, 0xa5, 0x49, 0x27, 0x59, 0x06, 0x49, 0x7f, 0x87,
      0x25, 0x87, 0x42, 0x16, 0x41, 0x92, 0x5f, 0x2f, 0x03, 0x41, 0x48, 0xb4,
      0xa5, 0x49, 0x27, 0x5a, 0x93, 0xc8, 0x5f, 0x86, 0xa8, 0x7d, 0xcd, 0x30,
      0xd2, 0x5f, 0x2f, 0x03, 0x41, 0x48, 0xb4, 0xa5, 0x49, 0x27, 0x5a, 0xd4,
      0x16, 0xcf, 0x02, 0x3f, 0x31, 0x2f, 0x03, 0x41, 0x48, 0xb4, 0xa5, 0x49,
      0x27, 0x5a, 0x42, 0xa1, 0x3f, 0x86, 0x90, 0xe4, 0xb6, 0x92, 0xd4, 0x9f,
      0x5f, 0x10, 0x92, 0x9b, 0xd9, 0xab, 0xfa, 0x52, 0x42, 0xcb, 0x40, 0xd2,
      0x5f, 0xa5, 0x23, 0xb3, 0xe9, 0x4f, 0x68, 0x4c, 0x9f, 0x5f, 0x39, 0x8b,
      0x2d, 0x4b, 0x70, 0xdd, 0xf4, 0x5a, 0xbe, 0xfb, 0x40, 0x05, 0xdf, 0x2e,
      0xae, 0xc3, 0x1e, 0xc3, 0x27, 0xd7, 0x85, 0xb6, 0x00, 0x7d, 0x28, 0x6f};
  wired_h3srv_state    st = {0};
  static u8            wrap[512], scratch[WIRED_H3_MAX_FIELD_SECTION];
  wired_obuf           ob = {wrap, sizeof wrap, 0};
  stream_frame         f  = {0, 0, sizeof chrome, chrome, 1};
  wired_h3reqdrive_req r;
  CHECK(appdata_stream_frame(&f, &ob));
  CHECK(wired_h3srv_on_request(
      &st,
      &(wired_h3srv_req_in){
          wired_span_of(wrap, ob.len), wired_mspan_of(scratch, sizeof scratch)},
      &r));
  CHECK(srv_eq(r.path, r.path_len, "/monstrous-frightened-keyboard", 30));
}

/* RFC 9114 4.1 / 4.3.2: request HEADERS -> 200 response carrying :status and
 * body, round-tripped by the client decoder. */
static void test_h3srv_request_answered(void) {
  wired_h3srv_state st     = {0};
  const u8          path[] = {'/'};
  const u8          auth[] = {'x'};
  const u8          body[] = {'o', 'k'};
  u8                req[256], scratch[128], resp[256];
  wired_obuf req_ob = {req, sizeof req, 0}, resp_ob = {resp, sizeof resp, 0};
  wired_h3reqdrive_req r;
  h3conn_resp          resp_out = {0};

  st.settings_sent = 1;
  CHECK(wired_h3reqdrive_send_get(
      0,
      &(wired_h3reqdrive_get_in){
          wired_span_of(path, sizeof path), wired_span_of(auth, sizeof auth)},
      &req_ob));
  CHECK(wired_h3srv_on_request(
      &st,
      &(wired_h3srv_req_in){
          wired_span_of(req, req_ob.len),
          wired_mspan_of(scratch, sizeof scratch)},
      &r));
  {
    wired_h3srv_send_in send = {0, {200, wired_span_of(body, sizeof body), 0}};
    CHECK(wired_h3srv_build_response(&st, &send, &resp_ob));
  }
  CHECK(h3conn_recv_response(wired_span_of(resp, resp_ob.len), &resp_out));
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
  wired_obuf        resp_ob  = {resp, sizeof resp, 0};
  h3conn_resp       resp_out = {0, wired_span_of((const u8*)1, 99), 0};

  st.settings_sent = 1;
  st.request_seen  = 1;
  {
    wired_h3srv_send_in send = {0, {200, wired_span_of(body, sizeof body), 0}};
    wired_h3srv_resp_for_method_in in = {
        wired_span_of(head, sizeof head), send};
    CHECK(wired_h3srv_build_response_for_method(&st, &in, &resp_ob));
  }
  CHECK(h3conn_recv_response(wired_span_of(resp, resp_ob.len), &resp_out));
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
  wired_obuf        resp_ob  = {resp, sizeof resp, 0};
  h3conn_resp       resp_out = {0};

  st.settings_sent = 1;
  st.request_seen  = 1;
  {
    wired_h3srv_send_in send = {0, {200, wired_span_of(body, sizeof body), 0}};
    wired_h3srv_resp_for_method_in in = {wired_span_of(get, sizeof get), send};
    CHECK(wired_h3srv_build_response_for_method(&st, &in, &resp_ob));
  }
  CHECK(h3conn_recv_response(wired_span_of(resp, resp_ob.len), &resp_out));
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
  wired_obuf               req_ob = {req, sizeof req, 0};
  wired_h3reqdrive_req     r;
  wired_h3reqdrive_send_in in = {
      wired_span_of(method, sizeof method), wired_span_of(star, sizeof star),
      wired_span_of(auth, sizeof auth), wired_span_of(0, 0)};

  CHECK(wired_h3reqdrive_send_method(0, &in, &req_ob));
  CHECK(wired_h3srv_on_request(
      &st,
      &(wired_h3srv_req_in){
          wired_span_of(req, req_ob.len),
          wired_mspan_of(scratch, sizeof scratch)},
      &r));
  CHECK(srv_eq(r.method, r.method_len, "OPTIONS", 7));
  CHECK(srv_eq(r.path, r.path_len, "*", 1)); /* 0x2a recovered, not rejected */
}

/* RFC 9114 4.1: no response on a stream that never received a request. */
static void test_h3srv_no_response_without_request(void) {
  wired_h3srv_state st = {0};
  u8                resp[256];
  wired_obuf        resp_ob = {resp, sizeof resp, 0};

  wired_h3srv_send_in send = {0, {200, wired_span_of(0, 0), 0}};
  st.settings_sent         = 1; /* own SETTINGS sent, but no request seen */
  CHECK(!st.request_seen);
  CHECK(!wired_h3srv_build_response(&st, &send, &resp_ob));
}

/* RFC 9114 6.2.1 / 7.2.4: no response before the server's own SETTINGS-first.
 */
static void test_h3srv_no_response_before_own_settings(void) {
  wired_h3srv_state st = {0};
  u8                resp[256];
  wired_obuf        resp_ob = {resp, sizeof resp, 0};

  wired_h3srv_send_in send = {0, {200, wired_span_of(0, 0), 0}};
  st.request_seen = 1; /* request received, but own SETTINGS not yet sent */
  CHECK(!st.settings_sent);
  CHECK(!wired_h3srv_build_response(&st, &send, &resp_ob));
}

/* RFC 9114 7.2.4.2: the server responds without having seen the peer SETTINGS.
 */
static void test_h3srv_respond_without_peer_settings(void) {
  wired_h3srv_state st = {0};
  u8                resp[256];
  wired_obuf        resp_ob  = {resp, sizeof resp, 0};
  h3conn_resp       resp_out = {0};

  wired_h3srv_send_in send = {0, {200, wired_span_of(0, 0), 0}};
  st.settings_sent         = 1;
  st.request_seen          = 1;
  CHECK(!st.peer_settings); /* peer SETTINGS never seen */
  CHECK(wired_h3srv_build_response(&st, &send, &resp_ob));
  CHECK(h3conn_recv_response(wired_span_of(resp, resp_ob.len), &resp_out));
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
  test_h3srv_accept_uni_webtransport();
  test_h3srv_peer_qpack_first_ok();
  test_h3srv_peer_second_qpack_encoder();
  test_h3srv_peer_second_qpack_decoder();
  test_h3srv_peer_qpack_ignores_other_types();
  test_h3srv_request_decode();
  test_h3srv_request_decode_chrome_headers();
  test_h3srv_request_answered();
  test_h3srv_head_no_body();
  test_h3srv_get_keeps_body();
  test_h3srv_options_asterisk();
  test_h3srv_no_response_without_request();
  test_h3srv_no_response_before_own_settings();
  test_h3srv_respond_without_peer_settings();
}
