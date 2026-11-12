#include "app/moqt/ctl/moqctl.h"

#include "app/moqt/ver/moqver.h"
#include "common/bytes/util/ct.h"
#include "moqt_golden.h"
#include "test.h"

/* @file
 * draft-ietf-moq-transport-19 SS10 Control Message codec tests. Golden byte
 * sequences are pinned in tests/app/moqt_golden.h (generated from
 * examples/moqt_chat/testvectors/moqt_golden.json); this file never hand-
 * types a wire byte sequence for round-trip coverage.
 *
 * Coverage: common envelope, per-message round trips, Message Parameters,
 * Setup Options, GOAWAY, REQUEST_OK, REQUEST_ERROR, FORWARD, Reason Phrase,
 * Location, Track Namespace/Name, Location Filter, grease/unknown-code.
 */

/* ===== TEST 1: common envelope round-trip ===== */

static void test_moqctl_peek_type_setup(void) {
  usz        off = 0;
  u64        type;
  wired_span body;

  CHECK(
      moqctl_peek_type(
          wired_span_of(g_moqt_ctl_setup_impl, G_MOQT_CTL_SETUP_IMPL_LEN), &off,
          &type, &body) == MOQCTL_OK);
  CHECK(type == G_MOQT_CTL_SETUP_IMPL_TYPE);
  CHECK(body.n == G_MOQT_CTL_SETUP_IMPL_MSG_LEN);
  CHECK(off == G_MOQT_CTL_SETUP_IMPL_LEN);
}

/* TEST 2: Message Length / Body mismatch -> VIOLATION. Shrink the
 * declared Length by 1 without touching the body bytes. */
static void test_moqctl_peek_type_length_mismatch(void) {
  u8         buf[32];
  usz        off = 0;
  u64        type;
  wired_span body;

  for (usz i = 0; i < G_MOQT_CTL_SUBSCRIBE_OK_BASIC_LEN; i++) {
    buf[i] = g_moqt_ctl_subscribe_ok_basic[i];
  }
  buf[2] = G_MOQT_CTL_SUBSCRIBE_OK_BASIC_MSG_LEN + 1; /* claim one more byte
                                                          than actually
                                                          present */
  CHECK(
      moqctl_peek_type(
          wired_span_of(buf, G_MOQT_CTL_SUBSCRIBE_OK_BASIC_LEN), &off, &type,
          &body) == MOQCTL_INSUFFICIENT);
}

/* TEST 3: body cut short mid-message -> INSUFFICIENT. */
static void test_moqctl_peek_type_truncated(void) {
  usz        off = 0;
  u64        type;
  wired_span body;

  CHECK(
      moqctl_peek_type(
          wired_span_of(
              g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN - 3),
          &off, &type, &body) == MOQCTL_INSUFFICIENT);
}

/* TEST 4: unknown message type -> UNKNOWN_TYPE. Type 0x2 (REQUEST_
 * UPDATE) is known-but-unimplemented; 0x99 is not in the SS10 table at
 * all. */
static void test_moqctl_peek_type_unknown(void) {
  const u8   in[] = {0x99, 0x01, 0x00, 0x00};
  usz        off  = 0;
  u64        type;
  wired_span body;

  CHECK(
      moqctl_peek_type(wired_span_of(in, sizeof in), &off, &type, &body) ==
      MOQCTL_UNKNOWN_TYPE);
}

/* TEST 5: known-but-unimplemented message type is distinguished from an
 * unknown one. REQUEST_UPDATE = 0x2, zero-length body. */
static void test_moqctl_peek_type_known_unimplemented(void) {
  const u8   in[] = {0x02, 0x00, 0x00};
  usz        off  = 0;
  u64        type;
  wired_span body;

  CHECK(
      moqctl_peek_type(wired_span_of(in, sizeof in), &off, &type, &body) ==
      MOQCTL_KNOWN_UNIMPLEMENTED);
}

/* draft-18 SS10's table lists 0x1E as PUBLISH_OK while its SS10.5 makes
 * PUBLISH_OK a REQUEST_OK alias: only a draft-18 session reads 0x1E as
 * REQUEST_OK; draft-19/22 keep it reserved (unknown). */
static void test_moqctl_type_ver_publish_ok_alias(void) {
  u64 t = 0x1E;
  CHECK(moqctl_type_ver(MOQVER_D18, MOQCTL_UNKNOWN_TYPE, &t) == MOQCTL_OK);
  CHECK(t == MOQCTL_T_REQUEST_OK);
  t = 0x1E;
  CHECK(
      moqctl_type_ver(MOQVER_D19, MOQCTL_UNKNOWN_TYPE, &t) ==
      MOQCTL_UNKNOWN_TYPE);
  CHECK(
      moqctl_type_ver(MOQVER_D22, MOQCTL_UNKNOWN_TYPE, &t) ==
      MOQCTL_UNKNOWN_TYPE);
  CHECK(t == 0x1E);
}

/* draft-22 SS9.10 PUBLISH_STATE_NOTIFY (0x22) is a known type only for a
 * draft-22 session. */
static void test_moqctl_type_ver_publish_state_notify(void) {
  u64 t = MOQCTL_T_PUBLISH_STATE_NOTIFY;
  CHECK(
      moqctl_type_ver(MOQVER_D22, MOQCTL_UNKNOWN_TYPE, &t) ==
      MOQCTL_KNOWN_UNIMPLEMENTED);
  CHECK(t == MOQCTL_T_PUBLISH_STATE_NOTIFY);
  CHECK(
      moqctl_type_ver(MOQVER_D19, MOQCTL_UNKNOWN_TYPE, &t) ==
      MOQCTL_UNKNOWN_TYPE);
  CHECK(
      moqctl_type_ver(MOQVER_D18, MOQCTL_UNKNOWN_TYPE, &t) ==
      MOQCTL_UNKNOWN_TYPE);
}

/* Any other classification (and any other Type) passes through as is. */
static void test_moqctl_type_ver_passthrough(void) {
  u64 t = MOQCTL_T_REQUEST_OK;
  CHECK(moqctl_type_ver(MOQVER_D18, MOQCTL_OK, &t) == MOQCTL_OK);
  CHECK(t == MOQCTL_T_REQUEST_OK);
  t = 0x99;
  CHECK(
      moqctl_type_ver(MOQVER_D22, MOQCTL_UNKNOWN_TYPE, &t) ==
      MOQCTL_UNKNOWN_TYPE);
  CHECK(t == 0x99);
}

/* A complete unknown or known-but-unimplemented message is still framed
 * by its Length: off skips the whole message so the caller can carry on
 * with the next one (draft-ietf-moq-transport-19 SS10). */
static void test_moqctl_peek_type_unknown_skips_whole_message(void) {
  const u8   in[] = {0x99, 0x01, 0x00, 0x02, 0xAA, 0xBB, 0x03};
  usz        off  = 0;
  u64        type = 0;
  wired_span body = {0, 0};

  CHECK(
      moqctl_peek_type(wired_span_of(in, sizeof in), &off, &type, &body) ==
      MOQCTL_UNKNOWN_TYPE);
  CHECK(off == 6);
  CHECK(type == 0x1901); /* 2-byte vi64 */
  CHECK(body.n == 2 && body.p == in + 4);
}

static void test_moqctl_peek_type_unimplemented_skips_whole_message(void) {
  const u8   in[] = {0x16, 0x00, 0x01, 0x07, 0x03};
  usz        off  = 0;
  u64        type = 0;
  wired_span body = {0, 0};

  CHECK(
      moqctl_peek_type(wired_span_of(in, sizeof in), &off, &type, &body) ==
      MOQCTL_KNOWN_UNIMPLEMENTED);
  CHECK(off == 4);
  CHECK(type == 0x16);
}

/* FETCH_OK (0x18) is in the SS10 table: known, not unknown. */
static void test_moqctl_peek_type_fetch_ok_is_known(void) {
  const u8   in[] = {0x18, 0x00, 0x00};
  usz        off  = 0;
  u64        type;
  wired_span body;

  CHECK(
      moqctl_peek_type(wired_span_of(in, sizeof in), &off, &type, &body) ==
      MOQCTL_KNOWN_UNIMPLEMENTED);
}

/* An unknown message whose body is cut short, or whose Length (up to the
 * 16-bit maximum) runs past the bytes available, waits for more bytes
 * exactly like a known one: INSUFFICIENT, off untouched. */
static void test_moqctl_peek_type_unknown_truncated_waits(void) {
  const u8   cut[]  = {0x99, 0x01, 0x00, 0x05, 0xAA, 0xBB};
  const u8   huge[] = {0x99, 0x01, 0xFF, 0xFF, 0xAA};
  usz        off    = 0;
  u64        type;
  wired_span body;

  CHECK(
      moqctl_peek_type(wired_span_of(cut, sizeof cut), &off, &type, &body) ==
      MOQCTL_INSUFFICIENT);
  CHECK(off == 0);
  CHECK(
      moqctl_peek_type(wired_span_of(huge, sizeof huge), &off, &type, &body) ==
      MOQCTL_INSUFFICIENT);
  CHECK(off == 0);
}

/* TEST 6: message total length boundary at 2^16-1. A Length field
 * that itself claims the max is accepted by peek_type as long as the body
 * bytes are actually present; this test only exercises the encoding of
 * the boundary value in the Length field via a minimal SUBSCRIBE_OK. */
static void test_moqctl_peek_type_max_len_field(void) {
  u8         buf[8];
  usz        off = 0;
  u64        type;
  wired_span body;

  buf[0] = 0x04; /* SUBSCRIBE_OK */
  buf[1] = 0xFF;
  buf[2] = 0xFF; /* Length = 65535, but only 2 bytes follow: insufficient */
  CHECK(
      moqctl_peek_type(wired_span_of(buf, 3), &off, &type, &body) ==
      MOQCTL_INSUFFICIENT);
}

/* ===== TEST 7-14: per-message round trip against golden ===== */

static void test_moqctl_setup_roundtrip(void) {
  usz          off = 0;
  u64          type;
  wired_span   body;
  moqctl_setup s;
  u8           out[G_MOQT_CTL_SETUP_IMPL_LEN];
  wired_mspan  ob   = wired_mspan_of(out, sizeof out);
  usz          eoff = 0;

  CHECK(
      moqctl_peek_type(
          wired_span_of(g_moqt_ctl_setup_impl, G_MOQT_CTL_SETUP_IMPL_LEN), &off,
          &type, &body) == MOQCTL_OK);
  {
    usz boff = 0;
    CHECK(moqctl_setup_take(body, &boff, &s) == MOQCTL_OK);
    CHECK(boff == body.n);
  }
  CHECK(!s.has_path);
  CHECK(!s.has_authority);
  CHECK(s.has_implementation);
  CHECK(s.implementation.n == 7);
  CHECK(s.implementation.p[0] == 'w');

  CHECK(moqvi_put(ob, &eoff, type));
  {
    usz         len_at = eoff;
    usz         body_at;
    wired_mspan full = wired_mspan_of(out, sizeof out);
    eoff += 2; /* placeholder for Length */
    body_at = eoff;
    CHECK(moqctl_setup_encode(full, &eoff, &s));
    out[len_at]     = (u8)((eoff - body_at) >> 8);
    out[len_at + 1] = (u8)(eoff - body_at);
  }
  CHECK(eoff == G_MOQT_CTL_SETUP_IMPL_LEN);
  for (usz i = 0; i < eoff; i++) {
    CHECK(out[i] == g_moqt_ctl_setup_impl[i]);
  }
}

/* Shared re-encode helper for the remaining messages: writes Type (vi64) +
 * placeholder Length + calls encode_body, then backpatches Length. */
typedef int (*moqctl_encode_body_fn)(wired_mspan, usz*, const void*);

static void moqctl_reencode(
    u8*                   out,
    usz                   cap,
    u64                   type,
    moqctl_encode_body_fn body_fn,
    const void*           msg,
    usz*                  out_len) {
  wired_mspan full = wired_mspan_of(out, cap);
  usz         eoff = 0;
  usz         len_at;
  usz         body_at;
  CHECK(moqvi_put(full, &eoff, type));
  len_at = eoff;
  eoff += 2;
  body_at = eoff;
  CHECK(body_fn(full, &eoff, msg));
  out[len_at]     = (u8)((eoff - body_at) >> 8);
  out[len_at + 1] = (u8)(eoff - body_at);
  *out_len        = eoff;
}

static int moqctl_encode_subscribe(wired_mspan buf, usz* off, const void* m) {
  return moqctl_subscribe_encode(buf, off, m);
}

static void test_moqctl_subscribe_roundtrip(void) {
  usz              off = 0;
  u64              type;
  wired_span       body;
  moqctl_subscribe m;
  u8               out[G_MOQT_CTL_SUBSCRIBE_BASIC_LEN];
  usz              out_len;

  CHECK(
      moqctl_peek_type(
          wired_span_of(
              g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
          &off, &type, &body) == MOQCTL_OK);
  {
    usz boff = 0;
    CHECK(moqctl_subscribe_take(MOQVER_D19, body, &boff, &m) == MOQCTL_OK);
    CHECK(boff == body.n);
  }
  CHECK(m.request_id == 0);
  CHECK(m.name.ns.n == 2);
  CHECK(m.name.ns.fields[0].n == 4);
  CHECK(m.name.ns.fields[0].p[0] == 'c');
  CHECK(m.name.ns.fields[1].n == 5);
  CHECK(m.name.name.n == 5);
  CHECK(m.name.name.p[0] == 'a');
  CHECK(m.params.n == 0);

  moqctl_reencode(out, sizeof out, type, moqctl_encode_subscribe, &m, &out_len);
  CHECK(out_len == G_MOQT_CTL_SUBSCRIBE_BASIC_LEN);
  for (usz i = 0; i < out_len; i++) {
    CHECK(out[i] == g_moqt_ctl_subscribe_basic[i]);
  }
}

static int moqctl_encode_subscribe_ok(
    wired_mspan buf, usz* off, const void* m) {
  return moqctl_subscribe_ok_encode(buf, off, m);
}

static void test_moqctl_subscribe_ok_roundtrip(void) {
  usz                 off = 0;
  u64                 type;
  wired_span          body;
  moqctl_subscribe_ok m;
  u8                  out[G_MOQT_CTL_SUBSCRIBE_OK_BASIC_LEN];
  usz                 out_len;

  CHECK(
      moqctl_peek_type(
          wired_span_of(
              g_moqt_ctl_subscribe_ok_basic, G_MOQT_CTL_SUBSCRIBE_OK_BASIC_LEN),
          &off, &type, &body) == MOQCTL_OK);
  {
    usz boff = 0;
    CHECK(moqctl_subscribe_ok_take(MOQVER_D19, body, &boff, &m) == MOQCTL_OK);
  }
  CHECK(m.track_alias == 1);
  CHECK(m.params.n == 0);
  CHECK(m.track_properties.n == 0);

  moqctl_reencode(
      out, sizeof out, type, moqctl_encode_subscribe_ok, &m, &out_len);
  CHECK(out_len == G_MOQT_CTL_SUBSCRIBE_OK_BASIC_LEN);
  for (usz i = 0; i < out_len; i++) {
    CHECK(out[i] == g_moqt_ctl_subscribe_ok_basic[i]);
  }
}

static int moqctl_encode_publish(wired_mspan buf, usz* off, const void* m) {
  return moqctl_publish_encode(buf, off, m);
}

static void test_moqctl_publish_roundtrip(void) {
  usz            off = 0;
  u64            type;
  wired_span     body;
  moqctl_publish m;
  u8             out[G_MOQT_CTL_PUBLISH_BASIC_LEN];
  usz            out_len;

  CHECK(
      moqctl_peek_type(
          wired_span_of(g_moqt_ctl_publish_basic, G_MOQT_CTL_PUBLISH_BASIC_LEN),
          &off, &type, &body) == MOQCTL_OK);
  {
    usz boff = 0;
    CHECK(moqctl_publish_take(MOQVER_D19, body, &boff, &m) == MOQCTL_OK);
  }
  CHECK(m.request_id == 0);
  CHECK(m.name.ns.n == 2);
  CHECK(m.track_alias == 1);
  CHECK(m.params.n == 0);
  CHECK(m.track_properties.n == 0);

  moqctl_reencode(out, sizeof out, type, moqctl_encode_publish, &m, &out_len);
  CHECK(out_len == G_MOQT_CTL_PUBLISH_BASIC_LEN);
  for (usz i = 0; i < out_len; i++) {
    CHECK(out[i] == g_moqt_ctl_publish_basic[i]);
  }
}

static int moqctl_encode_request_ok(wired_mspan buf, usz* off, const void* m) {
  return moqctl_request_ok_encode(buf, off, m);
}

static void test_moqctl_request_ok_roundtrip(void) {
  usz               off = 0;
  u64               type;
  wired_span        body;
  moqctl_request_ok m;
  u8                out[G_MOQT_CTL_REQUEST_OK_BASIC_LEN];
  usz               out_len;

  CHECK(
      moqctl_peek_type(
          wired_span_of(
              g_moqt_ctl_request_ok_basic, G_MOQT_CTL_REQUEST_OK_BASIC_LEN),
          &off, &type, &body) == MOQCTL_OK);
  {
    usz boff = 0;
    CHECK(moqctl_request_ok_take(MOQVER_D19, body, &boff, &m) == MOQCTL_OK);
  }
  CHECK(m.params.n == 0);
  CHECK(m.track_properties.n == 0);

  moqctl_reencode(
      out, sizeof out, type, moqctl_encode_request_ok, &m, &out_len);
  CHECK(out_len == G_MOQT_CTL_REQUEST_OK_BASIC_LEN);
  for (usz i = 0; i < out_len; i++) {
    CHECK(out[i] == g_moqt_ctl_request_ok_basic[i]);
  }
}

static int moqctl_encode_request_error(
    wired_mspan buf, usz* off, const void* m) {
  return moqctl_request_error_encode(buf, off, m);
}

static void test_moqctl_request_error_roundtrip(void) {
  usz                  off = 0;
  u64                  type;
  wired_span           body;
  moqctl_request_error m;
  u8                   out[G_MOQT_CTL_REQUEST_ERROR_NOT_SUPPORTED_LEN];
  usz                  out_len;

  CHECK(
      moqctl_peek_type(
          wired_span_of(
              g_moqt_ctl_request_error_not_supported,
              G_MOQT_CTL_REQUEST_ERROR_NOT_SUPPORTED_LEN),
          &off, &type, &body) == MOQCTL_OK);
  {
    usz boff = 0;
    CHECK(moqctl_request_error_take(body, &boff, &m) == MOQCTL_OK);
  }
  CHECK(m.error_code == MOQCTL_ERR_NOT_SUPPORTED);
  CHECK(m.retry_interval == 0);
  CHECK(m.reason.n == 13);
  CHECK(!m.has_redirect);

  moqctl_reencode(
      out, sizeof out, type, moqctl_encode_request_error, &m, &out_len);
  CHECK(out_len == G_MOQT_CTL_REQUEST_ERROR_NOT_SUPPORTED_LEN);
  for (usz i = 0; i < out_len; i++) {
    CHECK(out[i] == g_moqt_ctl_request_error_not_supported[i]);
  }
}

static int moqctl_encode_publish_done(
    wired_mspan buf, usz* off, const void* m) {
  return moqctl_publish_done_encode(buf, off, m);
}

static void test_moqctl_publish_done_roundtrip(void) {
  usz                 off = 0;
  u64                 type;
  wired_span          body;
  moqctl_publish_done m;
  u8                  out[G_MOQT_CTL_PUBLISH_DONE_TRACK_ENDED_LEN];
  usz                 out_len;

  CHECK(
      moqctl_peek_type(
          wired_span_of(
              g_moqt_ctl_publish_done_track_ended,
              G_MOQT_CTL_PUBLISH_DONE_TRACK_ENDED_LEN),
          &off, &type, &body) == MOQCTL_OK);
  {
    usz boff = 0;
    CHECK(moqctl_publish_done_take(body, &boff, &m) == MOQCTL_OK);
  }
  CHECK(m.status_code == MOQCTL_DONE_TRACK_ENDED);
  CHECK(m.stream_count == 2);
  CHECK(m.reason.n == 0);

  moqctl_reencode(
      out, sizeof out, type, moqctl_encode_publish_done, &m, &out_len);
  CHECK(out_len == G_MOQT_CTL_PUBLISH_DONE_TRACK_ENDED_LEN);
  for (usz i = 0; i < out_len; i++) {
    CHECK(out[i] == g_moqt_ctl_publish_done_track_ended[i]);
  }
}

static int moqctl_encode_goaway(wired_mspan buf, usz* off, const void* m) {
  return moqctl_goaway_encode(buf, off, m);
}

static void test_moqctl_goaway_roundtrip(void) {
  usz           off = 0;
  u64           type;
  wired_span    body;
  moqctl_goaway m;
  u8            out[G_MOQT_CTL_GOAWAY_EMPTY_LEN];
  usz           out_len;

  CHECK(
      moqctl_peek_type(
          wired_span_of(g_moqt_ctl_goaway_empty, G_MOQT_CTL_GOAWAY_EMPTY_LEN),
          &off, &type, &body) == MOQCTL_OK);
  {
    usz boff = 0;
    CHECK(moqctl_goaway_take(body, &boff, &m) == MOQCTL_OK);
  }
  CHECK(m.new_session_uri.n == 0);
  CHECK(m.timeout == 0);

  moqctl_reencode(out, sizeof out, type, moqctl_encode_goaway, &m, &out_len);
  CHECK(out_len == G_MOQT_CTL_GOAWAY_EMPTY_LEN);
  for (usz i = 0; i < out_len; i++) {
    CHECK(out[i] == g_moqt_ctl_goaway_empty[i]);
  }
}

/* draft-18 SS10.4: a control-stream GOAWAY ends with [Request ID]:
 * empty URI, Timeout 5, Request ID 4 is 00 05 04, and round-trips. */
static void test_moqctl_goaway18_request_id(void) {
  static const u8 wire[] = {0x00, 0x05, 0x04};
  moqctl_goaway   m      = {0};
  u8              out[8];
  usz             off = 0, n = 0;
  CHECK(
      moqctl_goaway18_take(wired_span_of(wire, sizeof wire), &off, &m) ==
      MOQCTL_OK);
  CHECK(off == sizeof wire);
  CHECK(m.new_session_uri.n == 0 && m.timeout == 5 && m.request_id == 4);
  CHECK(moqctl_goaway18_encode(wired_mspan_of(out, sizeof out), &n, &m));
  CHECK(n == sizeof wire);
  for (usz i = 0; i < n; i++) {
    CHECK(out[i] == wire[i]);
  }
}

/* A draft-19 body (no Request ID) is cut short for draft-18, and the
 * draft-19 decoder stops before a draft-18 Request ID. */
static void test_moqctl_goaway18_vs_19_shape(void) {
  static const u8 d19[] = {0x00, 0x05};
  static const u8 d18[] = {0x00, 0x05, 0x04};
  moqctl_goaway   m;
  usz             off = 0;
  CHECK(
      moqctl_goaway18_take(wired_span_of(d19, sizeof d19), &off, &m) ==
      MOQCTL_INSUFFICIENT);
  off = 0;
  CHECK(
      moqctl_goaway_take(wired_span_of(d18, sizeof d18), &off, &m) ==
      MOQCTL_OK);
  CHECK(off == 2);
}

/* ===== TEST: GOAWAY New Session URI 8192 boundary ===== */

static void test_moqctl_goaway_uri_boundary(void) {
  u8            buf_ok[3 + MOQCTL_MAX_URI_LEN + 4];
  u8            buf_reject[3 + MOQCTL_MAX_URI_LEN + 5];
  usz           at;
  moqctl_goaway m;

  /* 8192 accepted: len varint(2B, 0x9f 0x40 encodes 8192) + 8192 bytes +
   * timeout varint(1B, 0x00). moqvi_put proves the length encoding; we
   * only need decode acceptance here. */
  at = 0;
  CHECK(moqvi_put(wired_mspan_of(buf_ok, sizeof buf_ok), &at, 8192));
  for (usz i = 0; i < MOQCTL_MAX_URI_LEN; i++) {
    buf_ok[at + i] = 'a';
  }
  at += MOQCTL_MAX_URI_LEN;
  CHECK(moqvi_put(wired_mspan_of(buf_ok, sizeof buf_ok), &at, 0));
  {
    usz off = 0;
    CHECK(moqctl_goaway_take(wired_span_of(buf_ok, at), &off, &m) == MOQCTL_OK);
    CHECK(m.new_session_uri.n == MOQCTL_MAX_URI_LEN);
  }

  /* 8193 rejected */
  at = 0;
  CHECK(moqvi_put(
      wired_mspan_of(buf_reject, sizeof buf_reject), &at,
      MOQCTL_MAX_URI_LEN + 1));
  for (usz i = 0; i < MOQCTL_MAX_URI_LEN + 1; i++) {
    buf_reject[at + i] = 'a';
  }
  at += MOQCTL_MAX_URI_LEN + 1;
  {
    usz off = 0;
    CHECK(
        moqctl_goaway_take(wired_span_of(buf_reject, at), &off, &m) ==
        MOQCTL_R_FIELD_LEN);
  }
}

/* ===== TEST: Reason Phrase 1024 boundary ===== */

static void test_moqctl_reason_boundary(void) {
  u8            buf_ok[3 + MOQCTL_MAX_REASON_LEN];
  u8            buf_reject[3 + MOQCTL_MAX_REASON_LEN + 1];
  usz           at;
  moqctl_reason r;

  at = 0;
  CHECK(moqvi_put(wired_mspan_of(buf_ok, sizeof buf_ok), &at, 1024));
  for (usz i = 0; i < 1024; i++) {
    buf_ok[at + i] = 'x';
  }
  at += 1024;
  {
    usz off = 0;
    CHECK(moqctl_reason_take(wired_span_of(buf_ok, at), &off, &r) == MOQCTL_OK);
    CHECK(r.n == 1024);
  }

  at = 0;
  CHECK(moqvi_put(wired_mspan_of(buf_reject, sizeof buf_reject), &at, 1025));
  for (usz i = 0; i < 1025; i++) {
    buf_reject[at + i] = 'x';
  }
  at += 1025;
  {
    usz off = 0;
    CHECK(
        moqctl_reason_take(wired_span_of(buf_reject, at), &off, &r) ==
        MOQCTL_R_FIELD_LEN);
  }
}

/* ===== TEST: Location encode/compare ===== */

static void test_moqctl_location_roundtrip_and_order(void) {
  u8         buf[32];
  usz        off = 0;
  moqctl_loc a   = {5, 10};
  moqctl_loc b   = {5, 11};
  moqctl_loc c   = {6, 0};
  moqctl_loc out;

  CHECK(moqctl_loc_put(wired_mspan_of(buf, sizeof buf), &off, a));
  {
    usz roff = 0;
    CHECK(moqctl_loc_take(wired_span_of(buf, off), &roff, &out) == MOQCTL_OK);
    CHECK(out.group == a.group);
    CHECK(out.object == a.object);
  }
  CHECK(moqctl_loc_less(a, b));
  CHECK(moqctl_loc_less(b, c));
  CHECK(!moqctl_loc_less(b, a));
}

/* ===== TEST: Track Namespace / Full Track Name ===== */

static void test_moqctl_ftn_decode_basic(void) {
  moqctl_ftn f;
  usz        off = 0;

  CHECK(
      moqctl_ftn_take(
          wired_span_of(
              g_moqt_name_full_track_name_basic,
              G_MOQT_NAME_FULL_TRACK_NAME_BASIC_LEN),
          &off, &f) == MOQCTL_OK);
  CHECK(off == G_MOQT_NAME_FULL_TRACK_NAME_BASIC_LEN);
  CHECK(f.ns.n == 2);
  CHECK(f.ns.fields[0].n == 4);
  CHECK(f.ns.fields[1].n == 5);
  CHECK(f.name.n == 5);
}

/* Field Length 0 -> PROTOCOL_VIOLATION. */
static void test_moqctl_ns_field_len_zero_rejected(void) {
  moqctl_ns ns;
  usz       off = 0;

  CHECK(
      moqctl_ns_take(
          wired_span_of(
              g_moqt_name_ns_field_len_zero_reject,
              G_MOQT_NAME_NS_FIELD_LEN_ZERO_REJECT_LEN),
          &off, &ns) == MOQCTL_R_TRACK_NS);
}

/* 32 fields accepted, 33 rejected. */
static void test_moqctl_ns_fields_32_accept_33_reject(void) {
  moqctl_ns ns;
  usz       off;

  off = 0;
  CHECK(
      moqctl_ns_take(
          wired_span_of(
              g_moqt_name_ns_fields_32_accept,
              G_MOQT_NAME_NS_FIELDS_32_ACCEPT_LEN),
          &off, &ns) == MOQCTL_OK);
  CHECK(ns.n == 32);

  off = 0;
  CHECK(
      moqctl_ns_take(
          wired_span_of(
              g_moqt_name_ns_fields_33_reject,
              G_MOQT_NAME_NS_FIELDS_33_REJECT_LEN),
          &off, &ns) == MOQCTL_R_TRACK_NS);
}

/* Full Track Name 4096 boundary. */
static void test_moqctl_ftn_4096_accept_4097_reject(void) {
  moqctl_ftn f;
  usz        off;

  off = 0;
  CHECK(
      moqctl_ftn_take(
          wired_span_of(
              g_moqt_name_ftn_4096_accept, G_MOQT_NAME_FTN_4096_ACCEPT_LEN),
          &off, &f) == MOQCTL_OK);

  off = 0;
  CHECK(
      moqctl_ftn_take(
          wired_span_of(
              g_moqt_name_ftn_4097_reject, G_MOQT_NAME_FTN_4097_REJECT_LEN),
          &off, &f) == MOQCTL_R_FIELD_LEN);
}

/* ===== TEST: Message Parameters ===== */

/* FORWARD (uint8) round trip inside SUBSCRIBE's scope. */
static void test_moqctl_params_forward_roundtrip(void) {
  u8            buf[16];
  usz           off = 0;
  moqctl_params p   = {0};
  moqctl_params out;

  p.items[0].type = MOQCTL_PARAM_FORWARD;
  p.items[0].enc  = MOQCTL_PENC_UINT8;
  p.items[0].u8v  = 0;
  p.n             = 1;

  CHECK(moqctl_params_put(wired_mspan_of(buf, sizeof buf), &off, &p));
  {
    usz roff = 0;
    CHECK(
        moqctl_params_take(
            MOQVER_D19, wired_span_of(buf, off), &roff, MOQCTL_PCTX_SUBSCRIBE,
            &out) == MOQCTL_OK);
  }
  CHECK(out.n == 1);
  CHECK(out.items[0].type == MOQCTL_PARAM_FORWARD);
  CHECK(out.items[0].u8v == 0);
}

/* Cumulative Parameter Type overflow -> VIOLATION. Two params whose
 * deltas sum past 2^64-1. */
static void test_moqctl_params_type_overflow_violation(void) {
  u8            buf[24];
  usz           off = 0;
  moqctl_params out;

  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 2)); /* count */
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, MOQCTL_PARAM_FORWARD));
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 1)); /* value */
  CHECK(
      moqvi_put(wired_mspan_of(buf, sizeof buf), &off, (u64)-1)); /* delta
                                                                     overflow */
  {
    usz roff = 0;
    CHECK(
        moqctl_params_take(
            MOQVER_D19, wired_span_of(buf, off), &roff, MOQCTL_PCTX_SUBSCRIBE,
            &out) == MOQCTL_R_DELTA);
  }
}

/* Unknown Message Parameter Type -> VIOLATION. */
static void test_moqctl_params_unknown_type_violation(void) {
  u8            buf[8];
  usz           off = 0;
  moqctl_params out;

  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 1));
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 0x77));
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 0));
  {
    usz roff = 0;
    CHECK(
        moqctl_params_take(
            MOQVER_D19, wired_span_of(buf, off), &roff, MOQCTL_PCTX_SUBSCRIBE,
            &out) == MOQCTL_R_PARAM);
  }
}

/* Duplicate Parameter Type -> VIOLATION. */
static void test_moqctl_params_duplicate_type_violation(void) {
  u8            buf[16];
  usz           off = 0;
  moqctl_params out;

  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 2));
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, MOQCTL_PARAM_FORWARD));
  buf[off] = 1;
  off += 1;                                                   /* uint8 value */
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 0)); /* delta 0
                                                                      -> same
                                                                      type */
  buf[off] = 1;
  off += 1;
  {
    usz roff = 0;
    CHECK(
        moqctl_params_take(
            MOQVER_D19, wired_span_of(buf, off), &roff, MOQCTL_PCTX_SUBSCRIBE,
            &out) == MOQCTL_R_PARAM);
  }
}

/* Known parameter type outside its allowed message scope ->
 * VIOLATION. FORWARD is legal in SUBSCRIBE/PUBLISH but not SUBSCRIBE_OK. */
static void test_moqctl_params_scope_violation(void) {
  u8            buf[8];
  usz           off = 0;
  moqctl_params out;

  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 1));
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, MOQCTL_PARAM_FORWARD));
  buf[off] = 1;
  off += 1;
  {
    usz roff = 0;
    CHECK(
        moqctl_params_take(
            MOQVER_D19, wired_span_of(buf, off), &roff,
            MOQCTL_PCTX_SUBSCRIBE_OK, &out) == MOQCTL_R_PARAM);
  }
}

/* SUBGROUP/OBJECT_DELIVERY_TIMEOUT decode as varint, 0 = unset. */
static void test_moqctl_params_delivery_timeout_decode(void) {
  u8            buf[16];
  usz           off = 0;
  moqctl_params out;

  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 1));
  CHECK(moqvi_put(
      wired_mspan_of(buf, sizeof buf), &off,
      MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT));
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 0));
  {
    usz roff = 0;
    CHECK(
        moqctl_params_take(
            MOQVER_D19, wired_span_of(buf, off), &roff, MOQCTL_PCTX_SUBSCRIBE,
            &out) == MOQCTL_OK);
  }
  CHECK(out.n == 1);
  CHECK(out.items[0].vi == 0);
}

/* Builds one Message Parameter list: count 1, Type 0x03 (AUTHORIZATION
 * TOKEN, draft SS10.2.2), Length-prefixed Token bytes `tok`. */
static usz moqctl_test_auth_param(u8* buf, usz cap, const u8* tok, usz n) {
  usz off = 0;
  CHECK(moqvi_put(wired_mspan_of(buf, cap), &off, 1));
  CHECK(moqvi_put(
      wired_mspan_of(buf, cap), &off, MOQCTL_PARAM_AUTHORIZATION_TOKEN));
  CHECK(moqvi_put(wired_mspan_of(buf, cap), &off, n));
  for (usz i = 0; i < n; i++) {
    buf[off + i] = tok[i];
  }
  return off + n;
}

/* draft SS10.2.2 AUTHORIZATION TOKEN (Type 0x03) with Alias Type USE_VALUE
 * decodes inside SUBSCRIBE: Token Type 0x01, Token Value "ab". Pinned wire
 * bytes: [03 (USE_VALUE), 01 (Token Type), 61 62]. */
static void test_moqctl_params_auth_token_use_value_decode(void) {
  static const u8 tok[] = {0x03, 0x01, 0x61, 0x62};
  u8              buf[16];
  usz             n = moqctl_test_auth_param(buf, sizeof buf, tok, sizeof tok);
  moqctl_params   out;
  usz             roff = 0;
  CHECK(
      moqctl_params_take(
          MOQVER_D19, wired_span_of(buf, n), &roff, MOQCTL_PCTX_SUBSCRIBE,
          &out) == MOQCTL_OK);
  CHECK(out.n == 1);
  CHECK(out.items[0].type == MOQCTL_PARAM_AUTHORIZATION_TOKEN);
  CHECK(out.items[0].enc == MOQCTL_PENC_TOKEN);
  CHECK(out.items[0].token.alias_type == MOQCTL_TOKEN_USE_VALUE);
  CHECK(out.items[0].token.token_type == 1);
  wired_span v = out.items[0].token.value;
  CHECK(v.n == 2 && v.p[0] == 0x61 && v.p[1] == 0x62);
  CHECK(roff == n);
}

/* REGISTER carries Alias + Type + Value; DELETE/USE_ALIAS carry only the
 * Alias (SS10.2.2 Figure 5). Both PUBLISH and SUBSCRIBE may carry it. */
static void test_moqctl_params_auth_token_alias_shapes_decode(void) {
  static const u8 reg[] = {0x01, 0x07, 0x01, 0x78};
  static const u8 use[] = {0x02, 0x07};
  u8              buf[16];
  moqctl_params   out;
  usz             n = moqctl_test_auth_param(buf, sizeof buf, reg, sizeof reg);
  usz             roff = 0;
  CHECK(
      moqctl_params_take(
          MOQVER_D19, wired_span_of(buf, n), &roff, MOQCTL_PCTX_PUBLISH,
          &out) == MOQCTL_OK);
  CHECK(out.items[0].token.alias_type == MOQCTL_TOKEN_REGISTER);
  CHECK(out.items[0].token.alias == 7);
  CHECK(out.items[0].token.token_type == 1);
  CHECK(out.items[0].token.value.n == 1);
  n    = moqctl_test_auth_param(buf, sizeof buf, use, sizeof use);
  roff = 0;
  CHECK(
      moqctl_params_take(
          MOQVER_D19, wired_span_of(buf, n), &roff, MOQCTL_PCTX_SUBSCRIBE,
          &out) == MOQCTL_OK);
  CHECK(out.items[0].token.alias_type == MOQCTL_TOKEN_USE_ALIAS);
  CHECK(out.items[0].token.alias == 7);
}

/* An undecodable Token structure is KEY_VALUE_FORMATTING_ERROR
 * (SS10.2.2): unknown Alias Type, USE_VALUE truncated before Token Type,
 * DELETE with bytes trailing the Alias, USE_ALIAS cut before its Alias,
 * and a zero-length value (no Alias Type at all). */
static void test_moqctl_params_auth_token_malformed_kvfmt(void) {
  static const u8 bad_alias_type[] = {0x04, 0x01};
  static const u8 truncated[]      = {0x03};
  static const u8 trailing[]       = {0x00, 0x07, 0xFF};
  static const u8 no_alias[]       = {0x02};
  const u8*       cases[5]         = {
      bad_alias_type, truncated, trailing, no_alias, no_alias};
  const usz lens[5] = {2, 1, 3, 1, 0};
  for (usz i = 0; i < 5; i++) {
    u8            buf[16];
    moqctl_params out;
    usz n    = moqctl_test_auth_param(buf, sizeof buf, cases[i], lens[i]);
    usz roff = 0;
    CHECK(
        moqctl_params_take(
            MOQVER_D19, wired_span_of(buf, n), &roff, MOQCTL_PCTX_SUBSCRIBE,
            &out) == MOQCTL_R_AUTH_TOKEN);
  }
}

/* AUTHORIZATION TOKEN outside its scope (SUBSCRIBE_OK) -> VIOLATION
 * (SS10.2.1). */
static void test_moqctl_params_auth_token_scope_violation(void) {
  static const u8 tok[] = {0x03, 0x01, 0x61};
  u8              buf[16];
  usz             n = moqctl_test_auth_param(buf, sizeof buf, tok, sizeof tok);
  moqctl_params   out;
  usz             roff = 0;
  CHECK(
      moqctl_params_take(
          MOQVER_D19, wired_span_of(buf, n), &roff, MOQCTL_PCTX_SUBSCRIBE_OK,
          &out) == MOQCTL_R_PARAM);
}

/* draft-ietf-moq-transport-19 10.2.x / 15.7 Table 13: each Message
 * Parameter Type, a well-formed Value, and the MOQCTL_PCTX_* set whose
 * "MAY appear in" sentence names it (plus SUBSCRIBE_TRACKS where 10.19.1
 * extends every SUBSCRIBE parameter to it). Copied from the draft, not
 * from moqctl.c, so the test is an independent oracle. */
typedef struct {
  u64       type;
  u32       ctx;
  const u8* val;
  usz       n;
} mqpt_row;

static const u8 MQPT_VARINT[]   = {0x05};
static const u8 MQPT_UINT8[]    = {0x01};
static const u8 MQPT_TOKEN[]    = {0x02, 0x02, 0x07}; /* USE_ALIAS 7 */
static const u8 MQPT_LOC[]      = {0x07, 0x03};
static const u8 MQPT_RANGE[]    = {0x02, 0x00, 0x03}; /* SetID 0, Start 3 */
static const u8 MQPT_PROPRNG[]  = {0x03, 0x00, 0x02, 0x03};
static const u8 MQPT_LOCFLT[]   = {0x01, 0x01};       /* Next Group Start */
static const u8 MQPT_NS[]       = {0x01, 0x01, 0x61}; /* namespace ("a") */
static const u8 MQPT_FILL[]     = {0x01, 0x00};       /* Length 1, 0 params */
static const u8 MQPT_LOCFLT22[] = {0x05};             /* d22 Next Object */

static const mqpt_row MQPT_REGISTRY[] = {
    {0x02, 0x7D009, MQPT_VARINT, 1},  {0x03, 0x7D555, MQPT_TOKEN, 3},
    {0x04, 0x1001, MQPT_VARINT, 1},   {0x06, 0x7D009, MQPT_VARINT, 1},
    {0x08, 0x82A0E, MQPT_VARINT, 1},  {0x09, 0x80086, MQPT_LOC, 2},
    {0x0A, 0x10, MQPT_VARINT, 1},     {0x10, 0x500D, MQPT_UINT8, 1},
    {0x20, 0xD019, MQPT_UINT8, 1},    {0x22, 0x1015, MQPT_UINT8, 1},
    {0x25, 0x5019, MQPT_RANGE, 3},    {0x26, 0x5019, MQPT_RANGE, 3},
    {0x27, 0x5019, MQPT_RANGE, 3},    {0x28, 0x5019, MQPT_PROPRNG, 4},
    {0x29, 0x21000, MQPT_PROPRNG, 4}, {0x32, 0x5009, MQPT_VARINT, 1},
    {0x21, 0x5009, MQPT_LOCFLT, 2},   {0x34, 0x30000, MQPT_NS, 3},
    {0x23, 0, MQPT_FILL, 2},          {0x35, 0, MQPT_UINT8, 1},
};
#define MQPT_REGISTRY_N (sizeof MQPT_REGISTRY / sizeof MQPT_REGISTRY[0])

/* count 1 + Type + r's Value; returns the list length. */
static usz mqpt_build(u8* buf, usz cap, const mqpt_row* r) {
  usz off = 0;
  CHECK(moqvi_put(wired_mspan_of(buf, cap), &off, 1));
  CHECK(moqvi_put(wired_mspan_of(buf, cap), &off, r->type));
  for (usz i = 0; i < r->n; i++) {
    buf[off + i] = r->val[i];
  }
  return off + r->n;
}

/* One parameter decoded under one context bit: accepted (and consumed
 * whole) exactly when the registry lists that context, else
 * PROTOCOL_VIOLATION (10.2.1). */
static void mqpt_check_one(const mqpt_row* r, u32 bit) {
  static moqctl_params out;
  u8                   buf[16];
  usz                  n    = mqpt_build(buf, sizeof buf, r);
  usz                  roff = 0;
  int                  got =
      moqctl_params_take(MOQVER_D19, wired_span_of(buf, n), &roff, bit, &out);
  CHECK(got == ((r->ctx & bit) ? MOQCTL_OK : MOQCTL_R_PARAM));
  CHECK(got != MOQCTL_OK || (roff == n && out.items[0].type == r->type));
}

static void test_moqctl_params_registry_scope(void) {
  for (usz i = 0; i < MQPT_REGISTRY_N; i++) {
    for (u32 b = 0; b < 20; b++) {
      mqpt_check_one(&MQPT_REGISTRY[i], 1u << b);
    }
  }
}

/* draft-18 SS10.2.x "MAY appear in" (no SUBSCRIBE_TRACKS inheritance,
 * 0x25-0x29 / 0x23 / 0x35 unknown); GROUP_ORDER is SUBSCRIBE, PUBLISH_OK
 * or FETCH only (SS10.2.8 -- draft-18 SS10.19 echoes FORWARD alone). */
static const mqpt_row MQPT_REGISTRY18[] = {
    {0x02, 0x7C009, MQPT_VARINT, 1}, {0x03, 0x7D555, MQPT_TOKEN, 3},
    {0x04, 0x1, MQPT_VARINT, 1},     {0x06, 0x7C009, MQPT_VARINT, 1},
    {0x08, 0x8000E, MQPT_VARINT, 1}, {0x09, 0x80086, MQPT_LOC, 2},
    {0x0A, 0x10, MQPT_VARINT, 1},    {0x10, 0x500D, MQPT_UINT8, 1},
    {0x20, 0xC019, MQPT_UINT8, 1},   {0x22, 0x19, MQPT_UINT8, 1},
    {0x25, 0, MQPT_RANGE, 3},        {0x26, 0, MQPT_RANGE, 3},
    {0x27, 0, MQPT_RANGE, 3},        {0x28, 0, MQPT_PROPRNG, 4},
    {0x29, 0, MQPT_PROPRNG, 4},      {0x32, 0x4009, MQPT_VARINT, 1},
    {0x21, 0x4009, MQPT_LOCFLT, 2},  {0x34, 0x30000, MQPT_NS, 3},
    {0x23, 0, MQPT_FILL, 2},         {0x35, 0, MQPT_UINT8, 1},
};

/* draft-22 SS9.20.x "MAY appear in" (an unqualified REQUEST_UPDATE is
 * every kind, as in the draft-19 table); LOCATION_FILTER has no Length
 * (SS9.20.9), FILL_PARAMETERS is Length + Number of Parameters +
 * Parameters (SS9.20.15). */
static const mqpt_row MQPT_REGISTRY22[] = {
    {0x02, 0x7C005, MQPT_VARINT, 1},  {0x03, 0x7D555, MQPT_TOKEN, 3},
    {0x04, 0x1, MQPT_VARINT, 1},      {0x06, 0x7C005, MQPT_VARINT, 1},
    {0x08, 0x82A0E, MQPT_VARINT, 1},  {0x09, 0x80086, MQPT_LOC, 2},
    {0x0A, 0x10, MQPT_VARINT, 1},     {0x10, 0x25005, MQPT_UINT8, 1},
    {0x20, 0xC015, MQPT_UINT8, 1},    {0x22, 0x1015, MQPT_UINT8, 1},
    {0x25, 0x5011, MQPT_RANGE, 3},    {0x26, 0x5011, MQPT_RANGE, 3},
    {0x27, 0x5011, MQPT_RANGE, 3},    {0x28, 0x5011, MQPT_PROPRNG, 4},
    {0x29, 0x21000, MQPT_PROPRNG, 4}, {0x32, 0x4001, MQPT_VARINT, 1},
    {0x21, 0x4015, MQPT_LOCFLT22, 1}, {0x34, 0x30000, MQPT_NS, 3},
    {0x23, 0x4001, MQPT_FILL, 2},     {0x35, 0x1051, MQPT_UINT8, 1},
};

static void mqpt_check_one_v(int ver, const mqpt_row* r, u32 bit) {
  static moqctl_params out;
  u8                   buf[16];
  usz                  n    = mqpt_build(buf, sizeof buf, r);
  usz                  roff = 0;
  int got = moqctl_params_take(ver, wired_span_of(buf, n), &roff, bit, &out);
  CHECK(got == ((r->ctx & bit) ? MOQCTL_OK : MOQCTL_R_PARAM));
  CHECK(got != MOQCTL_OK || (roff == n && out.items[0].type == r->type));
}

static void mqpt_check_table(int ver, const mqpt_row* rows, usz n) {
  for (usz i = 0; i < n; i++) {
    for (u32 b = 0; b < 20; b++) {
      mqpt_check_one_v(ver, &rows[i], 1u << b);
    }
  }
}

static void test_moqctl_params_registry_scope_per_draft(void) {
  mqpt_check_table(MOQVER_D19, MQPT_REGISTRY, MQPT_REGISTRY_N);
  mqpt_check_table(
      MOQVER_D18, MQPT_REGISTRY18,
      sizeof MQPT_REGISTRY18 / sizeof MQPT_REGISTRY18[0]);
  mqpt_check_table(
      MOQVER_D22, MQPT_REGISTRY22,
      sizeof MQPT_REGISTRY22 / sizeof MQPT_REGISTRY22[0]);
}

/* draft-22 SS9.20.21: INCLUDE_PROPERTIES outside {0,1} is a
 * PROTOCOL_VIOLATION. */
static void test_moqctl_params_include_properties_range(void) {
  static const u8      two[] = {0x02};
  static moqctl_params out;
  mqpt_row             r = {0x35, 0, two, 1};
  u8                   buf[16];
  usz                  n    = mqpt_build(buf, sizeof buf, &r);
  usz                  roff = 0;
  CHECK(
      moqctl_params_take(
          MOQVER_D22, wired_span_of(buf, n), &roff, MOQCTL_PCTX_FETCH, &out) ==
      MOQCTL_R_PARAM);
}

/* Decodes the one-parameter list {type, val} under ctx into *out. */
static int mqpt_take(
    u64 type, const u8* val, usz n, u32 ctx, moqctl_params* out) {
  mqpt_row  r = {type, 0, val, n};
  static u8 buf[32]; /* out views into it (moqctl_params_take is a view API) */
  usz       len  = mqpt_build(buf, sizeof buf, &r);
  usz       roff = 0;
  return moqctl_params_take(
      MOQVER_D19, wired_span_of(buf, len), &roff, ctx, out);
}

/* LOCATION_FILTER (10.2.9) is a Length-prefixed Location Filter (5.1.2):
 * AbsoluteRange {5,0} + End Group Delta 3 decodes into .lf and encodes
 * back to the same bytes. */
static void test_moqctl_params_location_filter_roundtrip(void) {
  static const u8      val[] = {0x04, 0x04, 0x05, 0x00, 0x03};
  static moqctl_params out;
  u8                   buf[32];
  usz                  off = 0;
  CHECK(
      mqpt_take(
          MOQCTL_PARAM_LOCATION_FILTER, val, sizeof val, MOQCTL_PCTX_SUBSCRIBE,
          &out) == MOQCTL_OK);
  CHECK(out.items[0].lf.type == MOQCTL_FILTER_ABS_RANGE);
  CHECK(out.items[0].lf.start.group == 5 && out.items[0].lf.start.object == 0);
  CHECK(out.items[0].lf.end_group_delta == 3);
  /* the same filter in the version-neutral form */
  CHECK(out.items[0].has_filter == 1 && out.items[0].rl.sk == MOQCTL_RSK_ABS);
  CHECK(out.items[0].rl.start_group == 5 && out.items[0].rl.end_group == 8);
  CHECK(out.items[0].rl.ek == MOQCTL_REK_GROUP);
  CHECK(moqctl_params_put(wired_mspan_of(buf, sizeof buf), &off, &out));
  CHECK(off == 2 + sizeof val);
  for (usz i = 0; i < sizeof val; i++) {
    CHECK(buf[2 + i] == val[i]);
  }
}

/* A Location Filter that is not exactly its Length: unknown Filter Type
 * (5.1.2), a trailing byte, or a filter cut short inside the Length. */
static void test_moqctl_params_location_filter_malformed(void) {
  static const u8      bad_type[] = {0x01, 0x05};
  static const u8      trailing[] = {0x02, 0x01, 0x00};
  static const u8      short_[]   = {0x02, 0x04, 0x05};
  static moqctl_params out;
  const u8*            cases[3] = {bad_type, trailing, short_};
  for (usz i = 0; i < 3; i++) {
    CHECK(
        mqpt_take(
            MOQCTL_PARAM_LOCATION_FILTER, cases[i], 1 + cases[i][0],
            MOQCTL_PCTX_SUBSCRIBE, &out) == MOQCTL_VIOLATION);
  }
}

/* TRACK_NAMESPACE_PREFIX (10.2.19) is a bare Track Namespace (2.4.1):
 * .bytes spans its encoding; a zero-length field is a VIOLATION. */
static void test_moqctl_params_namespace_prefix(void) {
  static const u8      ok[]  = {0x02, 0x01, 0x61, 0x02, 0x62, 0x63};
  static const u8      bad[] = {0x01, 0x00};
  static moqctl_params out;
  CHECK(
      mqpt_take(
          MOQCTL_PARAM_TRACK_NAMESPACE_PREFIX, ok, sizeof ok,
          MOQCTL_PCTX_UPDATE_SUBSCRIBE_TRACKS, &out) == MOQCTL_OK);
  CHECK(out.items[0].bytes.n == sizeof ok && out.items[0].bytes.p[5] == 0x63);
  CHECK(
      mqpt_take(
          MOQCTL_PARAM_TRACK_NAMESPACE_PREFIX, bad, sizeof bad,
          MOQCTL_PCTX_UPDATE_SUBSCRIBE_TRACKS, &out) == MOQCTL_R_TRACK_NS);
}

/* uint8 value v of type under SUBSCRIBE: MOQCTL_OK or VIOLATION. */
static int mqpt_u8(u64 type, u8 v) {
  static moqctl_params out;
  return mqpt_take(type, &v, 1, MOQCTL_PCTX_SUBSCRIBE, &out);
}

/* FORWARD is 0 or 1 (10.2.17), GROUP_ORDER 1 or 2 (10.2.8); any other
 * value closes the session with PROTOCOL_VIOLATION. SUBSCRIBER_PRIORITY
 * takes the whole uint8. */
static void test_moqctl_params_uint8_value_ranges(void) {
  CHECK(mqpt_u8(MOQCTL_PARAM_FORWARD, 0) == MOQCTL_OK);
  CHECK(mqpt_u8(MOQCTL_PARAM_FORWARD, 1) == MOQCTL_OK);
  CHECK(mqpt_u8(MOQCTL_PARAM_FORWARD, 2) == MOQCTL_R_PARAM);
  CHECK(mqpt_u8(MOQCTL_PARAM_GROUP_ORDER, 0) == MOQCTL_R_PARAM);
  CHECK(mqpt_u8(MOQCTL_PARAM_GROUP_ORDER, 1) == MOQCTL_OK);
  CHECK(mqpt_u8(MOQCTL_PARAM_GROUP_ORDER, 2) == MOQCTL_OK);
  CHECK(mqpt_u8(MOQCTL_PARAM_GROUP_ORDER, 3) == MOQCTL_R_PARAM);
  CHECK(mqpt_u8(MOQCTL_PARAM_SUBSCRIBER_PRIORITY, 0) == MOQCTL_OK);
  CHECK(mqpt_u8(MOQCTL_PARAM_SUBSCRIBER_PRIORITY, 255) == MOQCTL_OK);
}

/* The value range applies only to uint8-encoded rows: a varint row's
 * value is never range-rejected, even with a stray u8v. */
static void test_moqctl_param_range_uint8_only(void) {
  moqctl_param p = {0};
  p.u8v          = 5;
  CHECK(moqctl_param_in_range(
      moqctl_param_rule_for(MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT), &p));
  CHECK(
      !moqctl_param_in_range(moqctl_param_rule_for(MOQCTL_PARAM_FORWARD), &p));
}

/* The same Type twice (Type Delta 0), each with r's Value, under ctx. */
static int mqpt_twice(const mqpt_row* r, u32 ctx, moqctl_params* out) {
  u8  buf[32];
  usz n    = mqpt_build(buf, sizeof buf, r);
  usz off  = n;
  usz roff = 0;
  buf[0]   = 2; /* count */
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 0));
  for (usz i = 0; i < r->n; i++) {
    buf[off + i] = r->val[i];
  }
  return moqctl_params_take(
      MOQVER_D19, wired_span_of(buf, off + r->n), &roff, ctx, out);
}

/* Range Filters MAY repeat (5.1.3); any other Type repeated is a
 * PROTOCOL_VIOLATION (10.2). */
static void test_moqctl_params_repeatable_filters(void) {
  static moqctl_params out;
  const mqpt_row sub_flt = {MOQCTL_PARAM_SUBGROUP_FILTER, 0, MQPT_RANGE, 3};
  const mqpt_row trk_flt = {
      MOQCTL_PARAM_TRACK_PROPERTY_FILTER, 0, MQPT_PROPRNG, 4};
  const mqpt_row order = {MOQCTL_PARAM_GROUP_ORDER, 0, MQPT_UINT8, 1};
  CHECK(mqpt_twice(&sub_flt, MOQCTL_PCTX_SUBSCRIBE, &out) == MOQCTL_OK);
  CHECK(out.n == 2 && out.items[1].type == MOQCTL_PARAM_SUBGROUP_FILTER);
  CHECK(mqpt_twice(&trk_flt, MOQCTL_PCTX_SUBSCRIBE_TRACKS, &out) == MOQCTL_OK);
  CHECK(mqpt_twice(&order, MOQCTL_PCTX_SUBSCRIBE, &out) == MOQCTL_R_PARAM);
}

/* REQUEST_OK (10.5) carries the parameters of whichever OK it stands for
 * (PUBLISH_OK, TRACK_STATUS_OK, ...): SUBSCRIBER_PRIORITY (PUBLISH_OK) and
 * LARGEST_OBJECT (TRACK_STATUS_OK) decode; GROUP_ORDER, legal in no OK,
 * is a PROTOCOL_VIOLATION. */
static void test_moqctl_request_ok_params_scope(void) {
  static const u8          prio[]  = {0x01, 0x20, 0x07};
  static const u8          large[] = {0x01, 0x09, 0x07, 0x03};
  static const u8          order[] = {0x01, 0x22, 0x01};
  static moqctl_request_ok m;
  usz                      off = 0;
  CHECK(
      moqctl_request_ok_take(
          MOQVER_D19, wired_span_of(prio, sizeof prio), &off, &m) == MOQCTL_OK);
  CHECK(m.params.n == 1 && m.params.items[0].u8v == 7);
  off = 0;
  CHECK(
      moqctl_request_ok_take(
          MOQVER_D19, wired_span_of(large, sizeof large), &off, &m) ==
      MOQCTL_OK);
  CHECK(m.params.items[0].loc.group == 7 && m.params.items[0].loc.object == 3);
  off = 0;
  CHECK(
      moqctl_request_ok_take(
          MOQVER_D19, wired_span_of(order, sizeof order), &off, &m) ==
      MOQCTL_R_PARAM);
}

/* moqctl_params_find: the first item of a Type, or 0 when absent -- so a
 * caller tells "absent" (use the draft default) from a decoded 0. */
static void test_moqctl_params_find(void) {
  static moqctl_params out;
  const mqpt_row       flt = {MOQCTL_PARAM_SUBGROUP_FILTER, 0, MQPT_RANGE, 3};
  CHECK(mqpt_twice(&flt, MOQCTL_PCTX_SUBSCRIBE, &out) == MOQCTL_OK);
  CHECK(
      moqctl_params_find(&out, MOQCTL_PARAM_SUBGROUP_FILTER) == &out.items[0]);
  CHECK(moqctl_params_find(&out, MOQCTL_PARAM_FORWARD) == 0);
}

/* Body of golden control message g (its envelope already checked). */
static wired_span mqpt_golden_body(const u8* g, usz n) {
  usz        off = 0;
  u64        type;
  wired_span body = {0, 0};
  CHECK(moqctl_peek_type(wired_span_of(g, n), &off, &type, &body) == MOQCTL_OK);
  return body;
}

/* Re-encodes m as golden g's type and checks it reproduces g exactly. */
static void mqpt_golden_reencode(
    const u8* g, usz n, u64 type, moqctl_encode_body_fn fn, const void* m) {
  u8  out[64];
  usz len = 0;
  moqctl_reencode(out, sizeof out, type, fn, m, &len);
  CHECK(len == n);
  for (usz i = 0; i < len; i++) {
    CHECK(out[i] == g[i]);
  }
}

/* Golden subscribe_params: FORWARD 1, SUBSCRIBER_PRIORITY 64,
 * LOCATION_FILTER AbsoluteRange {5,0}+3, GROUP_ORDER 2. */
static void test_moqctl_golden_subscribe_params(void) {
  static moqctl_subscribe m;
  wired_span              body = mqpt_golden_body(
      g_moqt_ctl_subscribe_params, G_MOQT_CTL_SUBSCRIBE_PARAMS_LEN);
  usz boff = 0;
  CHECK(moqctl_subscribe_take(MOQVER_D19, body, &boff, &m) == MOQCTL_OK);
  CHECK(m.params.n == 4);
  CHECK(moqctl_params_find(&m.params, MOQCTL_PARAM_FORWARD)->u8v == 1);
  CHECK(
      moqctl_params_find(&m.params, MOQCTL_PARAM_SUBSCRIBER_PRIORITY)->u8v ==
      64);
  CHECK(
      moqctl_params_find(&m.params, MOQCTL_PARAM_LOCATION_FILTER)
          ->lf.end_group_delta == 3);
  CHECK(moqctl_params_find(&m.params, MOQCTL_PARAM_GROUP_ORDER)->u8v == 2);
  mqpt_golden_reencode(
      g_moqt_ctl_subscribe_params, G_MOQT_CTL_SUBSCRIBE_PARAMS_LEN,
      MOQCTL_T_SUBSCRIBE, moqctl_encode_subscribe, &m);
}

/* Golden subscribe_ok_params: EXPIRES 100, LARGEST_OBJECT {7,3}. */
static void test_moqctl_golden_subscribe_ok_params(void) {
  static moqctl_subscribe_ok m;
  wired_span                 body = mqpt_golden_body(
      g_moqt_ctl_subscribe_ok_params, G_MOQT_CTL_SUBSCRIBE_OK_PARAMS_LEN);
  usz boff = 0;
  CHECK(moqctl_subscribe_ok_take(MOQVER_D19, body, &boff, &m) == MOQCTL_OK);
  CHECK(moqctl_params_find(&m.params, MOQCTL_PARAM_EXPIRES)->vi == 100);
  CHECK(
      moqctl_params_find(&m.params, MOQCTL_PARAM_LARGEST_OBJECT)->loc.object ==
      3);
  mqpt_golden_reencode(
      g_moqt_ctl_subscribe_ok_params, G_MOQT_CTL_SUBSCRIBE_OK_PARAMS_LEN,
      MOQCTL_T_SUBSCRIBE_OK, moqctl_encode_subscribe_ok, &m);
}

/* Golden request_ok_params (a PUBLISH_OK): FORWARD 0,
 * SUBSCRIBER_PRIORITY 7. */
static void test_moqctl_golden_request_ok_params(void) {
  static moqctl_request_ok m;
  wired_span               body = mqpt_golden_body(
      g_moqt_ctl_request_ok_params, G_MOQT_CTL_REQUEST_OK_PARAMS_LEN);
  usz boff = 0;
  CHECK(moqctl_request_ok_take(MOQVER_D19, body, &boff, &m) == MOQCTL_OK);
  CHECK(moqctl_params_find(&m.params, MOQCTL_PARAM_FORWARD)->u8v == 0);
  CHECK(
      moqctl_params_find(&m.params, MOQCTL_PARAM_SUBSCRIBER_PRIORITY)->u8v ==
      7);
  mqpt_golden_reencode(
      g_moqt_ctl_request_ok_params, G_MOQT_CTL_REQUEST_OK_PARAMS_LEN,
      MOQCTL_T_REQUEST_OK, moqctl_encode_request_ok, &m);
}

/* ===== TEST: SETUP Setup Options behaviors ===== */

/* Unknown Setup Option (including a duplicate of it) is ignored. */
static void test_moqctl_setup_unknown_option_ignored(void) {
  u8           buf[16];
  usz          off = 0;
  moqctl_setup s;

  /* two odd, unrecognized option types (0x0B, delta then +0x0A -> 0x15),
   * each carrying one raw byte -- both must be silently ignored. */
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 0x0B));
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 1));
  buf[off] = 0xAA;
  off += 1;
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 0x0A));
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 1));
  buf[off] = 0xBB;
  off += 1;

  {
    usz soff = 0;
    CHECK(moqctl_setup_take(wired_span_of(buf, off), &soff, &s) == MOQCTL_OK);
  }
  CHECK(!s.has_path);
  CHECK(!s.has_authority);
  CHECK(!s.has_implementation);
}

/* MOQT_IMPLEMENTATION option decode (UTF-8 name+version). Already
 * covered end-to-end by test_moqctl_setup_roundtrip via the golden vector;
 * this test isolates the PATH option instead for independent coverage. */
static void test_moqctl_setup_path_option_decode(void) {
  u8           buf[16];
  usz          off = 0;
  moqctl_setup s;

  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 1)); /* PATH=1 */
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 3));
  buf[off]     = '/';
  buf[off + 1] = 'a';
  buf[off + 2] = 'b';
  off += 3;

  {
    usz soff = 0;
    CHECK(moqctl_setup_take(wired_span_of(buf, off), &soff, &s) == MOQCTL_OK);
  }
  CHECK(s.has_path);
  CHECK(s.path.n == 3);
  CHECK(s.path.p[0] == '/');
}

/* MAX_FILTER_RANGES (0x06) / MAX_REQUEST_UPDATES (0x08) decode (draft-19
 * 10.4): even option types, value a single varint. Absent options leave
 * the draft default 0; an encode of the decoded struct round-trips. */
static void test_moqctl_setup_limit_options_roundtrip(void) {
  u8           buf[16];
  usz          off = 0;
  moqctl_setup s;

  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 0x06));
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 5));
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 0x02)); /* ->0x08 */
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 3));

  {
    usz soff = 0;
    CHECK(moqctl_setup_take(wired_span_of(buf, off), &soff, &s) == MOQCTL_OK);
  }
  CHECK(s.max_filter_ranges == 5);
  CHECK(s.max_request_updates == 3);

  {
    u8           out[16];
    usz          eoff = 0;
    moqctl_setup back;
    usz          boff = 0;
    CHECK(moqctl_setup_encode(wired_mspan_of(out, sizeof out), &eoff, &s));
    CHECK(
        moqctl_setup_take(wired_span_of(out, eoff), &boff, &back) == MOQCTL_OK);
    CHECK(back.max_filter_ranges == 5);
    CHECK(back.max_request_updates == 3);
  }
}

/* Absent limit options decode to the draft default 0 for both. */
static void test_moqctl_setup_limit_options_default_zero(void) {
  moqctl_setup s;
  usz          soff = 0;
  CHECK(moqctl_setup_take(wired_span_of(0, 0), &soff, &s) == MOQCTL_OK);
  CHECK(s.max_filter_ranges == 0);
  CHECK(s.max_request_updates == 0);
}

/* ===== TEST: draft-23 9.1.8 MAX_CONTROL_MESSAGE_SIZE ===== */

/* Setup Options opts decoded as draft ver; the result code. */
static int mqmcs_take(int ver, const u8* opts, usz n, moqctl_setup* s) {
  usz off = 0;
  return moqctl_setup_take_v(ver, wired_span_of(opts, n), &off, s);
}

/* Option 0x09 (odd: Length + one vi64) at 65535 (C0 FF FF: 3-byte vi64,
 * 110 + 21 bits) and at 65536 (C1 00 00) is taken and remembered; a
 * non-minimal 9-byte vi64 of 65535 too (#1595: non-minimal is legal). */
static void test_moqctl_setup_d23_max_ctl_size_ok(void) {
  static const u8 at_min[] = {0x09, 0x03, 0xC0, 0xFF, 0xFF};
  static const u8 above[]  = {0x09, 0x03, 0xC1, 0x00, 0x00};
  static const u8 nonmin[] = {0x09, 0x09, 0xFF, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0xFF, 0xFF};
  moqctl_setup    s;
  CHECK(mqmcs_take(MOQVER_D23, at_min, sizeof at_min, &s) == MOQCTL_OK);
  CHECK(s.has_max_ctl_size && s.max_ctl_size == 65535);
  CHECK(!s.has_ssts);
  CHECK(mqmcs_take(MOQVER_D23, above, sizeof above, &s) == MOQCTL_OK);
  CHECK(s.max_ctl_size == 65536);
  CHECK(mqmcs_take(MOQVER_D23, nonmin, sizeof nonmin, &s) == MOQCTL_OK);
  CHECK(s.max_ctl_size == 65535);
}

/* A value below 65535 (C0 FF FE), one byte short (Length 2 for a
 * 3-byte vi64), a trailing byte, or an empty value is
 * MALFORMED_KEY_VALUE (MOQCTL_PARAMS_KVFMT, code 0x6). */
static void test_moqctl_setup_d23_max_ctl_size_malformed(void) {
  static const u8 below[]    = {0x09, 0x03, 0xC0, 0xFF, 0xFE};
  static const u8 small[]    = {0x09, 0x01, 0x05};
  static const u8 short_[]   = {0x09, 0x02, 0xC0, 0xFF};
  static const u8 trailing[] = {0x09, 0x04, 0xC0, 0xFF, 0xFF, 0x00};
  static const u8 empty[]    = {0x09, 0x00};
  const u8*       cases[]    = {below, small, short_, trailing, empty};
  const usz       lens[]     = {
      sizeof below, sizeof small, sizeof short_, sizeof trailing, sizeof empty};
  moqctl_setup s;
  for (usz i = 0; i < sizeof lens / sizeof lens[0]; i++) {
    CHECK(mqmcs_take(MOQVER_D23, cases[i], lens[i], &s) == MOQCTL_PARAMS_KVFMT);
  }
}

/* Up to draft-22 0x09 stays the experimental SSTS_ALGORITHMS: the same
 * bytes are an SSTS list, never a size. */
static void test_moqctl_setup_d22_09_is_ssts(void) {
  static const u8 small[] = {0x09, 0x01, 0x01};
  moqctl_setup    s;
  CHECK(mqmcs_take(MOQVER_D22, small, sizeof small, &s) == MOQCTL_OK);
  CHECK(s.has_ssts && s.ssts_alg_n == 1 && s.ssts_algs[0] == 1);
  CHECK(!s.has_max_ctl_size);
}

/* draft-23 9.1.8: SSTS_ALGORITHMS moves to 0x3F01 (Delta Type BF 01:
 * 2-byte vi64 10 + 14 bits), both ways; wired's own SETUP carries no
 * MAX_CONTROL_MESSAGE_SIZE. */
static void test_moqctl_setup_d23_ssts_moved(void) {
  static const u8 d23[] = {0xBF, 0x01, 0x01, 0x01};
  u8              out[16];
  usz             n = 0;
  moqctl_setup    s;
  CHECK(mqmcs_take(MOQVER_D23, d23, sizeof d23, &s) == MOQCTL_OK);
  CHECK(s.has_ssts && s.ssts_alg_n == 1 && s.ssts_algs[0] == 1);
  CHECK(moqctl_setup_encode_v(
      MOQVER_D23, wired_mspan_of(out, sizeof out), &n, &s));
  CHECK(n == sizeof d23);
  CHECK(ct_diffn(out, d23, sizeof d23) == 0);
  n = 0;
  CHECK(moqctl_setup_encode_v(
      MOQVER_D22, wired_mspan_of(out, sizeof out), &n, &s));
  CHECK(n == 3 && out[0] == 0x09 && out[1] == 0x01 && out[2] == 0x01);
  CHECK(mqmcs_take(MOQVER_D22, d23, sizeof d23, &s) == MOQCTL_OK);
  CHECK(!s.has_ssts); /* 0x3F01 is an unknown option before draft-23 */
}

/* ===== TEST: Range Filter values (10.2.10-10.2.14) ===== */

/* The draft's own delta example: ranges 3-5 and 10-15 (Start 3, End 2,
 * Start 5, End 5) under SetID 1; the encode mirrors it byte for byte. */
static void test_moqctl_rangefilter_value_roundtrip(void) {
  static const u8    v[] = {0x01, 0x03, 0x02, 0x05, 0x05};
  moqctl_rangefilter f;
  u8                 out[32];
  usz                off = 0;
  CHECK(
      moqctl_rangefilter_take(
          MOQCTL_PARAM_SUBGROUP_FILTER, wired_span_of(v, sizeof v), &f) ==
      MOQCTL_OK);
  CHECK(!f.remove && !f.invalid && f.set_id == 1 && f.n == 2);
  CHECK(f.r[0].start == 3 && f.r[0].has_end && f.r[0].end == 5);
  CHECK(f.r[1].start == 10 && f.r[1].has_end && f.r[1].end == 15);
  CHECK(moqctl_rangefilter_put(
      wired_mspan_of(out, sizeof out), &off, MOQCTL_PARAM_SUBGROUP_FILTER, &f));
  CHECK(off == sizeof v);
  for (usz i = 0; i < off; i++) {
    CHECK(out[i] == v[i]);
  }
}

/* An omitted final End is open-ended; 0x28/0x29 carry a Property Type;
 * a zero-length value is the REQUEST_UPDATE delete. */
static void test_moqctl_rangefilter_open_end_prop_and_remove(void) {
  static const u8    open_v[] = {0x00, 0x07};
  static const u8    prop_v[] = {0x02, 0x02, 0x01, 0x01};
  moqctl_rangefilter f;
  CHECK(
      moqctl_rangefilter_take(
          MOQCTL_PARAM_OBJECTID_FILTER, wired_span_of(open_v, 2), &f) ==
      MOQCTL_OK);
  CHECK(f.n == 1 && f.r[0].start == 7 && !f.r[0].has_end);
  CHECK(
      moqctl_rangefilter_take(
          MOQCTL_PARAM_OBJECT_PROPERTY_FILTER, wired_span_of(prop_v, 4), &f) ==
      MOQCTL_OK);
  CHECK(f.has_prop && f.prop_type == 2 && f.n == 1);
  CHECK(f.r[0].start == 1 && f.r[0].has_end && f.r[0].end == 2);
  CHECK(
      moqctl_rangefilter_take(
          MOQCTL_PARAM_OBJECTID_FILTER, wired_span_of(open_v, 0), &f) ==
      MOQCTL_OK);
  CHECK(f.remove && f.n == 0);
}

/* Delta accumulation past 2^64-1 marks the filter invalid (the hub
 * answers REQUEST_ERROR INVALID_FILTER); a truncated structure is a
 * formatting error. */
static void test_moqctl_rangefilter_overflow_and_truncated(void) {
  u8                 v[64];
  usz                off = 0;
  moqctl_rangefilter f;
  v[off++] = 0x00;
  for (usz i = 0; i < 5; i++) { /* five max varints: 5*(2^62-1) wraps */
    v[off] = 0xFF;
    for (usz k = 1; k < 8; k++) {
      v[off + k] = 0xFF;
    }
    off += 8;
  }
  CHECK(
      moqctl_rangefilter_take(
          MOQCTL_PARAM_OBJECTID_FILTER, wired_span_of(v, off), &f) ==
      MOQCTL_OK);
  CHECK(f.invalid);
  CHECK(
      moqctl_rangefilter_take(
          MOQCTL_PARAM_TRACK_PROPERTY_FILTER, wired_span_of(v, 1), &f) ==
      MOQCTL_PARAMS_KVFMT); /* SetID alone: Property Type missing */
}

/* ===== TEST: Location Filter ===== */

static void test_moqctl_locfilter_next_group_and_largest(void) {
  const u8         in_ng[] = {0x01};
  const u8         in_lg[] = {0x02};
  usz              off;
  moqctl_locfilter f;

  off = 0;
  CHECK(
      moqctl_locfilter_take(wired_span_of(in_ng, sizeof in_ng), &off, &f) ==
      MOQCTL_OK);
  CHECK(f.type == MOQCTL_FILTER_NEXT_GROUP);
  CHECK(off == 1);

  off = 0;
  CHECK(
      moqctl_locfilter_take(wired_span_of(in_lg, sizeof in_lg), &off, &f) ==
      MOQCTL_OK);
  CHECK(f.type == MOQCTL_FILTER_LARGEST);
}

static void test_moqctl_locfilter_abs_start_and_range_roundtrip(void) {
  u8               buf[32];
  usz              off  = 0;
  moqctl_locfilter f_in = {0};
  moqctl_locfilter f_out;

  f_in.type            = MOQCTL_FILTER_ABS_RANGE;
  f_in.start.group     = 3;
  f_in.start.object    = 0;
  f_in.end_group_delta = 5;

  CHECK(moqctl_locfilter_put(wired_mspan_of(buf, sizeof buf), &off, &f_in));
  {
    usz roff = 0;
    CHECK(
        moqctl_locfilter_take(wired_span_of(buf, off), &roff, &f_out) ==
        MOQCTL_OK);
  }
  CHECK(f_out.type == MOQCTL_FILTER_ABS_RANGE);
  CHECK(f_out.start.group == 3);
  CHECK(f_out.end_group_delta == 5);
}

/* End Group overflow (Start.Group + Delta > 2^64-1) -> VIOLATION. */
static void test_moqctl_locfilter_end_group_overflow_violation(void) {
  u8               buf[24];
  usz              off = 0;
  moqctl_locfilter f;

  CHECK(moqvi_put(
      wired_mspan_of(buf, sizeof buf), &off, MOQCTL_FILTER_ABS_RANGE));
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 5)); /* Group */
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 0)); /* Object */
  CHECK(
      moqvi_put(wired_mspan_of(buf, sizeof buf), &off, (u64)-1)); /* delta
                                                                     overflow */
  {
    usz roff = 0;
    CHECK(
        moqctl_locfilter_take(wired_span_of(buf, off), &roff, &f) ==
        MOQCTL_R_DELTA);
  }
}

/* Unknown Filter Type -> VIOLATION. */
static void test_moqctl_locfilter_unknown_type_violation(void) {
  const u8         in[] = {0x05};
  usz              off  = 0;
  moqctl_locfilter f;

  CHECK(
      moqctl_locfilter_take(wired_span_of(in, sizeof in), &off, &f) ==
      MOQCTL_R_PARAM);
}

/* moxygen's interop client SUBSCRIBE (captured, moqt-18): its Subscription
 * Filter carries Filter Type 250 (vi64 80 fa), moxygen's non-spec
 * LargestGroup. The hub treats it as Largest Object instead of closing the
 * session with PROTOCOL_VIOLATION. */
static void test_moqctl_subscribe_d18_moxygen_largest_group(void) {
  static const u8 body[] = {
      0x00, 0x01, 0x10, 'm', 'o', 'q', '-',  'i',  'n',  't',  'e',  'r', 'o',
      'p',  '-',  't',  'e', 's', 't', 0x0d, 'i',  'n',  't',  'e',  'r', 'o',
      'p',  '-',  't',  'r', 'a', 'c', 'k',  0x01, 0x21, 0x02, 0x80, 0xfa};
  usz              off = 0;
  moqctl_subscribe m;

  CHECK(
      moqctl_subscribe_take(
          MOQVER_D18, wired_span_of(body, sizeof body), &off, &m) == MOQCTL_OK);
  CHECK(m.params.n == 1 && m.params.items[0].has_filter);
  CHECK(m.params.items[0].rl.sk == MOQCTL_RSK_NEXT_OBJ);
  CHECK(m.params.items[0].lf.type == MOQCTL_FILTER_LARGEST);
}

/* ===== TEST: Version-neutral range model (moqctl_rangeloc) ===== */

static void test_moqctl_rangeloc19_next_group(void) {
  const u8        in[] = {0x1};
  usz             off  = 0;
  moqctl_rangeloc r;

  CHECK(
      moqctl_rangeloc19_take(wired_span_of(in, sizeof in), &off, &r) ==
      MOQCTL_OK);
  CHECK(r.sk == MOQCTL_RSK_REL_GROUP);
  CHECK(r.start_group == 0); /* n = 0: d19 Next Group Start = relG 0 */
  CHECK(r.ek == MOQCTL_REK_UNBOUNDED);
  CHECK(off == 1);
}

static void test_moqctl_rangeloc19_largest_object(void) {
  const u8        in[] = {0x2};
  usz             off  = 0;
  moqctl_rangeloc r;

  CHECK(
      moqctl_rangeloc19_take(wired_span_of(in, sizeof in), &off, &r) ==
      MOQCTL_OK);
  CHECK(r.sk == MOQCTL_RSK_NEXT_OBJ);
  CHECK(r.ek == MOQCTL_REK_UNBOUNDED);
}

/* d19 9.3.1 AbsoluteStart (0x3): Start Location {7, 9}. */
static void test_moqctl_rangeloc19_abs_start_roundtrip(void) {
  static const u8 buf[] = {0x03, 0x07, 0x09};
  moqctl_rangeloc out;
  usz             roff = 0;

  CHECK(
      moqctl_rangeloc19_take(wired_span_of(buf, sizeof buf), &roff, &out) ==
      MOQCTL_OK);
  CHECK(roff == sizeof buf);
  CHECK(out.sk == MOQCTL_RSK_ABS);
  CHECK(out.start_group == 7);
  CHECK(out.start_object == 9);
  CHECK(out.ek == MOQCTL_REK_UNBOUNDED);
}

/* d19 9.3.1 AbsoluteRange (0x4): Start {3, 0}, End Group Delta 0. */
static void test_moqctl_rangeloc19_abs_range_egd_zero_roundtrip(void) {
  static const u8 buf[] = {0x04, 0x03, 0x00, 0x00};
  moqctl_rangeloc out;
  usz             roff = 0;

  CHECK(
      moqctl_rangeloc19_take(wired_span_of(buf, sizeof buf), &roff, &out) ==
      MOQCTL_OK);
  CHECK(out.sk == MOQCTL_RSK_ABS);
  CHECK(out.ek == MOQCTL_REK_GROUP);
  CHECK(out.end_group == 3);
}

/* d19 9.3.1 AbsoluteRange (0x4): Start {3, 0}, End Group Delta 5. */
static void test_moqctl_rangeloc19_abs_range_egd_positive_roundtrip(void) {
  static const u8 buf[] = {0x04, 0x03, 0x00, 0x05};
  moqctl_rangeloc out;
  usz             roff = 0;

  CHECK(
      moqctl_rangeloc19_take(wired_span_of(buf, sizeof buf), &roff, &out) ==
      MOQCTL_OK);
  CHECK(out.sk == MOQCTL_RSK_ABS);
  CHECK(out.ek == MOQCTL_REK_GROUP);
  CHECK(out.start_group == 3);
  CHECK(out.end_group == 8);
}

static void test_moqctl_rangeloc19_egd_overflow_violation(void) {
  u8              buf[24];
  usz             off = 0;
  moqctl_rangeloc out;

  CHECK(moqvi_put(
      wired_mspan_of(buf, sizeof buf), &off, MOQCTL_FILTER_ABS_RANGE));
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 5));       /* Group */
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 0));       /* Object */
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, (u64)-1)); /* EGD */

  {
    usz roff = 0;
    CHECK(
        moqctl_rangeloc19_take(wired_span_of(buf, off), &roff, &out) ==
        MOQCTL_R_DELTA);
  }
}

static void test_moqctl_rangeloc22_none(void) {
  const u8        in[]       = {0x00};
  usz             off        = 0;
  int             has_filter = -1;
  moqctl_rangeloc out;

  CHECK(
      moqctl_rangeloc22_take(
          wired_span_of(in, sizeof in), &off, &has_filter, &out) == MOQCTL_OK);
  CHECK(has_filter == 0);
  CHECK(out.sk == 0);
  CHECK(out.start_group == 0);
}

static void test_moqctl_rangeloc22_relative_start_roundtrip(void) {
  u8              buf[32];
  usz             off        = 0;
  int             has_filter = 0;
  moqctl_rangeloc in         = {0};
  moqctl_rangeloc out;

  in.sk          = MOQCTL_RSK_REL_GROUP;
  in.start_group = 4; /* N groups back from Largest.Group */
  in.ek          = MOQCTL_REK_UNBOUNDED;

  CHECK(moqctl_rangeloc22_put(wired_mspan_of(buf, sizeof buf), &off, 1, &in));
  {
    usz roff = 0;
    CHECK(
        moqctl_rangeloc22_take(
            wired_span_of(buf, off), &roff, &has_filter, &out) == MOQCTL_OK);
  }
  CHECK(has_filter == 1);
  CHECK(out.sk == MOQCTL_RSK_REL_GROUP);
  CHECK(out.start_group == 4);
  CHECK(out.ek == MOQCTL_REK_UNBOUNDED);
}

static void test_moqctl_rangeloc22_abs_start_roundtrip(void) {
  u8              buf[32];
  usz             off        = 0;
  int             has_filter = 0;
  moqctl_rangeloc in         = {0};
  moqctl_rangeloc out;

  in.sk           = MOQCTL_RSK_ABS;
  in.start_group  = 7;
  in.start_object = 9;
  in.ek           = MOQCTL_REK_UNBOUNDED;

  CHECK(moqctl_rangeloc22_put(wired_mspan_of(buf, sizeof buf), &off, 1, &in));
  {
    usz roff = 0;
    CHECK(
        moqctl_rangeloc22_take(
            wired_span_of(buf, off), &roff, &has_filter, &out) == MOQCTL_OK);
  }
  CHECK(has_filter == 1);
  CHECK(out.sk == MOQCTL_RSK_ABS);
  CHECK(out.start_group == 7);
  CHECK(out.start_object == 9);
  CHECK(out.ek == MOQCTL_REK_UNBOUNDED);
}

static void test_moqctl_rangeloc22_abs_start_group_end_roundtrip(void) {
  u8              buf[32];
  usz             off        = 0;
  int             has_filter = 0;
  moqctl_rangeloc in         = {0};
  moqctl_rangeloc out;

  in.sk           = MOQCTL_RSK_ABS;
  in.start_group  = 3;
  in.start_object = 1;
  in.ek           = MOQCTL_REK_GROUP;
  in.end_group    = 8; /* End Group Delta = 5 */

  CHECK(moqctl_rangeloc22_put(wired_mspan_of(buf, sizeof buf), &off, 1, &in));
  {
    usz roff = 0;
    CHECK(
        moqctl_rangeloc22_take(
            wired_span_of(buf, off), &roff, &has_filter, &out) == MOQCTL_OK);
  }
  CHECK(has_filter == 1);
  CHECK(out.sk == MOQCTL_RSK_ABS);
  CHECK(out.ek == MOQCTL_REK_GROUP);
  CHECK(out.start_group == 3);
  CHECK(out.end_group == 8);
}

static void test_moqctl_rangeloc22_abs_range_roundtrip(void) {
  u8              buf[32];
  usz             off        = 0;
  int             has_filter = 0;
  moqctl_rangeloc in         = {0};
  moqctl_rangeloc out;

  in.sk           = MOQCTL_RSK_ABS;
  in.start_group  = 3;
  in.start_object = 1;
  in.ek           = MOQCTL_REK_OBJ;
  in.end_group    = 8; /* End Group Delta = 5 */
  in.end_object   = 20;

  CHECK(moqctl_rangeloc22_put(wired_mspan_of(buf, sizeof buf), &off, 1, &in));
  {
    usz roff = 0;
    CHECK(
        moqctl_rangeloc22_take(
            wired_span_of(buf, off), &roff, &has_filter, &out) == MOQCTL_OK);
  }
  CHECK(has_filter == 1);
  CHECK(out.sk == MOQCTL_RSK_ABS);
  CHECK(out.ek == MOQCTL_REK_OBJ);
  CHECK(out.start_group == 3);
  CHECK(out.start_object == 1);
  CHECK(out.end_group == 8);
  CHECK(out.end_object == 20);
}

static void test_moqctl_rangeloc22_next_object_roundtrip(void) {
  u8              buf[32];
  usz             off        = 0;
  int             has_filter = 0;
  moqctl_rangeloc in         = {0};
  moqctl_rangeloc out;

  in.sk = MOQCTL_RSK_NEXT_OBJ;
  in.ek = MOQCTL_REK_UNBOUNDED;

  CHECK(moqctl_rangeloc22_put(wired_mspan_of(buf, sizeof buf), &off, 1, &in));
  {
    usz roff = 0;
    CHECK(
        moqctl_rangeloc22_take(
            wired_span_of(buf, off), &roff, &has_filter, &out) == MOQCTL_OK);
  }
  CHECK(has_filter == 1);
  CHECK(out.sk == MOQCTL_RSK_NEXT_OBJ);
  CHECK(out.ek == MOQCTL_REK_UNBOUNDED);
}

/* type 0x03/0x04 End Group Delta pushing StartGroup+EGD past 2^64-1 ->
 * VIOLATION. */
static void test_moqctl_rangeloc22_egd_overflow_violation(void) {
  u8              buf[24];
  usz             off        = 0;
  int             has_filter = 0;
  moqctl_rangeloc out;

  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 0x3));     /* type */
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 5));       /* SG */
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 0));       /* SO */
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, (u64)-1)); /* EGD */

  {
    usz roff = 0;
    CHECK(
        moqctl_rangeloc22_take(
            wired_span_of(buf, off), &roff, &has_filter, &out) ==
        MOQCTL_R_DELTA);
  }
}

/* Location Filter Type >= 0x06 -> VIOLATION. */
static void test_moqctl_rangeloc22_unknown_type_violation(void) {
  const u8        in[]       = {0x06};
  usz             off        = 0;
  int             has_filter = 0;
  moqctl_rangeloc out;

  CHECK(
      moqctl_rangeloc22_take(
          wired_span_of(in, sizeof in), &off, &has_filter, &out) ==
      MOQCTL_R_PARAM);
}

/* Cross-version: the same {group,object} AbsoluteStart decodes to a
 * bit-identical moqctl_rangeloc from both d19 (type 0x3) and d22 (type
 * 0x02). */
static void test_moqctl_rangeloc_cross_version_abs_start(void) {
  static const u8 buf19[] = {0x03, 11, 22}; /* d19 AbsoluteStart */
  u8              buf22[32];
  usz             off19 = sizeof buf19, off22 = 0;
  moqctl_rangeloc in = {0};
  moqctl_rangeloc out19, out22;
  int             has_filter = 0;

  in.sk           = MOQCTL_RSK_ABS;
  in.start_group  = 11;
  in.start_object = 22;
  in.ek           = MOQCTL_REK_UNBOUNDED;

  CHECK(moqctl_rangeloc22_put(
      wired_mspan_of(buf22, sizeof buf22), &off22, 1, &in));
  {
    usz r19 = 0, r22 = 0;
    CHECK(
        moqctl_rangeloc19_take(wired_span_of(buf19, off19), &r19, &out19) ==
        MOQCTL_OK);
    CHECK(
        moqctl_rangeloc22_take(
            wired_span_of(buf22, off22), &r22, &has_filter, &out22) ==
        MOQCTL_OK);
  }
  CHECK(has_filter == 1);
  CHECK(out19.sk == out22.sk);
  CHECK(out19.start_group == out22.start_group);
  CHECK(out19.start_object == out22.start_object);
  CHECK(out19.ek == out22.ek);
  CHECK(out19.end_group == out22.end_group);
  CHECK(out19.end_object == out22.end_object);
}

/* ===== TEST: grease / unknown error code normalization ===== */

static void test_moqctl_grease_pattern(void) {
  CHECK(moqctl_is_grease(0x9D));
  CHECK(moqctl_is_grease(0x9D + 0x7f));
  CHECK(moqctl_is_grease(0x9D + 2 * 0x7f));
  CHECK(!moqctl_is_grease(0));
  CHECK(!moqctl_is_grease(0x9C));
  CHECK(!moqctl_is_grease(0x9E));
}

/* Known means defined by the sender's own draft (draft-23 13): codes
 * only other drafts define are INTERNAL_ERROR too. Rows: draft, code,
 * kept as-is. */
static void test_moqctl_unknown_error_normalizes_to_internal(void) {
  static const struct {
    int ver;
    u64 code;
    int kept;
  } errs[] =
      {
          {MOQVER_D23, MOQCTL_ERR_NOT_SUPPORTED, 1},
          {MOQVER_D23, 0x7FFF, 0},
          {MOQVER_D18, MOQCTL_ERR_INVALID_FILTER, 0},
          {MOQVER_D19, MOQCTL_ERR_INVALID_FILTER, 1},
          {MOQVER_D18, MOQCTL_ERR_DUPLICATE_SUBSCRIPTION, 1},
          {MOQVER_D19, MOQCTL_ERR_DUPLICATE_SUBSCRIPTION, 0},
          {MOQVER_D22, MOQCTL_ERR_PREFIX_OVERLAP, 1},
          {MOQVER_D23, MOQCTL_ERR_PREFIX_OVERLAP, 0},
          {MOQVER_D19, MOQCTL_ERR_INVALID_JOINING_REQUEST_ID, 1},
          {MOQVER_D22, MOQCTL_ERR_INVALID_JOINING_REQUEST_ID, 0},
          {MOQVER_D22, MOQCTL_ERR_UNAVAILABLE, 0},
      },
    dones[] = {
        {MOQVER_D23, MOQCTL_DONE_TRACK_ENDED, 1},
        {MOQVER_D23, 0x7FFF, 0},
        {MOQVER_D18, MOQCTL_DONE_UPDATE_FAILED, 1},
        {MOQVER_D19, MOQCTL_DONE_SUBSCRIPTION_ENDED, 1},
        {MOQVER_D22, MOQCTL_DONE_SUBSCRIPTION_ENDED, 0},
        {MOQVER_D22, MOQCTL_DONE_EXPIRED_AUTH_TOKEN, 0},
    };
  for (usz i = 0; i < sizeof errs / sizeof errs[0]; i++) {
    CHECK(
        moqctl_known_request_error(errs[i].ver, errs[i].code) ==
        (errs[i].kept ? errs[i].code : MOQCTL_ERR_INTERNAL_ERROR));
  }
  for (usz i = 0; i < sizeof dones / sizeof dones[0]; i++) {
    CHECK(
        moqctl_known_publish_done(dones[i].ver, dones[i].code) ==
        (dones[i].kept ? dones[i].code : MOQCTL_DONE_INTERNAL_ERROR));
  }
}

/* Send side: a REQUEST_ERROR code the session's draft does not define is
 * replaced by that draft's nearest one; a defined code is kept. */
static void test_moqctl_request_error_for_draft(void) {
  CHECK(
      moqctl_request_error_for(MOQVER_D18, MOQCTL_ERR_INVALID_FILTER) ==
      MOQCTL_ERR_INVALID_RANGE);
  CHECK(
      moqctl_request_error_for(MOQVER_D18, MOQCTL_ERR_CONFLICTING_FILTERS) ==
      MOQCTL_ERR_EXCESSIVE_LOAD);
  CHECK(
      moqctl_request_error_for(MOQVER_D19, MOQCTL_ERR_DUPLICATE_SUBSCRIPTION) ==
      MOQCTL_ERR_INTERNAL_ERROR);
  CHECK(
      moqctl_request_error_for(MOQVER_D22, MOQCTL_ERR_DUPLICATE_SUBSCRIPTION) ==
      MOQCTL_ERR_INTERNAL_ERROR);
  CHECK(
      moqctl_request_error_for(MOQVER_D18, MOQCTL_ERR_DUPLICATE_SUBSCRIPTION) ==
      MOQCTL_ERR_DUPLICATE_SUBSCRIPTION);
  CHECK(
      moqctl_request_error_for(MOQVER_D19, MOQCTL_ERR_INVALID_FILTER) ==
      MOQCTL_ERR_INVALID_FILTER);
  CHECK(
      moqctl_request_error_for(MOQVER_D22, MOQCTL_ERR_NOT_SUPPORTED) ==
      MOQCTL_ERR_NOT_SUPPORTED);
}

/* draft-23 16.12.2-16.12.3 (Tables 21, 22): REQUEST_ERROR UNAVAILABLE
 * (0xA) is new and PREFIX_OVERLAP (0x30) gone, PUBLISH_DONE
 * EXPIRED_AUTH_TOKEN (0x7) is new. Per draft: UNAVAILABLE is 0xA only in
 * draft-23 (EXCESSIVE_LOAD 0x9 before), PREFIX_OVERLAP 0x30 before
 * draft-23 (INTERNAL_ERROR in it), and 0x7 is relayed as received. */
static void test_moqctl_codes_d23(void) {
  static const u64 unavailable[MOQVER_COUNT] = {0xA, 0x9, 0x9, 0x9};
  static const u64 overlap[MOQVER_COUNT]     = {0x0, 0x30, 0x30, 0x30};
  for (int v = 0; v < MOQVER_COUNT; v++) {
    CHECK(
        moqctl_request_error_for(v, MOQCTL_ERR_UNAVAILABLE) == unavailable[v]);
    CHECK(moqctl_request_error_for(v, MOQCTL_ERR_PREFIX_OVERLAP) == overlap[v]);
  }
  CHECK(moqctl_publish_done_for(MOQVER_D23, 0x7) == 0x7);
  CHECK(
      moqctl_known_publish_done(MOQVER_D23, 0x7) ==
      MOQCTL_DONE_EXPIRED_AUTH_TOKEN);
  CHECK(moqctl_known_request_error(MOQVER_D23, 0xA) == MOQCTL_ERR_UNAVAILABLE);
}

/* draft-22 SS12.4 drops SUBSCRIPTION_ENDED (0x3). */
static void test_moqctl_publish_done_for_draft(void) {
  CHECK(
      moqctl_publish_done_for(MOQVER_D22, MOQCTL_DONE_SUBSCRIPTION_ENDED) ==
      MOQCTL_DONE_TRACK_ENDED);
  CHECK(
      moqctl_publish_done_for(MOQVER_D19, MOQCTL_DONE_SUBSCRIPTION_ENDED) ==
      MOQCTL_DONE_SUBSCRIPTION_ENDED);
  CHECK(
      moqctl_publish_done_for(MOQVER_D22, MOQCTL_DONE_GOING_AWAY) ==
      MOQCTL_DONE_GOING_AWAY);
}

/* ===== TEST: REQUEST_ERROR Redirect only with REDIRECT code ===== */

static void test_moqctl_request_error_redirect_roundtrip(void) {
  u8                   buf[64];
  usz                  off = 0;
  moqctl_request_error m   = {0};
  moqctl_request_error out;
  u8                   uri[3] = {'/', 'a', 'b'};
  wired_span           name   = wired_span_of((const u8*)"n", 1);

  m.error_code                 = MOQCTL_ERR_REDIRECT;
  m.retry_interval             = 0;
  m.reason                     = wired_span_of(0, 0);
  m.has_redirect               = 1;
  m.redirect.connect_uri       = wired_span_of(uri, 3);
  m.redirect.track_namespace.n = 0;
  m.redirect.track_name        = name;

  CHECK(moqctl_request_error_encode(wired_mspan_of(buf, sizeof buf), &off, &m));
  {
    usz roff = 0;
    CHECK(
        moqctl_request_error_take(wired_span_of(buf, off), &roff, &out) ==
        MOQCTL_OK);
    CHECK(roff == off);
  }
  CHECK(out.has_redirect);
  CHECK(out.redirect.connect_uri.n == 3);
  CHECK(out.redirect.track_name.n == 1);
}

/* ===== TEST: cut-short input and output (every field's take / put) ===== */

/* Every capacity short of fn's full encoding of m is refused, so each
 * field's put reports "no room" when the buffer ends inside it. */
static void mct_cut_out(moqctl_encode_body_fn fn, const void* m) {
  static u8 out[MOQKVP_MAX_LEN + 64];
  usz       full = 0;
  CHECK(fn(wired_mspan_of(out, sizeof out), &full, m));
  for (usz cap = 0; cap < full; cap++) {
    usz n = 0;
    CHECK(!fn(wired_mspan_of(out, cap), &n, m));
  }
}

typedef int (*mct_take_fn)(wired_span body, void* m);

/* Every proper prefix of body is refused as want (the Message Length
 * already framed the body, so a short one is malformed); the whole body
 * then decodes into m. */
static void mct_cut_in(mct_take_fn fn, wired_span body, void* m, int want) {
  for (usz cut = 0; cut < body.n; cut++) {
    CHECK(fn(wired_span_of(body.p, cut), m) == want);
  }
  CHECK(fn(body, m) == MOQCTL_OK);
}

static int mct_take_sub(wired_span b, void* m) {
  usz off = 0;
  return moqctl_subscribe_take(MOQVER_D19, b, &off, m);
}

static int mct_take_subok(wired_span b, void* m) {
  usz off = 0;
  return moqctl_subscribe_ok_take(MOQVER_D19, b, &off, m);
}

static int mct_take_pub(wired_span b, void* m) {
  usz off = 0;
  return moqctl_publish_take(MOQVER_D19, b, &off, m);
}

static int mct_take_rok(wired_span b, void* m) {
  usz off = 0;
  return moqctl_request_ok_take(MOQVER_D19, b, &off, m);
}

static int mct_take_rerr(wired_span b, void* m) {
  usz off = 0;
  return moqctl_request_error_take(b, &off, m);
}

static int mct_take_done(wired_span b, void* m) {
  usz off = 0;
  return moqctl_publish_done_take(b, &off, m);
}

static int mct_take_goaway(wired_span b, void* m) {
  usz off = 0;
  return moqctl_goaway_take(b, &off, m);
}

static int mct_put_goaway18(wired_mspan buf, usz* off, const void* m) {
  return moqctl_goaway18_encode(buf, off, m);
}

static int mct_put_rerr23(wired_mspan buf, usz* off, const void* m) {
  return moqctl_request_error_encode23(buf, off, m);
}

static int mct_put_params(wired_mspan buf, usz* off, const void* m) {
  return moqctl_params_put(buf, off, m);
}

static int mct_put_locfilter(wired_mspan buf, usz* off, const void* m) {
  return moqctl_locfilter_put(buf, off, m);
}

typedef union {
  moqctl_subscribe     sub;
  moqctl_subscribe_ok  subok;
  moqctl_publish       pub;
  moqctl_request_ok    rok;
  moqctl_request_error rerr;
  moqctl_publish_done  done;
  moqctl_goaway        goaway;
} mct_msg;

typedef struct {
  const u8*             g;
  usz                   n;
  mct_take_fn           take;
  moqctl_encode_body_fn put;
  int                   want;
} mct_golden;

static wired_span mct_body(const u8* g, usz n) {
  usz        off = 0;
  u64        type;
  wired_span body = {0, 0};
  CHECK(moqctl_peek_type(wired_span_of(g, n), &off, &type, &body) == MOQCTL_OK);
  return body;
}

/* draft-19 SS10: each golden Message Body cut anywhere short is refused,
 * and its decoded message re-encodes into nothing shorter. */
static void test_moqctl_golden_cut_short(void) {
  static mct_msg          m;
  static const mct_golden gs[] = {
      {g_moqt_ctl_subscribe_params, G_MOQT_CTL_SUBSCRIBE_PARAMS_LEN,
       mct_take_sub, moqctl_encode_subscribe, MOQCTL_INSUFFICIENT},
      {g_moqt_ctl_subscribe_ok_params, G_MOQT_CTL_SUBSCRIBE_OK_PARAMS_LEN,
       mct_take_subok, moqctl_encode_subscribe_ok, MOQCTL_INSUFFICIENT},
      {g_moqt_ctl_publish_basic, G_MOQT_CTL_PUBLISH_BASIC_LEN, mct_take_pub,
       moqctl_encode_publish, MOQCTL_INSUFFICIENT},
      {g_moqt_ctl_request_ok_params, G_MOQT_CTL_REQUEST_OK_PARAMS_LEN,
       mct_take_rok, moqctl_encode_request_ok, MOQCTL_INSUFFICIENT},
      {g_moqt_ctl_request_error_not_supported,
       G_MOQT_CTL_REQUEST_ERROR_NOT_SUPPORTED_LEN, mct_take_rerr,
       moqctl_encode_request_error, MOQCTL_INSUFFICIENT},
  };
  for (usz i = 0; i < sizeof gs / sizeof gs[0]; i++) {
    mct_cut_in(gs[i].take, mct_body(gs[i].g, gs[i].n), &m, gs[i].want);
    mct_cut_out(gs[i].put, &m);
  }
}

/* SS10.12 PUBLISH_DONE / SS10.4 GOAWAY with every field non-empty: a
 * Reason Phrase "bye", a New Session URI "u" (+ the draft-18 Request ID). */
static void test_moqctl_done_goaway_cut_short(void) {
  static const u8     done_w[]   = {0x02, 0x03, 0x03, 'b', 'y', 'e'};
  static const u8     goaway_w[] = {0x01, 'u', 0x05};
  moqctl_publish_done d;
  moqctl_goaway       g;
  mct_cut_in(
      mct_take_done, wired_span_of(done_w, sizeof done_w), &d,
      MOQCTL_INSUFFICIENT);
  mct_cut_out(moqctl_encode_publish_done, &d);
  mct_cut_in(
      mct_take_goaway, wired_span_of(goaway_w, sizeof goaway_w), &g,
      MOQCTL_INSUFFICIENT);
  mct_cut_out(moqctl_encode_goaway, &g);
  g.request_id = 4;
  mct_cut_out(mct_put_goaway18, &g);
}

/* SS10.5 / SS10.7: the Track Properties residual is written last. */
static void test_moqctl_ok_props_cut_short(void) {
  moqctl_request_ok   ok = {0};
  moqctl_subscribe_ok so = {0};
  ok.track_properties    = wired_span_of((const u8*)"pp", 2);
  so.track_alias         = 300; /* two-byte varint */
  so.track_properties    = ok.track_properties;
  mct_cut_out(moqctl_encode_request_ok, &ok);
  mct_cut_out(moqctl_encode_subscribe_ok, &so);
}

static void mct_redirect(moqctl_request_error* m, const u8* uri, usz n) {
  *m                                    = (moqctl_request_error){0};
  m->error_code                         = MOQCTL_ERR_REDIRECT;
  m->retry_interval                     = 9;
  m->reason                             = wired_span_of((const u8*)"r", 1);
  m->has_redirect                       = 1;
  m->redirect.connect_uri               = wired_span_of(uri, n);
  m->redirect.track_namespace.n         = 1;
  m->redirect.track_namespace.fields[0] = wired_span_of((const u8*)"a", 1);
  m->redirect.track_name                = wired_span_of((const u8*)"n", 1);
}

/* SS10.8.1 Redirect (draft-19 inline, draft-23 9.4.1 as Error Details):
 * every field cut short is refused both ways. */
static void test_moqctl_redirect_cut_short(void) {
  static const u8      uri[] = {'/', 'x'};
  u8                   buf[64];
  usz                  n = 0;
  moqctl_request_error m, back;
  mct_redirect(&m, uri, sizeof uri);
  CHECK(moqctl_request_error_encode(wired_mspan_of(buf, sizeof buf), &n, &m));
  mct_cut_in(mct_take_rerr, wired_span_of(buf, n), &back, MOQCTL_INSUFFICIENT);
  mct_cut_out(moqctl_encode_request_error, &m);
  m.error_code     = MOQCTL_ERR_UNSUPPORTED_EXTENSION;
  m.unsupported[0] = 0x40;
  m.unsupported[1] = 0x42;
  m.n_unsupported  = 2;
  mct_cut_out(mct_put_rerr23, &m);
  m.has_redirect = 0; /* the UNSUPPORTED_PROPERTY details alone */
  mct_cut_out(mct_put_rerr23, &m);
}

/* draft-23 9.4.1: an Error Details value is a Key-Value-Pair, so a
 * Redirect longer than its 0xFFFF Length bound is never encoded. */
static void test_moqctl_redirect_detail_too_long(void) {
  static u8            uri[MOQKVP_MAX_LEN];
  static u8            buf[MOQKVP_MAX_LEN + 64];
  moqctl_request_error m;
  usz                  n = 0;
  mct_redirect(&m, uri, sizeof uri - 16);
  CHECK(moqctl_request_error_encode23(wired_mspan_of(buf, sizeof buf), &n, &m));
  mct_redirect(&m, uri, sizeof uri);
  n = 0;
  CHECK(
      !moqctl_request_error_encode23(wired_mspan_of(buf, sizeof buf), &n, &m));
}

static void mct_param(moqctl_params* ps, u64 type, int enc) {
  moqctl_param* p = &ps->items[ps->n++];
  *p              = (moqctl_param){0};
  p->type         = type;
  p->enc          = enc;
}

/* One parameter per value encoding (SS10.2 / draft-22 9.2), each with a
 * multi-byte field, in ascending Type order. */
static void mct_params_all(moqctl_params* ps) {
  static const u8 tok[] = {0x02, 0x07}; /* USE_ALIAS 7 */
  *ps                   = (moqctl_params){0};
  mct_param(ps, MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT, MOQCTL_PENC_VARINT);
  ps->items[0].vi = 300;
  mct_param(ps, MOQCTL_PARAM_AUTHORIZATION_TOKEN, MOQCTL_PENC_TOKEN);
  ps->items[1].bytes = wired_span_of(tok, sizeof tok);
  mct_param(ps, MOQCTL_PARAM_LARGEST_OBJECT, MOQCTL_PENC_LOCATION);
  ps->items[2].loc = moqctl_loc_of(300, 301);
  mct_param(ps, MOQCTL_PARAM_SUBSCRIBER_PRIORITY, MOQCTL_PENC_UINT8);
  mct_param(ps, MOQCTL_PARAM_LOCATION_FILTER, MOQCTL_PENC_LOCFILTER);
  ps->items[4].lf =
      (moqctl_locfilter){MOQCTL_FILTER_ABS_RANGE, moqctl_loc_of(1, 2), 3};
}

/* draft-22 9.2.2 encodings: Location Filter None and AbsoluteRange with an
 * End Object, SWITCH_FROM, a raw value, SWITCHING_SET_ASSIGNMENT. */
static void mct_params_d22(moqctl_params* ps) {
  static const u8 raw[] = {0x01, 0x61};
  moqctl_param*   p;
  mct_param(ps, MOQCTL_PARAM_LOCATION_FILTER, MOQCTL_PENC_RANGELOC22);
  mct_param(ps, MOQCTL_PARAM_LOCATION_FILTER, MOQCTL_PENC_RANGELOC22);
  p             = &ps->items[ps->n - 1];
  p->has_filter = 1;
  p->rl         = (moqctl_rangeloc){MOQCTL_RSK_ABS, 1, 2, MOQCTL_REK_OBJ, 3, 4};
  mct_param(ps, MOQCTL_PARAM_SWITCH_FROM, MOQCTL_PENC_SWITCHFROM);
  ps->items[ps->n - 1].sw.request_id = 9;
  mct_param(ps, MOQCTL_PARAM_SUBGROUP_FILTER, MOQCTL_PENC_BYTES);
  ps->items[ps->n - 1].bytes = wired_span_of(raw, sizeof raw);
  mct_param(ps, MOQCTL_PARAM_TRACK_NAMESPACE_PREFIX, MOQCTL_PENC_NS);
  ps->items[ps->n - 1].bytes = wired_span_of(raw, sizeof raw);
  mct_param(ps, MOQCTL_PARAM_SWITCHING_SET_ASSIGNMENT, MOQCTL_PENC_SSA);
  p               = &ps->items[ps->n - 1];
  p->ssa.weight   = 1;
  p->ssa.rank     = 2;
  p->ssa.has_rank = 1;
}

/* Every parameter value encoder refuses a buffer that ends inside it. */
static void test_moqctl_params_cut_short(void) {
  static moqctl_params ps;
  mct_params_all(&ps);
  mct_params_d22(&ps);
  mct_cut_out(mct_put_params, &ps);
  mct_cut_out(mct_put_locfilter, &ps.items[4].lf);
}

static int mct_put_setup(wired_mspan buf, usz* off, const void* m) {
  return moqctl_setup_encode(buf, off, m);
}

/* SS10.3 SETUP with every Setup Option the encoder writes: PATH,
 * AUTHORITY, MAX_FILTER_RANGES, MOQT_IMPLEMENTATION, MAX_REQUEST_UPDATES
 * and the draft-22 SSTS_ALGORITHMS list. */
static void test_moqctl_setup_cut_short(void) {
  moqctl_setup s        = {0};
  s.has_path            = 1;
  s.path                = wired_span_of((const u8*)"/p", 2);
  s.has_authority       = 1;
  s.authority           = wired_span_of((const u8*)"h", 1);
  s.max_filter_ranges   = 300;
  s.has_implementation  = 1;
  s.implementation      = wired_span_of((const u8*)"w", 1);
  s.max_request_updates = 300;
  s.has_ssts            = 1;
  s.ssts_alg_n          = 1;
  s.ssts_algs[0]        = 300;
  mct_cut_out(mct_put_setup, &s);
}

/* SS10.2: a Parameter whose Length is cut off is INSUFFICIENT before its
 * value decoder runs (Token, Location Filter, SWITCHING_SET_ASSIGNMENT). */
static void test_moqctl_params_value_len_cut(void) {
  static moqctl_params out;
  const u8             tok[] = {0x01, (u8)MOQCTL_PARAM_AUTHORIZATION_TOKEN};
  const u8             lf[]  = {0x01, (u8)MOQCTL_PARAM_LOCATION_FILTER};
  const u8 ssa[] = {0x01, (u8)MOQCTL_PARAM_SWITCHING_SET_ASSIGNMENT};
  usz      off   = 0;
  CHECK(
      moqctl_params_take(
          MOQVER_D19, wired_span_of(tok, sizeof tok), &off,
          MOQCTL_PCTX_SUBSCRIBE, &out) == MOQCTL_INSUFFICIENT);
  off = 0;
  CHECK(
      moqctl_params_take(
          MOQVER_D19, wired_span_of(lf, sizeof lf), &off, MOQCTL_PCTX_SUBSCRIBE,
          &out) == MOQCTL_INSUFFICIENT);
  off = 0;
  CHECK(
      moqctl_params_take(
          MOQVER_D22, wired_span_of(ssa, sizeof ssa), &off,
          MOQCTL_PCTX_SUBSCRIBE, &out) == MOQCTL_INSUFFICIENT);
}

/* SS10.2: Parameters are written in ascending Type order (the Type Delta
 * is unsigned); a list out of order is never encoded. */
static void test_moqctl_params_put_unsorted(void) {
  static moqctl_params ps;
  u8                   buf[32];
  usz                  n = 0;
  mct_param(&ps, MOQCTL_PARAM_GROUP_ORDER, MOQCTL_PENC_UINT8);
  mct_param(&ps, MOQCTL_PARAM_SUBSCRIBER_PRIORITY, MOQCTL_PENC_UINT8);
  CHECK(!moqctl_params_put(wired_mspan_of(buf, sizeof buf), &n, &ps));
}

/* A Parameter list longer than MOQCTL_MAX_PARAMS is refused as a
 * PROTOCOL_VIOLATION (SS10.2; Range Filters may repeat, 5.1.3), so the
 * decoder never writes past items[]. */
static void test_moqctl_params_take_too_many(void) {
  static moqctl_params out;
  u8                   buf[4 + 4 * (MOQCTL_MAX_PARAMS + 1)];
  usz                  n = 0, roff = 0;
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &n, MOQCTL_MAX_PARAMS + 1));
  for (usz i = 0; i <= MOQCTL_MAX_PARAMS; i++) {
    buf[n++] = i ? 0x00 : (u8)MOQCTL_PARAM_SUBGROUP_FILTER; /* Type Delta */
    buf[n++] = 0x02;                                        /* Length */
    buf[n++] = 0x00;                                        /* SetID */
    buf[n++] = 0x03;                                        /* Start 3 */
  }
  CHECK(
      moqctl_params_take(
          MOQVER_D19, wired_span_of(buf, n), &roff, MOQCTL_PCTX_SUBSCRIBE,
          &out) == MOQCTL_VIOLATION);
}

/* d19 10.2.10: a Start delta summing past 2^64-1, or a fifth Range past
 * MOQCTL_MAX_RANGES, marks the filter invalid (INVALID_FILTER); a Start or
 * End delta cut short is a formatting error. */
static void test_moqctl_rangefilter_start_limits(void) {
  static const u8    wrap[]      = {0x00, 0x01, 0x00, 0xFF, 0xFF, 0xFF,
                                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  static const u8    five[]      = {0x00, 0x00, 0x00, 0x01, 0x00,
                                    0x01, 0x00, 0x01, 0x00, 0x01};
  static const u8    cut_start[] = {0x00, 0x80};
  static const u8    cut_end[]   = {0x00, 0x01, 0x80};
  moqctl_rangefilter f;
  const u64          t = MOQCTL_PARAM_OBJECTID_FILTER;
  CHECK(
      moqctl_rangefilter_take(t, wired_span_of(wrap, sizeof wrap), &f) ==
      MOQCTL_OK);
  CHECK(f.invalid && f.n == 1);
  CHECK(
      moqctl_rangefilter_take(t, wired_span_of(five, sizeof five), &f) ==
      MOQCTL_OK);
  CHECK(f.invalid && f.n == MOQCTL_MAX_RANGES);
  CHECK(
      moqctl_rangefilter_take(
          t, wired_span_of(cut_start, sizeof cut_start), &f) ==
      MOQCTL_PARAMS_KVFMT);
  CHECK(
      moqctl_rangefilter_take(t, wired_span_of(cut_end, sizeof cut_end), &f) ==
      MOQCTL_PARAMS_KVFMT);
}

/* d19 SS9.3.1 / d22 9.20.9 Location Filter values cut inside a field:
 * the Type itself, a Start Location, an End Group Delta. */
static void test_moqctl_locfilter_values_cut_short(void) {
  static const u8  abs_range[] = {0x04, 0x03, 0x00, 0x05};
  moqctl_locfilter lf;
  moqctl_rangeloc  rl;
  int              has;
  usz              off;
  for (usz cut = 0; cut < sizeof abs_range; cut++) {
    off = 0;
    CHECK(
        moqctl_locfilter_take(wired_span_of(abs_range, cut), &off, &lf) ==
        MOQCTL_INSUFFICIENT);
    off = 0;
    CHECK(
        moqctl_rangeloc19_take(wired_span_of(abs_range, cut), &off, &rl) ==
        MOQCTL_INSUFFICIENT);
  }
  for (u8 t = 0x03; t <= 0x04; t++) { /* d22: Start, End Group (Object) */
    const u8 v[] = {t, 0x03, 0x00, 0x05, 0x06};
    for (usz cut = 0; cut < (usz)t + 1; cut++) {
      off = 0;
      CHECK(
          moqctl_rangeloc22_take(wired_span_of(v, cut), &off, &has, &rl) ==
          MOQCTL_INSUFFICIENT);
    }
  }
}

/* ===== main ===== */

void test_moqctl(void) {
  test_moqctl_peek_type_setup();
  test_moqctl_peek_type_length_mismatch();
  test_moqctl_peek_type_truncated();
  test_moqctl_peek_type_unknown();
  test_moqctl_peek_type_known_unimplemented();
  test_moqctl_type_ver_publish_ok_alias();
  test_moqctl_type_ver_publish_state_notify();
  test_moqctl_type_ver_passthrough();
  test_moqctl_peek_type_unknown_skips_whole_message();
  test_moqctl_peek_type_unimplemented_skips_whole_message();
  test_moqctl_peek_type_fetch_ok_is_known();
  test_moqctl_peek_type_unknown_truncated_waits();
  test_moqctl_peek_type_max_len_field();

  test_moqctl_setup_roundtrip();
  test_moqctl_subscribe_roundtrip();
  test_moqctl_subscribe_ok_roundtrip();
  test_moqctl_publish_roundtrip();
  test_moqctl_request_ok_roundtrip();
  test_moqctl_request_error_roundtrip();
  test_moqctl_publish_done_roundtrip();
  test_moqctl_goaway_roundtrip();
  test_moqctl_goaway18_request_id();
  test_moqctl_goaway18_vs_19_shape();

  test_moqctl_goaway_uri_boundary();
  test_moqctl_reason_boundary();
  test_moqctl_location_roundtrip_and_order();

  test_moqctl_ftn_decode_basic();
  test_moqctl_ns_field_len_zero_rejected();
  test_moqctl_ns_fields_32_accept_33_reject();
  test_moqctl_ftn_4096_accept_4097_reject();

  test_moqctl_params_forward_roundtrip();
  test_moqctl_params_type_overflow_violation();
  test_moqctl_params_unknown_type_violation();
  test_moqctl_params_duplicate_type_violation();
  test_moqctl_params_scope_violation();
  test_moqctl_params_delivery_timeout_decode();
  test_moqctl_params_auth_token_use_value_decode();
  test_moqctl_params_auth_token_alias_shapes_decode();
  test_moqctl_params_auth_token_malformed_kvfmt();
  test_moqctl_params_auth_token_scope_violation();
  test_moqctl_params_registry_scope();
  test_moqctl_params_registry_scope_per_draft();
  test_moqctl_params_include_properties_range();
  test_moqctl_params_location_filter_roundtrip();
  test_moqctl_params_location_filter_malformed();
  test_moqctl_params_namespace_prefix();
  test_moqctl_params_uint8_value_ranges();
  test_moqctl_param_range_uint8_only();
  test_moqctl_params_repeatable_filters();
  test_moqctl_request_ok_params_scope();
  test_moqctl_params_find();
  test_moqctl_golden_subscribe_params();
  test_moqctl_golden_subscribe_ok_params();
  test_moqctl_golden_request_ok_params();

  test_moqctl_setup_unknown_option_ignored();
  test_moqctl_setup_path_option_decode();
  test_moqctl_setup_d23_max_ctl_size_ok();
  test_moqctl_setup_d23_max_ctl_size_malformed();
  test_moqctl_setup_d22_09_is_ssts();
  test_moqctl_setup_d23_ssts_moved();
  test_moqctl_setup_limit_options_roundtrip();
  test_moqctl_setup_limit_options_default_zero();

  test_moqctl_rangefilter_value_roundtrip();
  test_moqctl_rangefilter_open_end_prop_and_remove();
  test_moqctl_rangefilter_overflow_and_truncated();
  test_moqctl_locfilter_next_group_and_largest();
  test_moqctl_locfilter_abs_start_and_range_roundtrip();
  test_moqctl_locfilter_end_group_overflow_violation();
  test_moqctl_locfilter_unknown_type_violation();
  test_moqctl_subscribe_d18_moxygen_largest_group();
  test_moqctl_rangeloc19_next_group();
  test_moqctl_rangeloc19_largest_object();
  test_moqctl_rangeloc19_abs_start_roundtrip();
  test_moqctl_rangeloc19_abs_range_egd_zero_roundtrip();
  test_moqctl_rangeloc19_abs_range_egd_positive_roundtrip();
  test_moqctl_rangeloc19_egd_overflow_violation();
  test_moqctl_rangeloc22_none();
  test_moqctl_rangeloc22_relative_start_roundtrip();
  test_moqctl_rangeloc22_abs_start_roundtrip();
  test_moqctl_rangeloc22_abs_start_group_end_roundtrip();
  test_moqctl_rangeloc22_abs_range_roundtrip();
  test_moqctl_rangeloc22_next_object_roundtrip();
  test_moqctl_rangeloc22_egd_overflow_violation();
  test_moqctl_rangeloc22_unknown_type_violation();
  test_moqctl_rangeloc_cross_version_abs_start();

  test_moqctl_grease_pattern();
  test_moqctl_unknown_error_normalizes_to_internal();
  test_moqctl_request_error_for_draft();
  test_moqctl_codes_d23();
  test_moqctl_publish_done_for_draft();

  test_moqctl_request_error_redirect_roundtrip();

  test_moqctl_golden_cut_short();
  test_moqctl_done_goaway_cut_short();
  test_moqctl_ok_props_cut_short();
  test_moqctl_redirect_cut_short();
  test_moqctl_redirect_detail_too_long();
  test_moqctl_params_cut_short();
  test_moqctl_params_put_unsorted();
  test_moqctl_setup_cut_short();
  test_moqctl_params_value_len_cut();
  test_moqctl_params_take_too_many();
  test_moqctl_rangefilter_start_limits();
  test_moqctl_locfilter_values_cut_short();
}
