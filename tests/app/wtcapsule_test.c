#include "app/webtransport/capsule/wtcapsule/wtcapsule.h"

#include "app/http3/core/capsule/capsule.h"
#include "app/webtransport/session/session/session.h"
#include "test.h"

/* @file
 * WebTransport-specific capsule types (WT_CLOSE_SESSION 0x2843,
 * WT_DRAIN_SESSION 0x78ae) layered on the generic RFC 9297 Capsule Protocol
 * codec.
 */

/* TEST 1: WT_CLOSE_SESSION round-trip with a nonzero error code and a short
 * message. */
static void test_wtcapsule_close_roundtrip(void) {
  u8         buf[64];
  wired_obuf out    = obuf_of(buf, sizeof buf);
  u8         msg[5] = {'h', 'e', 'l', 'l', 'o'};
  usz        at     = 0;
  u32        code_out;
  wired_span msg_out;

  CHECK(wired_wtcapsule_encode_close(
      &out, 0xDEADBEEF, wired_span_of(msg, sizeof msg)));
  CHECK(wired_wtcapsule_decode_close(
      wired_span_of(buf, out.len), &at, &code_out, &msg_out));
  CHECK(code_out == 0xDEADBEEF);
  CHECK(msg_out.n == 5);
  for (usz i = 0; i < 5; i++) CHECK(msg_out.p[i] == msg[i]);
  CHECK(at == out.len);
}

/* TEST 2: WT_CLOSE_SESSION with an empty message round-trips correctly. */
static void test_wtcapsule_close_roundtrip_empty_message(void) {
  u8         buf[32];
  wired_obuf out = obuf_of(buf, sizeof buf);
  usz        at  = 0;
  u32        code_out;
  wired_span msg_out;

  CHECK(wired_wtcapsule_encode_close(&out, 1, wired_span_of(0, 0)));
  CHECK(wired_wtcapsule_decode_close(
      wired_span_of(buf, out.len), &at, &code_out, &msg_out));
  CHECK(code_out == 1);
  CHECK(msg_out.n == 0);
  CHECK(at == out.len);
}

/* TEST 3: encode rejects a message over 1024 bytes even with plenty of room
 * in out. */
static void test_wtcapsule_close_encode_rejects_long_message(void) {
  u8         buf[4096];
  wired_obuf out = obuf_of(buf, sizeof buf);
  u8         msg[WTCAPSULE_CLOSE_MESSAGE_MAX + 1];
  for (usz i = 0; i < sizeof msg; i++) msg[i] = 'x';

  CHECK(!wired_wtcapsule_encode_close(&out, 0, wired_span_of(msg, sizeof msg)));
  CHECK(out.len == 0);
}

/* TEST 4: WT_DRAIN_SESSION round-trip: *at advances by the full empty-body
 * capsule size. */
static void test_wtcapsule_drain_roundtrip(void) {
  u8         buf[16];
  wired_obuf out = obuf_of(buf, sizeof buf);
  usz        at  = 0;

  CHECK(wtcapsule_encode_drain(&out));
  /* 0x78ae > 0x3FFF -> 4-byte type varint + 1-byte length(0) = 5 */
  CHECK(out.len == 5);
  CHECK(wtcapsule_decode_drain(wired_span_of(buf, out.len), &at));
  CHECK(at == 5);
}

/* TEST 5: wrong-type-no-advance -- decode_close on a WT_DRAIN_SESSION
 * capsule must fail AND leave *at unchanged, so the caller can retry with
 * decode_drain from the same offset. */
static void test_wtcapsule_wrong_type_does_not_advance(void) {
  u8         buf[16];
  wired_obuf out = obuf_of(buf, sizeof buf);
  usz        at  = 0;
  u32        code_out;
  wired_span msg_out;

  CHECK(wtcapsule_encode_drain(&out));
  CHECK(!wired_wtcapsule_decode_close(
      wired_span_of(buf, out.len), &at, &code_out, &msg_out));
  CHECK(at == 0);
  /* Same position now succeeds as a drain decode. */
  CHECK(wtcapsule_decode_drain(wired_span_of(buf, out.len), &at));
  CHECK(at == out.len);
}

/* TEST 6: malformed WT_CLOSE_SESSION -- correctly typed 0x2843 but body too
 * short to hold the 32-bit error code. */
static void test_wtcapsule_close_decode_body_too_short(void) {
  u8         buf[16];
  wired_obuf out           = obuf_of(buf, sizeof buf);
  u8         short_body[2] = {0, 0};
  usz        at            = 0;
  u32        code_out;
  wired_span msg_out;

  /* Hand-encode a generic capsule with type 0x2843 but a 2-byte body
   * (shorter than the mandatory 4-byte error code). */
  CHECK(capsule_encode(
      &out, 0x2843, wired_span_of(short_body, sizeof short_body)));
  CHECK(!wired_wtcapsule_decode_close(
      wired_span_of(buf, out.len), &at, &code_out, &msg_out));
  CHECK(at == 0);
}

/* TEST 7: sequential decode -- WT_DRAIN_SESSION then WT_CLOSE_SESSION
 * back-to-back in one buffer. */
static void test_wtcapsule_sequential_drain_then_close(void) {
  u8         buf[64];
  wired_obuf out    = obuf_of(buf, sizeof buf);
  u8         msg[3] = {'h', 'i', '!'};
  usz        at     = 0;
  u32        code_out;
  wired_span msg_out;
  wired_span data;

  CHECK(wtcapsule_encode_drain(&out));
  CHECK(wired_wtcapsule_encode_close(&out, 42, wired_span_of(msg, sizeof msg)));
  data = wired_span_of(buf, out.len);

  CHECK(wtcapsule_decode_drain(data, &at));
  CHECK(wired_wtcapsule_decode_close(data, &at, &code_out, &msg_out));
  CHECK(code_out == 42);
  CHECK(msg_out.n == 3);
  CHECK(msg_out.p[2] == '!');
  CHECK(at == out.len);
}

/* TEST 8: the HTTP/3 WebTransport mapping defines no per-stream
 * flow-control capsule (a hypothetical WT_MAX_STREAM_DATA /
 * WT_STREAM_DATA_BLOCKED, as opposed to the per-SESSION WT_MAX_DATA family
 * at 0x190B4D3D etc., which wtcapsule.h does implement -- see
 * wtcapsule_decode_max_data). There is no wire codepoint to construct
 * for a per-stream type this SDK will never emit or receive, so this test
 * instead pins: decode_close/decode_drain reject ANY capsule type outside
 * their own two types without advancing *at, shown here using the
 * per-SESSION WT_MAX_DATA codepoint (0x190B4D3D) as a stand-in "some other
 * capsule type" probe. */
static void test_wtcapsule_no_per_stream_flow_control_capsule(void) {
  u8         buf[32];
  wired_obuf out = obuf_of(buf, sizeof buf);
  usz        at  = 0;
  u32        code_out;
  wired_span msg_out;
  u8         value[4] = {1, 2, 3, 4};

  /* 0x190B4D3D is WT_MAX_DATA, owned by decode_max_data, not decode_close
   * or decode_drain -- used here only as "a type those two don't own"
   * probe. */
  CHECK(
      capsule_encode(&out, 0x190B4D3DULL, wired_span_of(value, sizeof value)));
  CHECK(!wired_wtcapsule_decode_close(
      wired_span_of(buf, out.len), &at, &code_out, &msg_out));
  CHECK(at == 0);
  CHECK(!wtcapsule_decode_drain(wired_span_of(buf, out.len), &at));
  CHECK(at == 0);
}

/* TEST 9: WT_MAX_STREAMS bidi round-trip; the bidi type (0x190B4D3F) does
 * not decode as the uni variant. */
static void test_wtcapsule_max_streams_bidi_roundtrip(void) {
  u8         buf[16];
  wired_obuf out = obuf_of(buf, sizeof buf);
  usz        at  = 0;
  u64        n_out;

  CHECK(wtcapsule_encode_max_streams(&out, 1, 42));
  CHECK(!wtcapsule_decode_max_streams(
      wired_span_of(buf, out.len), &at, 0, &n_out));
  CHECK(at == 0);
  CHECK(wtcapsule_decode_max_streams(
      wired_span_of(buf, out.len), &at, 1, &n_out));
  CHECK(n_out == 42);
  CHECK(at == out.len);
}

/* TEST 10: WT_MAX_STREAMS uni round-trip (distinct type 0x190B4D40). */
static void test_wtcapsule_max_streams_uni_roundtrip(void) {
  u8         buf[16];
  wired_obuf out = obuf_of(buf, sizeof buf);
  usz        at  = 0;
  u64        n_out;

  CHECK(wtcapsule_encode_max_streams(&out, 0, 7));
  CHECK(wtcapsule_decode_max_streams(
      wired_span_of(buf, out.len), &at, 0, &n_out));
  CHECK(n_out == 7);
  CHECK(at == out.len);
}

/* TEST 11: WT_STREAMS_BLOCKED bidi/uni round-trip, same direction-typed
 * shape as WT_MAX_STREAMS. */
static void test_wtcapsule_streams_blocked_roundtrip(void) {
  u8         buf[16];
  wired_obuf out = obuf_of(buf, sizeof buf);
  usz        at  = 0;
  u64        n_out;

  CHECK(wtcapsule_encode_streams_blocked(&out, 1, 3));
  CHECK(wtcapsule_decode_streams_blocked(
      wired_span_of(buf, out.len), &at, 1, &n_out));
  CHECK(n_out == 3);
  CHECK(at == out.len);

  out.len = 0;
  at      = 0;
  CHECK(wtcapsule_encode_streams_blocked(&out, 0, 9));
  CHECK(wtcapsule_decode_streams_blocked(
      wired_span_of(buf, out.len), &at, 0, &n_out));
  CHECK(n_out == 9);
  CHECK(at == out.len);
}

/* TEST 12: WT_MAX_DATA round-trip (single type, 0x190B4D3D). */
static void test_wtcapsule_max_data_roundtrip(void) {
  u8         buf[16];
  wired_obuf out = obuf_of(buf, sizeof buf);
  usz        at  = 0;
  u64        n_out;

  CHECK(wtcapsule_encode_max_data(&out, 65536));
  CHECK(wtcapsule_decode_max_data(wired_span_of(buf, out.len), &at, &n_out));
  CHECK(n_out == 65536);
  CHECK(at == out.len);
}

/* TEST 13: WT_DATA_BLOCKED round-trip (single type, 0x190B4D41); also
 * confirms it does not cross-decode as WT_MAX_DATA. */
static void test_wtcapsule_data_blocked_roundtrip(void) {
  u8         buf[16];
  wired_obuf out = obuf_of(buf, sizeof buf);
  usz        at  = 0;
  u64        n_out;

  CHECK(wtcapsule_encode_data_blocked(&out, 1024));
  CHECK(!wtcapsule_decode_max_data(wired_span_of(buf, out.len), &at, &n_out));
  CHECK(at == 0);
  CHECK(
      wtcapsule_decode_data_blocked(wired_span_of(buf, out.len), &at, &n_out));
  CHECK(n_out == 1024);
  CHECK(at == out.len);
}

/* TEST 14: malformed flow-control capsule -- correctly typed WT_MAX_DATA
 * but an empty body (no varint to read) is rejected without advancing. */
static void test_wtcapsule_max_data_decode_empty_body_rejected(void) {
  u8         buf[16];
  wired_obuf out = obuf_of(buf, sizeof buf);
  usz        at  = 0;
  u64        n_out;

  CHECK(capsule_encode(&out, 0x190B4D3DULL, wired_span_of(0, 0)));
  CHECK(!wtcapsule_decode_max_data(wired_span_of(buf, out.len), &at, &n_out));
  CHECK(at == 0);
}

/* TEST 15: malformed flow-control capsule -- correctly typed WT_MAX_STREAMS
 * (bidi) but trailing bytes after the varint are rejected without
 * advancing. */
static void test_wtcapsule_max_streams_decode_trailing_bytes_rejected(void) {
  u8         buf[16];
  wired_obuf out     = obuf_of(buf, sizeof buf);
  u8         body[2] = {5, 0xAA};
  usz        at      = 0;
  u64        n_out;

  CHECK(capsule_encode(&out, 0x190B4D3FULL, wired_span_of(body, sizeof body)));
  CHECK(!wtcapsule_decode_max_streams(
      wired_span_of(buf, out.len), &at, 1, &n_out));
  CHECK(at == 0);
}

/* TEST 16: draft-ietf-webtrans-http3-15 SS5.1 (WTH3-053): "If flow control
 * is not enabled, an endpoint shall ignore receipt of any flow control
 * capsules." No caller in src/ currently decodes a WT_MAX_STREAMS/
 * WT_MAX_DATA capsule off the wire (see WTH3-058/060/062's own gap notes),
 * so there is no live receive path yet where "ignore" is a decision an
 * endpoint makes -- decode success or failure is orthogonal to whether the
 * decoded value gets applied. What IS live is wired_wt_session's own
 * flow-control state (session.h SS5.3/5.4): a session that has never had
 * wired_wt_session_set_max_streams/set_max_data applied to it behaves
 * exactly as WTH3-053 prescribes for "flow control not enabled" --
 * opening streams and sending data stay unconditionally allowed. This
 * pins that a decoded-but-not-yet-applied capsule value (the shape any
 * future receive-path wiring would produce before calling
 * wired_wt_session_set_max_streams) has zero effect on the session until
 * a caller chooses to apply it -- i.e. "decode, then don't apply" IS the
 * ignore rule once the future receive path exists. */
static void test_wtcapsule_max_streams_decoded_value_ignored_until_applied(
    void) {
  u8               buf[16];
  wired_obuf       out = obuf_of(buf, sizeof buf);
  usz              at  = 0;
  u64              n_out;
  wired_wt_session s;

  wired_wt_session_init(&s, 4);
  CHECK(wtcapsule_encode_max_streams(&out, 1, 5));
  CHECK(wtcapsule_decode_max_streams(
      wired_span_of(buf, out.len), &at, 1, &n_out));
  CHECK(n_out == 5);
  /* Decoded successfully, but never applied to s (the "ignore" choice) --
   * the session's flow control stays unenabled, so it keeps allowing. */
  CHECK(wired_wt_session_stream_open_allowed(&s, 1) == 1);
  CHECK(wired_wt_session_stream_open_allowed(&s, 0) == 1);
}

void test_wtcapsule(void) {
  test_wtcapsule_close_roundtrip();
  test_wtcapsule_close_roundtrip_empty_message();
  test_wtcapsule_close_encode_rejects_long_message();
  test_wtcapsule_drain_roundtrip();
  test_wtcapsule_wrong_type_does_not_advance();
  test_wtcapsule_close_decode_body_too_short();
  test_wtcapsule_sequential_drain_then_close();
  test_wtcapsule_no_per_stream_flow_control_capsule();
  test_wtcapsule_max_streams_bidi_roundtrip();
  test_wtcapsule_max_streams_uni_roundtrip();
  test_wtcapsule_streams_blocked_roundtrip();
  test_wtcapsule_max_data_roundtrip();
  test_wtcapsule_data_blocked_roundtrip();
  test_wtcapsule_max_data_decode_empty_body_rejected();
  test_wtcapsule_max_streams_decode_trailing_bytes_rejected();
  test_wtcapsule_max_streams_decoded_value_ignored_until_applied();
}
